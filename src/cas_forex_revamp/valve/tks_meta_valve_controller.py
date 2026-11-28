"""TKS Meta-Valve Controller for CAS Forex Revamp (Phase 3 + Phase 6 Drawdown Hardening).

Provides:
1. TKSMetaValveController: 8 -> 16 (tanh) -> 1 (sigmoid) deterministic MLP controller
   (161 trainable parameters) for cognitive trajectory & Forex decision gating.
2. PeakEquityStore: Durable high-water peak-equity tracker (SQLite WAL or scoped memory)
   that auto-seeds new scopes at max(opening_balance, current_equity), monotonically
   ratchets upward, never resets on restart/rollback, and requires authenticated owner
   recovery to re-arm after a drawdown event.
3. ForexMetaValveGate: Dual-layer Forex trade-proposal safety valve combining:
   - Trained 8-D -> 16 -> 1 neural MLP admission probability (threshold = 0.55)
   - Constitutional Hard-Floor Invariant vetoing missing accounting (G-ABSENT),
     missing or exceeded peak-equity drawdown (MISSING_DRAWDOWN_ACCOUNTING /
     MAX_DRAWDOWN_EXCEEDED on OPEN/ADD while preserving WAIT/REDUCE/CLOSE),
     disallowed risk/management permissions, oversized quantity, unbacked evidence,
     missing/inverted protective stop on entries, prompt-injection override pressure,
     or expired market state.

Pure Python standard library only (zero external runtime dependencies inside air-gap).
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, localcontext
from hashlib import sha256
import hmac
import json
import math
from pathlib import Path
import secrets
import sqlite3
from threading import RLock
from types import MappingProxyType
from typing import Any

from cas_forex_revamp.contracts import ActionKind, ContractError, ControlKind, canonical_bytes, decimal_text
from cas_forex_revamp.contracts.primitives import utc_time
from cas_forex_revamp.risk.demo_high_growth_profile import (
    DEMO_HIGH_GROWTH_MAX_DRAWDOWN_PCT,
    DemoHighGrowthProfile,
)


MAX_CONSTITUTIONAL_DRAWDOWN_PCT = Decimal("0.10")
DEFAULT_MAX_DRAWDOWN_PCT = MAX_CONSTITUTIONAL_DRAWDOWN_PCT


def validate_constitutional_drawdown_pct(
    value: Any,
    *,
    field: str = "max_drawdown_pct",
    allow_none: bool = False,
) -> Decimal | None:
    """Validate that max_drawdown_pct is strictly in (0, 0.10] (immutable 10.00% constitutional ceiling)."""
    if value is None:
        if allow_none:
            return None
        raise ContractError(f"{field} must be a finite Decimal in (0, 0.10]")
    parsed = _safe_decimal(value)
    if parsed is None or parsed <= Decimal("0") or parsed >= Decimal("1"):
        raise ContractError(f"{field} must be a finite Decimal in (0, 0.10]")
    if parsed > MAX_CONSTITUTIONAL_DRAWDOWN_PCT:
        raise ContractError(
            f"CONSTITUTIONAL_DRAWDOWN_CEILING_EXCEEDED: {field}={parsed} exceeds immutable 0.10 (10.00%) ceiling"
        )
    return parsed
_GENESIS_SHA256 = "0" * 64

FOREX_FEATURE_NAMES: tuple[str, ...] = (
    "missing_accounting_ratio",
    "permission_violation",
    "quantity_excess_ratio",
    "unbacked_evidence_ratio",
    "prompt_injection_signal",
    "stop_protection_deficit",
    "quote_staleness_ratio",
    "reasoning_drift_score",
)

COGNITIVE_FEATURE_NAMES: tuple[str, ...] = (
    "repetition_3gram",
    "unique_token_deficit",
    "Lacunarity_proxy",
    "injection_marker_density",
    "unbacked_assertion_density",
    "contradiction_signal",
    "length_overflow_ratio",
    "entropy_collapse_score",
)

INJECTION_MARKERS: tuple[str, ...] = (
    "ignore policy",
    "ignore previous",
    "bypass",
    "override risk",
    "force trade",
    "urgent alpha",
    "disregard",
    "skip margin",
    "ignore unavailable",
    "execute immediately regardless",
    "system override",
)


DEFAULT_VALVE_GRANT_TTL_SECONDS = 30.0
MAX_VALVE_GRANT_TTL_SECONDS = 300.0
DEFAULT_VALVE_DECISION_TTL_SECONDS = 300.0
MAX_VALVE_REPLAY_LEDGER_ENTRIES = 16384

RISK_REDUCING_ACTION_KINDS: frozenset[str] = frozenset({"CLOSE", "REDUCE"})
CONDITIONAL_MANAGEMENT_ACTION_KINDS: frozenset[str] = frozenset({"AMEND_STOP"})
RISK_INCREASING_ACTION_KINDS: frozenset[str] = frozenset({"OPEN", "ADD"})
ALLOWED_VALVE_GRANT_ACTIONS: frozenset[str] = (
    RISK_REDUCING_ACTION_KINDS | CONDITIONAL_MANAGEMENT_ACTION_KINDS | RISK_INCREASING_ACTION_KINDS
)


class ValveRefusalError(ContractError):
    """Raised when ForexMetaValveGate blocks an unsafe or hallucinated trade proposal."""

    def __init__(self, message: str, decision: "ValveDecision | None" = None) -> None:
        super().__init__(message)
        self.decision = decision


class ValveGrantError(ValveRefusalError):
    """Raised when a ValveOrderGrant is missing, forged, tampered, expired, replayed, or mismatched."""


_VALVE_DECISION_SENTINEL = object()
_VALVE_GRANT_SENTINEL = object()


def _build_valve_hmac_sealer() -> tuple[Callable[[str], str], Callable[[str, str], bool]]:
    """Create process-private HMAC-SHA256 sign/verify closures for Valve decisions & order grants."""
    seal_material = secrets.token_bytes(32)

    def _sign(payload: str) -> str:
        return hmac.new(seal_material, payload.encode("utf-8"), sha256).hexdigest()

    def _verify(payload: str, mac_hex: str) -> bool:
        if not isinstance(mac_hex, str) or len(mac_hex) != 64:
            return False
        return hmac.compare_digest(_sign(payload), mac_hex.lower())

    return _sign, _verify


_sign_valve_payload, _verify_valve_payload = _build_valve_hmac_sealer()

_GRANT_LEDGER_LOCK = RLock()
_ISSUED_UNCONSUMED_GRANTS: dict[str, tuple[str, datetime]] = {}
_CONSUMED_GRANT_NONCES: dict[str, datetime] = {}
_CONSUMED_DECISION_TARGETS: dict[tuple[str, str, str], datetime] = {}


def _prune_valve_replay_ledgers_locked(now_dt: datetime) -> None:
    """Prune expired entries across all Valve replay ledgers under `_GRANT_LEDGER_LOCK`."""
    check_dt = utc_time(now_dt, "now")
    for key in [k for k, (_, exp) in _ISSUED_UNCONSUMED_GRANTS.items() if exp < check_dt]:
        _ISSUED_UNCONSUMED_GRANTS.pop(key, None)
    for key in [k for k, exp in _CONSUMED_GRANT_NONCES.items() if exp < check_dt]:
        _CONSUMED_GRANT_NONCES.pop(key, None)
    for key in [k for k, exp in _CONSUMED_DECISION_TARGETS.items() if exp < check_dt]:
        _CONSUMED_DECISION_TARGETS.pop(key, None)


def _norm_grant_symbol(raw: Any) -> str:
    txt = str(raw or "").strip().upper()
    if not txt:
        return ""
    if txt.startswith("TRADE_"):
        return txt
    if "/" in txt or "_" in txt:
        compact = txt.replace("/", "").replace("_", "")
        if len(compact) == 6 and compact.isalpha():
            return compact
    return txt


def _norm_grant_decimal(raw: Any) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return ""
        if s.upper() == "ALL":
            return "ALL"
    d = _safe_decimal(raw)
    if d is None:
        raise ValveGrantError(f"invalid decimal valve grant field: {raw!r}")
    txt = format(d, "f")
    if "." in txt:
        txt = txt.rstrip("0").rstrip(".")
    return "0" if txt in ("", "-0") else txt


def _norm_grant_side(raw: Any) -> str:
    if raw is None:
        return ""
    val = raw.value if hasattr(raw, "value") else str(raw)
    norm = val.strip().upper()
    if not norm:
        return ""
    if norm not in ("BUY", "SELL"):
        raise ValveGrantError(f"invalid side in valve grant: {norm!r}")
    return norm


def _norm_grant_action(raw: Any) -> str:
    val = raw.value if hasattr(raw, "value") else str(raw)
    norm = val.strip().upper()
    if norm not in ALLOWED_VALVE_GRANT_ACTIONS:
        raise ValveGrantError(f"unsupported valve grant action_kind: {norm!r}")
    return norm


def _norm_grant_execution_mode(raw: Any) -> str:
    norm = str(raw or "").strip().upper()
    if norm not in ("DEMO", "LIVE"):
        raise ValveGrantError(f"invalid execution_mode in valve grant: {norm!r}")
    return norm


def _is_monotonic_tightening_amend(
    *,
    side: Any,
    stop_loss: Decimal | str | None,
    previous_stop_loss: Decimal | str | None,
) -> bool:
    norm_side = _norm_grant_side(side)
    if norm_side not in ("BUY", "SELL"):
        return False
    norm_sl = _norm_grant_decimal(stop_loss)
    if not norm_sl:
        # Take-profit-only amendment does not alter the protective stop.
        return True
    norm_prev = _norm_grant_decimal(previous_stop_loss)
    if not norm_prev:
        return False
    new_d = Decimal(norm_sl)
    prev_d = Decimal(norm_prev)
    if new_d <= Decimal("0") or prev_d <= Decimal("0"):
        return False
    if norm_side == "BUY":
        return new_d >= prev_d
    return new_d <= prev_d


def _canonical_grant_order_digest(
    *,
    broker_id: str,
    account_id: str,
    server: str,
    execution_mode: str,
    action_kind: str,
    symbol: str,
    side: str,
    volume: str,
    stop_loss: str,
    take_profit: str,
    position_ticket: str,
    grant_nonce: str,
    issued_at: datetime,
    expires_at: datetime,
    previous_stop_loss: str = "",
) -> str:
    payload = {
        "protocol": "cas-forex-valve-order-grant/1",
        "broker_id": broker_id.strip().upper(),
        "account_id": str(account_id).strip(),
        "server": server.strip().casefold(),
        "execution_mode": _norm_grant_execution_mode(execution_mode),
        "action_kind": _norm_grant_action(action_kind),
        "symbol": _norm_grant_symbol(symbol),
        "side": _norm_grant_side(side),
        "volume": _norm_grant_decimal(volume),
        "stop_loss": _norm_grant_decimal(stop_loss),
        "take_profit": _norm_grant_decimal(take_profit),
        "position_ticket": str(position_ticket or "").strip(),
        "previous_stop_loss": _norm_grant_decimal(previous_stop_loss),
        "grant_nonce": grant_nonce.strip(),
        "issued_at": _iso_utc(issued_at),
        "expires_at": _iso_utc(expires_at),
    }
    return sha256(canonical_bytes(payload)).hexdigest()


def _canonical_grant_sig_input(
    *,
    order_digest_sha256: str,
    weights_sha256: str,
    decision_sha256: str,
    risk_reducing: bool,
    gate_id: str,
) -> str:
    return "|".join((
        "cas-forex-valve-grant-sig/1",
        order_digest_sha256.lower(),
        weights_sha256.lower(),
        decision_sha256.lower(),
        "RR" if risk_reducing else "RI",
        gate_id,
    ))


def _canonical_decision_seal_input(
    *,
    admitted: bool,
    valve_mode: str,
    mlp_score: float,
    threshold: float,
    mlp_admitted: bool,
    hard_veto: bool,
    hard_veto_reasons: tuple[str, ...],
    weights_sha256: str,
    request_id: str,
    selected_action_ref: str | None,
    gate_id: str,
    decision_nonce: str,
    issued_at: datetime | None,
    expires_at: datetime | None,
    bound_intent_digest: str,
    bound_action_kind: str,
    bound_symbol: str,
    bound_side: str,
    bound_quantity: str,
    bound_stop_price: str,
    bound_take_profit_price: str,
    bound_limit_price: str,
    bound_target_id: str,
) -> str:
    payload = {
        "protocol": "cas-forex-valve-decision-seal/1",
        "admitted": bool(admitted),
        "valve_mode": str(valve_mode),
        "mlp_score": _fmt8(mlp_score),
        "threshold": _fmt8(threshold),
        "mlp_admitted": bool(mlp_admitted),
        "hard_veto": bool(hard_veto),
        "hard_veto_reasons": list(hard_veto_reasons),
        "weights_sha256": str(weights_sha256).lower(),
        "request_id": str(request_id),
        "selected_action_ref": selected_action_ref,
        "gate_id": gate_id,
        "decision_nonce": decision_nonce,
        "issued_at": None if issued_at is None else _iso_utc(issued_at),
        "expires_at": None if expires_at is None else _iso_utc(expires_at),
        "bound_intent_digest": bound_intent_digest,
        "bound_action_kind": bound_action_kind,
        "bound_symbol": bound_symbol,
        "bound_side": bound_side,
        "bound_quantity": bound_quantity,
        "bound_stop_price": bound_stop_price,
        "bound_take_profit_price": bound_take_profit_price,
        "bound_limit_price": bound_limit_price,
        "bound_target_id": bound_target_id,
    }
    return sha256(canonical_bytes(payload)).hexdigest()


@dataclass(frozen=True, slots=True)
class ValveDecision:
    admitted: bool
    valve_mode: str
    mlp_score: float
    threshold: float
    mlp_admitted: bool
    hard_veto: bool
    hard_veto_reasons: tuple[str, ...]
    features: Mapping[str, float]
    weights_sha256: str
    request_id: str
    selected_action_ref: str | None
    _mint_token: object = field(default=None, repr=False, compare=False)
    _decision_seal: str = field(default="", repr=False, compare=False)
    _gate_id: str = field(default="", repr=False, compare=False)
    _decision_nonce: str = field(default="", repr=False, compare=False)
    _issued_at: datetime | None = field(default=None, repr=False, compare=False)
    _expires_at: datetime | None = field(default=None, repr=False, compare=False)
    _bound_intent_digest: str = field(default="", repr=False, compare=False)
    _bound_action_kind: str = field(default="", repr=False, compare=False)
    _bound_symbol: str = field(default="", repr=False, compare=False)
    _bound_side: str = field(default="", repr=False, compare=False)
    _bound_quantity: str = field(default="", repr=False, compare=False)
    _bound_stop_price: str = field(default="", repr=False, compare=False)
    _bound_take_profit_price: str = field(default="", repr=False, compare=False)
    _bound_limit_price: str = field(default="", repr=False, compare=False)
    _bound_target_id: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.admitted) is not bool:
            raise ContractError("ValveDecision.admitted must be a bool")
        if type(self.mlp_admitted) is not bool or type(self.hard_veto) is not bool:
            raise ContractError("ValveDecision boolean flags must be bool")
        if not isinstance(self.features, Mapping):
            raise ContractError("ValveDecision.features must be a Mapping")
        frozen_features = MappingProxyType({str(k): float(v) for k, v in self.features.items()})
        object.__setattr__(self, "features", frozen_features)
        frozen_reasons = tuple(str(r) for r in self.hard_veto_reasons)
        object.__setattr__(self, "hard_veto_reasons", frozen_reasons)

    @property
    def is_gate_minted(self) -> bool:
        if self._mint_token is not _VALVE_DECISION_SENTINEL:
            return False
        return _verify_valve_payload(self._seal_payload(), self._decision_seal)

    @property
    def bound_intent_digest(self) -> str:
        return self._bound_intent_digest

    @property
    def decision_nonce(self) -> str:
        return self._decision_nonce

    @property
    def issued_at(self) -> datetime | None:
        return self._issued_at

    @property
    def expires_at(self) -> datetime | None:
        return self._expires_at

    def _seal_payload(self) -> str:
        return _canonical_decision_seal_input(
            admitted=self.admitted,
            valve_mode=self.valve_mode,
            mlp_score=self.mlp_score,
            threshold=self.threshold,
            mlp_admitted=self.mlp_admitted,
            hard_veto=self.hard_veto,
            hard_veto_reasons=self.hard_veto_reasons,
            weights_sha256=self.weights_sha256,
            request_id=self.request_id,
            selected_action_ref=self.selected_action_ref,
            gate_id=self._gate_id,
            decision_nonce=self._decision_nonce,
            issued_at=self._issued_at,
            expires_at=self._expires_at,
            bound_intent_digest=self._bound_intent_digest,
            bound_action_kind=self._bound_action_kind,
            bound_symbol=self._bound_symbol,
            bound_side=self._bound_side,
            bound_quantity=self._bound_quantity,
            bound_stop_price=self._bound_stop_price,
            bound_take_profit_price=self._bound_take_profit_price,
            bound_limit_price=self._bound_limit_price,
            bound_target_id=self._bound_target_id,
        )

    def verify_provenance(
        self,
        *,
        expected_weights_sha256: str | None = None,
        expected_gate_id: str | None = None,
        now: datetime | None = None,
    ) -> None:
        """Fail closed unless this ValveDecision was cryptographically minted by ForexMetaValveGate."""
        if self._mint_token is not _VALVE_DECISION_SENTINEL or not _verify_valve_payload(
            self._seal_payload(), self._decision_seal
        ):
            raise ValveGrantError(
                "ValveDecision lacks valid ForexMetaValveGate cryptographic provenance seal; forged/manual decision refused",
                decision=self,
            )
        if expected_weights_sha256 is not None and not hmac.compare_digest(
            self.weights_sha256.lower(), expected_weights_sha256.lower()
        ):
            raise ValveGrantError("ValveDecision was produced by different Valve weights", decision=self)
        if expected_gate_id is not None and self._gate_id != expected_gate_id:
            raise ValveGrantError("ValveDecision was produced by a different ForexMetaValveGate", decision=self)
        if now is not None and self._issued_at is not None and self._expires_at is not None:
            check_now = utc_time(now, "now")
            if check_now < self._issued_at - timedelta(seconds=30) or check_now > self._expires_at:
                raise ValveGrantError(
                    f"ValveDecision expired or not yet valid (expires_at={_iso_utc(self._expires_at)})",
                    decision=self,
                )

    def assert_binds_order(
        self,
        *,
        action_ref: str,
        action_kind: ActionKind | str,
        symbol: str,
        side: Any = None,
        quantity_units: Decimal | str | None = None,
        stop_price: Decimal | str | None = None,
        take_profit_price: Decimal | str | None = None,
        limit_price: Decimal | str | None = None,
        position_ticket: str | None = None,
    ) -> None:
        """Verify that every order-relevant field matches the exact proposal evaluated by the Valve."""
        if self.selected_action_ref != action_ref:
            raise ValveGrantError("ValveDecision does not bind this order's action_ref", decision=self)
        ord_kind = _norm_grant_action(action_kind)
        bound_kind = self._bound_action_kind.strip().upper()
        if not bound_kind:
            raise ValveGrantError("ValveDecision carries no bound action_kind (WAIT or unminted decision)", decision=self)
        kind_ok = (ord_kind == bound_kind) or (bound_kind == "ADD" and ord_kind == "OPEN")
        if not kind_ok:
            raise ValveGrantError(
                f"ValveDecision bound action_kind {bound_kind!r} cannot authorize {ord_kind!r}",
                decision=self,
            )
        ord_sym = _norm_grant_symbol(symbol)
        if not self._bound_symbol or ord_sym != self._bound_symbol:
            raise ValveGrantError(
                f"ValveDecision bound symbol {self._bound_symbol!r} does not match order symbol {ord_sym!r}",
                decision=self,
            )
        ord_side = _norm_grant_side(side)
        if ord_kind in RISK_INCREASING_ACTION_KINDS:
            if not self._bound_side or ord_side != self._bound_side:
                raise ValveGrantError(
                    f"ValveDecision bound side {self._bound_side!r} does not match order side {ord_side!r}",
                    decision=self,
                )
        elif ord_side and self._bound_side and ord_side != self._bound_side:
            raise ValveGrantError(
                f"ValveDecision bound side {self._bound_side!r} does not match management side {ord_side!r}",
                decision=self,
            )
        ord_qty = _norm_grant_decimal(quantity_units)
        if ord_kind in ("OPEN", "ADD", "REDUCE"):
            if not self._bound_quantity or ord_qty != self._bound_quantity:
                raise ValveGrantError(
                    f"ValveDecision bound quantity {self._bound_quantity!r} does not match order quantity {ord_qty!r}",
                    decision=self,
                )
        elif ord_kind == "CLOSE":
            if ord_qty and self._bound_quantity and ord_qty != "ALL" and ord_qty != self._bound_quantity:
                raise ValveGrantError(
                    f"ValveDecision bound CLOSE quantity {self._bound_quantity!r} does not match {ord_qty!r}",
                    decision=self,
                )
        ord_stop = _norm_grant_decimal(stop_price)
        if ord_kind in RISK_INCREASING_ACTION_KINDS:
            if ord_stop != self._bound_stop_price:
                raise ValveGrantError(
                    f"ValveDecision bound stop_price {self._bound_stop_price!r} does not match {ord_stop!r}",
                    decision=self,
                )
        elif ord_kind == "AMEND_STOP":
            if self._bound_stop_price and ord_stop != self._bound_stop_price:
                raise ValveGrantError(
                    f"ValveDecision bound AMEND_STOP stop_price {self._bound_stop_price!r} does not match {ord_stop!r}",
                    decision=self,
                )
        ord_tp = _norm_grant_decimal(take_profit_price)
        if ord_kind in RISK_INCREASING_ACTION_KINDS:
            if ord_tp != self._bound_take_profit_price:
                raise ValveGrantError(
                    f"ValveDecision bound take_profit_price {self._bound_take_profit_price!r} does not match {ord_tp!r}",
                    decision=self,
                )
        elif ord_kind == "AMEND_STOP":
            if self._bound_take_profit_price and ord_tp != self._bound_take_profit_price:
                raise ValveGrantError(
                    f"ValveDecision bound AMEND_STOP take_profit_price {self._bound_take_profit_price!r} does not match {ord_tp!r}",
                    decision=self,
                )
        ord_limit = _norm_grant_decimal(limit_price)
        if ord_kind in RISK_INCREASING_ACTION_KINDS and ord_limit != self._bound_limit_price:
            raise ValveGrantError(
                f"ValveDecision bound limit_price {self._bound_limit_price!r} does not match {ord_limit!r}",
                decision=self,
            )
        ord_ticket = str(position_ticket or "").strip()
        if ord_kind in (RISK_REDUCING_ACTION_KINDS | CONDITIONAL_MANAGEMENT_ACTION_KINDS):
            if self._bound_target_id and ord_ticket and self._bound_target_id != ord_ticket:
                raise ValveGrantError(
                    f"ValveDecision bound target_id {self._bound_target_id!r} does not match position_ticket {ord_ticket!r}",
                    decision=self,
                )

    def to_dict(self) -> dict[str, Any]:
        return {
            "admitted": self.admitted,
            "valve_mode": self.valve_mode,
            "mlp_score": _fmt8(self.mlp_score),
            "threshold": _fmt8(self.threshold),
            "mlp_admitted": self.mlp_admitted,
            "hard_veto": self.hard_veto,
            "hard_veto_reasons": list(self.hard_veto_reasons),
            "features": {k: _fmt8(v) for k, v in self.features.items()},
            "weights_sha256": self.weights_sha256,
            "request_id": self.request_id,
            "selected_action_ref": self.selected_action_ref,
        }


@dataclass(frozen=True, slots=True, repr=False)
class ValveOrderGrant:
    """Opaque, frozen, short-lived, single-use order-bound capability minted exclusively by ForexMetaValveGate."""

    broker_id: str
    account_id: str
    server: str
    execution_mode: str
    action_kind: str
    symbol: str
    side: str
    volume: str
    stop_loss: str
    take_profit: str
    position_ticket: str
    grant_nonce: str
    issued_at: datetime
    expires_at: datetime
    weights_sha256: str
    decision_sha256: str
    risk_reducing: bool
    order_digest_sha256: str
    signature_hmac_sha256: str
    previous_stop_loss: str = ""
    _mint_token: object = field(default=None, repr=False, compare=False)
    _gate_id: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._mint_token is not _VALVE_GRANT_SENTINEL:
            raise ValveGrantError(
                "ValveOrderGrant cannot be constructed directly; must be minted by ForexMetaValveGate"
            )
        if not isinstance(self.broker_id, str) or not self.broker_id.strip():
            raise ValveGrantError("ValveOrderGrant requires a non-empty broker_id")
        if not isinstance(self.account_id, str) or not self.account_id.strip():
            raise ValveGrantError("ValveOrderGrant requires a non-empty account_id")
        if not isinstance(self.server, str) or not self.server.strip():
            raise ValveGrantError("ValveOrderGrant requires a non-empty server")
        _norm_grant_execution_mode(self.execution_mode)
        act = _norm_grant_action(self.action_kind)
        if type(self.risk_reducing) is not bool:
            raise ValveGrantError("ValveOrderGrant risk_reducing flag must be bool")
        if act in RISK_REDUCING_ACTION_KINDS and not self.risk_reducing:
            raise ValveGrantError("ValveOrderGrant risk_reducing flag does not match action_kind")
        if act in RISK_INCREASING_ACTION_KINDS and self.risk_reducing:
            raise ValveGrantError("ValveOrderGrant risk_reducing flag does not match action_kind")
        if act == "AMEND_STOP" and self.risk_reducing:
            if not _is_monotonic_tightening_amend(side=self.side, stop_loss=self.stop_loss, previous_stop_loss=self.previous_stop_loss):
                raise ValveGrantError("ValveOrderGrant risk_reducing AMEND_STOP requires proven non-widening stop vs previous_stop_loss")
        if not isinstance(self.symbol, str) or not self.symbol.strip():
            raise ValveGrantError("ValveOrderGrant requires a non-empty symbol")
        if not isinstance(self.grant_nonce, str) or len(self.grant_nonce.strip()) < 16:
            raise ValveGrantError("ValveOrderGrant requires a high-entropy grant_nonce")
        issued = utc_time(self.issued_at, "issued_at")
        expires = utc_time(self.expires_at, "expires_at")
        ttl = (expires - issued).total_seconds()
        if ttl <= 0 or ttl > MAX_VALVE_GRANT_TTL_SECONDS:
            raise ValveGrantError("ValveOrderGrant TTL must be in (0, 300] seconds")
        expected_digest = _canonical_grant_order_digest(
            broker_id=self.broker_id,
            account_id=self.account_id,
            server=self.server,
            execution_mode=self.execution_mode,
            action_kind=self.action_kind,
            symbol=self.symbol,
            side=self.side,
            volume=self.volume,
            stop_loss=self.stop_loss,
            take_profit=self.take_profit,
            position_ticket=self.position_ticket,
            grant_nonce=self.grant_nonce,
            issued_at=issued,
            expires_at=expires,
            previous_stop_loss=self.previous_stop_loss,
        )
        if not hmac.compare_digest(expected_digest, self.order_digest_sha256.lower()):
            raise ValveGrantError("ValveOrderGrant order_digest_sha256 verification failed")
        sig_input = _canonical_grant_sig_input(
            order_digest_sha256=self.order_digest_sha256,
            weights_sha256=self.weights_sha256,
            decision_sha256=self.decision_sha256,
            risk_reducing=self.risk_reducing,
            gate_id=self._gate_id,
        )
        if not _verify_valve_payload(sig_input, self.signature_hmac_sha256):
            raise ValveGrantError("ValveOrderGrant HMAC-SHA256 signature verification failed")

    def __repr__(self) -> str:
        return (
            f"ValveOrderGrant(broker_id={self.broker_id!r}, action_kind={self.action_kind!r}, "
            f"symbol={self.symbol!r}, execution_mode={self.execution_mode!r}, "
            f"risk_reducing={self.risk_reducing!r}, expires_at={_iso_utc(self.expires_at)!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


def verify_and_consume_valve_order_grant(
    grant: Any,
    *,
    broker_id: str,
    account_id: str | int,
    server: str,
    execution_mode: str,
    action_kind: ActionKind | str,
    symbol: str,
    side: Any = None,
    volume: Decimal | str | None = None,
    stop_loss: Decimal | str | None = None,
    take_profit: Decimal | str | None = None,
    position_ticket: str | None = None,
    previous_stop_loss: Decimal | str | None = None,
    now: datetime | None = None,
    require_risk_reducing: bool = False,
    expected_weights_sha256: str | None = None,
) -> ValveOrderGrant:
    """Verify cryptographic signature, exact order binding, TTL, and atomically consume a single-use ValveOrderGrant."""
    if not isinstance(grant, ValveOrderGrant):
        raise ValveGrantError("Broker mutation refused: valid ForexMetaValveGate ValveOrderGrant is mandatory")
    if grant._mint_token is not _VALVE_GRANT_SENTINEL:
        raise ValveGrantError("Broker mutation refused: ValveOrderGrant provenance sentinel invalid")
    norm_broker = str(broker_id or "").strip().upper()
    norm_acct = str(account_id or "").strip()
    norm_srv = str(server or "").strip()
    norm_mode = _norm_grant_execution_mode(execution_mode)
    norm_act = _norm_grant_action(action_kind)
    norm_sym = _norm_grant_symbol(symbol)
    norm_side = _norm_grant_side(side)
    norm_vol = _norm_grant_decimal(volume)
    norm_sl = _norm_grant_decimal(stop_loss)
    norm_tp = _norm_grant_decimal(take_profit)
    norm_ticket = str(position_ticket or "").strip()
    norm_prev_sl = _norm_grant_decimal(previous_stop_loss) if previous_stop_loss is not None else grant.previous_stop_loss
    eff_rr_allowed = RISK_REDUCING_ACTION_KINDS | CONDITIONAL_MANAGEMENT_ACTION_KINDS
    if require_risk_reducing and (norm_act not in eff_rr_allowed or not grant.risk_reducing):
        raise ValveGrantError(
            f"Management/protective broker sink refuses non-risk-reducing action {norm_act!r}"
        )
    if grant.action_kind in RISK_REDUCING_ACTION_KINDS and not grant.risk_reducing:
        raise ValveGrantError("ValveOrderGrant risk_reducing invariant violated")
    if grant.action_kind in RISK_INCREASING_ACTION_KINDS and grant.risk_reducing:
        raise ValveGrantError("ValveOrderGrant risk_reducing invariant violated")
    if grant.action_kind == "AMEND_STOP" and grant.risk_reducing:
        if not _is_monotonic_tightening_amend(
            side=(norm_side or grant.side),
            stop_loss=norm_sl,
            previous_stop_loss=norm_prev_sl,
        ):
            raise ValveGrantError("ValveOrderGrant risk_reducing AMEND_STOP fails monotonic non-widening check")
    if expected_weights_sha256 is not None and not hmac.compare_digest(
        grant.weights_sha256.lower(), expected_weights_sha256.lower()
    ):
        raise ValveGrantError("ValveOrderGrant weights_sha256 mismatch")
    sig_input = _canonical_grant_sig_input(
        order_digest_sha256=grant.order_digest_sha256,
        weights_sha256=grant.weights_sha256,
        decision_sha256=grant.decision_sha256,
        risk_reducing=grant.risk_reducing,
        gate_id=grant._gate_id,
    )
    if not _verify_valve_payload(sig_input, grant.signature_hmac_sha256):
        raise ValveGrantError("ValveOrderGrant HMAC-SHA256 verification failed")
    expected_digest = _canonical_grant_order_digest(
        broker_id=norm_broker,
        account_id=norm_acct,
        server=norm_srv,
        execution_mode=norm_mode,
        action_kind=norm_act,
        symbol=norm_sym,
        side=norm_side,
        volume=norm_vol,
        stop_loss=norm_sl,
        take_profit=norm_tp,
        position_ticket=norm_ticket,
        grant_nonce=grant.grant_nonce,
        issued_at=grant.issued_at,
        expires_at=grant.expires_at,
        previous_stop_loss=norm_prev_sl,
    )
    if not hmac.compare_digest(expected_digest, grant.order_digest_sha256.lower()):
        raise ValveGrantError(
            f"ValveOrderGrant field-binding mismatch for {norm_broker}/{norm_act}/{norm_sym}; "
            "order parameters differ from signed grant"
        )
    check_now = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
    if check_now < grant.issued_at - timedelta(seconds=30) or check_now > grant.expires_at:
        raise ValveGrantError(
            f"ValveOrderGrant expired or not yet valid (expires_at={_iso_utc(grant.expires_at)}, "
            f"checked_at={_iso_utc(check_now)})"
        )
    with _GRANT_LEDGER_LOCK:
        _prune_valve_replay_ledgers_locked(check_now)
        nonce = grant.grant_nonce
        if nonce in _CONSUMED_GRANT_NONCES:
            raise ValveGrantError("ValveOrderGrant replay refused: single-use grant_nonce already consumed")
        reg = _ISSUED_UNCONSUMED_GRANTS.get(nonce)
        if reg is None or not hmac.compare_digest(reg[0], expected_digest):
            raise ValveGrantError("ValveOrderGrant unknown or already consumed; failing closed")
        if len(_CONSUMED_GRANT_NONCES) >= MAX_VALVE_REPLAY_LEDGER_ENTRIES:
            raise ValveGrantError(
                f"Valve consumed grant replay ledger saturated ({MAX_VALVE_REPLAY_LEDGER_ENTRIES}); failing closed"
            )
        _ISSUED_UNCONSUMED_GRANTS.pop(nonce, None)
        _CONSUMED_GRANT_NONCES[nonce] = utc_time(grant.expires_at, "expires_at")
    return grant


def _fmt8(value: float) -> str:
    v = round(float(value), 8)
    if v == 0.0:
        v = 0.0
    return f"{v:.8f}"


def _clamp01(value: float) -> float:
    if math.isnan(value) or math.isinf(value):
        return 1.0
    return max(0.0, min(1.0, float(value)))


def _sigmoid(z: float) -> float:
    if z >= 35.0:
        return 1.0
    if z <= -35.0:
        return 0.0
    return 1.0 / (1.0 + math.exp(-z))


def _safe_decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, Decimal):
        return value if value.is_finite() else None
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return parsed if parsed.is_finite() else None


_BOM_AND_WS = "\ufeff\u00a0 \t\r\n\v\f"
_UNAVAILABLE_ACCOUNTING_TOKENS = frozenset(
    {
        "null",
        "unavailable",
        "",
        "nan",
        "-nan",
        "+nan",
        "snan",
        "-snan",
        "+snan",
        "n/a",
        "none",
        "undefined",
        "nil",
        "inf",
        "-inf",
        "+inf",
        "infinity",
        "-infinity",
        "+infinity",
    }
)
_NUMERIC_ACCOUNTING_FIELDS = frozenset({"balance", "equity", "available_margin", "peak_equity"})


def _strip_bom_and_ws(value: str) -> str:
    while True:
        nxt = value.strip(_BOM_AND_WS).strip()
        if nxt == value:
            return nxt
        value = nxt


def _unwrap_observed_json(raw: Any, max_depth: int = 4) -> dict[str, Any] | list[Any] | None:
    if isinstance(raw, (dict, list)):
        return raw
    if isinstance(raw, tuple):
        return list(raw)
    if not isinstance(raw, str):
        return None
    cur: Any = raw
    for _ in range(max_depth):
        if not isinstance(cur, str):
            break
        s = _strip_bom_and_ws(cur)
        if not s or s[0] not in ("{", "[", '"'):
            return None
        try:
            cur = json.loads(s)
        except (ValueError, TypeError):
            return None
        if isinstance(cur, (dict, list)):
            return cur
    return cur if isinstance(cur, (dict, list)) else None


def _is_unavailable_accounting_value(
    value: Any,
    *,
    allow_list: bool = True,
    require_list: bool = False,
) -> bool:
    if require_list:
        if isinstance(value, (list, tuple)):
            return False
        if isinstance(value, str):
            return not isinstance(_unwrap_observed_json(value), list)
        return True
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, (int, float, Decimal)):
        return _safe_decimal(value) is None
    if isinstance(value, (list, tuple)):
        return not allow_list
    if isinstance(value, dict):
        if "amount" not in value and "value" not in value:
            return True
        inner = value["amount"] if "amount" in value else value["value"]
        if _is_unavailable_accounting_value(inner, allow_list=False):
            return True
        norm_inner = _strip_bom_and_ws(inner) if isinstance(inner, str) else inner
        return _safe_decimal(norm_inner) is None
    if isinstance(value, str):
        s = _strip_bom_and_ws(value)
        for _ in range(8):
            if not (len(s) >= 2 and s[0] == '"' and s[-1] == '"'):
                break
            try:
                unwrapped = json.loads(s)
            except (ValueError, TypeError):
                nxt = _strip_bom_and_ws(s[1:-1])
                if nxt == s:
                    break
                s = nxt
                continue
            if isinstance(unwrapped, str):
                s = _strip_bom_and_ws(unwrapped)
            elif isinstance(unwrapped, dict):
                return _is_unavailable_accounting_value(unwrapped, allow_list=allow_list)
            elif isinstance(unwrapped, list):
                return not allow_list
            elif unwrapped is None or isinstance(unwrapped, bool):
                return True
            elif isinstance(unwrapped, (int, float)):
                return _safe_decimal(unwrapped) is None
            else:
                return True
        if s.startswith("{") or s.startswith("["):
            try:
                parsed = json.loads(s)
            except (ValueError, TypeError):
                parsed = None
            if isinstance(parsed, dict):
                return _is_unavailable_accounting_value(parsed, allow_list=allow_list)
            if isinstance(parsed, list):
                return not allow_list
        if s.lower() in _UNAVAILABLE_ACCOUNTING_TOKENS:
            return True
        return _safe_decimal(s) is None
    if hasattr(value, "amount"):
        return _is_unavailable_accounting_value(getattr(value, "amount"), allow_list=False)
    return True


def _extract_money_decimal(value: Any) -> Decimal | None:
    """Extract a finite Decimal from a plain scalar/string or typed Money wire dict."""
    if _is_unavailable_accounting_value(value, allow_list=False):
        return None
    if isinstance(value, str):
        s = _strip_bom_and_ws(value)
        for _ in range(8):
            if not (len(s) >= 2 and s[0] == '"' and s[-1] == '"'):
                break
            try:
                unwrapped = json.loads(s)
            except (ValueError, TypeError):
                nxt = _strip_bom_and_ws(s[1:-1])
                if nxt == s:
                    break
                s = nxt
                continue
            if isinstance(unwrapped, str):
                s = _strip_bom_and_ws(unwrapped)
            elif isinstance(unwrapped, (dict, int, float)):
                return _extract_money_decimal(unwrapped)
            else:
                return None
        if s.startswith("{"):
            try:
                parsed = json.loads(s)
            except (ValueError, TypeError):
                parsed = None
            if isinstance(parsed, dict):
                return _extract_money_decimal(parsed)
        return _safe_decimal(s)
    if isinstance(value, dict):
        if "amount" in value:
            raw_amt = value.get("amount")
        elif "value" in value:
            raw_amt = value.get("value")
        else:
            return None
        if isinstance(raw_amt, str):
            raw_amt = _strip_bom_and_ws(raw_amt)
        return _safe_decimal(raw_amt)
    if hasattr(value, "amount"):
        return _safe_decimal(getattr(value, "amount"))
    return _safe_decimal(value)


def compute_drawdown_pct(current_equity: Decimal, peak_equity: Decimal) -> Decimal:
    """Exact Decimal drawdown fraction in [0, +inf): max(0, (peak - current) / peak)."""
    cur = _safe_decimal(current_equity)
    peak = _safe_decimal(peak_equity)
    if cur is None or peak is None or peak <= Decimal("0"):
        raise ContractError("compute_drawdown_pct requires finite current_equity and positive peak_equity")
    if cur >= peak:
        return Decimal("0")
    with localcontext() as ctx:
        ctx.prec = 40
        return (peak - cur) / peak


def _iso_utc(ts: datetime | None) -> str:
    val = ts if isinstance(ts, datetime) and ts.tzinfo is not None else datetime.now(timezone.utc)
    return val.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class PeakEquityStore:
    """Durable high-water peak-equity tracker (SQLite WAL when path supplied, scoped memory otherwise).

    Invariants:
    - Inert on construction (no file or SQLite connection opened in __init__).
    - Auto-initializes an unseen scope to max(opening_balance, current_equity).
    - Monotonically ratchets upward on subsequent observations; restart or lower opening_balance
      never clears or lowers an existing high-water mark.
    - Lowering/resetting a high-water mark requires `rearm_after_drawdown` with an authenticated
      owner verifier (`OwnerRequestBook` with a registered `RESUME_NEW_RISK` fence request or an
      explicit `verify_drawdown_rearm` authority).
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._lock = RLock()
        self._memory: dict[str, Decimal] = {}
        self._initialized = False

    @property
    def path(self) -> Path | None:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        if self._path is None:
            raise ContractError("in-memory PeakEquityStore has no SQLite path")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._path), timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        if not self._initialized:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS peak_equity_marks (
                    scope_id TEXT PRIMARY KEY,
                    peak_equity TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_event_sha256 TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS peak_equity_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    scope_id TEXT NOT NULL,
                    event_kind TEXT NOT NULL,
                    peak_equity TEXT NOT NULL,
                    observed_equity TEXT NOT NULL,
                    owner_request_id TEXT,
                    observed_at TEXT NOT NULL,
                    prev_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL
                )
                """
            )
            self._initialized = True
        return conn

    def read_peak(self, scope_id: str) -> Decimal | None:
        if not isinstance(scope_id, str) or not scope_id.strip():
            raise ContractError("scope_id must be a non-empty string")
        key = scope_id.strip()
        with self._lock:
            if self._path is None:
                return self._memory.get(key)
            if not self._path.exists():
                return None
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT peak_equity FROM peak_equity_marks WHERE scope_id = ?",
                    (key,),
                ).fetchone()
            finally:
                conn.close()
            return _safe_decimal(row[0]) if row is not None else None

    def _append_sqlite(
        self,
        conn: sqlite3.Connection,
        *,
        scope_id: str,
        event_kind: str,
        peak: Decimal,
        observed: Decimal,
        owner_request_id: str | None,
        ts_str: str,
    ) -> None:
        last_row = conn.execute(
            "SELECT event_sha256 FROM peak_equity_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_sha = str(last_row[0]) if last_row is not None else _GENESIS_SHA256
        peak_txt = decimal_text(peak)
        obs_txt = decimal_text(observed)
        payload = {
            "scope_id": scope_id,
            "event_kind": event_kind,
            "peak_equity": peak_txt,
            "observed_equity": obs_txt,
            "owner_request_id": owner_request_id,
            "observed_at": ts_str,
            "prev_sha256": prev_sha,
        }
        ev_sha = sha256(canonical_bytes(payload)).hexdigest()
        conn.execute(
            """
            INSERT INTO peak_equity_events (
                scope_id, event_kind, peak_equity, observed_equity,
                owner_request_id, observed_at, prev_sha256, event_sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (scope_id, event_kind, peak_txt, obs_txt, owner_request_id, ts_str, prev_sha, ev_sha),
        )
        conn.execute(
            """
            INSERT INTO peak_equity_marks (scope_id, peak_equity, updated_at, last_event_sha256)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(scope_id) DO UPDATE SET
                peak_equity = excluded.peak_equity,
                updated_at = excluded.updated_at,
                last_event_sha256 = excluded.last_event_sha256
            """,
            (scope_id, peak_txt, ts_str, ev_sha),
        )

    def observe_equity(
        self,
        scope_id: str,
        *,
        current_equity: Decimal,
        opening_balance: Decimal | None = None,
        now: datetime | None = None,
    ) -> Decimal:
        if not isinstance(scope_id, str) or not scope_id.strip():
            raise ContractError("scope_id must be a non-empty string")
        cur = _safe_decimal(current_equity)
        if cur is None:
            raise ContractError("current_equity must be a finite Decimal")
        open_bal = _safe_decimal(opening_balance) if opening_balance is not None else None
        key = scope_id.strip()
        ts_str = _iso_utc(now)

        with self._lock:
            if self._path is None:
                existing = self._memory.get(key)
                if existing is not None:
                    nxt = max(existing, cur)
                else:
                    seed = max(cur, open_bal) if open_bal is not None else cur
                    if seed <= Decimal("0"):
                        raise ContractError("initial peak_equity seed must be positive")
                    nxt = seed
                self._memory[key] = nxt
                return nxt

            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT peak_equity FROM peak_equity_marks WHERE scope_id = ?",
                    (key,),
                ).fetchone()
                if row is not None:
                    stored = _safe_decimal(row[0])
                    if stored is None or stored <= Decimal("0"):
                        raise ContractError("corrupted peak_equity mark in durable store")
                    nxt = max(stored, cur)
                    if nxt > stored:
                        self._append_sqlite(
                            conn,
                            scope_id=key,
                            event_kind="PEAK_RATCHET",
                            peak=nxt,
                            observed=cur,
                            owner_request_id=None,
                            ts_str=ts_str,
                        )
                else:
                    seed = max(cur, open_bal) if open_bal is not None else cur
                    if seed <= Decimal("0"):
                        raise ContractError("initial peak_equity seed must be positive")
                    nxt = seed
                    self._append_sqlite(
                        conn,
                        scope_id=key,
                        event_kind="PEAK_INIT",
                        peak=nxt,
                        observed=cur,
                        owner_request_id=None,
                        ts_str=ts_str,
                    )
                conn.execute("COMMIT")
                return nxt
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    def rearm_after_drawdown(
        self,
        scope_id: str,
        *,
        new_peak_equity: Decimal,
        owner_verifier: Any,
        owner_request_id: str,
        fence_request: Any | None = None,
        now: datetime | None = None,
    ) -> Decimal:
        """Reset high-water peak_equity ONLY after authenticated owner recovery verification."""
        if not isinstance(scope_id, str) or not scope_id.strip():
            raise ContractError("scope_id must be a non-empty string")
        if not isinstance(owner_request_id, str) or not owner_request_id.strip():
            raise ContractError("owner_request_id must be a non-empty string")
        new_peak = _safe_decimal(new_peak_equity)
        if new_peak is None or new_peak <= Decimal("0"):
            raise ContractError("new_peak_equity must be a positive finite Decimal")
        if owner_verifier is None:
            raise ContractError("authenticated owner recovery verifier required to re-arm peak_equity")

        check_time = now if isinstance(now, datetime) and now.tzinfo is not None else datetime.now(timezone.utc)
        verified = False
        verify_rearm = getattr(owner_verifier, "verify_drawdown_rearm", None)
        if callable(verify_rearm):
            verified = bool(
                verify_rearm(
                    scope_id=scope_id.strip(),
                    request_id=owner_request_id.strip(),
                    new_peak_equity=new_peak,
                    now=check_time,
                )
            )
        elif fence_request is not None and callable(getattr(owner_verifier, "verify", None)):
            if getattr(fence_request, "control", None) is ControlKind.RESUME_NEW_RISK and getattr(
                fence_request, "owner_request_id", None
            ) == owner_request_id.strip():
                approval = owner_verifier.verify(fence_request, now=check_time)
                verified = approval is not None and getattr(approval, "request_id", None) == owner_request_id.strip()
        if not verified:
            raise ContractError("owner drawdown re-arm verification failed; peak_equity unchanged")

        key = scope_id.strip()
        ts_str = _iso_utc(check_time)
        with self._lock:
            if self._path is None:
                self._memory[key] = new_peak
                return new_peak
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                self._append_sqlite(
                    conn,
                    scope_id=key,
                    event_kind="OWNER_DRAWDOWN_REARM",
                    peak=new_peak,
                    observed=new_peak,
                    owner_request_id=owner_request_id.strip(),
                    ts_str=ts_str,
                )
                conn.execute("COMMIT")
                return new_peak
            except Exception:
                conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()


def _proposal_scope_id(proposal: Any, current_view: Mapping[str, Any] | None) -> str:
    if isinstance(current_view, Mapping):
        vs = current_view.get("scope_id")
        if isinstance(vs, str) and vs.strip():
            return vs.strip()
    req = getattr(proposal, "request", None)
    state = getattr(req, "state", None)
    scope = getattr(state, "scope", None)
    acct = getattr(scope, "account_id", None)
    run = getattr(scope, "run_id", None)
    if isinstance(acct, str) and acct and isinstance(run, str) and run:
        return f"{acct}:{run}"
    if isinstance(current_view, Mapping):
        va = current_view.get("account_id")
        vp = current_view.get("plan_id")
        if isinstance(va, str) and va:
            return f"{va}:{vp or 'default'}"
        bal = _extract_money_decimal(current_view.get("balance"))
        if bal is not None:
            return f"view-scope:{decimal_text(bal)}"
    return "default-valve-scope"


def _extract_fact_accounting(request: Any) -> tuple[Decimal | None, Decimal | None, Decimal | None, bool]:
    """Extract (current_equity, balance, peak_equity, explicit_peak_present) from DecisionRequest facts."""
    cur_eq: Decimal | None = None
    bal_eq: Decimal | None = None
    peak_eq: Decimal | None = None
    explicit_peak = False
    invalid_cur_eq = False
    invalid_peak_eq = False
    for f in getattr(request, "facts", ()):
        label = getattr(f, "label", "")
        raw_val = getattr(f, "value", "")
        fid = getattr(f, "fact_id", "")
        label_lower = _strip_bom_and_ws(label).lower() if isinstance(label, str) else ""
        if label_lower == "equity" or fid.startswith("observed-equity"):
            cand_eq = _extract_money_decimal(raw_val)
            if cand_eq is None:
                invalid_cur_eq = True
            else:
                cur_eq = cand_eq if cur_eq is None else min(cur_eq, cand_eq)
        elif label_lower == "balance" or fid.startswith("observed-balance"):
            cand_bal = _extract_money_decimal(raw_val)
            if cand_bal is not None:
                bal_eq = cand_bal if bal_eq is None else max(bal_eq, cand_bal)
        elif label_lower == "peak_equity" or fid.startswith("observed-peak_equity"):
            explicit_peak = True
            cand_peak = _extract_money_decimal(raw_val)
            if cand_peak is None:
                invalid_peak_eq = True
            else:
                peak_eq = cand_peak if peak_eq is None else max(peak_eq, cand_peak)
        elif fid.startswith("observed-") or label_lower == "account":
            parsed_json = _unwrap_observed_json(raw_val)
            if isinstance(parsed_json, dict):
                if "equity" in parsed_json:
                    cand_eq = _extract_money_decimal(parsed_json.get("equity"))
                    if cand_eq is None:
                        invalid_cur_eq = True
                    else:
                        cur_eq = cand_eq if cur_eq is None else min(cur_eq, cand_eq)
                if "balance" in parsed_json:
                    cand_bal = _extract_money_decimal(parsed_json.get("balance"))
                    if cand_bal is not None:
                        bal_eq = cand_bal if bal_eq is None else max(bal_eq, cand_bal)
                if "peak_equity" in parsed_json:
                    explicit_peak = True
                    cand_peak = _extract_money_decimal(parsed_json.get("peak_equity"))
                    if cand_peak is None:
                        invalid_peak_eq = True
                    else:
                        peak_eq = cand_peak if peak_eq is None else max(peak_eq, cand_peak)
    if invalid_cur_eq:
        cur_eq = None
    if invalid_peak_eq:
        peak_eq = None
    return cur_eq, bal_eq, peak_eq, explicit_peak


def _text_drift_and_injection(texts: list[str]) -> tuple[float, float]:
    joined = " ".join(t for t in texts if isinstance(t, str)).strip()
    lower = joined.lower()
    hits = sum(1 for marker in INJECTION_MARKERS if marker in lower)
    inj = _clamp01(hits / 1.0)  # Any explicit override/injection marker saturates signal

    tokens = [tok for tok in lower.replace(".", " ").replace(",", " ").split() if tok]
    if len(tokens) < 4:
        return inj, 0.0
    trigrams = [tuple(tokens[i : i + 3]) for i in range(len(tokens) - 2)]
    rep = 1.0 - (len(set(trigrams)) / len(trigrams)) if trigrams else 0.0
    uniq_deficit = max(0.0, 0.45 - (len(set(tokens)) / len(tokens))) / 0.45
    drift = _clamp01(0.65 * rep + 0.35 * uniq_deficit)
    return inj, drift


def extract_cognitive_valve_features(text: str, prompt: str = "") -> list[float]:
    inj, drift = _text_drift_and_injection([prompt, text])
    tokens = [t for t in text.lower().split() if t]
    n = len(tokens)
    if n >= 3:
        trigrams = [tuple(tokens[i : i + 3]) for i in range(n - 2)]
        rep3 = 1.0 - (len(set(trigrams)) / len(trigrams))
    else:
        rep3 = 0.0
    uniq_def = _clamp01(1.0 - (len(set(tokens)) / max(1, n)))
    lengths = [len(t) for t in tokens] or [0]
    mean_l = sum(lengths) / len(lengths)
    var_l = sum((x - mean_l) ** 2 for x in lengths) / len(lengths)
    lac = _clamp01((var_l / ((mean_l + 1.0) ** 2)))
    lower = text.lower()
    unbacked = _clamp01(
        sum(lower.count(w) for w in ("guaranteed", "risk-free", "certainty", "100%", "cannot lose", "infinite"))
        / 2.0
    )
    contradict = _clamp01(
        1.0 if ("unavailable" in lower and ("open " in lower or "buy " in lower or "sell " in lower)) else 0.0
    )
    overflow = _clamp01(max(0, len(text) - 1200) / 1200.0)
    return [
        _clamp01(rep3),
        uniq_def,
        lac,
        inj,
        unbacked,
        contradict,
        overflow,
        drift,
    ]


def extract_forex_valve_features(
    proposal: Any,
    *,
    current_view: Mapping[str, Any] | None = None,
    policy: Mapping[str, Any] | None = None,
    now: datetime | None = None,
    max_drawdown_pct: Decimal | str | None = DEFAULT_MAX_DRAWDOWN_PCT,
    peak_equity_store: PeakEquityStore | None = None,
    demo_max_drawdown_ceiling: Decimal = MAX_CONSTITUTIONAL_DRAWDOWN_PCT,
) -> tuple[list[float], list[str]]:
    """Extract 8-D safety feature vector and deterministic hard-veto reasons."""
    if policy is None and isinstance(current_view, Mapping) and "policy" in current_view and current_view["policy"] is not None:
        if not isinstance(current_view["policy"], Mapping):
            raise ContractError("current_view['policy'] must be a mapping")
        policy = current_view["policy"]

    request = proposal.request
    result = proposal.result
    intent = proposal.intent
    selection = result.selection

    vetoes: list[str] = []

    # 1. Missing required accounting facts (G-ABSENT)
    req_fields = list((policy or {}).get("accounting_required", ("balance", "equity", "available_margin", "position_inventory")))
    missing_count = 0
    if current_view is not None:
        for k in req_fields:
            val = current_view.get(k)
            if _is_unavailable_accounting_value(
                val,
                allow_list=(k not in _NUMERIC_ACCOUNTING_FIELDS),
                require_list=(k == "position_inventory"),
            ):
                missing_count += 1
    else:
        fact_map = {
            _strip_bom_and_ws(f.label).lower(): f.value
            for f in request.facts
            if isinstance(f.label, str)
        }
        for k in req_fields:
            k_lower = k.lower()
            if k_lower in fact_map and _is_unavailable_accounting_value(
                fact_map[k_lower],
                allow_list=(k not in _NUMERIC_ACCOUNTING_FIELDS),
                require_list=(k == "position_inventory"),
            ):
                missing_count += 1
        has_account_fact = False
        covered_req_fields: set[str] = set()
        for f in request.facts:
            f_label_lower = _strip_bom_and_ws(f.label).lower() if isinstance(f.label, str) else ""
            f_val_str = f.value if isinstance(f.value, str) else ""
            if "margin" in f_label_lower and ("null" in f_val_str.lower() or "unavailable" in f_val_str.lower()):
                missing_count = max(missing_count, 1)
            for k in req_fields:
                k_lower = k.lower()
                if f_label_lower == k_lower or f.fact_id == f"observed-{k}" or f.fact_id.startswith(f"observed-{k}-"):
                    if _is_unavailable_accounting_value(
                        f.value,
                        allow_list=(k not in _NUMERIC_ACCOUNTING_FIELDS),
                        require_list=(k == "position_inventory"),
                    ):
                        missing_count = max(missing_count, 1)
                    else:
                        covered_req_fields.add(k)
            is_account_fact = (
                f.fact_id == "observed-account"
                or f.fact_id.startswith("observed-account-")
                or f_label_lower == "account"
            )
            if is_account_fact:
                has_account_fact = True
                obs_acct = _unwrap_observed_json(f.value)
                if not isinstance(obs_acct, dict) or len(obs_acct) == 0:
                    missing_count = max(missing_count, 1)
            if f.fact_id.startswith("observed-") or f_label_lower == "account":
                obs_obj = _unwrap_observed_json(f.value)
                if isinstance(obs_obj, dict):
                    for k in req_fields:
                        if k in obs_obj:
                            if _is_unavailable_accounting_value(
                                obs_obj[k],
                                allow_list=(k not in _NUMERIC_ACCOUNTING_FIELDS),
                                require_list=(k == "position_inventory"),
                            ):
                                missing_count = max(missing_count, 1)
                            else:
                                covered_req_fields.add(k)
        if has_account_fact:
            missing_account_fields = sum(1 for k in req_fields if k not in covered_req_fields)
            if missing_account_fields > 0:
                missing_count = max(missing_count, missing_account_fields)
    missing_ratio = _clamp01(missing_count / max(1, len(req_fields)))
    if intent is not None and missing_count > 0:
        vetoes.append("MISSING_REQUIRED_ACCOUNTING")

    obs_bid: Decimal | None = None
    obs_ask: Decimal | None = None
    obs_pos_side: str | None = None
    obs_prev_stop: Decimal | None = None
    obs_pos_ambiguous = False
    raw_intent_inst = getattr(intent, "instrument_id", None) if intent is not None else None
    intent_inst = str(raw_intent_inst).strip().upper() if raw_intent_inst is not None and str(raw_intent_inst).strip() != "" else None
    raw_intent_target = getattr(intent, "target_id", None) if intent is not None else None
    intent_target = str(raw_intent_target).strip() if raw_intent_target is not None and str(raw_intent_target).strip() != "" else None

    def _consume_market_list(items: list[Any] | tuple[Any, ...]) -> None:
        nonlocal obs_bid, obs_ask
        chosen: dict[str, Any] | None = None
        for item in items:
            if not isinstance(item, dict):
                continue
            raw_inst = item.get("instrument_id")
            if raw_inst is None or str(raw_inst).strip() == "":
                raw_inst = item.get("symbol")
            item_inst = str(raw_inst).strip().upper() if raw_inst is not None and str(raw_inst).strip() != "" else None
            if intent_inst is not None and item_inst is not None and item_inst == intent_inst:
                chosen = item
                break
            if chosen is None and (intent_inst is None or item_inst is None):
                chosen = item
        if chosen is not None:
            if obs_bid is None:
                obs_bid = _safe_decimal(chosen.get("bid"))
            if obs_ask is None:
                obs_ask = _safe_decimal(chosen.get("ask"))

    def _consume_position_list(items: list[Any] | tuple[Any, ...]) -> None:
        nonlocal obs_pos_side, obs_prev_stop, obs_pos_ambiguous
        chosen: dict[str, Any] | None = None
        dict_count = 0
        for item in items:
            if not isinstance(item, dict):
                continue
            dict_count += 1
            raw_inst = item.get("instrument_id")
            if raw_inst is None or str(raw_inst).strip() == "":
                raw_inst = item.get("symbol")
            item_inst = str(raw_inst).strip().upper() if raw_inst is not None and str(raw_inst).strip() != "" else None
            if intent_inst is not None and item_inst is not None and item_inst != intent_inst:
                continue
            item_id: str | None = None
            for id_key in ("position_id", "position_ticket", "id", "ticket", "order_id"):
                cand_id = item.get(id_key)
                if cand_id is not None and str(cand_id).strip() != "":
                    item_id = str(cand_id).strip()
                    break
            if intent_target is not None and item_id is not None and item_id == intent_target:
                chosen = item
                break
            if chosen is None and len(items) == 1 and (intent_target is None or item_id is None):
                chosen = item
        if chosen is None and dict_count > 0:
            obs_pos_ambiguous = True
        if chosen is not None:
            raw_s = chosen.get("position_side") or chosen.get("side")
            if obs_pos_side is None and isinstance(raw_s, str):
                norm_s = raw_s.strip().upper()
                if norm_s in ("BUY", "SELL"):
                    obs_pos_side = norm_s
            if obs_prev_stop is None:
                for sk in ("stop_price", "stop", "stop_loss", "prev_stop", "previous_stop_price", "current_stop", "current_stop_price", "sl"):
                    cand = _safe_decimal(chosen.get(sk))
                    if cand is not None:
                        obs_prev_stop = cand
                        break

    def _consume_obs_dict(
        obs_meta: dict[str, Any],
        *,
        allow_market: bool = True,
        allow_positions: bool = True,
    ) -> None:
        nonlocal obs_bid, obs_ask, obs_pos_side, obs_prev_stop, obs_pos_ambiguous
        raw_inst = obs_meta.get("instrument_id")
        if raw_inst is None or str(raw_inst).strip() == "":
            raw_inst = obs_meta.get("symbol")
        item_inst = str(raw_inst).strip().upper() if raw_inst is not None and str(raw_inst).strip() != "" else None
        inst_matches = intent_inst is None or item_inst is None or item_inst == intent_inst
        if allow_market and inst_matches:
            if obs_bid is None:
                obs_bid = _safe_decimal(obs_meta.get("bid"))
            if obs_ask is None:
                obs_ask = _safe_decimal(obs_meta.get("ask"))

        if allow_positions:
            item_id: str | None = None
            for id_key in ("position_id", "position_ticket", "id", "ticket", "order_id"):
                cand_id = obs_meta.get(id_key)
                if cand_id is not None and str(cand_id).strip() != "":
                    item_id = str(cand_id).strip()
                    break
            pos_stop_keys = (
                "prev_stop",
                "previous_stop_price",
                "current_stop_price",
                "current_stop",
                "stop_price",
                "stop",
                "stop_loss",
                "sl",
            )
            target_matches = intent_target is None or item_id is None or item_id == intent_target
            if inst_matches and target_matches:
                if obs_pos_side is None:
                    for sk in ("position_side", "side"):
                        raw_s = obs_meta.get(sk)
                        if isinstance(raw_s, str):
                            norm_s = raw_s.strip().upper()
                            if norm_s in ("BUY", "SELL"):
                                obs_pos_side = norm_s
                                break
                if obs_prev_stop is None:
                    for pk in pos_stop_keys:
                        cand = _safe_decimal(obs_meta.get(pk))
                        if cand is not None:
                            obs_prev_stop = cand
                            break
            elif any(k in obs_meta for k in ("position_side", "side", *pos_stop_keys)):
                obs_pos_ambiguous = True

        if allow_market:
            for mk in ("current_market", "market"):
                mv = _unwrap_observed_json(obs_meta.get(mk))
                if isinstance(mv, (list, tuple)):
                    _consume_market_list(mv)
        if allow_positions:
            for pk in ("position_inventory", "positions"):
                pv = _unwrap_observed_json(obs_meta.get(pk))
                if isinstance(pv, (list, tuple)):
                    _consume_position_list(pv)

    cv_has_market = False
    cv_has_positions = False
    if isinstance(current_view, Mapping):
        _consume_obs_dict(current_view)
        cv_has_market = (obs_bid is not None or obs_ask is not None) or any(
            isinstance(mv, (list, tuple)) and len(mv) > 0
            for mv in (_unwrap_observed_json(current_view.get(mk)) for mk in ("current_market", "market"))
        )
        cv_has_positions = (obs_pos_side is not None or obs_prev_stop is not None or obs_pos_ambiguous) or any(
            isinstance(pv, (list, tuple)) and any(isinstance(it, dict) for it in pv)
            for pv in (_unwrap_observed_json(current_view.get(pk)) for pk in ("position_inventory", "positions"))
        )

    for f in request.facts:
        f_label_lower = _strip_bom_and_ws(f.label).lower() if isinstance(f.label, str) else ""
        if f.fact_id.startswith("observed-") or f_label_lower in ("account", "position_inventory", "positions", "current_market", "market"):
            obs_meta = _unwrap_observed_json(f.value)
            if isinstance(obs_meta, dict):
                _consume_obs_dict(
                    obs_meta,
                    allow_market=not cv_has_market,
                    allow_positions=not cv_has_positions,
                )
            elif isinstance(obs_meta, (list, tuple)):
                if f.fact_id.startswith("observed-current_market") or f.fact_id.startswith("observed-market") or f_label_lower in ("current_market", "market"):
                    if not cv_has_market:
                        _consume_market_list(obs_meta)
                elif f.fact_id.startswith("observed-position_inventory") or f.fact_id.startswith("observed-positions") or f_label_lower in ("position_inventory", "positions"):
                    if not cv_has_positions:
                        _consume_position_list(obs_meta)
                else:
                    if not cv_has_market and any(isinstance(it, dict) and ("bid" in it or "ask" in it) for it in obs_meta):
                        _consume_market_list(obs_meta)
                    if not cv_has_positions and any(isinstance(it, dict) and any(k in it for k in ("side", "position_side", "stop_price", "stop", "stop_loss")) for it in obs_meta):
                        _consume_position_list(obs_meta)

    _amend_is_monotonic_tightening = False
    if intent is not None and intent.kind is ActionKind.AMEND_STOP:
        _raw_am_stop = getattr(intent, "stop_price", None)
        _am_stop_p = _safe_decimal(_raw_am_stop)
        _am_side = obs_pos_side.upper() if isinstance(obs_pos_side, str) else None
        if _raw_am_stop is None:
            _amend_is_monotonic_tightening = True
        elif (
            _am_stop_p is not None
            and _am_stop_p > Decimal("0")
            and _am_side in ("BUY", "SELL")
            and obs_prev_stop is not None
            and obs_prev_stop > Decimal("0")
        ):
            if _am_side == "BUY":
                _amend_is_monotonic_tightening = _am_stop_p >= obs_prev_stop and (obs_bid is None or _am_stop_p < obs_bid)
            else:
                _amend_is_monotonic_tightening = _am_stop_p <= obs_prev_stop and (obs_ask is None or _am_stop_p > obs_ask)

    # 1b. Peak-equity / maximum drawdown hard-floor gate on new-risk entries & non-tightening AMEND_STOP.
    # WAIT (intent is None) and risk-reducing/protective management (REDUCE, CLOSE, AMEND_STOP, CANCEL_ORDER)
    # remain available during drawdown.
    # Constitutional invariant (Finding [5]): max_drawdown_pct can NEVER exceed 0.10 (10.00%);
    # policy overrides may ONLY tighten below the immutable 10.00% ceiling.
    if (
        not isinstance(demo_max_drawdown_ceiling, Decimal)
        or not demo_max_drawdown_ceiling.is_finite()
        or demo_max_drawdown_ceiling <= Decimal("0")
        or demo_max_drawdown_ceiling > DEMO_HIGH_GROWTH_MAX_DRAWDOWN_PCT
    ):
        raise ContractError(
            f"demo_max_drawdown_ceiling must be Decimal in (0, {DEMO_HIGH_GROWTH_MAX_DRAWDOWN_PCT}]"
        )
    if intent is not None and (
        intent.kind in (ActionKind.OPEN, ActionKind.ADD)
        or (intent.kind is ActionKind.AMEND_STOP and not _amend_is_monotonic_tightening)
    ):
        pol_dict = policy if isinstance(policy, Mapping) else {}
        eff_dd_ceiling = demo_max_drawdown_ceiling
        dd_threshold: Decimal | None = None
        dd_invalid = False
        dd_ceiling_exceeded = False
        gate_dd: Decimal | None = None
        if max_drawdown_pct is not None:
            gate_dd = _safe_decimal(max_drawdown_pct)
            if gate_dd is None or gate_dd <= Decimal("0") or gate_dd >= Decimal("1"):
                dd_invalid = True
            elif gate_dd > eff_dd_ceiling:
                dd_ceiling_exceeded = True
                gate_dd = eff_dd_ceiling
        if "max_drawdown_pct" in pol_dict:
            pol_dd = _safe_decimal(pol_dict.get("max_drawdown_pct"))
            if pol_dd is None or pol_dd <= Decimal("0") or pol_dd >= Decimal("1"):
                dd_invalid = True
            elif pol_dd > eff_dd_ceiling:
                dd_ceiling_exceeded = True
                dd_threshold = (
                    min(gate_dd, eff_dd_ceiling)
                    if gate_dd is not None
                    else eff_dd_ceiling
                )
            else:
                dd_threshold = min(pol_dd, gate_dd) if gate_dd is not None else pol_dd
        elif gate_dd is not None:
            dd_threshold = min(gate_dd, eff_dd_ceiling)

        if dd_ceiling_exceeded:
            vetoes.append("CONSTITUTIONAL_DRAWDOWN_CEILING_EXCEEDED")
        if dd_invalid:
            missing_ratio = max(missing_ratio, 0.25)
            vetoes.append("MISSING_DRAWDOWN_ACCOUNTING")
        if not dd_invalid and dd_threshold is not None:
            require_explicit_peak = bool(pol_dict.get("require_peak_equity", False))
            if current_view is not None:
                cur_eq = _extract_money_decimal(current_view.get("equity"))
                bal_eq = _extract_money_decimal(current_view.get("balance"))
                explicit_peak = "peak_equity" in current_view
                peak_eq = _extract_money_decimal(current_view.get("peak_equity")) if explicit_peak else None
            else:
                cur_eq, bal_eq, peak_eq, explicit_peak = _extract_fact_accounting(request)

            if cur_eq is None or (explicit_peak and (peak_eq is None or peak_eq <= Decimal("0"))):
                missing_ratio = max(missing_ratio, 0.25)
                vetoes.append("MISSING_DRAWDOWN_ACCOUNTING")
            elif not explicit_peak and require_explicit_peak:
                missing_ratio = max(missing_ratio, 0.25)
                vetoes.append("MISSING_DRAWDOWN_ACCOUNTING")
            else:
                resolved_peak = peak_eq
                scope_id = _proposal_scope_id(proposal, current_view)
                if resolved_peak is None:
                    if bal_eq is None or max(cur_eq, bal_eq) <= Decimal("0"):
                        missing_ratio = max(missing_ratio, 0.25)
                        vetoes.append("MISSING_DRAWDOWN_ACCOUNTING")
                    elif peak_equity_store is not None:
                        resolved_peak = peak_equity_store.observe_equity(
                            scope_id,
                            current_equity=cur_eq,
                            opening_balance=bal_eq,
                            now=now,
                        )
                    else:
                        resolved_peak = max(cur_eq, bal_eq)
                elif peak_equity_store is not None:
                    stored_peak = peak_equity_store.observe_equity(
                        scope_id,
                        current_equity=cur_eq,
                        opening_balance=resolved_peak,
                        now=now,
                    )
                    resolved_peak = max(resolved_peak, stored_peak)

                if resolved_peak is not None and "MISSING_DRAWDOWN_ACCOUNTING" not in vetoes:
                    dd_pct = compute_drawdown_pct(cur_eq, resolved_peak)
                    if dd_pct >= dd_threshold:
                        vetoes.append("MAX_DRAWDOWN_EXCEEDED")

    # 2. Policy permission violation (from explicit policy OR observed-* JSON fact)
    perm_violation = 0.0
    if intent is not None:
        if policy is not None:
            if intent.kind in (ActionKind.OPEN, ActionKind.ADD):
                if policy.get("new_risk_permission") != "ALLOWED":
                    perm_violation = 1.0
                    vetoes.append("NEW_RISK_NOT_ALLOWED")
            else:
                if policy.get("management_permission") != "ALLOWED":
                    perm_violation = 1.0
                    vetoes.append("MANAGEMENT_NOT_ALLOWED")
        if current_view is None:
            for f in request.facts:
                f_label_lower = _strip_bom_and_ws(f.label).lower() if isinstance(f.label, str) else ""
                if f.fact_id.startswith("observed-") or f_label_lower == "account":
                    obs_obj = _unwrap_observed_json(f.value)
                    if isinstance(obs_obj, dict):
                        if intent.kind in (ActionKind.OPEN, ActionKind.ADD) and obs_obj.get("new_risk") is False:
                            perm_violation = 1.0
                            if "NEW_RISK_NOT_ALLOWED" not in vetoes:
                                vetoes.append("NEW_RISK_NOT_ALLOWED")
                        elif intent.kind not in (ActionKind.OPEN, ActionKind.ADD) and obs_obj.get("management") is False:
                            perm_violation = 1.0
                            if "MANAGEMENT_NOT_ALLOWED" not in vetoes:
                                vetoes.append("MANAGEMENT_NOT_ALLOWED")

    # 3. Entry quantity excess ratio
    qty_excess = 0.0
    if intent is not None and intent.kind in (ActionKind.OPEN, ActionKind.ADD):
        qty = _safe_decimal(intent.quantity)
        if qty is None or qty <= Decimal("0"):
            qty_excess = 1.0
            vetoes.append("INVALID_ENTRY_QUANTITY")
        elif policy is not None and "max_entry_quantity" in policy:
            max_q = _safe_decimal(policy["max_entry_quantity"])
            if max_q is not None and max_q <= Decimal("0"):
                qty_excess = 1.0
                vetoes.append("ZERO_MAX_ENTRY_POLICY")
            elif max_q is not None and qty > max_q:
                qty_excess = _clamp01(float((qty - max_q) / max_q))
                if qty_excess == 0.0:
                    qty_excess = 0.01
                vetoes.append("QUANTITY_EXCEEDS_MAX_ENTRY")

    # 4. Unbacked or missing evidence citations on action proposals
    supplied_eids = {e.evidence_id for e in request.evidence}
    cited_eids = tuple(selection.evidence_ids)
    if intent is not None:
        if not cited_eids or any(eid not in supplied_eids for eid in cited_eids):
            unbacked_ev = 1.0
            vetoes.append("UNBACKED_OR_EMPTY_EVIDENCE")
        else:
            unbacked_ev = 0.0
    else:
        unbacked_ev = 1.0 if any(eid not in supplied_eids for eid in cited_eids) else 0.0

    # 5 & 8. Prompt injection pressure & reasoning drift
    fact_texts = [selection.reason]
    for f in request.facts:
        if "presentation" in f.fact_id or "untrusted" in f.fact_id or "untrusted" in f.label.lower():
            fact_texts.append(f.value)
    inj_signal, drift_score = _text_drift_and_injection(fact_texts)
    reason_inj, _ = _text_drift_and_injection([selection.reason])
    if intent is not None and reason_inj > 0.0:
        vetoes.append("PROMPT_INJECTION_IN_REASON")

    # 6. Protective stop and resting take-profit geometry checks
    stop_deficit = 0.0
    raw_tp = getattr(intent, "take_profit_price", None) if intent is not None else None
    tp_p = _safe_decimal(raw_tp) if intent is not None else None
    if intent is not None and intent.kind in (ActionKind.OPEN, ActionKind.ADD):
        stop_p = _safe_decimal(intent.stop_price)
        limit_p = _safe_decimal(intent.limit_price)
        side_val = intent.side.value if hasattr(intent.side, "value") else str(intent.side)
        if stop_p is None or stop_p <= Decimal("0"):
            stop_deficit = 1.0
            vetoes.append("MISSING_PROTECTIVE_STOP")
        elif side_val == "BUY":
            marketable_buy = limit_p is None or (obs_ask is not None and limit_p >= obs_ask)
            if (limit_p is not None and stop_p >= limit_p) or (
                marketable_buy and obs_bid is not None and stop_p >= obs_bid
            ):
                stop_deficit = 1.0
                vetoes.append("INVERTED_BUY_PROTECTIVE_STOP")
        elif side_val == "SELL":
            marketable_sell = limit_p is None or (obs_bid is not None and limit_p <= obs_bid)
            if (limit_p is not None and stop_p <= limit_p) or (
                marketable_sell and obs_ask is not None and stop_p <= obs_ask
            ):
                stop_deficit = 1.0
                vetoes.append("INVERTED_SELL_PROTECTIVE_STOP")
        if raw_tp is not None:
            if tp_p is None or tp_p <= Decimal("0"):
                stop_deficit = 1.0
                vetoes.append("INVALID_TAKE_PROFIT_PRICE")
            elif side_val == "BUY" and (
                (stop_p is not None and tp_p <= stop_p)
                or (limit_p is not None and tp_p <= limit_p)
                or (obs_ask is not None and tp_p <= obs_ask)
            ):
                stop_deficit = 1.0
                vetoes.append("INVERTED_BUY_TAKE_PROFIT")
            elif side_val == "SELL" and (
                (stop_p is not None and tp_p >= stop_p)
                or (limit_p is not None and tp_p >= limit_p)
                or (obs_bid is not None and tp_p >= obs_bid)
            ):
                stop_deficit = 1.0
                vetoes.append("INVERTED_SELL_TAKE_PROFIT")
    elif intent is not None and intent.kind is ActionKind.AMEND_STOP:
        raw_stop = getattr(intent, "stop_price", None)
        stop_p = _safe_decimal(raw_stop)
        amend_side = obs_pos_side.upper() if isinstance(obs_pos_side, str) else None
        if raw_stop is None:
            stop_deficit = 1.0
            vetoes.append("MISSING_PROTECTIVE_STOP")
        elif stop_p is None or stop_p <= Decimal("0"):
            stop_deficit = 1.0
            vetoes.append("INVALID_PROTECTIVE_STOP")
        elif amend_side not in ("BUY", "SELL"):
            stop_deficit = 1.0
            vetoes.append("MISSING_POSITION_SIDE")
        elif obs_prev_stop is None or obs_prev_stop <= Decimal("0"):
            stop_deficit = 1.0
            vetoes.append("MISSING_AUTHORITATIVE_PREVIOUS_STOP")
        else:
            if amend_side == "BUY":
                if obs_bid is not None and stop_p >= obs_bid:
                    stop_deficit = 1.0
                    vetoes.append("INVERTED_BUY_PROTECTIVE_STOP")
                elif stop_p < obs_prev_stop:
                    stop_deficit = 1.0
                    vetoes.append("LOOSENED_BUY_PROTECTIVE_STOP")
            elif amend_side == "SELL":
                if obs_ask is not None and stop_p <= obs_ask:
                    stop_deficit = 1.0
                    vetoes.append("INVERTED_SELL_PROTECTIVE_STOP")
                elif stop_p > obs_prev_stop:
                    stop_deficit = 1.0
                    vetoes.append("LOOSENED_SELL_PROTECTIVE_STOP")
        if raw_tp is not None:
            if tp_p is None or tp_p <= Decimal("0"):
                stop_deficit = 1.0
                vetoes.append("INVALID_TAKE_PROFIT_PRICE")
            elif amend_side == "BUY" and (
                (stop_p is not None and stop_p > Decimal("0") and tp_p <= stop_p)
                or (obs_ask is not None and tp_p <= obs_ask)
            ):
                stop_deficit = 1.0
                vetoes.append("INVERTED_BUY_TAKE_PROFIT")
            elif amend_side == "SELL" and (
                (stop_p is not None and stop_p > Decimal("0") and tp_p >= stop_p)
                or (obs_bid is not None and tp_p >= obs_bid)
            ):
                stop_deficit = 1.0
                vetoes.append("INVERTED_SELL_TAKE_PROFIT")

    # 7. Quote / state staleness ratio
    staleness = 0.0
    check_now = now or request.state.observed_at
    ttl = (request.state.valid_until - request.state.observed_at).total_seconds()
    if ttl <= 0:
        staleness = 1.0
        if intent is not None:
            vetoes.append("NONPOSITIVE_STATE_TTL")
    else:
        age = (check_now - request.state.observed_at).total_seconds()
        if age < 0 or check_now >= request.state.valid_until:
            staleness = 1.0
            if intent is not None:
                vetoes.append("STALE_OR_FUTURE_STATE")
        else:
            staleness = _clamp01(age / ttl)

    vec = [
        missing_ratio,
        perm_violation,
        qty_excess,
        unbacked_ev,
        inj_signal,
        stop_deficit,
        staleness,
        drift_score,
    ]
    return vec, vetoes


def _finite_float(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a finite numeric value")
    out = float(value)
    if not math.isfinite(out):
        raise ContractError(f"{field} must be finite")
    return out


class TKSMetaValveController:
    """Deterministic 8 -> 16 (tanh) -> 1 (sigmoid) MLP controller (161 parameters)."""

    def __init__(
        self,
        *,
        w1: list[list[float]],
        b1: list[float],
        w2: list[float],
        b2: float,
        threshold: float = 0.55,
        feature_names: tuple[str, ...] = FOREX_FEATURE_NAMES,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if (
            not isinstance(w1, (list, tuple))
            or not isinstance(b1, (list, tuple))
            or not isinstance(w2, (list, tuple))
            or len(w1) != 16
            or any(not isinstance(row, (list, tuple)) or len(row) != 8 for row in w1)
            or len(b1) != 16
            or len(w2) != 16
        ):
            raise ContractError("TKSMetaValveController requires exact 8->16->1 weight geometry (161 params)")
        self.w1 = [[_finite_float(v, f"w1[{i}][{j}]") for j, v in enumerate(row)] for i, row in enumerate(w1)]
        self.b1 = [_finite_float(v, f"b1[{i}]") for i, v in enumerate(b1)]
        self.w2 = [_finite_float(v, f"w2[{i}]") for i, v in enumerate(w2)]
        self.b2 = _finite_float(b2, "b2")
        self.threshold = _finite_float(threshold, "threshold")
        if not (0.0 < self.threshold < 1.0):
            raise ContractError("TKSMetaValveController threshold must satisfy 0.0 < threshold < 1.0")
        self.feature_names = tuple(feature_names)
        self.metadata = dict(metadata or {})

    @property
    def parameter_count(self) -> int:
        return sum(len(r) for r in self.w1) + len(self.b1) + len(self.w2) + 1

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema": "tks.meta-valve.weights/1.0",
            "architecture": "8->16(tanh)->1(sigmoid)",
            "parameter_count": self.parameter_count,
            "threshold": self.threshold,
            "feature_names": list(self.feature_names),
            "w1": self.w1,
            "b1": self.b1,
            "w2": self.w2,
            "b2": self.b2,
            "metadata": self.metadata,
        }

    def weights_sha256(self) -> str:
        core = {
            "architecture": "8->16(tanh)->1(sigmoid)",
            "threshold": _fmt8(self.threshold),
            "w1": [[_fmt8(x) for x in r] for r in self.w1],
            "b1": [_fmt8(x) for x in self.b1],
            "w2": [_fmt8(x) for x in self.w2],
            "b2": _fmt8(self.b2),
        }
        return sha256(canonical_bytes(core)).hexdigest()

    def forward(self, x: list[float]) -> float:
        if not isinstance(x, (list, tuple)) or len(x) != 8:
            raise ContractError("TKSMetaValveController requires an 8-element feature vector")
        vec = [_finite_float(x_j, f"x[{j}]") for j, x_j in enumerate(x)]
        hidden = [
            math.tanh(sum(w_ij * x_j for w_ij, x_j in zip(row, vec)) + bias)
            for row, bias in zip(self.w1, self.b1)
        ]
        logit = sum(w_i * h_i for w_i, h_i in zip(self.w2, hidden)) + self.b2
        return _sigmoid(logit)

    def save_weights(self, path: Path) -> str:
        raw = json.dumps(self.to_payload(), indent=2, sort_keys=True).encode("utf-8") + b"\n"
        path.write_bytes(raw)
        return sha256(raw).hexdigest()

    @classmethod
    def load_weights(cls, path: Path) -> "TKSMetaValveController":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ContractError("TKSMetaValveController weights payload must be a JSON object")
        param_cnt = data.get("parameter_count")
        if type(param_cnt) is not int or param_cnt != 161:
            raise ContractError("TKSMetaValveController weights payload parameter_count must equal 161")
        return cls(
            w1=data["w1"],
            b1=data["b1"],
            w2=data["w2"],
            b2=data["b2"],
            threshold=data.get("threshold", 0.55),
            feature_names=tuple(data.get("feature_names", FOREX_FEATURE_NAMES)),
            metadata=data.get("metadata", {}),
        )


class ForexMetaValveGate:
    """Runtime admission valve wired into RehearsalWiring, CaseRuntime, and trajectory driver."""

    def __init__(
        self,
        controller: TKSMetaValveController,
        *,
        default_policy: dict[str, Any] | None = None,
        max_drawdown_pct: Decimal | str | None = DEFAULT_MAX_DRAWDOWN_PCT,
        peak_equity_store: PeakEquityStore | None = None,
        demo_high_growth: DemoHighGrowthProfile | None = None,
    ) -> None:
        if not isinstance(controller, TKSMetaValveController):
            raise ContractError("ForexMetaValveGate requires a typed TKSMetaValveController")
        if demo_high_growth is not None and not isinstance(demo_high_growth, DemoHighGrowthProfile):
            raise ContractError("demo_high_growth must be a DemoHighGrowthProfile or None")
        self.controller = controller
        if default_policy is not None:
            if not isinstance(default_policy, Mapping):
                raise ContractError("default_policy must be a mapping")
            if "max_drawdown_pct" in default_policy:
                validate_constitutional_drawdown_pct(
                    default_policy.get("max_drawdown_pct"),
                    field="default_policy['max_drawdown_pct']",
                    allow_none=False,
                )
        self.default_policy = deepcopy(default_policy) if default_policy is not None else None
        self._base_max_drawdown_pct: Decimal | None = validate_constitutional_drawdown_pct(
            max_drawdown_pct,
            field="max_drawdown_pct",
            allow_none=True,
        )
        self._demo_high_growth: DemoHighGrowthProfile = (
            demo_high_growth if demo_high_growth is not None else DemoHighGrowthProfile(enabled=False)
        )
        self.max_drawdown_pct: Decimal | None = (
            self._demo_high_growth.max_drawdown_pct
            if self._demo_high_growth.enabled
            else self._base_max_drawdown_pct
        )
        self.peak_equity_store = peak_equity_store if peak_equity_store is not None else PeakEquityStore()
        self._weights_sha256 = controller.weights_sha256()
        self._gate_id = secrets.token_hex(16)

    def effective_drawdown_ceiling_pct(self) -> Decimal:
        return self._demo_high_growth.effective_drawdown_ceiling_pct()

    def set_demo_high_growth_profile(
        self,
        profile: DemoHighGrowthProfile,
        *,
        execution_mode: Any = "DEMO",
        live_trading_armed: bool = False,
        live_trading_locked: bool = True,
    ) -> None:
        if not isinstance(profile, DemoHighGrowthProfile):
            raise ContractError("profile must be a DemoHighGrowthProfile")
        profile.assert_demo_mode(
            execution_mode,
            live_trading_armed=live_trading_armed,
            live_trading_locked=live_trading_locked,
        )
        self._demo_high_growth = profile
        self.max_drawdown_pct = (
            profile.max_drawdown_pct if profile.enabled else self._base_max_drawdown_pct
        )

    @property
    def weights_sha256(self) -> str:
        return self._weights_sha256

    @property
    def gate_id(self) -> str:
        return self._gate_id

    def _mint_decision(
        self,
        *,
        admitted: bool,
        valve_mode: str,
        mlp_score: float,
        threshold: float,
        mlp_admitted: bool,
        hard_veto: bool,
        hard_veto_reasons: tuple[str, ...],
        features: Mapping[str, float],
        request_id: str,
        selected_action_ref: str | None,
        issued_at: datetime,
        expires_at: datetime,
        bound_action_kind: str = "",
        bound_symbol: str = "",
        bound_side: str = "",
        bound_quantity: str = "",
        bound_stop_price: str = "",
        bound_take_profit_price: str = "",
        bound_limit_price: str = "",
        bound_target_id: str = "",
    ) -> ValveDecision:
        nonce = secrets.token_hex(16)
        bound_payload = {
            "request_id": request_id,
            "selected_action_ref": selected_action_ref,
            "action_kind": bound_action_kind,
            "symbol": bound_symbol,
            "side": bound_side,
            "quantity": bound_quantity,
            "stop_price": bound_stop_price,
            "take_profit_price": bound_take_profit_price,
            "limit_price": bound_limit_price,
            "target_id": bound_target_id,
        }
        bound_digest = sha256(canonical_bytes(bound_payload)).hexdigest()
        seal_in = _canonical_decision_seal_input(
            admitted=admitted,
            valve_mode=valve_mode,
            mlp_score=mlp_score,
            threshold=threshold,
            mlp_admitted=mlp_admitted,
            hard_veto=hard_veto,
            hard_veto_reasons=hard_veto_reasons,
            weights_sha256=self._weights_sha256,
            request_id=request_id,
            selected_action_ref=selected_action_ref,
            gate_id=self._gate_id,
            decision_nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
            bound_intent_digest=bound_digest,
            bound_action_kind=bound_action_kind,
            bound_symbol=bound_symbol,
            bound_side=bound_side,
            bound_quantity=bound_quantity,
            bound_stop_price=bound_stop_price,
            bound_take_profit_price=bound_take_profit_price,
            bound_limit_price=bound_limit_price,
            bound_target_id=bound_target_id,
        )
        seal = _sign_valve_payload(seal_in)
        return ValveDecision(
            admitted=admitted,
            valve_mode=valve_mode,
            mlp_score=mlp_score,
            threshold=threshold,
            mlp_admitted=mlp_admitted,
            hard_veto=hard_veto,
            hard_veto_reasons=hard_veto_reasons,
            features=features,
            weights_sha256=self._weights_sha256,
            request_id=request_id,
            selected_action_ref=selected_action_ref,
            _mint_token=_VALVE_DECISION_SENTINEL,
            _decision_seal=seal,
            _gate_id=self._gate_id,
            _decision_nonce=nonce,
            _issued_at=issued_at,
            _expires_at=expires_at,
            _bound_intent_digest=bound_digest,
            _bound_action_kind=bound_action_kind,
            _bound_symbol=bound_symbol,
            _bound_side=bound_side,
            _bound_quantity=bound_quantity,
            _bound_stop_price=bound_stop_price,
            _bound_take_profit_price=bound_take_profit_price,
            _bound_limit_price=bound_limit_price,
            _bound_target_id=bound_target_id,
        )

    def evaluate(
        self,
        proposal: Any,
        *,
        current_view: Mapping[str, Any] | None = None,
        policy: Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> ValveDecision:
        if policy is not None:
            eff_policy = policy
        elif isinstance(current_view, Mapping) and "policy" in current_view and current_view["policy"] is not None:
            if not isinstance(current_view["policy"], Mapping):
                raise ContractError("current_view['policy'] must be a mapping")
            eff_policy = current_view["policy"]
        else:
            eff_policy = self.default_policy
        vec, vetoes = extract_forex_valve_features(
            proposal,
            current_view=current_view,
            policy=eff_policy,
            now=now,
            max_drawdown_pct=self.max_drawdown_pct,
            peak_equity_store=self.peak_equity_store,
            demo_max_drawdown_ceiling=self.effective_drawdown_ceiling_pct(),
        )
        feature_map = {name: val for name, val in zip(FOREX_FEATURE_NAMES, vec)}
        score = self.controller.forward(vec)
        mlp_ok = score >= self.controller.threshold
        req_state = getattr(proposal.request, "state", None)
        obs_at = getattr(req_state, "observed_at", None)
        valid_until = getattr(req_state, "valid_until", None)
        if now is not None:
            issued_dt = utc_time(now, "now")
        elif obs_at is not None:
            issued_dt = utc_time(obs_at, "observed_at")
        else:
            issued_dt = datetime.now(timezone.utc)
        default_exp = issued_dt + timedelta(seconds=DEFAULT_VALVE_DECISION_TTL_SECONDS)
        if valid_until is not None:
            vu_dt = utc_time(valid_until, "valid_until")
            expires_dt = min(vu_dt, default_exp) if vu_dt > issued_dt else (issued_dt + timedelta(seconds=1))
        else:
            expires_dt = default_exp
        if proposal.intent is None:
            return self._mint_decision(
                admitted=True,
                valve_mode="WAIT_BYPASS",
                mlp_score=score,
                threshold=self.controller.threshold,
                mlp_admitted=True,
                hard_veto=False,
                hard_veto_reasons=(),
                features=feature_map,
                request_id=proposal.request.request_id,
                selected_action_ref=None,
                issued_at=issued_dt,
                expires_at=expires_dt,
            )
        intent = proposal.intent
        b_kind = intent.kind.value if hasattr(intent.kind, "value") else str(intent.kind)
        b_sym = _norm_grant_symbol(getattr(intent, "instrument_id", None) or getattr(intent, "symbol", None) or "")
        raw_side = getattr(intent, "side", None)
        try:
            b_side = _norm_grant_side(raw_side)
        except ValveGrantError:
            b_side = ""
        raw_qty = getattr(intent, "quantity", None)
        if raw_qty is None:
            raw_qty = getattr(intent, "quantity_units", None)
        try:
            b_qty = _norm_grant_decimal(raw_qty)
        except ValveGrantError:
            b_qty = ""
        try:
            b_stop = _norm_grant_decimal(getattr(intent, "stop_price", None))
        except ValveGrantError:
            b_stop = ""
        try:
            b_tp = _norm_grant_decimal(getattr(intent, "take_profit_price", None))
        except ValveGrantError:
            b_tp = ""
        try:
            b_limit = _norm_grant_decimal(getattr(intent, "limit_price", None))
        except ValveGrantError:
            b_limit = ""
        b_target = str(getattr(intent, "target_id", None) or getattr(intent, "position_ticket", None) or "").strip()
        hard_veto = len(vetoes) > 0
        admitted = bool(mlp_ok and not hard_veto)
        mode = (
            "ADMIT"
            if admitted
            else ("HARD_FLOOR_AND_MLP_VETO" if (hard_veto and not mlp_ok) else ("HARD_FLOOR_VETO" if hard_veto else "MLP_SCORE_VETO"))
        )
        return self._mint_decision(
            admitted=admitted,
            valve_mode=mode,
            mlp_score=score,
            threshold=self.controller.threshold,
            mlp_admitted=mlp_ok,
            hard_veto=hard_veto,
            hard_veto_reasons=tuple(vetoes),
            features=feature_map,
            request_id=proposal.request.request_id,
            selected_action_ref=proposal.result.selection.selected_action_ref,
            issued_at=issued_dt,
            expires_at=expires_dt,
            bound_action_kind=b_kind,
            bound_symbol=b_sym,
            bound_side=b_side,
            bound_quantity=b_qty,
            bound_stop_price=b_stop,
            bound_take_profit_price=b_tp,
            bound_limit_price=b_limit,
            bound_target_id=b_target,
        )

    def require_admissible(
        self,
        proposal: Any,
        *,
        current_view: Mapping[str, Any] | None = None,
        policy: Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> ValveDecision:
        dec = self.evaluate(proposal, current_view=current_view, policy=policy, now=now)
        if not dec.admitted:
            reasons = ",".join(dec.hard_veto_reasons) if dec.hard_veto_reasons else f"mlp_score={dec.mlp_score:.6f}<{dec.threshold:.6f}"
            raise ValveRefusalError(f"ForexMetaValveGate blocked unsafe proposal ({dec.valve_mode}): {reasons}", decision=dec)
        return dec

    def _mint_and_register_grant(
        self,
        *,
        broker_id: str,
        account_id: str | int,
        server: str,
        execution_mode: str,
        action_kind: ActionKind | str,
        symbol: str,
        side: Any,
        volume: Decimal | str | None,
        stop_loss: Decimal | str | None,
        take_profit: Decimal | str | None,
        position_ticket: str | None,
        decision_sha256: str,
        now: datetime | None,
        ttl_seconds: float,
        previous_stop_loss: Decimal | str | None = None,
        require_risk_reducing: bool = False,
        decision_target_key: tuple[str, str, str] | None = None,
        decision_expires_at: datetime | None = None,
        decision: ValveDecision | None = None,
    ) -> ValveOrderGrant:
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, (int, float)):
            raise ValveGrantError("ttl_seconds must be a finite number in (0, 300]")
        ttl_f = float(ttl_seconds)
        if not math.isfinite(ttl_f) or ttl_f <= 0.0 or ttl_f > MAX_VALVE_GRANT_TTL_SECONDS:
            raise ValveGrantError(f"ttl_seconds must be in (0, {MAX_VALVE_GRANT_TTL_SECONDS}]")
        norm_broker = str(broker_id or "").strip().upper()
        norm_acct = str(account_id or "").strip()
        norm_srv = str(server or "").strip()
        if not norm_broker or not norm_acct or not norm_srv:
            raise ValveGrantError("ValveOrderGrant requires non-empty broker_id, account_id, and server")
        norm_mode = _norm_grant_execution_mode(execution_mode)
        norm_act = _norm_grant_action(action_kind)
        norm_sym = _norm_grant_symbol(symbol)
        if not norm_sym:
            raise ValveGrantError("ValveOrderGrant requires a non-empty symbol")
        norm_side = _norm_grant_side(side)
        norm_vol = _norm_grant_decimal(volume)
        norm_sl = _norm_grant_decimal(stop_loss)
        norm_tp = _norm_grant_decimal(take_profit)
        norm_ticket = str(position_ticket or "").strip()
        norm_prev_sl = _norm_grant_decimal(previous_stop_loss)
        issued_dt = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        expires_dt = issued_dt + timedelta(seconds=ttl_f)
        grant_nonce = secrets.token_hex(16)
        if norm_act in RISK_REDUCING_ACTION_KINDS:
            risk_reducing = True
        elif norm_act == "AMEND_STOP":
            risk_reducing = _is_monotonic_tightening_amend(
                side=norm_side,
                stop_loss=norm_sl,
                previous_stop_loss=norm_prev_sl,
            )
            if require_risk_reducing and not risk_reducing:
                raise ValveGrantError(
                    "Risk-reducing AMEND_STOP grant requires authoritative side and non-widening stop vs previous_stop_loss",
                    decision=decision,
                )
        else:
            risk_reducing = False
        order_digest = _canonical_grant_order_digest(
            broker_id=norm_broker,
            account_id=norm_acct,
            server=norm_srv,
            execution_mode=norm_mode,
            action_kind=norm_act,
            symbol=norm_sym,
            side=norm_side,
            volume=norm_vol,
            stop_loss=norm_sl,
            take_profit=norm_tp,
            position_ticket=norm_ticket,
            grant_nonce=grant_nonce,
            issued_at=issued_dt,
            expires_at=expires_dt,
            previous_stop_loss=norm_prev_sl,
        )
        sig_input = _canonical_grant_sig_input(
            order_digest_sha256=order_digest,
            weights_sha256=self._weights_sha256,
            decision_sha256=decision_sha256,
            risk_reducing=risk_reducing,
            gate_id=self._gate_id,
        )
        sig_hex = _sign_valve_payload(sig_input)
        grant = ValveOrderGrant(
            broker_id=norm_broker,
            account_id=norm_acct,
            server=norm_srv,
            execution_mode=norm_mode,
            action_kind=norm_act,
            symbol=norm_sym,
            side=norm_side,
            volume=norm_vol,
            stop_loss=norm_sl,
            take_profit=norm_tp,
            position_ticket=norm_ticket,
            grant_nonce=grant_nonce,
            issued_at=issued_dt,
            expires_at=expires_dt,
            weights_sha256=self._weights_sha256,
            decision_sha256=decision_sha256,
            risk_reducing=risk_reducing,
            order_digest_sha256=order_digest,
            signature_hmac_sha256=sig_hex,
            previous_stop_loss=norm_prev_sl,
            _mint_token=_VALVE_GRANT_SENTINEL,
            _gate_id=self._gate_id,
        )
        with _GRANT_LEDGER_LOCK:
            _prune_valve_replay_ledgers_locked(issued_dt)
            if decision_target_key is not None:
                if decision_target_key in _CONSUMED_DECISION_TARGETS:
                    raise ValveGrantError(
                        f"ValveDecision replay refused for {norm_broker}/{norm_acct}",
                        decision=decision,
                    )
                if len(_CONSUMED_DECISION_TARGETS) >= MAX_VALVE_REPLAY_LEDGER_ENTRIES:
                    raise ValveGrantError(
                        f"Valve consumed decision replay ledger saturated ({MAX_VALVE_REPLAY_LEDGER_ENTRIES}); failing closed",
                        decision=decision,
                    )
            if len(_ISSUED_UNCONSUMED_GRANTS) >= MAX_VALVE_REPLAY_LEDGER_ENTRIES:
                raise ValveGrantError(
                    f"Valve issued grant ledger saturated ({MAX_VALVE_REPLAY_LEDGER_ENTRIES}); failing closed",
                    decision=decision,
                )
            if decision_target_key is not None:
                eff_dec_exp = (
                    utc_time(decision_expires_at, "decision.expires_at")
                    if decision_expires_at is not None
                    else (issued_dt + timedelta(seconds=DEFAULT_VALVE_DECISION_TTL_SECONDS))
                )
                _CONSUMED_DECISION_TARGETS[decision_target_key] = eff_dec_exp
            _ISSUED_UNCONSUMED_GRANTS[grant_nonce] = (order_digest, expires_dt)
        return grant

    def issue_order_grant(
        self,
        decision: ValveDecision,
        *,
        broker_id: str,
        account_id: str | int,
        server: str,
        execution_mode: str,
        action_kind: ActionKind | str,
        symbol: str,
        side: Any = None,
        volume: Decimal | str | None = None,
        stop_loss: Decimal | str | None = None,
        take_profit: Decimal | str | None = None,
        position_ticket: str | None = None,
        order_action_ref: str | None = None,
        order_quantity_units: Decimal | str | None = None,
        order_side: Any = None,
        order_stop_price: Decimal | str | None = None,
        order_take_profit_price: Decimal | str | None = None,
        order_limit_price: Decimal | str | None = None,
        previous_stop_loss: Decimal | str | None = None,
        require_risk_reducing: bool = False,
        now: datetime | None = None,
        ttl_seconds: float = DEFAULT_VALVE_GRANT_TTL_SECONDS,
    ) -> ValveOrderGrant:
        """Issue an opaque, single-use, exact-order-bound ValveOrderGrant from an admitted ValveDecision."""
        if not isinstance(decision, ValveDecision):
            raise ValveGrantError("issue_order_grant requires a gate-minted ValveDecision")
        check_now = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        decision.verify_provenance(expected_weights_sha256=self._weights_sha256, now=check_now)
        if not decision.admitted or decision.valve_mode != "ADMIT" or decision.hard_veto or not decision.mlp_admitted:
            raise ValveGrantError(
                f"ForexMetaValveGate did not admit this decision ({decision.valve_mode})", decision=decision
            )
        if decision.mlp_score < decision.threshold:
            raise ValveGrantError("ForexMetaValveGate score below threshold", decision=decision)
        norm_act = _norm_grant_action(action_kind)
        eff_rr_allowed = RISK_REDUCING_ACTION_KINDS | CONDITIONAL_MANAGEMENT_ACTION_KINDS
        if require_risk_reducing and norm_act not in eff_rr_allowed:
            raise ValveGrantError(
                f"Risk-reducing grant requested, refusing {norm_act!r}", decision=decision
            )
        eff_action_ref = decision.selected_action_ref if order_action_ref is None else order_action_ref
        if not isinstance(eff_action_ref, str) or not eff_action_ref.strip():
            raise ValveGrantError("ValveDecision missing selected_action_ref", decision=decision)
        decision.assert_binds_order(
            action_ref=eff_action_ref,
            action_kind=norm_act,
            symbol=symbol,
            side=(side if order_side is None else order_side),
            quantity_units=(volume if order_quantity_units is None else order_quantity_units),
            stop_price=(stop_loss if order_stop_price is None else order_stop_price),
            take_profit_price=(take_profit if order_take_profit_price is None else order_take_profit_price),
            limit_price=order_limit_price,
            position_ticket=position_ticket,
        )
        norm_broker = str(broker_id or "").strip().upper()
        norm_acct = str(account_id or "").strip()
        target_key = (decision.decision_nonce, norm_broker, norm_acct)
        decision_sha = sha256(canonical_bytes(decision.to_dict())).hexdigest()
        return self._mint_and_register_grant(
            broker_id=norm_broker,
            account_id=norm_acct,
            server=server,
            execution_mode=execution_mode,
            action_kind=norm_act,
            symbol=symbol,
            side=side,
            volume=volume,
            stop_loss=stop_loss,
            take_profit=take_profit,
            position_ticket=position_ticket,
            decision_sha256=decision_sha,
            now=check_now,
            ttl_seconds=ttl_seconds,
            previous_stop_loss=previous_stop_loss,
            require_risk_reducing=require_risk_reducing,
            decision_target_key=target_key,
            decision_expires_at=decision.expires_at,
            decision=decision,
        )

    def issue_protective_order_grant(
        self,
        *,
        broker_id: str,
        account_id: str | int,
        server: str,
        execution_mode: str,
        action_kind: ActionKind | str,
        symbol: str,
        position_ticket: str,
        side: Any = None,
        volume: Decimal | str | None = None,
        stop_loss: Decimal | str | None = None,
        take_profit: Decimal | str | None = None,
        previous_stop_loss: Decimal | str | None = None,
        reason: str = "PROTECTIVE_RISK_REDUCTION",
        now: datetime | None = None,
        ttl_seconds: float = DEFAULT_VALVE_GRANT_TTL_SECONDS,
    ) -> ValveOrderGrant:
        """Protective grant for CLOSE, REDUCE, or verified monotonic-tightening AMEND_STOP."""
        norm_act = _norm_grant_action(action_kind)
        if norm_act not in (RISK_REDUCING_ACTION_KINDS | CONDITIONAL_MANAGEMENT_ACTION_KINDS):
            raise ValveGrantError(
                f"issue_protective_order_grant permits only CLOSE/REDUCE/AMEND_STOP; refused {norm_act!r}"
            )
        norm_ticket = str(position_ticket or "").strip()
        if not norm_ticket:
            raise ValveGrantError("issue_protective_order_grant requires a non-empty position_ticket")
        if norm_act in ("CLOSE", "REDUCE") and not _norm_grant_decimal(volume):
            raise ValveGrantError(f"issue_protective_order_grant({norm_act}) requires volume")
        if norm_act == "AMEND_STOP":
            if not (_norm_grant_decimal(stop_loss) or _norm_grant_decimal(take_profit)):
                raise ValveGrantError("issue_protective_order_grant(AMEND_STOP) requires stop_loss or take_profit")
            if _norm_grant_decimal(stop_loss) and not _is_monotonic_tightening_amend(
                side=side, stop_loss=stop_loss, previous_stop_loss=previous_stop_loss
            ):
                raise ValveGrantError(
                    "issue_protective_order_grant(AMEND_STOP) requires authoritative side, previous_stop_loss, and non-widening stop"
                )
        check_now = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        prot_sha = sha256(
            canonical_bytes({
                "mode": "PROTECTIVE_RISK_REDUCTION",
                "action_kind": norm_act,
                "broker_id": str(broker_id).strip().upper(),
                "account_id": str(account_id).strip(),
                "position_ticket": norm_ticket,
                "symbol": _norm_grant_symbol(symbol),
                "previous_stop_loss": _norm_grant_decimal(previous_stop_loss),
                "reason": str(reason or "PROTECTIVE_RISK_REDUCTION")[:128],
                "issued_at": _iso_utc(check_now),
            })
        ).hexdigest()
        return self._mint_and_register_grant(
            broker_id=broker_id,
            account_id=account_id,
            server=server,
            execution_mode=execution_mode,
            action_kind=norm_act,
            symbol=symbol,
            side=side,
            volume=volume,
            stop_loss=stop_loss,
            take_profit=take_profit,
            position_ticket=norm_ticket,
            decision_sha256=prot_sha,
            now=check_now,
            ttl_seconds=ttl_seconds,
            previous_stop_loss=previous_stop_loss,
            require_risk_reducing=True,
        )


def load_default_forex_valve_gate(
    weights_path: Path | None = None,
    *,
    max_drawdown_pct: Decimal | str | None = DEFAULT_MAX_DRAWDOWN_PCT,
    peak_equity_store: PeakEquityStore | None = None,
) -> ForexMetaValveGate:
    target = Path(weights_path) if weights_path is not None else (Path(__file__).resolve().parent / "tks_meta_valve_forex_weights_v1.json")
    return ForexMetaValveGate(
        TKSMetaValveController.load_weights(target),
        max_drawdown_pct=max_drawdown_pct,
        peak_equity_store=peak_equity_store,
    )
