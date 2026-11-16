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

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, localcontext
from hashlib import sha256
import json
import math
from pathlib import Path
import sqlite3
from threading import RLock
from typing import Any

from cas_forex_revamp.contracts import ActionKind, ContractError, ControlKind, canonical_bytes, decimal_text


DEFAULT_MAX_DRAWDOWN_PCT = Decimal("0.10")
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


class ValveRefusalError(ContractError):
    """Raised when ForexMetaValveGate blocks an unsafe or hallucinated trade proposal."""

    def __init__(self, message: str, decision: "ValveDecision | None" = None) -> None:
        super().__init__(message)
        self.decision = decision


@dataclass(frozen=True, slots=True)
class ValveDecision:
    admitted: bool
    valve_mode: str
    mlp_score: float
    threshold: float
    mlp_admitted: bool
    hard_veto: bool
    hard_veto_reasons: tuple[str, ...]
    features: dict[str, float]
    weights_sha256: str
    request_id: str
    selected_action_ref: str | None

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


def _extract_money_decimal(value: Any) -> Decimal | None:
    """Extract a finite Decimal from a plain scalar/string or typed Money wire dict."""
    if value is None or value == "UNAVAILABLE":
        return None
    if isinstance(value, dict):
        if "amount" not in value:
            return None
        return _safe_decimal(value.get("amount"))
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


def _proposal_scope_id(proposal: Any, current_view: dict[str, Any] | None) -> str:
    req = getattr(proposal, "request", None)
    state = getattr(req, "state", None)
    scope = getattr(state, "scope", None)
    acct = getattr(scope, "account_id", None)
    run = getattr(scope, "run_id", None)
    if isinstance(acct, str) and acct and isinstance(run, str) and run:
        return f"{acct}:{run}"
    if isinstance(current_view, dict):
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
    for f in getattr(request, "facts", ()):
        label = getattr(f, "label", "")
        raw_val = getattr(f, "value", "")
        fid = getattr(f, "fact_id", "")
        parsed_json: Any = raw_val
        if isinstance(raw_val, str) and (raw_val.startswith("{") or raw_val.startswith('"') or raw_val in ("null",)):
            try:
                parsed_json = json.loads(raw_val)
            except (ValueError, TypeError):
                parsed_json = raw_val
        if label == "equity" or fid.startswith("observed-equity"):
            cur_eq = _extract_money_decimal(parsed_json)
        elif label == "balance" or fid.startswith("observed-balance"):
            bal_eq = _extract_money_decimal(parsed_json)
        elif label == "peak_equity" or fid.startswith("observed-peak_equity"):
            explicit_peak = True
            peak_eq = _extract_money_decimal(parsed_json)
        elif fid.startswith("observed-") and isinstance(parsed_json, dict):
            if "equity" in parsed_json and cur_eq is None:
                cur_eq = _extract_money_decimal(parsed_json.get("equity"))
            if "balance" in parsed_json and bal_eq is None:
                bal_eq = _extract_money_decimal(parsed_json.get("balance"))
            if "peak_equity" in parsed_json:
                explicit_peak = True
                peak_eq = _extract_money_decimal(parsed_json.get("peak_equity"))
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
    current_view: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    now: datetime | None = None,
    max_drawdown_pct: Decimal | str | None = DEFAULT_MAX_DRAWDOWN_PCT,
    peak_equity_store: PeakEquityStore | None = None,
) -> tuple[list[float], list[str]]:
    """Extract 8-D safety feature vector and deterministic hard-veto reasons."""
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
            if val is None or val == "UNAVAILABLE":
                missing_count += 1
    else:
        fact_map = {f.label: f.value for f in request.facts}
        for k in req_fields:
            if k in fact_map and (fact_map[k] in ("null", '"UNAVAILABLE"', "UNAVAILABLE")):
                missing_count += 1
        for f in request.facts:
            if "margin" in f.label.lower() and ("null" in f.value.lower() or "unavailable" in f.value.lower()):
                missing_count = max(missing_count, 1)
            if f.fact_id.startswith("observed-") and f.value.startswith("{"):
                try:
                    obs_obj = json.loads(f.value)
                except (ValueError, TypeError):
                    obs_obj = {}
                if isinstance(obs_obj, dict):
                    if "available_margin" in obs_obj and (obs_obj["available_margin"] is None or obs_obj["available_margin"] == "UNAVAILABLE"):
                        missing_count = max(missing_count, 1)
    missing_ratio = _clamp01(missing_count / max(1, len(req_fields)))
    if intent is not None and missing_count > 0:
        vetoes.append("MISSING_REQUIRED_ACCOUNTING")

    # 1b. Peak-equity / maximum drawdown hard-floor gate on new-risk entries (OPEN / ADD).
    # WAIT (intent is None) and risk-reducing/protective management (REDUCE, CLOSE, AMEND_STOP, CANCEL_ORDER)
    # remain available during drawdown.
    if intent is not None and intent.kind in (ActionKind.OPEN, ActionKind.ADD):
        pol_dict = policy if isinstance(policy, dict) else {}
        dd_threshold: Decimal | None
        dd_invalid = False
        if "max_drawdown_pct" in pol_dict:
            dd_threshold = _safe_decimal(pol_dict.get("max_drawdown_pct"))
            if dd_threshold is None or dd_threshold <= Decimal("0") or dd_threshold >= Decimal("1"):
                dd_invalid = True
        elif max_drawdown_pct is not None:
            dd_threshold = _safe_decimal(max_drawdown_pct)
            if dd_threshold is None or dd_threshold <= Decimal("0") or dd_threshold >= Decimal("1"):
                dd_invalid = True
        else:
            dd_threshold = None

        if dd_invalid:
            missing_ratio = max(missing_ratio, 0.25)
            vetoes.append("MISSING_DRAWDOWN_ACCOUNTING")
        elif dd_threshold is not None:
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
                if f.fact_id.startswith("observed-") and f.value.startswith("{"):
                    try:
                        obs_obj = json.loads(f.value)
                    except (ValueError, TypeError):
                        obs_obj = {}
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

    # 6. Protective stop deficit on OPEN/ADD entries
    stop_deficit = 0.0
    if intent is not None and intent.kind in (ActionKind.OPEN, ActionKind.ADD):
        stop_p = _safe_decimal(intent.stop_price)
        limit_p = _safe_decimal(intent.limit_price)
        side_val = intent.side.value if hasattr(intent.side, "value") else str(intent.side)
        if stop_p is None or stop_p <= Decimal("0"):
            stop_deficit = 1.0
            vetoes.append("MISSING_PROTECTIVE_STOP")
        elif limit_p is not None:
            if side_val == "BUY" and stop_p >= limit_p:
                stop_deficit = 1.0
                vetoes.append("INVERTED_BUY_PROTECTIVE_STOP")
            elif side_val == "SELL" and stop_p <= limit_p:
                stop_deficit = 1.0
                vetoes.append("INVERTED_SELL_PROTECTIVE_STOP")

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
        if len(w1) != 16 or any(len(row) != 8 for row in w1) or len(b1) != 16 or len(w2) != 16:
            raise ContractError("TKSMetaValveController requires exact 8->16->1 weight geometry (161 params)")
        self.w1 = [[float(v) for v in row] for row in w1]
        self.b1 = [float(v) for v in b1]
        self.w2 = [float(v) for v in w2]
        self.b2 = float(b2)
        self.threshold = float(threshold)
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
        if len(x) != 8:
            raise ContractError("TKSMetaValveController requires an 8-element feature vector")
        hidden = [
            math.tanh(sum(w_ij * x_j for w_ij, x_j in zip(row, x)) + bias)
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
    ) -> None:
        if not isinstance(controller, TKSMetaValveController):
            raise ContractError("ForexMetaValveGate requires a typed TKSMetaValveController")
        self.controller = controller
        self.default_policy = deepcopy(default_policy) if default_policy is not None else None
        if max_drawdown_pct is None:
            self.max_drawdown_pct: Decimal | None = None
        else:
            parsed_dd = _safe_decimal(max_drawdown_pct)
            if parsed_dd is None or parsed_dd <= Decimal("0") or parsed_dd >= Decimal("1"):
                raise ContractError("max_drawdown_pct must be a finite Decimal in (0, 1)")
            self.max_drawdown_pct = parsed_dd
        self.peak_equity_store = peak_equity_store if peak_equity_store is not None else PeakEquityStore()
        self._weights_sha256 = controller.weights_sha256()

    @property
    def weights_sha256(self) -> str:
        return self._weights_sha256

    def evaluate(
        self,
        proposal: Any,
        *,
        current_view: dict[str, Any] | None = None,
        policy: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> ValveDecision:
        eff_policy = policy if policy is not None else self.default_policy
        vec, vetoes = extract_forex_valve_features(
            proposal,
            current_view=current_view,
            policy=eff_policy,
            now=now,
            max_drawdown_pct=self.max_drawdown_pct,
            peak_equity_store=self.peak_equity_store,
        )
        feature_map = {name: val for name, val in zip(FOREX_FEATURE_NAMES, vec)}
        score = self.controller.forward(vec)
        mlp_ok = score >= self.controller.threshold
        if proposal.intent is None:
            return ValveDecision(
                admitted=True,
                valve_mode="WAIT_BYPASS",
                mlp_score=score,
                threshold=self.controller.threshold,
                mlp_admitted=True,
                hard_veto=False,
                hard_veto_reasons=(),
                features=feature_map,
                weights_sha256=self._weights_sha256,
                request_id=proposal.request.request_id,
                selected_action_ref=None,
            )
        hard_veto = len(vetoes) > 0
        admitted = bool(mlp_ok and not hard_veto)
        mode = (
            "ADMIT"
            if admitted
            else ("HARD_FLOOR_AND_MLP_VETO" if (hard_veto and not mlp_ok) else ("HARD_FLOOR_VETO" if hard_veto else "MLP_SCORE_VETO"))
        )
        return ValveDecision(
            admitted=admitted,
            valve_mode=mode,
            mlp_score=score,
            threshold=self.controller.threshold,
            mlp_admitted=mlp_ok,
            hard_veto=hard_veto,
            hard_veto_reasons=tuple(vetoes),
            features=feature_map,
            weights_sha256=self._weights_sha256,
            request_id=proposal.request.request_id,
            selected_action_ref=proposal.result.selection.selected_action_ref,
        )

    def require_admissible(
        self,
        proposal: Any,
        *,
        current_view: dict[str, Any] | None = None,
        policy: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> ValveDecision:
        dec = self.evaluate(proposal, current_view=current_view, policy=policy, now=now)
        if not dec.admitted:
            reasons = ",".join(dec.hard_veto_reasons) if dec.hard_veto_reasons else f"mlp_score={dec.mlp_score:.6f}<{dec.threshold:.6f}"
            raise ValveRefusalError(f"ForexMetaValveGate blocked unsafe proposal ({dec.valve_mode}): {reasons}", decision=dec)
        return dec


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
