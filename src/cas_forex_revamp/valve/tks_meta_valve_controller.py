"""TKS Meta-Valve Controller for CAS Forex Revamp (Phase 3).

Provides:
1. TKSMetaValveController: 8 -> 16 (tanh) -> 1 (sigmoid) deterministic MLP controller
   (161 trainable parameters) for cognitive trajectory & Forex decision gating.
2. ForexMetaValveGate: Dual-layer Forex trade-proposal safety valve combining:
   - Trained 8-D -> 16 -> 1 neural MLP admission probability (threshold = 0.55)
   - Constitutional Hard-Floor Invariant vetoing missing accounting (G-ABSENT),
     disallowed risk/management permissions, oversized quantity, unbacked evidence,
     missing/inverted protective stop on entries, prompt-injection override pressure,
     or expired market state.

Pure Python standard library only (zero external runtime dependencies inside air-gap).
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import math
from pathlib import Path
from typing import Any

from cas_forex_revamp.contracts import ActionKind, ContractError, canonical_bytes


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
    if value is None:
        return None
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None


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
        # Inspect DecisionRequest facts when called from RehearsalWiring without CaseRuntime view
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
                except Exception:
                    obs_obj = {}
                if isinstance(obs_obj, dict):
                    if "available_margin" in obs_obj and (obs_obj["available_margin"] is None or obs_obj["available_margin"] == "UNAVAILABLE"):
                        missing_count = max(missing_count, 1)
    missing_ratio = _clamp01(missing_count / max(1, len(req_fields)))
    if intent is not None and missing_count > 0:
        vetoes.append("MISSING_REQUIRED_ACCOUNTING")

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
                    except Exception:
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

    def __init__(self, controller: TKSMetaValveController, *, default_policy: dict[str, Any] | None = None) -> None:
        if not isinstance(controller, TKSMetaValveController):
            raise ContractError("ForexMetaValveGate requires a typed TKSMetaValveController")
        self.controller = controller
        self.default_policy = deepcopy(default_policy) if default_policy is not None else None
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
            proposal, current_view=current_view, policy=eff_policy, now=now
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


def load_default_forex_valve_gate(weights_path: Path | None = None) -> ForexMetaValveGate:
    target = Path(weights_path) if weights_path is not None else (Path(__file__).resolve().parent / "tks_meta_valve_forex_weights_v1.json")
    return ForexMetaValveGate(TKSMetaValveController.load_weights(target))
