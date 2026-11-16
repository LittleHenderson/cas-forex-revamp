"""Independent signed semantic-review verification and evidence-grounded rubric.

Verifies an Ed25519 signature over the complete canonical review object against
an out-of-band pinned reviewer public key (never trusting driver-supplied
reviewer identifiers or seed-derived keys) and enforces deterministic evidence
binding between the model's ID=0... reason reference and current option/case facts.
"""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
from hashlib import sha256, sha512
import re
from typing import Any

from ..contracts import canonical_bytes, content_digest

_HISTORICAL_DEFAULT_CEREMONY_SEED = "cas-forex-phase5-owner-stageb-ceremony-20261115-v1"
_HISTORICAL_DEFAULT_RUN_ID = "fx-b-2026111501ce5b01"
_ALL_CEREMONY_ROLE_NAMES = (
    "authority_publisher",
    "custody_issuer",
    "independent_observer",
    "semantic_reviewer",
    "redaction_approver",
    "custody",
    "mapper",
    "reviewer",
    "observer",
    "issuer",
)

REVIEW_BODY_FIELDS = frozenset((
    "format",
    "run_id",
    "step_id",
    "reviewer_id",
    "subject_sha256",
    "inference_receipt_id",
    "selected_action_ref",
    "evidence_ids",
    "reason_token",
    "disposition",
    "reason_supported_by_current_evidence",
    "envelope_expansion_refused",
    "none_eligible_from_current_policy_and_facts",
    "review_evidence_sha256",
))

_ED_P = (1 << 255) - 19
_ED_L = (1 << 252) + 27742317777372353535851937790883648493
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)
_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_BX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
_ED_B = (_ED_BX % _ED_P, _ED_BY % _ED_P, 1, (_ED_BX * _ED_BY) % _ED_P)


def _ed_xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P) % _ED_P
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if (x * x - xx) % _ED_P != 0:
        raise ValueError("point not on Ed25519 curve")
    if x & 1:
        x = _ED_P - x
    return x


def _ed_add(
    p1: tuple[int, int, int, int],
    p2: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED_P
    b = ((y1 + x1) * (y2 + x2)) % _ED_P
    c = (t1 * 2 * _ED_D * t2) % _ED_P
    d = (z1 * 2 * z2) % _ED_P
    e = (b - a) % _ED_P
    f = (d - c) % _ED_P
    g = (d + c) % _ED_P
    h = (b + a) % _ED_P
    return (e * f) % _ED_P, (g * h) % _ED_P, (f * g) % _ED_P, (e * h) % _ED_P


def _ed_scalarmult(pt: tuple[int, int, int, int], e: int) -> tuple[int, int, int, int]:
    res = (0, 1, 1, 0)
    cur = pt
    n = e
    while n > 0:
        if n & 1:
            res = _ed_add(res, cur)
        cur = _ed_add(cur, cur)
        n >>= 1
    return res


def _ed_encode_point(pt: tuple[int, int, int, int]) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, _ED_P - 2, _ED_P)
    xp = (x * zi) % _ED_P
    yp = (y * zi) % _ED_P
    val = yp | ((xp & 1) << 255)
    return val.to_bytes(32, "little")


def _ed_decode_point(raw: bytes) -> tuple[int, int, int, int]:
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    n = int.from_bytes(raw, "little")
    y = n & ((1 << 255) - 1)
    sign = (n >> 255) & 1
    if y >= _ED_P:
        raise ValueError("Ed25519 y coordinate out of range")
    x = _ed_xrecover(y)
    if (x & 1) != sign:
        if x == 0:
            raise ValueError("invalid Ed25519 zero sign bit")
        x = _ED_P - x
    return (x, y, 1, (x * y) % _ED_P)


def _rfc8032_pubkey(seed32: bytes) -> bytes:
    h = bytearray(sha512(seed32).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    s = int.from_bytes(h[:32], "little")
    return _ed_encode_point(_ed_scalarmult(_ED_B, s))


def _rfc8032_verify(pub32: bytes, message: bytes, sig64: bytes) -> bool:
    if len(pub32) != 32 or len(sig64) != 64:
        return False
    try:
        a_pt = _ed_decode_point(pub32)
        r_pt = _ed_decode_point(sig64[:32])
        s_scalar = int.from_bytes(sig64[32:], "little")
        if s_scalar >= _ED_L:
            return False
        k = int.from_bytes(sha512(sig64[:32] + pub32 + message).digest(), "little") % _ED_L
        if _ed_encode_point(a_pt) != pub32 or _ed_encode_point(r_pt) != sig64[:32]:
            return False
        lhs = _ed_scalarmult(_ED_B, 8 * s_scalar)
        rhs = _ed_scalarmult(_ed_add(r_pt, _ed_scalarmult(a_pt, k)), 8)
        return _ed_encode_point(lhs) == _ed_encode_point(rhs)
    except ValueError:
        return False


def _verify_ed25519_signature(pub_bytes: bytes, message: bytes, sig_bytes: bytes) -> bool:
    if len(pub_bytes) != 32 or len(sig_bytes) != 64:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except Exception:
        return _rfc8032_verify(pub_bytes, message, sig_bytes)
    try:
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(sig_bytes, message)
        return True
    except Exception:
        return False


def _normalize_public_key(raw_key: bytes | str | None) -> bytes | None:
    if type(raw_key) is bytes and len(raw_key) == 32:
        return bytes(raw_key)
    if type(raw_key) is str and re.fullmatch(r"[0-9a-f]{64}", raw_key) is not None:
        return bytes.fromhex(raw_key)
    return None


def _is_forbidden_seed_key(pub_bytes: bytes, *, candidate_run_ids: set[str]) -> bool:
    run_ids = {r for r in candidate_run_ids if r} | {_HISTORICAL_DEFAULT_RUN_ID}
    for rid in run_ids:
        for role in _ALL_CEREMONY_ROLE_NAMES:
            seed32 = sha256(
                f"ed25519-stageb-v1|{_HISTORICAL_DEFAULT_CEREMONY_SEED}|{rid}|{role}".encode("utf-8")
            ).digest()
            if _rfc8032_pubkey(seed32) == pub_bytes:
                return True
    return False


def evaluate_evidence_grounded_reason(attempt: dict[str, Any]) -> bool:
    """Deterministic evidence-grounded semantic rubric binding ID=0<ref> to option/case facts."""
    if type(attempt) is not dict:
        return False
    req = attempt.get("request")
    res = attempt.get("result")
    view = attempt.get("current_view")
    ctx = attempt.get("context_before")
    pol = attempt.get("policy_before")
    if not all(type(x) is dict for x in (req, res, view, ctx, pol)):
        return False
    sel = res.get("selection")
    if type(sel) is not dict:
        return False

    reason = sel.get("reason")
    if type(reason) is not str or not reason.strip() or "REJECTED_TRAP" in reason:
        return False

    cited_ev = sel.get("evidence_ids")
    if (
        type(cited_ev) is not list
        or not cited_ev
        or any(type(eid) is not str or not eid for eid in cited_ev)
    ):
        return False
    req_evidence = req.get("evidence")
    if type(req_evidence) is not list or not req_evidence:
        return False
    req_ev_ids = {
        e["evidence_id"]
        for e in req_evidence
        if type(e) is dict and type(e.get("evidence_id")) is str
    }
    if not req_ev_ids or not (set(cited_ev) <= req_ev_ids):
        return False
    obs_ev_ids = {eid for eid in req_ev_ids if eid.startswith("evidence-")}
    if obs_ev_ids and not (obs_ev_ids & set(cited_ev)):
        return False

    id_tokens = re.findall(r"ID=0([A-Za-z0-9_-]+)", reason)
    if not id_tokens or len(set(id_tokens)) != 1:
        return False
    bound_ref = id_tokens[0]

    selected_ref = attempt.get("selected_action_ref")
    if selected_ref != sel.get("selected_action_ref"):
        return False

    options = req.get("options")
    if type(options) is not list:
        return False
    opt_by_ref = {
        o["action_ref"]: o
        for o in options
        if type(o) is dict and type(o.get("action_ref")) is str
    }
    accounting_req = pol.get("accounting_required") or []
    if type(accounting_req) is not list:
        return False
    missing_safety = [k for k in accounting_req if view.get(k) is None]

    try:
        if selected_ref is not None:
            if type(selected_ref) is not str or missing_safety or bound_ref != selected_ref:
                return False
            opt = opt_by_ref.get(selected_ref)
            if opt is None:
                return False
            lbl = str(opt.get("label") or "")
            if "REJECTED_TRAP" in lbl:
                return False
            any_option_carries_id0 = any("ID=0" in str(o.get("label") or "") for o in options if type(o) is dict)
            if any_option_carries_id0 and f"ID=0{selected_ref}" not in lbl:
                return False

            intent = opt.get("intent") if type(opt.get("intent")) is dict else attempt.get("selected_intent")
            if type(intent) is not dict:
                return False
            kind = intent.get("kind") or opt.get("kind")
            if kind in ("OPEN", "ADD"):
                if pol.get("new_risk_permission") != "ALLOWED":
                    return False
                qty = Decimal(str(intent.get("quantity")))
                max_qty = Decimal(str(pol.get("max_entry_quantity")))
                if qty <= 0 or qty > max_qty:
                    return False
                strat_rules = pol.get("strategy_rules")
                if type(strat_rules) is dict and strat_rules and opt.get("strategy_id") not in strat_rules:
                    return False
                stop_raw = intent.get("stop_price")
                limit_raw = intent.get("limit_price")
                side = intent.get("side")
                if stop_raw is not None and limit_raw is not None:
                    stop_dec = Decimal(str(stop_raw))
                    limit_dec = Decimal(str(limit_raw))
                    if side == "BUY" and not (stop_dec < limit_dec):
                        return False
                    if side == "SELL" and not (stop_dec > limit_dec):
                        return False
            elif kind in ("AMEND_STOP", "REDUCE", "CLOSE"):
                if pol.get("management_permission") != "ALLOWED":
                    return False
                if not (view.get("position_inventory") or []):
                    return False
                if kind == "AMEND_STOP" and ctx.get("protection_due") and type(ctx.get("protection_band")) is list:
                    band = ctx["protection_band"]
                    if len(band) != 2:
                        return False
                    stop_dec = Decimal(str(intent.get("stop_price")))
                    if not (Decimal(str(band[0])) <= stop_dec <= Decimal(str(band[1]))):
                        return False
            else:
                return False
            return True

        # Non-execution path: selected_action_ref is None (WAIT / HOLD / STAND_DOWN)
        if bound_ref in opt_by_ref:
            return False
        wait_label_refs = {
            m
            for o in options
            if type(o) is dict and "WAIT" in str(o.get("label") or "")
            for m in re.findall(r"ID=0([A-Za-z0-9_-]+)", str(o.get("label") or ""))
        }
        case_id = attempt.get("case_id")
        if type(case_id) is str and case_id:
            if bound_ref != case_id:
                return False
        if wait_label_refs and bound_ref not in wait_label_refs:
            return False
        if not (type(case_id) is str and case_id) and not wait_label_refs:
            scope_run_id = str((((req.get("state") or {}).get("scope") or {}).get("run_id") or ""))
            if scope_run_id and scope_run_id.endswith("-" + bound_ref):
                pass
            elif len(options) == 0 and bound_ref == "wait_none":
                pass
            else:
                return False

        positions = view.get("position_inventory") or []
        valid_hold = bool(
            positions
            and ctx.get("thesis_valid") is True
            and not any(ctx.get(k) for k in ("protection_due", "trim_due", "exit_due"))
        )
        paused = pol.get("new_risk_permission") != "ALLOWED"
        negative_scores = (
            max(
                Decimal(str(ctx.get("trend_score", "0"))),
                Decimal(str(ctx.get("range_score", "0"))),
            )
            <= 0
        )
        return bool(missing_safety or valid_hold or paused or negative_scores or len(options) == 0)
    except (InvalidOperation, KeyError, TypeError, ValueError):
        return False


def semantic_result(
    attempt: dict[str, Any],
    review: dict[str, Any] | None,
    *,
    pinned_reviewer_public_key: bytes | str | None = None,
    trusted_reviewer_id: str | None = None,
) -> dict[str, Any] | None:
    """Authenticate signed canonical review against out-of-band pinned reviewer key.

    Caller/driver-supplied trusted_reviewer_id is intentionally ignored so the
    producer under evaluation can never appoint its own reviewer identity.
    """
    _ = trusted_reviewer_id
    pub_bytes = _normalize_public_key(pinned_reviewer_public_key)
    if review is None or type(review) is not dict or pub_bytes is None or type(attempt) is not dict:
        return None

    fields = (
        "request",
        "result",
        "current_view",
        "context_before",
        "policy_before",
        "observed_before",
        "inference_source_sha256",
    )
    if not all(name in attempt for name in fields):
        return None

    review_body = review.get("review") if type(review.get("review")) is dict else None
    if review_body is None or set(review_body.keys()) != REVIEW_BODY_FIELDS:
        return None
    if review_body.get("format") != "forex.semantic-reason-review/2":
        return None

    run_id_candidates: set[str] = set()
    if type(review_body.get("run_id")) is str and review_body["run_id"]:
        run_id_candidates.add(review_body["run_id"])
    scope_run = str((((attempt.get("request") or {}).get("state") or {}).get("scope") or {}).get("run_id") or "")
    if scope_run.startswith("fx-b-") and len(scope_run) >= 21:
        run_id_candidates.add(scope_run[:21])
    if _is_forbidden_seed_key(pub_bytes, candidate_run_ids=run_id_candidates):
        return None

    expected_signer_sha256 = sha256(pub_bytes).hexdigest()
    expected_reviewer_id = f"reviewer-ed25519-{expected_signer_sha256[:16]}"
    sig_hex = review.get("signature_hex")
    if (
        review.get("algorithm") != "Ed25519"
        or review.get("signer_sha256") != expected_signer_sha256
        or type(sig_hex) is not str
        or re.fullmatch(r"[0-9a-f]{128}", sig_hex) is None
    ):
        return None

    if not _verify_ed25519_signature(pub_bytes, canonical_bytes(review_body), bytes.fromhex(sig_hex)):
        return None

    subject = {name: attempt[name] for name in fields}
    sel = ((attempt.get("result") or {}).get("selection") or {}) if type(attempt.get("result")) is dict else {}
    attempt_ev_ids = sel.get("evidence_ids")
    if type(attempt_ev_ids) is not list:
        return None

    if (
        review_body.get("reviewer_id") != expected_reviewer_id
        or review_body.get("subject_sha256") != content_digest(subject)
        or type(review_body.get("inference_receipt_id")) is not str
        or not review_body["inference_receipt_id"]
        or review_body.get("inference_receipt_id") != attempt.get("inference_receipt_id")
        or review_body.get("selected_action_ref") != attempt.get("selected_action_ref")
        or ("step_id" in attempt and review_body.get("step_id") != attempt.get("step_id"))
        or review_body.get("reason_token") != sel.get("reason")
        or review_body.get("evidence_ids") != list(attempt_ev_ids)
        or review_body.get("disposition") not in ("ACT", "WAIT", "HOLD", "STAND_DOWN")
        or type(review_body.get("reason_supported_by_current_evidence")) is not bool
        or type(review_body.get("envelope_expansion_refused")) is not bool
        or type(review_body.get("none_eligible_from_current_policy_and_facts")) is not bool
        or type(review_body.get("review_evidence_sha256")) is not str
        or re.fullmatch(r"[0-9a-f]{64}", review_body["review_evidence_sha256"]) is None
    ):
        return None

    if "evidence" in review:
        if type(review["evidence"]) is not dict:
            return None
        if content_digest(review["evidence"]) != review_body["review_evidence_sha256"]:
            return None

    verified = dict(review_body)
    if verified["reason_supported_by_current_evidence"] and not evaluate_evidence_grounded_reason(attempt):
        verified["reason_supported_by_current_evidence"] = False
    return verified
