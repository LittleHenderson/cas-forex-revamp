"""Strict public wire primitives. No application imports or I/O."""
from datetime import datetime, timezone
from hashlib import sha256
import json
import re


class Blocked(ValueError):
    """A fixed public code only; never include values, paths or raw errors."""


def need(condition, code="EVIDENCE_UNAVAILABLE"):
    if not condition:
        raise Blocked(code)


def shape(value, fields):
    need(type(value) is dict and set(value) == set(fields))


def digest(value):
    need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None)
    return value


def identifier(value):
    need(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}", value) is not None)
    return value


def integer(value, low=0, high=2**63-1):
    need(type(value) is int and low <= value <= high)
    return value


def timestamp(value, *, z=True):
    need(type(value) is str)
    if z:
        need(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value) is not None)
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        need(result.tzinfo is not None and result.utcoffset().total_seconds() == 0)
        return result
    except (ValueError, OverflowError, AttributeError):
        raise Blocked("EVIDENCE_UNAVAILABLE") from None


def utc_now_value(now):
    need(type(now) is datetime and now.tzinfo is not None and now.utcoffset().total_seconds() == 0)
    return now.astimezone(timezone.utc)


def _wire(value, depth=0):
    need(depth <= 64)
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is list:
        return [_wire(v, depth+1) for v in value]
    if type(value) is dict:
        need(all(type(k) is str for k in value))
        return {k: _wire(v, depth+1) for k, v in value.items()}
    raise Blocked("EVIDENCE_UNAVAILABLE")


def canonical(value):
    try:
        return json.dumps(_wire(value), ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        raise Blocked("EVIDENCE_UNAVAILABLE") from None


def content_digest(value):
    return sha256(canonical(value)).hexdigest()


def raw_digest(raw):
    need(type(raw) is bytes)
    return sha256(raw).hexdigest()


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4_194_304)

    def pairs(values):
        result = {}
        for key, value in values:
            need(key not in result)
            result[key] = value
        return result

    def reject(_):
        raise Blocked("EVIDENCE_UNAVAILABLE")

    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                            parse_float=reject, parse_constant=reject)
        _wire(result)
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise Blocked("EVIDENCE_UNAVAILABLE") from None


def reference(value):
    shape(value, ("path", "bytes", "sha256"))
    need(type(value["path"]) is str and value["path"].startswith("/opt/cas-forex/")
         and "\\" not in value["path"] and "\x00" not in value["path"])
    need(all(part not in ("", ".", "..") for part in value["path"].split("/")[1:]))
    integer(value["bytes"], 1, 4_194_304)
    digest(value["sha256"])
    return value


RELEASE_DIGESTS = frozenset((
    "scope_sha256", "issuer_binding_sha256", "issuer_authentication_evidence_sha256",
    "execution_identity_sha256", "separate_execution_authorization_sha256",
    "stop_egress_deadline_proofs_sha256", "original_clock_and_budget_binding_sha256",
    "complete_freeze_manifest_sha256", "custody_manifest_sha256", "inherited_exposure_heads_sha256",
    "accepted_private_mapping_sha256", "independent_review_attestation_sha256",
    "approved_topology_sha256", "trusted_observer_binding_sha256", "role_read_isolation_receipt_sha256",
    "controller_identity_sha256", "authorized_current_frame_channel_sha256",
))
RELEASE_FIELDS = RELEASE_DIGESTS | {"format", "release_id", "run_id", "epoch",
                                  "issued_at_utc", "not_before_utc", "expires_at_utc"}
FREEZE_COMPONENTS = frozenset((
    "source_archive_and_manifest", "application_controller_release_and_supervisor_adapters",
    "exact_execution_configuration", "candidate_algorithm", "system_policy",
    "prompt_version_and_template", "selection_schema", "runtime_model_and_extracted_asset_inventory",
    "exact_tokenizer_identity_and_count_policy", "inference_settings_and_inference_seed",
    "policy_scope_and_permissions", "shadow_baseline_source_and_settings",
    "custody_generation_and_parent_lineage", "suite_key_schedule_mapping_and_review_digests",
))
ROLES = frozenset(("CUSTODY_CONTROLLER", "DECISION_RUNNER", "MODEL_SERVICE"))
UNTRUSTED_ROLES = frozenset(("DECISION_RUNNER", "MODEL_SERVICE"))
OPERATIONS = frozenset(("OPEN_READ_WITHOUT_READING", "PROC_MEM_OPEN", "PROC_FD_ACCESS",
                        "PROC_ROOT_ACCESS", "SIBLING_STATE_OPEN", "UNAUTHORIZED_CHANNEL_PEER"))
FAILURE_CODES = frozenset(("CUSTODY_GATE", "ISOLATION_GATE", "PIN_MISMATCH", "TOKEN_GATE",
    "TRANSPORT_GATE", "MODEL_PROTOCOL_GATE", "MANDATORY_CHECK_FAILED", "TIME_BUDGET",
    "CALL_BUDGET", "EVIDENCE_UNAVAILABLE"))
AGGREGATE_FIELDS = frozenset(("format", "run_id", "source_freeze_manifest_sha256",
    "custody_public_manifest_sha256", "status", "broad_failure_codes", "generation_attempts_spent",
    "mandatory_steps_accounted", "mandatory_steps_incomplete", "all_mandatory_assertions_passed",
    "retained_evaluation_bundle_sha256", "independent_redaction_receipt_sha256"))

