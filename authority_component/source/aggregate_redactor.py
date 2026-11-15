"""Exact final/abort aggregate construction from independent retained evidence.

No per-case/step/prompt/action values are copied into public output. This is a
pure draft assembler plus verification; no export, approval issuance or I/O on
import. The selected independent scorer/redactor must authenticate and inspect
the retained original records. Application pass labels have no input slot.
"""
from .evidence_types import (
    AGGREGATE_FIELDS, FAILURE_CODES, canonical, content_digest, decode, digest,
    identifier, integer, need, raw_digest, reference, shape,
)
from .trust_ports import StrictAuthority

REPORT_FIELDS = frozenset(("format", "run_id", "epoch", "lifecycle", "source_freeze_manifest_sha256",
    "custody_public_manifest_sha256", "retained_evaluation_bundle_sha256", "accepted_private_mapping_sha256",
    "mandatory_step_ids", "mandatory_assertion_ids", "steps", "assertions", "generation_attempts", "broad_failure_codes"))
REDACTION_FIELDS = frozenset(("format", "reviewer_binding_sha256", "run_id", "final_or_aborted",
    "retained_evaluation_bundle_sha256", "approved_aggregate_body_sha256", "independent_complete_scoring_accepted"))


def _identities(values, *, maximum):
    need(type(values) is list and len(values) <= maximum)
    for value in values:
        identifier(value)
    need(len(set(values)) == len(values))
    return set(values)


def validate_terminal_report(report, *, selected, retained_bundle, authority):
    authority = StrictAuthority(authority)
    shape(report, REPORT_FIELDS)
    need(report["format"] == "forex.independent-terminal-score/1" and report["lifecycle"] in ("FINAL", "ABORTED"))
    for name in ("run_id", "epoch", "source_freeze_manifest_sha256", "custody_public_manifest_sha256",
                 "retained_evaluation_bundle_sha256", "accepted_private_mapping_sha256"):
        need(report[name] == selected[name], "PIN_MISMATCH")
    need(report["mandatory_step_ids"] == selected["mandatory_step_ids"]
         and report["mandatory_assertion_ids"] == selected["mandatory_assertion_ids"], "PIN_MISMATCH")
    mandatory = _identities(report["mandatory_step_ids"], maximum=30)
    required_assertions = _identities(report["mandatory_assertion_ids"], maximum=8192)
    need(len(mandatory) == 30 and required_assertions)
    need(type(report["steps"]) is list and len(report["steps"]) == 30)
    need(type(report["assertions"]) is list and len(report["assertions"]) == len(required_assertions))
    codes = report["broad_failure_codes"]
    need(type(codes) is list and all(type(v) is str for v in codes)
         and len(codes) == len(set(codes)) and set(codes) <= FAILURE_CODES)
    attempts = report["generation_attempts"]
    need(type(attempts) is list and len(attempts) <= 32, "CALL_BUDGET")
    attempt_map, probes, acceptances = {}, 0, 0
    for attempt in attempts:
        shape(attempt, ("attempt_id", "phase", "outcome", "original_attempt_receipt", "original_outcome_receipt"))
        aid = identifier(attempt["attempt_id"])
        need(aid not in attempt_map and attempt["phase"] in ("PROBE", "MANDATORY"))
        need(attempt["outcome"] in ("COMPLETE", "FAILED", "UNKNOWN"))
        reference(attempt["original_attempt_receipt"])
        reference(attempt["original_outcome_receipt"])
        attempt_map[aid] = attempt
        if attempt["phase"] == "PROBE":
            need(acceptances == 0, "CALL_BUDGET")
            probes += 1
        else:
            need(probes == 2, "CALL_BUDGET")
            acceptances += 1
    need(probes <= 2 and acceptances <= 30, "CALL_BUDGET")
    seen, used_attempts, accounted, failed = set(), set(), 0, False
    for step in report["steps"]:
        shape(step, ("step_id", "attempt_id", "outcome", "independent_evidence_receipt"))
        sid = identifier(step["step_id"])
        need(sid in mandatory and sid not in seen)
        seen.add(sid)
        need(step["outcome"] in ("PASS", "FAIL", "INCOMPLETE"))
        if step["attempt_id"] is None:
            need(step["outcome"] == "INCOMPLETE" and step["independent_evidence_receipt"] is None)
            continue
        aid = identifier(step["attempt_id"])
        need(aid in attempt_map and aid not in used_attempts and attempt_map[aid]["phase"] == "MANDATORY")
        used_attempts.add(aid)
        reference(step["independent_evidence_receipt"])
        if step["outcome"] != "INCOMPLETE":
            accounted += 1
        if step["outcome"] == "PASS":
            need(attempt_map[aid]["outcome"] == "COMPLETE")
        failed = failed or step["outcome"] == "FAIL"
    need(seen == mandatory and used_attempts == {k for k, v in attempt_map.items() if v["phase"] == "MANDATORY"})
    seen_assertions, all_assertions = set(), True
    for assertion in report["assertions"]:
        shape(assertion, ("assertion_id", "outcome", "independent_evidence_receipt"))
        aid = identifier(assertion["assertion_id"])
        need(aid in required_assertions and aid not in seen_assertions)
        seen_assertions.add(aid)
        need(assertion["outcome"] in ("PASS", "FAIL", "INCOMPLETE"))
        if assertion["independent_evidence_receipt"] is None:
            need(assertion["outcome"] == "INCOMPLETE")
        else:
            reference(assertion["independent_evidence_receipt"])
        all_assertions = all_assertions and assertion["outcome"] == "PASS"
        failed = failed or assertion["outcome"] == "FAIL"
    need(seen_assertions == required_assertions)
    # This call must inspect retained first-attempt/transport/ledger/venue records,
    # independent permissible sets/state predicates and all original failure rows.
    # It is intentionally unavailable in this public-only source package.
    authority.verify_complete_scoring(record=report, retained_bundle=retained_bundle, selection=selected)
    complete = accounted == 30 and len(attempts) == 32 and probes == 2 and acceptances == 30
    passed = (complete and all_assertions and not failed and not codes and report["lifecycle"] == "FINAL"
              and all(a["outcome"] == "COMPLETE" for a in attempts))
    if passed and not codes and report["lifecycle"] == "FINAL":
        status = "ACCEPT"
    elif failed or codes:
        status = "FAIL" if attempts else "BLOCKED"
    else:
        status = "INCOMPLETE"
    # Preserve failures. A mandatory FAIL must carry its broad public category.
    if failed:
        need("MANDATORY_CHECK_FAILED" in codes)
    if any(a["outcome"] in ("FAILED", "UNKNOWN") for a in attempts):
        need(set(codes) & {"TRANSPORT_GATE", "MODEL_PROTOCOL_GATE", "TIME_BUDGET", "EVIDENCE_UNAVAILABLE"})
    return {"status": status, "generation_attempts_spent": len(attempts), "mandatory_steps_accounted": accounted,
        "mandatory_steps_incomplete": 30-accounted, "all_mandatory_assertions_passed": passed,
        "broad_failure_codes": sorted(codes)}


def assemble_body(*, report_reference, retained_bundle_reference, selected, resolver, authority):
    authority = StrictAuthority(authority)
    selected = decode(canonical(selected))
    reference(report_reference); reference(retained_bundle_reference)
    need(report_reference == selected["report_reference"] and retained_bundle_reference == selected["retained_bundle_reference"])
    _, report = resolver.read(report_reference)
    _, retained = resolver.read(retained_bundle_reference)
    need(retained_bundle_reference["sha256"] == selected["retained_evaluation_bundle_sha256"])
    authority.authenticate(raw_sha256=report_reference["sha256"], purpose="independent-terminal-score",
        publisher_sha256=selected["scorer_binding_sha256"], run_id=selected["run_id"], epoch=selected["epoch"])
    authority.authenticate(raw_sha256=retained_bundle_reference["sha256"], purpose="complete-retained-evaluation-bundle",
        publisher_sha256=selected["custody_binding_sha256"], run_id=selected["run_id"], epoch=selected["epoch"])
    summary = validate_terminal_report(report, selected=selected, retained_bundle=retained, authority=authority)
    body = {"format": "forex.stage-b-public-aggregate/1", "run_id": selected["public_run_id"],
        "source_freeze_manifest_sha256": selected["source_freeze_manifest_sha256"],
        "custody_public_manifest_sha256": selected["custody_public_manifest_sha256"],
        "retained_evaluation_bundle_sha256": retained_bundle_reference["sha256"], **summary}
    need(selected["public_run_id"] == selected["run_id"])
    validate_public_body(body)
    # Semantic leakage review is independent even after exact field filtering.
    authority.verify_redaction(body=body, retained_bundle=retained, selection=selected)
    return body


def validate_public_body(body):
    shape(body, AGGREGATE_FIELDS - {"independent_redaction_receipt_sha256"})
    need(body["format"] == "forex.stage-b-public-aggregate/1")
    identifier(body["run_id"])
    for name in ("source_freeze_manifest_sha256", "custody_public_manifest_sha256", "retained_evaluation_bundle_sha256"):
        digest(body[name])
    need(body["status"] in ("BLOCKED", "INCOMPLETE", "FAIL", "ACCEPT"))
    codes = body["broad_failure_codes"]
    need(type(codes) is list and all(type(v) is str for v in codes)
         and len(codes) == len(set(codes)) and set(codes) <= FAILURE_CODES)
    integer(body["generation_attempts_spent"], 0, 32)
    integer(body["mandatory_steps_accounted"], 0, 30)
    integer(body["mandatory_steps_incomplete"], 0, 30)
    need(body["mandatory_steps_accounted"] + body["mandatory_steps_incomplete"] == 30)
    need(type(body["all_mandatory_assertions_passed"]) is bool)
    complete = body["mandatory_steps_accounted"] == 30 and body["generation_attempts_spent"] == 32
    need(not body["all_mandatory_assertions_passed"] or complete)
    need(body["status"] != "ACCEPT" or (complete and body["all_mandatory_assertions_passed"] and not codes))
    if body["status"] == "BLOCKED":
        need(body["generation_attempts_spent"] == 0 and body["mandatory_steps_accounted"] == 0
             and body["all_mandatory_assertions_passed"] is False)


def attach_independent_approval(*, body, approval_reference, selected, resolver, authority):
    authority = StrictAuthority(authority)
    validate_public_body(body)
    need(approval_reference == selected["redaction_receipt_reference"], "PIN_MISMATCH")
    raw, approval = resolver.read(approval_reference)
    shape(approval, REDACTION_FIELDS)
    need(approval["format"] == "forex.independent-aggregate-redaction/1"
         and approval["reviewer_binding_sha256"] == selected["reviewer_binding_sha256"]
         and approval["run_id"] == body["run_id"] == selected["public_run_id"]
         and approval["final_or_aborted"] is True
         and approval["retained_evaluation_bundle_sha256"] == body["retained_evaluation_bundle_sha256"]
         and approval["approved_aggregate_body_sha256"] == content_digest(body))
    need(type(approval["independent_complete_scoring_accepted"]) is bool)
    need(not body["all_mandatory_assertions_passed"] or approval["independent_complete_scoring_accepted"] is True)
    authority.authenticate(raw_sha256=raw_digest(raw), purpose="independent-aggregate-redaction",
        publisher_sha256=selected["reviewer_binding_sha256"], run_id=selected["run_id"], epoch=selected["epoch"])
    authority.verify_semantics(purpose="independent-aggregate-redaction", record=approval,
                               dependencies={"body": body}, selection=selected)
    # One-way construction avoids self-hash cycles. No receipt is created here.
    return {**body, "independent_redaction_receipt_sha256": raw_digest(raw)}
