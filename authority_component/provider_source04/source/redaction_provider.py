"""Exact-body aggregate verification; no publication or receipt issuance.

The scorer derives results from retained originals. Independently selected public
bindings constrain every identifier/hash allowed into the aggregate. A separately
authenticated reviewer receipt must approve the exact canonical body. This source
does not claim that future independent reviewers or runtime providers are appointed.
"""
from .authority_provider import canonical, digest, hash_value, need, parse, ref, shape

BODY_FIELDS = frozenset(("format", "run_id", "source_freeze_manifest_sha256", "custody_public_manifest_sha256",
    "status", "broad_failure_codes", "generation_attempts_spent", "mandatory_steps_accounted",
    "mandatory_steps_incomplete", "all_mandatory_assertions_passed", "retained_evaluation_bundle_sha256"))
APPROVAL_FIELDS = frozenset(("format", "reviewer_binding_sha256", "run_id", "final_or_aborted",
    "retained_evaluation_bundle_sha256", "approved_aggregate_body_sha256", "independent_complete_scoring_accepted"))


class RedactionProvider:
    def __init__(self, *, scorer, public_bindings_reference, reviewer_sha256, application_sha256):
        self.scorer = scorer
        self.bindings_ref = parse(canonical(ref(public_bindings_reference)))
        self.reviewer = digest(reviewer_sha256)
        need(self.reviewer != digest(application_sha256), "REDACTION_INDEPENDENCE")
        need(self.reviewer == scorer.publishers["reviewer"], "REDACTION_REVIEWER_PIN")

    def derive_body(self, *, retained_bundle, authority):
        report = self.scorer.derive(retained_bundle=retained_bundle, authority=authority)
        bindings = authority.record(self.bindings_ref, purpose="approved-public-aggregate-bindings", publisher_sha256=self.reviewer)
        shape(bindings, ("format", "run_id", "source_freeze_manifest_sha256", "custody_public_manifest_sha256",
            "retained_evaluation_bundle_sha256", "reviewer_binding_sha256"))
        need(bindings["format"] == "forex.approved-public-aggregate-bindings/1"
             and bindings["reviewer_binding_sha256"] == self.reviewer, "PUBLIC_BINDINGS")
        for name in ("run_id", "source_freeze_manifest_sha256", "custody_public_manifest_sha256", "retained_evaluation_bundle_sha256"):
            need(bindings[name] == report[name], "UNAPPROVED_PUBLIC_VALUE")
        # Never copy private plan, fact, case, action, reason or exception values.
        attempts, steps, assertions, codes = (report[k] for k in ("generation_attempts", "steps", "assertions", "broad_failure_codes"))
        accounted = sum(s["outcome"] != "INCOMPLETE" for s in steps)
        failed = any(s["outcome"] == "FAIL" for s in steps) or any(a["outcome"] == "FAIL" for a in assertions)
        complete = (accounted == 30 and len(attempts) == 32 and sum(a["phase"] == "PROBE" for a in attempts) == 2
                    and sum(a["phase"] == "MANDATORY" for a in attempts) == 30)
        passed = (complete and not failed and not codes and report["lifecycle"] == "FINAL"
                  and all(a["outcome"] == "PASS" for a in assertions)
                  and all(a["outcome"] == "COMPLETE" for a in attempts))
        if passed:
            status = "ACCEPT"
        elif failed or codes:
            status = "FAIL" if attempts else "BLOCKED"
        else:
            status = "INCOMPLETE"
        body = {"format": "forex.stage-b-public-aggregate/1", "run_id": bindings["run_id"],
            "source_freeze_manifest_sha256": bindings["source_freeze_manifest_sha256"],
            "custody_public_manifest_sha256": bindings["custody_public_manifest_sha256"],
            "retained_evaluation_bundle_sha256": bindings["retained_evaluation_bundle_sha256"],
            "status": status, "broad_failure_codes": sorted(codes), "generation_attempts_spent": len(attempts),
            "mandatory_steps_accounted": accounted, "mandatory_steps_incomplete": 30-accounted,
            "all_mandatory_assertions_passed": passed}
        shape(body, BODY_FIELDS)
        return body

    def verify_body(self, *, body, retained_bundle, selection, authority):
        expected = self.derive_body(retained_bundle=retained_bundle, authority=authority)
        shape(body, BODY_FIELDS)
        need(selection["public_run_id"] == selection["run_id"] == expected["run_id"], "PUBLIC_RUN_PIN")
        for name in ("source_freeze_manifest_sha256", "custody_public_manifest_sha256", "retained_evaluation_bundle_sha256"):
            need(selection[name] == expected[name], "PUBLIC_BINDING_PIN")
        need(canonical(body) == canonical(expected), "EXACT_AGGREGATE_BODY_REQUIRED")

    def verify_approval(self, *, record, dependencies, selection, authority):
        shape(record, APPROVAL_FIELDS)
        approved = authority.record(selection["redaction_receipt_reference"], purpose="independent-aggregate-redaction",
                                    publisher_sha256=self.reviewer)
        need(canonical(approved) == canonical(record), "REDACTION_RECEIPT_SUBSTITUTED")
        retained = authority.record(self.scorer.bundle_ref, purpose="complete-retained-evaluation-bundle",
                                    publisher_sha256=self.scorer.publishers["custody"])
        shape(dependencies, ("body",))
        body = dependencies["body"]
        self.verify_body(body=body, retained_bundle=retained, selection=selection, authority=authority)
        need(record["format"] == "forex.independent-aggregate-redaction/1"
             and record["reviewer_binding_sha256"] == selection["reviewer_binding_sha256"] == self.reviewer
             and record["run_id"] == body["run_id"] and record["final_or_aborted"] is True
             and record["retained_evaluation_bundle_sha256"] == body["retained_evaluation_bundle_sha256"]
             and record["approved_aggregate_body_sha256"] == hash_value(body), "REDACTION_EXACT_BODY_PIN")
        # True means the scorer's complete accounting was accepted, including
        # failed/incomplete outcomes. It does not mean the evaluation passed.
        need(record["independent_complete_scoring_accepted"] is True, "INDEPENDENT_SCORING_NOT_ACCEPTED")
