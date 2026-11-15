"""Independent release evidence checks. No app-selected truth or expected keys.

Reference resolution and publisher authentication are separate. Purposes with
no concrete semantic producer remain blocked by UnsupportedAuthority; opaque
record hashes alone never discharge execution, topology, review or exposure.
"""
from datetime import timedelta

from .evidence_types import (
    FREEZE_COMPONENTS, RELEASE_DIGESTS, RELEASE_FIELDS, content_digest, digest,
    identifier, integer, need, reference, shape, timestamp, utc_now_value,
)
from .trust_ports import StrictAuthority

SELECTED_RELEASE_FIELDS = frozenset(("format", "run_id", "release_id", "epoch", "config_sha256",
    "source_manifest_sha256", "asset_manifest_sha256", "issuer_binding_sha256", "observer_binding_sha256",
    "freeze_reviewer_binding_sha256", "expected_release_bindings", "publishers", "references",
    "guest_evidence", "freeze_components", "original_clock_record", "t0_utc", "work_deadline_utc",
    "independently_validated_observed_roles", "source_test_completion", "source_test_observer_binding_sha256"))
SOURCE_TEST_COMPLETION_FIELDS = frozenset(("format", "run_id", "epoch", "observer_binding_sha256", "source_manifest_sha256",
    "config_sha256", "original_clock_record_content_sha256", "completed_at_utc", "original_source_test_report",
    "observation_evidence"))


def validate_release_selection(selected):
    shape(selected, SELECTED_RELEASE_FIELDS)
    need(selected["format"] == "forex.independent-release-selection/2")
    for name in ("run_id", "release_id"):
        identifier(selected[name])
    integer(selected["epoch"], 1)
    for name in ("config_sha256", "source_manifest_sha256", "asset_manifest_sha256", "issuer_binding_sha256",
                 "observer_binding_sha256", "freeze_reviewer_binding_sha256", "source_test_observer_binding_sha256"):
        digest(selected[name])
    reference(selected["source_test_completion"])
    shape(selected["references"], RELEASE_DIGESTS)
    shape(selected["publishers"], RELEASE_DIGESTS)
    for value in selected["publishers"].values():
        digest(value)
    shape(selected["guest_evidence"], ("authorization", "case_review", "source_review", "stop_proof", "egress"))
    for value in selected["guest_evidence"].values():
        reference(value)


def validate_release_shape(value, *, expected, now, deadline):
    shape(value, RELEASE_FIELDS)
    need(value["format"] == "forex.custody-release-receipt/2")
    for name in RELEASE_DIGESTS:
        digest(value[name])
    for name in ("release_id", "run_id"):
        identifier(value[name])
    integer(value["epoch"], 1)
    shape(expected, RELEASE_DIGESTS | {"run_id", "epoch"})
    need(all(value[k] == v for k, v in expected.items()), "PIN_MISMATCH")
    need(timestamp(value["issued_at_utc"]) <= timestamp(value["not_before_utc"])
         <= utc_now_value(now) < timestamp(value["expires_at_utc"]) <= utc_now_value(deadline), "TIME_BUDGET")


def validate_clock(record, *, selected, source_test_completion, now):
    shape(record, ("model_window", "model_calls", "retry_calls", "bootstrap_started_utc", "test_deadline_utc"))
    need(record == selected["original_clock_record"], "TIME_BUDGET")
    need(type(record["model_calls"]) is int and record["model_calls"] == 32
         and type(record["retry_calls"]) is int and record["retry_calls"] == 0, "CALL_BUDGET")
    window = record["model_window"]
    shape(window, ("started_at", "deadline", "total_generation_limit", "probe_limit", "acceptance_limit", "includes"))
    for name, value in (("total_generation_limit", 32), ("probe_limit", 2), ("acceptance_limit", 30)):
        need(type(window[name]) is int and window[name] == value, "CALL_BUDGET")
    need(window["includes"] == ["startup", "render", "tokenize", "probes", "acceptance", "export", "shutdown"])
    start, end = timestamp(window["started_at"], z=False), timestamp(window["deadline"], z=False)
    bootstrap, test_end = timestamp(record["bootstrap_started_utc"]), timestamp(record["test_deadline_utc"])
    t0, work_end = timestamp(selected["t0_utc"]), timestamp(selected["work_deadline_utc"])
    shape(source_test_completion, SOURCE_TEST_COMPLETION_FIELDS)
    integer(source_test_completion["epoch"], 1)
    need(source_test_completion["format"] == "forex.observed-source-test-completion/1"
         and source_test_completion["run_id"] == selected["run_id"]
         and source_test_completion["epoch"] == selected["epoch"]
         and source_test_completion["source_manifest_sha256"] == selected["source_manifest_sha256"]
         and source_test_completion["config_sha256"] == selected["config_sha256"]
         and source_test_completion["observer_binding_sha256"] == selected["source_test_observer_binding_sha256"]
         and source_test_completion["original_clock_record_content_sha256"] == content_digest(record), "TIME_BUDGET")
    completed = timestamp(source_test_completion["completed_at_utc"])
    reference(source_test_completion["original_source_test_report"])
    reference(source_test_completion["observation_evidence"])
    # Source tests have their own deadline. Their observed completion precedes
    # model start; model completion is NOT nested inside the test phase.
    need(work_end-t0 == timedelta(seconds=13200) and t0 <= bootstrap <= start <= utc_now_value(now) < end
         and bootstrap < test_end <= work_end and bootstrap <= completed <= test_end and completed <= start
         and end == min(work_end, start+timedelta(seconds=5400))
         and test_end-bootstrap <= timedelta(seconds=7200), "TIME_BUDGET")


def resolve_source_test_completion(*, selected, clock_record, resolver, authority):
    """Bind actual completion evidence, never an application PASS label alone."""
    authority = StrictAuthority(authority)
    ref = reference(selected["source_test_completion"])
    _, completion = resolver.read(ref)
    shape(completion, SOURCE_TEST_COMPLETION_FIELDS)
    reference(completion["original_source_test_report"])
    reference(completion["observation_evidence"])
    authority.authenticate(raw_sha256=ref["sha256"], purpose="source-test-completion",
        publisher_sha256=selected["source_test_observer_binding_sha256"], run_id=selected["run_id"], epoch=selected["epoch"])
    # validate_clock checks the strict envelope/timing; these are retained raw
    # dependencies for the independently appointed purpose-specific verifier.
    _, report = resolver.read(completion["original_source_test_report"])
    _, observation = resolver.read(completion["observation_evidence"])
    shape(report, ("status", "finished_utc", "original_bootstrap_started_utc", "test_deadline_utc"))
    need(report["status"] == "PASS" and report["original_bootstrap_started_utc"] == clock_record["bootstrap_started_utc"]
         and report["test_deadline_utc"] == clock_record["test_deadline_utc"]
         and timestamp(report["finished_utc"], z=False) == timestamp(completion["completed_at_utc"]), "TIME_BUDGET")
    authority.verify_semantics(purpose="source-test-completion", record=completion,
        dependencies={"original_clock_record": clock_record, "original_source_test_report": report,
                      "observation_evidence": observation}, selection=selected)
    return completion


def validate_freeze(record, *, selected, resolver, authority):
    authority = StrictAuthority(authority)
    shape(record, ("config_sha256", "source_manifest_sha256", "asset_manifest_sha256", "bound_components", "component_records"))
    for name in ("config_sha256", "source_manifest_sha256", "asset_manifest_sha256"):
        digest(record[name])
        need(record[name] == selected[name], "PIN_MISMATCH")
    shape(record["bound_components"], FREEZE_COMPONENTS)
    shape(record["component_records"], FREEZE_COMPONENTS)
    shape(selected["freeze_components"], FREEZE_COMPONENTS)
    for name in sorted(FREEZE_COMPONENTS):
        ref = reference(record["component_records"][name])
        need(ref["sha256"] == record["bound_components"][name] == selected["freeze_components"][name], "PIN_MISMATCH")
        _, component = resolver.read(ref)
        authority.authenticate(raw_sha256=ref["sha256"], purpose="freeze-component:"+name,
            publisher_sha256=selected["freeze_reviewer_binding_sha256"], run_id=selected["run_id"], epoch=selected["epoch"])
        authority.verify_semantics(purpose="freeze-component:"+name, record=component,
                                   dependencies={}, selection=selected)


def validate_reference_set(*, selected, references, resolver, authority, now):
    """Resolve all 17 records with preselected purposes, publishers and pins.

    selected must itself be independently authenticated by the embedding owner.
    This function never derives trust selection from the supplied references.
    """
    authority = StrictAuthority(authority)
    validate_release_selection(selected)
    shape(references, RELEASE_DIGESTS)
    shape(selected["expected_release_bindings"], RELEASE_DIGESTS | {"run_id", "epoch"})
    shape(selected["publishers"], RELEASE_DIGESTS)
    resolved = {}
    for name in sorted(RELEASE_DIGESTS):
        ref = reference(references[name])
        need(ref == selected["references"][name] and ref["sha256"] == selected["expected_release_bindings"][name], "PIN_MISMATCH")
        _, record = resolver.read(ref)
        authority.authenticate(raw_sha256=ref["sha256"], purpose=name,
            publisher_sha256=selected["publishers"][name], run_id=selected["run_id"], epoch=selected["epoch"])
        resolved[name] = record
    expected = selected["expected_release_bindings"]
    need(expected["run_id"] == selected["run_id"] and expected["epoch"] == selected["epoch"]
         and expected["issuer_binding_sha256"] == selected["issuer_binding_sha256"]
         and expected["trusted_observer_binding_sha256"] == selected["observer_binding_sha256"], "CUSTODY_GATE")
    for name, config_name in (("separate_execution_authorization_sha256", "authorization"),
        ("accepted_private_mapping_sha256", "case_review"), ("independent_review_attestation_sha256", "source_review")):
        need(expected[name] == selected["guest_evidence"][config_name]["sha256"], "PIN_MISMATCH")
    stop = resolved["stop_egress_deadline_proofs_sha256"]
    shape(stop, ("stop_proof_sha256", "egress_sha256", "work_deadline_utc"))
    need(stop == {"stop_proof_sha256": selected["guest_evidence"]["stop_proof"]["sha256"],
        "egress_sha256": selected["guest_evidence"]["egress"]["sha256"],
        "work_deadline_utc": selected["work_deadline_utc"]}, "PIN_MISMATCH")
    clock_record = resolved["original_clock_and_budget_binding_sha256"]
    completion = resolve_source_test_completion(selected=selected, clock_record=clock_record, resolver=resolver, authority=authority)
    validate_clock(clock_record, selected=selected, source_test_completion=completion, now=now)
    validate_freeze(resolved["complete_freeze_manifest_sha256"], selected=selected, resolver=resolver, authority=authority)
    observed = resolved["role_read_isolation_receipt_sha256"]
    # Independently reconstructed observation must match complete raw semantics;
    # a consumer's observed/verified booleans do not substitute for this value.
    need(observed == selected["independently_validated_observed_roles"], "ISOLATION_GATE")
    need(timestamp(observed["observed_at_utc"]) <= utc_now_value(now) < timestamp(observed["expires_at_utc"])
         <= timestamp(selected["original_clock_record"]["model_window"]["deadline"], z=False), "ISOLATION_GATE")
    for name, record in resolved.items():
        # Every purpose needs substantive independent validation, including
        # lineage/exposure, topology, role continuity and separate authorization.
        authority.verify_semantics(purpose=name, record=record, dependencies=resolved, selection=selected)
    return resolved


def validate_exposure_heads(record, *, ancestor_heads):
    """Review-side conservation checks; event authenticity remains external."""
    shape(record, ("format", "lineages", "freshness"))
    need(record["format"] == "forex.inherited-exposure-heads/1")
    need(record["freshness"] in ("UNEXPOSED", "CONSUMED_REGRESSION", "UNVERIFIED"))
    need(type(record["lineages"]) is list and len(record["lineages"]) == len(ancestor_heads))
    seen = set()
    for lineage in record["lineages"]:
        shape(lineage, ("generation_manifest_sha256", "parent_manifest_sha256", "streams"))
        generation = digest(lineage["generation_manifest_sha256"])
        need(generation in ancestor_heads and generation not in seen)
        seen.add(generation)
        original = ancestor_heads[generation]
        need(lineage["parent_manifest_sha256"] == original["parent_manifest_sha256"])
        shape(lineage["streams"], ("custody", "attempts", "failures", "retries", "consumed"))
        for name, stream in lineage["streams"].items():
            shape(stream, ("initial_head_sha256", "current_head_sha256", "retained_prefix_sha256", "rows", "extension_receipt"))
            for field in ("initial_head_sha256", "current_head_sha256", "retained_prefix_sha256"):
                digest(stream[field])
            need(stream["initial_head_sha256"] == original["streams"][name]["initial_head_sha256"]
                 and stream["retained_prefix_sha256"] == original["streams"][name]["retained_prefix_sha256"])
            integer(stream["rows"], original["streams"][name]["rows"])
            reference(stream["extension_receipt"])
    need(record["freshness"] != "UNVERIFIED", "CUSTODY_GATE")
    return content_digest(record)
