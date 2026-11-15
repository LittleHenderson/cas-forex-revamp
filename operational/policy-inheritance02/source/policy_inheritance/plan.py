"""Pure coverage/dependency validation, including design05's stage boundaries."""

from __future__ import annotations

import copy
from collections import Counter
from typing import Any

from .contract import Contract, canonical_bytes, digest
from .errors import require


class Coverage:
    def __init__(self, contract: Contract, plan: dict[str, Any],
                 *, selected_scope: dict[str, Any]) -> None:
        contract.validate("CoveragePlan", plan)
        contract.validate("Scope", selected_scope)
        require(plan["scope"] == selected_scope, "CONTEXT_MISMATCH", "coverage.scope")
        spec = contract.spec
        rows = plan["slots"]
        ids = [r["slot_id"] for r in rows]
        require(len(set(ids)) == len(ids), "EXTRA_SLOT", "coverage.slot_ids")
        by_id = {r["slot_id"]: r for r in rows}
        counts = Counter(r["kind"] for r in rows)
        expected = {k: 8 if k == "CALIBRATION_CASE" else 1
                    for k in spec["enums"]["EventKind"] if k != "FAILURE"}
        require(dict(counts) == expected, "MISSING_SLOT", "coverage.kinds")
        for row in rows:
            require(row["origin"] == spec["event_origin_and_evidence_class"][row["kind"]]["origin"],
                    "CALIBRATION_WRONG_ORIGIN", "coverage.origin")
            after = row["after_slots"]
            require(len(after) == len(set(after)) and row["slot_id"] not in after
                    and set(after) <= set(ids), "DEPENDENCY_ORDER", "coverage.edges")
            require(len(row["required_raw_kinds"]) == len(set(row["required_raw_kinds"])),
                    "EXTRA_SLOT", "coverage.raw_kinds")
        expectations = plan["calibration_plan"]
        kinds = spec["enums"]["CalibrationKind"]
        require([x["case_kind"] for x in expectations] == kinds,
                "CALIBRATION_BASELINE_MISMATCH", "coverage.case_order")
        receiver_components = {x["receiver_component_sha256"] for x in expectations}
        require(len(receiver_components) == 1, "CALIBRATION_BASELINE_MISMATCH", "coverage.receiver_component")
        case_ids = [x["case_id"] for x in expectations]
        case_slots = [x["slot_id"] for x in expectations]
        require(len(set(case_ids)) == 8 and len(set(case_slots)) == 8,
                "CALIBRATION_INCOMPLETE", "coverage.case_ids")
        require(set(case_slots) == {r["slot_id"] for r in rows if r["kind"] == "CALIBRATION_CASE"},
                "CALIBRATION_INCOMPLETE", "coverage.case_slots")
        for exp in expectations:
            baseline = spec["fixed_calibration_baseline"][exp["case_kind"]]
            require(exp["expected_exchange_verdicts"] == baseline["exchange_verdicts"]
                    and exp["requires_foreign_pid"] == baseline["foreign_pid"],
                    "CALIBRATION_BASELINE_MISMATCH", "coverage.case_predicate")
            require(by_id[exp["slot_id"]]["expected_subject_id"] == exp["case_id"]
                    and exp["fixture_ref"]["artifact_kind"] == "PUBLIC_FIXTURE",
                    "CONTEXT_MISMATCH", "coverage.case_subject")
        singleton = {r["kind"]: r["slot_id"] for r in rows if r["kind"] != "CALIBRATION_CASE"}
        required: dict[str, set[str]] = {x: set() for x in ids}
        def need(kind: str, *deps: str) -> None:
            required[singleton[kind]].update(singleton[d] for d in deps)
        need("CALIBRATION_BEGIN", "SETUP_BEGIN")
        previous = singleton["CALIBRATION_BEGIN"]
        for sid in case_slots:
            required[sid].add(previous)
            previous = sid
        required[singleton["CALIBRATION_RETIRED"]].update(case_slots)
        need("FINAL_CHANNEL_CREATED", "CALIBRATION_RETIRED")
        need("RUNNER_INSTALL", "SETUP_BEGIN", "FINAL_CHANNEL_CREATED")
        need("MODEL_INSTALL", "RUNNER_INSTALL")
        need("ASSET_BINDINGS", "SETUP_BEGIN")
        need("MODEL_POST_EXEC", "RUNNER_INSTALL", "MODEL_INSTALL", "ASSET_BINDINGS")
        need("FINAL_PEER_BOUND", "FINAL_CHANNEL_CREATED", "RUNNER_INSTALL", "MODEL_POST_EXEC")
        policy, seal = singleton["POLICY_ARGUMENT"], singleton["SETUP_SEAL"]
        required[policy].update(set(ids) - {policy, seal})
        required[seal].update(set(ids) - {seal})

        # Transitive prerequisites count, but undeclared requirements cannot be
        # silently added by an evaluator after plan selection.
        visiting: set[str] = set()
        closure: dict[str, set[str]] = {}
        def ancestors(sid: str) -> set[str]:
            require(sid not in visiting, "DEPENDENCY_ORDER", "coverage.cycle")
            if sid in closure:
                return closure[sid]
            visiting.add(sid)
            value = set(by_id[sid]["after_slots"])
            for dep in by_id[sid]["after_slots"]:
                value.update(ancestors(dep))
            visiting.remove(sid)
            closure[sid] = value
            return value
        for sid in ids:
            require(required[sid] <= ancestors(sid), "DEPENDENCY_ORDER", "coverage.missing_dependency")
        require(not ancestors(singleton["SETUP_BEGIN"]), "DEPENDENCY_ORDER", "coverage.setup_first")
        # Input slot array is a declarative set; the stream must choose one
        # compatible topological order. It need not use this array's order.
        self._plan = copy.deepcopy(plan)
        self._by_id = copy.deepcopy(by_id)
        self._closure = copy.deepcopy(closure)
        self._single = dict(singleton)
        self._expectations = {x["slot_id"]: copy.deepcopy(x) for x in expectations}
        self.sha256 = digest(canonical_bytes(plan))

    @property
    def plan(self) -> dict[str, Any]:
        return copy.deepcopy(self._plan)

    @property
    def case_ids(self) -> list[str]:
        return [x["case_id"] for x in self._plan["calibration_plan"]]

    @property
    def receiver_component_sha256(self) -> str:
        return self._plan["calibration_plan"][0]["receiver_component_sha256"]

    def slot(self, slot_id: str) -> dict[str, Any]:
        require(slot_id in self._by_id, "EXTRA_SLOT", "event.slot_id")
        return copy.deepcopy(self._by_id[slot_id])

    def singleton(self, kind: str) -> str:
        require(kind in self._single, "MISSING_SLOT", "singleton.kind")
        return self._single[kind]

    def expectation(self, slot_id: str) -> dict[str, Any]:
        require(slot_id in self._expectations, "CALIBRATION_INCOMPLETE", "case.slot")
        return copy.deepcopy(self._expectations[slot_id])

    def require_next(self, event: dict[str, Any], accepted_slots: tuple[str, ...]) -> None:
        slot = self.slot(event["slot_id"])
        require(event["slot_id"] not in accepted_slots, "REPLAY_OR_EQUIVOCATION", "slot")
        require(event["kind"] == slot["kind"] and event["origin"] == slot["origin"],
                "CONTEXT_MISMATCH", "slot.kind_origin")
        require(self._closure[event["slot_id"]] <= set(accepted_slots),
                "DEPENDENCY_ORDER", "event.predecessors")
        if event["kind"] == "POLICY_ARGUMENT":
            require(len(accepted_slots) == 17 and event["sequence"] == 18,
                    "INCOMPLETE_STREAM", "policy.prefix")
        if event["kind"] == "SETUP_SEAL":
            require(len(accepted_slots) == 18 and event["sequence"] == 19,
                    "INCOMPLETE_STREAM", "seal.prefix")
