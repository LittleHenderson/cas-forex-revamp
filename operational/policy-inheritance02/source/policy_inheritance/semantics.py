"""Pure semantic checks over proposed public normalized fixture records.

No normalized fixture is accepted as actual kernel evidence. Real decoding,
producer authentication and external selection are unimplemented and rejected by
OperationalAdapters. These functions make the expected predicates reviewable.
"""

from __future__ import annotations

from typing import Any

from .contract import Contract, canonical_bytes, digest
from .evidence import PublicEvidence, PublicSelections, exact_fields
from .errors import require
from .guards import stamp_le
from .plan import Coverage


def _unique(values: list[Any], code: str, field: str) -> None:
    encoded = [canonical_bytes(x) for x in values]
    require(len(encoded) == len(set(encoded)), code, field)


def _same(left: Any, right: Any) -> bool:
    """Canonical comparison keeps bool distinct from int in normalized raw facts."""
    return canonical_bytes(left) == canonical_bytes(right)


def _hex(value: Any, field: str) -> bytes:
    require(type(value) is str and len(value) % 2 == 0 and len(value) <= 2_097_152
            and all(c in "0123456789abcdef" for c in value), "DECODER_UNAVAILABLE", field)
    return bytes.fromhex(value)


class Semantics:
    def __init__(self, contract: Contract, coverage: Coverage,
                 selections: PublicSelections) -> None:
        require(type(selections) is PublicSelections, "CONTEXT_MISMATCH", "selections")
        self.contract, self.coverage = contract, coverage
        self._selected = selections.values
        self._spec = contract.spec

    def _validate_channel(self, value: Any) -> None:
        channel = exact_fields(value, {"channel_id", "endpoint_ids", "owner", "key_operation_id", "created_at"}, "selected.channel")
        for name in ["channel_id", "key_operation_id"]:
            self.contract.validate_value("Id", channel[name])
        self.contract.validate_value("array<Id>[2,2]", channel["endpoint_ids"])
        require(len(set(channel["endpoint_ids"])) == 2, "CONTEXT_MISMATCH", "selected.channel_endpoints")
        self.contract.validate("ProcessIdentity", channel["owner"])
        self.contract.validate("Stamp", channel["created_at"])

    def _validate_listener(self, value: Any) -> None:
        listener = exact_fields(value, {"process", "address", "port", "socket_inode", "observed"}, "selected.listener")
        self.contract.validate("ProcessIdentity", listener["process"])
        require(listener["address"] == "127.0.0.1", "CONTEXT_MISMATCH", "selected.listener_address")
        self.contract.validate_value("Int[1,65535]", listener["port"])
        self.contract.validate_value("PositiveInt", listener["socket_inode"])
        self.contract.validate("Stamp", listener["observed"])

    def _validate_selections(self, kind: str) -> None:
        """Validate nested selected shapes before any semantic field lookup."""
        c = self.contract
        if "calibration" in self._selected:
            value = exact_fields(self._selected["calibration"],
                                 {"receiver_component_sha256", "expected_peer", "foreign_sender", "retired_pids", "temporary_actors"}, "selected.calibration")
            c.validate_value("Sha256", value["receiver_component_sha256"])
            c.validate("ProcessIdentity", value["expected_peer"])
            c.validate("ProcessIdentity", value["foreign_sender"])
            c.validate_value("array<PositiveInt>[1,256]", value["retired_pids"])
            c.validate_value("array<ProcessIdentity>[1,256]", value["temporary_actors"])
            require(len(set(value["retired_pids"])) == len(value["retired_pids"]), "CONTEXT_MISMATCH", "selected.retired_pids")
            require(sorted(value["retired_pids"]) == sorted(a["pid"] for a in value["temporary_actors"]),
                    "CONTEXT_MISMATCH", "selected.temporary_actors")
            require(value["receiver_component_sha256"] == self.coverage.receiver_component_sha256,
                    "CALIBRATION_BASELINE_MISMATCH", "selected.receiver_component")
        if "channel" in self._selected:
            self._validate_channel(self._selected["channel"])
        if "installations" in self._selected:
            self._validate_installation_selection(kind)
        if "assets" in self._selected:
            self._validate_assets(self._selected["assets"])
        if "asset_manifest_sha256" in self._selected:
            c.validate_value("Sha256", self._selected["asset_manifest_sha256"])
        if "post_exec" in self._selected:
            value = exact_fields(self._selected["post_exec"],
                                 {"process", "parent", "exe_path", "executable_asset_id", "listener"}, "selected.post_exec")
            c.validate("ProcessIdentity", value["process"])
            c.validate("ProcessIdentity", value["parent"])
            c.validate_value("Id", value["executable_asset_id"])
            require(type(value["exe_path"]) is str and value["exe_path"].startswith("/"),
                    "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "selected.exe_path")
            self._validate_listener(value["listener"])
        if "peer" in self._selected:
            value = exact_fields(self._selected["peer"], {"first_packet", "current"}, "selected.peer")
            packet = exact_fields(value["first_packet"],
                {"channel_id", "endpoint_id", "owner", "ucred", "mac_valid", "sequence", "received_at", "key_operation_id"}, "selected.first_packet")
            for name in ["channel_id", "endpoint_id", "key_operation_id"]:
                c.validate_value("Id", packet[name])
            c.validate("ProcessIdentity", packet["owner"])
            c.validate_value("array<UInt>[3,3]", packet["ucred"])
            c.validate_value("Bool", packet["mac_valid"])
            c.validate_value("PositiveInt", packet["sequence"])
            c.validate("Stamp", packet["received_at"])
            current = exact_fields(value["current"], {"process", "endpoint_id", "descriptor", "observed"}, "selected.current_peer")
            c.validate("ProcessIdentity", current["process"])
            c.validate_value("Id", current["endpoint_id"])
            c.validate("DescriptorIdentity", current["descriptor"])
            c.validate("Stamp", current["observed"])
        if "source_argument_ref" in self._selected:
            c.validate("ObjectRef", self._selected["source_argument_ref"])

    def _validate_installation_selection(self, kind: str) -> None:
        contract = self.contract
        require(type(self._selected["installations"]) is dict and set(self._selected["installations"]) == {kind},
                "CONTEXT_MISMATCH", "stage.installation_selection")
        selected = self._selected["installations"][kind]
        exact_fields(selected, {"process", "descriptors", "descriptor_plan", "rules", "targets", "abi", "handled_fs"},
                     "selected.installation")
        contract.validate("ProcessIdentity", selected["process"])
        contract.validate_value("array<DescriptorIdentity>[3,16]", selected["descriptors"])
        contract.validate_value("Int[4,2147483647]", selected["abi"])
        contract.validate_value("UInt", selected["handled_fs"])
        spawn = exact_fields(selected["descriptor_plan"],
                             {"role", "process", "parent", "descriptors", "selection_origin"}, "selected.spawn")
        contract.validate("ProcessIdentity", spawn["parent"])
        require(spawn["role"] == kind and spawn["selection_origin"] == "PUBLIC_TRUSTED_SPAWN_PREMISE"
                and _same(spawn["process"], selected["process"])
                and _same(spawn["descriptors"], selected["descriptors"]),
                "DESCRIPTOR_IDENTITY_MISMATCH", "selected.spawn_binding")
        require(type(selected["rules"]) is list and 0 <= len(selected["rules"]) <= 252
                and type(selected["targets"]) is list, "CONTEXT_MISMATCH", "selected.rules")
        _unique(selected["descriptors"], "DESCRIPTOR_IDENTITY_MISMATCH", "selected.descriptors")
        require(len({x["fd"] for x in selected["descriptors"]}) == len(selected["descriptors"]),
                "DESCRIPTOR_IDENTITY_MISMATCH", "selected.fd_numbers")
        rule_ids, target_ids = [], []
        for rule in selected["rules"]:
            exact_fields(rule, {"target_id", "rights"}, "selected.rule")
            contract.validate_value("Id", rule["target_id"])
            contract.validate_value("PositiveInt", rule["rights"])
            require(rule["rights"] & ~selected["handled_fs"] == 0,
                    "CONTEXT_MISMATCH", "selected.handled_fs")
            rule_ids.append(rule["target_id"])
        for target in selected["targets"]:
            exact_fields(target, {"target_id", "device", "inode", "resolved_path"}, "selected.target")
            contract.validate_value("Id", target["target_id"])
            contract.validate_value("UInt", target["device"])
            contract.validate_value("PositiveInt", target["inode"])
            require(type(target["resolved_path"]) is str and target["resolved_path"].startswith("/"),
                    "CONTEXT_MISMATCH", "selected.target_path")
            target_ids.append(target["target_id"])
        require(len(rule_ids) == len(set(rule_ids)) and len(target_ids) == len(set(target_ids))
                and set(rule_ids) == set(target_ids), "CONTEXT_MISMATCH", "selected.target_ids")

    def _validate_assets(self, rows: Any) -> None:
        require(type(rows) is list and 1 <= len(rows) <= 256,
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "assets")
        ids, paths = [], []
        for row in rows:
            exact_fields(row, {"asset_id", "path", "bytes", "sha256", "device", "inode", "read_only"}, "asset")
            self.contract.validate_value("Id", row["asset_id"])
            self.contract.validate_value("PositiveInt", row["bytes"])
            self.contract.validate_value("Sha256", row["sha256"])
            self.contract.validate_value("UInt", row["device"])
            self.contract.validate_value("PositiveInt", row["inode"])
            require(row["read_only"] is True and type(row["path"]) is str and row["path"].startswith("/"),
                    "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "asset.path_readonly")
            ids.append(row["asset_id"]); paths.append(row["path"])
        require(len(set(ids)) == len(ids) and len(set(paths)) == len(paths),
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "assets.unique")

    @staticmethod
    def _prior(accepted: tuple[dict[str, Any], ...], kind: str) -> dict[str, Any]:
        found = [r for r in accepted if r["event"]["kind"] == kind]
        require(len(found) == 1, "INCOMPLETE_STREAM", "required_predecessor")
        return found[0]

    def _inside(self, event: dict[str, Any], stamp: dict[str, Any]) -> None:
        self.contract.validate("Stamp", stamp)
        require(stamp_le(event["observed_start"], stamp) and stamp_le(stamp, event["observed_end"]),
                "CONTEXT_MISMATCH", "raw.observation_interval")

    def validate(self, event: dict[str, Any], payload: dict[str, Any], evidence: PublicEvidence,
                 accepted: tuple[dict[str, Any], ...], *, now: dict[str, Any]) -> None:
        require(type(evidence) is PublicEvidence, "DECODER_UNAVAILABLE", "public_evidence_only")
        kind = event["kind"]
        required_selections = {
            "SETUP_BEGIN": {"controller"},
            "CALIBRATION_BEGIN": {"controller", "calibration"},
            "CALIBRATION_CASE": {"controller", "calibration"},
            "CALIBRATION_RETIRED": {"calibration"},
            "FINAL_CHANNEL_CREATED": {"controller", "channel"},
            "RUNNER_INSTALL": {"controller", "installations"},
            "MODEL_INSTALL": {"installations"},
            "ASSET_BINDINGS": {"assets", "asset_manifest_sha256"},
            "MODEL_POST_EXEC": {"assets", "post_exec"},
            "FINAL_PEER_BOUND": {"channel", "peer"},
            "POLICY_ARGUMENT": {"source_argument_ref"},
            "SETUP_SEAL": set(),
        }
        require(kind in required_selections, "DECODER_UNAVAILABLE", "normal_event.kind")
        require(set(self._selected) == required_selections[kind] | {"subject_id"},
                "CONTEXT_MISMATCH", "stage.selection_fields")
        self.contract.validate_value("Id", self._selected["subject_id"])
        require(self._selected["subject_id"] == self.coverage.slot(event["slot_id"])["expected_subject_id"],
                "CONTEXT_MISMATCH", "stage.subject_binding")
        self._validate_selections(kind)
        if "controller" in self._selected:
            self.contract.validate("ProcessIdentity", self._selected["controller"])
            if kind != "SETUP_BEGIN":
                require(_same(self._selected["controller"], self._prior(accepted, "SETUP_BEGIN")["payload"]["producer_identity"]),
                        "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "stage.controller_continuity")
        if "calibration" in self._selected:
            controller = self._prior(accepted, "SETUP_BEGIN")["payload"]["producer_identity"]
            selected_calibration = self._selected["calibration"]
            actors = selected_calibration["temporary_actors"]
            require(all(a["pid"] != controller["pid"] for a in actors)
                    and any(_same(a, selected_calibration["foreign_sender"]) for a in actors)
                    and (_same(selected_calibration["expected_peer"], controller)
                         or any(_same(a, selected_calibration["expected_peer"]) for a in actors)),
                    "CALIBRATION_BASELINE_MISMATCH", "calibration.temporary_actor_scope")
            if kind != "CALIBRATION_BEGIN":
                begun = self._prior(accepted, "CALIBRATION_BEGIN")
                require(_same(selected_calibration, begun["selected_values"]["calibration"]),
                        "CALIBRATION_BASELINE_MISMATCH", "calibration.selection_continuity")
        self.contract.validate(self._spec["payload_type_by_event_kind"][kind], payload)
        evidence.resolve_nested(event)
        evidence.resolve_nested(payload)
        required_kinds = set(self.coverage.slot(event["slot_id"])["required_raw_kinds"])
        require(required_kinds <= {r["artifact_kind"] for r in event["raw_refs"]},
                "RAW_EVIDENCE_UNAVAILABLE", "required_raw_kinds")
        if kind == "SETUP_BEGIN":
            require(payload["coverage_plan_sha256"] == self.coverage.sha256
                    and payload["budget_sha256"] == event["budget_sha256"]
                    and payload["producer_identity"] == self._selected["controller"],
                    "CONTEXT_MISMATCH", "setup_begin")
            actual = evidence.one(event, "PROC_IDENTITY")
            require(_same(actual, payload["producer_identity"]), "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "controller.actual")
        elif kind == "CALIBRATION_BEGIN":
            selected = self._selected["calibration"]
            require(payload["receiver_identity"] == self._selected["controller"]
                    and payload["receiver_component_sha256"] == selected["receiver_component_sha256"] == self.coverage.receiver_component_sha256
                    and payload["planned_case_ids"] == self.coverage.case_ids,
                    "CALIBRATION_WRONG_ORIGIN", "calibration_begin")
            require(_same(evidence.one(event, "PROC_IDENTITY"), payload["receiver_identity"]),
                    "CALIBRATION_WRONG_ORIGIN", "receiver.actual")
        elif kind == "CALIBRATION_CASE":
            self._calibration(event, payload, evidence, accepted)
        elif kind == "CALIBRATION_RETIRED":
            cases = [r for r in accepted if r["event"]["kind"] == "CALIBRATION_CASE"]
            require(len(cases) == 8 and payload["completed_case_ids"] == self.coverage.case_ids,
                    "CALIBRATION_INCOMPLETE", "retired.cases")
            endpoints = [x for r in cases for x in r["payload"]["channel_object_ids"]]
            close = exact_fields(evidence.object(payload["endpoint_retirement_ref"], kind="ENDPOINT_RETIREMENT"),
                                 {"closed_endpoint_ids", "observed"}, "retired.endpoints")
            require(sorted(close["closed_endpoint_ids"]) == sorted(endpoints)
                    and len(set(close["closed_endpoint_ids"])) == len(endpoints),
                    "CLEANUP_UNCONFIRMED", "retired.endpoints")
            self._inside(event, close["observed"])
            process = exact_fields(evidence.object(payload["process_retirement_ref"], kind="PROCESS_RETIREMENT"),
                                   {"challenger", "retired_pids", "retired_identities", "remaining_descendants", "unclosed_delivered_fds", "observed"},
                                   "retired.processes")
            require(process["challenger"] == payload["challenger_identity"] == self._selected["calibration"]["foreign_sender"]
                    and process["remaining_descendants"] == [] and process["unclosed_delivered_fds"] == [],
                    "CLEANUP_UNCONFIRMED", "retired.processes")
            selected_pids = sorted(self._selected["calibration"]["retired_pids"])
            selected_actors = self._selected["calibration"]["temporary_actors"]
            self.contract.validate_value("array<ProcessIdentity>[1,256]", process["retired_identities"])
            wrong = [r for r in cases if r["payload"]["case_kind"] == "WRONG_PEER_PID"]
            require(len(wrong) == 1 and _same(payload["challenger_identity"], wrong[0]["payload"]["exchanges"][0]["actual_sender_identity"])
                    and sorted(canonical_bytes(x) for x in process["retired_identities"])
                    == sorted(canonical_bytes(x) for x in selected_actors),
                    "CLEANUP_UNCONFIRMED", "retired.approved_temporary_actors")
            require(sorted(process["retired_pids"]) == selected_pids
                    and len(set(process["retired_pids"])) == len(process["retired_pids"]),
                    "CLEANUP_UNCONFIRMED", "retired.pids")
            self._inside(event, process["observed"])
        elif kind == "FINAL_CHANNEL_CREATED":
            retired = self._prior(accepted, "CALIBRATION_RETIRED")
            require(payload["calibration_retired_record_id"] == retired["event"]["record_id"],
                    "CONTEXT_MISMATCH", "creation.retirement")
            actual = exact_fields(evidence.object(payload["endpoint_inventory_ref"], kind="DESCRIPTOR_INVENTORY"),
                                  {"channel_id", "endpoint_ids", "owner", "key_operation_id", "created_at"}, "creation.raw")
            selected = self._selected["channel"]
            require(_same(actual, selected) and payload["channel_id"] == actual["channel_id"]
                    and payload["key_generation_operation_id"] == actual["key_operation_id"]
                    and actual["owner"] == self._selected["controller"],
                    "CONTEXT_MISMATCH", "creation.selection")
            self._inside(event, actual["created_at"])
            require(stamp_le(retired["event"]["recorded"], actual["created_at"]),
                    "AUTHORITY_CREATED_EARLY", "creation.time")
            require(len(actual["endpoint_ids"]) == 2 and len(set(actual["endpoint_ids"])) == 2,
                    "CONTEXT_MISMATCH", "creation.endpoints")
            for prior in accepted:
                if prior["event"]["kind"] == "CALIBRATION_CASE":
                    p = prior["payload"]
                    require(not set(actual["endpoint_ids"]) & set(p["channel_object_ids"])
                            and actual["channel_id"] != p["channel_instance_id"]
                            and actual["key_operation_id"] != p["public_fixture_key_id"],
                            "AUTHORITY_CREATED_EARLY", "creation.reuse")
        elif kind in {"RUNNER_INSTALL", "MODEL_INSTALL"}:
            self._installation(event, payload, evidence, accepted)
        elif kind == "ASSET_BINDINGS":
            actual = evidence.object(payload["actual_file_inventory_ref"], kind="ASSET_INVENTORY")
            self._validate_assets(actual)
            require(_same(actual, self._selected["assets"]) and payload["selected_asset_manifest_sha256"] ==
                    self._selected["asset_manifest_sha256"], "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "assets.selected")
            self._inside(event, payload["hash_scan_started"])
            self._inside(event, payload["hash_scan_completed"])
            require(stamp_le(payload["hash_scan_started"], payload["hash_scan_completed"]),
                    "CONTEXT_MISMATCH", "assets.hash_interval")
        elif kind == "MODEL_POST_EXEC":
            self._post_exec(event, payload, evidence, accepted)
        elif kind == "FINAL_PEER_BOUND":
            self._peer(event, payload, evidence, accepted, now)
        elif kind == "POLICY_ARGUMENT":
            self.contract.validate("ObjectRef", self._selected["source_argument_ref"])
            require(self._selected["source_argument_ref"]["artifact_kind"] == "SOURCE_ARGUMENT",
                    "PURPOSE_MISMATCH", "source_argument")
            require(len(accepted) == 17, "INCOMPLETE_STREAM", "policy.prefix")
            runner, model = self._prior(accepted, "RUNNER_INSTALL"), self._prior(accepted, "MODEL_INSTALL")
            post = self._prior(accepted, "MODEL_POST_EXEC")
            require(payload["installation_record_ids"] == [runner["event"]["record_id"], model["event"]["record_id"]]
                    and payload["post_exec_record_id"] == post["event"]["record_id"]
                    and payload["source_argument_ref"] == self._selected["source_argument_ref"],
                    "CLAIM_OUTSIDE_METHOD_SCOPE", "policy.references")
            argument = exact_fields(evidence.object(payload["source_argument_ref"], kind="SOURCE_ARGUMENT"),
                                    {"claim", "non_forwarding_status", "unsupported_routes", "every_task_post_exec_probes_claimed"},
                                    "policy.argument")
            require(_same(argument, {k: payload[k] for k in argument}),
                    "CLAIM_OUTSIDE_METHOD_SCOPE", "policy.argument_values")
        elif kind == "SETUP_SEAL":
            require(len(accepted) == 18 and event["sequence"] == 19,
                    "INCOMPLETE_STREAM", "seal.prefix")
            entries = [{"sequence": r["event"]["sequence"], "record_id": r["event"]["record_id"],
                        "record_sha256": r["event_sha256"]} for r in accepted]
            require(payload["entries"] == entries and payload["covered_slot_ids"] ==
                    [r["event"]["slot_id"] for r in accepted]
                    and payload["previous_head_sha256"] == accepted[-1]["event_sha256"]
                    and set(payload["covered_slot_ids"] + [event["slot_id"]]) ==
                    {s["slot_id"] for s in self.coverage.plan["slots"]},
                    "INCOMPLETE_STREAM", "seal.entries")
        else:
            require(False, "DECODER_UNAVAILABLE", "normal_event.kind")

    def _installation(self, event, p, evidence, accepted):
        kind = event["kind"]
        self._validate_installation_selection(kind)
        selected = self._selected["installations"][kind]
        require(p["process_identity"] == selected["process"],
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "install.spawn_identity")
        observation = exact_fields(evidence.one(event, "PROC_IDENTITY"),
                                   {"process", "parent", "threads", "observed_start", "observed_end"}, "install.proc")
        require(_same(observation["process"], p["process_identity"]) and _same(observation["threads"], p["threads"]),
                "INSTALLATION_FAILED_OR_UNOBSERVED", "install.actual_threads")
        self._inside(event, observation["observed_start"]); self._inside(event, observation["observed_end"])
        require(stamp_le(observation["observed_start"], observation["observed_end"])
                and p["threads"][0]["tid"] == p["process_identity"]["pid"]
                and p["threads"][0]["start_ticks"] == p["process_identity"]["start_ticks"],
                "INSTALLATION_FAILED_OR_UNOBSERVED", "install.single_thread")
        if kind == "RUNNER_INSTALL":
            parent = self._selected["controller"]
            require(p["parent_installation_record_id"] is None,
                    "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "runner.parent_record")
        else:
            runner = self._prior(accepted, "RUNNER_INSTALL")
            parent = runner["payload"]["process_identity"]
            require(p["parent_installation_record_id"] == runner["event"]["record_id"]
                    and stamp_le(runner["event"]["observed_end"], event["observed_start"]),
                    "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "model.parent_record")
        require(p["process_identity"]["parent_pid"] == parent["pid"]
                and p["process_identity"]["boot_id"] == parent["boot_id"] and _same(observation["parent"], parent),
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "install.parent")
        descriptor_plan = evidence.object(p["expected_descriptor_plan_ref"], kind="DESCRIPTOR_INVENTORY")
        require(_same(descriptor_plan, selected["descriptor_plan"]),
                "DESCRIPTOR_IDENTITY_MISMATCH", "install.descriptor_plan")
        require(_same(descriptor_plan["parent"], parent),
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "install.spawn_parent")
        actual = exact_fields(evidence.one(event, "DESCRIPTOR_INVENTORY"),
                              {"process", "descriptors", "observed"}, "install.descriptor_read")
        require(_same(actual["process"], p["process_identity"]) and _same(actual["descriptors"], p["initial_descriptors"])
                and _same(sorted(p["initial_descriptors"], key=lambda x: x["fd"]), sorted(selected["descriptors"], key=lambda x: x["fd"])),
                "DESCRIPTOR_IDENTITY_MISMATCH", "install.descriptors")
        self._inside(event, actual["observed"])
        require(len({d["fd"] for d in p["initial_descriptors"]}) == len(p["initial_descriptors"]),
                "DESCRIPTOR_IDENTITY_MISMATCH", "install.duplicate_fd")
        rules = evidence.object(p["normalized_rules_ref"], kind="NORMALIZED_RULES")
        targets = evidence.object(p["rule_target_inventory_ref"], kind="RULE_TARGET_INVENTORY")
        require(_same(rules, selected["rules"]) and _same(targets, selected["targets"])
                and p["handled_fs"] == selected["handled_fs"] and p["landlock_abi"] == selected["abi"],
                "INSTALLATION_FAILED_OR_UNOBSERVED", "install.selected_policy")
        calls = p["syscalls"]
        require(len(calls) == len(rules) + 4, "INSTALLATION_FAILED_OR_UNOBSERVED", "install.call_count")
        arguments = [evidence.object(call["arguments_ref"], kind="INSTALL_ARGUMENTS") for call in calls]
        require(calls[0]["operation"] == "LANDLOCK_CREATE_RULESET"
                and _same(arguments[0], {"mode": "ABI_QUERY"}) and calls[0]["return_value"] == p["landlock_abi"]
                and calls[1]["operation"] == "LANDLOCK_CREATE_RULESET"
                and _same(arguments[1], {"mode": "CREATE", "handled_fs": p["handled_fs"]})
                and calls[1]["return_value"] >= 0,
                "INSTALLATION_FAILED_OR_UNOBSERVED", "install.create_calls")
        ruleset_fd = calls[1]["return_value"]
        by_target = {x["target_id"]: x for x in targets}
        for i, rule in enumerate(rules, 2):
            require(calls[i]["operation"] == "LANDLOCK_ADD_RULE"
                    and _same(arguments[i], {"ruleset_fd": ruleset_fd, "target": by_target[rule["target_id"]], "rights": rule["rights"]})
                    and calls[i]["return_value"] == 0,
                    "INSTALLATION_FAILED_OR_UNOBSERVED", "install.add_rule")
        require(calls[-2]["operation"] == "PR_SET_NO_NEW_PRIVS"
                and _same(arguments[-2], {"no_new_privs": 1}) and calls[-2]["return_value"] == 0
                and calls[-1]["operation"] == "LANDLOCK_RESTRICT_SELF"
                and _same(arguments[-1], {"ruleset_fd": ruleset_fd, "flags": 0})
                and calls[-1]["return_value"] == 0,
                "INSTALLATION_FAILED_OR_UNOBSERVED", "install.restrict_calls")
        for i, call in enumerate(calls):
            self._inside(event, call["observed"])
            require(call["errno"] == 0, "INSTALLATION_FAILED_OR_UNOBSERVED", "install.errno")
            if i: require(stamp_le(calls[i-1]["observed"], call["observed"]),
                          "INSTALLATION_FAILED_OR_UNOBSERVED", "install.call_order")
        nnp = exact_fields(evidence.one(event, "INSTALL_ARGUMENTS"),
                           {"process", "no_new_privs", "observed"}, "install.nnp_readback")
        require(_same(nnp["process"], p["process_identity"]) and type(nnp["no_new_privs"]) is int
                and nnp["no_new_privs"] == 1 and stamp_le(calls[-1]["observed"], nnp["observed"]),
                "INSTALLATION_FAILED_OR_UNOBSERVED", "install.nnp_readback")
        self._inside(event, nnp["observed"])

    def _post_exec(self, event, p, evidence, accepted):
        model = self._prior(accepted, "MODEL_INSTALL"); assets = self._prior(accepted, "ASSET_BINDINGS")
        runner = self._prior(accepted, "RUNNER_INSTALL")
        parent = runner["payload"]["process_identity"]
        self._validate_assets(self._selected["assets"])
        require(_same(self._selected["assets"], assets["selected_values"]["assets"]),
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "postexec.asset_selection_continuity")
        require(p["wrapper_installation_record_id"] == model["event"]["record_id"]
                and p["asset_binding_record_id"] == assets["event"]["record_id"],
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "postexec.references")
        before, after = model["payload"]["process_identity"], p["actual_server_identity"]
        for key in ["boot_id", "pid", "start_ticks", "parent_pid", "uid", "gid", "namespace_inventory_ref", "mount_inventory_ref"]:
            require(before[key] == after[key], "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "postexec.lineage")
        require(stamp_le(model["event"]["observed_end"], event["observed_start"]),
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "postexec.causal_time")
        actual = exact_fields(evidence.one(event, "PROC_IDENTITY"),
                              {"process", "parent", "exe_path", "observed"}, "postexec.actual")
        self.contract.validate("ProcessIdentity", actual["parent"])
        require(_same(actual["process"], after) and _same(after, self._selected["post_exec"]["process"])
                and _same(actual["parent"], parent) and _same(actual["parent"], self._selected["post_exec"]["parent"])
                and _same(parent, model["selected_values"]["installations"]["MODEL_INSTALL"]["descriptor_plan"]["parent"]),
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "postexec.actual")
        self._inside(event, actual["observed"])
        lineage = exact_fields(evidence.object(p["wrapper_to_exec_identity_ref"], kind="EXEC_LINEAGE"),
                               {"before", "after", "parent", "exe_path", "observed"}, "postexec.raw_lineage")
        require(_same(lineage["before"], before) and _same(lineage["after"], after)
                and _same(lineage["parent"], parent) and _same(lineage["parent"], actual["parent"])
                and lineage["exe_path"] == actual["exe_path"] == self._selected["post_exec"]["exe_path"],
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "postexec.raw_lineage")
        self._inside(event, lineage["observed"])
        matches = [a for a in self._selected["assets"] if a["asset_id"] == self._selected["post_exec"]["executable_asset_id"]]
        require(len(matches) == 1, "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "postexec.asset")
        asset = matches[0]
        require(actual["exe_path"] == asset["path"]
                and after["exe_device"] == asset["device"] and after["exe_inode"] == asset["inode"]
                and after["exe_object_ref"]["sha256"] == asset["sha256"]
                and after["exe_object_ref"]["bytes"] == asset["bytes"],
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "postexec.exe")
        listener = exact_fields(evidence.object(p["owned_listener_ref"], kind="LISTENER_IDENTITY"),
                                {"process", "address", "port", "socket_inode", "observed"}, "postexec.listener")
        require(_same(listener, self._selected["post_exec"]["listener"]) and _same(listener["process"], after)
                and listener["address"] == "127.0.0.1" and type(listener["port"]) is int
                and 1 <= listener["port"] <= 65535 and type(listener["socket_inode"]) is int
                and listener["socket_inode"] > 0, "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "postexec.listener")
        self._inside(event, listener["observed"])

    def _peer(self, event, p, evidence, accepted, now):
        created = self._prior(accepted, "FINAL_CHANNEL_CREATED")
        require(_same(self._selected["channel"], created["selected_values"]["channel"]),
                "CONTEXT_MISMATCH", "peer.channel_selection_continuity")
        runner = self._prior(accepted, "RUNNER_INSTALL"); post = self._prior(accepted, "MODEL_POST_EXEC")
        peer = runner["payload"]["process_identity"]
        require(p["channel_created_record_id"] == created["event"]["record_id"]
                and p["channel_id"] == created["payload"]["channel_id"]
                and p["model_post_exec_record_id"] == post["event"]["record_id"]
                and p["actual_peer_identity"] == peer
                and p["actual_ucred"] == [peer["pid"], peer["uid"], peer["gid"]],
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "peer.binding")
        packet = exact_fields(evidence.object(p["first_packet_ref"], kind="IPC_RECEIVE"),
                              {"channel_id", "endpoint_id", "owner", "ucred", "mac_valid", "sequence", "received_at", "key_operation_id"},
                              "peer.first_packet")
        require(_same(packet, self._selected["peer"]["first_packet"])
                and packet["owner"] == peer and packet["channel_id"] == p["channel_id"]
                and packet["ucred"] == p["actual_ucred"] and packet["mac_valid"] is True
                and type(packet["sequence"]) is int and packet["sequence"] == 1
                and packet["key_operation_id"] == created["payload"]["key_generation_operation_id"]
                and packet["endpoint_id"] == self._selected["channel"]["endpoint_ids"][1],
                "CONTEXT_MISMATCH", "peer.first_packet")
        require(stamp_le(created["event"]["recorded"], packet["received_at"])
                and stamp_le(packet["received_at"], event["observed_end"]),
                "CONTEXT_MISMATCH", "peer.first_packet_time")
        current = exact_fields(evidence.one(event, "PROC_IDENTITY"),
                               {"process", "endpoint_id", "descriptor", "observed"}, "peer.current")
        self.contract.validate("DescriptorIdentity", current["descriptor"])
        retained_descriptors = [d for d in runner["payload"]["initial_descriptors"]
                                if d["selected_target_id"] == packet["endpoint_id"]]
        spawn_descriptors = runner["selected_values"]["installations"]["RUNNER_INSTALL"]["descriptor_plan"]["descriptors"]
        require(len(retained_descriptors) == 1 and retained_descriptors[0]["object_type"] == "SOCKET"
                and _same(current["descriptor"], retained_descriptors[0])
                and sum(_same(d, current["descriptor"]) for d in spawn_descriptors) == 1,
                "DESCRIPTOR_IDENTITY_MISMATCH", "peer.retained_runner_endpoint")
        require(current["process"] == peer and current["endpoint_id"] == packet["endpoint_id"]
                and _same(current, self._selected["peer"]["current"]),
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "peer.current")
        self._inside(event, current["observed"])
        require(stamp_le(post["event"]["recorded"], current["observed"])
                and stamp_le(current["observed"], now), "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "peer.current_time")

    def _calibration(self, event, p, evidence, accepted):
        expectation = self.coverage.expectation(event["slot_id"])
        baseline = self._spec["fixed_calibration_baseline"][p["case_kind"]]
        selected = self._selected["calibration"]
        begun = self._prior(accepted, "CALIBRATION_BEGIN")
        require(p["case_id"] == expectation["case_id"] and p["slot_id"] == expectation["slot_id"]
                and p["case_kind"] == expectation["case_kind"] and p["fixture_ref"] == expectation["fixture_ref"]
                and p["receiver_component_sha256"] == expectation["receiver_component_sha256"] == selected["receiver_component_sha256"]
                == begun["payload"]["receiver_component_sha256"] == self.coverage.receiver_component_sha256
                and p["receiver_identity"] == self._selected["controller"]
                and p["expected_peer_identity"] == selected["expected_peer"],
                "CALIBRATION_BASELINE_MISMATCH", "case.bindings")
        fixture = exact_fields(evidence.object(p["fixture_ref"], kind="PUBLIC_FIXTURE"),
                               {"case_kind", "public_only"}, "case.fixture")
        require(_same(fixture, {"case_kind": p["case_kind"], "public_only": True}),
                "CALIBRATION_BASELINE_MISMATCH", "case.fixture")
        require(len(set(p["channel_object_ids"])) == 2,
                "CALIBRATION_BASELINE_MISMATCH", "case.endpoints")
        for row in accepted:
            if row["event"]["kind"] != "CALIBRATION_CASE": continue
            prior = row["payload"]
            for key in ["channel_instance_id", "verifier_instance_id", "public_fixture_key_id"]:
                require(p[key] != prior[key], "CALIBRATION_BASELINE_MISMATCH", "case.reused_instance")
            require(not set(p["channel_object_ids"]) & set(prior["channel_object_ids"]),
                    "CALIBRATION_BASELINE_MISMATCH", "case.reused_endpoint")
        exchanges = p["exchanges"]
        require(len(exchanges) == len(baseline["exchange_verdicts"]),
                "CALIBRATION_BASELINE_MISMATCH", "case.exchange_count")
        live = exact_fields(evidence.one(event, "PROC_IDENTITY"),
                            {"receiver", "expected_peer", "senders", "live_pids", "observed"}, "case.live")
        expected_senders = [selected["foreign_sender"] if baseline["foreign_pid"] else selected["expected_peer"]]
        require(_same(live["receiver"], p["receiver_identity"]) and _same(live["expected_peer"], p["expected_peer_identity"])
                and _same(live["senders"], expected_senders)
                and {x["pid"] for x in [live["receiver"], live["expected_peer"], *live["senders"]]} <= set(live["live_pids"]),
                "CALIBRATION_BASELINE_MISMATCH", "case.live")
        self._inside(event, live["observed"])
        for i, exchange in enumerate(exchanges):
            self._inside(event, exchange["observed_start"]); self._inside(event, exchange["observed_end"])
            require(stamp_le(exchange["observed_start"], exchange["observed_end"])
                    and exchange["exchange_index"] == i + 1
                    and exchange["verdict"] == baseline["exchange_verdicts"][i]
                    and exchange["rejection_stage"] == baseline["rejection_stages"][i]
                    and [exchange["recv_seq_before"], exchange["recv_seq_after"]] == baseline["recv_sequences"][i]
                    and exchange["receiver_closed_before"] is False
                    and exchange["receiver_closed_after"] == baseline["closed_after"][i],
                    "CALIBRATION_UNEXPECTED_OUTCOME", "case.outcome")
            sender = expected_senders[0]
            require(exchange["actual_sender_identity"] == sender,
                    "CALIBRATION_BASELINE_MISMATCH", "case.sender")
            sent = exact_fields(evidence.object(exchange["sent_record_ref"], kind="IPC_SEND"),
                                {"application_hex", "frames_hex", "sender", "return_value", "errno"}, "case.send")
            received = exact_fields(evidence.object(exchange["recv_record_ref"], kind="IPC_RECEIVE"),
                                    {"frames_hex", "receiver", "actual_ucred", "return_value", "errno", "msg_trunc", "msg_ctrunc", "delivered_fds"},
                                    "case.recv")
            packet_bytes, sent_frames = _hex(sent["application_hex"], "case.packet"), _hex(sent["frames_hex"], "case.frames")
            received_frames = _hex(received["frames_hex"], "case.received_frames")
            require(_same(sent["sender"], sender) and _same(received["receiver"], p["receiver_identity"]),
                    "CALIBRATION_BASELINE_MISMATCH", "case.wire_processes")
            require(type(sent["return_value"]) is int and type(received["return_value"]) is int
                    and sent["return_value"] == exchange["send_return"] == len(sent_frames) > 0
                    and received["return_value"] == exchange["recv_return"] == len(received_frames) > 0
                    and type(sent["errno"]) is int and type(received["errno"]) is int
                    and sent["errno"] == received["errno"] == 0
                    and digest(packet_bytes) == exchange["sent_application_packet_sha256"]
                    and digest(sent_frames) == exchange["sent_frames_sha256"]
                    and digest(received_frames) == exchange["received_frames_sha256"]
                    and sent_frames == received_frames,
                    "CALIBRATION_BASELINE_MISMATCH", "case.wire_bytes")
            for key in ["actual_ucred", "msg_trunc", "msg_ctrunc", "delivered_fds"]:
                require(_same(received[key], exchange[key]), "CALIBRATION_BASELINE_MISMATCH", "case.recv_fields")
            require(exchange["msg_trunc"] is False and exchange["msg_ctrunc"] == (p["case_kind"] == "TRUNCATED_RIGHTS"),
                    "CALIBRATION_BASELINE_MISMATCH", "case.flags")
            credentials = exchange["actual_ucred"]
            if credentials is None:
                require(p["case_kind"] == "TRUNCATED_RIGHTS", "CALIBRATION_BASELINE_MISMATCH", "case.missing_ucred")
            else:
                require(credentials == {"pid": sender["pid"], "uid": sender["uid"], "gid": sender["gid"]},
                        "CALIBRATION_BASELINE_MISMATCH", "case.actual_ucred")
            expected = p["expected_peer_identity"]
            require(sender["uid"] == expected["uid"] and sender["gid"] == expected["gid"]
                    and ((sender["pid"] != expected["pid"]) == baseline["foreign_pid"]),
                    "CALIBRATION_BASELINE_MISMATCH", "case.foreign_pid")
            trace = exact_fields(evidence.object(exchange["verifier_trace_ref"], kind="VERIFIER_TRACE"),
                {"frame_valid", "mac_valid", "channel_matches", "packet_sequence", "verdict", "rejection_stage", "seq_before", "seq_after",
                 "closed_before", "closed_after", "handler_before", "handler_after", "instance_id", "channel_instance_id", "key_id",
                 "exchange_id", "verdict_operation_index", "exposure_operation_index", "verdict_observed", "exposure_observed"}, "case.trace")
            exchange_id = p["case_id"] + "-exchange-" + str(i + 1)
            self.contract.validate_value("PositiveInt", trace["verdict_operation_index"])
            self.contract.validate_value("PositiveInt", trace["exposure_operation_index"])
            self._inside(event, trace["verdict_observed"]); self._inside(event, trace["exposure_observed"])
            require(trace["exchange_id"] == exchange_id
                    and trace["verdict_operation_index"] < trace["exposure_operation_index"]
                    and stamp_le(exchange["observed_start"], trace["verdict_observed"])
                    and stamp_le(trace["verdict_observed"], trace["exposure_observed"])
                    and stamp_le(trace["exposure_observed"], exchange["observed_end"]),
                    "CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE", "case.outcome_order")
            expected_trace = {"frame_valid": p["case_kind"] != "BAD_FRAME", "mac_valid": p["case_kind"] != "BAD_MAC",
                "channel_matches": p["case_kind"] != "BAD_CHANNEL_ID", "packet_sequence": 1,
                "verdict": exchange["verdict"], "rejection_stage": exchange["rejection_stage"],
                "seq_before": exchange["recv_seq_before"], "seq_after": exchange["recv_seq_after"],
                "closed_before": exchange["receiver_closed_before"], "closed_after": exchange["receiver_closed_after"],
                "handler_before": 0, "handler_after": 0, "instance_id": p["verifier_instance_id"],
                "channel_instance_id": p["channel_instance_id"], "key_id": p["public_fixture_key_id"],
                "exchange_id": exchange_id, "verdict_operation_index": trace["verdict_operation_index"],
                "exposure_operation_index": trace["exposure_operation_index"],
                "verdict_observed": trace["verdict_observed"], "exposure_observed": trace["exposure_observed"]}
            require(canonical_bytes(trace) == canonical_bytes(expected_trace),
                    "CALIBRATION_UNEXPECTED_OUTCOME", "case.trace_values")
            delivered, closes = exchange["delivered_fds"], exchange["close_outcomes"]
            require(baseline["delivered_rights_minimum"] <= len(delivered) <= baseline["delivered_rights_maximum"],
                    "CALIBRATION_EMPTY_RIGHTS", "case.rights_count")
            require(len({d["fd"] for d in delivered}) == len(delivered) and len(closes) == len(delivered),
                    "CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE", "case.close_count")
            require(sorted(canonical_bytes(x) for x in delivered) == sorted(canonical_bytes(x["descriptor"]) for x in closes),
                    "CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE", "case.close_bijection")
            close_indices = []
            for close in closes:
                require(stamp_le(exchange["observed_start"], close["closed_at"])
                        and stamp_le(close["closed_at"], exchange["observed_end"]),
                        "CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE", "case.close_time")
                raw = exact_fields(evidence.object(close["raw_close_ref"], kind="DESCRIPTOR_CLOSES"),
                                   {"descriptor", "return_value", "errno", "observed", "exchange_id", "operation_index"}, "case.close_raw")
                self.contract.validate_value("PositiveInt", raw["operation_index"])
                close_indices.append(raw["operation_index"])
                require(raw["exchange_id"] == exchange_id and raw["operation_index"] < trace["verdict_operation_index"]
                        and stamp_le(close["closed_at"], trace["verdict_observed"]),
                        "CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE", "case.close_before_reject_expose")
                require(_same(raw, {"descriptor": close["descriptor"], "return_value": 0, "errno": 0, "observed": close["closed_at"],
                                   "exchange_id": exchange_id, "operation_index": raw["operation_index"]}),
                        "CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE", "case.close_raw")
            require(len(set(close_indices)) == len(close_indices), "CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE", "case.close_order_unique")
        if p["case_kind"] == "BAD_SEQUENCE":
            first, second = exchanges
            require(stamp_le(first["observed_end"], second["observed_start"]),
                    "CALIBRATION_REPLAY_NOT_DEMONSTRATED", "replay.time")
            for key in ["sent_application_packet_sha256", "sent_frames_sha256", "received_frames_sha256", "actual_sender_identity"]:
                require(first[key] == second[key], "CALIBRATION_REPLAY_NOT_DEMONSTRATED", "replay.exact_bytes")
