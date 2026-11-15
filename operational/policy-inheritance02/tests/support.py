"""Public fixture authorship only; no private suite, runtime key or real signature.

The zero-filled signature field is deliberately NOT a valid Ed25519 proof. The
pure model checks its exact shape and bindings only. OperationalAdapters rejects
it unconditionally. No fixture can issue or activate runtime authority.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from policy_inheritance.contract import Contract, SPEC_SHA256, ZERO, canonical_bytes, digest, object_ref
from policy_inheritance.evidence import PublicEvidence, PublicSelections
from policy_inheritance.guards import PublicGuardSample
from policy_inheritance.machine import ProtocolModel
from policy_inheritance.checkpoint import PublicInitialView, original_key

TIMES = (4, 6, 8, 10, 13, 15, 17, 20, 23, 26, 30, 34, 67, 70, 74, 78, 82, 87, 92)
KINDS = ("SETUP_BEGIN", "CALIBRATION_BEGIN", *("CALIBRATION_CASE",) * 8,
         "CALIBRATION_RETIRED", "FINAL_CHANNEL_CREATED", "RUNNER_INSTALL", "MODEL_INSTALL",
         "ASSET_BINDINGS", "MODEL_POST_EXEC", "FINAL_PEER_BOUND", "POLICY_ARGUMENT", "SETUP_SEAL")


def h(text: str) -> str:
    return digest(text.encode("utf-8"))


def stamp(seconds: int) -> dict[str, Any]:
    value = datetime(2026, 10, 11, 8, tzinfo=timezone.utc) + timedelta(seconds=seconds)
    return {"utc": value.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "boottime_ns": 1_000_000_000_000 + seconds * 1_000_000_000}


@dataclass
class Packet:
    event: dict[str, Any]
    payload: dict[str, Any]
    selections: dict[str, Any]
    witness: dict[str, Any]
    ack: dict[str, Any]
    ack_envelope: dict[str, Any]
    evidence: PublicEvidence


class Fixture:
    def __init__(self) -> None:
        path = Path(__file__).resolve().parents[1] / "accepted-design05" / "proposed-contract.json"
        self.contract = Contract(path.read_bytes())
        self.spec = self.contract.spec
        self.objects: dict[str, bytes] = {}
        self.decoder = h("PUBLIC-SYNTHETIC-NORMALIZED-DECODER-ONLY")
        self.scope = {"method_id": "POLICY_INHERITANCE_TRUSTED_ADAPTER_V1", "method_spec_sha256": SPEC_SHA256,
                      "source_manifest_sha256": h("synthetic-source"), "config_sha256": h("synthetic-config"),
                      "topology_sha256": h("synthetic-topology"), "run_id": "public-run", "epoch": 1,
                      "original_window_sha256": h("one-original-window"), "setup_identity": "public-setup"}
        self.clock_domain = {"boot_id": "00000000-0000-0000-0000-000000000001", "time_namespace_inode": 200,
                             "clock_id": "CLOCK_BOOTTIME"}
        self.exec_python = self.put(b"PUBLIC-PYTHON-EXECUTABLE-FIXTURE", "EXECUTABLE_PIN")
        self.exec_model = self.put(b"PUBLIC-MODEL-EXECUTABLE-FIXTURE", "EXECUTABLE_PIN")
        self.namespace = self.put({"public_namespace_inode": 200}, "NAMESPACE_INVENTORY")
        self.mounts = self.put({"public_mount_identity": 300}, "MOUNT_INVENTORY")
        self.controller = self.process(7000, 100000, 6000)
        self.expected_peer = self.process(7001, 100100, 7000)
        self.foreign = self.process(7002, 100200, 7000)
        self.temporary_actors = [self.expected_peer, self.foreign]
        self.runner = self.process(7100, 110000, 7000)
        self.wrapper = self.process(7200, 111000, 7100)
        self.server = self.process(7200, 111000, 7100, model=True)
        self.case_kinds = self.spec["enums"]["CalibrationKind"]
        self.case_ids = [f"c{i:02}" for i in range(1, 9)]
        self.receiver_component = h("PUBLIC-RECEIVER-COMPONENT")
        self.plan = self._plan()
        roles = ["TRUSTED_CONTROLLER_WITNESS", "INDEPENDENT_SETUP_CONSUMER", "INDEPENDENT_CHECKPOINT_CUSTODIAN"]
        self.principal_ids = dict(zip(roles, ["witness", "consumer", "checkpoint"]))
        principals = [{"principal_id": self.principal_ids[role], "role": role,
                       "component_manifest_sha256": h("component-" + role), "signer_public_sha256": h("NOT-A-REAL-KEY-" + role),
                       "allowed_purposes": self.spec["role_purpose_allowlists"][role],
                       "not_before_utc": stamp(-60)["utc"], "expires_at_utc": stamp(300)["utc"]} for role in roles]
        self.appointment = {"format": "forex.policy-inheritance-appointment/2", "appointment_id": "public-appointment",
            "scope": self.scope, "coverage_plan_sha256": digest(canonical_bytes(self.plan)), "principals": principals,
            "clock_domain": self.clock_domain, "not_before_utc": stamp(-60)["utc"], "expires_at_utc": stamp(300)["utc"],
            "producer_staging_root_id": "public-producer", "consumer_retention_root_id": "public-consumer",
            "independent_checkpoint_root_id": "public-independent-checkpoint", "approved_runtime_topology_ref": self.put({"public_only": True}, "TOPOLOGY_APPROVAL"),
            "watchdog_binding_ref": self.put({"public_watchdog_premise_only": True}, "WATCHDOG_BINDING"),
            "stream_id": "public-stream", "checkpoint_authority_id": "checkpoint"}
        self.binding = {"scope": self.scope, "appointment_sha256": digest(canonical_bytes(self.appointment))}
        self.auth_ref = self.put({"PUBLIC_UNAUTHENTICATED_PREMISE": True}, "AUTHENTICATED_INTERVAL")
        self.budget = {"format": "forex.policy-inheritance-setup-budget/2", "binding": self.binding, "budget_id": "public-budget",
            "issuer_id": "consumer", "clock_domain": self.clock_domain, "started": stamp(0), "deadline": stamp(180),
            "outer_deadline": stamp(240), "maximum_seconds": 180, "coverage_plan_sha256": digest(canonical_bytes(self.plan)),
            "appointment_interval_ref": self.put(self.interval(0), "AUTHENTICATED_INTERVAL")}
        self.budget_hash = digest(canonical_bytes(self.budget))
        self.assets = [{"asset_id": "model-exe", "path": "/public/model-server", "bytes": self.exec_model["bytes"],
                        "sha256": self.exec_model["sha256"], "device": 1, "inode": 102, "read_only": True}]
        self.asset_manifest_hash = h("PUBLIC-SELECTED-ASSET-MANIFEST")
        self.channel = {"channel_id": "final-channel", "endpoint_ids": ["final-endpoint-c", "final-endpoint-r"],
                        "owner": self.controller, "key_operation_id": "new-public-key-operation-identity", "created_at": stamp(34)}
        self.listener = {"process": self.server, "address": "127.0.0.1", "port": 11434, "socket_inode": 808,
                         "observed": stamp(64)}
        self.first_packet = {"channel_id": "final-channel", "endpoint_id": "final-endpoint-r", "owner": self.runner,
            "ucred": [7100, 1000, 1000], "mac_valid": True, "sequence": 1, "received_at": stamp(65),
            "key_operation_id": self.channel["key_operation_id"]}
        self.current_peer = {"process": self.runner, "endpoint_id": "final-endpoint-r",
                             "descriptor": self.descriptor(7, "final-endpoint-r", "SOCKET"), "observed": stamp(81)}
        self.argument = {"claim": "TRUSTED_INSTALLATION_AND_INHERITANCE", "non_forwarding_status": "ASSUMPTION_BOUND_NON_FORWARDING",
                         "unsupported_routes": self.spec["fixed_unsupported_routes"], "every_task_post_exec_probes_claimed": False}
        self.argument_ref = self.put(self.argument, "SOURCE_ARGUMENT")

    def put(self, value: Any, kind: str) -> dict[str, Any]:
        raw = value if type(value) is bytes else canonical_bytes(value)
        ref = object_ref(raw, kind)
        self.objects[ref["object_id"]] = raw
        return ref

    def process(self, pid, start, parent, model=False):
        return {"boot_id": self.clock_domain["boot_id"], "pid": pid, "start_ticks": start, "parent_pid": parent,
                "uid": 1000, "gid": 1000, "exe_object_ref": self.exec_model if model else self.exec_python,
                "exe_device": 1, "exe_inode": 102 if model else 101,
                "namespace_inventory_ref": self.namespace, "mount_inventory_ref": self.mounts}

    @staticmethod
    def descriptor(fd, target, kind="PIPE"):
        return {"fd": fd, "object_type": kind, "device": 2, "inode": 400 + fd, "access_flags": 2,
                "close_on_exec": False, "selected_target_id": target}

    def _plan(self):
        slots, expectations = [], []
        required = {"SETUP_BEGIN": ["PROC_IDENTITY"], "CALIBRATION_BEGIN": ["PROC_IDENTITY"],
                    "CALIBRATION_CASE": ["PROC_IDENTITY"], "RUNNER_INSTALL": ["PROC_IDENTITY", "DESCRIPTOR_INVENTORY", "INSTALL_ARGUMENTS"],
                    "MODEL_INSTALL": ["PROC_IDENTITY", "DESCRIPTOR_INVENTORY", "INSTALL_ARGUMENTS"],
                    "MODEL_POST_EXEC": ["PROC_IDENTITY"], "FINAL_PEER_BOUND": ["PROC_IDENTITY"]}
        for i, kind in enumerate(KINDS, 1):
            sid = f"slot-e{i:02}"
            subject = self.case_ids[i-3] if kind == "CALIBRATION_CASE" else "subject-" + kind.lower()
            slots.append({"slot_id": sid, "kind": kind, "origin": self.spec["event_origin_and_evidence_class"][kind]["origin"],
                          "after_slots": [] if i == 1 else [f"slot-e{i-1:02}"], "payload_decoder_sha256": self.decoder,
                          "expected_subject_id": subject, "required_raw_kinds": required.get(kind, [])})
            if kind == "CALIBRATION_CASE":
                ck = self.case_kinds[i-3]; baseline = self.spec["fixed_calibration_baseline"][ck]
                expectations.append({"case_id": subject, "slot_id": sid,
                    "fixture_ref": self.put({"case_kind": ck, "public_only": True}, "PUBLIC_FIXTURE"), "case_kind": ck,
                    "expected_exchange_verdicts": baseline["exchange_verdicts"], "receiver_component_sha256": self.receiver_component,
                    "requires_foreign_pid": baseline["foreign_pid"]})
        return {"format": "forex.policy-inheritance-coverage-plan/2", "scope": self.scope, "plan_id": "public-plan",
                "slots": slots, "calibration_plan": expectations, "max_records": 19, "max_raw_bytes": 67_108_864,
                "unsupported_routes": self.spec["fixed_unsupported_routes"]}

    def interval(self, t):
        return {"binding": self.binding, "not_before_utc": stamp(-60)["utc"], "expires_at_utc": stamp(300)["utc"],
                "appointment_authentication_refs": [self.auth_ref], "principal_authority_refs": [self.auth_ref]*3,
                "dependency_attestation_refs": [], "validated_at": stamp(t)}

    def sample(self, t):
        return PublicGuardSample(canonical_bytes(stamp(t)), canonical_bytes(self.clock_domain), canonical_bytes(self.interval(t)))

    def envelope(self, body, producer, purpose, t, aid, *, is_budget=False, expires=170):
        raw = canonical_bytes(body)
        principal = next(p for p in self.appointment["principals"] if p["principal_id"] == producer)
        return {"body": {"format": "forex.policy-inheritance-attestation/2", "binding": self.binding,
            "attestation_id": aid, "purpose": purpose, "producer_id": producer, "record_sha256": digest(raw),
            "record_bytes": len(raw), "budget_sha256": None if is_budget else self.budget_hash,
            "issued": stamp(t), "expires": stamp(expires)}, "algorithm": "Ed25519",
            "signer_sha256": principal["signer_public_sha256"], "signature_hex": "0"*128}

    def new_model(self):
        return ProtocolModel(self.contract, scope=self.scope, plan=self.plan, appointment=self.appointment, budget=self.budget)

    def checkpoint_packet(self, previous, output, transition, seq, head, commit, t):
        generation = 1 if previous is None else previous["generation"] + 1
        previous_hash = ZERO if previous is None else digest(canonical_bytes(previous))
        key = {k: self.scope[k] for k in ["run_id", "original_window_sha256", "setup_identity"]}
        claim = "RESERVED" if transition == "SETUP_RESERVATION" else "CLAIMED"
        request = {"format": "forex.policy-inheritance-checkpoint-transition/2", "binding": self.binding,
            "original_setup_key": key, "transition_id": f"transition-{generation}", "transition_kind": transition,
            "requester_id": "consumer", "expected_generation": generation-1, "expected_checkpoint_sha256": previous_hash,
            "budget_id": self.budget["budget_id"], "budget_sha256": self.budget_hash, "stream_id": "public-stream",
            "event_sequence": seq, "event_head_sha256": head, "consumer_prepare_commit_id": commit, "output": output,
            "claim_state": claim, "prepared_at": stamp(t), "original_budget_body_ref": object_ref(canonical_bytes(self.budget), "SETUP_BUDGET")}
        checkpoint = {"format": "forex.policy-inheritance-checkpoint/2", "binding": self.binding,
            "original_setup_key": key, "checkpoint_authority_id": "checkpoint", "checkpoint_id": f"checkpoint-{generation}",
            "generation": generation, "previous_checkpoint_sha256": previous_hash,
            "transition_request_ref": object_ref(canonical_bytes(request), "CHECKPOINT_TRANSITION"), "transition_kind": transition,
            "budget_id": self.budget["budget_id"], "budget_sha256": self.budget_hash, "stream_id": "public-stream",
            "event_sequence": seq, "event_head_sha256": head, "consumer_prepare_commit_id": commit, "output": output,
            "claim_state": claim, "checkpointed_at": stamp(t), "original_budget_body_ref": request["original_budget_body_ref"]}
        envelope = self.envelope(checkpoint, "checkpoint", "policy-inheritance-checkpoint-v2", t, f"cp-attestation-{generation}")
        return request, checkpoint, envelope

    def start(self):
        model = self.new_model()
        request, cp, env = self.checkpoint_packet(None, {"kind": "NONE", "body_ref": None, "attestation_ref": None},
                                                 "SETUP_RESERVATION", 0, ZERO, "reserve-commit", 0)
        model.prepare_reservation(canonical_bytes(request), before=self.sample(0), after=self.sample(0),initial_view=self.initial_view())
        model.model_checkpoint_attempt(sample=self.sample(0))
        model.reserve(request, cp, env, before=self.sample(0), after=self.sample(0))
        model.confirm_reservation(cp, before=self.sample(0), after=self.sample(0))
        env = self.envelope(self.budget, "consumer", "policy-inheritance-setup-budget-v2", 2, "budget-attestation", is_budget=True)
        model.prepare_budget(env, prepare_id="budget-commit", sample=self.sample(2))
        self.commit(model, "BUDGET_CLAIM", 0, ZERO, "budget-commit", 2)
        return model

    def initial_view(self,state="ABSENT",checkpoint=None,t=0):
        return PublicInitialView(state,canonical_bytes(original_key(self.binding)),canonical_bytes(stamp(t)),
                                 None if checkpoint is None else canonical_bytes(checkpoint))

    def commit(self, model, kind, seq, head, commit, t, *, stop_after=None):
        request, cp, env = self.checkpoint_packet(model.checkpoint, model.pending_output, kind, seq, head, commit, t)
        self.attempt(model, request, t)
        model.record_checkpoint(request, cp, env, before=self.sample(t), after=self.sample(t))
        if stop_after == "checkpoint": return request, cp, env
        model.confirm_current(cp, before=self.sample(t), after=self.sample(t))
        if stop_after == "confirm": return request, cp, env
        model.model_exposure(sample=self.sample(t))
        return request, cp, env

    def attempt(self, model, request, t):
        model.prepare_checkpoint(canonical_bytes(request), sample=self.sample(t))
        model.model_checkpoint_attempt(sample=self.sample(t))

    def _calibration_selection(self):
        return {"receiver_component_sha256": self.receiver_component, "expected_peer": self.expected_peer,
                "foreign_sender": self.foreign, "retired_pids": [a["pid"] for a in self.temporary_actors],
                "temporary_actors": self.temporary_actors}

    def _case(self, index, t):
        exp = self.plan["calibration_plan"][index]; ck = exp["case_kind"]
        base = self.spec["fixed_calibration_baseline"][ck]
        cid = exp["case_id"]; channel = "channel-"+cid; verifier = "verifier-"+cid; key = "fixture-key-"+cid
        sender = self.foreign if base["foreign_pid"] else self.expected_peer
        exchanges = []
        for j, verdict in enumerate(base["exchange_verdicts"]):
            at = t - (len(base["exchange_verdicts"]) - 1 - j)
            data = ("PUBLIC-PACKET-"+cid).encode(); frames = ("PUBLIC-FRAMES-"+cid).encode()
            delivered = [self.descriptor(31+index, "delivered-"+cid)] if base["delivered_rights_minimum"] else []
            creds = None if ck == "TRUNCATED_RIGHTS" else {"pid": sender["pid"], "uid": sender["uid"], "gid": sender["gid"]}
            send = {"application_hex": data.hex(), "frames_hex": frames.hex(), "sender": sender, "return_value": len(frames), "errno": 0}
            recv = {"frames_hex": frames.hex(), "receiver": self.controller, "actual_ucred": creds, "return_value": len(frames), "errno": 0,
                    "msg_trunc": False, "msg_ctrunc": ck == "TRUNCATED_RIGHTS", "delivered_fds": delivered}
            trace = {"frame_valid": ck != "BAD_FRAME", "mac_valid": ck != "BAD_MAC", "channel_matches": ck != "BAD_CHANNEL_ID",
                "packet_sequence": 1, "verdict": verdict, "rejection_stage": base["rejection_stages"][j],
                "seq_before": base["recv_sequences"][j][0], "seq_after": base["recv_sequences"][j][1],
                "closed_before": False, "closed_after": base["closed_after"][j], "handler_before": 0, "handler_after": 0,
                "instance_id": verifier, "channel_instance_id": channel, "key_id": key,
                "exchange_id": cid+"-exchange-"+str(j+1), "verdict_operation_index": 100,
                "exposure_operation_index": 101, "verdict_observed": stamp(at), "exposure_observed": stamp(at)}
            closes = [{"descriptor": d, "close_return": 0, "close_errno": 0, "closed_at": stamp(at),
                       "raw_close_ref": self.put({"descriptor": d, "return_value": 0, "errno": 0, "observed": stamp(at),
                       "exchange_id": cid+"-exchange-"+str(j+1), "operation_index": k+1}, "DESCRIPTOR_CLOSES")} for k,d in enumerate(delivered)]
            exchanges.append({"exchange_index": j+1, "observed_start": stamp(at), "observed_end": stamp(at), "actual_sender_identity": sender,
                "sent_record_ref": self.put(send, "IPC_SEND"), "recv_record_ref": self.put(recv, "IPC_RECEIVE"),
                "sent_application_packet_sha256": digest(data), "sent_frames_sha256": digest(frames), "received_frames_sha256": digest(frames),
                "send_return": len(frames), "send_errno": 0, "recv_return": len(frames), "recv_errno": 0,
                "actual_ucred": creds, "msg_trunc": False, "msg_ctrunc": ck == "TRUNCATED_RIGHTS",
                "recv_seq_before": base["recv_sequences"][j][0], "recv_seq_after": base["recv_sequences"][j][1],
                "receiver_closed_before": False, "receiver_closed_after": base["closed_after"][j], "verdict": verdict,
                "rejection_stage": base["rejection_stages"][j], "verifier_trace_ref": self.put(trace, "VERIFIER_TRACE"),
                "handler_entries_before": 0, "handler_entries_after": 0, "delivered_fds": delivered, "close_outcomes": closes})
        payload = {"case_id": cid, "case_kind": ck, "slot_id": exp["slot_id"], "fixture_ref": exp["fixture_ref"],
            "receiver_identity": self.controller, "receiver_component_sha256": self.receiver_component, "expected_peer_identity": self.expected_peer,
            "channel_instance_id": channel, "verifier_instance_id": verifier, "channel_object_ids": ["endpoint-c-"+cid, "endpoint-r-"+cid],
            "public_fixture_key_id": key, "exchanges": exchanges}
        live = {"receiver": self.controller, "expected_peer": self.expected_peer, "senders": [sender],
                "live_pids": sorted({self.controller["pid"], self.expected_peer["pid"], sender["pid"]}), "observed": stamp(t)}
        return payload, [self.put(live, "PROC_IDENTITY")], t-len(exchanges)+1, t

    def _installation(self, kind):
        runner = kind == "RUNNER_INSTALL"; proc = self.runner if runner else self.wrapper
        parent = self.controller if runner else self.runner; start = 40 if runner else 44; end = start+2
        descriptors = [self.descriptor(i, f"stdio-{i}") for i in range(3)]
        descriptors.append(self.descriptor(7 if runner else 9, "final-endpoint-r" if runner else "model-ready-pipe", "SOCKET" if runner else "PIPE"))
        rules = [{"target_id": "public-source", "rights": 1}, {"target_id": "public-state", "rights": 3}]
        targets = [{"target_id": r["target_id"], "device": 4, "inode": 900+i, "resolved_path": "/public/"+r["target_id"]} for i,r in enumerate(rules)]
        descriptor_plan = {"role": kind, "process": proc, "parent": parent, "descriptors": descriptors, "selection_origin": "PUBLIC_TRUSTED_SPAWN_PREMISE"}
        selected = {"process": proc, "descriptors": descriptors, "descriptor_plan": descriptor_plan, "rules": rules, "targets": targets, "abi": 4, "handled_fs": 3}
        call_specs = [("LANDLOCK_CREATE_RULESET", {"mode": "ABI_QUERY"}, 4, start),
                      ("LANDLOCK_CREATE_RULESET", {"mode": "CREATE", "handled_fs": 3}, 11, start)]
        call_specs += [("LANDLOCK_ADD_RULE", {"ruleset_fd": 11, "target": target, "rights": rule["rights"]}, 0, start+1) for rule,target in zip(rules,targets)]
        call_specs += [("PR_SET_NO_NEW_PRIVS", {"no_new_privs": 1}, 0, end), ("LANDLOCK_RESTRICT_SELF", {"ruleset_fd": 11, "flags": 0}, 0, end)]
        threads = [{"tid": proc["pid"], "start_ticks": proc["start_ticks"]}]
        payload = {"process_identity": proc, "threads": threads, "initial_descriptors": descriptors,
            "expected_descriptor_plan_ref": self.put(descriptor_plan, "DESCRIPTOR_INVENTORY"), "normalized_rules_ref": self.put(rules, "NORMALIZED_RULES"),
            "rule_target_inventory_ref": self.put(targets, "RULE_TARGET_INVENTORY"), "landlock_abi": 4, "handled_fs": 3,
            "syscalls": [{"operation": op, "arguments_ref": self.put(args, "INSTALL_ARGUMENTS"), "return_value": result, "errno": 0,
                          "observed": stamp(at)} for op,args,result,at in call_specs], "no_new_privs_readback": 1,
            "parent_installation_record_id": None if runner else "e13"}
        raw = [self.put({"process": proc, "parent": parent, "threads": threads, "observed_start": stamp(start), "observed_end": stamp(end)}, "PROC_IDENTITY"),
               self.put({"process": proc, "descriptors": descriptors, "observed": stamp(start)}, "DESCRIPTOR_INVENTORY"),
               self.put({"process": proc, "no_new_privs": 1, "observed": stamp(end)}, "INSTALL_ARGUMENTS")]
        selections = {"installations": {kind: selected}}
        if runner: selections["controller"] = self.controller
        return payload, raw, selections, start, end

    def packet(self, model, sequence):
        kind = KINDS[sequence-1]; t = TIMES[sequence-1]; start = end = t; raw = []; selected = {}
        if kind == "SETUP_BEGIN":
            p = {"coverage_plan_sha256": digest(canonical_bytes(self.plan)), "producer_identity": self.controller, "budget_sha256": self.budget_hash}
            raw = [self.put(self.controller, "PROC_IDENTITY")]; selected = {"controller": self.controller}
        elif kind == "CALIBRATION_BEGIN":
            p = {"receiver_identity": self.controller, "receiver_component_sha256": self.receiver_component, "planned_case_ids": self.case_ids,
                 "final_key_created": False, "private_documents_opened": False}
            raw = [self.put(self.controller, "PROC_IDENTITY")]; selected = {"controller": self.controller, "calibration": self._calibration_selection()}
        elif kind == "CALIBRATION_CASE":
            p, raw, start, end = self._case(sequence-3, t)
            selected = {"controller": self.controller, "calibration": self._calibration_selection()}
        elif kind == "CALIBRATION_RETIRED":
            endpoints = [v for cid in self.case_ids for v in ["endpoint-c-"+cid,"endpoint-r-"+cid]]
            p = {"completed_case_ids": self.case_ids, "endpoint_retirement_ref": self.put({"closed_endpoint_ids": endpoints,"observed":stamp(t)}, "ENDPOINT_RETIREMENT"),
                "challenger_identity": self.foreign, "process_retirement_ref": self.put({"challenger":self.foreign,
                  "retired_pids":[a["pid"] for a in self.temporary_actors],"retired_identities":self.temporary_actors,
                  "remaining_descendants":[],"unclosed_delivered_fds":[],"observed":stamp(t)}, "PROCESS_RETIREMENT"),
                "remaining_challenger_descendants":0,"unclosed_delivered_fds":0,"final_key_created":False}
            selected = {"calibration": self._calibration_selection()}
        elif kind == "FINAL_CHANNEL_CREATED":
            p = {"channel_id": "final-channel", "endpoint_inventory_ref": self.put(self.channel,"DESCRIPTOR_INVENTORY"),
                 "key_generation_operation_id":self.channel["key_operation_id"],"calibration_retired_record_id":"e11","key_material_recorded":False}
            selected = {"controller":self.controller,"channel":self.channel}
        elif kind in {"RUNNER_INSTALL","MODEL_INSTALL"}:
            p,raw,selected,start,end = self._installation(kind)
        elif kind == "ASSET_BINDINGS":
            start,end=49,60
            p={"selected_asset_manifest_sha256":self.asset_manifest_hash,"actual_file_inventory_ref":self.put(self.assets,"ASSET_INVENTORY"),
               "hash_scan_started":stamp(start),"hash_scan_completed":stamp(end)}
            selected={"assets":self.assets,"asset_manifest_sha256":self.asset_manifest_hash}
        elif kind == "MODEL_POST_EXEC":
            start,end=61,64
            p={"wrapper_installation_record_id":"e14","actual_server_identity":self.server,"asset_binding_record_id":"e15",
               "owned_listener_ref":self.put(self.listener,"LISTENER_IDENTITY"),
               "wrapper_to_exec_identity_ref":self.put({"before":self.wrapper,"after":self.server,"parent":self.runner,
                    "exe_path":"/public/model-server","observed":stamp(63)},"EXEC_LINEAGE")}
            raw=[self.put({"process":self.server,"parent":self.runner,"exe_path":"/public/model-server","observed":stamp(63)},"PROC_IDENTITY")]
            selected={"assets":self.assets,"post_exec":{"process":self.server,"parent":self.runner,
                       "exe_path":"/public/model-server","executable_asset_id":"model-exe","listener":self.listener}}
        elif kind == "FINAL_PEER_BOUND":
            start,end=65,81
            p={"channel_created_record_id":"e12","channel_id":"final-channel","actual_peer_identity":self.runner,
               "first_packet_ref":self.put(self.first_packet,"IPC_RECEIVE"),"actual_ucred":[7100,1000,1000],"model_post_exec_record_id":"e16"}
            raw=[self.put(self.current_peer,"PROC_IDENTITY")]
            selected={"channel":self.channel,"peer":{"first_packet":self.first_packet,"current":self.current_peer}}
        elif kind == "POLICY_ARGUMENT":
            p={"installation_record_ids":["e13","e14"],"post_exec_record_id":"e16","source_argument_ref":self.argument_ref,**self.argument}
            selected={"source_argument_ref":self.argument_ref}
        else:
            p={"entries":[{"sequence":r["event"]["sequence"],"record_id":r["event"]["record_id"],"record_sha256":r["event_sha256"]} for r in model.accepted],
               "covered_slot_ids":[r["event"]["slot_id"] for r in model.accepted],"previous_head_sha256":model.inspect().retained_head_sha256,
               "previous_record_count":18,"unsupported_routes":self.spec["fixed_unsupported_routes"]}
        event={"format":"forex.policy-inheritance-event/2","binding":self.binding,"budget_sha256":self.budget_hash,"stream_id":"public-stream",
               "record_id":f"e{sequence:02}","producer_id":"witness","sequence":sequence,"previous_record_sha256":model.inspect().retained_head_sha256,
               "slot_id":f"slot-e{sequence:02}","kind":kind,**self.spec["event_origin_and_evidence_class"][kind],
               "observed_start":stamp(start),"observed_end":stamp(end),"recorded":stamp(t),"payload_ref":self.put(p,"CANONICAL_PAYLOAD"),"raw_refs":raw}
        selected["subject_id"]=self.plan["slots"][sequence-1]["expected_subject_id"]
        packet=Packet(event,p,selected,{}, {}, {},self.evidence())
        self.repack(packet)
        return packet

    def evidence(self):
        return PublicEvidence(self.contract,self.objects,decoder_sha256=self.decoder)

    def repack(self, packet):
        event,p=packet.event,packet.payload;seq=event["sequence"];t=TIMES[seq-1]
        event["payload_ref"]=self.put(p,"CANONICAL_PAYLOAD")
        packet.witness=self.envelope(event,"witness","policy-inheritance-witness-v2",t,f"witness-e{seq:02}")
        packet.ack={"format":"forex.policy-inheritance-ingestion-ack/2","binding":self.binding,"consumer_id":"consumer","stream_id":"public-stream",
                    "sequence":seq,"record_sha256":digest(canonical_bytes(event)),"retention_commit_id":f"commit-e{seq:02}","acknowledged":stamp(t),"budget_sha256":self.budget_hash}
        packet.ack_envelope=self.envelope(packet.ack,"consumer","policy-inheritance-ingestion-ack-v2",t,f"ack-e{seq:02}")
        packet.evidence=self.evidence()

    def prepare(self, model, packet):
        t=TIMES[packet.event["sequence"]-1]
        return model.prepare_event(canonical_bytes(packet.event),canonical_bytes(packet.payload),packet.evidence,packet.witness,
                                   packet.ack,packet.ack_envelope,selections=PublicSelections(packet.selections),sample=self.sample(t))

    def advance(self,model,sequence):
        packet=self.packet(model,sequence);self.prepare(model,packet)
        self.commit(model,"ACK_EXPOSURE",sequence,digest(canonical_bytes(packet.event)),packet.ack["retention_commit_id"],TIMES[sequence-1])
        return packet

    def through(self,count):
        model=self.start()
        for i in range(1,count+1):self.advance(model,i)
        return model

    def decision(self,model,t=100):
        decision={"format":"forex.policy-inheritance-method-decision/2","binding":self.binding,"consumer_id":"consumer","decision_id":"public-decision",
            "budget_sha256":self.budget_hash,"stream_id":"public-stream","status":"ACCEPTED_NARROW_METHOD","failure_code":None,
            "sealed_head_sha256":model.inspect().retained_head_sha256,"retained_prefix_head_sha256":model.inspect().retained_head_sha256,
            "retained_record_count":19,"retention_commit_id":"decision-commit","decided":stamp(t),"expires":stamp(160),
            "accepted_claims":self.spec["enums"]["AcceptedClaim"],"unsupported_routes":self.spec["fixed_unsupported_routes"],
            "evidence_classes":list(dict.fromkeys(r["event"]["evidence_class"] for r in model.accepted)),
            "completion_scoring_publication_authority":False,"authenticated_interval_ref":object_ref(canonical_bytes(self.interval(t)),"AUTHENTICATED_INTERVAL")}
        return decision,self.envelope(decision,"consumer","policy-inheritance-method-decision-v2",t,"decision-attestation",expires=160)
