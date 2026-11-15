"""Operational public predicates over authenticated, independently decoded bytes.

The older implementation-02 pure predicates were source references only. No
fixture evidence class, caller-normalized success, or public spawn premise is
accepted here. All I/O and authentication occur on explicit validation calls.
"""
from __future__ import annotations
from dataclasses import dataclass
from threading import RLock
from typing import Any
import re
from cas_forex_operational_contracts import method, capture
from cas_forex_operational_contracts.common import canonical_bytes, decode_canonical, digest, MAX_OBJECT, MAX_GRAPH, utc
from .authentication import AuthorityError, need, ref, same, stamp_le, ZERO


def require(condition, code, field=""):
    need(condition, code)


def exact_fields(value, fields, label=""):
    need(type(value) is dict and set(value) == set(fields), "CONTEXT_MISMATCH")
    return value


def _same(left, right):
    return same(left, right)


def _unique(values, code, field=""):
    need(len({canonical_bytes(x) for x in values}) == len(values), code)


def _hex(value, field=""):
    need(type(value) is str and len(value) % 2 == 0 and len(value) <= 2097152
         and all(c in "0123456789abcdef" for c in value), "DECODER_UNAVAILABLE")
    return bytes.fromhex(value)


def _subject_matches(subject, process):
    return all(same(subject[k], process[k]) for k in ("boot_id", "pid", "start_ticks", "parent_pid", "uid", "gid"))


def _child_descriptor(mapping):
    item = dict(mapping["object_identity"])
    item["fd"] = mapping["child_fd"]
    # The selected PASS_FDS/STDIO_DUP spawn clears FD_CLOEXEC in the child.
    item["close_on_exec"] = False
    item["selected_target_id"] = mapping["target_id"]
    return item


class _Shapes:
    def validate(self, name, value):
        return method.validate(name, value)

    def validate_value(self, name, value):
        if name.startswith("array<"):
            match = re.fullmatch(r"array<([^>]+)>\[(\d+),(\d+)\]", name)
            need(match is not None and type(value) is list and int(match[2]) <= len(value) <= int(match[3]), "CONTEXT_MISMATCH")
            for item in value: self.validate_value(match[1], item)
        elif name == "Id": need(type(value) is str and 0 < len(value) <= 256, "CONTEXT_MISMATCH")
        elif name == "Sha256": need(type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None, "CONTEXT_MISMATCH")
        elif name == "PositiveInt": need(type(value) is int and value > 0, "CONTEXT_MISMATCH")
        elif name == "UInt": need(type(value) is int and value >= 0, "CONTEXT_MISMATCH")
        else: method.validate(name, value)


class _Coverage:
    def __init__(self, plan, raw):
        self.plan, self.sha256 = plan, digest(raw)
        self.case_ids = [x["case_id"] for x in plan["calibration_plan"]]
        components = {x["receiver_component_sha256"] for x in plan["calibration_plan"]}
        need(len(components) == 1, "CALIBRATION_BASELINE_MISMATCH")
        self.receiver_component_sha256 = next(iter(components))
    def slot(self, identity):
        matches = [x for x in self.plan["slots"] if x["slot_id"] == identity]
        need(len(matches) == 1, "MISSING_SLOT")
        return matches[0]
    def expectation(self, identity):
        matches = [x for x in self.plan["calibration_plan"] if x["slot_id"] == identity]
        need(len(matches) == 1, "CALIBRATION_BASELINE_MISMATCH")
        return matches[0]

PAYLOAD_TYPES = {'SETUP_BEGIN': 'SetupBeginPayload', 'CALIBRATION_BEGIN': 'CalibrationBeginPayload', 'CALIBRATION_CASE': 'CalibrationCasePayload', 'CALIBRATION_RETIRED': 'CalibrationRetiredPayload', 'FINAL_CHANNEL_CREATED': 'FinalChannelCreatedPayload', 'RUNNER_INSTALL': 'InstallationPayload', 'MODEL_INSTALL': 'InstallationPayload', 'ASSET_BINDINGS': 'AssetBindingsPayload', 'MODEL_POST_EXEC': 'PostExecPayload', 'FINAL_PEER_BOUND': 'FinalPeerPayload', 'POLICY_ARGUMENT': 'PolicyArgumentPayload', 'SETUP_SEAL': 'SetupSealPayload', 'FAILURE': 'FailurePayload'}
ORIGIN_LABELS = {'SETUP_BEGIN': {'origin': 'CONTROLLER', 'evidence_class': 'CONTROLLER_STREAM_METADATA'}, 'CALIBRATION_BEGIN': {'origin': 'CONTROLLER', 'evidence_class': 'PUBLIC_RECEIVER_OBSERVATION'}, 'CALIBRATION_CASE': {'origin': 'CONTROLLER', 'evidence_class': 'PUBLIC_RECEIVER_OBSERVATION'}, 'CALIBRATION_RETIRED': {'origin': 'CONTROLLER', 'evidence_class': 'PUBLIC_RECEIVER_OBSERVATION'}, 'FINAL_CHANNEL_CREATED': {'origin': 'CONTROLLER', 'evidence_class': 'CONTROLLER_OS_READBACK'}, 'RUNNER_INSTALL': {'origin': 'DECISION_BOOTSTRAP', 'evidence_class': 'TRUSTED_BOOTSTRAP_REPORT'}, 'MODEL_INSTALL': {'origin': 'MODEL_BOOTSTRAP', 'evidence_class': 'TRUSTED_BOOTSTRAP_REPORT'}, 'ASSET_BINDINGS': {'origin': 'CONTROLLER', 'evidence_class': 'CONTROLLER_OS_READBACK'}, 'MODEL_POST_EXEC': {'origin': 'CONTROLLER', 'evidence_class': 'CONTROLLER_OS_READBACK'}, 'FINAL_PEER_BOUND': {'origin': 'CONTROLLER', 'evidence_class': 'CONTROLLER_OS_READBACK'}, 'POLICY_ARGUMENT': {'origin': 'CONTROLLER', 'evidence_class': 'INSTALLATION_INHERITANCE_ARGUMENT'}, 'SETUP_SEAL': {'origin': 'CONTROLLER', 'evidence_class': 'CONTROLLER_STREAM_METADATA'}, 'FAILURE': {'origin': 'CONTROLLER', 'evidence_class': 'CONTROLLER_STREAM_METADATA'}}
BASELINES = {'POSITIVE_INERT': {'exchange_verdicts': ['ACCEPTED_INERT'], 'rejection_stages': ['NONE'], 'foreign_pid': False, 'delivered_rights_minimum': 0, 'delivered_rights_maximum': 0, 'recv_sequences': [[0, 1]], 'closed_after': [False]}, 'BAD_MAC': {'exchange_verdicts': ['AUTH_REJECTED'], 'rejection_stages': ['MAC'], 'foreign_pid': False, 'delivered_rights_minimum': 0, 'delivered_rights_maximum': 0, 'recv_sequences': [[0, 0]], 'closed_after': [True]}, 'BAD_SEQUENCE': {'exchange_verdicts': ['ACCEPTED_INERT', 'AUTH_REJECTED'], 'rejection_stages': ['NONE', 'SEQUENCE'], 'foreign_pid': False, 'delivered_rights_minimum': 0, 'delivered_rights_maximum': 0, 'recv_sequences': [[0, 1], [1, 1]], 'closed_after': [False, True]}, 'BAD_CHANNEL_ID': {'exchange_verdicts': ['AUTH_REJECTED'], 'rejection_stages': ['CHANNEL_ID'], 'foreign_pid': False, 'delivered_rights_minimum': 0, 'delivered_rights_maximum': 0, 'recv_sequences': [[0, 0]], 'closed_after': [True]}, 'BAD_FRAME': {'exchange_verdicts': ['FRAMING_REJECTED'], 'rejection_stages': ['FRAME'], 'foreign_pid': False, 'delivered_rights_minimum': 0, 'delivered_rights_maximum': 0, 'recv_sequences': [[0, 0]], 'closed_after': [True]}, 'DELIVERED_RIGHTS': {'exchange_verdicts': ['RIGHTS_REJECTED'], 'rejection_stages': ['ANCILLARY'], 'foreign_pid': False, 'delivered_rights_minimum': 1, 'delivered_rights_maximum': 256, 'recv_sequences': [[0, 0]], 'closed_after': [True]}, 'TRUNCATED_RIGHTS': {'exchange_verdicts': ['FRAMING_REJECTED'], 'rejection_stages': ['ANCILLARY'], 'foreign_pid': False, 'delivered_rights_minimum': 1, 'delivered_rights_maximum': 256, 'recv_sequences': [[0, 0]], 'closed_after': [True]}, 'WRONG_PEER_PID': {'exchange_verdicts': ['AUTH_REJECTED'], 'rejection_stages': ['PEER_CREDENTIALS'], 'foreign_pid': True, 'delivered_rights_minimum': 0, 'delivered_rights_maximum': 0, 'recv_sequences': [[0, 0]], 'closed_after': [True]}}

@dataclass(frozen=True)
class SemanticSelection:
    """Trusted bootstrap inputs, not a record-selected policy or new wire type.

    Source references are canonical ObjectRef bytes keyed by coverage slot. They
    must be selected independently of the proposed capture's observed results.
    """
    decoder_component_sha256: str
    decoder_format_sha256: str
    sources_by_slot: tuple[tuple[str, tuple[bytes, ...]], ...]
    spawn_pins_by_slot: tuple[tuple[str, str, str, str], ...] = ()
    policies_by_slot: tuple[tuple[str, bytes], ...] = ()


class _RecomputedSink:
    """Fresh per-decode sink: producer normalized bytes cannot populate it."""
    def __init__(self):
        self.items = {}
    def retain(self, raw, *, artifact_kind):
        need(type(raw) is bytes and 0 < len(raw) <= MAX_OBJECT, "RAW_BYTES_MISMATCH")
        reference = ref(raw, artifact_kind)
        key = canonical_bytes(reference)
        need(sum(len(x[1]) for x in self.items.values()) + (0 if key in self.items else len(raw)) <= MAX_GRAPH,
             "RAW_EVIDENCE_UNAVAILABLE")
        self.items[key] = (reference, raw)
        return dict(reference)
    def readback(self, reference):
        item = self.items.get(canonical_bytes(reference))
        need(item is not None, "RAW_EVIDENCE_UNAVAILABLE")
        return item[1]


class _Graph:
    TYPES = {"AUTHENTICATED_EVENT_INPUTS": "EventInputs", "TRUSTED_CAPTURE_BATCH": "CaptureBatch",
             "RUNTIME_DECODE_BINDING": "DecodeBinding", "TRUSTED_SPAWN_SELECTION": "SpawnSelection",
             "RUNTIME_SELECTION_BINDING": "RuntimeSelectionBinding", "RUNTIME_SELECTED_VALUES": "RuntimeSelectedValues",
             "RAW_BLOB_MANIFEST": "RawBlobManifest"}

    def __init__(self, owner, event, accepted, artifacts, envelopes):
        self.owner, self.event, self.accepted = owner, event, accepted
        self.artifacts, self.envelopes = artifacts, envelopes
        self.allowed, self.native, self.normalized, self.walked = set(), set(), set(), set()
        self.inputs, self.spawn = None, None
        self.captures, self.bindings = [], []

    def resolve(self, reference):
        """Exact-byte resolver for the selected decoder; authority is checked separately."""
        method.validate("ObjectRef", reference)
        key = canonical_bytes(reference)
        self.owner.fresh()
        if key in self.artifacts:
            raw = self.artifacts[key][1]
            need(ref(raw, reference["artifact_kind"]) == reference, "RAW_BYTES_MISMATCH")
            return raw
        raw = self.owner.evidence.resolve(reference)
        self.owner.fresh()
        need(type(raw) is bytes and len(raw) == reference["bytes"] and digest(raw) == reference["sha256"], "RAW_BYTES_MISMATCH")
        need(key not in self.artifacts or self.artifacts[key][1] == raw, "REPLAY_OR_EQUIVOCATION")
        self.artifacts[key] = (dict(reference), raw)
        need(len(self.artifacts) <= 4096 and sum(len(x[1]) for x in self.artifacts.values()) <= min(MAX_GRAPH, self.owner.plan["max_raw_bytes"]),
             "RAW_EVIDENCE_UNAVAILABLE")
        return raw

    def retain_exact(self, reference, raw):
        # Read-only decoder evidence port. Derived output goes to its fresh sink.
        need(self.resolve(reference) == raw, "RAW_BYTES_MISMATCH")
        return dict(reference)

    def authenticated(self, pair, kind):
        capture.validate("AuthenticatedMethodObject", pair)
        need(pair["object_ref"]["artifact_kind"] == kind and pair["envelope_ref"]["artifact_kind"] == "SIGNED_ENVELOPE", "PURPOSE_MISMATCH")
        raw, envelope_raw = self.resolve(pair["object_ref"]), self.resolve(pair["envelope_ref"])
        value = capture.decode(self.TYPES[kind], raw).payload()
        envelope = method.decode("SignedEnvelope", envelope_raw).payload()
        now = self.owner.fresh()
        self.owner.authentication.verify_attestation(raw, envelope, expected_purpose="policy-inheritance-witness-v3",
                                                    appointment=self.owner.appointment, now=now)
        need(same(value["binding"], self.owner.budget["binding"]) and value["budget_sha256"] == digest(self.owner.budget_raw), "CONTEXT_MISMATCH")
        witness = self.owner.witness_id
        need(envelope["body"]["producer_id"] == witness and ("producer_id" not in value or value["producer_id"] == witness), "SIGNER_UNAPPOINTED")
        self.allowed.update((canonical_bytes(pair["object_ref"]), canonical_bytes(pair["envelope_ref"])))
        self.envelopes[canonical_bytes(pair["envelope_ref"])] = (dict(pair["envelope_ref"]), envelope)
        self.owner.fresh()
        return value

    def _inside(self, started, finished):
        need(stamp_le(self.event["observed_start"], started) and stamp_le(started, finished)
             and stamp_le(finished, self.event["observed_end"]), "CLOCK_DRIFT")

    def load(self):
        event, owner = self.event, self.owner
        pair = {"object_ref": event["input_bundle_ref"], "envelope_ref": event["input_bundle_envelope_ref"]}
        self.inputs = self.authenticated(pair, "AUTHENTICATED_EVENT_INPUTS")
        inputs = self.inputs
        for a, b in (("stream_id", "stream_id"), ("record_id", "record_id"), ("slot_id", "slot_id"), ("event_kind", "kind")):
            need(inputs[a] == event[b], "CONTEXT_MISMATCH")
        slot = owner.coverage.slot(event["slot_id"])
        # Dynamic predecessor hashes come only from the consumer's exact accepted
        # prefix, so inert construction never needs to predict future event hashes.
        selected_sources = owner.sources[event["slot_id"]] + [ref(x["event_raw"], "EVENT_RECORD") for x in self.accepted]
        need(len(selected_sources) <= 32, "RAW_EVIDENCE_UNAVAILABLE")
        need(same(inputs["selected_source_refs"], selected_sources), "SOURCE_OR_EXEC_IDENTITY_MISMATCH")
        self.allowed.update(canonical_bytes(x) for x in selected_sources)
        self.selection = self.authenticated(inputs["selected_values"], "RUNTIME_SELECTED_VALUES")
        runtime = self.authenticated(inputs["runtime_selection"], "RUNTIME_SELECTION_BINDING")
        need(self.selection["slot_id"] == runtime["slot_id"] == event["slot_id"]
             and self.selection["event_kind"] == event["kind"]
             and self.selection["subject_id"] == runtime["subject_id"] == slot["expected_subject_id"]
             and same(runtime["selection_ref"], inputs["selected_values"]["object_ref"])
             and same(runtime["selected_source_refs"], selected_sources)
             and runtime["selected_decoder_sha256"] == slot["payload_decoder_sha256"] == owner.selection.decoder_component_sha256,
             "CONTEXT_MISMATCH")
        need(stamp_le(owner.budget["started"], runtime["selected_at"]) and stamp_le(runtime["selected_at"], event["recorded"]), "CLOCK_DRIFT")
        _unique(inputs["capture_objects"], "REPLAY_OR_EQUIVOCATION")
        for capture_pair in inputs["capture_objects"]:
            value = self.authenticated(capture_pair, "TRUSTED_CAPTURE_BATCH")
            self._inside(value["started"], value["finished"])
            # Controller spawn/readback and bootstrap enforcement may share an
            # installation event. Preserve each batch's actual reporting label.
            role = value["subject"]["role"]
            expected_origin = {"DECISION_BOOTSTRAP": "DECISION_BOOTSTRAP", "MODEL_BOOTSTRAP": "MODEL_BOOTSTRAP"}.get(role, "CONTROLLER")
            need(value["reporting_origin"] == expected_origin, "CONTEXT_MISMATCH")
            if expected_origin != "CONTROLLER":
                need(value["evidence_class"] == "TRUSTED_BOOTSTRAP_REPORT", "CONTEXT_MISMATCH")
            else:
                need(value["evidence_class"] in ("CONTROLLER_OS_READBACK", "PUBLIC_RECEIVER_OBSERVATION",
                     "TRUSTED_SOURCE_ARGUMENT", "CONTROLLER_STREAM_METADATA"), "CONTEXT_MISMATCH")
            need(value["subject"]["boot_id"] == owner.budget["clock_domain"]["boot_id"], "CLOCK_DOMAIN_UNSUPPORTED")
            if event["kind"].startswith("CALIBRATION"):
                need(value["receiver_component_sha256"] == owner.coverage.receiver_component_sha256, "CALIBRATION_BASELINE_MISMATCH")
            self.captures.append(value)
            for operation in value["operations"]:
                op_raw = canonical_bytes(operation)
                op_ref = ref(op_raw, "CANONICAL_PAYLOAD")
                # Exact operation bodies embedded in a signed batch are covered.
                self.allowed.add(canonical_bytes(op_ref))
                if canonical_bytes(op_ref) in self.artifacts:
                    need(self.artifacts[canonical_bytes(op_ref)][1] == op_raw, "RAW_BYTES_MISMATCH")
                self.artifacts[canonical_bytes(op_ref)] = (op_ref, op_raw)
        for manifest_pair in inputs["raw_blob_manifests"]:
            manifest = self.authenticated(manifest_pair, "RAW_BLOB_MANIFEST")
            self._inside(manifest["started"], manifest["finished"])
            need(manifest["subject"]["boot_id"] == owner.budget["clock_domain"]["boot_id"]
                 and any(c["reporting_origin"] == manifest["origin"] and c["producer_id"] == manifest["producer_id"] for c in self.captures), "CONTEXT_MISMATCH")
            if manifest["blob_ref"] is not None:
                reference = manifest["blob_ref"]
                need(reference["artifact_kind"] == "NATIVE_CAPTURE_BYTES", "PURPOSE_MISMATCH")
                need(self.resolve(reference) and reference["sha256"] == manifest["raw_sha256"], "RAW_BYTES_MISMATCH")
                self.native.add(canonical_bytes(reference)); self.allowed.add(canonical_bytes(reference))
        if event["kind"] in ("RUNNER_INSTALL", "MODEL_INSTALL"):
            need(inputs["spawn_selection"] is not None, "DESCRIPTOR_IDENTITY_MISMATCH")
            self.spawn = self.authenticated(inputs["spawn_selection"], "TRUSTED_SPAWN_SELECTION")
            self._spawn()
        else:
            need(inputs["spawn_selection"] is None, "CONTEXT_MISMATCH")
        need(inputs["decode_objects"], "DECODER_UNAVAILABLE")
        for decode_pair in inputs["decode_objects"]:
            binding = self.authenticated(decode_pair, "RUNTIME_DECODE_BINDING")
            need(binding["event_kind"] == event["kind"]
                 and binding["decoder_component_sha256"] == owner.selection.decoder_component_sha256
                 and binding["decoder_format_sha256"] == owner.selection.decoder_format_sha256, "DECODER_UNAVAILABLE")
            need(same(binding["capture_refs"], [x["object_ref"] for x in inputs["capture_objects"]])
                 and same(binding["capture_envelope_refs"], [x["envelope_ref"] for x in inputs["capture_objects"]]), "CONTEXT_MISMATCH")
            need(stamp_le(runtime["selected_at"], binding["decoded"]) and stamp_le(binding["decoded"], event["recorded"])
                 and all(stamp_le(x["finished"], binding["decoded"]) for x in self.captures), "CLOCK_DRIFT")
            normalized_key = canonical_bytes(binding["normalized_ref"])
            need(normalized_key not in self.normalized, "REPLAY_OR_EQUIVOCATION")
            self.normalized.add(normalized_key); self.allowed.add(normalized_key)
            self.bindings.append(binding)
        expected = {canonical_bytes(event["input_bundle_ref"]), canonical_bytes(event["input_bundle_envelope_ref"])} | self.normalized
        need({canonical_bytes(x) for x in event["raw_refs"]} == expected and len(expected) <= 64
             and canonical_bytes(event["payload_ref"]) in self.normalized, "RAW_EVIDENCE_UNAVAILABLE")
        self._recompute(pair)
        # Every graph edge must lead to a separately authenticated object, a
        # recomputed normalized object, an authenticated raw leaf, or selected source.
        for reference in [event["input_bundle_ref"], *event["raw_refs"], *selected_sources]:
            self.walk(reference, set(), 0)
        need(sum(len(x[1]) for x in self.artifacts.values()) <= min(MAX_GRAPH, owner.plan["max_raw_bytes"]), "RAW_EVIDENCE_UNAVAILABLE")

    def _spawn(self):
        spawn, event = self.spawn, self.event
        pins = [x for x in self.owner.selection.spawn_pins_by_slot if x[0] == event["slot_id"]]
        need(len(pins) == 1 and (spawn["component_sha256"], spawn["selected_executable_asset_id"], spawn["selected_policy_sha256"]) == pins[0][1:],
             "SOURCE_OR_EXEC_IDENTITY_MISMATCH")
        need(spawn["role"] == event["kind"] and spawn["selection_origin"] == "AUTHENTICATED_CONTROLLER_SPAWN", "DESCRIPTOR_IDENTITY_MISMATCH")
        matching = [c for p, c in zip(self.inputs["capture_objects"], self.captures) if same(p["object_ref"], spawn["spawn_capture_ref"])]
        need(len(matching) == 1, "RAW_EVIDENCE_UNAVAILABLE")
        operations = [x for x in matching[0]["operations"] if x["operation_index"] == spawn["spawn_operation_index"] and x["kind"] == "SPAWN"]
        need(len(operations) == 1, "RAW_EVIDENCE_UNAVAILABLE")
        actual = capture.validate("SpawnCapture", operations[0]["data"]).payload()
        for selected, observed in (("spawn_id", "spawn_id"), ("role", "role"), ("parent", "parent"), ("child", "paused_child"),
                                   ("component_sha256", "selected_component_sha256"), ("selected_executable_asset_id", "selected_executable_asset_id"),
                                   ("selected_policy_sha256", "selected_policy_sha256"), ("descriptor_bindings", "descriptor_bindings")):
            need(same(spawn[selected], actual[observed]), "DESCRIPTOR_IDENTITY_MISMATCH")
        need(actual["result"] == "SPAWNED_AND_PAUSED" and actual["errno"] == 0 and actual["returned_pid"] == spawn["child"]["pid"]
             and spawn["child"]["parent_pid"] == spawn["parent"]["pid"]
             and spawn["child"]["parent_start_ticks"] == spawn["parent"]["start_ticks"]
             and spawn["child"]["boot_id"] == spawn["parent"]["boot_id"] == self.owner.budget["clock_domain"]["boot_id"], "SOURCE_OR_EXEC_IDENTITY_MISMATCH")
        need(stamp_le(operations[0]["finished"], spawn["created"]) and stamp_le(spawn["created"], event["recorded"]), "CLOCK_DRIFT")
        descriptors = spawn["descriptor_bindings"]
        need(3 <= len(descriptors) <= 16 and len({x["child_fd"] for x in descriptors}) == len(descriptors), "DESCRIPTOR_IDENTITY_MISMATCH")
        need({x["child_fd"] for x in descriptors if x["inheritance"] == "STDIO_DUP"} == {0, 1, 2}, "DESCRIPTOR_IDENTITY_MISMATCH")
        for mapping in descriptors:
            need((mapping["inheritance"] == "STDIO_DUP" and mapping["child_fd"] in (0, 1, 2))
                 or (mapping["inheritance"] == "PASS_FDS" and mapping["parent_fd"] == mapping["child_fd"]), "DESCRIPTOR_IDENTITY_MISMATCH")
            need(mapping["parent_fd"] == mapping["object_identity"]["fd"] and mapping["target_id"] == mapping["object_identity"]["selected_target_id"], "DESCRIPTOR_IDENTITY_MISMATCH")

    def accepted_event(self, reference, *, now):
        self.owner.fresh(now)
        need(reference["artifact_kind"] == "EVENT_RECORD", "PURPOSE_MISMATCH")
        rows = [x for x in self.accepted if same(ref(x["event_raw"], "EVENT_RECORD"), reference)]
        need(len(rows) == 1, "DEPENDENCY_ORDER")
        return rows[0]["event_raw"]

    def _recompute(self, pair):
        need(self.owner.decoder_factory is not None, "DECODER_UNAVAILABLE")
        sink = _RecomputedSink()
        decoder = self.owner.decoder_factory(event_inputs=pair, evidence=self, authenticator=self.owner.authentication,
                    appointment=self.owner.appointment, budget=self.owner.budget, plan=self.owner.plan, sink=sink,
                    component_sha256=self.owner.selection.decoder_component_sha256, format_sha256=self.owner.selection.decoder_format_sha256,
                    accepted_event=self.accepted_event, phase_guard=self.owner.phase_guard)
        self.owner.fresh()
        binding, payload_raw = decoder.decode_actual(tuple(self.inputs["capture_objects"]), selection=self.selection,
                    decoder_component_sha256=self.owner.selection.decoder_component_sha256,
                    decoder_format_sha256=self.owner.selection.decoder_format_sha256, now=self.owner.fresh())
        self.owner.fresh()
        capture.validate("DecodeBinding", binding)
        actual_artifacts, actual_bindings = decoder.derived_artifacts, decoder.derived_bindings
        need(type(actual_artifacts) is tuple and type(actual_bindings) is tuple and actual_artifacts and actual_bindings, "DECODER_UNAVAILABLE")
        need(same(binding["normalized_ref"], self.event["payload_ref"]) and binding["normalized_artifact_kind"] == "CANONICAL_PAYLOAD"
             and payload_raw == self.resolve(self.event["payload_ref"]), "RAW_BYTES_MISMATCH")
        computed = {}
        for reference, raw in actual_artifacts:
            key = canonical_bytes(reference)
            need(key not in computed and sink.readback(reference) == raw and self.resolve(reference) == raw, "RAW_BYTES_MISMATCH")
            computed[key] = raw
        need(set(computed) == self.normalized, "RAW_EVIDENCE_UNAVAILABLE")
        need(len(actual_bindings) == len(self.bindings) and {canonical_bytes(x) for x in actual_bindings} == {canonical_bytes(x) for x in self.bindings}
             and sum(same(x, binding) for x in self.bindings) == 1, "RAW_BYTES_MISMATCH")
        for row in actual_bindings: capture.validate("DecodeBinding", row)
        need(len({canonical_bytes(x["decoded"]) for x in self.bindings}) == 1, "CLOCK_DRIFT")

    def walk(self, reference, active, depth):
        key = canonical_bytes(reference)
        need(depth <= 64 and key not in active and key in self.allowed, "RAW_EVIDENCE_UNAVAILABLE")
        if key in self.walked: return
        if reference["artifact_kind"] == "EVENT_RECORD":
            raw = self.accepted_event(reference, now=self.owner.fresh())
            need(self.resolve(reference) == raw, "RAW_BYTES_MISMATCH")
            # Its complete earlier graph has already been revalidated in this call.
            return
        raw = self.resolve(reference)
        if key in self.native: return
        value = decode_canonical(raw, limit=MAX_OBJECT)
        def visit(item, nesting):
            need(nesting <= 64, "RAW_EVIDENCE_UNAVAILABLE")
            if type(item) is dict:
                if set(item) == {"object_id", "bytes", "sha256", "artifact_kind"}:
                    self.walk(item, active | {key}, depth + 1)
                else:
                    for child in item.values(): visit(child, nesting + 1)
            elif type(item) is list:
                for child in item: visit(child, nesting + 1)
        visit(value, 0)
        self.walked.add(key)

    def object(self, reference, *, kind):
        need(reference["artifact_kind"] == kind and canonical_bytes(reference) in self.allowed, "PURPOSE_MISMATCH")
        return decode_canonical(self.resolve(reference), limit=MAX_OBJECT)

    def one(self, event, kind, *, fields=None):
        candidates = [self.object(r, kind=kind) for r in event["raw_refs"] if r["artifact_kind"] == kind]
        if fields is not None: candidates = [x for x in candidates if type(x) is dict and set(x) == fields]
        need(len(candidates) == 1, "RAW_EVIDENCE_UNAVAILABLE")
        return candidates[0]


class OperationalSemanticVerifier:
    """Sole public semantic verifier. Constructor is inert and snapshots selections.

    decoder_factory is the selected measurement AuthenticatedDecoder constructor.
    clock returns a freshly checked Stamp; authority_status returns a fresh,
    root-authenticated status through the selected authentication implementation.
    event_envelope resolves an exact already-retained witness envelope by Event ref.
    No callback can be substituted by a producer record or a positive default.
    """
    def __init__(self, *, authentication, evidence, appointment, budget, plan, selection,
                 decoder_factory, event_envelope, authority_status, clock, phase_guard):
        need(type(selection) is SemanticSelection, "CONTEXT_MISMATCH")
        self.authentication, self.evidence, self.selection = authentication, evidence, selection
        self.appointment_raw = method.validate("Appointment", appointment).raw
        self.budget_raw, self.plan_raw = method.validate("SetupBudget", budget).raw, method.validate("CoveragePlan", plan).raw
        self.decoder_factory, self.event_envelope = decoder_factory, event_envelope
        self.authority_status, self.clock = authority_status, clock
        self.phase_guard = phase_guard
        need(all(callable(x) for x in (event_envelope, authority_status, clock, phase_guard)), "APPOINTMENT_UNAVAILABLE")
        self.coverage = _Coverage(self.plan, self.plan_raw)
        self.sources = {slot: [method.decode("ObjectRef", raw).payload() for raw in refs] for slot, refs in selection.sources_by_slot}
        need(len(self.sources) == len(selection.sources_by_slot) and set(self.sources) == {x["slot_id"] for x in self.plan["slots"]}, "MISSING_SLOT")
        need(all(r["artifact_kind"] != "EVENT_RECORD" for rows in self.sources.values() for r in rows), "DEPENDENCY_ORDER")
        _Shapes().validate_value("Sha256", selection.decoder_component_sha256)
        _Shapes().validate_value("Sha256", selection.decoder_format_sha256)
        self._lock, self._interval = RLock(), None
        # Reuse the runtime's pure graph rules; this call does not construct a runtime.
        from .method_runtime import MethodRuntime
        MethodRuntime._validate_plan(None, self.plan)

    @property
    def appointment(self): return decode_canonical(self.appointment_raw)
    @property
    def budget(self): return decode_canonical(self.budget_raw)
    @property
    def plan(self): return decode_canonical(self.plan_raw)
    @property
    def witness_id(self):
        rows = [x["principal_id"] for x in self.appointment["principals"] if x["role"] == "TRUSTED_CONTROLLER_WITNESS"]
        need(len(rows) == 1, "SIGNER_UNAPPOINTED")
        return rows[0]

    def fresh(self, supplied=None):
        now = method.validate("Stamp", self.clock()).payload()
        need(supplied is None or stamp_le(supplied, now), "CLOCK_DRIFT")
        status = self.authority_status(now)
        interval = self.authentication.authenticate_appointment(self.appointment, authority_status=status, budget=self.budget, now=now)
        method.validate("AuthenticatedInterval", interval)
        need(same(interval["binding"], self.budget["binding"]) and utc(interval["not_before_utc"]) <= utc(now["utc"]) < utc(interval["expires_at_utc"]), "AUTHENTICATED_INTERVAL_EXPIRED")
        self._interval = interval
        return interval["validated_at"]

    def _all(self, raws, *, plan_raw, budget_raw, now):
        need(type(raws) is tuple and 0 < len(raws) <= 19 and plan_raw == self.plan_raw and budget_raw == self.budget_raw, "CONTEXT_MISMATCH")
        self.fresh(now)
        need(digest(plan_raw) == self.appointment["coverage_plan_sha256"] == self.budget["coverage_plan_sha256"]
             and digest(self.appointment_raw) == self.budget["binding"]["appointment_sha256"]
             and same(self.plan["scope"], self.budget["binding"]["scope"]), "CONTEXT_MISMATCH")
        accepted, artifacts, envelopes = [], {}, {}
        for index, raw in enumerate(raws):
            event = method.decode("Event", raw).payload()
            slot = self.plan["slots"][index]
            need(event["sequence"] == index + 1 and event["slot_id"] == slot["slot_id"] and event["kind"] == slot["kind"]
                 and event["origin"] == slot["origin"]
                 and event["previous_record_sha256"] == (digest(raws[index - 1]) if index else ZERO), "SEQUENCE_GAP")
            need(event["record_id"] not in {x["event"]["record_id"] for x in accepted}
                 and set(slot["after_slots"]) <= {x["event"]["slot_id"] for x in accepted}, "DEPENDENCY_ORDER")
            need(same(event["binding"], self.budget["binding"]) and event["budget_sha256"] == digest(budget_raw)
                 and event["stream_id"] == self.appointment["stream_id"] and event["producer_id"] == self.witness_id, "CONTEXT_MISMATCH")
            label = ORIGIN_LABELS[event["kind"]]
            need(event["origin"] == label["origin"] and event["evidence_class"] == label["evidence_class"], "CONTEXT_MISMATCH")
            need(stamp_le(self.budget["started"], event["observed_start"]) and stamp_le(event["observed_start"], event["observed_end"])
                 and stamp_le(event["observed_end"], event["recorded"]) and stamp_le(event["recorded"], self.fresh())
                 and (not index or stamp_le(accepted[-1]["event"]["recorded"], event["recorded"])), "CLOCK_DRIFT")
            event_ref = ref(raw, "EVENT_RECORD")
            envelope = self.event_envelope(event_ref)
            envelope_raw = method.validate("SignedEnvelope", envelope).raw
            self.authentication.verify_attestation(raw, envelope, expected_purpose="policy-inheritance-witness-v3", appointment=self.appointment, now=self.fresh())
            need(envelope["body"]["producer_id"] == event["producer_id"], "SIGNER_UNAPPOINTED")
            envelope_ref = ref(envelope_raw, "SIGNED_ENVELOPE")
            artifacts[canonical_bytes(event_ref)] = (event_ref, raw)
            artifacts[canonical_bytes(envelope_ref)] = (envelope_ref, envelope_raw)
            envelopes[canonical_bytes(envelope_ref)] = (envelope_ref, envelope)
            graph = _Graph(self, event, tuple(accepted), artifacts, envelopes)
            graph.load()
            payload = method.decode(PAYLOAD_TYPES[event["kind"]], graph.resolve(event["payload_ref"])).payload()
            selected = dict(graph.selection["values"])
            selected["subject_id"] = graph.selection["subject_id"]
            if "installation" in selected:
                selected["installations"] = {event["kind"]: selected.pop("installation")}
            _Predicates(self.coverage, selected).validate(event, payload, graph, tuple(accepted), now=self.fresh())
            if "unsupported_routes" in payload:
                need(same(payload["unsupported_routes"], self.plan["unsupported_routes"]), "UNSUPPORTED_ROUTE_RELABELED")
            self._selection_rules(graph, payload)
            accepted.append({"event": event, "event_raw": raw, "event_sha256": digest(raw), "payload": payload,
                             "selected_values": selected, "spawn": graph.spawn})
        self.fresh()
        interval = dict(self._interval)
        interval["not_before_utc"] = max([interval["not_before_utc"]] + [x[1]["body"]["issued"]["utc"] for x in envelopes.values()])
        interval["expires_at_utc"] = min([interval["expires_at_utc"], self.budget["deadline"]["utc"]] + [x[1]["body"]["expires"]["utc"] for x in envelopes.values()])
        interval["dependency_attestation_refs"] = [x[0] for _, x in sorted(envelopes.items())]
        interval["validated_at"] = self.fresh()
        need(utc(interval["not_before_utc"]) <= utc(interval["validated_at"]["utc"]) < utc(interval["expires_at_utc"]), "AUTHENTICATED_INTERVAL_EXPIRED")
        method.validate("AuthenticatedInterval", interval)
        return tuple(artifacts[key] for key in sorted(artifacts)), interval

    def _selection_rules(self, graph, payload):
        values = graph.selection["values"]
        kind = graph.event["kind"]
        if "calibration" in values:
            calibration = values["calibration"]
            need(len(set(calibration["retired_pids"])) == len(calibration["retired_pids"])
                 and sorted(calibration["retired_pids"]) == sorted(x["pid"] for x in calibration["temporary_actors"]), "CALIBRATION_BASELINE_MISMATCH")
        if kind == "CALIBRATION_CASE":
            expectation = self.coverage.expectation(graph.event["slot_id"])
            baseline = BASELINES[expectation["case_kind"]]
            need(same(expectation["expected_exchange_verdicts"], baseline["exchange_verdicts"])
                 and expectation["requires_foreign_pid"] is baseline["foreign_pid"]
                 and graph.selection["subject_id"] == expectation["case_id"], "CALIBRATION_BASELINE_MISMATCH")
        if "installation" in values:
            selected = values["installation"]
            policies = [raw for slot_id, raw in self.selection.policies_by_slot if slot_id == graph.event["slot_id"]]
            need(len(policies) == 1, "INSTALLATION_FAILED_OR_UNOBSERVED")
            expected_policy = decode_canonical(policies[0])
            need(type(expected_policy) is dict and set(expected_policy) == {"abi", "handled_fs", "rules", "targets"}
                 and same(expected_policy, {k: selected[k] for k in expected_policy})
                 and digest(policies[0]) == graph.spawn["selected_policy_sha256"]
                 and ref(policies[0], "CANONICAL_PAYLOAD") in graph.inputs["selected_source_refs"], "INSTALLATION_FAILED_OR_UNOBSERVED")
            need(selected["abi"] >= 4 and len({x["fd"] for x in selected["descriptors"]}) == len(selected["descriptors"]), "DESCRIPTOR_IDENTITY_MISMATCH")
            rules, targets = selected["rules"], selected["targets"]
            need(len({r["target_id"] for r in rules}) == len(rules) and len({r["target_id"] for r in targets}) == len(targets)
                 and {x["target_id"] for x in rules} == {x["target_id"] for x in targets}
                 and all(x["rights"] > 0 and x["rights"] & ~selected["handled_fs"] == 0 for x in rules), "INSTALLATION_FAILED_OR_UNOBSERVED")

    def validate_event(self, *, event_raw: bytes, accepted_raw: tuple[bytes, ...], plan_raw: bytes, budget_raw: bytes, now: method.Stamp) -> tuple[tuple[method.ObjectRef, bytes], ...]:
        with self._lock:
            artifacts, _ = self._all(accepted_raw + (event_raw,), plan_raw=plan_raw, budget_raw=budget_raw, now=now)
            return artifacts

    def validate_sealed(self, *, accepted_raw: tuple[bytes, ...], plan_raw: bytes, budget_raw: bytes, now: method.Stamp) -> method.AuthenticatedInterval:
        with self._lock:
            need(len(accepted_raw) == 19, "INCOMPLETE_STREAM")
            artifacts, interval = self._all(accepted_raw, plan_raw=plan_raw, budget_raw=budget_raw, now=now)
            # Revalidation reads never advance checkpoint or create an ACK.
            # Existing bytes must already be retained; retain_exact is idempotent.
            for reference, raw in artifacts:
                need(same(self.evidence.retain_exact(reference, raw), reference), "RETENTION_COMMIT_FAILED")
                need(self.evidence.resolve(reference) == raw, "RETENTION_UNAVAILABLE")
                self.fresh()
            return interval


class _Predicates:
    def __init__(self, coverage, selected):
        self.contract, self.coverage, self._selected = _Shapes(), coverage, selected
        self._spec = {"payload_type_by_event_kind": PAYLOAD_TYPES, "fixed_calibration_baseline": BASELINES}

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

    def validate(self, event: dict[str, Any], payload: dict[str, Any], evidence: _Graph,
                 accepted: tuple[dict[str, Any], ...], *, now: dict[str, Any]) -> None:
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
        selected = self._selected["installations"][kind]
        require(p["process_identity"] == selected["process"],
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "install.spawn_identity")
        observation = exact_fields(evidence.one(event, "PROC_IDENTITY"),
                                   {"process", "parent", "threads", "observed_start", "observed_end"}, "install.proc")
        require(_same(observation["process"], p["process_identity"]) and _same(observation["threads"], p["threads"]),
                "INSTALLATION_FAILED_OR_UNOBSERVED", "install.actual_threads")
        self._inside(event, observation["observed_start"]); self._inside(event, observation["observed_end"])
        require(stamp_le(observation["observed_start"], observation["observed_end"])
                and len(p["threads"]) == 1
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
        require(_same(p["expected_descriptor_plan_ref"], selected["descriptor_plan_ref"])
                and _same(p["expected_descriptor_plan_ref"], evidence.inputs["spawn_selection"]["object_ref"]),
                "DESCRIPTOR_IDENTITY_MISMATCH", "install.descriptor_plan")
        spawn = evidence.spawn
        require(_subject_matches(spawn["parent"], parent) and _subject_matches(spawn["child"], p["process_identity"]),
                "SOURCE_OR_EXEC_IDENTITY_MISMATCH", "install.spawn_parent")
        expected_descriptors = [_child_descriptor(x) for x in spawn["descriptor_bindings"]]
        require(_same(sorted(expected_descriptors, key=lambda x:x["fd"]), sorted(selected["descriptors"], key=lambda x:x["fd"])),
                "DESCRIPTOR_IDENTITY_MISMATCH", "install.parent_selected_descriptors")
        actual = exact_fields(evidence.one(event, "DESCRIPTOR_INVENTORY", fields={"process", "descriptors", "observed"}),
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
        nnp = exact_fields(evidence.one(event, "INSTALL_ARGUMENTS", fields={"process", "no_new_privs", "observed"}),
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
                and _subject_matches(model["spawn"]["parent"], parent),
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
                and after["exe_asset"]["sha256"] == asset["sha256"]
                and after["exe_asset"]["bytes"] == asset["bytes"]
                and after["exe_asset"]["asset_id"] == asset["asset_id"]
                and after["exe_asset"]["selected_path"] == asset["path"]
                and after["exe_asset"]["device"] == asset["device"] and after["exe_asset"]["inode"] == asset["inode"],
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
        require(_same(p["first_packet_ref"], self._selected["peer"]["first_packet_ref"])
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
        spawn_descriptors = [_child_descriptor(x) for x in runner["spawn"]["descriptor_bindings"]]
        require(len(retained_descriptors) == 1 and retained_descriptors[0]["object_type"] == "SOCKET"
                and _same(current["descriptor"], retained_descriptors[0])
                and sum(_same(d, current["descriptor"]) for d in spawn_descriptors) == 1,
                "DESCRIPTOR_IDENTITY_MISMATCH", "peer.retained_runner_endpoint")
        require(current["process"] == peer and current["endpoint_id"] == packet["endpoint_id"]
                and _same(current, evidence.object(self._selected["peer"]["current_peer_ref"], kind="PROC_IDENTITY")),
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
