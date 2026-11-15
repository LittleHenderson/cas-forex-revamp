"""NR01-NR11 custody checks and exact durable release admission.

No activation, initialization, signer/key loading, NR12 consumption, process or
model launch occurs on import/construction. All operational dependencies are
externally selected. No missing capture, schema or semantic check can pass.
"""
import re
import os
import stat
import contextlib
from dataclasses import dataclass, fields
from cas_forex_operational_contracts import common, method, capture, protected, completion, release, validation
from .selection_provider import require, same, fresh, call_none

ROLE_SLOT = "role_read_isolation_receipt_sha256"
SLOTS = tuple(validation.ENUMS["protected"]["ReleaseEvidenceSlot"])


def _ordered(a, b):
    return common.utc(a["utc"]) <= common.utc(b["utc"]) and a["boottime_ns"] <= b["boottime_ns"]


def _latest(stamps):
    result = max(stamps, key=lambda s:s["boottime_ns"])
    require(all(_ordered(s,result) for s in stamps), "PAIRED_CLOCK_REGRESSION")
    return result


def _subject_identity(subject, identity):
    return all(subject[k] == identity[k] for k in ("boot_id","pid","start_ticks","parent_pid","uid","gid"))


def _stat(raw):
    """Parse Linux /proc/PID/stat with a parenthesized comm containing spaces."""
    text = raw.decode("ascii", "strict").strip()
    opening, closing = text.find("("), text.rfind(")")
    require(opening > 0 and closing > opening, "PROC_STAT_ENCODING")
    fields = text[closing+1:].split()
    require(len(fields) >= 20 and text[:opening].strip().isdigit(), "PROC_STAT_FIELDS")
    return {"pid":int(text[:opening].strip()),"parent_pid":int(fields[1]),"start_ticks":int(fields[19])}


def _status(raw):
    fields = {}
    for line in raw.decode("ascii", "strict").splitlines():
        if ":" not in line: continue
        name, value = line.split(":",1)
        require(name not in fields,"PROC_STATUS_DUPLICATE"); fields[name]=value.split()
    for key in ("Uid","Gid","Pid","PPid","Threads"): require(key in fields,"PROC_STATUS_FIELD")
    require(len(fields["Uid"])==len(fields["Gid"])==4,"PROC_CREDENTIAL_FIELDS")
    require(len(set(fields["Uid"]))==len(set(fields["Gid"]))==1,"PROC_CREDENTIAL_AMBIGUITY")
    return {"uid":int(fields["Uid"][0]),"gid":int(fields["Gid"][0]),"pid":int(fields["Pid"][0]),
            "parent_pid":int(fields["PPid"][0]),"threads":int(fields["Threads"][0])}


@dataclass(frozen=True)
class ReleaseContext:
    """Pinned constructor data, not a new wire record or a supplied success flag.

    Integration resolves these existing accepted records through appointed ports.
    Expected processes/parents/channel and opaque issuance ID/time/expiry come
    from the independently selected observer/controller context, never the wrapper.
    """
    appointment: dict
    budget: dict
    coverage_plan: dict
    sealed_history: tuple
    controller: dict
    parents: dict
    evidence_id: str
    issued: dict
    requested_expiry: dict
    original_model_deadline: dict
    original_global_deadline: dict
    observer_record: dict
    controller_record: dict
    channel_record: dict
    original_clock_record: dict
    role_schema_sha256: str


@dataclass(frozen=True)
class DecoderSelection:
    """Independent constructor pins; not producer-supplied wire fields.

    Source refs are immutable canonical ObjectRef bytes, grouped by every plan
    slot. Spawn pins are (slot, component hash, executable asset ID, policy hash).
    """
    decoder_component_sha256: str
    decoder_format_sha256: str
    sources_by_slot: tuple
    spawn_pins_by_slot: tuple
    policies_by_slot: tuple


class RecomputedSink:
    """Fresh decoder output only. Never populated from retained producer data."""
    def __init__(self): self.items={}

    def retain(self, raw, *, artifact_kind):
        require(type(raw) is bytes and 0<len(raw)<=common.MAX_OBJECT,"RECOMPUTED_OBJECT_BOUND")
        ref=method.validate("ObjectRef",{"object_id":common.digest(raw),"sha256":common.digest(raw),
            "bytes":len(raw),"artifact_kind":artifact_kind}).payload()
        key=common.canonical_bytes(ref)
        if key in self.items: require(self.items[key]==raw,"RECOMPUTED_OBJECT_CHANGED")
        else:
            require(len(self.items)<4096 and sum(map(len,self.items.values()))+len(raw)<=common.MAX_GRAPH,"RECOMPUTED_GRAPH_BOUND")
            self.items[key]=raw
        return ref

    def readback(self, reference):
        ref=reference
        key=common.canonical_bytes(method.validate("ObjectRef",ref).payload())
        require(key in self.items,"RECOMPUTED_OBJECT_UNAVAILABLE")
        raw=self.items[key];validation.verify_reference_bytes(ref,raw)
        return raw


class MethodGraph:
    """Fresh authenticated bounded graph, with exact raw leaf preservation."""
    def __init__(self, *, context, evidence_store, authentication, authority_status,
                 runtime, decoder_factory, decoder_selection, selected_phase_guard, clock, current_authority_guard):
        self.context=context; self.store=evidence_store; self.auth=authentication
        self.status=authority_status; self.runtime=runtime
        require(type(decoder_selection) is DecoderSelection and callable(decoder_factory) and callable(selected_phase_guard),"SELECTED_DECODER_UNAVAILABLE")
        require(all(type(pin) is str and re.fullmatch(r"[0-9a-f]{64}",pin) for pin in
            (decoder_selection.decoder_component_sha256,decoder_selection.decoder_format_sha256)),"SELECTED_DECODER_PIN")
        require(type(decoder_selection.sources_by_slot) is tuple and type(decoder_selection.spawn_pins_by_slot) is tuple
            and type(decoder_selection.policies_by_slot) is tuple
            and all(type(row) is tuple and len(row)==2 and type(row[0]) is str and type(row[1]) is tuple
                    and all(type(raw) is bytes for raw in row[1]) for row in decoder_selection.sources_by_slot)
            and all(type(row) is tuple and len(row)==4 and all(type(v) is str for v in row)
                    for row in decoder_selection.spawn_pins_by_slot)
            and all(type(row) is tuple and len(row)==2 and type(row[0]) is str and type(row[1]) is bytes
                    for row in decoder_selection.policies_by_slot),"IMMUTABLE_DECODER_SELECTION")
        self.selected_phase_guard=selected_phase_guard
        self.decoder_factory,self.decoder_selection=decoder_factory,decoder_selection
        self.sources={slot:[method.decode("ObjectRef",raw).payload() for raw in refs]
                      for slot,refs in decoder_selection.sources_by_slot}
        require(len(self.sources)==len(decoder_selection.sources_by_slot)
                and set(self.sources)=={s["slot_id"] for s in context.coverage_plan["slots"]},"SELECTED_SOURCE_SLOTS")
        self.spawn_pins={row[0]:row[1:] for row in decoder_selection.spawn_pins_by_slot}
        require(len(self.spawn_pins)==len(decoder_selection.spawn_pins_by_slot)
                and set(self.spawn_pins)=={s["slot_id"] for s in context.coverage_plan["slots"] if s["kind"] in ("RUNNER_INSTALL","MODEL_INSTALL")},"SELECTED_POLICY_SLOTS")
        self.policies=dict(decoder_selection.policies_by_slot)
        require(len(self.policies)==len(decoder_selection.policies_by_slot) and set(self.policies)==set(self.spawn_pins),"SELECTED_POLICY_BODIES")
        self.clock,self.guard=clock,current_authority_guard
        self.cache={}; self.caps=[]; self.interval=None; self.walked=set()
        self.native_manifests={};self.accepted_prefix={}

    def current(self, now):
        if now is None: now=self.clock()
        now=fresh(self.clock,self.guard,now,self.context.budget["deadline"])
        if self.status is None: raise common.DependencyUnavailable("current-authority-status")
        interval=self.auth.authenticate_appointment(self.context.appointment,authority_status=self.status(now),budget=self.context.budget,now=now)
        interval=method.validate("AuthenticatedInterval",interval).payload()
        now=fresh(self.clock,self.guard,now,self.context.budget["deadline"])
        require(same(interval["binding"],self.context.budget["binding"])
                and common.utc(interval["not_before_utc"])<=common.utc(now["utc"])<common.utc(interval["expires_at_utc"]),"METHOD_AUTHORITY_INTERVAL")
        self.interval=interval
        return now

    def raw(self, reference, now):
        now=self.current(now)
        reference=method.validate("ObjectRef",reference).payload()
        raw=self.store.resolve(reference)
        validation.verify_reference_bytes(reference,raw)
        key=reference["sha256"]
        if key in self.cache: require(self.cache[key]==raw,"GRAPH_OBJECT_CHANGED")
        else:
            require(len(self.cache)<4096 and sum(map(len,self.cache.values()))+len(raw)<=min(common.MAX_GRAPH,self.context.coverage_plan["max_raw_bytes"]),"COMPLETE_GRAPH_BOUND")
            self.cache[key]=raw
        self.current(now)
        return raw

    def resolve(self, reference):
        """Read-only evidence port supplied to the selected decoder."""
        return self.raw(reference,self.current(None))

    def accepted_event(self, reference, *, now):
        self.current(now)
        key=common.canonical_bytes(method.validate("ObjectRef",reference).payload())
        require(reference["artifact_kind"]=="EVENT_RECORD" and key in self.accepted_prefix,"ACCEPTED_PREFIX_ONLY")
        raw=self.accepted_prefix[key]
        require(self.raw(reference,now)==raw,"ACCEPTED_PREFIX_CHANGED")
        return raw

    def phase_guard(self, kind, *, observed, now):
        current=self.current(now)
        require(_ordered(self.context.budget["started"],observed) and _ordered(observed,current),"CALIBRATION_PHASE_INTERVAL")
        call_none(self.selected_phase_guard,kind,observed=observed,now=current)
        self.current(current)

    def _recompute(self, pair, inputs, values, event, bindings, now):
        sink=RecomputedSink()
        decoder=self.decoder_factory(event_inputs=pair,evidence=self,authenticator=self.auth,
            appointment=self.context.appointment,budget=self.context.budget,plan=self.context.coverage_plan,
            sink=sink,component_sha256=self.decoder_selection.decoder_component_sha256,
            format_sha256=self.decoder_selection.decoder_format_sha256,
            accepted_event=self.accepted_event,phase_guard=self.phase_guard)
        primary,payload_raw=decoder.decode_actual(tuple(inputs["capture_objects"]),selection=values,
            decoder_component_sha256=self.decoder_selection.decoder_component_sha256,
            decoder_format_sha256=self.decoder_selection.decoder_format_sha256,now=self.current(now))
        self.current(now)
        primary=capture.validate("DecodeBinding",primary).payload()
        artifacts,actual_bindings=decoder.derived_artifacts,decoder.derived_bindings
        require(type(artifacts) is tuple and type(actual_bindings) is tuple and artifacts and actual_bindings,"COMPLETE_DECODE_ACCESSORS")
        require(primary["normalized_artifact_kind"]=="CANONICAL_PAYLOAD" and same(primary["normalized_ref"],event["payload_ref"])
                and type(payload_raw) is bytes and self.raw(event["payload_ref"],now)==payload_raw,"PRIMARY_DECODE_BYTES")
        computed=set()
        for ref,raw in artifacts:
            key=common.canonical_bytes(method.validate("ObjectRef",ref).payload())
            require(key not in computed and type(raw) is bytes and sink.readback(ref)==raw
                    and self.raw(ref,now)==raw,"INDEPENDENT_DECODE_BYTES")
            computed.add(key)
        normalized={common.canonical_bytes(x["normalized_ref"]) for x in bindings}
        require(len(normalized)==len(bindings) and computed==normalized and set(sink.items)==computed,"COMPLETE_NORMALIZED_SET")
        for binding in actual_bindings: capture.validate("DecodeBinding",binding)
        require(len(actual_bindings)==len(bindings) and {common.canonical_bytes(x) for x in actual_bindings}=={common.canonical_bytes(x) for x in bindings}
                and sum(same(x,primary) for x in bindings)==1,"COMPLETE_ORIGINAL_BINDING_SET")
        require(len({common.canonical_bytes(x["decoded"]) for x in bindings})==1,"ORIGINAL_DECODE_STAMP")

    def walk_dependencies(self, value, now):
        """Resolve content-bound nested objects, including normalized leaf refs.

        This proves retained bytes/graph closure only. Authentication and actual
        semantics remain the separate selected envelope/decoder/role checks.
        """
        if isinstance(value,dict):
            if set(value)=={"object_id","bytes","sha256","artifact_kind"}:
                reference=method.validate("ObjectRef",value).payload()
                raw=self.raw(reference,now)
                key=(reference["sha256"],reference["artifact_kind"])
                if key in self.walked: return
                self.walked.add(key)
                if reference["artifact_kind"] not in {"NATIVE_CAPTURE_BYTES","SOURCE_ARGUMENT","PUBLIC_FIXTURE","EXECUTABLE_PIN"}:
                    self.walk_dependencies(common.decode_canonical(raw,limit=common.MAX_OBJECT),now)
                return
            for child in value.values(): self.walk_dependencies(child,now)
        elif isinstance(value,list):
            for child in value: self.walk_dependencies(child,now)

    def authenticated(self, pair, kind, namespace, type_name, now, *, purpose="policy-inheritance-witness-v3"):
        pair=capture.validate("AuthenticatedMethodObject",pair).payload()
        require(pair["object_ref"]["artifact_kind"]==kind and pair["envelope_ref"]["artifact_kind"]=="SIGNED_ENVELOPE","METHOD_OBJECT_ROUTE")
        raw=self.raw(pair["object_ref"],now)
        envelope=method.decode("SignedEnvelope",self.raw(pair["envelope_ref"],now)).payload()
        require(envelope["body"]["record_sha256"]==pair["object_ref"]["sha256"]
                and envelope["body"]["record_bytes"]==len(raw)
                and same(envelope["body"]["binding"],self.context.budget["binding"])
                and envelope["body"]["budget_sha256"]==common.digest(method.validate("SetupBudget",self.context.budget).raw),"METHOD_ENVELOPE_BINDING")
        current=self.current(now)
        call_none(self.auth.verify_attestation,raw,envelope,expected_purpose=purpose,appointment=self.context.appointment,now=current)
        current=self.current(current)
        require(_ordered(envelope["body"]["issued"],current) and common.utc(current["utc"])<common.utc(envelope["body"]["expires"]["utc"])
                and current["boottime_ns"]<envelope["body"]["expires"]["boottime_ns"],"METHOD_ATTESTATION_EXPIRED")
        self.caps.append(envelope["body"]["expires"])
        value=validation.decode_record(namespace,type_name,raw).payload() if type_name else common.decode_canonical(raw,limit=common.MAX_OBJECT)
        self.walk_dependencies(value,now)
        return value

    def sealed(self, decision, exposure, now):
        output={"kind":"METHOD_DECISION","body_ref":exposure["body_ref"],"attestation_ref":exposure["attestation_ref"]}
        recovered=self.runtime.recover_exact(output,now=self.current(now))
        require(same(method.validate("ExposedOutput",recovered).payload(),exposure),"EXACT_METHOD_RECOVERY")
        require(len(self.context.sealed_history)==19,"COMPLETE_SEALED_HISTORY")
        previous=common.ZERO_SHA256; events=[]; stage_inputs={}; payloads={}
        for index,pair in enumerate(self.context.sealed_history,1):
            event=self.authenticated(pair,"EVENT_RECORD","method","Event",now)
            require(event["sequence"]==index and event["previous_record_sha256"]==previous
                    and event["stream_id"]==decision["stream_id"] and event["budget_sha256"]==decision["budget_sha256"]
                    and same(event["binding"],decision["binding"]),"SEALED_EVENT_CHAIN")
            slots=[s for s in self.context.coverage_plan["slots"] if s["slot_id"]==event["slot_id"]]
            require(len(slots)==1 and slots[0]["kind"]==event["kind"] and slots[0]["origin"]==event["origin"],"SEALED_SLOT")
            input_pair={"object_ref":event["input_bundle_ref"],"envelope_ref":event["input_bundle_envelope_ref"]}
            inputs=self.authenticated(input_pair,
                "AUTHENTICATED_EVENT_INPUTS","capture","EventInputs",now)
            require(inputs["record_id"]==event["record_id"] and inputs["stream_id"]==event["stream_id"]
                    and inputs["slot_id"]==event["slot_id"] and inputs["event_kind"]==event["kind"]
                    and same(inputs["binding"],event["binding"]) and inputs["budget_sha256"]==event["budget_sha256"],"EVENT_INPUT_BINDING")
            values=self.authenticated(inputs["selected_values"],"RUNTIME_SELECTED_VALUES","capture","RuntimeSelectedValues",now)
            selection=self.authenticated(inputs["runtime_selection"],"RUNTIME_SELECTION_BINDING","capture","RuntimeSelectionBinding",now)
            require(values["slot_id"]==selection["slot_id"]==event["slot_id"] and values["event_kind"]==event["kind"]
                    and values["subject_id"]==selection["subject_id"]==slots[0]["expected_subject_id"]
                    and selection["selected_decoder_sha256"]==slots[0]["payload_decoder_sha256"]
                    and same(selection["selection_ref"],inputs["selected_values"]["object_ref"]),"STAGE_SELECTION")
            selected_sources=self.sources[event["slot_id"]]+[prior_pair["object_ref"] for prior_pair,_ in events]
            require(len(selected_sources)<=32 and len({common.canonical_bytes(r) for r in selected_sources})==len(selected_sources)
                    and same(inputs["selected_source_refs"],selected_sources)
                    and same(selection["selected_source_refs"],selected_sources)
                    and selection["selected_decoder_sha256"]==self.decoder_selection.decoder_component_sha256
                    and _ordered(self.context.budget["started"],selection["selected_at"])
                    and _ordered(selection["selected_at"],event["recorded"]),"INDEPENDENT_SOURCE_SELECTION")
            for source in inputs["selected_source_refs"]: self.raw(source,now)
            for obj in inputs["raw_blob_manifests"]:
                manifest=self.authenticated(obj,"RAW_BLOB_MANIFEST","capture","RawBlobManifest",now)
                self.native_manifests[obj["object_ref"]["sha256"]]=manifest
                if manifest["blob_ref"] is not None:
                    native=self.raw(manifest["blob_ref"],now)
                    require(len(native)==manifest["raw_bytes"] and common.digest(native)==manifest["raw_sha256"],"NATIVE_BLOB_PIN")
            captures=[self.authenticated(obj,"TRUSTED_CAPTURE_BATCH","capture","CaptureBatch",now) for obj in inputs["capture_objects"]]
            if inputs["spawn_selection"] is not None:
                spawn=self.authenticated(inputs["spawn_selection"],"TRUSTED_SPAWN_SELECTION","capture","SpawnSelection",now)
                require(event["slot_id"] in self.spawn_pins and tuple(self.spawn_pins[event["slot_id"]])==
                    (spawn["component_sha256"],spawn["selected_executable_asset_id"],spawn["selected_policy_sha256"]),"INDEPENDENT_SPAWN_POLICY")
                policy_raw=self.policies[event["slot_id"]]
                policy=common.decode_canonical(policy_raw)
                require(type(policy) is dict and set(policy)=={"abi","handled_fs","rules","targets"}
                        and same(policy,{key:values["values"][key] for key in policy})
                        and common.digest(policy_raw)==spawn["selected_policy_sha256"],"INDEPENDENT_POLICY_BODY")
                policy_ref={"object_id":common.digest(policy_raw),"sha256":common.digest(policy_raw),"bytes":len(policy_raw),"artifact_kind":"CANONICAL_PAYLOAD"}
                require(policy_ref in selected_sources and self.raw(policy_ref,now)==policy_raw,"SELECTED_POLICY_SOURCE")
            else: require(event["slot_id"] not in self.spawn_pins,"MISSING_SPAWN_POLICY")
            normalized=[];bindings=[]
            for obj in inputs["decode_objects"]:
                claimed=self.authenticated(obj,"RUNTIME_DECODE_BINDING","capture","DecodeBinding",now)
                require(claimed["decoder_component_sha256"]==slots[0]["payload_decoder_sha256"]
                        and claimed["decoder_format_sha256"]==self.decoder_selection.decoder_format_sha256
                        and claimed["event_kind"]==event["kind"] and same(claimed["capture_refs"],[p["object_ref"] for p in inputs["capture_objects"]])
                        and same(claimed["capture_envelope_refs"],[p["envelope_ref"] for p in inputs["capture_objects"]])
                        and same(claimed["selected_input_refs"],selected_sources)
                        and _ordered(selection["selected_at"],claimed["decoded"]) and _ordered(claimed["decoded"],event["recorded"])
                        and all(_ordered(c["finished"],claimed["decoded"]) for c in captures),"DECODER_PIN_AND_ORIGINAL_STAMP")
                normalized.append(claimed["normalized_ref"])
                bindings.append(claimed)
            self._recompute(input_pair,inputs,values,event,bindings,now)
            require(event["payload_ref"] in normalized and {common.canonical_bytes(r) for r in event["raw_refs"]}
                    == {common.canonical_bytes(r) for r in [event["input_bundle_ref"],event["input_bundle_envelope_ref"],*normalized]},"EVENT_RAW_REFERENCE_SET")
            payload=common.decode_canonical(self.raw(event["payload_ref"],now))
            stage_inputs[event["record_id"]]=(inputs,captures,values)
            payloads[event["record_id"]]=payload
            events.append((pair,event)); previous=pair["object_ref"]["sha256"]
            self.accepted_prefix[common.canonical_bytes(pair["object_ref"])]=self.raw(pair["object_ref"],now)
        require(previous==decision["sealed_head_sha256"] and events[-1][1]["kind"]=="SETUP_SEAL","SEALED_HEAD")
        seal=method.validate("SetupSealPayload",payloads[events[-1][1]["record_id"]]).payload()
        require(seal["entries"]==[{"sequence":event["sequence"],"record_id":event["record_id"],"record_sha256":pair["object_ref"]["sha256"]} for pair,event in events[:-1]]
                and seal["previous_head_sha256"]==events[-2][0]["object_ref"]["sha256"],"SEALED_DENOMINATOR")
        return events,stage_inputs,payloads


class NarrowRoleEvidenceVerifier:
    def __init__(self, *, context, authority, method_evidence, method_authentication, authority_status,
                 method_runtime, decoder_factory, decoder_selection, selected_phase_guard, clock, current_authority_guard):
        body={f.name:getattr(context,f.name) for f in fields(ReleaseContext)}
        body["sealed_history"]=list(body["sealed_history"])
        body=common.decode_canonical(common.canonical_bytes(body,limit=common.MAX_GRAPH),limit=common.MAX_GRAPH)
        body["sealed_history"]=tuple(body["sealed_history"])
        context=ReleaseContext(**body)
        self.context=context; self.authority=authority
        self.dependencies=dict(context=context,evidence_store=method_evidence,authentication=method_authentication,
            authority_status=authority_status,runtime=method_runtime,decoder_factory=decoder_factory,decoder_selection=decoder_selection,
            selected_phase_guard=selected_phase_guard,clock=clock,current_authority_guard=current_authority_guard)

    def verify(self, evidence, *, selected, publishers, resolver, now):
        self.reconstruct(evidence,selected=selected,publishers=publishers,resolver=resolver,now=now)

    def reconstruct(self, evidence, *, selected, publishers, resolver, now):
        graph=MethodGraph(**self.dependencies)
        now=graph.current(now)
        selected=protected.validate("ReleaseSelection3",selected).payload()
        evidence=release.validate("NarrowRoleReleaseEvidence1",evidence).payload()
        uses={row["slot"]:row["evidence"] for row in selected["release_evidence"]}
        require(set(uses)==set(SLOTS) and len(selected["release_evidence"])==17,"NR01_EXACT_GATES")
        role_use=uses[ROLE_SLOT]
        require(role_use["required_use"]=="PRIVATE_RELEASE" and role_use["reference"]["record_kind"]=="EXTERNAL_RELEASE_EVIDENCE"
                and role_use["reference"]["purpose"]=="release-evidence:"+ROLE_SLOT,"NR01_ROUTE")
        _,publisher,grant,now=self.authority.check_grant(role_use["reference"],publishers,now,required_use="PRIVATE_RELEASE")
        witnesses=[p for p in self.context.appointment["principals"] if p["role"]=="TRUSTED_CONTROLLER_WITNESS"]
        require(len(witnesses)==1,"NR02_WITNESS_APPOINTMENT"); witness=witnesses[0]
        require(grant["payload_schema_sha256"]==self.context.role_schema_sha256==validation.ACCEPTED_FILE_PINS["role-release-evidence.candidate.json"]
                and publisher["role"]=="CONTROLLER"
                and publisher["publisher_id"]==witness["principal_id"]==selected["observer_id"]==evidence["observer_id"]
                and publisher["signer_public_sha256"]==witness["signer_public_sha256"]
                and publisher["component_manifest_sha256"]==witness["component_manifest_sha256"],"NR01_APPOINTED_PUBLISHER")
        raw=resolver.resolve(role_use,selection=publishers,now=now)
        require(same(release.decode("NarrowRoleReleaseEvidence1",raw).payload(),evidence),"NR01_WRAPPER_SUBSTITUTED")
        require(same(evidence["binding"],selected["binding"]) and same(evidence["method_binding"],self.context.budget["binding"])
                and all(evidence["method_binding"]["scope"][k]==v for k,v in selected["binding"].items())
                and evidence["setup_budget_sha256"]==selected["setup_budget_sha256"]==common.digest(method.validate("SetupBudget",self.context.budget).raw)
                and selected["method_appointment_sha256"]==common.digest(method.validate("Appointment",self.context.appointment).raw),"NR02_BINDING")
        require(same(evidence["observer_binding"],uses["trusted_observer_binding_sha256"])
                and same(evidence["original_clock_binding"],uses["original_clock_and_budget_binding_sha256"]),"NR02_REFERENCE_BINDING")
        for slot,expected in (("trusted_observer_binding_sha256",self.context.observer_record),
                              ("controller_identity_sha256",self.context.controller_record),
                              ("authorized_current_frame_channel_sha256",self.context.channel_record),
                              ("original_clock_and_budget_binding_sha256",self.context.original_clock_record)):
            require(same(common.decode_canonical(resolver.resolve(uses[slot],selection=publishers,now=now)),expected),"NR02_EXTERNAL_CONTEXT")
        require(evidence["controller_id"]==selected["controller_id"] and evidence["channel_binding_sha256"]==selected["channel_binding_sha256"]
                and evidence["boot_id"]==self.context.appointment["clock_domain"]["boot_id"]==self.context.controller["boot_id"],"NR02_CONTROLLER_CHANNEL")
        require(same(evidence["method_decision"]["object_ref"],selected["method_decision"]),"NR03_DECISION_REFERENCE")
        decision=graph.authenticated(evidence["method_decision"],"METHOD_DECISION","method","ConsumerDecision",now,purpose="policy-inheritance-method-decision-v3")
        require(decision["status"]=="ACCEPTED_NARROW_METHOD" and decision["failure_code"] is None and decision["retained_record_count"]==19
                and decision["accepted_claims"]==validation.ACCEPTED_CLAIMS and decision["unsupported_routes"]==validation.UNSUPPORTED_ROUTES
                and decision["completion_scoring_publication_authority"] is False,"NR03_NARROW_DECISION")
        interval=method.decode("AuthenticatedInterval",graph.raw(decision["authenticated_interval_ref"],now)).payload()
        require(same(interval["binding"],decision["binding"]) and common.utc(now["utc"])<common.utc(interval["expires_at_utc"]),"NR03_INTERVAL")
        require(same(evidence["method_exposure"],selected["method_exposure"]),"NR04_EXPOSURE_REFERENCE")
        exposure=method.decode("ExposedOutput",graph.raw(evidence["method_exposure"],now)).payload()
        require(exposure["kind"]=="METHOD_DECISION" and same(exposure["body_ref"],evidence["method_decision"]["object_ref"])
                and same(exposure["attestation_ref"],evidence["method_decision"]["envelope_ref"]),"NR04_EXPOSURE_BINDING")
        checkpoint=graph.authenticated({"object_ref":exposure["checkpoint_ref"],"envelope_ref":exposure["checkpoint_attestation_ref"]},
            "CHECKPOINT_CERTIFICATE","method","ConsumerCheckpoint",now,purpose="policy-inheritance-checkpoint-v3")
        require(checkpoint["generation"]==evidence["decision_generation"]==selected["expected_decision_generation"]==22
                and exposure["checkpoint_ref"]["sha256"]==evidence["decision_head_sha256"]==selected["expected_decision_head_sha256"]
                and checkpoint["transition_kind"]=="DECISION_EXPOSURE" and checkpoint["event_sequence"]==19
                and checkpoint["event_head_sha256"]==decision["sealed_head_sha256"] and same(checkpoint["original_setup_key"],selected["setup_original_key"])
                and same(checkpoint["output"],{"kind":"METHOD_DECISION","body_ref":exposure["body_ref"],"attestation_ref":exposure["attestation_ref"]}),"NR04_CHECKPOINT")
        events,stage_inputs,payloads=graph.sealed(decision,exposure,now)
        accepted={event["record_id"]:(pair,event) for pair,event in events}
        setup={}
        for field,kind in (("runner_install","RUNNER_INSTALL"),("model_install","MODEL_INSTALL"),("model_post_exec","MODEL_POST_EXEC"),("final_peer_bound","FINAL_PEER_BOUND"),("policy_argument","POLICY_ARGUMENT")):
            pair=evidence["setup_records"][field]
            matches=[event for retained,event in events if same(pair,retained) and event["kind"]==kind]
            require(len(matches)==1,"NR04_SETUP_MEMBERSHIP"); setup[field]=matches[0]
        require(evidence["role_setup_sha256"]==common.digest(release.validate("RoleSetupRecords",evidence["setup_records"]).raw),"NR04_SETUP_HASH")
        runner=method.validate("InstallationPayload",payloads[setup["runner_install"]["record_id"]]).payload()
        model_install=method.validate("InstallationPayload",payloads[setup["model_install"]["record_id"]]).payload()
        post=method.validate("PostExecPayload",payloads[setup["model_post_exec"]["record_id"]]).payload()
        peer=method.validate("FinalPeerPayload",payloads[setup["final_peer_bound"]["record_id"]]).payload()
        require(post["wrapper_installation_record_id"]==setup["model_install"]["record_id"] and peer["model_post_exec_record_id"]==setup["model_post_exec"]["record_id"]
                and same(peer["actual_peer_identity"],runner["process_identity"]),"NR06_ACCEPTED_LINEAGE")
        require(_subject_identity(post["actual_server_identity"],model_install["process_identity"])
                and model_install["parent_installation_record_id"]==setup["runner_install"]["record_id"]
                and all(self.context.parents["model_service"][k]==runner["process_identity"][k] for k in ("boot_id","pid","start_ticks","uid","gid"))
                and all(self.context.parents["decision_runner"][k]==self.context.controller[k] for k in ("boot_id","pid","start_ticks","uid","gid")),"NR06_EXEC_PARENT_LINEAGE")
        current=CurrentReadbacks(graph=graph,evidence=evidence,decision=decision,witness_id=witness["principal_id"],now=now)
        expected_processes={"controller":self.context.controller,"decision_runner":runner["process_identity"],"model_service":post["actual_server_identity"]}
        reconstructed_roles={}
        for role,process in expected_processes.items():
            old_boundaries=[op["data"] for _,batches,_ in stage_inputs.values() for batch in batches for op in batch["operations"]
                if op["kind"]=="PROCESS_BOUNDARY" and _subject_identity(op["data"]["subject"],process)]
            require(old_boundaries,"NR06_ACCEPTED_PROCESS_BOUNDARY_UNAVAILABLE")
            reconstructed_roles[role]=current.process(evidence["roles"][role],process,self.context.parents[role],old_boundaries)
        channel=current.channel(evidence["channel"],runner["process_identity"],self.context.controller,peer,accepted,payloads,stage_inputs)
        post_selection=capture.validate("PostExecSelection",stage_inputs[setup["model_post_exec"]["record_id"]][2]["values"]["post_exec"]).payload()
        listener=current.listener(evidence["model_listener"],post["actual_server_identity"],post_selection["listener"])
        observed=_latest([r["observed"] for r in reconstructed_roles.values()]+[channel["observed"],listener["observed"]])
        require(same(observed,evidence["observed"]) and evidence["observed_at_utc"]==observed["utc"]
                and evidence["not_before_utc"]==observed["utc"] and same(evidence["issued"],self.context.issued)
                and _ordered(observed,self.context.issued) and _ordered(self.context.issued,now),"NR09_OBSERVATION_ORDER")
        expiry=self.context.requested_expiry
        paired_caps=[decision["expires"],self.context.budget["deadline"],self.context.original_model_deadline,self.context.original_global_deadline,*graph.caps]
        require(all(_ordered(expiry,cap) for cap in paired_caps) and common.utc(expiry["utc"])<=min(common.utc(interval["expires_at_utc"]),
                common.utc(graph.interval["expires_at_utc"]),common.utc(publisher["expires_at_utc"]),common.utc(publishers["expires_at_utc"])),"NR09_EXPIRY_CAP")
        require(same(expiry,evidence["expires"]) and evidence["expires_at_utc"]==expiry["utc"]
                and _ordered(observed,now) and common.utc(now["utc"])<common.utc(expiry["utc"]) and now["boottime_ns"]<expiry["boottime_ns"],"NR09_CURRENT_VALIDITY")
        current.complete()
        rebuilt={"format":"forex.narrow-role-release-evidence/1","binding":selected["binding"],"evidence_id":self.context.evidence_id,
            "method_binding":self.context.budget["binding"],"observer_id":selected["observer_id"],"observer_binding":uses["trusted_observer_binding_sha256"],
            "controller_id":selected["controller_id"],"channel_id":channel["channel_id"],"channel_binding_sha256":selected["channel_binding_sha256"],
            "boot_id":self.context.appointment["clock_domain"]["boot_id"],"setup_budget_sha256":selected["setup_budget_sha256"],
            "method_decision":{"object_ref":exposure["body_ref"],"envelope_ref":exposure["attestation_ref"]},"method_exposure":selected["method_exposure"],
            "decision_generation":22,"decision_head_sha256":selected["expected_decision_head_sha256"],"setup_records":evidence["setup_records"],
            "role_setup_sha256":common.digest(release.validate("RoleSetupRecords",evidence["setup_records"]).raw),"roles":reconstructed_roles,
            "channel":channel,"model_listener":listener,"observed":observed,"observed_at_utc":observed["utc"],"issued":self.context.issued,
            "not_before_utc":observed["utc"],"expires":expiry,"expires_at_utc":expiry["utc"],"original_clock_binding":uses["original_clock_and_budget_binding_sha256"],
            "accepted_claims":list(validation.ACCEPTED_CLAIMS),"non_forwarding_status":"ASSUMPTION_BOUND_NON_FORWARDING", "unsupported_routes":list(validation.UNSUPPORTED_ROUTES),
            "every_task_post_exec_probes_claimed":False,"broad_role_read_denial_claimed":False,"completion_scoring_publication_authority":False,
            "supporting_objects":current.exact_supporting_objects()}
        require(same(release.validate("NarrowRoleReleaseEvidence1",rebuilt).payload(),evidence),"NR10_RECONSTRUCTION")
        now=graph.current(now)
        self.authority.current(publishers,now)
        require(common.utc(now["utc"])<common.utc(expiry["utc"]) and now["boottime_ns"]<expiry["boottime_ns"],"NR11_FINAL_EXPIRY")
        return rebuilt


class CurrentReadbacks:
    def __init__(self, *, graph, evidence, decision, witness_id, now):
        self.graph,self.evidence,self.decision,self.witness,self.now=graph,evidence,decision,witness_id,now
        self.support={}; self.used=set(); self.batches={}; self.operations={}; self.batch_pairs={}; self.process_contexts={}
        allowed={"RAW_BLOB_MANIFEST","PROC_IDENTITY","NAMESPACE_INVENTORY","MOUNT_INVENTORY","DESCRIPTOR_INVENTORY","LISTENER_IDENTITY"}
        for pair in evidence["supporting_objects"]:
            ref=pair["object_ref"]
            require(ref["artifact_kind"] in allowed and ref["sha256"] not in self.support,"NR05_SUPPORT_SET")
            name="RawBlobManifest" if ref["artifact_kind"]=="RAW_BLOB_MANIFEST" else None
            value=graph.authenticated(pair,ref["artifact_kind"],"capture" if name=="RawBlobManifest" else "method",name,now)
            self.support[ref["sha256"]]=(pair,value)

    def _object(self, reference, kind):
        require(reference["artifact_kind"]==kind and reference["sha256"] in self.support,"NR05_SUPPORT_UNAVAILABLE")
        pair,value=self.support[reference["sha256"]]
        require(same(reference,pair["object_ref"]),"NR05_SUPPORT_REFERENCE")
        self.used.add(reference["sha256"])
        return value

    def _operation(self, use, kind, identity):
        require(use["operation_kind"]==kind,"NR05_OPERATION_KIND")
        pair=use["capture"]
        batch=self.graph.authenticated(pair,"TRUSTED_CAPTURE_BATCH","capture","CaptureBatch",self.now)
        require(batch["reporting_origin"]=="CONTROLLER" and batch["evidence_class"]=="CONTROLLER_OS_READBACK"
                and batch["producer_id"]==self.witness and same(batch["binding"],self.evidence["method_binding"])
                and batch["budget_sha256"]==self.evidence["setup_budget_sha256"] and _subject_identity(batch["subject"],identity),"NR05_CAPTURE_PROVENANCE")
        matches=[o for o in batch["operations"] if o["operation_index"]==use["operation_index"]]
        require(len(matches)==1 and matches[0]["kind"]==kind,"NR05_EXPLICIT_OPERATION_INDEX")
        op=matches[0]
        require(same(op["data"]["subject"],batch["subject"]),"NR05_TARGET_SUBJECT")
        require(_ordered(self.decision["decided"],batch["started"]) and _ordered(batch["started"],op["started"])
                and _ordered(op["started"],op["finished"]) and _ordered(op["finished"],batch["finished"])
                and _ordered(batch["finished"],self.evidence["observed"]),"NR09_CURRENT_CAPTURE_INTERVAL")
        key=pair["object_ref"]["sha256"]
        self.batches[key]=batch
        self.batch_pairs[key]=pair
        self.operations.setdefault(key,set()).add(use["operation_index"])
        return op

    def _captured_reference(self, reference, kind, identity, interval):
        """Nested operation bytes are accepted only as members of a current batch.

        CANONICAL_PAYLOAD is the existing capture sink's content record. It is
        never cast to a normalized identity or granted stand-alone authority.
        """
        require(reference["artifact_kind"]=="CANONICAL_PAYLOAD","NR05_NESTED_OPERATION_KIND")
        raw=self.graph.raw(reference,self.now)
        value=capture.decode("CaptureOperation",raw).payload()
        matches=[(key,op) for key,batch in self.batches.items() for op in batch["operations"]
                 if common.canonical_bytes(op)==raw]
        require(len(matches)==1 and value["kind"]==kind,"NR05_NESTED_OPERATION_MEMBERSHIP")
        key,op=matches[0]
        require(_subject_identity(op["data"]["subject"],identity)
                and _ordered(interval[0],op["started"]) and _ordered(op["finished"],interval[1]),"NR05_NESTED_OPERATION_TARGET")
        self.operations.setdefault(key,set()).add(op["operation_index"])
        return key,op

    def _boundary_reference(self, reference, identity, interval):
        if reference["artifact_kind"]=="PROC_IDENTITY":
            normalized=method.validate("ProcessIdentity",self._object(reference,"PROC_IDENTITY")).payload()
            require(same(normalized,identity),"NR08_PROCESS_SNAPSHOT")
            return normalized
        key,op=self._captured_reference(reference,"PROCESS_BOUNDARY",identity,interval)
        context=self.process_contexts.get((identity["boot_id"],identity["pid"],identity["start_ticks"]))
        require(context is not None,"NR06_CURRENT_ROLE_CONTEXT")
        role,parent,accepted=context
        submitted={"role":role,"observed":op["finished"],"process_boundary":{
            "capture":self.batch_pairs[key],"operation_index":op["operation_index"],"operation_kind":"PROCESS_BOUNDARY"}}
        return self.process(submitted,identity,parent,accepted)["process"]

    def _manifest(self, reference, selector, subject, interval):
        if reference["artifact_kind"]=="RAW_BLOB_MANIFEST":
            values=[self._object(reference,"RAW_BLOB_MANIFEST")]
        else:
            require(reference["artifact_kind"]=="NATIVE_CAPTURE_BYTES","NR05_NATIVE_KIND")
            matches=[(key,pair,value) for key,(pair,value) in self.support.items()
                     if pair["object_ref"]["artifact_kind"]=="RAW_BLOB_MANIFEST" and same(value["blob_ref"],reference)
                     and value["source_selector"]==selector and same(value["subject"],subject)
                     and _ordered(interval[0],value["started"]) and _ordered(value["finished"],interval[1])]
            require(matches,"NR05_NATIVE_MANIFEST")
            values=[]
            for key,_,value in matches:
                self.used.add(key); values.append(value)
        return values

    def _native(self, reference, selector, subject, interval):
        values=self._manifest(reference,selector,subject,interval)
        raws=[]
        for value in values:
            require(value["source_selector"]==selector and same(value["subject"],subject) and value["producer_id"]==self.witness
                    and value["origin"]=="CONTROLLER" and same(value["binding"],self.evidence["method_binding"])
                    and value["budget_sha256"]==self.evidence["setup_budget_sha256"]
                    and _ordered(interval[0],value["started"]) and _ordered(value["finished"],interval[1]),"NR05_NATIVE_PROVENANCE")
            raw=b"" if value["blob_ref"] is None else self.graph.raw(value["blob_ref"],self.now)
            require(len(raw)==value["raw_bytes"] and common.digest(raw)==value["raw_sha256"],"NR05_NATIVE_BYTES")
            matches=[(key,op) for key,batch in self.batches.items() for op in batch["operations"]
                if op["kind"]=="PROC_READ" and same(op["data"]["raw_ref"],value["blob_ref"])
                and op["data"]["selector"]==selector and same(op["data"]["subject"],subject)
                and same(op["started"],value["started"]) and same(op["finished"],value["finished"])]
            require(len(matches)==1,"NR05_NATIVE_OPERATION_MEMBERSHIP")
            key,operation=matches[0]
            data=capture.validate("ProcRead",operation["data"]).payload()
            require(data["errno"]==0 and data["return_value"]==len(raw),"NR05_NATIVE_OPERATION")
            self.operations.setdefault(key,set()).add(operation["operation_index"])
            raws.append(raw)
        require(all(raw==raws[0] for raw in raws),"NR05_NATIVE_CONFLICT")
        raw=raws[0]
        return raw

    def _old_native(self, reference):
        manifests=self.graph.native_manifests
        if reference["artifact_kind"]=="RAW_BLOB_MANIFEST":
            require(reference["sha256"] in manifests,"NR06_ACCEPTED_NATIVE_MANIFEST")
            item=manifests[reference["sha256"]]
        else:
            found=[v for v in manifests.values() if same(v["blob_ref"],reference)]
            require(found,"NR06_ACCEPTED_NATIVE_MANIFEST"); item=found[0]
            require(all(v["raw_bytes"]==item["raw_bytes"] and v["raw_sha256"]==item["raw_sha256"] for v in found),"NR06_ACCEPTED_NATIVE_CONFLICT")
        raw=b"" if item["blob_ref"] is None else self.graph.raw(item["blob_ref"],self.now)
        require(common.digest(raw)==item["raw_sha256"] and len(raw)==item["raw_bytes"],"NR06_ACCEPTED_NATIVE_PIN")
        return raw

    def process(self, submitted, expected, expected_parent, accepted_boundaries):
        self.process_contexts[(expected["boot_id"],expected["pid"],expected["start_ticks"])]=(submitted["role"],expected_parent,accepted_boundaries)
        op=self._operation(submitted["process_boundary"],"PROCESS_BOUNDARY",expected)
        data=capture.validate("ProcessBoundary",op["data"]).payload(); interval=(op["started"],op["finished"])
        before=_stat(self._native(data["before_stat_ref"],"STAT",data["subject"],interval))
        after=_stat(self._native(data["after_stat_ref"],"STAT",data["subject"],interval))
        status=_status(self._native(data["status_ref"],"STATUS",data["subject"],interval))
        require(before==after and all(before[k]==expected[k] for k in before)
                and all(status[k]==expected[k] for k in ("pid","parent_pid","uid","gid")),"NR06_CURRENT_PROCESS")
        tids=[]
        for ref in data["task_stat_refs"]:
            task=_stat(self._native(ref,"TASK_STAT",data["subject"],interval))
            require(task["start_ticks"]>0,"NR06_TASK_START"); tids.append(task["pid"])
        require(len(tids)==len(set(tids))==status["threads"] and expected["pid"] in tids,"NR06_TASK_INVENTORY")
        parent=data["parent_subject"]
        require(parent["pid"]==expected["parent_pid"] and all(parent[k]==expected_parent[k] for k in ("boot_id","pid","start_ticks","uid","gid")),"NR06_PARENT_IDENTITY")
        parent_samples=[]; parent_intervals=[]
        for pair,value in self.support.values():
            if (pair["object_ref"]["artifact_kind"]=="RAW_BLOB_MANIFEST" and value["source_selector"]=="STAT" and same(value["subject"],parent)
                    and _ordered(interval[0],value["started"]) and _ordered(value["finished"],interval[1])):
                parent_samples.append(_stat(self._native(pair["object_ref"],"STAT",parent,interval)))
                parent_intervals.append((value["started"],value["finished"]))
            if (pair["object_ref"]["artifact_kind"]=="RAW_BLOB_MANIFEST" and value["source_selector"]=="STATUS" and same(value["subject"],parent)
                    and _ordered(interval[0],value["started"]) and _ordered(value["finished"],interval[1])):
                parent_status=_status(self._native(pair["object_ref"],"STATUS",parent,interval))
                require(all(parent_status[k]==parent[k] for k in ("pid","parent_pid","uid","gid")),"NR06_PARENT_STATUS")
        parent_intervals.sort(key=lambda item:item[0]["boottime_ns"])
        require(len(parent_samples)>=2 and len({common.canonical_bytes(list(x)) for x in parent_intervals})==len(parent_samples)
                and all(_ordered(a[1],b[0]) for a,b in zip(parent_intervals,parent_intervals[1:]))
                and all(s["pid"]==parent["pid"] and s["parent_pid"]==parent["parent_pid"] and s["start_ticks"]==parent["start_ticks"] for s in parent_samples),"NR06_PARENT_RAW_SAMPLES")
        namespace_values=[]
        for item in data["namespace_reads"]:
            raw=self._native(item["raw_ref"],"NAMESPACE_LINK",data["subject"],interval).decode("ascii").strip()
            require(raw==item["link_text"]==item["namespace"]+":["+str(item["inode"])+"]","NR06_NAMESPACE_LINK")
            namespace_values.append((item["namespace"],item["device"],item["inode"]))
        require(len(namespace_values)==len({v[0] for v in namespace_values}),"NR06_NAMESPACE_DUPLICATE")
        require({v[0] for v in namespace_values}=={"mnt","pid","net","time","user","ipc","uts","cgroup"},"NR06_COMPLETE_NAMESPACE_SET")
        old_values=[sorted((item["namespace"],item["device"],item["inode"]) for item in old["namespace_reads"]) for old in accepted_boundaries]
        require(all(sorted(namespace_values)==values for values in old_values),"NR06_NAMESPACE_CHANGED")
        domain=self.graph.context.appointment["clock_domain"]
        require(any(name=="time" and inode==domain["time_namespace_inode"] for name,_,inode in namespace_values),"NR09_CLOCK_DOMAIN")
        mount=self._native(data["mountinfo_ref"],"MOUNTINFO",data["subject"],interval)
        require(all(self._old_native(old["mountinfo_ref"])==mount for old in accepted_boundaries),"NR06_MOUNT_CHANGED")
        exe=self._native(data["exe_link_ref"],"EXE_LINK",data["subject"],interval).decode("utf-8").strip()
        require(exe==expected["exe_asset"]["selected_path"] and data["exe_stat"]["device"]==expected["exe_device"]==expected["exe_asset"]["device"]
                and data["exe_stat"]["inode"]==expected["exe_inode"]==expected["exe_asset"]["inode"]
                and data["exe_stat"]["bytes"]==expected["exe_asset"]["bytes"],"NR06_EXECUTABLE_BINDING")
        # The accepted immutable executable and inventory references are reused
        # only after current raw identity/mount/namespace equality is established.
        namespaces=self._object(expected["namespace_inventory_ref"],"NAMESPACE_INVENTORY")
        require(same(namespaces,[{k:item[k] for k in ("namespace","link_text","device","inode")} for item in data["namespace_reads"]]),"NR06_NAMESPACE_NORMALIZATION")
        mounts=self._object(expected["mount_inventory_ref"],"MOUNT_INVENTORY")
        require(same(mounts,{"mountinfo_utf8":mount.decode("utf-8","strict")}),"NR06_MOUNT_NORMALIZATION")
        rebuilt={"boot_id":data["subject"]["boot_id"],"pid":before["pid"],"start_ticks":before["start_ticks"],"parent_pid":before["parent_pid"],
            "uid":status["uid"],"gid":status["gid"],"exe_device":data["exe_stat"]["device"],"exe_inode":data["exe_stat"]["inode"],
            "namespace_inventory_ref":expected["namespace_inventory_ref"],"mount_inventory_ref":expected["mount_inventory_ref"],"exe_asset":expected["exe_asset"]}
        require(same(rebuilt,expected) and same(submitted["observed"],op["finished"]),"NR06_RECONSTRUCTED_PROCESS")
        return {"role":submitted["role"],"process":rebuilt,"parent":{k:parent[k] for k in ("boot_id","pid","start_ticks","uid","gid")},
                "process_boundary":submitted["process_boundary"],"observed":op["finished"]}

    def _fd(self, use, expected, process, selector):
        op=self._operation(use,"PROC_READ",process)
        value=capture.validate("ProcRead",op["data"]).payload()
        require(value["selector"]==selector and value["selector_argument"]==str(expected["fd"]) and value["errno"]==0,"NR07_FD_READ_TARGET")
        raw=self._native(value["raw_ref"],selector,value["subject"],(op["started"],op["finished"]))
        require(value["return_value"]==len(raw),"NR07_FD_READ_RESULT")
        if selector=="FD_LINK": require(raw.decode("ascii").strip()=="socket:["+str(expected["inode"])+"]","NR07_SOCKET_OBJECT")
        else:
            lines={}
            for line in raw.decode("ascii").splitlines():
                key,sep,text=line.partition(":")
                require(sep and key not in lines,"NR07_FDINFO_FORMAT"); lines[key]=text.strip()
            require("flags" in lines and "ino" in lines,"NR07_FDINFO_FIELDS")
            flags=int(lines["flags"],8)
            require(int(lines["ino"])==expected["inode"] and (flags & ~0o2000000)==(expected["access_flags"] & ~0o2000000)
                    and bool(flags & 0o2000000)==expected["close_on_exec"],"NR07_FDINFO_OBJECT")
        return op["finished"]

    def channel(self, submitted, runner, controller, peer, accepted, payloads, stage_inputs):
        created_id=peer["channel_created_record_id"]
        require(created_id in accepted and accepted[created_id][1]["kind"]=="FINAL_CHANNEL_CREATED","NR07_CREATED_RECORD")
        payload=method.validate("FinalChannelCreatedPayload",payloads[created_id]).payload()
        inputs,batches,selected=stage_inputs[created_id]
        selected_channel=capture.validate("ChannelSelection",selected["values"]["channel"]).payload()
        creates=[op["data"] for batch in batches for op in batch["operations"] if op["kind"]=="ENDPOINT_CREATE"]
        require(len(creates)==1,"NR07_ENDPOINT_CREATION")
        creation=capture.validate("EndpointCreate",creates[0]).payload()
        require(payload["channel_id"]==peer["channel_id"]==selected_channel["channel_id"]==creation["channel_id"]
                and payload["key_generation_operation_id"]==selected_channel["key_operation_id"]==creation["key_operation_id"]
                and _subject_identity(creation["owner"],controller) and same(selected_channel["owner"],controller)
                and creation["random_source_call_succeeded"] is True and creation["key_material_recorded"] is False,"NR07_ACCEPTED_CHANNEL")
        endpoints=creation["endpoints"]
        require(len(endpoints)==2,"NR07_ENDPOINT_PAIR")
        by_target={d["selected_target_id"]:d for d in endpoints}
        require(set(by_target)==set(selected_channel["endpoint_ids"]),"NR07_SELECTED_ENDPOINTS")
        controller_endpoint=by_target[selected_channel["endpoint_ids"][0]]
        runner_endpoint=dict(by_target[selected_channel["endpoint_ids"][1]])
        spawns=[self.graph.authenticated(values[0]["spawn_selection"],"TRUSTED_SPAWN_SELECTION","capture","SpawnSelection",self.now)
                for values in stage_inputs.values() if values[0]["event_kind"]=="RUNNER_INSTALL" and values[0]["spawn_selection"] is not None]
        require(len(spawns)==1,"NR07_RUNNER_SPAWN")
        mappings=[m for m in spawns[0]["descriptor_bindings"] if m["object_identity"]["inode"]==runner_endpoint["inode"]
                  and m["object_identity"]["device"]==runner_endpoint["device"]]
        require(len(mappings)==1,"NR07_RUNNER_DESCRIPTOR_MAP")
        installed=[method.validate("InstallationPayload",payloads[rid]).payload() for rid,(_,event) in accepted.items() if event["kind"]=="RUNNER_INSTALL"]
        require(len(installed)==1,"NR07_INSTALLED_RUNNER")
        descriptors=[d for d in installed[0]["initial_descriptors"] if d["fd"]==mappings[0]["child_fd"]
                     and d["device"]==runner_endpoint["device"] and d["inode"]==runner_endpoint["inode"]]
        require(len(descriptors)==1 and descriptors[0]["selected_target_id"]==runner_endpoint["selected_target_id"],"NR07_INSTALLED_ENDPOINT")
        runner_endpoint=descriptors[0]
        observed=_latest([self._fd(submitted["controller_fd_link"],controller_endpoint,controller,"FD_LINK"),
            self._fd(submitted["controller_fdinfo"],controller_endpoint,controller,"FDINFO"),
            self._fd(submitted["runner_fd_link"],runner_endpoint,runner,"FD_LINK"),self._fd(submitted["runner_fdinfo"],runner_endpoint,runner,"FDINFO")])
        credential=dict(zip(("pid","uid","gid"),peer["actual_ucred"],strict=True))
        require(credential=={k:runner[k] for k in ("pid","uid","gid")},"NR07_PEER_CREDENTIALS")
        peer_ids=[rid for rid,(_,event) in accepted.items() if event["kind"]=="FINAL_PEER_BOUND" and same(payloads[rid],peer)]
        require(len(peer_ids)==1,"NR07_PEER_RECORD")
        return {"channel_id":payload["channel_id"],"channel_binding_sha256":self.evidence["channel_binding_sha256"],
            "key_operation_id":creation["key_operation_id"],"created_record_id":created_id,"peer_record_id":peer_ids[0],
            "controller_endpoint":controller_endpoint,"runner_endpoint":runner_endpoint,
            **{k:submitted[k] for k in ("controller_fd_link","controller_fdinfo","runner_fd_link","runner_fdinfo")},
            "accepted_first_receive":peer["first_packet_ref"],"accepted_ucred":credential,"observed":observed}

    def listener(self, submitted, model, selected_listener):
        op=self._operation(submitted["listener"],"LISTENER_READ",model)
        data=capture.validate("ListenerRead",op["data"]).payload()
        self._boundary_reference(data["process_snapshot_ref"],model,(op["started"],op["finished"]))
        require(same(selected_listener["process"],model) and data["address"]==selected_listener["address"]=="127.0.0.1" and data["port"]==selected_listener["port"]
                and data["socket_descriptor"]["inode"]==selected_listener["socket_inode"],"NR08_SELECTED_LISTENER")
        table=self._native(data["tcp_table_ref"],"NET_TCP",data["subject"],(op["started"],op["finished"])).decode("ascii")
        rows=[]
        for line in table.splitlines()[1:]:
            columns=line.split()
            require(len(columns)>=10,"NR08_TCP_TABLE_FORMAT")
            if columns[1]=="0100007F:"+format(data["port"],"04X") and columns[3]=="0A" and int(columns[9])==data["socket_descriptor"]["inode"]:
                rows.append(columns)
        require(len(rows)==1 and int(rows[0][7])==model["uid"],"NR08_ACTUAL_LISTENER")
        if data["fd_inventory_ref"]["artifact_kind"]=="CANONICAL_PAYLOAD":
            _,inventory_op=self._captured_reference(data["fd_inventory_ref"],"FD_INVENTORY",model,(op["started"],op["finished"]))
            inventory=capture.validate("FdInventory",inventory_op["data"]).payload()
        else:
            inventory=capture.validate("FdInventory",self._object(data["fd_inventory_ref"],"DESCRIPTOR_INVENTORY")).payload()
        require(_subject_identity(inventory["subject"],model) and inventory["enumeration_complete"] is True,"NR08_OWNER_INVENTORY")
        require(sorted(inventory["enumerated_fds"])==sorted(e["descriptor"]["fd"] for e in inventory["entries"])
                and len(inventory["entries"])==len(set(inventory["enumerated_fds"])),"NR08_COMPLETE_FD_SET")
        owners=[entry for entry in inventory["entries"] if same(entry["descriptor"],data["socket_descriptor"])]
        require(len(owners)==1 and owners[0]["fstat_return"]==0 and owners[0]["fstat_errno"]==0
                and owners[0]["stat"]["device"]==data["socket_descriptor"]["device"]
                and owners[0]["stat"]["inode"]==data["socket_descriptor"]["inode"],"NR08_LISTENER_OWNERSHIP")
        for entry in inventory["entries"]:
            link=self._native(entry["link_ref"],"FD_LINK",data["subject"],(op["started"],op["finished"]))
            info=self._native(entry["fdinfo_ref"],"FDINFO",data["subject"],(op["started"],op["finished"]))
            descriptor=entry["descriptor"]
            require(entry["fstat_return"]==0 and entry["fstat_errno"]==0 and entry["stat"]["device"]==descriptor["device"]
                    and entry["stat"]["inode"]==descriptor["inode"],"NR08_DESCRIPTOR_STAT")
            if descriptor["object_type"]=="SOCKET":
                require(link.decode("ascii").strip()=="socket:["+str(descriptor["inode"])+"]","NR08_SOCKET_LINK")
            lines={}
            for line in info.decode("ascii").splitlines():
                name,separator,value=line.partition(":")
                require(separator and name not in lines,"NR08_FDINFO_FORMAT");lines[name]=value.strip()
            require("flags" in lines and "ino" in lines,"NR08_FDINFO_FIELDS")
            flags=int(lines["flags"],8)
            require(int(lines["ino"])==descriptor["inode"] and flags & ~0o2000000==descriptor["access_flags"] & ~0o2000000
                    and bool(flags & 0o2000000)==descriptor["close_on_exec"],"NR08_DESCRIPTOR_FLAGS")
        for name in ("before_process_ref","after_process_ref"):
            self._boundary_reference(inventory[name],model,(op["started"],op["finished"]))
        return {"listener":submitted["listener"],"observed":op["finished"]}

    def complete(self):
        require(self.used==set(self.support),"NR05_EXTRA_OR_UNRESOLVED_SUPPORT")
        for key,batch in self.batches.items():
            require(self.operations[key]=={o["operation_index"] for o in batch["operations"]},"NR05_UNRESOLVED_CURRENT_OPERATION")

    def exact_supporting_objects(self):
        # Preserve only the authenticated, fully consumed declared ordering.
        return [pair for pair in self.evidence["supporting_objects"] if pair["object_ref"]["sha256"] in self.used]


@dataclass(frozen=True)
class GateCheck:
    """Independently appointed semantic implementation, never payload-selected.

    The sixteen non-role payload schemas are external accepted successor inputs.
    No generic PASS/verified/hash-only interpretation is provided for them.
    The authority guard must bind this component and its actual implementation.
    """
    publisher_id: str
    schema_sha256: str
    component_sha256: str
    expires: dict
    verify: object


class IssuanceJournal:
    """Existing protected issuer root; exclusive creation is a separate action.

    One signed receipt/envelope pair per release identity. An incomplete append
    remains an uncertainty barrier; it is never truncated, repaired or reminted.
    External restore authority must protect this journal against rollback.
    """
    def __init__(self, *, files, authority, root_id):
        self.files,self.authority,self.root_id=files,authority,root_id

    def _root(self, publishers):
        roots=[r for r in publishers["roots"] if r["root_id"]==self.root_id]
        require(len(roots)==1 and self.authority.local_principal_id in roots[0]["writer_principal_ids"],"ISSUER_JOURNAL_GRANT")
        return roots[0]

    def initialize_exclusive(self, *, publishers, now):
        """Never invoked by constructors, issue, publish or recovery."""
        with self.files.root(self._root(publishers),publishers,now) as directory:
            fd=os.open("issuance.v3.log",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
            try: os.fsync(fd)
            finally: os.close(fd)
            os.fsync(directory)

    @contextlib.contextmanager
    def locked(self, publishers, now):
        import fcntl
        root=self._root(publishers)
        with self.files.root(root,publishers,now) as directory:
            fd=os.open("issuance.v3.log",os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
            try:
                info=os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==root["expected_uid"]
                        and info.st_gid==root["expected_gid"] and stat.S_IMODE(info.st_mode)==0o600,"ISSUANCE_METADATA")
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                yield fd
                named=os.stat("issuance.v3.log",dir_fd=directory,follow_symlinks=False)
                current=os.fstat(fd)
                require((named.st_dev,named.st_ino,named.st_uid,named.st_gid,named.st_mode)==
                        (current.st_dev,current.st_ino,current.st_uid,current.st_gid,current.st_mode)
                        and named.st_nlink==1 and stat.S_ISREG(named.st_mode),"ISSUANCE_PATH_REPLACED")
                self.authority.current(publishers,now)
            finally: os.close(fd)

    def rows(self, fd, publishers, now):
        os.lseek(fd,0,os.SEEK_SET); chunks=[]; size=0
        while True:
            block=os.read(fd,65536)
            if not block: break
            size+=len(block); require(size<=common.MAX_GRAPH,"ISSUANCE_JOURNAL_BOUND"); chunks.append(block)
        raw=b"".join(chunks)
        require(not raw or raw.endswith(b"\n"),"UNCERTAIN_ISSUANCE_TAIL")
        rows=[]; seen=set()
        for line in raw.splitlines():
            row=common.decode_canonical(line)
            require(set(row)=={"receipt","envelope"},"ISSUANCE_ROW")
            receipt=protected.validate("ReleaseReceipt3",row["receipt"]).payload()
            envelope=protected.validate("ProtectedRecordEnvelope",row["envelope"]).payload()
            ref=envelope["body"]["record_ref"]
            validation.verify_reference_bytes(ref,protected.validate("ReleaseReceipt3",receipt).raw,protected_reference=True)
            require(same(receipt["binding"],publishers["binding"]) and ref["record_kind"]=="RELEASE_RECEIPT"
                    and ref["purpose"]=="custody-release-receipt" and ref["publisher_id"]==receipt["issuer_id"]
                    and envelope["body"]["issued_at_utc"]==receipt["issued_at_utc"]
                    and envelope["body"]["expires_at_utc"]==receipt["expires_at_utc"],"ISSUANCE_RECORD_BINDING")
            appointed=[p for p in publishers["publishers"] if p["publisher_id"]==receipt["issuer_id"]]
            require(len(appointed)==1 and appointed[0]["role"]=="RELEASE_ISSUER"
                    and appointed[0]["signer_public_sha256"]==envelope["signer_sha256"],"ISSUANCE_SIGNER")
            self.authority.signature_check(signer_pin=envelope["signer_sha256"],message=protected.record_signing_bytes(envelope["body"]),
                                           signature=bytes.fromhex(envelope["signature_hex"]))
            key=(receipt["binding"]["run_id"],receipt["binding"]["epoch"],receipt["release_id"])
            require(key not in seen,"DUPLICATE_ISSUANCE"); seen.add(key); rows.append(row)
        self.authority.current(publishers,now)
        return rows

    def append(self, fd, row, publishers, now):
        line=common.canonical_bytes(row)+b"\n"
        os.lseek(fd,0,os.SEEK_END)
        require(os.write(fd,line)==len(line),"ISSUANCE_WRITE_UNCERTAIN")
        os.fsync(fd)
        require(same(self.rows(fd,publishers,now)[-1],row),"ISSUANCE_READBACK")


class ReleaseIssuer:
    """NR11 admission and durable exact publication. NR12 remains integration.

    Construction is inert. Operation requires an independently appointed guard,
    actual protected files/registry, signer, all gate implementations, the sole
    completion verifier and substantive narrow-role verifier. No enabled flag,
    environment variable, unsigned example or fallback can fill a dependency.
    """
    def __init__(self, *, selection_use, publishers, authority, resolver, registry,
                 files, journal, narrow_verifier, completion_verifier, gate_checks,
                 issuer_id, receipt_root_id, signer, clock, current_authority_guard,
                 original_deadline):
        self.selection_use=common.decode_canonical(common.canonical_bytes(selection_use))
        self.publishers=common.decode_canonical(common.canonical_bytes(publishers))
        self.authority,self.resolver,self.registry=authority,resolver,registry
        self.files,self.journal=files,journal
        self.narrow,self.completion=narrow_verifier,completion_verifier
        require(all(type(gate) is GateCheck for gate in gate_checks.values()),"NR11_GATE_IMPLEMENTATION_TYPE")
        self.gates={slot:GateCheck(gate.publisher_id,gate.schema_sha256,gate.component_sha256,
            common.decode_canonical(common.canonical_bytes(gate.expires)),gate.verify) for slot,gate in gate_checks.items()}
        self.issuer_id,self.receipt_root_id,self.signer=issuer_id,receipt_root_id,signer
        self.clock,self.guard=clock,current_authority_guard
        self.deadline=common.decode_canonical(common.canonical_bytes(original_deadline))

    def _now(self, now):
        now=fresh(self.clock,self.guard,now,self.deadline)
        return self.authority.current(self.publishers,now)

    def _protected(self, use, kind, purpose, permitted_use, now):
        use=protected.validate("ProtectedReferenceUse",use).payload(); ref=use["reference"]
        require(ref["record_kind"]==kind and ref["purpose"]==purpose and use["required_use"]==permitted_use,"NR11_REFERENCE_ROUTE")
        raw=self.resolver.resolve(use,selection=self.publishers,now=self._now(now))
        registration=self.registry.read_registration(use["registration_sha256"],selection=self.publishers,now=self._now(now))
        require(same(registration["record_ref"],ref),"NR11_REGISTERED_REFERENCE")
        ar=registration["attestation_ref"]
        root,_,_,current=self.authority.check_grant(ar,self.publishers,self._now(now),required_use="AUTHORITY_METADATA")
        envelope=protected.decode("ProtectedRecordEnvelope",self.files.read(ar,root,self.publishers,current)).payload()
        self.authority.attest(ref,envelope,self.publishers,current)
        return raw,common.utc(envelope["body"]["expires_at_utc"])

    def _validate(self, selected, now):
        now=self._now(now)
        selected=protected.validate("ReleaseSelection3",selected).payload()
        raw,selection_cap=self._protected(self.selection_use,"RELEASE_SELECTION","custody-release-selection","PRIVATE_RELEASE",now)
        require(same(protected.decode("ReleaseSelection3",raw).payload(),selected)
                and same(selected["binding"],self.publishers["binding"])
                and selected["publisher_selection_sha256"]==self.authority.pin
                and selected["issuer_id"]==self.issuer_id==self.selection_use["reference"]["publisher_id"],"NR11_SELECTED_ISSUER")
        require(set(self.gates)==set(SLOTS)-{ROLE_SLOT},"NR11_SEMANTIC_GATES_UNAVAILABLE")
        resolved={}; caps=[selection_cap,common.utc(selected["expires_at_utc"]),common.utc(self.publishers["expires_at_utc"])]
        uses={row["slot"]:row["evidence"] for row in selected["release_evidence"]}
        for slot in SLOTS:
            gate_raw,cap=self._protected(uses[slot],"EXTERNAL_RELEASE_EVIDENCE","release-evidence:"+slot,"PRIVATE_RELEASE",now)
            resolved[slot]=gate_raw; caps.append(cap)
            if slot!=ROLE_SLOT:
                gate=self.gates[slot]
                _,publisher,grant,_=self.authority.check_grant(uses[slot]["reference"],self.publishers,self._now(now),required_use="PRIVATE_RELEASE")
                require(publisher["publisher_id"]==gate.publisher_id and grant["payload_schema_sha256"]==gate.schema_sha256,"NR11_GATE_APPOINTMENT")
                common.require(re.fullmatch(r"[0-9a-f]{64}",gate.component_sha256) is not None,"NR11_GATE_COMPONENT_PIN")
                expiry=method.validate("Stamp",gate.expires).payload()
                require(_ordered(self.narrow.context.requested_expiry,expiry),"NR11_GATE_EXPIRY_CAP")
                caps.append(common.utc(expiry["utc"]))
        dependencies=tuple((slot,resolved[slot]) for slot in SLOTS)
        selected_raw=protected.validate("ReleaseSelection3",selected).raw
        for slot in SLOTS:
            if slot!=ROLE_SLOT:
                gate=self.gates[slot]
                call_none(gate.verify,record=resolved[slot],selection=selected_raw,dependencies=dependencies,
                          component_sha256=gate.component_sha256,now=self._now(now))
        role=release.decode("NarrowRoleReleaseEvidence1",resolved[ROLE_SLOT]).payload()
        call_none(self.narrow.verify,role,selected=selected,publishers=self.publishers,resolver=self.resolver,now=self._now(now))
        caps.append(common.utc(role["expires_at_utc"]))
        completion_raw,completion_cap=self._protected(selected["source_test_completion"],"SOURCE_TEST_COMPLETION","source-test-completion","SOURCE_COMPLETION",now)
        receipt=completion.decode("CompletionReceipt2",completion_raw).payload(); caps.append(completion_cap)
        require(same(receipt["binding"],selected["binding"])
                and receipt["original_clock_record_content_sha256"]==selected["binding"]["original_window_sha256"],"NR11_COMPLETION_BINDING")
        completion_inputs=[]
        for use,name,kind,purpose in ((receipt["selection_ref"],"CompletionSelection2","COMPLETION_SELECTION","completion-selection"),
                (receipt["original_source_test_report"],"SourceTestReport2","SOURCE_TEST_REPORT","original-source-test-report"),
                (receipt["observation_evidence"],"CompletionObservation2","SOURCE_TEST_OBSERVATION","source-test-observation")):
            body,cap=self._protected(use,kind,purpose,"SOURCE_COMPLETION",now)
            completion_inputs.append(completion.decode(name,body).payload()); caps.append(cap)
        recomputed=self.completion.verify(*completion_inputs,resolver=self.resolver,publishers=self.publishers,now=self._now(now))
        require(same(recomputed,receipt) and selected["source_test_completion"]["reference"]["publisher_id"]==receipt["observer_id"],"NR11_COMPLETE_THIRTEEN_GROUPS")
        require(uses["scope_sha256"]["reference"]["sha256"]==selected["scope_sha256"],"NR11_SCOPE_PIN")
        now=self._now(now)
        end=min(caps+[common.utc(self.deadline["utc"])])
        require(common.utc(selected["not_before_utc"])<=common.utc(now["utc"])<end
                and common.utc(selected["expires_at_utc"])<=end,"NR11_RELEASE_INTERVAL")
        return selected,role,now

    def _reference(self, receipt):
        raw=protected.validate("ReleaseReceipt3",receipt).raw; pin=common.digest(raw)
        ref={"format":"forex.protected-record-ref/1","binding":receipt["binding"],"publisher_selection_sha256":self.authority.pin,
             "root_id":self.receipt_root_id,"object_id":pin,"bytes":len(raw),"sha256":pin,"record_kind":"RELEASE_RECEIPT",
             "publisher_id":self.issuer_id,"purpose":"custody-release-receipt"}
        return protected.validate("ProtectedRecordRef",ref).payload(),raw

    def _original(self, rows, release_id):
        found=[row for row in rows if row["receipt"]["release_id"]==release_id]
        require(len(found)<=1,"DUPLICATE_ISSUANCE")
        return found[0] if found else None

    def _receipt(self, selected, issued):
        result={"format":"forex.custody-release-receipt/3","binding":selected["binding"],"release_id":selected["release_id"],
            "selection_ref":self.selection_use["reference"],"issuer_id":self.issuer_id,"controller_id":selected["controller_id"],
            "channel_binding_sha256":selected["channel_binding_sha256"],"scope_sha256":selected["scope_sha256"],
            "evidence_uses_sha256":common.digest(common.canonical_bytes(selected["release_evidence"])),
            "completion_ref":selected["source_test_completion"]["reference"],"method_decision_ref":selected["method_decision"],
            "method_exposure_ref":selected["method_exposure"],"original_setup_key":selected["setup_original_key"],
            "setup_budget_sha256":selected["setup_budget_sha256"],"method_appointment_sha256":selected["method_appointment_sha256"],
            "checkpoint_access_selection_sha256":selected["checkpoint_access_selection_sha256"],
            "expected_decision_generation":selected["expected_decision_generation"],"expected_decision_head_sha256":selected["expected_decision_head_sha256"],
            "issued_at_utc":issued,"not_before_utc":issued,"expires_at_utc":selected["expires_at_utc"]}
        return protected.validate("ReleaseReceipt3",result).payload()

    def issue(self, selection, *, now):
        selected,role,now=self._validate(selection,now)
        with self.journal.locked(self.publishers,now) as fd:
            original=self._original(self.journal.rows(fd,self.publishers,now),selected["release_id"])
            if original:
                expected=self._receipt(selected,original["receipt"]["issued_at_utc"])
                require(same(original["receipt"],expected),"RELEASE_ID_ALREADY_BOUND")
                self.authority.attest(self._reference(expected)[0],original["envelope"],self.publishers,self._now(now))
                return expected
            now=self._now(now); receipt=self._receipt(selected,now["utc"])
            ref,raw=self._reference(receipt)
            _,publisher,grant,now=self.authority.check_grant(ref,self.publishers,now,required_use="PRIVATE_RELEASE")
            require(publisher["publisher_id"]==self.authority.local_principal_id==self.issuer_id,"ISSUER_LOCAL_IDENTITY")
            self.authority.validate_payload(raw,grant)
            if self.signer is None: raise common.DependencyUnavailable("release-signer")
            body={"format":"forex.protected-record-attestation/1","record_ref":ref,
                "attestation_id":"release-"+common.digest(common.canonical_bytes([selected["binding"],selected["release_id"]])),
                "publisher_id":self.issuer_id,"purpose":"custody-release-receipt","issued_at_utc":receipt["issued_at_utc"],"expires_at_utc":receipt["expires_at_utc"]}
            signature=self.signer.sign(domain=protected.RECORD_DOMAIN,canonical_body=protected.validate("ProtectedAttestationBody",body).raw)
            require(type(signature) is bytes and len(signature)==64,"RELEASE_SIGNATURE")
            envelope={"body":body,"algorithm":"Ed25519","signer_sha256":publisher["signer_public_sha256"],"signature_hex":signature.hex()}
            self.authority.attest(ref,envelope,self.publishers,self._now(now))
            self.journal.append(fd,{"receipt":receipt,"envelope":envelope},self.publishers,self._now(now))
            # A failed postcommit check retains a spent/uncertain original row.
            # Recovery can return only those exact bytes while still valid.
            current=self._now(now)
            require(common.utc(current["utc"])<common.utc(receipt["expires_at_utc"])
                    and current["boottime_ns"]<role["expires"]["boottime_ns"],"RELEASE_EXPIRED_AFTER_COMMIT")
            return receipt

    def publish_exact(self, receipt, *, now):
        receipt=protected.validate("ReleaseReceipt3",receipt).payload()
        selected_raw=self.resolver.resolve(self.selection_use,selection=self.publishers,now=self._now(now))
        selected,role,now=self._validate(protected.decode("ReleaseSelection3",selected_raw).payload(),now)
        with self.journal.locked(self.publishers,now) as fd:
            original=self._original(self.journal.rows(fd,self.publishers,now),receipt["release_id"])
            require(original is not None and same(original["receipt"],receipt)
                    and same(receipt,self._receipt(selected,receipt["issued_at_utc"])),"EXACT_ISSUANCE_REQUIRED")
            ref,raw=self._reference(receipt); envelope=original["envelope"]
            root,_,_,now=self.authority.check_grant(ref,self.publishers,self._now(now),required_use="PRIVATE_RELEASE")
            self.authority.attest(ref,envelope,self.publishers,now)
            envelope_raw=protected.validate("ProtectedRecordEnvelope",envelope).raw; pin=common.digest(envelope_raw)
            ar={**ref,"object_id":pin,"sha256":pin,"bytes":len(envelope_raw),"record_kind":"RECORD_ATTESTATION","purpose":"record-attestation"}
            ar_root,_,_,now=self.authority.check_grant(ar,self.publishers,self._now(now),required_use="AUTHORITY_METADATA")
            self.files.retain_exact(ref,raw,root,self.publishers,now)
            self.files.retain_exact(ar,envelope_raw,ar_root,self.publishers,self._now(now))
            registered=self.registry.register_exact_record(raw,ref,envelope,selection=self.publishers,now=self._now(now))
            use={"reference":ref,"registration_sha256":common.digest(protected.validate("ProtectedRegistration",registered).raw),"required_use":"PRIVATE_RELEASE"}
            require(self.resolver.resolve(use,selection=self.publishers,now=self._now(now))==raw,"RELEASE_PUBLICATION_READBACK")
            current=self._now(now)
            require(common.utc(current["utc"])<common.utc(receipt["expires_at_utc"])
                    and current["boottime_ns"]<role["expires"]["boottime_ns"],"PUBLICATION_EXPIRED")
            return protected.validate("ProtectedReferenceUse",use).payload()
