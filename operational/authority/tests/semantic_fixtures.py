"""PUBLIC FAKE graph fixtures, never operational raw-observation provenance.

This decoder deliberately derives a fixed public synthetic graph. It tests the
consumer boundary and has no Linux measurement authority. Source tests NOT_RUN.
"""
from copy import deepcopy
from types import SimpleNamespace
from cas_forex_operational_contracts.common import canonical_bytes, digest
from cas_forex_authority.authentication import ref, ZERO
from cas_forex_authority.semantic_verifier import SemanticSelection, OperationalSemanticVerifier, _Coverage, BASELINES
from support import fixture, stamp, process, FixtureSigner


class MemoryEvidence:
    def __init__(self): self.rows = {}; self.reads = []
    def retain_exact(self, reference, raw):
        assert ref(raw, reference["artifact_kind"]) == reference
        key = canonical_bytes(reference)
        assert key not in self.rows or self.rows[key] == raw
        self.rows[key] = raw
        return dict(reference)
    def resolve(self, reference):
        self.reads.append(canonical_bytes(reference))
        return self.rows[canonical_bytes(reference)]
    def add(self, kind, value):
        raw = canonical_bytes(value); reference = ref(raw, kind); self.retain_exact(reference, raw)
        return reference


def identity(evidence, pid=10):
    return {"boot_id":"00000000-0000-4000-8000-000000000001","pid":pid,"start_ticks":pid*10,"parent_pid":1,"uid":1000,"gid":1000,
            "exe_device":1,"exe_inode":pid+100,
            "namespace_inventory_ref":evidence.add("NAMESPACE_INVENTORY",[{"namespace":"pid","inode":77}]),
            "mount_inventory_ref":evidence.add("MOUNT_INVENTORY",{"mountinfo_utf8":"public fake mount"}),
            "exe_asset":{"asset_id":"public-exe","selected_path":"/public/fixture","bytes":100,"sha256":"a"*64,"device":1,"inode":pid+100}}


def begin_graph():
    f=fixture(); evidence=MemoryEvidence(); controller=identity(evidence)
    source=evidence.add("EXECUTABLE_PIN",{"public_test_source":True})
    sources=[source]
    signer=FixtureSigner(f.keys["witness"])
    def signed(kind, body):
        reference=evidence.add(kind, body); raw=evidence.resolve(reference)
        envelope=f.auth.attest(raw,purpose="policy-inheritance-witness-v3",producer_id="witness",signer=signer,now=f.guard.check())
        envref=evidence.add("SIGNED_ENVELOPE",envelope)
        return {"object_ref":reference,"envelope_ref":envref}
    selected={"format":"forex.runtime-selected-values/1","binding":f.binding,"budget_sha256":digest(canonical_bytes(f.budget)),
              "slot_id":"s0","event_kind":"SETUP_BEGIN","subject_id":"subject","values":{"controller":controller}}
    selected_pair=signed("RUNTIME_SELECTED_VALUES",selected)
    runtime={"format":"forex.runtime-selection-binding/2","binding":f.binding,"budget_sha256":selected["budget_sha256"],
             "slot_id":"s0","subject_id":"subject","selected_source_refs":sources,"selected_decoder_sha256":"f"*64,
             "selection_ref":selected_pair["object_ref"],"selected_at":stamp()}
    runtime_pair=signed("RUNTIME_SELECTION_BINDING",runtime)
    operation={"operation_index":1,"kind":"STREAM_MARKER","started":stamp(),"finished":stamp(1),
               "data":{"marker":"SETUP_BEGIN","slot_id":"s0","sequence":1,"accepted_predecessor_refs":[],"source_argument_ref":None}}
    batch={"format":"forex.trusted-setup-capture/2","binding":f.binding,"budget_sha256":selected["budget_sha256"],
           "capture_id":"public-capture","producer_id":"witness","reporting_origin":"CONTROLLER","evidence_class":"CONTROLLER_STREAM_METADATA",
           "subject":process("CONTROLLER",10,1000),"receiver_component_sha256":None,"started":stamp(),"finished":stamp(1),
           "operations":[operation],"previous_batch_sha256":ZERO}
    batch_pair=signed("TRUSTED_CAPTURE_BATCH",batch)
    payload={"coverage_plan_sha256":digest(canonical_bytes(f.plan)),"producer_identity":controller,"budget_sha256":selected["budget_sha256"]}
    raw_values=[("NAMESPACE_INVENTORY",[{"namespace":"pid","inode":77}]),("MOUNT_INVENTORY",{"mountinfo_utf8":"public fake mount"}),
                ("PROC_IDENTITY",controller),("CANONICAL_PAYLOAD",payload)]
    actual_artifacts=tuple((evidence.add(kind,value),canonical_bytes(value)) for kind,value in raw_values)
    bindings=[]; decode_pairs=[]
    for reference,raw in actual_artifacts:
        binding={"format":"forex.runtime-decode-binding/2","binding":f.binding,"budget_sha256":selected["budget_sha256"],"event_kind":"SETUP_BEGIN",
                 "decoder_component_sha256":"f"*64,"decoder_format_sha256":"b"*64,"capture_refs":[batch_pair["object_ref"]],
                 "capture_envelope_refs":[batch_pair["envelope_ref"]],"selected_input_refs":sources,"normalized_ref":reference,
                 "normalized_artifact_kind":reference["artifact_kind"],"decoded":stamp(1)}
        bindings.append(binding);decode_pairs.append(signed("RUNTIME_DECODE_BINDING",binding))
    inputs={"format":"forex.authenticated-event-inputs/1","binding":f.binding,"budget_sha256":selected["budget_sha256"],
            "stream_id":f.appointment["stream_id"],"record_id":"public-event-1","slot_id":"s0","event_kind":"SETUP_BEGIN",
            "capture_objects":[batch_pair],"decode_objects":decode_pairs,"runtime_selection":runtime_pair,"selected_values":selected_pair,
            "spawn_selection":None,"selected_source_refs":sources,"raw_blob_manifests":[]}
    inputs_pair=signed("AUTHENTICATED_EVENT_INPUTS",inputs)
    event={"format":"forex.policy-inheritance-event/3","binding":f.binding,"budget_sha256":selected["budget_sha256"],"stream_id":f.appointment["stream_id"],
           "record_id":"public-event-1","producer_id":"witness","sequence":1,"previous_record_sha256":ZERO,"slot_id":"s0","kind":"SETUP_BEGIN",
           "origin":"CONTROLLER","evidence_class":"CONTROLLER_STREAM_METADATA","observed_start":stamp(),"observed_end":stamp(1),"recorded":stamp(1),
           "payload_ref":actual_artifacts[-1][0],"raw_refs":[inputs_pair["object_ref"],inputs_pair["envelope_ref"]]+[x[0] for x in actual_artifacts],
           "input_bundle_ref":inputs_pair["object_ref"],"input_bundle_envelope_ref":inputs_pair["envelope_ref"]}
    event_pair=signed("EVENT_RECORD",event)
    event_envelopes={event_pair["object_ref"]["sha256"]:evidence.resolve(event_pair["envelope_ref"])}
    state=SimpleNamespace(decoder_calls=0,artifacts=actual_artifacts,bindings=tuple(bindings),bad_return=False)
    class PublicFakeDecoder:
        def __init__(self,**kwargs): self.sink=kwargs["sink"]
        def decode_actual(self,captures,**kwargs):
            state.decoder_calls+=1
            for reference,raw in state.artifacts:self.sink.retain(raw,artifact_kind=reference["artifact_kind"])
            return deepcopy(state.bindings[-1]), state.artifacts[-1][1] if not state.bad_return else b"{}"
        @property
        def derived_artifacts(self):return tuple((dict(r),b) for r,b in state.artifacts)
        @property
        def derived_bindings(self):return tuple(deepcopy(x) for x in state.bindings)
    from cas_forex_operational_contracts.common import decode_canonical
    selection=SemanticSelection("f"*64,"b"*64,tuple((x["slot_id"],(canonical_bytes(source),)) for x in f.plan["slots"]))
    verifier=OperationalSemanticVerifier(authentication=f.auth,evidence=evidence,appointment=f.appointment,budget=f.budget,plan=f.plan,selection=selection,
        decoder_factory=PublicFakeDecoder,event_envelope=lambda r:decode_canonical(event_envelopes[r["sha256"]]),
        authority_status=lambda now:f.auth.current(now)[0],clock=f.guard.check,phase_guard=lambda kind,**kw:None)
    return SimpleNamespace(f=f,evidence=evidence,event=event,inputs=inputs,inputs_pair=inputs_pair,batch_pair=batch_pair,
        selected_pair=selected_pair,decode_pairs=decode_pairs,signed=signed,event_envelopes=event_envelopes,
        verifier=verifier,state=state,payload=payload,controller=controller)


def accept_begin(g):
    return g.verifier.validate_event(event_raw=canonical_bytes(g.event),accepted_raw=(),plan_raw=canonical_bytes(g.f.plan),
                                     budget_raw=canonical_bytes(g.f.budget),now=g.f.guard.check())


class PredicateEvidence:
    """Pure predicate test map. Never accepted by OperationalSemanticVerifier."""
    def __init__(self):self.evidence=MemoryEvidence();self.direct={}
    def add(self,kind,value):return self.evidence.add(kind,value)
    def object(self,reference,*,kind):
        assert reference["artifact_kind"]==kind
        from cas_forex_operational_contracts.common import decode_canonical
        return decode_canonical(self.evidence.resolve(reference))
    def one(self,event,kind,**kwargs):return deepcopy(self.direct[kind])


def calibration_case(case_kind):
    f=fixture(); evidence=PredicateEvidence(); controller=identity(evidence.evidence,10); peer=identity(evidence.evidence,11); foreign=identity(evidence.evidence,12)
    index=list(BASELINES).index(case_kind); slot=f.plan["calibration_plan"][index]; slot["fixture_ref"]=evidence.add("PUBLIC_FIXTURE",{"case_kind":case_kind,"public_only":True})
    selected={"subject_id":slot["case_id"],"controller":controller,"calibration":{"receiver_component_sha256":"9"*64,"expected_peer":peer,
        "foreign_sender":foreign,"retired_pids":[11,12],"temporary_actors":[peer,foreign]}}
    baseline=BASELINES[case_kind];sender=foreign if baseline["foreign_pid"] else peer
    event={"slot_id":slot["slot_id"],"kind":"CALIBRATION_CASE","observed_start":stamp(),"observed_end":stamp(10)}
    p={"case_id":slot["case_id"],"case_kind":case_kind,"slot_id":slot["slot_id"],"fixture_ref":slot["fixture_ref"],"receiver_identity":controller,
       "receiver_component_sha256":"9"*64,"expected_peer_identity":peer,"channel_instance_id":"channel-"+case_kind,
       "verifier_instance_id":"verifier-"+case_kind,"channel_object_ids":["left-"+case_kind,"right-"+case_kind],"public_fixture_key_id":"key-"+case_kind,"exchanges":[]}
    evidence.direct["PROC_IDENTITY"]={"receiver":controller,"expected_peer":peer,"senders":[sender],"live_pids":[10,11,12],"observed":stamp(1)}
    for i,verdict in enumerate(baseline["exchange_verdicts"]):
        begin,end=stamp(i*3),stamp(i*3+2);exchange_id=p["case_id"]+"-exchange-"+str(i+1)
        descriptor={"fd":40,"object_type":"REGULAR","device":1,"inode":50,"access_flags":0,"close_on_exec":True,"selected_target_id":"public-right"}
        delivered=[descriptor] if baseline["delivered_rights_minimum"] else []
        credentials=None if case_kind=="TRUNCATED_RIGHTS" else {k:sender[k] for k in ("pid","uid","gid")}
        sent={"application_hex":b"public packet".hex(),"frames_hex":b"public frames".hex(),"sender":sender,"return_value":13,"errno":0}
        received={"frames_hex":sent["frames_hex"],"receiver":controller,"actual_ucred":credentials,"return_value":13,"errno":0,
                  "msg_trunc":False,"msg_ctrunc":case_kind=="TRUNCATED_RIGHTS","delivered_fds":delivered}
        trace={"frame_valid":case_kind!="BAD_FRAME","mac_valid":case_kind!="BAD_MAC","channel_matches":case_kind!="BAD_CHANNEL_ID","packet_sequence":1,
            "verdict":verdict,"rejection_stage":baseline["rejection_stages"][i],"seq_before":baseline["recv_sequences"][i][0],"seq_after":baseline["recv_sequences"][i][1],
            "closed_before":False,"closed_after":baseline["closed_after"][i],"handler_before":0,"handler_after":0,"instance_id":p["verifier_instance_id"],
            "channel_instance_id":p["channel_instance_id"],"key_id":p["public_fixture_key_id"],"exchange_id":exchange_id,
            "verdict_operation_index":10+i*20,"exposure_operation_index":11+i*20,"verdict_observed":end,"exposure_observed":end}
        closes=[]
        for d in delivered:
            closed=stamp(i*3+1);rawclose={"descriptor":d,"return_value":0,"errno":0,"observed":closed,"exchange_id":exchange_id,"operation_index":9+i*20}
            closes.append({"descriptor":d,"close_return":0,"close_errno":0,"closed_at":closed,"raw_close_ref":evidence.add("DESCRIPTOR_CLOSES",rawclose)})
        p["exchanges"].append({"exchange_index":i+1,"observed_start":begin,"observed_end":end,"actual_sender_identity":sender,
            "sent_record_ref":evidence.add("IPC_SEND",sent),"recv_record_ref":evidence.add("IPC_RECEIVE",received),
            "sent_application_packet_sha256":digest(b"public packet"),"sent_frames_sha256":digest(b"public frames"),"received_frames_sha256":digest(b"public frames"),
            "send_return":13,"send_errno":0,"recv_return":13,"recv_errno":0,"actual_ucred":credentials,"msg_trunc":False,"msg_ctrunc":case_kind=="TRUNCATED_RIGHTS",
            "recv_seq_before":trace["seq_before"],"recv_seq_after":trace["seq_after"],"receiver_closed_before":False,"receiver_closed_after":trace["closed_after"],
            "verdict":verdict,"rejection_stage":trace["rejection_stage"],"verifier_trace_ref":evidence.add("VERIFIER_TRACE",trace),
            "handler_entries_before":0,"handler_entries_after":0,"delivered_fds":delivered,"close_outcomes":closes})
    accepted=({"event":{"kind":"CALIBRATION_BEGIN"},"payload":{"receiver_component_sha256":"9"*64}},)
    return SimpleNamespace(event=event,payload=p,evidence=evidence,selected=selected,accepted=accepted,coverage=_Coverage(f.plan,canonical_bytes(f.plan)))


def installation_case():
    f=fixture(); e=PredicateEvidence(); parent=identity(e.evidence,10); child=identity(e.evidence,20); child["parent_pid"]=10
    descriptors=[{"fd":i,"object_type":"PIPE","device":1,"inode":30+i,"access_flags":0,"close_on_exec":False,"selected_target_id":"stdio"+str(i)} for i in range(3)]
    mappings=[{"parent_fd":i,"child_fd":i,"object_identity":{**d,"close_on_exec":True},"target_id":d["selected_target_id"],"inheritance":"STDIO_DUP"} for i,d in enumerate(descriptors)]
    spawn={"parent":parent,"child":child,"descriptor_bindings":mappings};spawn_ref=e.add("TRUSTED_SPAWN_SELECTION",spawn)
    e.spawn=spawn;e.inputs={"spawn_selection":{"object_ref":spawn_ref}}
    targets=[{"target_id":"models","device":1,"inode":77,"resolved_path":"/public/models"}];rules=[{"target_id":"models","rights":1}]
    selected={"subject_id":"subject","controller":parent,"installations":{"RUNNER_INSTALL":{"process":child,"descriptors":descriptors,
        "descriptor_plan_ref":spawn_ref,"rules":rules,"targets":targets,"abi":4,"handled_fs":1}}}
    calls=[]
    for i,(operation,args,result) in enumerate([
        ("LANDLOCK_CREATE_RULESET",{"mode":"ABI_QUERY"},4),("LANDLOCK_CREATE_RULESET",{"mode":"CREATE","handled_fs":1},50),
        ("LANDLOCK_ADD_RULE",{"ruleset_fd":50,"target":targets[0],"rights":1},0),
        ("PR_SET_NO_NEW_PRIVS",{"no_new_privs":1},0),("LANDLOCK_RESTRICT_SELF",{"ruleset_fd":50,"flags":0},0)]):
        calls.append({"operation":operation,"arguments_ref":e.add("INSTALL_ARGUMENTS",args),"return_value":result,"errno":0,"observed":stamp(i+1)})
    p={"process_identity":child,"threads":[{"tid":20,"start_ticks":200}],"initial_descriptors":descriptors,"expected_descriptor_plan_ref":spawn_ref,
       "normalized_rules_ref":e.add("NORMALIZED_RULES",rules),"rule_target_inventory_ref":e.add("RULE_TARGET_INVENTORY",targets),"landlock_abi":4,"handled_fs":1,
       "syscalls":calls,"no_new_privs_readback":1,"parent_installation_record_id":None}
    e.direct["PROC_IDENTITY"]={"process":child,"parent":parent,"threads":p["threads"],"observed_start":stamp(),"observed_end":stamp(1)}
    e.direct["DESCRIPTOR_INVENTORY"]={"process":child,"descriptors":descriptors,"observed":stamp(1)}
    e.direct["INSTALL_ARGUMENTS"]={"process":child,"no_new_privs":1,"observed":stamp(6)}
    event={"kind":"RUNNER_INSTALL","slot_id":"s12","observed_start":stamp(),"observed_end":stamp(10)}
    return SimpleNamespace(event=event,payload=p,selected=selected,evidence=e,accepted=(),coverage=_Coverage(f.plan,canonical_bytes(f.plan)))


def seal_case():
    f=fixture();e=PredicateEvidence();rows=[]
    for i,slot in enumerate(f.plan["slots"][:18]):
        event={"sequence":i+1,"kind":slot["kind"],"record_id":"r"+str(i+1),"slot_id":slot["slot_id"]}
        rows.append({"event":event,"event_sha256":digest(canonical_bytes(event))})
    entries=[{"sequence":r["event"]["sequence"],"record_id":r["event"]["record_id"],"record_sha256":r["event_sha256"]} for r in rows]
    p={"entries":entries,"covered_slot_ids":[r["event"]["slot_id"] for r in rows],"previous_head_sha256":rows[-1]["event_sha256"],
       "previous_record_count":18,"unsupported_routes":f.plan["unsupported_routes"]}
    event={"kind":"SETUP_SEAL","slot_id":"s18","sequence":19,"raw_refs":[ref(canonical_bytes(p),"CANONICAL_PAYLOAD")]}
    return SimpleNamespace(event=event,payload=p,evidence=e,selected={"subject_id":"subject"},accepted=tuple(rows),coverage=_Coverage(f.plan,canonical_bytes(f.plan)))


def post_exec_case():
    f=fixture(); e=PredicateEvidence(); parent=identity(e.evidence,20); before=identity(e.evidence,30);before["parent_pid"]=20
    after=deepcopy(before);after["exe_inode"]=300;after["exe_asset"]={"asset_id":"server","selected_path":"/public/server","bytes":200,"sha256":"b"*64,"device":1,"inode":300}
    asset={"asset_id":"server","path":"/public/server","bytes":200,"sha256":"b"*64,"device":1,"inode":300,"read_only":True}
    listener={"process":after,"address":"127.0.0.1","port":8000,"socket_inode":500,"observed":stamp(5)}
    selected={"subject_id":"subject","assets":[asset],"post_exec":{"process":after,"parent":parent,"exe_path":"/public/server","executable_asset_id":"server","listener":listener}}
    rows=({"event":{"kind":"RUNNER_INSTALL","record_id":"runner"},"payload":{"process_identity":parent}},
          {"event":{"kind":"MODEL_INSTALL","record_id":"model","observed_end":stamp(2)},"payload":{"process_identity":before},"spawn":{"parent":parent}},
          {"event":{"kind":"ASSET_BINDINGS","record_id":"assets"},"selected_values":{"assets":[asset]}})
    e.direct["PROC_IDENTITY"]={"process":after,"parent":parent,"exe_path":"/public/server","observed":stamp(5)}
    p={"wrapper_installation_record_id":"model","actual_server_identity":after,"asset_binding_record_id":"assets",
       "owned_listener_ref":e.add("LISTENER_IDENTITY",listener),"wrapper_to_exec_identity_ref":e.add("EXEC_LINEAGE",{"before":before,"after":after,"parent":parent,"exe_path":"/public/server","observed":stamp(5)})}
    event={"kind":"MODEL_POST_EXEC","slot_id":"s15","observed_start":stamp(3),"observed_end":stamp(6)}
    return SimpleNamespace(event=event,payload=p,evidence=e,selected=selected,accepted=rows,coverage=_Coverage(f.plan,canonical_bytes(f.plan)))


def peer_case():
    f=fixture();e=PredicateEvidence();peer=identity(e.evidence,20);controller=identity(e.evidence,10)
    descriptor={"fd":4,"object_type":"SOCKET","device":1,"inode":50,"access_flags":2,"close_on_exec":False,"selected_target_id":"runner-endpoint"}
    channel={"channel_id":"final","endpoint_ids":["controller-endpoint","runner-endpoint"],"owner":controller,"key_operation_id":"final-key","created_at":stamp(1)}
    packet={"channel_id":"final","endpoint_id":"runner-endpoint","owner":peer,"ucred":[20,1000,1000],"mac_valid":True,"sequence":1,"received_at":stamp(2),"key_operation_id":"final-key"}
    current={"process":peer,"endpoint_id":"runner-endpoint","descriptor":descriptor,"observed":stamp(5)}
    packetref=e.add("IPC_RECEIVE",packet);currentref=e.add("PROC_IDENTITY",current);e.direct["PROC_IDENTITY"]=current
    selected={"subject_id":"subject","channel":channel,"peer":{"first_packet_ref":packetref,"current_peer_ref":currentref}}
    rows=({"event":{"kind":"FINAL_CHANNEL_CREATED","record_id":"created","recorded":stamp(1)},"payload":{"channel_id":"final","key_generation_operation_id":"final-key"},"selected_values":{"channel":channel}},
          {"event":{"kind":"RUNNER_INSTALL","record_id":"runner"},"payload":{"process_identity":peer,"initial_descriptors":[descriptor]},
           "spawn":{"descriptor_bindings":[{"child_fd":4,"target_id":"runner-endpoint","object_identity":descriptor}]}},
          {"event":{"kind":"MODEL_POST_EXEC","record_id":"post","recorded":stamp(4)}})
    p={"channel_created_record_id":"created","channel_id":"final","actual_peer_identity":peer,"first_packet_ref":packetref,"actual_ucred":[20,1000,1000],"model_post_exec_record_id":"post"}
    event={"kind":"FINAL_PEER_BOUND","slot_id":"s16","observed_start":stamp(3),"observed_end":stamp(6)}
    return SimpleNamespace(event=event,payload=p,evidence=e,selected=selected,accepted=rows,coverage=_Coverage(f.plan,canonical_bytes(f.plan)))


def retired_case():
    base=calibration_case("WRONG_PEER_PID");f=fixture();e=base.evidence;cal=base.selected["calibration"];controller=base.selected["controller"]
    rows=[{"event":{"kind":"SETUP_BEGIN"},"payload":{"producer_identity":controller}},
          {"event":{"kind":"CALIBRATION_BEGIN"},"selected_values":{"calibration":cal}}]
    endpoints=[]
    for index,kind in enumerate(BASELINES):
        pair=["left"+str(index),"right"+str(index)];endpoints+=pair
        rows.append({"event":{"kind":"CALIBRATION_CASE"},"payload":{"case_id":"case"+str(index),"case_kind":kind,"channel_object_ids":pair,
            "exchanges":[{"actual_sender_identity":cal["foreign_sender"] if kind=="WRONG_PEER_PID" else cal["expected_peer"]}]}})
    process_raw={"challenger":cal["foreign_sender"],"retired_pids":cal["retired_pids"],"retired_identities":cal["temporary_actors"],"remaining_descendants":[],"unclosed_delivered_fds":[],"observed":stamp(8)}
    p={"completed_case_ids":["case"+str(i) for i in range(8)],"endpoint_retirement_ref":e.add("ENDPOINT_RETIREMENT",{"closed_endpoint_ids":endpoints,"observed":stamp(8)}),
       "challenger_identity":cal["foreign_sender"],"process_retirement_ref":e.add("PROCESS_RETIREMENT",process_raw),"remaining_challenger_descendants":0,"unclosed_delivered_fds":0,"final_key_created":False}
    event={"kind":"CALIBRATION_RETIRED","slot_id":"s10","observed_start":stamp(7),"observed_end":stamp(9),"raw_refs":[ref(canonical_bytes(p),"CANONICAL_PAYLOAD")]}
    return SimpleNamespace(event=event,payload=p,evidence=e,selected={"subject_id":"subject","calibration":cal},accepted=tuple(rows),coverage=_Coverage(f.plan,canonical_bytes(f.plan)))


def final_channel_case():
    f=fixture();e=PredicateEvidence();controller=identity(e.evidence,10)
    channel={"channel_id":"final-channel","endpoint_ids":["final-left","final-right"],"owner":controller,"key_operation_id":"final-key","created_at":stamp(11)}
    rows=({"event":{"kind":"SETUP_BEGIN"},"payload":{"producer_identity":controller}},
          {"event":{"kind":"CALIBRATION_RETIRED","record_id":"retired","recorded":stamp(10)}},
          {"event":{"kind":"CALIBRATION_CASE"},"payload":{"channel_object_ids":["cal-left","cal-right"],"channel_instance_id":"cal-channel","public_fixture_key_id":"public-key"}})
    payload={"channel_id":"final-channel","endpoint_inventory_ref":e.add("DESCRIPTOR_INVENTORY",channel),"key_generation_operation_id":"final-key","calibration_retired_record_id":"retired","key_material_recorded":False}
    event={"kind":"FINAL_CHANNEL_CREATED","slot_id":"s11","observed_start":stamp(11),"observed_end":stamp(12),"raw_refs":[ref(canonical_bytes(payload),"CANONICAL_PAYLOAD")]}
    return SimpleNamespace(event=event,payload=payload,evidence=e,selected={"subject_id":"subject","controller":controller,"channel":channel},accepted=rows,coverage=_Coverage(f.plan,canonical_bytes(f.plan)))


def asset_case():
    f=fixture();e=PredicateEvidence()
    assets=[{"asset_id":"server","path":"/public/server","bytes":100,"sha256":"a"*64,"device":1,"inode":99,"read_only":True}]
    payload={"selected_asset_manifest_sha256":"b"*64,"actual_file_inventory_ref":e.add("ASSET_INVENTORY",assets),"hash_scan_started":stamp(1),"hash_scan_completed":stamp(2)}
    event={"kind":"ASSET_BINDINGS","slot_id":"s14","observed_start":stamp(1),"observed_end":stamp(3),"raw_refs":[ref(canonical_bytes(payload),"CANONICAL_PAYLOAD")]}
    return SimpleNamespace(event=event,payload=payload,evidence=e,selected={"subject_id":"subject","assets":assets,"asset_manifest_sha256":"b"*64},accepted=(),coverage=_Coverage(f.plan,canonical_bytes(f.plan)))


def policy_case():
    f=fixture();e=PredicateEvidence();rows=seal_case().accepted[:17]
    argument={"claim":"TRUSTED_INSTALLATION_AND_INHERITANCE","non_forwarding_status":"ASSUMPTION_BOUND_NON_FORWARDING","unsupported_routes":f.plan["unsupported_routes"],"every_task_post_exec_probes_claimed":False}
    source=e.add("SOURCE_ARGUMENT",argument)
    payload={"installation_record_ids":["r13","r14"],"post_exec_record_id":"r16","source_argument_ref":source,**argument}
    event={"kind":"POLICY_ARGUMENT","slot_id":"s17","raw_refs":[ref(canonical_bytes(payload),"CANONICAL_PAYLOAD")]}
    return SimpleNamespace(event=event,payload=payload,evidence=e,selected={"subject_id":"subject","source_argument_ref":source},accepted=rows,coverage=_Coverage(f.plan,canonical_bytes(f.plan)))
