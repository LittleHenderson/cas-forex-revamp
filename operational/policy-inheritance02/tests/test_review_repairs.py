"""Public source regressions for the eight combined independent findings.

All methods are authored only. No test was executed during this source task.
"""
import copy
import unittest
from unittest.mock import patch

from policy_inheritance.contract import ZERO, canonical_bytes, decode_canonical, digest, object_ref
from policy_inheritance.errors import ContractViolation
from policy_inheritance.evidence import PublicSelections
from policy_inheritance.plan import Coverage
from policy_inheritance.checkpoint import validate_request
from support import Fixture, TIMES, h, stamp


class ReviewRepairTests(unittest.TestCase):
    def reject_and_retry(self, fixture, model, packet, code=None):
        prefix = model.inspect().accepted_record_count
        with self.assertRaises(ContractViolation) as caught:
            fixture.prepare(model, packet)
        if code:
            self.assertEqual(caught.exception.code, code)
        self.assertTrue(model.inspect().terminal)
        self.assertEqual(model.inspect().phase,"FAILED_ANALYSIS_ONLY")
        self.assertEqual(model.inspect().accepted_record_count, prefix)
        clean = fixture.packet(model, prefix + 1)
        with self.assertRaises(ContractViolation) as retry:
            fixture.prepare(model, clean)
        self.assertEqual(retry.exception.code, "REPLAY_OR_EQUIVOCATION")
        self.assertEqual(model.inspect().accepted_record_count, prefix)

    @staticmethod
    def replace_raw(fixture, packet, kind, mutate):
        index = next(i for i, r in enumerate(packet.event["raw_refs"]) if r["artifact_kind"] == kind)
        value = decode_canonical(fixture.objects[packet.event["raw_refs"][index]["object_id"]])
        mutate(value)
        packet.event["raw_refs"][index] = fixture.put(value, kind)
        return value

    def test_peer_endpoint_not_in_retained_runner_inventory_rejected(self):
        f=Fixture();m=f.through(12);p=f.packet(m,13)
        p.payload["initial_descriptors"][-1]["selected_target_id"]="unrelated-endpoint"
        selected=p.selections["installations"]["RUNNER_INSTALL"]
        selected["descriptors"]=copy.deepcopy(p.payload["initial_descriptors"])
        selected["descriptor_plan"]["descriptors"]=copy.deepcopy(selected["descriptors"])
        p.payload["expected_descriptor_plan_ref"]=f.put(selected["descriptor_plan"],"DESCRIPTOR_INVENTORY")
        self.replace_raw(f,p,"DESCRIPTOR_INVENTORY",lambda x:x.update(descriptors=copy.deepcopy(selected["descriptors"])))
        f.repack(p);f.prepare(m,p)
        f.commit(m,"ACK_EXPOSURE",13,p.ack["record_sha256"],p.ack["retention_commit_id"],67)
        for seq in range(14,17):f.advance(m,seq)
        p=f.packet(m,17)
        self.reject_and_retry(f,m,p,"DESCRIPTOR_IDENTITY_MISMATCH")

    def test_peer_same_endpoint_marker_with_different_socket_inode_rejected(self):
        f=Fixture();m=f.through(16);p=f.packet(m,17)
        value=self.replace_raw(f,p,"PROC_IDENTITY",lambda x:x["descriptor"].update(inode=99999))
        p.selections["peer"]["current"]=value;f.repack(p)
        self.reject_and_retry(f,m,p,"DESCRIPTOR_IDENTITY_MISMATCH")

    def test_peer_same_endpoint_marker_with_different_descriptor_flags_rejected(self):
        f=Fixture();m=f.through(16);p=f.packet(m,17)
        value=self.replace_raw(f,p,"PROC_IDENTITY",lambda x:x["descriptor"].update(close_on_exec=True))
        p.selections["peer"]["current"]=value;f.repack(p)
        self.reject_and_retry(f,m,p,"DESCRIPTOR_IDENTITY_MISMATCH")

    def test_postexec_parent_same_pid_reused_start_identity_rejected(self):
        f=Fixture();m=f.through(15);p=f.packet(m,16)
        value=self.replace_raw(f,p,"PROC_IDENTITY",lambda x:x["parent"].update(start_ticks=x["parent"]["start_ticks"]+1))
        p.selections["post_exec"]["parent"]=copy.deepcopy(value["parent"])
        lineage=decode_canonical(f.objects[p.payload["wrapper_to_exec_identity_ref"]["object_id"]])
        lineage["parent"]=value["parent"];p.payload["wrapper_to_exec_identity_ref"]=f.put(lineage,"EXEC_LINEAGE")
        f.repack(p);self.reject_and_retry(f,m,p,"SOURCE_OR_EXEC_IDENTITY_MISMATCH")

    def test_postexec_path_disagrees_with_asset_despite_same_inode_and_hash(self):
        f=Fixture();m=f.through(15);p=f.packet(m,16)
        self.replace_raw(f,p,"PROC_IDENTITY",lambda x:x.update(exe_path="/unselected/alias"))
        p.selections["post_exec"]["exe_path"]="/unselected/alias"
        lineage=decode_canonical(f.objects[p.payload["wrapper_to_exec_identity_ref"]["object_id"]])
        lineage["exe_path"]="/unselected/alias";p.payload["wrapper_to_exec_identity_ref"]=f.put(lineage,"EXEC_LINEAGE")
        f.repack(p);self.reject_and_retry(f,m,p,"SOURCE_OR_EXEC_IDENTITY_MISMATCH")

    def test_postexec_missing_current_parent_observation_rejected(self):
        f=Fixture();m=f.through(15);p=f.packet(m,16)
        self.replace_raw(f,p,"PROC_IDENTITY",lambda x:x.pop("parent"))
        f.repack(p);self.reject_and_retry(f,m,p,"DECODER_UNAVAILABLE")

    def test_checkpoint_request_is_retained_before_attempt(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,p.ack["record_sha256"],"commit-e01",4)
        original=canonical_bytes(request);m.prepare_checkpoint(original,sample=f.sample(4))
        self.assertEqual(m.inspect().phase,"CHECKPOINT_REQUEST_PREPARED")
        self.assertEqual(m.retained_checkpoint_requests[-1],original)
        request["transition_id"]="mutated-caller-dictionary"
        self.assertEqual(m.retained_checkpoint_requests[-1],original)
        m.model_checkpoint_attempt(sample=f.sample(4))
        m.record_checkpoint(decode_canonical(original),cp,env,before=f.sample(4),after=f.sample(4))
        self.assertEqual(m.inspect().phase,"CHECKPOINTED_UNCONFIRMED")

    def test_no_attempt_without_prepared_exact_request(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        with self.assertRaises(ContractViolation):m.model_checkpoint_attempt(sample=f.sample(4))
        self.assertTrue(m.inspect().terminal)
        with self.assertRaises(ContractViolation):f.commit(m,"ACK_EXPOSURE",1,p.ack["record_sha256"],"commit-e01",4)

    def test_response_without_modeled_attempt_cannot_advance(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,p.ack["record_sha256"],"commit-e01",4)
        m.prepare_checkpoint(canonical_bytes(request),sample=f.sample(4))
        with self.assertRaises(ContractViolation):m.record_checkpoint(request,cp,env,before=f.sample(4),after=f.sample(4))
        self.assertTrue(m.inspect().terminal)
        with self.assertRaises(ContractViolation):m.model_checkpoint_attempt(sample=f.sample(4))

    def test_recovery_cannot_replace_transition_id_or_preparation_time(self):
        for field,value in [("transition_id","replacement-id"),("prepared_at",stamp(5))]:
            with self.subTest(field=field):
                f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
                request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,p.ack["record_sha256"],"commit-e01",4)
                original=copy.deepcopy(request);original_cp=copy.deepcopy(cp);original_env=copy.deepcopy(env)
                f.attempt(m,request,4);m.mark_checkpoint_response_unknown()
                request[field]=value
                cp["transition_request_ref"]=object_ref(canonical_bytes(request),"CHECKPOINT_TRANSITION")
                cp["checkpointed_at"]=stamp(5);env=f.envelope(cp,"checkpoint","policy-inheritance-checkpoint-v2",5,"cp-attestation-3")
                with self.assertRaises(ContractViolation) as caught:
                    m.recover_checkpoint(request,cp,env,before=f.sample(5),after=f.sample(5))
                self.assertEqual(caught.exception.code,"CHECKPOINT_LEDGER_DIVERGENCE")
                self.assertEqual(m.retained_checkpoint_requests[-1],canonical_bytes(original))
                self.assertTrue(m.inspect().terminal)
                with self.assertRaises(ContractViolation):
                    m.recover_checkpoint(original,original_cp,original_env,before=f.sample(5),after=f.sample(5))
                self.assertEqual(m.inspect().accepted_record_count,0)

    def test_reservation_ambiguity_recovers_only_original_request(self):
        f=Fixture();m=f.new_model()
        request,cp,env=f.checkpoint_packet(None,{"kind":"NONE","body_ref":None,"attestation_ref":None},"SETUP_RESERVATION",0,ZERO,"reserve-commit",0)
        raw=canonical_bytes(request)
        m.prepare_reservation(raw,before=f.sample(0),after=f.sample(0),initial_view=f.initial_view())
        m.model_checkpoint_attempt(sample=f.sample(0));m.mark_checkpoint_response_unknown()
        m.recover_reservation(request,cp,env,before=f.sample(0),after=f.sample(0))
        self.assertEqual(m.retained_checkpoint_requests,(raw,))
        m.confirm_reservation(cp,before=f.sample(0),after=f.sample(0))
        self.assertEqual(m.inspect().phase,"RESERVED")

    def test_reservation_recovery_cannot_replace_original_identity(self):
        f=Fixture();m=f.new_model()
        request,cp,env=f.checkpoint_packet(None,{"kind":"NONE","body_ref":None,"attestation_ref":None},"SETUP_RESERVATION",0,ZERO,"reserve-commit",0)
        m.prepare_reservation(canonical_bytes(request),before=f.sample(0),after=f.sample(0),initial_view=f.initial_view())
        m.model_checkpoint_attempt(sample=f.sample(0));m.mark_checkpoint_response_unknown()
        request["transition_id"]="replacement"
        cp["transition_request_ref"]=object_ref(canonical_bytes(request),"CHECKPOINT_TRANSITION")
        env=f.envelope(cp,"checkpoint","policy-inheritance-checkpoint-v2",0,"cp-attestation-1")
        with self.assertRaises(ContractViolation):m.recover_reservation(request,cp,env,before=f.sample(0),after=f.sample(0))
        self.assertTrue(m.inspect().terminal)
        with self.assertRaises(ContractViolation):m.prepare_reservation(canonical_bytes(request),before=f.sample(0),after=f.sample(0),initial_view=f.initial_view())

    def test_request_cannot_predate_pending_ack_preparation(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,p.ack["record_sha256"],"commit-e01",3)
        with self.assertRaises(ContractViolation):m.prepare_checkpoint(canonical_bytes(request),sample=f.sample(4))
        self.assertTrue(m.inspect().terminal)
        with self.assertRaises(ContractViolation):f.commit(m,"ACK_EXPOSURE",1,p.ack["record_sha256"],"commit-e01",4)

    def test_request_cannot_predate_output_envelope_issuance(self):
        f=Fixture();m=f.start();p=f.packet(m,1)
        p.ack_envelope=f.envelope(p.ack,"consumer","policy-inheritance-ingestion-ack-v2",5,"ack-e01")
        m.validate_event(canonical_bytes(p.event),canonical_bytes(p.payload),p.evidence,p.witness,
                        selections=PublicSelections(p.selections),sample=f.sample(4))
        m.prepare_ack(p.ack,p.ack_envelope,sample=f.sample(5))
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,p.ack["record_sha256"],"commit-e01",4)
        with self.assertRaises(ContractViolation):m.prepare_checkpoint(canonical_bytes(request),sample=f.sample(5))
        self.assertTrue(m.inspect().terminal)

    def test_checkpoint_time_cannot_move_before_request_or_prior_checkpoint(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,p.ack["record_sha256"],"commit-e01",4)
        f.attempt(m,request,4);cp["checkpointed_at"]=stamp(1)
        env=f.envelope(cp,"checkpoint","policy-inheritance-checkpoint-v2",4,"cp-attestation-3")
        with self.assertRaises(ContractViolation):m.record_checkpoint(request,cp,env,before=f.sample(4),after=f.sample(4))
        self.assertTrue(m.inspect().terminal)
        cp["checkpointed_at"]=stamp(4)
        with self.assertRaises(ContractViolation):m.record_checkpoint(request,cp,env,before=f.sample(4),after=f.sample(4))

    def test_checkpoint_cannot_precede_later_modeled_attempt(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,p.ack["record_sha256"],"commit-e01",4)
        m.prepare_checkpoint(canonical_bytes(request),sample=f.sample(4));m.model_checkpoint_attempt(sample=f.sample(5))
        with self.assertRaises(ContractViolation):m.record_checkpoint(request,cp,env,before=f.sample(5),after=f.sample(5))
        self.assertTrue(m.inspect().terminal)

    def test_request_time_must_follow_previous_checkpoint_without_other_lower_bound(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,p.ack["record_sha256"],"commit-e01",1)
        with self.assertRaises(ContractViolation) as caught:
            validate_request(f.contract,m.guards,m.checkpoint,request,expected_kind="ACK_EXPOSURE",
                expected_sequence=1,expected_head=p.ack["record_sha256"],expected_output=m.pending_output,
                expected_prepare_id="commit-e01",now=stamp(4))
        self.assertEqual(caught.exception.field,"request.preparation_order")

    def test_coverage_rejects_heterogeneous_receiver_components(self):
        f=Fixture();plan=copy.deepcopy(f.plan);plan["calibration_plan"][7]["receiver_component_sha256"]=h("other-receiver")
        with self.assertRaises(ContractViolation) as caught:Coverage(f.contract,plan,selected_scope=f.scope)
        self.assertEqual(caught.exception.code,"CALIBRATION_BASELINE_MISMATCH")

    def test_calibration_begin_cannot_choose_component_outside_plan(self):
        f=Fixture();m=f.through(1);p=f.packet(m,2)
        p.payload["receiver_component_sha256"]=p.selections["calibration"]["receiver_component_sha256"]=h("other-receiver")
        f.repack(p);self.reject_and_retry(f,m,p,"CALIBRATION_BASELINE_MISMATCH")

    def test_later_calibration_cannot_change_receiver_component(self):
        f=Fixture();m=f.through(3);p=f.packet(m,4)
        p.payload["receiver_component_sha256"]=p.selections["calibration"]["receiver_component_sha256"]=h("replacement-receiver")
        f.repack(p);self.reject_and_retry(f,m,p,"CALIBRATION_BASELINE_MISMATCH")

    def test_malformed_nested_selection_fails_terminal_then_rejects_retry(self):
        cases=[(2,"calibration",{}),(2,"calibration",None),(12,"channel",[]),(12,"channel",{}),
               (13,"installations",{"RUNNER_INSTALL":{}}),(15,"assets",{}),(16,"post_exec",{}),
               (17,"peer",{"first_packet":{},"current":{}}),(18,"source_argument_ref",[])]
        for seq,key,value in cases:
            with self.subTest(sequence=seq,key=key,value=value):
                f=Fixture();m=f.through(seq-1);p=f.packet(m,seq);p.selections[key]=value
                self.reject_and_retry(f,m,p)

    def test_missing_nested_peer_field_cannot_leave_active_branch(self):
        f=Fixture();m=f.through(16);p=f.packet(m,17);p.selections["peer"].pop("current")
        self.reject_and_retry(f,m,p,"DECODER_UNAVAILABLE")

    def test_malformed_raw_typeerror_is_sanitized_and_terminal(self):
        f=Fixture();m=f.through(10);p=f.packet(m,11)
        p.payload["endpoint_retirement_ref"]=f.put({"closed_endpoint_ids":[1,"bad-type"],"observed":stamp(30)},"ENDPOINT_RETIREMENT")
        f.repack(p);self.reject_and_retry(f,m,p,"DECODER_UNAVAILABLE")

    def test_unexpected_lookup_errors_terminate_and_do_not_leak_input_text(self):
        for error_type in [KeyError,TypeError,IndexError,AttributeError]:
            with self.subTest(error_type=error_type.__name__):
                f=Fixture();m=f.start();p=f.packet(m,1)
                with patch("policy_inheritance.machine.Semantics.validate",side_effect=error_type("public-fixture-marker")):
                    with self.assertRaises(ContractViolation) as caught:f.prepare(m,p)
                self.assertEqual(caught.exception.code,"DECODER_UNAVAILABLE")
                self.assertNotIn("public-fixture-marker",str(caught.exception))
                self.assertTrue(m.inspect().terminal)
                with self.assertRaises(ContractViolation) as retry:f.prepare(m,p)
                self.assertEqual(retry.exception.code,"REPLAY_OR_EQUIVOCATION")

    def test_same_process_controller_can_survive_calibration_and_continue(self):
        f=Fixture();f.expected_peer=f.controller;f.temporary_actors=[f.foreign]
        m=f.through(19)
        retirement=m.accepted[10]
        raw=decode_canonical(retirement["raw_objects"][retirement["payload"]["process_retirement_ref"]["object_id"]])
        self.assertEqual(raw["retired_pids"],[f.foreign["pid"]])
        self.assertNotIn(f.controller["pid"],raw["retired_pids"])
        self.assertEqual(m.inspect().phase,"SEALED")

    def test_temporary_actor_selection_cannot_require_controller_retirement(self):
        f=Fixture();m=f.through(1);p=f.packet(m,2)
        p.selections["calibration"]["temporary_actors"].append(f.controller)
        p.selections["calibration"]["retired_pids"].append(f.controller["pid"])
        self.reject_and_retry(f,m,p,"CALIBRATION_BASELINE_MISMATCH")

    def test_retirement_requires_exact_start_identity_of_temporary_actor(self):
        f=Fixture();m=f.through(10);p=f.packet(m,11)
        value=decode_canonical(f.objects[p.payload["process_retirement_ref"]["object_id"]])
        value["retired_identities"][0]["start_ticks"]+=1
        p.payload["process_retirement_ref"]=f.put(value,"PROCESS_RETIREMENT")
        f.repack(p);self.reject_and_retry(f,m,p,"CLEANUP_UNCONFIRMED")

    def test_extra_controller_retirement_not_accepted_as_cleanup(self):
        f=Fixture();m=f.through(10);p=f.packet(m,11)
        value=decode_canonical(f.objects[p.payload["process_retirement_ref"]["object_id"]])
        value["retired_identities"].append(f.controller);value["retired_pids"].append(f.controller["pid"])
        p.payload["process_retirement_ref"]=f.put(value,"PROCESS_RETIREMENT")
        f.repack(p);self.reject_and_retry(f,m,p,"CLEANUP_UNCONFIRMED")

    def test_close_after_rejection_or_exposure_rejected_even_same_timestamp(self):
        for index in [100,101,102]:
            with self.subTest(operation_index=index):
                f=Fixture();m=f.through(7);p=f.packet(m,8);close=p.payload["exchanges"][0]["close_outcomes"][0]
                raw=decode_canonical(f.objects[close["raw_close_ref"]["object_id"]]);raw["operation_index"]=index
                close["raw_close_ref"]=f.put(raw,"DESCRIPTOR_CLOSES")
                f.repack(p);self.reject_and_retry(f,m,p,"CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE")

    def test_close_timestamp_after_rejection_rejected_despite_earlier_index(self):
        f=Fixture();m=f.through(7);p=f.packet(m,8);x=p.payload["exchanges"][0]
        p.event["observed_start"]=x["observed_start"]=stamp(19)
        trace=decode_canonical(f.objects[x["verifier_trace_ref"]["object_id"]]);trace["verdict_observed"]=stamp(19)
        x["verifier_trace_ref"]=f.put(trace,"VERIFIER_TRACE")
        f.repack(p);self.reject_and_retry(f,m,p,"CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE")

    def test_missing_outcome_order_observation_cannot_be_inferred(self):
        f=Fixture();m=f.through(7);p=f.packet(m,8);x=p.payload["exchanges"][0]
        trace=decode_canonical(f.objects[x["verifier_trace_ref"]["object_id"]]);trace.pop("exposure_operation_index")
        x["verifier_trace_ref"]=f.put(trace,"VERIFIER_TRACE")
        f.repack(p);self.reject_and_retry(f,m,p,"DECODER_UNAVAILABLE")

    def test_descriptor_close_cannot_borrow_other_exchange_order(self):
        f=Fixture();m=f.through(7);p=f.packet(m,8);close=p.payload["exchanges"][0]["close_outcomes"][0]
        raw=decode_canonical(f.objects[close["raw_close_ref"]["object_id"]]);raw["exchange_id"]="other-exchange"
        close["raw_close_ref"]=f.put(raw,"DESCRIPTOR_CLOSES")
        f.repack(p);self.reject_and_retry(f,m,p,"CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE")

    def test_exposure_before_verdict_rejected(self):
        f=Fixture();m=f.through(7);p=f.packet(m,8);x=p.payload["exchanges"][0]
        trace=decode_canonical(f.objects[x["verifier_trace_ref"]["object_id"]]);trace["exposure_operation_index"]=99
        x["verifier_trace_ref"]=f.put(trace,"VERIFIER_TRACE")
        f.repack(p);self.reject_and_retry(f,m,p,"CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE")

