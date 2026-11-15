import copy
import unittest

from policy_inheritance.checkpoint import original_key, require_recovery_match
from policy_inheritance.contract import ZERO, canonical_bytes, digest
from policy_inheritance.errors import ContractViolation, UnsupportedAuthority
from policy_inheritance.evidence import PublicEvidence, PublicSelections
from support import Fixture, TIMES, h, stamp


class ProtocolTests(unittest.TestCase):
    def test_complete_incremental_trace_has_no_forward_prerequisites(self):
        f=Fixture();m=f.start()
        for sequence in range(1,20):
            p=f.packet(m,sequence)
            before=m.inspect();self.assertEqual(before.accepted_record_count,sequence-1)
            if sequence==12:self.assertEqual(set(p.selections),{"controller","channel","subject_id"})
            if sequence==18:self.assertEqual(len(m.accepted),17)
            if sequence==19:
                self.assertEqual(len(p.payload["entries"]),18)
                self.assertNotIn("e19",[x["record_id"] for x in p.payload["entries"]])
            m.validate_event(canonical_bytes(p.event),canonical_bytes(p.payload),p.evidence,p.witness,
                             selections=PublicSelections(p.selections),sample=f.sample(TIMES[sequence-1]))
            self.assertEqual(m.inspect().phase,"EVENT_VALIDATED")
            self.assertIsNone(m.pending_output)
            m.prepare_ack(p.ack,p.ack_envelope,sample=f.sample(TIMES[sequence-1]))
            self.assertEqual(m.inspect().phase,"PREPARED")
            self.assertEqual(m.inspect().accepted_record_count,sequence-1)
            request,cp,env=f.commit(m,"ACK_EXPOSURE",sequence,digest(canonical_bytes(p.event)),p.ack["retention_commit_id"],TIMES[sequence-1],stop_after="checkpoint")
            self.assertEqual(m.inspect().checkpoint_generation,sequence+2)
            self.assertEqual(m.inspect().accepted_record_count,sequence-1)
            m.confirm_current(cp,before=f.sample(TIMES[sequence-1]),after=f.sample(TIMES[sequence-1]))
            self.assertEqual(m.inspect().accepted_record_count,sequence-1)
            result=m.model_exposure(sample=f.sample(TIMES[sequence-1]))
            self.assertEqual(result.accepted_record_count,sequence)
            self.assertFalse(result.runtime_authority);self.assertFalse(result.release_enabled)
        self.assertEqual(m.inspect().phase,"SEALED")
        decision,env=f.decision(m);m.prepare_decision(decision,env,sample=f.sample(100),independently_observed_checkpoint=m.checkpoint)
        f.commit(m,"DECISION_EXPOSURE",19,m.inspect().retained_head_sha256,"decision-commit",102)
        result=m.inspect();self.assertEqual(result.phase,"DECIDED_ANALYSIS_ONLY");self.assertTrue(result.terminal)
        self.assertEqual(result.checkpoint_generation,22)
        with self.assertRaises(UnsupportedAuthority):m.operational_output()
        with self.assertRaises(UnsupportedAuthority):m.release_consume()

    def test_constructor_needs_no_future_process_or_descriptor_evidence(self):
        f=Fixture();m=f.new_model()
        self.assertEqual(m.inspect().phase,"NEW")
        self.assertEqual(m.inspect().accepted_record_count,0)

    def test_event_validation_needs_no_ack_candidate_or_checkpoint(self):
        f=Fixture();m=f.start();p=f.packet(m,1)
        result=m.validate_event(canonical_bytes(p.event),canonical_bytes(p.payload),p.evidence,p.witness,
                                selections=PublicSelections(p.selections),sample=f.sample(4))
        self.assertEqual(result.phase,"EVENT_VALIDATED")
        self.assertEqual(result.accepted_record_count,0)
        self.assertEqual(result.checkpoint_generation,2)
        self.assertIsNone(m.pending_output)
        m.prepare_ack(p.ack,p.ack_envelope,sample=f.sample(4))
        self.assertEqual(m.inspect().phase,"PREPARED")

    def test_ack_cannot_be_prepared_before_event_semantics(self):
        f=Fixture();m=f.start();p=f.packet(m,1)
        with self.assertRaises(ContractViolation):m.prepare_ack(p.ack,p.ack_envelope,sample=f.sample(4))
        self.assertEqual(m.inspect().accepted_record_count,0)

    def test_validated_event_cannot_expose_before_ack_and_checkpoint(self):
        f=Fixture();m=f.start();p=f.packet(m,1)
        m.validate_event(canonical_bytes(p.event),canonical_bytes(p.payload),p.evidence,p.witness,
                         selections=PublicSelections(p.selections),sample=f.sample(4))
        with self.assertRaises(ContractViolation):m.model_exposure(sample=f.sample(4))

    def test_witness_expiry_between_validation_and_ack_is_rejected(self):
        f=Fixture();m=f.start();p=f.packet(m,1);p.witness["body"]["expires"]=stamp(5)
        m.validate_event(canonical_bytes(p.event),canonical_bytes(p.payload),p.evidence,p.witness,
                         selections=PublicSelections(p.selections),sample=f.sample(4))
        with self.assertRaises(ContractViolation) as c:m.prepare_ack(p.ack,p.ack_envelope,sample=f.sample(6))
        self.assertEqual(c.exception.code,"AUTHENTICATED_INTERVAL_EXPIRED")

    def test_ack_prepare_id_cannot_reuse_prior_event_or_budget_identity(self):
        for identity in ["commit-e01","budget-commit","reserve-commit"]:
            f=Fixture();m=f.through(1);p=f.packet(m,2);p.ack["retention_commit_id"]=identity
            p.ack_envelope=f.envelope(p.ack,"consumer","policy-inheritance-ingestion-ack-v2",6,"ack-e02")
            with self.subTest(identity=identity),self.assertRaises(ContractViolation) as c:f.prepare(m,p)
            self.assertEqual(c.exception.code,"REPLAY_OR_EQUIVOCATION")

    def test_split_validation_defensively_retains_event_bytes(self):
        f=Fixture();m=f.start();p=f.packet(m,1)
        m.validate_event(canonical_bytes(p.event),canonical_bytes(p.payload),p.evidence,p.witness,
                         selections=PublicSelections(p.selections),sample=f.sample(4))
        p.event["record_id"]="mutated-after-validation"
        m.prepare_ack(p.ack,p.ack_envelope,sample=f.sample(4))
        f.commit(m,"ACK_EXPOSURE",1,p.ack["record_sha256"],p.ack["retention_commit_id"],4)
        self.assertEqual(m.accepted[0]["event"]["record_id"],"e01")

    def test_creation_requires_no_future_runner_or_model_selection(self):
        f=Fixture();m=f.through(11);p=f.packet(m,12)
        self.assertEqual(set(p.selections),{"controller","channel","subject_id"})
        f.prepare(m,p)
        self.assertEqual(m.inspect().accepted_record_count,11)
        self.assertEqual(m.inspect().phase,"PREPARED")

    def test_policy_validates_before_seal_exists(self):
        f=Fixture();m=f.through(17);p=f.packet(m,18);f.prepare(m,p)
        self.assertEqual(m.inspect().accepted_record_count,17)
        self.assertEqual(m.inspect().phase,"PREPARED")

    def test_seal_validates_before_own_checkpoint(self):
        f=Fixture();m=f.through(18);p=f.packet(m,19);f.prepare(m,p)
        self.assertEqual(m.inspect().checkpoint_generation,20)
        self.assertEqual(m.inspect().accepted_record_count,18)

    def test_future_selection_fields_not_silently_consumed(self):
        f=Fixture();m=f.through(11);p=f.packet(m,12);p.selections["installations"]={}
        with self.assertRaises(ContractViolation):f.prepare(m,p)

    def test_unconfirmed_seal_cannot_support_decision(self):
        f=Fixture();m=f.through(18);p=f.packet(m,19);f.prepare(m,p)
        decision,env=f.decision(m)
        with self.assertRaises(ContractViolation):m.prepare_decision(decision,env,sample=f.sample(100),independently_observed_checkpoint=m.checkpoint)

    def test_prepared_ack_cannot_expose_without_checkpoint(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        with self.assertRaises(ContractViolation) as c:m.model_exposure(sample=f.sample(4))
        self.assertEqual(c.exception.code,"OUTPUT_NOT_CHECKPOINTED")
        self.assertEqual(m.inspect().accepted_record_count,0)

    def test_checkpoint_without_fresh_confirmation_cannot_expose(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        f.commit(m,"ACK_EXPOSURE",1,digest(canonical_bytes(p.event)),p.ack["retention_commit_id"],4,stop_after="checkpoint")
        with self.assertRaises(ContractViolation):m.model_exposure(sample=f.sample(4))

    def test_missing_checkpoint_readback_fails_closed(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        f.commit(m,"ACK_EXPOSURE",1,digest(canonical_bytes(p.event)),p.ack["retention_commit_id"],4,stop_after="checkpoint")
        with self.assertRaises(ContractViolation) as c:m.confirm_current(None,before=f.sample(4),after=f.sample(4))
        self.assertEqual(c.exception.code,"CHECKPOINT_ADVANCE_UNCONFIRMED")

    def test_altered_checkpoint_output_rejected(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,digest(canonical_bytes(p.event)),p.ack["retention_commit_id"],4)
        f.attempt(m,request,4)
        cp["consumer_prepare_commit_id"]="other-commit"
        with self.assertRaises(ContractViolation):m.record_checkpoint(request,cp,env,before=f.sample(4),after=f.sample(4))

    def test_wrong_previous_generation_rejected(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,digest(canonical_bytes(p.event)),p.ack["retention_commit_id"],4)
        request["expected_generation"]=0
        with self.assertRaises(ContractViolation):m.prepare_checkpoint(canonical_bytes(request),sample=f.sample(4))

    def test_ambiguous_checkpoint_can_only_recover_exact_pending_bytes(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p);pending=m.pending_output
        request,cp,env=f.checkpoint_packet(m.checkpoint,pending,"ACK_EXPOSURE",1,digest(canonical_bytes(p.event)),p.ack["retention_commit_id"],4)
        f.attempt(m,request,4)
        m.mark_checkpoint_response_unknown()
        m.recover_checkpoint(request,cp,env,before=f.sample(4),after=f.sample(4))
        self.assertEqual(pending,m.pending_output)
        m.confirm_current(cp,before=f.sample(4),after=f.sample(4));m.model_exposure(sample=f.sample(4))
        self.assertEqual(m.inspect().accepted_record_count,1)

    def test_ambiguous_recovery_cannot_change_commit_identity(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,digest(canonical_bytes(p.event)),p.ack["retention_commit_id"],4)
        f.attempt(m,request,4)
        m.mark_checkpoint_response_unknown();cp["consumer_prepare_commit_id"]="reminted"
        with self.assertRaises(ContractViolation):m.recover_checkpoint(request,cp,env,before=f.sample(4),after=f.sample(4))

    def test_rollback_without_retained_pending_output_cannot_reconstruct(self):
        with self.assertRaises(ContractViolation):require_recovery_match(None,None,{})

    def test_existing_independent_claim_blocks_new_reservation(self):
        f=Fixture();existing=f.start().checkpoint;fresh=f.new_model()
        request,cp,env=f.checkpoint_packet(None,{"kind":"NONE","body_ref":None,"attestation_ref":None},"SETUP_RESERVATION",0,ZERO,"again",0)
        with self.assertRaises(ContractViolation):fresh.prepare_reservation(canonical_bytes(request),before=f.sample(0),after=f.sample(0),initial_view=f.initial_view("PRESENT",existing))

    def test_unavailable_initial_read_is_not_absence(self):
        f=Fixture();m=f.new_model()
        request,cp,env=f.checkpoint_packet(None,{"kind":"NONE","body_ref":None,"attestation_ref":None},"SETUP_RESERVATION",0,ZERO,"reserve",0)
        with self.assertRaises(ContractViolation) as c:
            m.prepare_reservation(canonical_bytes(request),before=f.sample(0),after=f.sample(0),initial_view=f.initial_view("UNAVAILABLE"))
        self.assertEqual(c.exception.code,"CHECKPOINT_AUTHORITY_UNAVAILABLE")

    def test_missing_initial_view_cannot_infer_an_empty_store(self):
        f=Fixture();m=f.new_model()
        request,cp,env=f.checkpoint_packet(None,{"kind":"NONE","body_ref":None,"attestation_ref":None},"SETUP_RESERVATION",0,ZERO,"reserve",0)
        with self.assertRaises(ContractViolation):
            m.prepare_reservation(canonical_bytes(request),before=f.sample(0),after=f.sample(0),initial_view=None)

    def test_decision_checkpoint_cannot_precede_decision_prepare(self):
        f=Fixture();m=f.through(19)
        request,cp,env=f.checkpoint_packet(m.checkpoint,{"kind":"NONE","body_ref":None,"attestation_ref":None},"DECISION_EXPOSURE",19,m.inspect().retained_head_sha256,"not-prepared",100)
        with self.assertRaises(ContractViolation):m.record_checkpoint(request,cp,env,before=f.sample(100),after=f.sample(100))

    def test_failed_predecessor_cannot_continue_to_policy(self):
        f=Fixture();m=f.through(12);p=f.packet(m,13);p.payload["syscalls"][-1]["return_value"]=-1;f.repack(p)
        with self.assertRaises(ContractViolation):f.prepare(m,p)
        policy=f.packet(m,18)
        with self.assertRaises(ContractViolation):f.prepare(m,policy)
        self.assertEqual(m.inspect().accepted_record_count,12)

    def test_original_key_excludes_replaced_epoch_source_config(self):
        f=Fixture();changed=copy.deepcopy(f.binding);changed["scope"].update(epoch=2,source_manifest_sha256=h("new-source"),config_sha256=h("new-config"))
        self.assertEqual(original_key(f.binding),original_key(changed))

    def test_guard_expiry_after_blocking_read_prevents_acceptance(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,digest(canonical_bytes(p.event)),p.ack["retention_commit_id"],4)
        f.attempt(m,request,4)
        with self.assertRaises(ContractViolation):m.record_checkpoint(request,cp,env,before=f.sample(4),after=f.sample(180))
        self.assertEqual(m.inspect().accepted_record_count,0)

    def test_output_expiry_at_final_guard_prevents_exposure(self):
        f=Fixture();m=f.start();p=f.packet(m,1);f.prepare(m,p)
        f.commit(m,"ACK_EXPOSURE",1,digest(canonical_bytes(p.event)),p.ack["retention_commit_id"],4,stop_after="confirm")
        with self.assertRaises(ContractViolation):m.model_exposure(sample=f.sample(170))

    def test_stream_replay_gap_and_chain_mismatch_rejected(self):
        for field,value in [("sequence",3),("previous_record_sha256","e"*64),("record_id","e01")]:
            f=Fixture();m=f.through(1);p=f.packet(m,2);p.event[field]=value;f.repack(p)
            with self.subTest(field=field),self.assertRaises(ContractViolation):f.prepare(m,p)

    def test_wrong_decoder_pin_rejected(self):
        f=Fixture();m=f.start();p=f.packet(m,1)
        p.evidence=PublicEvidence(f.contract,p.evidence.snapshot(),decoder_sha256=h("unselected-decoder"))
        with self.assertRaises(ContractViolation) as c:f.prepare(m,p)
        self.assertEqual(c.exception.code,"DECODER_UNAVAILABLE")

    def test_noncalibration_subject_is_bound_to_selected_slot(self):
        f=Fixture();m=f.start();p=f.packet(m,1);p.selections["subject_id"]="unselected-subject"
        with self.assertRaises(ContractViolation) as c:f.prepare(m,p)
        self.assertEqual(c.exception.code,"CONTEXT_MISMATCH")

    def test_decision_cannot_extend_dependency_expiry(self):
        f=Fixture();m=f.through(19);decision,env=f.decision(m);decision["expires"]=stamp(175)
        with self.assertRaises(ContractViolation):m.prepare_decision(decision,env,sample=f.sample(100),independently_observed_checkpoint=m.checkpoint)

    def test_decision_requires_current_independent_checkpoint(self):
        f=Fixture();m=f.through(19);decision,env=f.decision(m)
        with self.assertRaises(ContractViolation) as c:
            m.prepare_decision(decision,env,sample=f.sample(100),independently_observed_checkpoint=None)
        self.assertEqual(c.exception.code,"CHECKPOINT_ADVANCE_UNCONFIRMED")

    def test_pending_witness_expiry_checked_before_checkpoint(self):
        f=Fixture();m=f.start();p=f.packet(m,1);p.witness["body"]["expires"]=stamp(5);f.prepare(m,p)
        request,cp,env=f.checkpoint_packet(m.checkpoint,m.pending_output,"ACK_EXPOSURE",1,digest(canonical_bytes(p.event)),p.ack["retention_commit_id"],4)
        f.attempt(m,request,4)
        cp["checkpointed_at"]=stamp(6);env=f.envelope(cp,"checkpoint","policy-inheritance-checkpoint-v2",6,"cp-attestation-3")
        with self.assertRaises(ContractViolation) as c:
            m.record_checkpoint(request,cp,env,before=f.sample(4),after=f.sample(6))
        self.assertEqual(c.exception.code,"AUTHENTICATED_INTERVAL_EXPIRED")

    def test_retained_records_are_defensive_copies(self):
        f=Fixture();m=f.through(1);value=m.accepted;value[0]["event"]["record_id"]="changed"
        self.assertEqual(m.accepted[0]["event"]["record_id"],"e01")

    def test_failure_record_ends_incomplete_prefix(self):
        f=Fixture();m=f.through(1);p=f.packet(m,2)
        p.event.update(kind="FAILURE",slot_id="terminal-failure",origin="CONTROLLER",evidence_class="CONTROLLER_STREAM_METADATA")
        p.payload={"failed_slot_id":"slot-e02","code":"RAW_EVIDENCE_UNAVAILABLE","last_retained_record_id":"e01",
                   "authority_created":False,"cleanup_status":"UNKNOWN"};f.repack(p)
        m.record_failure(canonical_bytes(p.event),canonical_bytes(p.payload),p.evidence,p.witness,sample=f.sample(6))
        self.assertTrue(m.inspect().terminal);self.assertEqual(m.inspect().accepted_record_count,1)
        with self.assertRaises(ContractViolation):f.advance(m,2)
