import copy
import unittest

from policy_inheritance.contract import canonical_bytes, decode_canonical, digest
from policy_inheritance.errors import ContractViolation
from support import Fixture


class SemanticTests(unittest.TestCase):
    def rejection(self,sequence,mutate,expected=None):
        f=Fixture();m=f.through(sequence-1);p=f.packet(m,sequence);mutate(f,p);f.repack(p)
        with self.assertRaises(ContractViolation) as caught:f.prepare(m,p)
        if expected:self.assertEqual(caught.exception.code,expected)
        self.assertTrue(m.inspect().terminal)
        self.assertEqual(m.inspect().accepted_record_count,sequence-1)

    def test_bad_mac_cannot_be_labelled_accepted(self):
        self.rejection(4,lambda f,p:p.payload["exchanges"][0].update(verdict="ACCEPTED_INERT"),"CALIBRATION_UNEXPECTED_OUTCOME")

    def test_wrong_pid_requires_actual_foreign_credentials(self):
        self.rejection(10,lambda f,p:p.payload["exchanges"][0].update(actual_ucred={"pid":7001,"uid":1000,"gid":1000}))

    def test_replay_requires_identical_packet_and_frames(self):
        def mutate(f,p):
            x=p.payload["exchanges"][1]
            send=decode_canonical(f.objects[x["sent_record_ref"]["object_id"]]);recv=decode_canonical(f.objects[x["recv_record_ref"]["object_id"]])
            packet=b"CHANGED-PACKET";frames=b"CHANGED-FRAMES"
            send.update(application_hex=packet.hex(),frames_hex=frames.hex(),return_value=len(frames))
            recv.update(frames_hex=frames.hex(),return_value=len(frames))
            x.update(sent_record_ref=f.put(send,"IPC_SEND"),recv_record_ref=f.put(recv,"IPC_RECEIVE"),
                     sent_application_packet_sha256=digest(packet),sent_frames_sha256=digest(frames),received_frames_sha256=digest(frames),
                     send_return=len(frames),recv_return=len(frames))
        self.rejection(5,mutate,"CALIBRATION_REPLAY_NOT_DEMONSTRATED")

    def test_rights_require_nonempty_actual_delivery(self):
        def mutate(f,p):
            x=p.payload["exchanges"][0];recv=decode_canonical(f.objects[x["recv_record_ref"]["object_id"]]);recv["delivered_fds"]=[]
            x.update(delivered_fds=[],close_outcomes=[],recv_record_ref=f.put(recv,"IPC_RECEIVE"))
        self.rejection(8,mutate,"CALIBRATION_EMPTY_RIGHTS")

    def test_each_delivered_descriptor_requires_close(self):
        self.rejection(8,lambda f,p:p.payload["exchanges"][0].update(close_outcomes=[]),"CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE")

    def test_truncated_rights_require_actual_ctrunc(self):
        def mutate(f,p):
            x=p.payload["exchanges"][0];recv=decode_canonical(f.objects[x["recv_record_ref"]["object_id"]]);recv["msg_ctrunc"]=False
            x.update(msg_ctrunc=False,recv_record_ref=f.put(recv,"IPC_RECEIVE"))
        self.rejection(9,mutate,"CALIBRATION_BASELINE_MISMATCH")

    def test_unclosed_challenger_cannot_retire(self):
        self.rejection(11,lambda f,p:p.payload.update(remaining_challenger_descendants=1))

    def test_wrong_retired_sender_cannot_be_substituted(self):
        self.rejection(11,lambda f,p:p.payload.update(challenger_identity=f.expected_peer),"CLEANUP_UNCONFIRMED")

    def test_creation_cannot_reuse_calibration_channel(self):
        def mutate(f,p):
            channel=copy.deepcopy(p.selections["channel"]);channel["channel_id"]="channel-c01"
            p.selections["channel"]=channel;p.payload.update(channel_id=channel["channel_id"],endpoint_inventory_ref=f.put(channel,"DESCRIPTOR_INVENTORY"))
        self.rejection(12,mutate,"AUTHORITY_CREATED_EARLY")

    def test_creation_cannot_be_before_retirement(self):
        def mutate(f,p):
            channel=copy.deepcopy(p.selections["channel"]);channel["created_at"]=p.event["observed_start"]=p.event["observed_end"]={"utc":"2026-10-11T08:00:29.000000Z","boottime_ns":1_029_000_000_000}
            p.selections["channel"]=channel;p.payload["endpoint_inventory_ref"]=f.put(channel,"DESCRIPTOR_INVENTORY")
        self.rejection(12,mutate,"AUTHORITY_CREATED_EARLY")

    def test_installation_missing_descriptor_rejected(self):
        self.rejection(13,lambda f,p:p.payload["initial_descriptors"].pop(),"DESCRIPTOR_IDENTITY_MISMATCH")

    def test_model_supplied_descriptor_plan_cannot_be_selected(self):
        def mutate(f,p):
            selected=p.selections["installations"]["RUNNER_INSTALL"]
            selected["descriptor_plan"]["selection_origin"]="MODEL_SUPPLIED"
            p.payload["expected_descriptor_plan_ref"]=f.put(selected["descriptor_plan"],"DESCRIPTOR_INVENTORY")
        self.rejection(13,mutate,"DESCRIPTOR_IDENTITY_MISMATCH")

    def test_installation_same_fd_different_object_rejected(self):
        def mutate(f,p):p.payload["initial_descriptors"][0]["inode"]+=1
        self.rejection(13,mutate,"DESCRIPTOR_IDENTITY_MISMATCH")

    def test_installation_single_thread_identity_required(self):
        def mutate(f,p):p.payload["threads"][0]["tid"]+=1
        self.rejection(13,mutate,"INSTALLATION_FAILED_OR_UNOBSERVED")

    def test_parent_start_identity_is_read_from_raw(self):
        def mutate(f,p):
            index=next(i for i,r in enumerate(p.event["raw_refs"]) if r["artifact_kind"]=="PROC_IDENTITY")
            value=decode_canonical(f.objects[p.event["raw_refs"][index]["object_id"]]);value["parent"]["start_ticks"]+=1
            p.event["raw_refs"][index]=f.put(value,"PROC_IDENTITY")
        self.rejection(14,mutate,"SOURCE_OR_EXEC_IDENTITY_MISMATCH")

    def test_all_rule_adds_required(self):
        self.rejection(13,lambda f,p:p.payload["syscalls"].pop(2),"INSTALLATION_FAILED_OR_UNOBSERVED")

    def test_failed_ruleset_creation_rejected(self):
        def mutate(f,p):p.payload["syscalls"][1].update(return_value=-1,errno=22)
        self.rejection(13,mutate,"INSTALLATION_FAILED_OR_UNOBSERVED")

    def test_failed_restriction_rejected(self):
        def mutate(f,p):p.payload["syscalls"][-1].update(return_value=-1,errno=1)
        self.rejection(14,mutate,"INSTALLATION_FAILED_OR_UNOBSERVED")

    def test_nnp_must_precede_restriction(self):
        def mutate(f,p):p.payload["syscalls"][-2:]=reversed(p.payload["syscalls"][-2:])
        self.rejection(13,mutate,"INSTALLATION_FAILED_OR_UNOBSERVED")

    def test_raw_bool_is_not_success_integer(self):
        def mutate(f,p):
            i=next(i for i,r in enumerate(p.event["raw_refs"]) if r["artifact_kind"]=="INSTALL_ARGUMENTS")
            value=decode_canonical(f.objects[p.event["raw_refs"][i]["object_id"]]);value["no_new_privs"]=True
            p.event["raw_refs"][i]=f.put(value,"INSTALL_ARGUMENTS")
        self.rejection(13,mutate,"INSTALLATION_FAILED_OR_UNOBSERVED")

    def test_selected_policy_cannot_be_widened(self):
        def mutate(f,p):
            value=decode_canonical(f.objects[p.payload["normalized_rules_ref"]["object_id"]]);value[0]["rights"]=3
            p.payload["normalized_rules_ref"]=f.put(value,"NORMALIZED_RULES")
        self.rejection(13,mutate,"INSTALLATION_FAILED_OR_UNOBSERVED")

    def test_asset_actual_hashes_must_match(self):
        def mutate(f,p):
            value=copy.deepcopy(f.assets);value[0]["sha256"]="f"*64
            p.payload["actual_file_inventory_ref"]=f.put(value,"ASSET_INVENTORY")
        self.rejection(15,mutate,"SOURCE_OR_EXEC_IDENTITY_MISMATCH")

    def test_prebudget_asset_hash_interval_rejected(self):
        from support import stamp
        self.rejection(15,lambda f,p:p.payload.update(hash_scan_started=stamp(-1)),"CONTEXT_MISMATCH")

    def test_postexec_pid_reuse_rejected(self):
        def mutate(f,p):p.payload["actual_server_identity"]["start_ticks"]+=1
        self.rejection(16,mutate,"SOURCE_OR_EXEC_IDENTITY_MISMATCH")

    def test_postexec_actual_executable_required(self):
        def mutate(f,p):p.payload["actual_server_identity"]["exe_inode"]+=1
        self.rejection(16,mutate,"SOURCE_OR_EXEC_IDENTITY_MISMATCH")

    def test_postexec_owned_listener_required(self):
        def mutate(f,p):
            value=copy.deepcopy(f.listener);value["process"]=f.runner
            p.payload["owned_listener_ref"]=f.put(value,"LISTENER_IDENTITY")
        self.rejection(16,mutate,"SOURCE_OR_EXEC_IDENTITY_MISMATCH")

    def test_peer_actual_credentials_required(self):
        self.rejection(17,lambda f,p:p.payload.update(actual_ucred=[7001,1000,1000]),"SOURCE_OR_EXEC_IDENTITY_MISMATCH")

    def test_peer_mac_mismatch_not_creation_success(self):
        def mutate(f,p):
            value=copy.deepcopy(f.first_packet);value["mac_valid"]=False
            p.payload["first_packet_ref"]=f.put(value,"IPC_RECEIVE")
        self.rejection(17,mutate,"CONTEXT_MISMATCH")

    def test_peer_missing_actual_readback_rejected(self):
        self.rejection(17,lambda f,p:p.event.update(raw_refs=[]),"RAW_EVIDENCE_UNAVAILABLE")

    def test_policy_cannot_substitute_selected_argument(self):
        def mutate(f,p):
            value=dict(f.argument,extra="broader claim")
            p.payload["source_argument_ref"]=f.put(value,"SOURCE_ARGUMENT")
        self.rejection(18,mutate,"CLAIM_OUTSIDE_METHOD_SCOPE")

    def test_policy_broad_claim_rejected(self):
        self.rejection(18,lambda f,p:p.payload.update(claim="EVERY_TASK_DENIED"))

    def test_policy_unsupported_routes_cannot_be_removed(self):
        self.rejection(18,lambda f,p:p.payload["unsupported_routes"].pop(),"UNSUPPORTED_ROUTE_RELABELED")

    def test_seal_cannot_include_itself(self):
        def mutate(f,p):p.payload["entries"][-1].update(sequence=19,record_id="e19",record_sha256="f"*64)
        self.rejection(19,mutate,"INCOMPLETE_STREAM")

    def test_seal_wrong_prior_head_rejected(self):
        self.rejection(19,lambda f,p:p.payload.update(previous_head_sha256="e"*64),"INCOMPLETE_STREAM")

    def test_seal_missing_predecessor_rejected(self):
        self.rejection(19,lambda f,p:p.payload["entries"].pop())
