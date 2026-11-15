"""Authored public graph/predicate regressions. NOT_RUN, not Linux evidence."""
from copy import deepcopy
from unittest import TestCase
from cas_forex_operational_contracts.common import canonical_bytes, digest, decode_canonical
from cas_forex_authority.authentication import AuthorityError, ref
from cas_forex_authority.semantic_verifier import _Predicates, _Graph, _child_descriptor, BASELINES
from semantic_fixtures import begin_graph, accept_begin, calibration_case, PredicateEvidence
from support import stamp


class AuthenticatedGraphTests(TestCase):
    def test_public_fake_decoder_graph_requires_recomputation(self):
        g=begin_graph(); returned=accept_begin(g)
        self.assertEqual(g.state.decoder_calls,1)
        self.assertTrue(all((r,g.evidence.resolve(r)) in returned for r in g.event["raw_refs"]))

    def test_repeated_validation_recomputes_instead_of_caching_pass(self):
        g=begin_graph(); accept_begin(g); accept_begin(g)
        self.assertEqual(g.state.decoder_calls,2)

    def test_tampered_payload_bytes_fail(self):
        g=begin_graph();g.evidence.rows[canonical_bytes(g.event["payload_ref"])]=b"{}"
        with self.assertRaises(AuthorityError):accept_begin(g)

    def test_valid_witness_graph_cannot_override_recomputed_bytes(self):
        g=begin_graph();g.state.bad_return=True
        with self.assertRaises(AuthorityError):accept_begin(g)
        self.assertEqual(g.state.decoder_calls,1)

    def test_missing_derived_artifact_rejects(self):
        g=begin_graph();g.state.artifacts=g.state.artifacts[1:]
        with self.assertRaises(AuthorityError):accept_begin(g)

    def test_missing_derived_binding_rejects(self):
        g=begin_graph();g.state.bindings=g.state.bindings[1:]
        with self.assertRaises(AuthorityError):accept_begin(g)

    def test_missing_input_envelope_rejects(self):
        g=begin_graph();del g.evidence.rows[canonical_bytes(g.event["input_bundle_envelope_ref"])]
        with self.assertRaises(Exception):accept_begin(g)
        self.assertEqual(g.state.decoder_calls,0)

    def test_forged_event_signature_rejects_before_decoder(self):
        g=begin_graph(); key=digest(canonical_bytes(g.event));e=decode_canonical(g.event_envelopes[key]);e["signature_hex"]="00"*64
        g.event_envelopes[key]=canonical_bytes(e)
        with self.assertRaises(AuthorityError):accept_begin(g)
        self.assertEqual(g.state.decoder_calls,0)

    def test_rebound_decoder_component_rejects(self):
        g=begin_graph(); from dataclasses import replace
        g.verifier.selection=replace(g.verifier.selection,decoder_component_sha256="e"*64)
        with self.assertRaises(AuthorityError):accept_begin(g)
        self.assertEqual(g.state.decoder_calls,0)

    def test_unavailable_decoder_does_not_accept_signature_alone(self):
        g=begin_graph();g.verifier.decoder_factory=None
        with self.assertRaises(AuthorityError):accept_begin(g)

    def test_expired_graph_cannot_reuse_prior_acceptance(self):
        g=begin_graph();accept_begin(g);g.f.clock.now=stamp(180)
        with self.assertRaises(AuthorityError):accept_begin(g)

    def test_seal_needs_all_nineteen_exact_events(self):
        g=begin_graph()
        with self.assertRaises(AuthorityError):
            g.verifier.validate_sealed(accepted_raw=(canonical_bytes(g.event),),plan_raw=canonical_bytes(g.f.plan),budget_raw=canonical_bytes(g.f.budget),now=g.f.guard.check())

    def test_future_event_is_not_an_accepted_predecessor(self):
        g=begin_graph();graph=_Graph(g.verifier,g.event,(),{}, {})
        with self.assertRaises(AuthorityError):graph.accepted_event(ref(canonical_bytes(g.event),"EVENT_RECORD"),now=g.f.guard.check())

    def test_nested_ref_must_have_authenticated_or_recomputed_provenance(self):
        g=begin_graph(); graph=_Graph(g.verifier,g.event,(),{}, {})
        bare=g.evidence.add("NATIVE_CAPTURE_BYTES",{"untrusted":"bare bytes"})
        with self.assertRaises(AuthorityError):graph.walk(bare,set(),0)

    def test_spawn_inheritance_clears_cloexec_and_binds_child_fd(self):
        parent={"fd":70,"object_type":"PIPE","device":1,"inode":2,"access_flags":0,"close_on_exec":True,"selected_target_id":"stdout"}
        actual=_child_descriptor({"object_identity":parent,"child_fd":1,"target_id":"stdout"})
        self.assertEqual(actual,{**parent,"fd":1,"close_on_exec":False})
        self.assertTrue(parent["close_on_exec"])


class CalibrationPredicateTests(TestCase):
    def check_case(self,g):_Predicates(g.coverage,g.selected)._calibration(g.event,g.payload,g.evidence,g.accepted)

    def test_all_eight_fixed_public_baselines_have_positive_predicate_sources(self):
        for kind in BASELINES:
            with self.subTest(kind=kind):self.check_case(calibration_case(kind))

    def test_each_baseline_rejects_wrong_reported_verdict(self):
        for kind in BASELINES:
            with self.subTest(kind=kind):
                g=calibration_case(kind);g.payload["exchanges"][0]["verdict"]="AUTH_REJECTED" if kind=="POSITIVE_INERT" else "ACCEPTED_INERT"
                if kind=="BAD_SEQUENCE":g.payload["exchanges"][0]["verdict"]="AUTH_REJECTED"
                with self.assertRaises(AuthorityError):self.check_case(g)

    def test_replay_requires_two_identical_packets(self):
        g=calibration_case("BAD_SEQUENCE");g.payload["exchanges"][1]["sent_application_packet_sha256"]="f"*64
        with self.assertRaises(AuthorityError):self.check_case(g)

    def test_replay_cannot_reset_receiver_sequence(self):
        g=calibration_case("BAD_SEQUENCE");g.payload["exchanges"][1]["recv_seq_before"]=0
        with self.assertRaises(AuthorityError):self.check_case(g)

    def test_rights_cases_require_nonempty_actual_delivery(self):
        for kind in ("DELIVERED_RIGHTS","TRUNCATED_RIGHTS"):
            with self.subTest(kind=kind):
                g=calibration_case(kind);g.payload["exchanges"][0]["delivered_fds"]=[]
                with self.assertRaises(AuthorityError):self.check_case(g)

    def test_every_delivered_descriptor_needs_exact_close(self):
        g=calibration_case("DELIVERED_RIGHTS");g.payload["exchanges"][0]["close_outcomes"]=[]
        with self.assertRaises(AuthorityError):self.check_case(g)

    def test_duplicate_close_cannot_cover_one_descriptor(self):
        g=calibration_case("DELIVERED_RIGHTS");x=g.payload["exchanges"][0];x["close_outcomes"]*=2
        with self.assertRaises(AuthorityError):self.check_case(g)

    def test_close_must_precede_verdict(self):
        g=calibration_case("DELIVERED_RIGHTS");close=g.payload["exchanges"][0]["close_outcomes"][0]
        value=g.evidence.object(close["raw_close_ref"],kind="DESCRIPTOR_CLOSES");value["operation_index"]=100
        close["raw_close_ref"]=g.evidence.add("DESCRIPTOR_CLOSES",value)
        with self.assertRaises(AuthorityError):self.check_case(g)

    def test_wrong_peer_is_actual_distinct_pid_same_uid_gid(self):
        g=calibration_case("WRONG_PEER_PID");g.payload["expected_peer_identity"]=g.selected["calibration"]["foreign_sender"]
        with self.assertRaises(AuthorityError):self.check_case(g)

    def test_missing_credentials_only_allowed_for_truncated_rights(self):
        g=calibration_case("POSITIVE_INERT");g.payload["exchanges"][0]["actual_ucred"]=None
        with self.assertRaises(AuthorityError):self.check_case(g)

    def test_mac_gate_cannot_be_replaced_by_framing_failure(self):
        g=calibration_case("BAD_MAC");g.payload["exchanges"][0]["rejection_stage"]="FRAME"
        with self.assertRaises(AuthorityError):self.check_case(g)

    def test_calibration_endpoint_reuse_rejects(self):
        g=calibration_case("BAD_MAC");prior={"event":{"kind":"CALIBRATION_CASE"},"payload":deepcopy(g.payload)}
        g.accepted+=(prior,)
        with self.assertRaises(AuthorityError):self.check_case(g)


class InstallationPredicateTests(TestCase):
    def fixture(self):
        from semantic_fixtures import installation_case
        return installation_case()
    def check(self,g):_Predicates(g.coverage,g.selected)._installation(g.event,g.payload,g.evidence,g.accepted)

    def test_selected_parent_mapping_and_full_target_identity_satisfy_pure_predicates(self):self.check(self.fixture())

    def test_successful_syscall_name_with_failed_return_rejects(self):
        g=self.fixture();g.payload["syscalls"][-1]["return_value"]=-1
        with self.assertRaises(AuthorityError):self.check(g)

    def test_no_new_privs_truth_flag_does_not_replace_actual_readback(self):
        g=self.fixture();g.evidence.direct["INSTALL_ARGUMENTS"]["no_new_privs"]=0
        with self.assertRaises(AuthorityError):self.check(g)

    def test_second_thread_rejects(self):
        g=self.fixture();g.payload["threads"].append({"tid":21,"start_ticks":201})
        with self.assertRaises(AuthorityError):self.check(g)

    def test_same_fd_number_different_inode_rejects(self):
        g=self.fixture();g.payload["initial_descriptors"]=deepcopy(g.payload["initial_descriptors"]);g.payload["initial_descriptors"][0]["inode"]+=1
        with self.assertRaises(AuthorityError):self.check(g)

    def test_target_name_alone_cannot_replace_actual_inode_and_path(self):
        g=self.fixture();call=g.payload["syscalls"][2]
        call["arguments_ref"]=g.evidence.add("INSTALL_ARGUMENTS",{"ruleset_fd":50,"target":"models","rights":1})
        with self.assertRaises(AuthorityError):self.check(g)

    def test_wrong_parent_start_identity_rejects(self):
        g=self.fixture();g.evidence.spawn=deepcopy(g.evidence.spawn);g.evidence.spawn["parent"]["start_ticks"]+=1
        with self.assertRaises(AuthorityError):self.check(g)

    def test_reordered_no_new_privs_and_restrict_rejects(self):
        g=self.fixture();g.payload["syscalls"][-2:]=reversed(g.payload["syscalls"][-2:])
        with self.assertRaises(AuthorityError):self.check(g)

    def test_rule_rights_must_match_selected_policy(self):
        g=self.fixture();g.payload["normalized_rules_ref"]=g.evidence.add("NORMALIZED_RULES",[{"target_id":"models","rights":2}])
        with self.assertRaises(AuthorityError):self.check(g)

    def test_no_new_privs_observation_before_restriction_rejects(self):
        g=self.fixture();g.evidence.direct["INSTALL_ARGUMENTS"]["observed"]=stamp()
        with self.assertRaises(AuthorityError):self.check(g)


class SealPredicateTests(TestCase):
    def fixture(self):
        from semantic_fixtures import seal_case
        return seal_case()
    def check(self,g):_Predicates(g.coverage,g.selected).validate(g.event,g.payload,g.evidence,g.accepted,now=stamp(20))

    def test_current_seal_uses_eighteen_prior_records(self):self.check(self.fixture())

    def test_seal_cannot_claim_its_own_hash_as_already_accepted(self):
        g=self.fixture();g.payload["covered_slot_ids"].append("s18")
        with self.assertRaises(Exception):self.check(g)

    def test_stale_prefix_head_rejects(self):
        g=self.fixture();g.payload["previous_head_sha256"]="f"*64
        with self.assertRaises(AuthorityError):self.check(g)

    def test_same_record_ids_with_changed_prefix_hash_rejects(self):
        g=self.fixture();g.payload["entries"][3]["record_sha256"]="f"*64
        with self.assertRaises(AuthorityError):self.check(g)

    def test_duplicate_prefix_slot_rejects(self):
        g=self.fixture();g.payload["covered_slot_ids"][3]=g.payload["covered_slot_ids"][2]
        with self.assertRaises(Exception):self.check(g)


class PostExecAndPeerTests(TestCase):
    def post(self):
        from semantic_fixtures import post_exec_case
        return post_exec_case()
    def peer(self):
        from semantic_fixtures import peer_case
        return peer_case()
    def check_post(self,g):_Predicates(g.coverage,g.selected)._post_exec(g.event,g.payload,g.evidence,g.accepted)
    def check_peer(self,g):_Predicates(g.coverage,g.selected)._peer(g.event,g.payload,g.evidence,g.accepted,stamp(7))

    def test_exact_exec_lineage_and_listener_satisfy_pure_predicates(self):self.check_post(self.post())
    def test_exact_current_peer_and_retained_socket_satisfy_pure_predicates(self):self.check_peer(self.peer())

    def test_pid_reuse_after_exec_rejects(self):
        g=self.post();g.payload["actual_server_identity"]=deepcopy(g.payload["actual_server_identity"]);g.payload["actual_server_identity"]["start_ticks"]+=1
        with self.assertRaises(AuthorityError):self.check_post(g)

    def test_executable_same_path_different_content_rejects(self):
        g=self.post();g.selected["assets"][0]["sha256"]="e"*64
        with self.assertRaises(AuthorityError):self.check_post(g)

    def test_listener_owned_by_wrong_process_rejects(self):
        g=self.post();value=g.evidence.object(g.payload["owned_listener_ref"],kind="LISTENER_IDENTITY");value["process"]["pid"]+=1
        g.payload["owned_listener_ref"]=g.evidence.add("LISTENER_IDENTITY",value)
        with self.assertRaises(AuthorityError):self.check_post(g)

    def test_final_peer_receiver_identity_cannot_substitute_sender(self):
        g=self.peer();packet=g.evidence.object(g.payload["first_packet_ref"],kind="IPC_RECEIVE");packet["owner"]=g.selected["channel"]["owner"]
        reference=g.evidence.add("IPC_RECEIVE",packet);g.payload["first_packet_ref"]=reference;g.selected["peer"]["first_packet_ref"]=reference
        with self.assertRaises(AuthorityError):self.check_peer(g)

    def test_final_peer_same_fd_different_socket_inode_rejects(self):
        g=self.peer();g.evidence.direct["PROC_IDENTITY"]["descriptor"]["inode"]+=1
        with self.assertRaises(AuthorityError):self.check_peer(g)

    def test_final_peer_must_be_observed_after_model_post_exec(self):
        g=self.peer();g.evidence.direct["PROC_IDENTITY"]["observed"]=stamp(1)
        with self.assertRaises(AuthorityError):self.check_peer(g)

    def test_first_packet_mac_failure_rejects(self):
        g=self.peer();packet=g.evidence.object(g.payload["first_packet_ref"],kind="IPC_RECEIVE");packet["mac_valid"]=False
        reference=g.evidence.add("IPC_RECEIVE",packet);g.payload["first_packet_ref"]=reference;g.selected["peer"]["first_packet_ref"]=reference
        with self.assertRaises(AuthorityError):self.check_peer(g)


class RetirementTests(TestCase):
    def fixture(self):
        from semantic_fixtures import retired_case
        return retired_case()
    def check(self,g):_Predicates(g.coverage,g.selected).validate(g.event,g.payload,g.evidence,g.accepted,now=stamp(10))

    def test_all_actual_endpoints_and_actors_retired_satisfy_pure_predicates(self):self.check(self.fixture())

    def test_unclosed_endpoint_cannot_be_hidden_by_zero_count(self):
        g=self.fixture();raw=g.evidence.object(g.payload["endpoint_retirement_ref"],kind="ENDPOINT_RETIREMENT");raw["closed_endpoint_ids"].pop()
        g.payload["endpoint_retirement_ref"]=g.evidence.add("ENDPOINT_RETIREMENT",raw)
        with self.assertRaises(AuthorityError):self.check(g)

    def test_remaining_descendant_cannot_be_hidden_by_zero_count(self):
        g=self.fixture();raw=g.evidence.object(g.payload["process_retirement_ref"],kind="PROCESS_RETIREMENT");raw["remaining_descendants"]=[99]
        g.payload["process_retirement_ref"]=g.evidence.add("PROCESS_RETIREMENT",raw)
        with self.assertRaises(AuthorityError):self.check(g)

    def test_retirement_needs_actual_identity_not_pid_only(self):
        g=self.fixture();raw=g.evidence.object(g.payload["process_retirement_ref"],kind="PROCESS_RETIREMENT");raw["retired_identities"][0]["start_ticks"]+=1
        g.payload["process_retirement_ref"]=g.evidence.add("PROCESS_RETIREMENT",raw)
        with self.assertRaises(AuthorityError):self.check(g)


class FinalChannelAssetPolicyTests(TestCase):
    def check(self,g):_Predicates(g.coverage,g.selected).validate(g.event,g.payload,g.evidence,g.accepted,now=stamp(20))

    def test_channel_created_after_retirement_satisfies_pure_predicates(self):
        from semantic_fixtures import final_channel_case
        self.check(final_channel_case())

    def test_channel_created_before_retirement_rejects(self):
        from semantic_fixtures import final_channel_case
        g=final_channel_case();g.accepted[1]["event"]["recorded"]=stamp(12)
        with self.assertRaises(AuthorityError):self.check(g)

    def test_reusing_public_calibration_key_id_for_final_channel_rejects(self):
        from semantic_fixtures import final_channel_case
        g=final_channel_case();g.accepted[2]["payload"]["public_fixture_key_id"]="final-key"
        with self.assertRaises(AuthorityError):self.check(g)

    def test_exact_observed_asset_manifest_satisfies_pure_predicates(self):
        from semantic_fixtures import asset_case
        self.check(asset_case())

    def test_same_asset_path_with_changed_inode_rejects(self):
        from semantic_fixtures import asset_case
        g=asset_case();g.selected["assets"][0]["inode"]+=1
        with self.assertRaises(AuthorityError):self.check(g)

    def test_writable_asset_is_not_read_only_evidence(self):
        from semantic_fixtures import asset_case
        g=asset_case();g.selected["assets"][0]["read_only"]=False
        with self.assertRaises(AuthorityError):self.check(g)

    def test_narrow_source_argument_requires_seventeen_predecessors(self):
        from semantic_fixtures import policy_case
        self.check(policy_case())

    def test_incomplete_argument_prefix_rejects(self):
        from semantic_fixtures import policy_case
        g=policy_case();g.accepted=g.accepted[:-1]
        with self.assertRaises(AuthorityError):self.check(g)

    def test_argument_cannot_claim_every_task_post_exec_probes(self):
        from semantic_fixtures import policy_case
        g=policy_case();g.payload["every_task_post_exec_probes_claimed"]=True
        with self.assertRaises(Exception):self.check(g)

    def test_omitting_unsupported_route_rejects(self):
        from semantic_fixtures import policy_case
        g=policy_case();g.payload["unsupported_routes"]=g.payload["unsupported_routes"][:-1]
        with self.assertRaises(Exception):self.check(g)

    def test_self_selected_installation_policy_cannot_replace_external_pin(self):
        from types import SimpleNamespace
        from dataclasses import replace
        g=begin_graph()
        policy={"abi":4,"handled_fs":1,"rules":[{"target_id":"target","rights":1}],"targets":[{"target_id":"target","path":"/public","device":1,"inode":1,"object_type":"DIRECTORY"}]}
        raw=canonical_bytes(policy);reference=ref(raw,"CANONICAL_PAYLOAD")
        graph=SimpleNamespace(event={"kind":"RUNNER_INSTALL","slot_id":"s12"},selection={"values":{"installation":{**policy,"descriptors":[]}}},
            spawn={"selected_policy_sha256":digest(raw)},inputs={"selected_source_refs":[reference]})
        with self.assertRaises(AuthorityError):g.verifier._selection_rules(graph,{})
        g.verifier.selection=replace(g.verifier.selection,policies_by_slot=(("s12",raw),))
        g.verifier._selection_rules(graph,{})
        graph.selection["values"]["installation"]["handled_fs"]=3
        with self.assertRaises(AuthorityError):g.verifier._selection_rules(graph,{})
