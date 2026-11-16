"""Public-only contract regressions, no credentials or OS observations. NOT_RUN."""
import copy
import json
from pathlib import Path
import unittest
from cas_forex_operational_contracts import capture, checkpoint, completion, protected, release
from cas_forex_operational_contracts.common import ContractError, DependencyUnavailable, canonical_bytes, digest, ValidationLimits
from cas_forex_operational_contracts.validation import (
    verify_contract_bundle, verify_reference_bytes, ACCEPTED_FILE_PINS)

ROOT=Path(__file__).resolve().parents[2]
ACCEPTED=ROOT/"shared-interface"/"accepted-contracts"
def packet():
    return json.loads((ACCEPTED/"examples"/"role-release-evidence.json").read_text(encoding="utf-8"))
def ref(kind="NATIVE_CAPTURE_BYTES",raw=b"abc"):
    h=digest(raw)
    return {"object_id":h,"bytes":len(raw),"sha256":h,"artifact_kind":kind}
def public_fact():
    return {"format":"forex.retained-fact/2","binding":packet()["role_evidence"]["binding"],
            "record_id":"public-fact","kind":"CONTEXT","step_id":None,
            "payload_schema_sha256":"1"*64,"payload":{"public":True}}

class ContractBoundaryTests(unittest.TestCase):
    def test_pinned_bundle_requires_exact_files(self):
        with self.assertRaises(ContractError): verify_contract_bundle({})
    def test_one_byte_contract_change_rejected(self):
        files={name:(ACCEPTED/name).read_bytes() for name in ACCEPTED_FILE_PINS}
        files["method-contract.candidate.json"]+=b" "
        with self.assertRaises(ContractError): verify_contract_bundle(files)
    def test_reference_bytes_mismatch_rejected(self):
        with self.assertRaises(ContractError): verify_reference_bytes(ref(),b"abd")
    def test_reference_length_mismatch_rejected(self):
        with self.assertRaises(ContractError): verify_reference_bytes(ref(),b"abcx")
    def test_protected_ref_cannot_supply_path(self):
        value=packet()["role_evidence_use"]["reference"]; value["path"]="/" + "tmp/injected"
        with self.assertRaises(ContractError): protected.validate("ProtectedRecordRef",value)
    def test_missing_private_schema_fails_closed(self):
        with self.assertRaises(DependencyUnavailable): protected.validate("RetainedFact2",public_fact())
    def test_schema_callback_boolean_not_success(self):
        class Bad:
            def validate(self,**kwargs): return True
        with self.assertRaises(ContractError):
            protected.validate("RetainedFact2",public_fact(),shape_validator=Bad())
    def test_schema_callback_error_does_not_expose_private_detail(self):
        class Bad:
            def validate(self,**kwargs): raise ValueError("private-case-marker")
        with self.assertRaises(ContractError) as caught:
            protected.validate("RetainedFact2",public_fact(),shape_validator=Bad())
        self.assertNotIn("private-case-marker",str(caught.exception))
        self.assertEqual(caught.exception.code,"SELECTED_SCHEMA_REJECTED")
    def test_schema_callback_gets_only_byte_snapshots(self):
        seen=[]
        class PublicSchema:
            def validate(self,*,context,raw_value):
                seen.append((context,raw_value))
                value=json.loads(raw_value); value["public"]=False
        result=protected.validate("RetainedFact2",public_fact(),shape_validator=PublicSchema())
        self.assertTrue(result.payload()["payload"]["public"])
        self.assertIs(type(seen[0][1]),bytes)
        self.assertIs(type(seen[0][0].parent_raw),bytes)
    def test_narrow_body_has_shape_but_no_authority(self):
        result=release.validate("NarrowRoleReleaseEvidence1",packet()["role_evidence"])
        self.assertEqual(result.type_name,"NarrowRoleReleaseEvidence1")
        self.assertFalse(hasattr(result,"authenticated"))
    def test_narrow_expiry_mirror_mismatch_rejected(self):
        value=packet()["role_evidence"]; value["expires_at_utc"]="2030-01-01T00:02:59.000000Z"
        with self.assertRaises(ContractError): release.validate("NarrowRoleReleaseEvidence1",value)
    def test_narrow_extra_claim_rejected(self):
        value=packet()["role_evidence"]; value["accepted_claims"].append("BROAD_ISOLATION")
        with self.assertRaises(ContractError): release.validate("NarrowRoleReleaseEvidence1",value)
    def test_narrow_missing_unsupported_route_rejected(self):
        value=packet()["role_evidence"]; value["unsupported_routes"].pop()
        with self.assertRaises(ContractError): release.validate("NarrowRoleReleaseEvidence1",value)
    def test_narrow_cross_boot_parent_rejected(self):
        value=packet()["role_evidence"]; value["roles"]["decision_runner"]["parent"]["boot_id"]="22222222-2222-4222-8222-222222222222"
        with self.assertRaises(ContractError): release.validate("NarrowRoleReleaseEvidence1",value)
    def test_narrow_channel_rebinding_rejected(self):
        value=packet()["role_evidence"]; value["channel"]["channel_id"]="other"
        with self.assertRaises(ContractError): release.validate("NarrowRoleReleaseEvidence1",value)
    def test_release_missing_slot_rejected(self):
        value=packet()["release_selection"]; value["release_evidence"].pop()
        with self.assertRaises(ContractError): protected.validate("ReleaseSelection3",value)
    def test_release_duplicate_slot_rejected(self):
        value=packet()["release_selection"]; value["release_evidence"][1]=copy.deepcopy(value["release_evidence"][0])
        with self.assertRaises(ContractError): protected.validate("ReleaseSelection3",value)
    def test_release_wrong_purpose_rejected(self):
        value=packet()["release_selection"]; value["release_evidence"][0]["evidence"]["reference"]["purpose"]="public-aggregate-body"
        with self.assertRaises(ContractError): protected.validate("ReleaseSelection3",value)
    def test_rpc_consumption_binding_required(self):
        value=packet()["controller_fresh_read_request"]; value["body"]["consumption_binding"]=None
        with self.assertRaises(ContractError): checkpoint.validate("CheckpointRpcRequest",value)
    def test_rpc_consumption_generation_mismatch_rejected(self):
        value=packet()["controller_fresh_read_request"]; value["body"]["minimum_generation"]=21
        with self.assertRaises(ContractError): checkpoint.validate("CheckpointRpcRequest",value)
    def test_rpc_expired_request_rejected(self):
        value=packet()["controller_fresh_read_request"]; value["issued"]=copy.deepcopy(value["deadline"])
        with self.assertRaises(ContractError): checkpoint.validate("CheckpointRpcRequest",value)
    def test_wrong_capture_tag_body_rejected(self):
        value={"operation_index":1,"kind":"PROC_READ","started":{"utc":"2030-01-01T00:00:00.000000Z","boottime_ns":0},"finished":{"utc":"2030-01-01T00:00:01.000000Z","boottime_ns":1},"data":{"verified":True}}
        with self.assertRaises(ContractError): capture.validate("CaptureOperation",value)
    def test_unhashable_capture_tag_rejected_safely(self):
        value={"operation_index":1,"kind":{},"started":{"utc":"2030-01-01T00:00:00.000000Z","boottime_ns":0},"finished":{"utc":"2030-01-01T00:00:01.000000Z","boottime_ns":1},"data":{}}
        with self.assertRaises(ContractError): capture.validate("CaptureOperation",value)
    def test_unhashable_rpc_operation_rejected_safely(self):
        value=packet()["controller_fresh_read_request"]; value["operation"]=[]
        with self.assertRaises(ContractError): checkpoint.validate("CheckpointRpcRequest",value)
    def test_unhashable_install_tag_rejected_safely(self):
        subject=packet()["controller_fresh_read_request"]["body"]["consumption_binding"]["controller_process"]
        value={"subject":subject,"operation":{},"abi_layout_sha256":"1"*64,"arguments":{},"return_value":0,"errno":0}
        with self.assertRaises(ContractError): capture.validate("InstallCall",value)
    def test_command_digest_mismatch_rejected(self):
        data=json.loads((ACCEPTED/"examples"/"public-flow.json").read_text(encoding="utf-8"))
        row=data["completion_group_selection_rows"][0]
        value=data["objects"][row["command"]["reference"]["sha256"]]["body"]
        value["argv"].append("--extra")
        with self.assertRaises(ContractError): completion.validate("CommandPin",value)
    def test_duplicate_collection_ids_rejected(self):
        data=json.loads((ACCEPTED/"examples"/"public-flow.json").read_text(encoding="utf-8"))
        row=data["completion_group_selection_rows"][0]
        value=data["objects"][row["expected_inventory"]["reference"]["sha256"]]["body"]
        value["entries"].append(copy.deepcopy(value["entries"][0]))
        with self.assertRaises(ContractError): completion.validate("CollectionInventory",value)
    def test_missing_selected_stream_limit_blocks(self):
        p=packet()
        value={"format":"forex.test-stream/2","binding":p["role_evidence"]["binding"],"group_id":"contracts",
               "process":p["controller_fresh_read_request"]["body"]["consumption_binding"]["controller_process"],
               "stream":"STDOUT","encoding":"UTF8_STRICT","utf8":"abc","raw_sha256":digest(b"abc"),"bytes":3,"complete":True}
        with self.assertRaises(DependencyUnavailable): completion.validate("TestStream2",value)
    def test_stream_bytes_must_match(self):
        p=packet()
        value={"format":"forex.test-stream/2","binding":p["role_evidence"]["binding"],"group_id":"contracts",
               "process":p["controller_fresh_read_request"]["body"]["consumption_binding"]["controller_process"],
               "stream":"STDOUT","encoding":"UTF8_STRICT","utf8":"abc","raw_sha256":digest(b"abc"),"bytes":2,"complete":True}
        with self.assertRaises(ContractError): completion.validate("TestStream2",value,limits=ValidationLimits(stream_bytes=10))

