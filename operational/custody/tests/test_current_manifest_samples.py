"""Public mock observations for repeated raw bytes. NOT_RUN."""
import copy
import unittest
from types import SimpleNamespace
from cas_forex_operational_contracts import common
from custody_runtime.release_issuer import CurrentReadbacks
from public_fixtures import packet, stamp


def samples():
    role=packet()["role_evidence"]["roles"]["controller"]
    process=role["process"]
    subject={k:process[k] for k in ("boot_id","pid","start_ticks","parent_pid","uid","gid")}
    subject.update(role="CONTROLLER",parent_start_ticks=role["parent"]["start_ticks"])
    raw=b"public identical native sample"
    ref={"object_id":common.digest(raw),"sha256":common.digest(raw),"bytes":len(raw),"artifact_kind":"NATIVE_CAPTURE_BYTES"}
    binding=packet()["role_evidence"]["method_binding"]
    current=CurrentReadbacks.__new__(CurrentReadbacks)
    current.witness="public-witness";current.now=stamp(20)
    current.evidence={"method_binding":binding,"setup_budget_sha256":"1"*64}
    current.support={};current.used=set();current.operations={"public-batch":set()}
    operations=[]
    for index,start in enumerate((2,5),1):
        manifest={"format":"forex.raw-capture-blob/1","binding":binding,"budget_sha256":"1"*64,
            "producer_id":"public-witness","origin":"CONTROLLER","subject":subject,"started":stamp(start),
            "finished":stamp(start+1),"blob_ref":ref,"encoding":"BINARY","source_selector":"STAT",
            "raw_bytes":len(raw),"raw_sha256":common.digest(raw)}
        body=common.canonical_bytes(manifest);key=common.digest(body)
        pair={"object_ref":{"object_id":key,"sha256":key,"bytes":len(body),"artifact_kind":"RAW_BLOB_MANIFEST"}}
        current.support[key]=(pair,manifest)
        operations.append({"operation_index":index,"kind":"PROC_READ","started":stamp(start),"finished":stamp(start+1),
            "data":{"subject":subject,"selector":"STAT","selector_argument":None,"raw_ref":ref,"return_value":len(raw),"errno":0}})
    current.batches={"public-batch":{"operations":operations}}
    current.graph=SimpleNamespace(raw=lambda reference,now:raw)
    return current,ref,subject,raw


class TimedManifestTests(unittest.TestCase):
    def test_same_native_hash_preserves_two_timed_manifests(self):
        current,ref,subject,raw=samples()
        self.assertEqual(current._native(ref,"STAT",subject,(stamp(1),stamp(7))),raw)
        self.assertEqual(len(current.used),2)
        self.assertEqual(current.operations["public-batch"],{1,2})
        current.complete()

    def test_interval_selects_only_its_original_sample(self):
        current,ref,subject,_=samples()
        current._native(ref,"STAT",subject,(stamp(1),stamp(4)))
        self.assertEqual(len(current.used),1)
        self.assertEqual(current.operations["public-batch"],{1})
        with self.assertRaises(common.ContractError):current.complete()

    def test_signed_manifest_without_matching_child_is_rejected(self):
        current,ref,subject,_=samples();current.batches["public-batch"]["operations"].pop()
        with self.assertRaises(common.ContractError):current._native(ref,"STAT",subject,(stamp(1),stamp(7)))

    def test_child_stamp_cannot_be_substituted(self):
        current,ref,subject,_=samples();current.batches["public-batch"]["operations"][0]["finished"]=stamp(4)
        with self.assertRaises(common.ContractError):current._native(ref,"STAT",subject,(stamp(1),stamp(7)))

    def test_duplicate_child_membership_is_rejected(self):
        current,ref,subject,_=samples();ops=current.batches["public-batch"]["operations"]
        duplicate=copy.deepcopy(ops[0]);duplicate["operation_index"]=3;ops.append(duplicate)
        with self.assertRaises(common.ContractError):current._native(ref,"STAT",subject,(stamp(1),stamp(7)))

    def test_equal_bytes_for_other_subject_do_not_supply_sample(self):
        current,ref,subject,_=samples();subject=copy.deepcopy(subject);subject["start_ticks"]+=1
        with self.assertRaises(common.ContractError):current._native(ref,"STAT",subject,(stamp(1),stamp(7)))
