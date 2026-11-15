"""Pure negative controls with visibly unauthenticated test doubles. NOT_RUN."""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from cas_forex_operational_contracts.common import ContractError,DependencyUnavailable
from cas_forex_measurement.decoder import AuthenticatedDecoder,AuthenticatedGraph,CaptureDeriver,one
from cas_forex_measurement.watchdog import IndependentWatchdog
from support import stamp,reference,budget,PublicClock


class DecoderGuardTests(unittest.TestCase):
    def test_ambiguous_capture_is_rejected(self):
        with self.assertRaises(ContractError):one([1,2],'AMBIGUOUS')
    def test_missing_capture_is_rejected(self):
        with self.assertRaises(ContractError):one([],'MISSING')
    def test_raw_self_hash_without_manifest_is_rejected(self):
        evidence=Mock();graph=AuthenticatedGraph(owner=SimpleNamespace(evidence=evidence),now=stamp())
        with self.assertRaises(ContractError):graph.raw(reference(b'bytes','NATIVE_CAPTURE_BYTES'))
        evidence.resolve.assert_not_called()
    def test_reference_hash_mismatch_is_rejected(self):
        graph=AuthenticatedGraph(owner=SimpleNamespace(evidence=SimpleNamespace(resolve=lambda ref:b'other')),now=stamp())
        with self.assertRaises(ContractError):graph.bytes(reference(b'bytes'))
    def test_external_decoder_pin_cannot_be_replaced(self):
        decoder=object.__new__(AuthenticatedDecoder);decoder.component='a'*64;decoder.format='b'*64
        with self.assertRaises(ContractError):decoder.decode_actual((),selection={},decoder_component_sha256='c'*64,decoder_format_sha256='b'*64,now=stamp())
    def test_failure_has_no_invented_cleanup_success(self):
        graph=SimpleNamespace(selected={'values':{}})
        with self.assertRaises(DependencyUnavailable):CaptureDeriver(graph).derive_payload('FAILURE')
    def test_derived_artifact_access_does_not_expose_mutable_references(self):
        decoder=object.__new__(AuthenticatedDecoder);ref=reference();decoder._artifacts=((ref,b'public'),)
        obtained=decoder.derived_artifacts;obtained[0][0]['artifact_kind']='WATCHDOG_BINDING'
        self.assertEqual(decoder.derived_artifacts[0][0]['artifact_kind'],'AUTHENTICATED_INTERVAL')
    def test_missing_watchdog_schema_never_arms(self):
        inventory=Mock();clock=PublicClock();watchdog=IndependentWatchdog(clock=clock,inventory=inventory,execution_gate=lambda:None)
        with self.assertRaises(DependencyUnavailable):watchdog.arm_original(budget(),selected_processes=())
        self.assertFalse(watchdog._armed);inventory.subject.assert_not_called();self.assertEqual(clock.calls,0)
    def test_watchdog_diagnostic_cannot_be_accepted(self):
        watchdog=IndependentWatchdog(clock=PublicClock(),inventory=Mock(),execution_gate=lambda:None)
        with self.assertRaises(DependencyUnavailable):watchdog.observe(reference(b'body','WATCHDOG_BINDING'),now=stamp())

    def test_policy_must_be_an_exact_selected_static_source(self):
        from cas_forex_operational_contracts.common import canonical_bytes,digest
        selected={'abi':4,'handled_fs':1,'rules':[],'targets':[]}
        raw=canonical_bytes(selected);graph=SimpleNamespace(selected={'values':{}},source_refs=[],bytes=Mock())
        with self.assertRaises(ContractError):
            CaptureDeriver(graph)._installation_policy(selected,{'selected_policy_sha256':digest(raw)})
        graph.bytes.assert_not_called()
    def test_captured_policy_cannot_replace_external_pin(self):
        graph=SimpleNamespace(selected={'values':{}},source_refs=[],bytes=Mock())
        with self.assertRaises(ContractError):
            CaptureDeriver(graph)._installation_policy({'abi':4,'handled_fs':1,'rules':[],'targets':[]},
                                                      {'selected_policy_sha256':'a'*64})
        graph.bytes.assert_not_called()
    def test_policy_source_bytes_must_equal_exact_selected_policy(self):
        from cas_forex_operational_contracts.common import canonical_bytes,digest
        selected={'abi':4,'handled_fs':1,'rules':[],'targets':[]};raw=canonical_bytes(selected)
        graph=SimpleNamespace(selected={'values':{}},source_refs=[reference(raw,'CANONICAL_PAYLOAD')],bytes=lambda ref:b'other')
        with self.assertRaises(ContractError):
            CaptureDeriver(graph)._installation_policy(selected,{'selected_policy_sha256':digest(raw)})

    def test_parent_label_without_distinct_raw_samples_is_rejected(self):
        parent={'pid':21,'parent_pid':20,'start_ticks':2}
        child={'parent_pid':21,'parent_start_ticks':2}
        graph=SimpleNamespace(selected={'values':{}},operations=lambda kind:[])
        op={'data':{'parent_subject':parent,'subject':child},'_batch':reference(),'started':stamp(),'finished':stamp(2)}
        with self.assertRaises(ContractError):CaptureDeriver(graph)._parent_samples(op)
