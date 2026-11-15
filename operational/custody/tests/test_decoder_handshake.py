"""Public mock contract cases. No model or operational evidence. NOT_RUN."""
import copy
import unittest
from types import SimpleNamespace
from cas_forex_operational_contracts import common
from custody_runtime.release_issuer import MethodGraph, RecomputedSink
from public_fixtures import packet, stamp


def fixture(change=None):
    example=packet()["role_evidence"]
    raw_values=[("CANONICAL_PAYLOAD",common.canonical_bytes({"public":"primary"})),
                ("NAMESPACE_INVENTORY",common.canonical_bytes([{"public":"derived"}]))]
    source=RecomputedSink()
    artifacts=tuple((source.retain(raw,artifact_kind=kind),raw) for kind,raw in raw_values)
    capture_ref=source.retain(b'{"public":"capture"}',artifact_kind="TRUSTED_CAPTURE_BATCH")
    envelope_ref=source.retain(b'{"public":"envelope"}',artifact_kind="SIGNED_ENVELOPE")
    input_ref=source.retain(b'{"public":"selected-source"}',artifact_kind="SOURCE_ARGUMENT")
    bindings=[{"format":"forex.runtime-decode-binding/2","binding":example["method_binding"],
        "budget_sha256":example["setup_budget_sha256"],"event_kind":"SETUP_BEGIN",
        "decoder_component_sha256":"1"*64,"decoder_format_sha256":"2"*64,
        "capture_refs":[capture_ref],"capture_envelope_refs":[envelope_ref],"selected_input_refs":[input_ref],
        "normalized_ref":ref,"normalized_artifact_kind":ref["artifact_kind"],"decoded":stamp(10)} for ref,_ in artifacts]
    calls=[]
    def factory(**kwargs):
        calls.append(kwargs)
        class Decoder:
            def decode_actual(self,*args,**decode_kwargs):
                calls.append(decode_kwargs)
                self.derived_artifacts=artifacts
                self.derived_bindings=tuple(copy.deepcopy(bindings))
                for ref,raw in artifacts: kwargs["sink"].retain(raw,artifact_kind=ref["artifact_kind"])
                if change: change(self,kwargs["sink"])
                return self.derived_bindings[0],artifacts[0][1]
        return Decoder()
    graph=MethodGraph.__new__(MethodGraph)
    graph.context=SimpleNamespace(appointment={},budget={},coverage_plan={})
    graph.auth=object();graph.decoder_factory=factory
    graph.decoder_selection=SimpleNamespace(decoder_component_sha256="1"*64,decoder_format_sha256="2"*64)
    graph.current=lambda now:stamp(20)
    graph.raw=lambda ref,now:source.readback(ref)
    pair={"public":"final-authenticated-input-pair"}
    def run():graph._recompute(pair,{"capture_objects":[]},{},{"payload_ref":artifacts[0][0]},bindings,stamp(20))
    return run,calls,pair


class DecoderHandshakeTests(unittest.TestCase):
    def test_one_decode_compares_multiple_derived_kinds(self):
        run,calls,pair=fixture();run()
        self.assertEqual(len(calls),2)
        self.assertIs(calls[0]["event_inputs"],pair)
        self.assertEqual(calls[0]["component_sha256"],"1"*64)
        self.assertEqual(calls[0]["format_sha256"],"2"*64)

    def test_missing_derived_artifact_rejected(self):
        def change(decoder,sink):decoder.derived_artifacts=decoder.derived_artifacts[:1]
        run,_,_=fixture(change)
        with self.assertRaises(common.ContractError):run()

    def test_missing_derived_binding_rejected(self):
        def change(decoder,sink):decoder.derived_bindings=decoder.derived_bindings[:1]
        run,_,_=fixture(change)
        with self.assertRaises(common.ContractError):run()

    def test_original_decoded_stamp_cannot_be_refreshed(self):
        def change(decoder,sink):
            for row in decoder.derived_bindings:row["decoded"]=stamp(20)
        run,_,_=fixture(change)
        with self.assertRaises(common.ContractError):run()

    def test_duplicate_artifact_rejected(self):
        def change(decoder,sink):decoder.derived_artifacts+=decoder.derived_artifacts[:1]
        run,_,_=fixture(change)
        with self.assertRaises(common.ContractError):run()

    def test_unreported_sink_output_rejected(self):
        def change(decoder,sink):sink.retain(b'{"public":"extra"}',artifact_kind="CANONICAL_PAYLOAD")
        run,_,_=fixture(change)
        with self.assertRaises(common.ContractError):run()

    def test_mutable_accessor_container_rejected(self):
        def change(decoder,sink):decoder.derived_artifacts=list(decoder.derived_artifacts)
        run,_,_=fixture(change)
        with self.assertRaises(common.ContractError):run()

    def test_fresh_sink_cannot_read_producer_reference(self):
        source=RecomputedSink();ref=source.retain(b'{"public":"retained"}',artifact_kind="CANONICAL_PAYLOAD")
        with self.assertRaises(common.ContractError):RecomputedSink().readback(ref)
