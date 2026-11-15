"""AUTHORED/NOT_RUN. Temporary software stores only; no model evidence claim."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import json
from hashlib import sha256
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from cas_forex_revamp.contracts import (ContractError, RunScope, StateReference, DecisionRequest,
    DecisionSelection, DecisionProvenance, DecisionOrigin, DecisionResult, InferenceBudget,
    canonical_bytes, content_digest)
from cas_forex_revamp.operator.model import ModelSpecification, ModelInvocation, SYSTEM_POLICY
from cas_forex_revamp.operator.decisions import decision_identity
from cas_forex_revamp.composition.evidence_journal import EvidenceJournal
from cas_forex_revamp.composition.model_evidence_bridge import AnchoredModelStore, ModelDecisionReader


class ModelAnchorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); root=Path(self.temp.name).resolve()
        self.now=datetime(2030,1,1,tzinfo=timezone.utc)
        self.scope=RunScope('fake','fake-run',1,'test-build','test-policy','test-case','test-venue')
        self.journal=EvidenceJournal(root/'test.evidence.sqlite3',self.scope.key); self.journal.initialize(create=True)
        self.store=AnchoredModelStore(root/'test.model-evidence.sqlite3',run_id='test-model',deadline=self.now+timedelta(minutes=10))
        self.store.bind_journal(self.journal,self.scope,lambda:self.now)
        self.store.initialize(create=True); self.store._anchor()

    def tearDown(self):
        self.temp.cleanup()

    def reserve(self):
        return self.store.begin_http(phase='probe',operation='generation',invocation_sha256='a'*64,
            body_sha256='b'*64,timeout_seconds=60,now=self.now)

    def test_reservation_is_anchored_before_return(self):
        item=self.reserve()
        self.assertEqual(self.store.verified_records(),(item,))

    def test_interrupted_anchor_retains_spent_attempt(self):
        with patch.object(self.journal,'append',side_effect=OSError('fake interrupted anchor')):
            with self.assertRaises(OSError): self.reserve()
        self.assertEqual(len(self.store.records()),1)
        with self.assertRaises(ContractError): self.store.verified_records()
        with self.assertRaises(ContractError): self.reserve()

    def test_existing_history_is_not_recreated(self):
        with self.assertRaises(FileExistsError): self.store.initialize(create=True)

    def test_restart_requires_external_anchor(self):
        with self.assertRaises(ContractError): self.store.initialize()

    def test_imported_inference_label_cannot_make_source_record(self):
        reader=ModelDecisionReader(self.store,object(),expected_adapter_id='fake-test')
        with self.assertRaises(ContractError): reader({}, {'provenance':{'inference_receipt_id':'invented'}})

    def fake_source(self):
        state=StateReference('fake-state',self.scope,1,self.now,self.now+timedelta(minutes=2),0)
        request=DecisionRequest('fake-request','fake-options',state,(),(),())
        selection=DecisionSelection(request.request_id,request.opportunity_set_id,state.state_id,None,'Fake unit WAIT',())
        raw=canonical_bytes(selection).decode()
        model=ModelSpecification('fake-model','a'*64,'disabled','fake-prompt-v1')
        invocation=ModelInvocation(content_digest(request),model,'fake-session',SYSTEM_POLICY,
            canonical_bytes(request).decode(),InferenceBudget(2,1024,256,60,600),seed=1)
        result=DecisionResult(decision_identity(request),selection,DecisionProvenance(DecisionOrigin.ACTUAL_MODEL,
            'fake-test',content_digest(request),sha256(raw.encode()).hexdigest(),'fake-prompt-v1',self.now,self.now,
            model_id=model.model_id,model_artifact_sha256=model.artifact_sha256,inference_receipt_id='fake-inference'))
        for name in ('fake-http','fake-token','fake-before','fake-after'):
            self.store.append(name,'FAKE_UNIT_DEPENDENCY',{'FAKE_TEST_ONLY':True},now=self.now)
        self.store.append('fake-inference','MODEL_INFERENCE_RECEIPT',dict(invocation=invocation,
            invocation_sha256=content_digest(invocation),raw_selection_json=raw,requested_model=model,
            started_at=self.now,completed_at=self.now,observed_provider_input_tokens=1,observed_provider_generated_tokens=1,
            generation_http_id='fake-http',token_proof_id='fake-token',runtime_before_id='fake-before',runtime_after_id='fake-after'),now=self.now)
        reader=ModelDecisionReader(self.store,SimpleNamespace(verify=lambda reply,inv:True),expected_adapter_id='fake-test')
        return reader,json.loads(canonical_bytes(request)),json.loads(canonical_bytes(result))

    def test_prompt_version_must_match_independent_invocation(self):
        reader,request,result=self.fake_source();result['provenance']['prompt_version']='different'
        with self.assertRaises(ContractError):reader(request,result)

    def test_adapter_label_must_match_selected_reader(self):
        reader,request,result=self.fake_source();result['provenance']['adapter_id']='different'
        with self.assertRaises(ContractError):reader(request,result)

    def test_wait_decision_identity_cannot_be_rewritten(self):
        reader,request,result=self.fake_source();result['decision_id']='different'
        with self.assertRaises(ContractError):reader(request,result)
