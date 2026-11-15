"""AUTHORED/NOT_RUN. Fake adapter exercises composition, never actual-model proof."""
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import tempfile
import json
import unittest
from cas_forex_revamp.contracts import (DecisionOrigin, DecisionProvenance, DecisionResult,
    DecisionSelection, InferenceBudget, canonical_bytes, content_digest)
from cas_forex_revamp.operator.decisions import decision_identity
from cas_forex_revamp.composition.continuous_model_driver import run_trajectory


NOW=datetime(2030,1,1,tzinfo=timezone.utc)


class FakeAdapter:
    def __init__(self, wait=False): self.wait=wait
    def decide(self, request):
        selection=DecisionSelection(request.request_id,request.opportunity_set_id,request.state.state_id,
            None if self.wait else request.options[0].action_ref,'Visible fake software test only',
            tuple(e.evidence_id for e in request.evidence))
        return DecisionResult(decision_identity(request),selection,DecisionProvenance(
            DecisionOrigin.ACTUAL_MODEL,'fake-unit-adapter',content_digest(request),
            sha256(canonical_bytes(selection)).hexdigest(),'fake-unit-policy',NOW,NOW,
            model_id='fake-unit-model',model_artifact_sha256='a'*64,inference_receipt_id='fake-'+request.request_id))


def fake_reader(request,result):
    return dict(invocation_sha256='b'*64,budget=InferenceBudget(32,4096,512,120,5400),
        latency_ms=0,receipt={'FAKE_TEST_ONLY':True},sources=[])


def case():
    market={'bid':'1.1000','ask':'1.1002'}
    entry=dict(step_id='a'*24,market_before=market,market_after=[market],invalidate_while_pending=False,
        facts=[{'label':'Toy context','value':'Visible software fixture, not a held-out case'}], options=[
            dict(action_ref='1'*24,strategy_id='first',timeframe='M5',label='Buy candidate',kind='OPEN',side='BUY',quantity='10',limit_price='1.1002',stop_price='1.09'),
            dict(action_ref='2'*24,strategy_id='second',timeframe='H1',label='Sell candidate',kind='OPEN',side='SELL',quantity='10',limit_price='1.1000',stop_price='1.11')])
    close=dict(step_id='b'*24,market_before=market,market_after=[market],invalidate_while_pending=False,
        facts=[{'label':'Toy context','value':'Updated visible test context'}],options=[
            dict(action_ref='3'*24,strategy_id='exit',timeframe='M5',label='Close remaining',kind='CLOSE',quantity='ALL',limit_price='1.1000'),
            dict(action_ref='4'*24,strategy_id='trim',timeframe='H1',label='Reduce four',kind='REDUCE',quantity='4',limit_price='1.1000')])
    return dict(case_id='c'*32,initial_market=market,steps=[entry,close])


class ModelTrajectoryTests(unittest.TestCase):
    def run_case(self, payload, adapter):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve()/'trajectory'
            rows, snapshot=run_trajectory(payload,directory=root,execution_id='fake-b',build_id='test-build',
                adapter=adapter,model_store=None,model_reader=fake_reader,clock=lambda:NOW)
            self.assertTrue((root/'account.core.sqlite3').is_file())
            self.assertTrue((root/'account.venue.sqlite3').is_file())
            self.assertTrue((root/'decision-read.json').is_file())
            self.assertTrue((root/'decision-catalog.json').is_file())
            read=json.loads((root/'decision-read.json').read_text())
            facts=[x for x in read['envelope']['evidence'] if x['producer_class']=='AUTHORED_FIXTURE']
            self.assertTrue(facts)
            self.assertTrue(all(x['assessment']=='unresolved' for x in facts))
            return rows,snapshot

    def test_selected_model_reference_reaches_separate_venue_and_exit(self):
        rows,_=self.run_case(case(),FakeAdapter())
        self.assertEqual([r['error_type'] for r in rows],[None,None])
        self.assertEqual([r['effect'] for r in rows],['FILLED','FILLED'])
        self.assertEqual(rows[0]['position_id'],rows[1]['position_id'])
        self.assertEqual(rows[1]['position_quantity_after'],'0')
        self.assertEqual(rows[1]['positions_after'],0)

    def test_wait_cannot_fall_back_to_first_trade(self):
        payload=case();payload['steps']=payload['steps'][:1]
        rows,_=self.run_case(payload,FakeAdapter(wait=True))
        self.assertEqual(rows[0]['action_kind'],'WAIT')
        self.assertFalse(rows[0]['venue_changed']);self.assertNotIn('receipt_id',rows[0])
