"""Actual two-store development regressions; AUTHORED/NOT_RUN, no model calls."""
from copy import deepcopy
from decimal import Decimal
from pathlib import Path
import tempfile
import unittest

from cas_forex_revamp.contracts import ContractError, content_digest
from cas_forex_revamp.composition.r6_runtime import CaseRuntime,packet_json
from cas_forex_revamp.composition.r6_observation import actual_state
from r6_development_fixture import Clock,case,step,submit


class R6RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.clock=Clock()

    def start(self, value=None):
        value=value or case()
        r=CaseRuntime(value,directory=Path(self.temp.name)/'case',execution_id='development-only',
                      build_id='development',adapter=None,clock=self.clock)
        r.initialize();return r

    def test_constructor_is_inert(self):
        r=CaseRuntime(case(),directory=Path(self.temp.name)/'case',execution_id='development-only',build_id='dev',adapter=None,clock=self.clock)
        self.assertFalse(r.directory.exists())

    def test_quote_decimal_format_is_not_a_new_market_event(self):
        r=self.start();before=r.observe()['snapshot']['sequence'];r.prepare(r.case['steps'][0])
        self.assertEqual(before,r.observe()['snapshot']['sequence'])

    def test_context_rebind_rejects_prior_source(self):
        r=self.start();r.set_context(r.case['steps'][0]['context']);old=r.current_state()
        changed=deepcopy(r.context);changed['trend_score']='4';r.set_context(changed)
        self.assertNotEqual(old,r.current_state())
        self.assertEqual(r.context_version,2)

    def test_policy_change_preserves_account_and_raises_epoch(self):
        r=self.start();key=r.scope.key;old=r.scope
        r.change_policy({'policy_revision':2,'max_entry_quantity':'12'})
        self.assertEqual(r.scope.key,key);self.assertGreater(r.scope.epoch,old.epoch)
        self.assertNotEqual(r.scope.policy_id,old.policy_id)
        self.assertEqual(r.observe()['snapshot']['balance']['amount'],'10000')

    def test_missing_margin_not_recovered_from_initial_declaration(self):
        s=step(observed_accounting_override={'available_margin':None});r=self.start(case([s]))
        request,_,_,view,_=r.prepare(s);packet=packet_json(request)
        self.assertIsNone(view['available_margin']);self.assertNotIn('9000',packet)
        self.assertIn('UNAVAILABLE',packet)

    def test_observation_reread_cannot_extend_original_quote_ttl(self):
        r=self.start();self.clock.advance(301)
        with self.assertRaises(ContractError):r.prepare(r.case['steps'][0])

    def test_step_identity_cannot_be_retried(self):
        r=self.start();s=r.case['steps'][0];r.prepare(s)
        with self.assertRaises(ContractError):r.prepare(s)

    def test_partial_entry_finishes_at_declared_next_event(self):
        s=step();s['schedule']['fill_quotas']=['4','6'];r=self.start(case([s]));submit(r,s)
        self.clock.advance();r.market({'bid':'1.1','ask':'1.1002'})
        first=r.observe();self.assertEqual(first['snapshot']['positions'][0]['quantity'],'4')
        self.clock.advance();r.market({'bid':'1.1','ask':'1.1002'})
        second=r.observe();self.assertEqual(second['snapshot']['positions'][0]['quantity'],'10')
        self.assertGreater(second['snapshot']['positions'][0]['version'],first['snapshot']['positions'][0]['version'])

    def test_protective_stop_retains_terminal_metadata(self):
        r=self.start();submit(r,r.case['steps'][0]);self.clock.advance();r.market({'bid':'1.1','ask':'1.1002'})
        identity=r.observe()['snapshot']['positions'][0]['position_id']
        self.clock.advance();r.market({'bid':'0.99','ask':'0.9902'})
        seen=r.observe();actual=actual_state(seen,policy_version=1,context_version=1,position_id=identity)
        self.assertEqual(actual['open_quantity'],'0');self.assertTrue(actual['terminal_record_available'])
        self.assertEqual(actual['side'],'BUY');self.assertEqual(actual['stop'],'1')
        self.assertTrue(any(x['reason_code']=='VENUE_PROTECTIVE_STOP' for x in seen['receipts']))

    def test_exact_close_retains_same_position_and_balance(self):
        s1,s2=step(),step(2,'CLOSE');r=self.start(case([s1,s2]));submit(r,s1)
        self.clock.advance();r.market({'bid':'1.1','ask':'1.1002'})
        identity=r.observe()['snapshot']['positions'][0]['position_id'];r.last_position_id=identity
        self.clock.advance();submit(r,s2);r.market({'bid':'1.1','ask':'1.1002'})
        seen=r.observe();actual=actual_state(seen,policy_version=1,context_version=r.context_version,position_id=identity)
        self.assertEqual(actual['position_id'],identity);self.assertEqual(actual['open_quantity'],'0')
        self.assertTrue(actual['terminal_record_available'])
