"""Synthetic read-binding oracle; AUTHORED/NOT_RUN; fake model source only."""
from copy import deepcopy
from pathlib import Path
import sqlite3
import tempfile
import unittest
from cas_forex_revamp.contracts import RunScope,content_digest
from cas_forex_revamp.composition.evidence_journal import EvidenceJournal
from cas_forex_revamp.composition.r6_observation import actual_state,wire
from cas_forex_revamp.composition.r6_readback import AttemptReader
from cas_forex_revamp.composition.r6_runtime import CaseRuntime,packet_json
from cas_forex_revamp.composition.r6_shadow import decide
from r6_development_fixture import Clock,case


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.build()

    def build(self,pending_mode=None):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.clock=Clock();value=case()
        self.runtime=CaseRuntime(value,directory=self.root/('trajectory-'+value['case_id']),
            execution_id='development',build_id='dev',adapter=None,clock=self.clock)
        r=self.runtime;r.initialize();s=value['steps'][0]
        request,before,binding,view,pre=r.prepare(s);packet=packet_json(request)
        self.source={'receipt':{'payload':{'invocation':{'packet_json':packet}}}}
        core=wire(r.core.read_snapshot(r.scope.key))
        actual=actual_state(before,policy_version=1,context_version=r.context_version)
        self.row=dict(case_id=value['case_id'],step_id=s['step_id'],request=wire(request),
            result={'selection':{'selected_action_ref':None,'evidence_ids':[]}},
            selected_action_ref=None,evidence_ids=[],selected_intent=None,action_kind=None,
            selected_strategy_id=None,selected_timeframe=None,new_core_commands=[],
            admission_count=0,dispatch_count=0,command_receipts=[],receipt=None,effect=None,
            decision_venue_changed=False,
            packet_json=packet,actual_receipt_verified=True,inference_source_sha256=content_digest(self.source),
            shadow=decide(packet),current_view=view,binding_before=binding,binding_after=binding,
            observed_before=before,observed_after=before,observed_before_preparation=pre,
            observed_before_after_events=before,core_before=core,core_after=core,
            actual_before=actual,actual_after=actual,prior_position_id=None,position_id=None)
        if pending_mode:
            # Development-only observations. The production model reader resolves
            # the separately anchored socket receipts before this reader sees them.
            def stamp(n):return {'utc':'2030-01-01T00:00:00+00:00','monotonic_ns':n,'clock_id':'development'}
            declared={'type':'CONTEXT_CHANGE','development_only':True}
            event={'before':before,'after':before,'declared':declared,
                'started_at':stamp(2)['utc'],'completed_at':stamp(3)['utc'],
                'transport_receipt_id':'development-pending'}
            transport={'request_sent':{'payload':{'submitted':stamp(1),'pending_events':[declared]}},
                'response_capture':{'payload':{'first_bytes':{'before_recv':stamp(5)}}},
                'windows':[{'receipt_id':'development-pending','payload':{
                    'event_result':{'before':before,'after':before},'declared':declared,
                    'started':stamp(2),'completed':stamp(3),'after_check':stamp(4),
                    'before_response_ready':False,'after_response_ready':False,'error_type':None}}]}
            self.row.update(pending_events=[event],pending_ordering_verified=True)
            if pending_mode!='missing':self.source['transport']=transport
            if pending_mode=='before_send':transport['windows'][0]['payload']['started']=stamp(1)
            if pending_mode=='response_wins':transport['windows'][0]['payload']['after_response_ready']=True
            if pending_mode!='missing_event':r.append('R6_PENDING_EVENT',event)
            self.row['inference_source_sha256']=content_digest(self.source)
        r.append('R6_FIRST_ATTEMPT',self.row)
        scope=RunScope('dev-controller','dev-control',1,'dev','dev','dev','dev')
        self.journal=EvidenceJournal(self.root/'controller.evidence.sqlite3',scope.key);self.journal.initialize(create=True)
        self.journal.append('trajectory','R6_TRAJECTORY_CHECKPOINT',scope,
            {'case_id':value['case_id'],'scope':wire(r.scope),'evidence_checkpoint':r.journal.checkpoint(),
             'venue_checkpoint':before['checkpoint'],'core_event_sha256':core['event_sha256']},now=self.clock())
        self.reader=AttemptReader(root=self.root,controller_journal=self.journal,model_reader=lambda request,result:self.source)

    def test_separate_readback_resolves_original_development_row(self):
        self.assertIs(self.reader(self.row),True)

    def test_changed_actual_amount_rejected(self):
        changed=deepcopy(self.row);changed['actual_after']['realized_balance']='0'
        self.assertIs(self.reader(changed),False)

    def test_changed_shadow_choice_rejected(self):
        changed=deepcopy(self.row);changed['shadow']['selected_action_ref']='invented'
        self.assertIs(self.reader(changed),False)

    def test_venue_bytes_corruption_cannot_pass_journal_copy(self):
        with sqlite3.connect(self.runtime.venue_path) as db:
            db.execute("UPDATE checkpoints SET sha256=? WHERE sequence=(SELECT MAX(sequence) FROM checkpoints)",('0'*64,))
        self.assertIs(self.reader(self.row),False)

    def test_pending_readback_reconstructs_valid_development_observations(self):
        self.build('valid');self.assertIs(self.reader(self.row),True)

    def test_durable_true_label_without_transport_observations_rejected(self):
        self.build('missing');self.assertIs(self.reader(self.row),False)

    def test_durable_true_label_cannot_hide_change_before_send(self):
        self.build('before_send');self.assertIs(self.reader(self.row),False)

    def test_durable_true_label_cannot_hide_response_wins(self):
        self.build('response_wins');self.assertIs(self.reader(self.row),False)

    def test_pending_transport_copy_needs_original_trajectory_event(self):
        self.build('missing_event');self.assertIs(self.reader(self.row),False)
