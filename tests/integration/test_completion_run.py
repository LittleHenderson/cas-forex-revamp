"""Public synthetic composition regressions; NOT_RUN, no authority evidence."""
import copy
from datetime import datetime,timezone,timedelta
import unittest
from cas_forex_operational_contracts import common
from cas_forex_revamp.composition.operational_completion import CompletionRun, GROUPS, require_group_complete

def stamp(seconds):
    return {'utc':(datetime(2030,1,1,tzinfo=timezone.utc)+timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%S.000000Z'),
            'boottime_ns':seconds*1_000_000_000}

class Fixture:
    """Explicit fakes test composition only; never shared production providers."""
    def __init__(self):
        self.time=1;self.rows={};self.called=[];self.published=[];self.fail=None;self.tamper=False
        self.clock={'model_calls':32,'retry_calls':0,'bootstrap_started_utc':stamp(0)['utc'],'test_deadline_utc':stamp(170)['utc'],
          'model_window':{'started_at':stamp(175)['utc'],'deadline':stamp(179)['utc'],'total_generation_limit':32,
            'probe_limit':2,'acceptance_limit':30,'includes':['startup','render','tokenize','probes','acceptance','export','shutdown']}}
        self.binding={'run_id':'PUBLIC-UNIT-NOT-A-RUN','epoch':1,'source_manifest_sha256':'1'*64,
           'config_sha256':'2'*64,'topology_sha256':'3'*64,'original_window_sha256':common.digest(common.canonical_bytes(self.clock))}
        root={'root_id':'public-root','root_instance_id':'public-instance','absolute_directory':'/public-fixture',
          'owner_principal_id':'public-custody','expected_uid':1000,'expected_gid':1000,'expected_mode':0o750,
          'expected_device':1,'expected_inode':2,'reader_principal_ids':['public-observer','public-custody'],
          'writer_principal_ids':['public-observer','public-custody'],'restore_authority_id':'public-restore',
          'object_layout':'objects/<lowercase-sha256>','maximum_object_bytes':4194304}
        def publisher(name,role,kind,purpose):
            return {'publisher_id':name,'role':role,'signer_public_sha256':'4'*64,'component_manifest_sha256':'5'*64,
              'not_before_utc':stamp(0)['utc'],'expires_at_utc':stamp(180)['utc'],
              'grants':[{'root_id':'public-root','record_kind':kind,'purpose':purpose,'permitted_use':'SOURCE_COMPLETION','payload_schema_sha256':'6'*64}]}
        self.publishers={'format':'forex.publisher-root-selection/1','selection_id':'public-selection','binding':self.binding,
          'authorizer_id':'public-authorizer','not_before_utc':stamp(0)['utc'],'expires_at_utc':stamp(180)['utc'],'roots':[root],
          'publishers':[publisher('public-observer','COMPLETION_OBSERVER','TEST_GROUP_REPORT','test-group-report'),
                        publisher('public-custody','CUSTODY','SOURCE_TEST_REPORT','original-source-test-report')],
          'registry_authority_id':'public-registry','registry_root_id':'public-root','registry_signer_public_sha256':'7'*64,
          'registry_component_sha256':'8'*64}
        self.publisher_hash=common.digest(common.canonical_bytes(self.publishers))
        groups=[]
        for name in GROUPS:
            groups.append({'group_id':name,'command':self.ref('COMMAND_PIN','test-command-pin'),
              'parser':self.ref('PARSER_PIN','test-parser-pin'),'expected_inventory':self.ref('COLLECTION_INVENTORY','test-collection-inventory'),
              'expected_test_count':0 if name=='node-version' else 1,
              'mode':'NODE_VERSION' if name=='node-version' else ('NODE_TAP' if name=='ui' else 'PYTHON_METHODS')})
        self.selection={'format':'forex.runtime-completion-selection/2','selection_id':'public-completion','binding':self.binding,
          'publisher_selection_sha256':self.publisher_hash,'observer_id':'public-observer','verifier_id':'public-verifier',
          'verifier_component_sha256':'9'*64,'original_clock_ref':self.ref('EXTERNAL_RELEASE_EVIDENCE',
              'release-evidence:original_clock_and_budget_binding_sha256',raw=common.canonical_bytes(self.clock)),
          'source_inventory_ref':self.ref('SOURCE_INVENTORY','completion-source-inventory'),'groups':groups,
          'not_before_utc':stamp(0)['utc'],'expires_at_utc':stamp(180)['utc']}
        self.selection_use=self.ref('COMPLETION_SELECTION','completion-selection',raw=common.canonical_bytes(self.selection))
    def ref(self,kind,purpose,*,raw=b'{}',publisher='public-observer'):
        digest=common.digest(raw);self.rows[digest]=raw
        return {'reference':{'format':'forex.protected-record-ref/1','binding':copy.deepcopy(self.binding),
          'publisher_selection_sha256':self.publisher_hash,'root_id':'public-root','object_id':digest,'bytes':len(raw),'sha256':digest,
          'record_kind':kind,'publisher_id':publisher,'purpose':purpose},'registration_sha256':'a'*64,'required_use':'SOURCE_COMPLETION'}
    def resolve(self,use,*,selection,now):return self.rows[use['reference']['sha256']]
    def now(self):return stamp(self.time)
    def publish(self,raw,*,record_kind,purpose,now,publisher):
        self.published.append((publisher,record_kind,common.decode_canonical(raw)))
        result=self.ref(record_kind,purpose,raw=raw,publisher=publisher)
        if self.tamper:result['reference']['publisher_id']='public-substitute'
        return result
    def observe(self,selection,*,group):
        self.called.append(group['group_id']);begin=self.time;self.time+=1;count=group['expected_test_count']
        subject={'role':'COMPLETION_OBSERVER','boot_id':'00000000-0000-0000-0000-000000000001','pid':101,'start_ticks':10,
          'parent_pid':100,'parent_start_ticks':9,'uid':1000,'gid':1000}
        counts={'discovered':count,'ran':count,'passed':count,'skipped':0,'failures':0,'errors':0,'cancelled':0,'todo':0}
        if self.fail==group['group_id']:counts['passed']=0;counts['failures']=1
        report={'format':'forex.observed-test-group/2','binding':copy.deepcopy(self.binding),'selection_sha256':common.digest(common.canonical_bytes(selection)),
          'group_id':group['group_id'],'process':subject,'command_ref':group['command'],'parser_ref':group['parser'],
          'expected_inventory_ref':group['expected_inventory'],'capture_ref':self.ref('TEST_PROCESS_CAPTURE','test-process-capture'),
          'stdout_ref':self.ref('TEST_STREAM','test-stream'),'stderr_ref':self.ref('TEST_STREAM','test-stream'),
          'original_framework_report_ref':self.ref('TEST_FRAMEWORK_REPORT','test-framework-report'),
          'started_at_utc':stamp(begin)['utc'],'finished_at_utc':stamp(self.time)['utc'],'exit_code':1 if self.fail==group['group_id'] else 0,
          'collected_test_ids':[] if count==0 else [group['group_id']+'.public-test'],
          'executed_test_ids':[] if count==0 else [group['group_id']+'.public-test'],'counts':counts,
          'node_version_utf8':'v24.21.0\n' if count==0 else None,'discovery_report_ref':self.ref('TEST_DISCOVERY_REPORT','test-discovery-report')}
        return None,None,None,report
    def compose(self,gate=lambda:None):
        return CompletionRun(observer=self,resolver=self,publishers=self.publishers,selection_use=self.selection_use,
          observer_publish=lambda raw,**kw:self.publish(raw,publisher='public-observer',**kw),
          custody_publish=lambda raw,**kw:self.publish(raw,publisher='public-custody',**kw),
          custody_publisher_id='public-custody',authenticate_selection=lambda *args,**kwargs:None,guard=self,execution_gate=gate)

class CompletionRunTests(unittest.TestCase):
    def test_constructor_runs_and_publishes_nothing(self):
        fixture=Fixture();run=fixture.compose()
        self.assertEqual(fixture.called,[]);self.assertEqual(fixture.published,[]);self.assertEqual(run.state,'NEW')
    def test_exact_thirteen_original_groups_are_published_once(self):
        fixture=Fixture();run=fixture.compose();result=run.run()
        self.assertEqual(fixture.called,list(GROUPS));self.assertEqual(len(run.retained_group_uses),13)
        report=common.decode_canonical(result.report_raw);observation=common.decode_canonical(result.observation_raw)
        self.assertEqual(report['finished_utc'],stamp(14)['utc']);self.assertEqual(observation['completed_at_utc'],report['finished_utc'])
        self.assertEqual(report['group_reports'],observation['groups'])
        self.assertEqual(run.state,'PUBLISHED_AWAITING_CUSTODY_VERIFICATION')
    def test_failure_retains_observed_group_and_stops_without_fake_tail(self):
        fixture=Fixture();fixture.fail='core';run=fixture.compose()
        with self.assertRaises(common.ContractError):run.run()
        self.assertEqual(fixture.called,['contracts','core']);self.assertEqual(len(run.retained_group_uses),2)
        self.assertEqual(run.state,'INCOMPLETE');self.assertFalse(any(x[1]=='SOURCE_TEST_REPORT' for x in fixture.published))
    def test_failed_instance_cannot_retry_or_reset(self):
        fixture=Fixture();fixture.fail='contracts';run=fixture.compose()
        with self.assertRaises(common.ContractError):run.run()
        fixture.fail=None
        with self.assertRaises(common.ContractError):run.run()
        self.assertEqual(fixture.called,['contracts'])
    def test_missing_execution_gate_prevents_every_observation(self):
        fixture=Fixture();run=fixture.compose(gate=lambda:False)
        with self.assertRaises(common.ContractError):run.run()
        self.assertEqual(fixture.called,[])
    def test_publisher_substitution_cannot_create_complete_result(self):
        fixture=Fixture();fixture.tamper=True;run=fixture.compose()
        with self.assertRaises(common.ContractError):run.run()
        self.assertEqual(fixture.called,['contracts']);self.assertEqual(run.state,'INCOMPLETE')
    def test_custody_report_and_observer_observation_remain_separate(self):
        fixture=Fixture();fixture.compose().run()
        self.assertEqual([p for p,k,v in fixture.published if k=='SOURCE_TEST_REPORT'],['public-custody'])
        self.assertEqual([p for p,k,v in fixture.published if k=='SOURCE_TEST_OBSERVATION'],['public-observer'])
    def test_observed_subset_cannot_satisfy_expected_count(self):
        fixture=Fixture();group=fixture.selection['groups'][0];report=fixture.observe(fixture.selection,group=group)[3]
        report['executed_test_ids']=[]
        with self.assertRaises(common.ContractError):require_group_complete(report,group)
    def test_retained_uses_are_detached_from_caller_mutation(self):
        fixture=Fixture();run=fixture.compose();run.run();uses=run.retained_group_uses
        uses[0]['reference']['sha256']='b'*64
        self.assertNotEqual(run.retained_group_uses[0]['reference']['sha256'],'b'*64)
