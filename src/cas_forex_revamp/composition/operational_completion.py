"""Explicit thirteen-group composition. Constructors neither run nor publish.

Measurement supplies observed groups. Separately appointed observer and custody
publishers retain their own records. Custody alone verifies complete acceptance.
No source expectation is promoted to an observation or a runtime authorization.
"""
from dataclasses import dataclass
from cas_forex_operational_contracts import common, completion as co, protected as pr
from custody_runtime.gate_adapters import clock_utc
from custody_runtime.source_test_clock import completion_clock_bytes, SOURCE_CLOCK_FORMAT
from custody_runtime.completion_verifier import CompletionVerifier

GROUPS=('contracts','core','venue','operator','rpa','integration','provider04',
        'policy-inheritance02','operational-measurement','operational-authority',
        'operational-custody','node-version','ui')
require=common.require

def copy(value):return common.decode_canonical(common.canonical_bytes(value,limit=common.MAX_GRAPH))

def require_group_complete(report,group):
    """Prepublication sanity only; never replaces independent custody checks."""
    require(report['group_id']==group['group_id'] and report['exit_code']==0,'GROUP_EXECUTION_FAILED')
    count=group['expected_test_count'];counts=report['counts']
    require(all(counts[k]==count for k in ('discovered','ran','passed')) and
        all(counts[k]==0 for k in ('skipped','failures','errors','cancelled','todo')),'GROUP_COUNTS_INCOMPLETE')
    for key in ('collected_test_ids','executed_test_ids'):
        values=report[key]
        require(len(values)==len(set(values))==count,'GROUP_ID_COUNT')
    require(sorted(report['collected_test_ids'])==sorted(report['executed_test_ids']),'GROUP_ID_SET')
    if group['group_id']=='node-version':
        require(count==0 and report['node_version_utf8']=='v24.21.0\n','NODE_VERSION_OUTPUT')
    else:require(count>0 and report['node_version_utf8'] is None,'GROUP_MODE')


@dataclass(frozen=True)
class CompletionRunResult:
    selection_raw:bytes
    report_raw:bytes
    observation_raw:bytes
    report_use_raw:bytes
    observation_use_raw:bytes


class CompletionRun:
    def __init__(self,*,observer,resolver,publishers,selection_use,observer_publish,
                 custody_publish,custody_publisher_id,authenticate_selection,guard,execution_gate):
        require(all(callable(x) for x in (observer_publish,custody_publish,authenticate_selection,execution_gate)),
                'COMPLETION_COMPOSITION_DEPENDENCY')
        self.observer,self.resolver=observer,resolver
        self.publishers=pr.validate('PublisherRootSelection',publishers).payload()
        self.selection_use=pr.validate('ProtectedReferenceUse',selection_use).payload()
        self.observer_publish,self.custody_publish=observer_publish,custody_publish
        self.custody_id=custody_publisher_id
        self.authenticate,self.guard,self.gate=authenticate_selection,guard,execution_gate
        self.state='NEW';self._groups=();self.failure_type=None

    @property
    def retained_group_uses(self):return tuple(common.decode_canonical(raw) for raw in self._groups)

    def _current(self,selection):
        now=self.guard.now()
        require(self.gate() is None,'EXECUTION_APPROVAL_UNAVAILABLE')
        require(self.authenticate(copy(selection),now=copy(now)) is None,'SELECTION_AUTHENTICATION')
        require(common.utc(selection['not_before_utc'])<=common.utc(now['utc'])<common.utc(selection['expires_at_utc']),
                'COMPLETION_SELECTION_EXPIRED')
        require(self.resolver.resolve(copy(self.selection_use),selection=copy(self.publishers),now=copy(now))
                ==co.validate('CompletionSelection2',selection).raw,'SELECTION_REPLACED')
        return now

    def _publish(self,value,type_name,kind,purpose,publisher,callback,selection):
        raw=co.validate(type_name,value).raw;now=self._current(selection)
        selected=[p for p in self.publishers['publishers'] if p['publisher_id']==publisher]
        role='CUSTODY' if kind=='SOURCE_TEST_REPORT' else 'COMPLETION_OBSERVER'
        require(len(selected)==1 and selected[0]['role']==role,'COMPLETION_PUBLISHER_ROLE')
        use=callback(raw,record_kind=kind,purpose=purpose,now=copy(now))
        use=pr.validate('ProtectedReferenceUse',use).payload();ref=use['reference']
        require(ref['publisher_id']==publisher and ref['record_kind']==kind and ref['purpose']==purpose
            and ref['binding']==selection['binding'] and ref['publisher_selection_sha256']==selection['publisher_selection_sha256']
            and ref['sha256']==common.digest(raw) and ref['bytes']==len(raw)
            and use['required_use']=='SOURCE_COMPLETION','COMPLETION_PUBLICATION_SUBSTITUTED')
        require(self.resolver.resolve(copy(use),selection=copy(self.publishers),now=self._current(selection))==raw,
                'COMPLETION_PUBLICATION_READBACK')
        return common.canonical_bytes(use)

    def run(self):
        """Only this explicit call may execute selected groups and publish reports.

        A failed/unknown group keeps already published refs and leaves the run
        incomplete. No fake thirteen-row record, automatic restart or retry.
        One-shot is per instance; durable authorization remains independently
        enforced by the selected gate/observer/publication mechanisms.
        """
        require(self.state=='NEW','COMPLETION_RUN_ALREADY_ATTEMPTED');self.state='ATTEMPTED'
        try:
            require(self.gate() is None,'EXECUTION_APPROVAL_UNAVAILABLE')
            raw=self.resolver.resolve(copy(self.selection_use),selection=copy(self.publishers),now=self.guard.now())
            selection=co.decode('CompletionSelection2',raw).payload()
            require(self.selection_use['required_use']=='SOURCE_COMPLETION'
                and self.selection_use['reference']['record_kind']=='COMPLETION_SELECTION'
                and self.selection_use['reference']['purpose']=='completion-selection','COMPLETION_SELECTION_ROUTE')
            require(self.selection_use['reference']['binding']==selection['binding']==self.publishers['binding'],
                    'COMPLETION_SCOPE_BINDING')
            require(selection['publisher_selection_sha256']==common.digest(pr.validate('PublisherRootSelection',self.publishers).raw),
                    'COMPLETION_PUBLISHER_SELECTION')
            require(tuple(g['group_id'] for g in selection['groups'])==GROUPS,'COMPLETE_GROUP_ORDER')
            selection_hash=common.digest(raw);self._current(selection)
            clock_raw=self.resolver.resolve(copy(selection['original_clock_ref']),selection=copy(self.publishers),now=self.guard.now())
            original=completion_clock_bytes(clock_raw);clock=common.decode_canonical(original)
            require(common.digest(original)==selection['binding']['original_window_sha256'],'ORIGINAL_CLOCK_CONTENT_PIN')
            start=clock_utc(clock['bootstrap_started_utc']);end=clock_utc(clock['test_deadline_utc'])
            previous=None
            for group in selection['groups']:
                now=self._current(selection)
                require(start<=common.utc(now['utc'])<end,'ORIGINAL_TEST_WINDOW')
                require(self.resolver.resolve(copy(selection['original_clock_ref']),selection=copy(self.publishers),now=copy(now))==clock_raw,
                        'ORIGINAL_CLOCK_REPLACED')
                capture,stdout,stderr,report=self.observer.observe(copy(selection),group=copy(group))
                # Measurement publishes the exact capture/stream refs. Custody
                # independently resolves and reparses those originals later.
                report=co.validate('GroupReport2',report).payload()
                require(report['binding']==selection['binding'] and report['selection_sha256']==selection_hash,'GROUP_SELECTION_BINDING')
                require(report['command_ref']==group['command'] and report['parser_ref']==group['parser']
                    and report['expected_inventory_ref']==group['expected_inventory'],'GROUP_SELECTED_INPUTS')
                begin,finish=common.utc(report['started_at_utc']),common.utc(report['finished_at_utc'])
                require(start<=begin<=finish<=end and (previous is None or previous<=begin),'GROUP_ORIGINAL_TIME_ORDER')
                require(finish<=common.utc(self._current(selection)['utc']),'GROUP_FUTURE_FINISH')
                use_raw=self._publish(report,'GroupReport2','TEST_GROUP_REPORT','test-group-report',
                    selection['observer_id'],self.observer_publish,selection)
                self._groups+= (use_raw,)
                # A failed complete report is retained before stopping. Missing
                # reports are never synthesized to fill the remaining slots.
                require_group_complete(report,group)
                previous=finish
            finished=report['finished_at_utc']
            cutoff = clock_utc(clock['test_deadline_utc']) if clock.get('format') == SOURCE_CLOCK_FORMAT else clock_utc(clock['model_window']['started_at'],window=True)
            require(common.utc(finished)<=cutoff,'COMPLETION_AFTER_PHASE_END')
            uses=list(self.retained_group_uses)
            observation={'format':'forex.source-test-observation/2','binding':selection['binding'],
                'selection_sha256':selection_hash,'observer_id':selection['observer_id'],'groups':uses,'completed_at_utc':finished}
            source_report={'format':'forex.original-source-test-report/2','binding':selection['binding'],
                'selection_sha256':selection_hash,'group_reports':uses,'status':'PASS','finished_utc':finished,
                'original_bootstrap_started_utc':clock['bootstrap_started_utc'],'test_deadline_utc':clock['test_deadline_utc']}
            observation_use=self._publish(observation,'CompletionObservation2','SOURCE_TEST_OBSERVATION','source-test-observation',
                selection['observer_id'],self.observer_publish,selection)
            report_use=self._publish(source_report,'SourceTestReport2','SOURCE_TEST_REPORT','original-source-test-report',
                self.custody_id,self.custody_publish,selection)
            self.state='PUBLISHED_AWAITING_CUSTODY_VERIFICATION'
            return CompletionRunResult(raw,co.validate('SourceTestReport2',source_report).raw,
                co.validate('CompletionObservation2',observation).raw,report_use,observation_use)
        except BaseException as error:
            self.state='INCOMPLETE';self.failure_type=type(error).__name__;raise


def verify_completion_run(result,*,selection_use,verifier_id,verifier_component_sha256,
                          source_manifest_raw,parser_implementations,registry,clock,
                          current_authority_guard,original_deadline,resolver,publishers,now):
    """Explicit independent verifier call after exact reference publication.

    This returns custody's receipt body only. Publication under the independently
    selected SOURCE_TEST_COMPLETION observer grant is a separate explicit action.
    It neither issues a release nor launches a model.
    """
    require(type(result) is CompletionRunResult,'EXACT_COMPLETION_RESULT')
    verifier=CompletionVerifier(selection_use=selection_use,
        report_use=common.decode_canonical(result.report_use_raw),
        observation_use=common.decode_canonical(result.observation_use_raw),
        verifier_id=verifier_id,verifier_component_sha256=verifier_component_sha256,
        source_manifest_raw=source_manifest_raw,parser_implementations=parser_implementations,
        registry=registry,clock=clock,current_authority_guard=current_authority_guard,original_deadline=original_deadline)
    return verifier.verify(co.decode('CompletionSelection2',result.selection_raw).payload(),
        co.decode('SourceTestReport2',result.report_raw).payload(),
        co.decode('CompletionObservation2',result.observation_raw).payload(),
        resolver=resolver,publishers=publishers,now=now)
