"""AUTHORED/NOT_RUN: bounded private evidence capacity without new model calls."""
from datetime import datetime,timedelta,timezone
from pathlib import Path
import tempfile
import unittest
from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.composition.custody_evidence_store import CustodyModelEvidenceStore,MAX_RECORDS

NOW=datetime(2030,1,1,tzinfo=timezone.utc)


class CustodyCapacityTests(unittest.TestCase):
    def test_source_bound_covers_maximum_approved_event_graph(self):
        # 12 model rows + outcome + submitted-no-due + completion per call;
        # eight pending events add five rows each and one final window proof.
        self.assertLessEqual(1+32*15+30*(8*5+1),MAX_RECORDS)
    def test_more_than_operator_512_rows_are_retained_without_replacement(self):
        with tempfile.TemporaryDirectory() as d:
            store=CustodyModelEvidenceStore(Path(d).resolve()/'development.model-evidence.sqlite3',
                run_id='development-run',deadline=NOW+timedelta(hours=1));store.initialize(create=True)
            for i in range(513):store.append('development-'+str(i),'DEVELOPMENT',{'index':i},now=NOW)
            self.assertEqual(len(store.records()),513)
            point=store.checkpoint()
            reopened=CustodyModelEvidenceStore(store.path,run_id=store.run_id,deadline=store.deadline)
            reopened.initialize(expected_checkpoint=point)
            self.assertEqual(reopened.checkpoint(),point)
    def test_capacity_is_enforced_before_insertion(self):
        store=CustodyModelEvidenceStore(Path('/development.model-evidence.sqlite3'),run_id='development-run',
            deadline=NOW+timedelta(hours=1))
        records=[{'receipt_id':'retained-'+str(i),'sha256':'a'*64} for i in range(MAX_RECORDS)]
        class NoWrite:
            def execute(self,*args):raise AssertionError('capacity overflow attempted write')
        with self.assertRaises(ContractError):store._insert(NoWrite(),records,'new','DEVELOPMENT',{},NOW)
    def test_changed_identity_remains_a_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            store=CustodyModelEvidenceStore(Path(d).resolve()/'development.model-evidence.sqlite3',
                run_id='development-run',deadline=NOW+timedelta(hours=1));store.initialize(create=True)
            first=store.append('same','DEVELOPMENT',{'v':1},now=NOW)
            with self.assertRaises(ContractError):store.append('same','DEVELOPMENT',{'v':2},now=NOW)
            self.assertEqual(store.resolve('same'),first)
