"""Source-authored public regressions. NOT_RUN during preparation."""
import os
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'source_runtime'))
import launch_common as c
import source_runtime_common as s

import source_test_controller as controller

class ReviewAdmissionTests(unittest.TestCase):
    def fixture(self):
        directory=str(Path(s.__file__).resolve().parent)
        names=('launch_common.py','source_runtime_common.py','source_role_service.py',
               'source_test_controller.py','source_test_launcher.py','source_test_worker.py')
        rows=[{'path':directory+'/'+n,'bytes':1,'sha256':'a'*64} for n in names]
        selection={'status':'INDEPENDENTLY_SOURCE_REVIEWED',
            'source_manifest':{'sha256':'1'*64},'completion_material':{'sha256':'2'*64},
            'review_receipt':{'path':'/review'}}
        review={'format':'forex.source-test-runtime-review/1','decision':'ACCEPTED_SOURCE',
            'source_manifest_sha256':'1'*64,'completion_material_sha256':'2'*64,
            'infrastructure_files':rows,'review_report':{'path':'/report'}}
        return selection,rows,review
    def inspect(self,selection,rows,review):
        with patch.object(c,'pinned',side_effect=lambda row:(c.canonical(review),None)):
            s.reviewed_runtime(selection,rows)
    def test_missing_review_holds(self):
        sel,rows,rev=self.fixture();sel['status']='BLOCKED'
        with self.assertRaises(RuntimeError):self.inspect(sel,rows,rev)
    def test_predecessor_manifest_does_not_clear_hold(self):
        sel,rows,rev=self.fixture();rev['source_manifest_sha256']='3'*64
        with self.assertRaises(RuntimeError):self.inspect(sel,rows,rev)
    def test_different_material_does_not_clear_hold(self):
        sel,rows,rev=self.fixture();rev['completion_material_sha256']='3'*64
        with self.assertRaises(RuntimeError):self.inspect(sel,rows,rev)
    def test_review_must_bind_controller_and_role_bytes(self):
        sel,rows,rev=self.fixture();rev['infrastructure_files']=rows[:-1]
        with self.assertRaises(RuntimeError):self.inspect(sel,rows,rev)
    def test_required_controller_member_cannot_be_omitted(self):
        sel,rows,rev=self.fixture();rows=rows[:-1];rev['infrastructure_files']=rows
        with self.assertRaises(RuntimeError):self.inspect(sel,rows,rev)
    def test_unrecognized_review_field_rejected(self):
        sel,rows,rev=self.fixture();rev['ready']=True
        with self.assertRaises(RuntimeError):self.inspect(sel,rows,rev)
    def test_exact_review_source_mechanism(self):
        self.inspect(*self.fixture())
    def test_existing_gid_cannot_be_reassigned(self):
        cfg={'reader_group_name':s.GROUP,'reader_group_gid':1234,'reader_group_create':False}
        with patch.object(controller.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=999,gr_mem=[])),patch.object(controller.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):controller.ensure_reader_group(cfg,{},SimpleNamespace(),c,s)
            run.assert_not_called()
    def test_existing_host_membership_is_rejected(self):
        cfg={'reader_group_name':s.GROUP,'reader_group_gid':1234,'reader_group_create':False}
        with patch.object(controller.grp,'getgrnam',return_value=SimpleNamespace(gr_gid=1234,gr_mem=['host-user'])):
            with self.assertRaises(RuntimeError):controller.ensure_reader_group(cfg,{},SimpleNamespace(),c,s)
    def test_missing_group_no_implicit_creation(self):
        cfg={'reader_group_name':s.GROUP,'reader_group_gid':1234,'reader_group_create':False}
        with patch.object(controller.grp,'getgrnam',side_effect=KeyError),patch.object(controller.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):controller.ensure_reader_group(cfg,{},SimpleNamespace(),c,s)
            run.assert_not_called()
    def test_existing_directory_never_overwritten(self):
        with patch.object(os.path,'lexists',return_value=True),patch.object(os,'mkdir') as create:
            with self.assertRaises(RuntimeError):controller.make_dir('/reviewed/path',100,100,0o750,c)
            create.assert_not_called()
    def test_cleanup_wrong_unit_description_cannot_kill(self):
        with patch.object(controller.subprocess,'run',return_value=SimpleNamespace(stdout='other\n')) as run:
            self.assertFalse(controller.kill_owned('selected','ours',c))
            self.assertEqual(run.call_count,1)
    def test_cleanup_failure_returns_unconfirmed(self):
        with patch.object(controller.subprocess,'run',side_effect=OSError):
            self.assertFalse(controller.kill_owned('selected','ours',c))

class LiveOwnerTests(unittest.TestCase):
    def fixture(self):
        parent={'pid':11,'start_ticks':22,'uid':0}
        base=SimpleNamespace(remaining=lambda reserve:30-reserve)
        native=SimpleNamespace(UNIT='worker',process_identity=lambda pid:dict(parent),
            read_protected=lambda path:(b'accepted',None),need=c.need)
        owned=[]
        return controller.LiveDeadline(base,parent,owned,'/accepted',b'accepted',native),native,owned
    def test_private_input_wait_uses_original_remaining(self):
        deadline,native,owned=self.fixture()
        self.assertEqual(deadline.remaining(5),25)
    def test_parent_pid_reuse_stops_private_input_wait(self):
        deadline,native,owned=self.fixture()
        native.process_identity=lambda pid:{'pid':11,'start_ticks':23,'uid':0}
        with self.assertRaises(RuntimeError):deadline.remaining()
    def test_native_acceptance_withdrawal_stops_wait(self):
        deadline,native,owned=self.fixture()
        native.read_protected=lambda path:(b'withdrawn',None)
        with self.assertRaises(RuntimeError):deadline.remaining()
    def test_dead_prepared_role_stops_wait(self):
        deadline,native,owned=self.fixture()
        owned.append(('role','selected',SimpleNamespace(poll=lambda:1),None))
        with self.assertRaises(RuntimeError):deadline.remaining()
    def test_original_deadline_failure_is_not_reset(self):
        deadline,native,owned=self.fixture()
        def expired(reserve):raise RuntimeError('expired')
        deadline.base.remaining=expired
        with self.assertRaises(RuntimeError):deadline.remaining()
    def test_successful_launcher_exit_does_not_fake_role_liveness(self):
        deadline,native,owned=self.fixture()
        owned.extend([('worker','selected',SimpleNamespace(poll=lambda:0),None),
                      ('role','selected',SimpleNamespace(poll=lambda:None),None)])
        self.assertEqual(deadline.remaining(),30)

