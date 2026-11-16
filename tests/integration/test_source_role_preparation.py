"""Focused source-authored regressions; NOT_RUN. Fixture files only on future run."""
import contextlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'source_runtime'))
import launch_common as c

import source_runtime_common as s
import source_role_service as role_service
import source_test_controller as controller

class RolePreparationTests(unittest.TestCase):
    def fixture(self):
        published={'path':s.IPC+'/observer-records','device':1,'inode':10,'uid':60001,'gid':60000,'mode':0o2750}
        objects={**published,'path':published['path']+'/objects','inode':11}
        return published,objects
    def test_restricted_role_only_validates_prepared_directory(self):
        published,objects=self.fixture()
        with patch.object(s,'directory_identity',return_value=objects),patch.object(os,'mkdir',side_effect=PermissionError('restricted')),patch.object(os,'chmod',side_effect=PermissionError('restricted')):
            self.assertEqual(role_service.validate_prepared_objects(published,s,c),objects)
    def test_missing_root_preparation_is_rejected(self):
        published,objects=self.fixture()
        with patch.object(s,'directory_identity',side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):role_service.validate_prepared_objects(published,s,c)
    def test_owner_mismatch_is_rejected(self):
        published,objects=self.fixture();objects['uid']+=1
        with patch.object(s,'directory_identity',return_value=objects):
            with self.assertRaises(RuntimeError):role_service.validate_prepared_objects(published,s,c)
    def test_group_mismatch_is_rejected(self):
        published,objects=self.fixture();objects['gid']+=1
        with patch.object(s,'directory_identity',return_value=objects):
            with self.assertRaises(RuntimeError):role_service.validate_prepared_objects(published,s,c)
    def test_missing_sgid_is_rejected_without_repair(self):
        published,objects=self.fixture();objects['mode']=0o750
        with patch.object(s,'directory_identity',return_value=objects),patch.object(os,'chmod') as chmod:
            with self.assertRaises(RuntimeError):role_service.validate_prepared_objects(published,s,c)
            chmod.assert_not_called()
    def test_group_writable_directory_is_rejected(self):
        published,objects=self.fixture();objects['mode']=0o2770
        with patch.object(s,'directory_identity',return_value=objects):
            with self.assertRaises(RuntimeError):role_service.validate_prepared_objects(published,s,c)
    def test_wrong_device_is_rejected(self):
        published,objects=self.fixture();objects['device']+=1
        with patch.object(s,'directory_identity',return_value=objects):
            with self.assertRaises(RuntimeError):role_service.validate_prepared_objects(published,s,c)
    def test_nonroot_cannot_prepare_special_modes(self):
        with patch.object(os,'geteuid',return_value=1000),patch.object(controller,'make_dir') as make:
            with self.assertRaises(RuntimeError):controller.prepare_role_directories('observer',{'uid':60001},60000,c,s)
            make.assert_not_called()
    def test_root_prepares_objects_for_actual_observed_owner(self):
        published,objects=self.fixture()
        def identity(path):return {'path':path}
        with patch.object(os,'geteuid',return_value=0),patch.object(os,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR|0o750)),patch.object(os,'chown') as chown,patch.object(os,'chmod') as chmod,patch.object(controller,'make_dir') as make,patch.object(s,'directory_identity',side_effect=identity):
            answer=controller.prepare_role_directories('observer',{'uid':60001},60000,c,s)
            make.assert_called_once_with(s.IPC+'/observer-records/objects',60001,60000,0o2750,c)
            self.assertEqual(chown.call_count,2);self.assertEqual(chmod.call_count,2)
            self.assertEqual(answer['format'],'forex.source-role-prepare/1')
    def test_unknown_role_does_not_change_directories(self):
        with patch.object(os,'geteuid',return_value=0),patch.object(os,'chown') as change:
            with self.assertRaises(RuntimeError):controller.prepare_role_directories('arbitrary',{'uid':60001},60000,c,s)
            change.assert_not_called()
    def test_restriction_is_retained_in_unit_command(self):
        argv=controller.role_command('observer',{'path':'/selected','sha256':'a'*64},10,'/runtime',c)
        self.assertIn('--property=RestrictSUIDSGID=yes',argv)
        self.assertIn('--property=NoNewPrivileges=yes',argv)
        self.assertIn('--property=CapabilityBoundingSet=',argv)

