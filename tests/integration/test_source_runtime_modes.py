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

@unittest.skipUnless(sys.platform=='linux','Approved Linux source-test runner required')
class ReceiptModeTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path=Path(self.directory.name)/'public.json'
        self.previous=os.umask(0o077)
        self.addCleanup(os.umask,self.previous)
    def descriptor(self):
        fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        self.addCleanup(os.close,fd)
        os.write(fd,b'{"fixture":true}')
        return fd
    def test_public_mode_exact_under_restrictive_umask(self):
        fd=self.descriptor()
        self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode),0o600)
        c._set_created_receipt_mode(fd,uid=os.getuid(),gid=os.getgid(),mode=0o644)
        actual=os.fstat(fd)
        self.assertEqual((actual.st_uid,actual.st_gid,stat.S_IMODE(actual.st_mode)),
                         (os.getuid(),os.getgid(),0o644))
    def test_private_receipt_mode_remains_private(self):
        fd=self.descriptor()
        c._set_created_receipt_mode(fd,uid=os.getuid(),gid=os.getgid(),mode=0o600)
        self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode),0o600)
    def test_setuid_or_group_writable_receipt_modes_rejected(self):
        fd=self.descriptor()
        for mode in (0o4755,0o2750,0o664,0o666):
            with self.subTest(mode=mode),self.assertRaises(RuntimeError):
                c._set_created_receipt_mode(fd,uid=os.getuid(),gid=os.getgid(),mode=mode)
        self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode),0o600)
    def test_wrong_new_owner_rejected_before_mutation(self):
        fd=self.descriptor()
        with patch.object(c.os,'fchmod') as change:
            with self.assertRaises(RuntimeError):
                c._set_created_receipt_mode(fd,uid=os.getuid()+1,gid=os.getgid(),mode=0o644)
            change.assert_not_called()
    def test_failed_mode_application_is_not_reported_as_success(self):
        fd=self.descriptor()
        with patch.object(c.os,'fchmod',return_value=None):
            with self.assertRaises(RuntimeError):
                c._set_created_receipt_mode(fd,uid=os.getuid(),gid=os.getgid(),mode=0o644)
    def test_mode_set_does_not_change_receipt_bytes(self):
        fd=self.descriptor();before=self.path.read_bytes()
        c._set_created_receipt_mode(fd,uid=os.getuid(),gid=os.getgid(),mode=0o644)
        self.assertEqual(self.path.read_bytes(),before)
    def test_existing_receipt_is_never_chmod_repaired(self):
        self.path.write_bytes(b'original')
        os.chmod(self.path,0o600)
        parent=os.open(self.directory.name,os.O_RDONLY|os.O_DIRECTORY)
        with patch.object(c.os,'geteuid',return_value=0),patch.object(c,'protected_parent',return_value=(parent,self.path.name)),patch.object(c,'_set_created_receipt_mode') as seal:
            with self.assertRaises(FileExistsError):c.create_retained(str(self.path),{'new':True})
            seal.assert_not_called()
        self.assertEqual(self.path.read_bytes(),b'original')
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)

from cas_forex_operational_contracts import common
from custody_runtime import protected_registry as pr

@unittest.skipUnless(sys.platform=='linux','Approved Linux source-test runner required')
class ProtectedObjectModeTests(unittest.TestCase):
    """Exercises filesystem retention with an isolated public authority fixture."""
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.previous=os.umask(0o077);self.addCleanup(os.umask,self.previous)
        self.raw=b'public source-only filesystem fixture'
        self.digest=common.digest(self.raw);self.path=Path(self.directory.name)/self.digest
        self.root={'expected_uid':os.getuid(),'expected_gid':os.getgid(),'expected_device':self.path.parent.stat().st_dev,
                   'writer_principal_ids':['fixture'],'reader_principal_ids':['fixture']}
        directory=self.directory.name
        class Files(pr.ProtectedFiles):
            @contextlib.contextmanager
            def objects(inner,root,selection,now):
                fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:yield fd
                finally:os.close(fd)
        authority=SimpleNamespace(local_principal_id='fixture',current=lambda selection,now:now)
        self.files=Files(authority)
        self.ref={'format':'forex.protected-record-ref/1',
            'binding':{'run_id':'public-fixture','epoch':1,'source_manifest_sha256':'a'*64,
                       'config_sha256':'b'*64,'topology_sha256':'c'*64,'original_window_sha256':'d'*64},
            'publisher_selection_sha256':'e'*64,'root_id':'public-fixture-root','object_id':self.digest,
            'bytes':len(self.raw),'sha256':self.digest,'record_kind':'SOURCE_TEST_REPORT',
            'publisher_id':'fixture','purpose':'original-source-test-report'}
    def retain(self):
        self.files.retain_exact(self.ref,self.raw,self.root,{},None)
    def test_new_object_is_group_readable_under_077(self):
        self.retain()
        st=self.path.stat()
        self.assertEqual(stat.S_IMODE(st.st_mode),0o440)
        self.assertEqual((st.st_uid,st.st_gid),(self.root['expected_uid'],self.root['expected_gid']))
        self.assertEqual(self.path.read_bytes(),self.raw)
    def test_repeated_correct_object_keeps_original_inode(self):
        self.retain();before=self.path.stat()
        self.retain();after=self.path.stat()
        self.assertEqual((before.st_dev,before.st_ino,before.st_mtime_ns),
                         (after.st_dev,after.st_ino,after.st_mtime_ns))
    def test_old_0400_object_rejected_without_mode_repair(self):
        self.path.write_bytes(self.raw);os.chmod(self.path,0o400)
        with patch.object(pr.os,'fchmod') as change:
            with self.assertRaises(common.ContractError):self.retain()
            change.assert_not_called()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o400)
        self.assertEqual(self.path.read_bytes(),self.raw)
    def test_partial_0600_object_rejected_without_rewrite(self):
        self.path.write_bytes(b'partial')
        with self.assertRaises(common.ContractError):self.retain()
        self.assertEqual(self.path.read_bytes(),b'partial')
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)
    def test_failed_seal_leaves_private_partial_not_published(self):
        with patch.object(pr.os,'fchmod',side_effect=PermissionError):
            with self.assertRaises(PermissionError):self.retain()
        self.assertTrue(self.path.exists())
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)
        with self.assertRaises(common.ContractError):self.retain()
    def test_ownership_mismatch_prevents_publication(self):
        self.root['expected_gid']=os.getgid()+1
        with patch.object(pr.os,'fchmod') as change:
            with self.assertRaises(common.ContractError):self.retain()
            change.assert_not_called()
    def test_seal_never_requests_suid_or_sgid(self):
        original=os.fchmod
        def restricted(fd,mode):
            self.assertEqual(mode&0o6000,0)
            return original(fd,mode)
        with patch.object(pr.os,'fchmod',side_effect=restricted):self.retain()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o440)

