"""Synthetic metadata only. AUTHORED/NOT_RUN; no symlink or mount operations."""
import copy
import os
import stat
import unittest
from model_state_directory import validate_state_layout


RUN = 'fx-b-' + 'a' * 16
NAME = 'cas-forex-' + RUN
TARGET = '/var/lib/private/' + NAME


def record(mode, uid=0, gid=0, device=1, inode=1):
    return dict(mode=mode, uid=uid, gid=gid, device=device, inode=inode)


def fixture():
    state = record(stat.S_IFDIR | 0o700, uid=61111, gid=61111, inode=20)
    return dict(alias_path='/var/lib/' + NAME, environment_path='/var/lib/' + NAME,
        target_path=TARGET, resolved_path=TARGET,
        parents={p: record(stat.S_IFDIR | 0o755) for p in ('/', '/var', '/var/lib', '/var/lib/private')},
        alias=record(stat.S_IFLNK | 0o777), target=state, opened_target=copy.deepcopy(state),
        alias_followed=copy.deepcopy(state), link_text='private/' + NAME, filesystem_readonly=False,
        target_mounts=[dict(mount_id=42, device=str(os.major(1)) + ':' + str(os.minor(1)),
                           mountpoint=TARGET, options=['rw', 'nosuid', 'nodev'])])


class StateDirectoryTests(unittest.TestCase):
    def validate(self, value):
        return validate_state_layout(value, run_id=RUN, uid=61111, gid=61111)

    def test_exact_systemd_alias_metadata_accepted(self):
        self.assertEqual(self.validate(fixture())['private_target'], TARGET)

    def test_exact_absolute_alias_text_also_accepted(self):
        value = fixture(); value['link_text'] = TARGET
        self.assertEqual(self.validate(value)['mount_id'], 42)

    def test_arbitrary_symlink_escape_rejected(self):
        value = fixture(); value['link_text'] = '/tmp/another-state'
        with self.assertRaises(RuntimeError): self.validate(value)

    def test_workload_owned_alias_rejected(self):
        value = fixture(); value['alias']['uid'] = 61111
        with self.assertRaises(RuntimeError): self.validate(value)

    def test_writable_or_linked_parent_rejected(self):
        for mode in (stat.S_IFDIR | 0o777, stat.S_IFLNK | 0o777):
            value = fixture(); value['parents']['/var/lib/private']['mode'] = mode
            with self.assertRaises(RuntimeError): self.validate(value)

    def test_wrong_private_target_owner_rejected(self):
        value = fixture(); value['target']['uid'] = 0
        with self.assertRaises(RuntimeError): self.validate(value)

    def test_changed_opened_inode_rejected(self):
        value = fixture(); value['opened_target']['inode'] += 1
        with self.assertRaises(RuntimeError): self.validate(value)

    def test_missing_exact_mount_rejected(self):
        value = fixture(); value['target_mounts'] = []
        with self.assertRaises(RuntimeError): self.validate(value)

    def test_readonly_state_mount_rejected(self):
        value = fixture(); value['filesystem_readonly'] = True
        with self.assertRaises(RuntimeError): self.validate(value)

    def test_wrong_environment_alias_rejected(self):
        value = fixture(); value['environment_path'] = TARGET
        with self.assertRaises(RuntimeError): self.validate(value)
