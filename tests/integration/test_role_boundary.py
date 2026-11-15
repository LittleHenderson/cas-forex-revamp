"""AUTHORED/NOT_RUN. Approved Linux test route only; public temporary sentinels.

These tests cannot establish actual custody-target isolation. The independent
runtime observer must still test and bind the actual workload and target set.
"""
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from role_boundary import normalized_policy,READ,WRITE


class PolicySourceTests(unittest.TestCase):
    def test_root_rule_is_rejected(self):
        with self.assertRaises(RuntimeError):normalized_policy({'read':['/'],'write':[],'execute':[]})
    def test_unknown_rule_kind_is_rejected(self):
        with self.assertRaises(RuntimeError):normalized_policy({'allow':['/']})
    def test_missing_target_is_not_a_valid_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):normalized_policy({'read':[str(Path(d)/'absent')],'write':[],'execute':[]})
    def test_write_rights_exclude_reparenting_and_socket_creation(self):
        self.assertEqual(WRITE & ((1<<13)|(1<<9)),0)
    def test_explicit_leaf_keeps_read_without_write(self):
        with tempfile.TemporaryDirectory() as d:
            path=str(Path(d).resolve());p=normalized_policy({'read':[path],'write':[],'execute':[]})
            self.assertEqual(p[path],READ)


class ActualLinuxSentinelTests(unittest.TestCase):
    def run_child(self, *, allowed, denied, read_proc=False):
        source=Path(__file__).resolve().parents[2]
        script='''import json,sys,os
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from role_boundary import confine,open_probe
allowed,denied=sys.argv[2],sys.argv[3]
confine({'read':[sys.argv[1],'/usr/lib','/proc',allowed],
         'write':['/dev/null'],'execute':[]},allowed_fds=set(),
        boot_id='00000000-0000-0000-0000-000000000001')
print(json.dumps({'allowed':open_probe(allowed),'denied':open_probe(denied)}))
'''
        result=subprocess.run(['/usr/bin/python3','-B','-c',script,str(source),str(allowed),str(denied)],
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'},
            stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=15,close_fds=True)
        self.assertEqual(result.returncode,0,'required Linux confinement unavailable')
        return json.loads(result.stdout)
    def test_actual_denied_file_is_not_readable(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();a=root/'allowed';b=root/'denied'
            a.write_text('public-development-sentinel');b.write_text('public-development-sentinel')
            result=self.run_child(allowed=a,denied=b)
            self.assertTrue(result['allowed']['opened']);self.assertTrue(result['denied']['denied'])
    def test_controller_memory_open_is_denied(self):
        with tempfile.TemporaryDirectory() as d:
            a=Path(d).resolve()/'allowed';a.write_text('public-development-sentinel')
            result=self.run_child(allowed=a,denied=Path('/proc')/str(os.getpid())/'mem')
            self.assertTrue(result['denied']['denied'])
    def test_parent_descriptor_cannot_expose_a_denied_file(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d).resolve();a=root/'allowed';b=root/'denied'
            a.write_text('public-development-sentinel');b.write_text('public-development-sentinel')
            with b.open('rb') as handle:
                result=self.run_child(allowed=a,denied=Path('/proc')/str(os.getpid())/'fd'/str(handle.fileno()))
                self.assertTrue(result['denied']['denied'])
