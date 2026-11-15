"""AUTHORED/NOT_RUN. Public synthetic observations; no protected files opened."""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from isolation_release import verify_role_access


def digest(name):return sha256(name.encode()).hexdigest()


class ProtectedTargetTests(unittest.TestCase):
    def setUp(self):
        self.roles={role:{'pid':pid,'start_ticks':1} for role,pid in
                    [('DECISION_RUNNER',101),('MODEL_SERVICE',102)]}
        self.targets={digest('synthetic-private-'+str(i)) for i in range(5)}
        self.observed={'actual_private_target_sha256':sorted(self.targets),'access_probes':[]}
        for role in self.roles:
            for target in sorted(self.targets):self.add(role,'OPEN_READ_WITHOUT_READING',target,'DENY',13)
            for op in ('PROC_MEM_OPEN','PROC_FD_ACCESS','PROC_ROOT_ACCESS','SIBLING_STATE_OPEN','UNAUTHORIZED_CHANNEL_PEER'):
                self.add(role,op,digest('synthetic-'+op),'DENY',1)
            self.add(role,'OPEN_READ_WITHOUT_READING',digest('synthetic-public'),'ALLOW',None)
        self.read=[]

    def add(self,role,operation,target,result,number):
        self.observed['access_probes'].append(dict(role=role,operation=operation,target_sha256=target,
            expected=result,actual=result,errno=number,target_exists=True,raw_receipt={'synthetic':True},
            **self.roles[role]))

    def verify(self):
        return verify_role_access(self.observed,self.roles,self.targets,self.read.append)

    def test_every_target_denied_in_each_role_accepts_source_observations(self):
        self.assertTrue(self.verify());self.assertEqual(len(self.read),len(self.observed['access_probes']))

    def test_private_allow_plus_unrelated_public_deny_is_rejected(self):
        # B07 accepted this: all operations had DENY somewhere, all private
        # digests appeared in OPEN rows, and every row matched its expected label.
        for row in self.observed['access_probes']:
            if row['target_sha256'] in self.targets:
                row.update(expected='ALLOW',actual='ALLOW',errno=None)
        for role in self.roles:self.add(role,'OPEN_READ_WITHOUT_READING',digest('other-public'),'DENY',13)
        with self.assertRaises(RuntimeError):self.verify()

    def test_duplicate_deny_cannot_hide_private_allow(self):
        self.add('DECISION_RUNNER','OPEN_READ_WITHOUT_READING',min(self.targets),'ALLOW',None)
        with self.assertRaises(RuntimeError):self.verify()

    def test_private_allow_on_other_operation_is_rejected(self):
        self.add('MODEL_SERVICE','PROC_FD_ACCESS',min(self.targets),'ALLOW',None)
        with self.assertRaises(RuntimeError):self.verify()

    def test_one_missing_model_target_denial_is_rejected(self):
        self.observed['access_probes']=[r for r in self.observed['access_probes']
            if not (r['role']=='MODEL_SERVICE' and r['target_sha256']==min(self.targets))]
        with self.assertRaises(RuntimeError):self.verify()

    def test_denial_for_other_operation_cannot_replace_file_read(self):
        self.observed['access_probes'][0]['operation']='PROC_MEM_OPEN'
        with self.assertRaises(RuntimeError):self.verify()

    def test_nonexistent_private_file_is_not_denial(self):
        self.observed['access_probes'][0]['target_exists']=False
        with self.assertRaises(RuntimeError):self.verify()

    def test_enoent_or_boolean_errno_is_not_denial(self):
        for number in (2,True,None,0):
            with self.subTest(errno=number):
                self.observed['access_probes'][0]['errno']=number
                with self.assertRaises(RuntimeError):self.verify()

    def test_observed_allow_against_expected_deny_is_rejected(self):
        self.observed['access_probes'][0]['actual']='ALLOW'
        with self.assertRaises(RuntimeError):self.verify()

    def test_declared_extra_private_target_also_requires_denial(self):
        self.observed['actual_private_target_sha256'].append(digest('extra-protected'))
        with self.assertRaises(RuntimeError):self.verify()

    def test_omitted_configured_target_is_rejected(self):
        self.observed['actual_private_target_sha256'].pop()
        with self.assertRaises(RuntimeError):self.verify()

    def test_changed_role_identity_is_rejected(self):
        self.observed['access_probes'][0]['start_ticks']=2
        with self.assertRaises(RuntimeError):self.verify()

    def test_allowed_control_must_be_a_nonprotected_read(self):
        for row in self.observed['access_probes']:
            if row['expected']=='ALLOW':row['operation']='UNAUTHORIZED_CHANNEL_PEER'
        with self.assertRaises(RuntimeError):self.verify()
