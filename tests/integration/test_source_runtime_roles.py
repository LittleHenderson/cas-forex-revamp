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

class RolePolicyTests(unittest.TestCase):
    def fixture(self):
        identities={name:{'pid':i+100,'uid':i+1000,'gid':i+1000,'start_ticks':20+i,'boot_id':'public-boot'}
            for i,name in enumerate(('controller','workload','current','registry','observer','custody'))}
        endpoints={name:{'path':'/public/'+name,'device':1,'inode':10+i,'uid':1000+i,'gid':400,
            'mode':0o660,'maximum_frame_bytes':4194304,'timeout_ms':30000,'maximum_registry_entries':4096}
            for i,name in enumerate(s.ROLES)}
        return identities,endpoints
    def test_workload_cannot_register(self):
        ids,ep=self.fixture();rows=controller.peer_rows('registry',ep,ids,s)
        row=next(r for r in rows if r['selection']['peer_pid']==ids['workload']['pid'])
        self.assertEqual(row['operations'],['READ_REGISTRATION'])
    def test_observer_never_calls_itself(self):
        ids,ep=self.fixture();rows=controller.peer_rows('observer',ep,ids,s)
        self.assertEqual([r['selection']['peer_pid'] for r in rows],[ids['workload']['pid']])
    def test_custody_publisher_only_workload(self):
        ids,ep=self.fixture();rows=controller.peer_rows('custody',ep,ids,s)
        self.assertEqual([r['selection']['peer_pid'] for r in rows],[ids['workload']['pid']])
    def test_current_only_current_selection_operation(self):
        ids,ep=self.fixture();rows=controller.peer_rows('current',ep,ids,s)
        self.assertTrue(all(r['operations']==['CURRENT_SELECTION'] for r in rows))
    def test_registry_does_not_connect_back_to_observer(self):
        ids,ep=self.fixture();rows=controller.peer_rows('observer',ep,ids,s)
        self.assertNotIn(ids['registry']['pid'],[r['selection']['peer_pid'] for r in rows])
    def test_exact_peer_start_time_retained(self):
        ids,ep=self.fixture();rows=controller.peer_rows('current',ep,ids,s)
        for row in rows:
            who=next(i for i in ids.values() if i['pid']==row['selection']['peer_pid'])
            self.assertEqual(row['selection']['peer_start_ticks'],who['start_ticks'])
    def test_each_role_has_own_selected_unit(self):
        self.assertEqual(len({controller.unit_name(n) for n in s.ROLES}),4)
    def test_no_role_restart_or_loose_kill_boundary(self):
        args=controller.role_command('observer',{'path':'/plan','sha256':'a'*64},10,'/source-runtime',c)
        self.assertIn('--property=Restart=no',args)
        self.assertIn('--property=KillMode=control-group',args)
        self.assertIn('--property=SendSIGKILL=yes',args)
        self.assertIn('--property=RuntimeMaxSec=10',args)
    def test_role_has_no_network_rpc_address_family(self):
        args=controller.role_command('registry',{'path':'/plan','sha256':'a'*64},10,'/source-runtime',c)
        self.assertIn('--property=RestrictAddressFamilies=AF_UNIX',args)
    def test_role_write_mounts_do_not_include_other_roles(self):
        args=controller.role_command('observer',{'path':'/plan','sha256':'a'*64},10,'/source-runtime',c)
        write=next(a for a in args if a.startswith('--property=ReadWritePaths='))
        self.assertNotIn('/custody',write);self.assertNotIn('/registry',write)
    def test_role_guard_rechecks_config_bytes(self):
        conf={'controller':{'pid':1,'start_ticks':2,'uid':0}}
        with patch.object(c,'process_identity',return_value=conf['controller']),patch.object(c,'pinned',return_value=(b'changed',None)):
            with self.assertRaises(RuntimeError):s.role_guard(conf,b'original',{},SimpleNamespace())
    def test_role_guard_requires_live_exact_controller(self):
        conf={'controller':{'pid':1,'start_ticks':2,'uid':0}}
        with patch.object(c,'process_identity',return_value={'pid':1,'start_ticks':3,'uid':0}):
            with self.assertRaises(RuntimeError):s.role_guard(conf,b'original',{},SimpleNamespace())

