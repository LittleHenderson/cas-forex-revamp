"""Authored OC-01 regressions; NOT_RUN. Synthetic records confer no authority.

Linux tests below actually fork only when an approved runner explicitly executes
this suite. Their publication callback is a labelled public structural premise,
not a signed RegistryPort or operational completion receipt.
"""
from copy import deepcopy
from datetime import datetime,timezone
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from cas_forex_operational_contracts.common import ContractError,canonical_bytes,decode_canonical,digest,utc
from cas_forex_measurement.completion import (DiscoveryFrame,ForkExecCapture,MAX_DISCOVERY_BODY,
    parse_discovery,release_frame,selected_driver_arguments)
from cas_forex_measurement.inventory import LinuxInventory
from support import PublicMemorySink


def binding():
    return dict(run_id='public-discovery-test',epoch=1,source_manifest_sha256='a'*64,
        config_sha256='b'*64,topology_sha256='c'*64,original_window_sha256='d'*64)


def body(**changes):
    value={'format':'forex.test-driver-discovery/1','group_id':'operator',
        'inventory_sha256':'e'*64,'test_ids':['public.Case.test_actual']}
    value.update(changes);return canonical_bytes(value)


def repin(command):
    keys=('executable','argv','cwd','environment_profile_sha256','stdin_policy','source_manifest_sha256','group_id')
    command['command_sha256']=digest(canonical_bytes({k:command[k] for k in keys}))
    return command


def command_pin():
    executable=dict(asset_id='public-python',selected_path='/public/python',bytes=1,sha256='f'*64,device=1,inode=1)
    value={'format':'forex.test-command-pin/1','binding':binding(),'group_id':'operator','executable':executable,
        'argv':['/public/python','--discovery-fd','200','--release-fd','201','--group','operator',
                '--inventory-sha256','e'*64],
        'cwd':'/public','environment_profile_sha256':'1'*64,'stdin_policy':'CLOSED','source_manifest_sha256':'a'*64}
    return repin(value)


def structural_publication(raw):
    # This value deliberately has no signature. It only exercises the capture
    # protocol callback; independent publication/registry trust is not asserted.
    return {'reference':{'format':'forex.protected-record-ref/1','binding':binding(),
        'publisher_selection_sha256':'2'*64,'root_id':'public-test-root','object_id':digest(raw),
        'bytes':len(raw),'sha256':digest(raw),'record_kind':'TEST_DISCOVERY_REPORT',
        'publisher_id':'public-test-observer','purpose':'test-discovery-report'},
        'registration_sha256':'3'*64,'required_use':'SOURCE_COMPLETION'}


class DiscoveryFrameTests(unittest.TestCase):
    def test_fragmented_frame_requires_eof(self):
        raw=body();wire=struct.pack('!I',len(raw))+raw;frame=DiscoveryFrame()
        for byte in wire:frame.feed(bytes([byte]))
        with self.assertRaises(ContractError):_ = frame.body
        with self.assertRaises(ContractError):_ = frame.wire
        frame.eof();self.assertEqual(frame.body,raw);self.assertEqual(frame.wire,wire)
    def test_truncated_prefix_or_body_rejected(self):
        raw=body();wire=struct.pack('!I',len(raw))+raw
        for count in (0,1,3,4,len(wire)-1):
            with self.subTest(count=count):
                frame=DiscoveryFrame()
                if count:frame.feed(wire[:count])
                with self.assertRaises(ContractError):frame.eof()
    def test_extra_byte_or_second_frame_rejected(self):
        raw=body();wire=struct.pack('!I',len(raw))+raw
        for suffix in (b'x',wire):
            with self.subTest(suffix_size=len(suffix)):
                with self.assertRaises(ContractError):DiscoveryFrame().feed(wire+suffix)
    def test_zero_and_oversized_lengths_rejected(self):
        for size in (0,MAX_DISCOVERY_BODY+1,2**32-1):
            with self.subTest(size=size):
                with self.assertRaises(ContractError):DiscoveryFrame().feed(struct.pack('!I',size))
    def test_second_eof_or_late_bytes_rejected(self):
        raw=body();frame=DiscoveryFrame();frame.feed(struct.pack('!I',len(raw))+raw);frame.eof()
        with self.assertRaises(ContractError):frame.eof()
        with self.assertRaises(ContractError):frame.feed(b'x')
    def test_wrong_group_inventory_format_or_extra_fields_rejected(self):
        for change in ({'group_id':'core'},{'inventory_sha256':'f'*64},{'format':'success'},{'success':True}):
            with self.subTest(change=change):
                with self.assertRaises(ContractError):parse_discovery(body(**change),group_id='operator',inventory_sha256='e'*64)
    def test_duplicate_empty_or_nonstring_ids_rejected(self):
        for ids in ([],['same','same'],[''],[True],['x'*1025]):
            with self.subTest(ids=ids):
                with self.assertRaises(ContractError):parse_discovery(body(test_ids=ids),group_id='operator',inventory_sha256='e'*64)
    def test_noncanonical_or_invalid_utf8_rejected(self):
        for raw in (body()+b'\n',b'\xff',b'{"test_ids":[]}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ContractError):parse_discovery(raw,group_id='operator',inventory_sha256='e'*64)
    def test_version_requires_empty_ids(self):
        value=parse_discovery(body(group_id='node-version',test_ids=[]),group_id='node-version',inventory_sha256='e'*64)
        self.assertEqual(value['test_ids'],[])
        with self.assertRaises(ContractError):parse_discovery(body(group_id='node-version'),group_id='node-version',inventory_sha256='e'*64)
    def test_release_binds_exact_original_body(self):
        raw=body();wire=release_frame('operator',raw)
        self.assertEqual(struct.unpack('!I',wire[:4])[0],len(wire)-4)
        self.assertEqual(decode_canonical(wire[4:]),{'format':'forex.test-driver-start/1',
            'group_id':'operator','discovery_sha256':digest(raw)})
        self.assertNotEqual(wire,release_frame('operator',body(test_ids=['public.Case.test_other'])))


class DiscoveryCommandTests(unittest.TestCase):
    def test_selected_descriptors_are_not_rewritten(self):
        command=command_pin();before=deepcopy(command)
        self.assertEqual(selected_driver_arguments(command)['discovery-fd'],200)
        self.assertEqual(selected_driver_arguments(command)['release-fd'],201)
        self.assertEqual(command,before)
    def test_duplicate_missing_or_assignment_flags_rejected(self):
        base=command_pin()
        for argv in (base['argv']+['--group','operator'],base['argv'][:-2],
                     base['argv']+['--discovery-fd=200']):
            with self.subTest(argv=argv):
                command=deepcopy(base);command['argv']=argv;repin(command)
                with self.assertRaises(ContractError):selected_driver_arguments(command)
    def test_collision_stdio_noncanonical_or_high_fd_rejected(self):
        for value in ('201','0','2','0200','-1','abc','1025'):
            with self.subTest(value=value):
                command=command_pin();command['argv'][2]=value;repin(command)
                with self.assertRaises(ContractError):selected_driver_arguments(command)
    def test_group_and_inventory_substitution_rejected(self):
        for index,value in ((6,'core'),(8,'bad-digest')):
            with self.subTest(index=index):
                command=command_pin();command['argv'][index]=value;repin(command)
                with self.assertRaises(ContractError):selected_driver_arguments(command)
    def test_changed_argv_without_repin_rejected(self):
        command=command_pin();command['argv'][2]='202'
        with self.assertRaises(ContractError):selected_driver_arguments(command)
    def test_missing_callbacks_cannot_open_executable(self):
        capture=ForkExecCapture(inventory=None,guard=None,execution_gate=lambda:None,capture_sink=None)
        with patch('cas_forex_measurement.completion.os.open') as opened:
            with self.assertRaises(ContractError):capture.run(command_pin(),environment={},maximum_stream_bytes=1024,
                on_discovery=None,before_release=lambda **kwargs:None)
            opened.assert_not_called()


class PublicTestDeadline:
    """Test-only timeout, never a method clock or authority verifier."""
    def __init__(self):self.end=time.monotonic()+30
    def remaining(self):
        left=self.end-time.monotonic()
        if left<=0:raise ContractError('PUBLIC_TEST_TIMEOUT')
        return left
    def now(self):
        self.remaining()
        return {'utc':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                'boottime_ns':time.clock_gettime_ns(time.CLOCK_BOOTTIME)}


class ActualDiscoveryPipeTests(unittest.TestCase):
    def exercise(self,*,reject_publication=False,reject_release=False):
        # No skip-as-success path: the approved execution environment must be
        # Linux with pidfd/fd-exec support. Runtime is NOT_RUN during authoring.
        with tempfile.TemporaryDirectory(prefix='public-oc01-') as directory:
            marker=Path(directory)/'executed';exe=Path(sys.executable).resolve();raw=exe.read_bytes();stat=exe.stat()
            command=command_pin();command['cwd']=directory
            command['executable']=dict(asset_id='public-selected-python',selected_path=str(exe),bytes=len(raw),
                sha256=digest(raw),device=stat.st_dev,inode=stat.st_ino)
            command['argv']=[str(exe),'-I',str(Path(__file__).with_name('discovery_child.py').resolve()),
                '--discovery-fd','200','--release-fd','201','--group','operator','--inventory-sha256','e'*64,'--marker',str(marker)]
            repin(command);guard=PublicTestDeadline();sink=PublicMemorySink();order=[];registered=[]
            capture=ForkExecCapture(inventory=LinuxInventory(),guard=guard,execution_gate=lambda:None,capture_sink=sink)
            def publish(notice):
                self.assertFalse(marker.exists());self.assertEqual(notice.body_bytes,body())
                self.assertEqual(notice.process['parent_pid'],os.getpid())
                order.append('publish')
                if reject_publication:raise ContractError('PUBLIC_PUBLICATION_FAILURE')
                registered.append(guard.now())
                return structural_publication(notice.body_bytes)
            def before_release(*,process,now):
                self.assertEqual(order,['publish']);self.assertFalse(marker.exists())
                order.append('fresh-check')
                return False if reject_release else None
            if reject_publication or reject_release:
                with self.assertRaises(ContractError):capture.run(command,environment={'LANG':'C.UTF-8'},
                    maximum_stream_bytes=4096,on_discovery=publish,before_release=before_release)
                self.assertFalse(marker.exists())
                self.assertEqual(order,['publish'] if reject_publication else ['publish','fresh-check'])
                return
            actual=capture.run(command,environment={'LANG':'C.UTF-8'},maximum_stream_bytes=4096,
                on_discovery=publish,before_release=before_release)
            self.assertEqual(marker.read_bytes(),b'EXECUTED_AFTER_RELEASE')
            self.assertEqual((actual.exit_code,actual.stdout,actual.stderr),(0,b'EXECUTED_AFTER_RELEASE\n',b''))
            self.assertEqual(order,['publish','fresh-check'])
            stamps=[actual.discovery.spawned,actual.discovery.collected,registered[0],actual.execution_started,actual.exited]
            self.assertEqual([utc(x['utc']) for x in stamps],sorted(utc(x['utc']) for x in stamps))
            self.assertEqual([x['boottime_ns'] for x in stamps],sorted(x['boottime_ns'] for x in stamps))
            wire=sink.readback(actual.discovery_frame_ref)
            self.assertEqual(wire[4:],body())
            self.assertEqual(sink.readback(actual.release_frame_ref),release_frame('operator',body()))
    def test_both_inherited_child_ends_nonblocking_and_release_precedes_execution(self):
        self.exercise()
    def test_publication_failure_never_releases_test_body(self):
        self.exercise(reject_publication=True)
    def test_fresh_authority_failure_never_releases_test_body(self):
        self.exercise(reject_release=True)
