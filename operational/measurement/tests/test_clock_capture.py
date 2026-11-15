"""Focused source regressions. NOT_RUN; synthetic premises are never authority."""
import unittest
from unittest.mock import Mock
from cas_forex_operational_contracts.common import ContractError
from cas_forex_measurement.capture import OriginalClock,DirectoryCaptureSink,CaptureSession
from support import budget,stamp,PublicClock,PublicMemorySink


class ClockCaptureTests(unittest.TestCase):
    def guard(self):
        clock=PublicClock();return OriginalClock(budget(),clock=clock,execution_gate=lambda:None),clock
    def test_constructor_does_not_read_clock(self):
        guard,clock=self.guard();self.assertEqual(clock.calls,0)
    def test_deadline_is_exclusive(self):
        guard,clock=self.guard();clock.value=stamp(180)
        with self.assertRaises(ContractError):guard.now()
    def test_changed_time_namespace_is_rejected(self):
        guard,clock=self.guard();clock.clock_domain['time_namespace_inode']=2
        with self.assertRaises(ContractError):guard.now()
    def test_clock_rollback_is_rejected(self):
        guard,clock=self.guard();guard.now();clock.value=stamp(0)
        with self.assertRaises(ContractError):guard.now()
    def test_utc_boottime_drift_is_rejected(self):
        guard,clock=self.guard();clock.value['boottime_ns']+=3_000_000_000
        with self.assertRaises(ContractError):guard.now()
    def test_truthy_gate_does_not_authorize(self):
        guard=OriginalClock(budget(),clock=PublicClock(),execution_gate=lambda:True)
        with self.assertRaises(ContractError):guard.now()
    def test_sink_constructor_does_not_open_root(self):
        with unittest.mock.patch('cas_forex_measurement.capture.os.open',side_effect=AssertionError):
            DirectoryCaptureSink('/public-unit-root',execution_gate=lambda:None)
    def test_gate_rejects_before_sink_open(self):
        sink=DirectoryCaptureSink('/public-unit-root',execution_gate=lambda:False)
        with unittest.mock.patch('cas_forex_measurement.capture.os.open',side_effect=AssertionError):
            with self.assertRaises(ContractError):sink.retain(b'x',artifact_kind='NATIVE_CAPTURE_BYTES')
    def test_oversize_capture_rejects_before_retention(self):
        sink=DirectoryCaptureSink('/public-unit-root',execution_gate=lambda:None)
        with self.assertRaises(ContractError):sink.retain(b'',artifact_kind='NATIVE_CAPTURE_BYTES')

    def test_drift_above_one_second_up_to_two_is_rejected(self):
        for drift in (1_000_000_001,1_500_000_000,2_000_000_000):
            with self.subTest(drift=drift):
                guard,clock=self.guard();clock.value['boottime_ns']+=drift
                with self.assertRaises(ContractError):guard.now()
    def test_config_cannot_relax_one_second_limit(self):
        with self.assertRaises(ContractError):
            OriginalClock(budget(),clock=PublicClock(),execution_gate=lambda:None,drift_ns=1_000_000_001)
    def test_watchdog_rejects_one_and_half_second_drift_without_waiting(self):
        from cas_forex_measurement.watchdog import IndependentWatchdog
        from cas_forex_operational_contracts.common import decode_canonical
        clock=PublicClock();clock.value['boottime_ns']+=1_500_000_000
        watchdog=IndependentWatchdog(clock=clock,inventory=Mock(),execution_gate=lambda:None)
        with unittest.mock.patch('cas_forex_measurement.watchdog.os.set_blocking'), \
             unittest.mock.patch('cas_forex_measurement.watchdog.os.write') as writes, \
             unittest.mock.patch('cas_forex_measurement.watchdog.select.select',side_effect=AssertionError):
            watchdog._watch(budget(),(),10,11)
        report=decode_canonical(writes.call_args_list[-1].args[1])
        self.assertEqual(report['reason'],'CLOCK_DRIFT')

    def test_nonchild_cleanup_never_sends_pid_signal(self):
        from cas_forex_measurement.inventory import terminate_owned_child
        with unittest.mock.patch('cas_forex_measurement.inventory.require_owned_child_lifecycle'), \
             unittest.mock.patch('cas_forex_measurement.inventory.os.waitid',side_effect=ChildProcessError), \
             unittest.mock.patch('cas_forex_measurement.inventory.os.kill') as kill:
            self.assertFalse(terminate_owned_child(123))
        kill.assert_not_called()
    def test_reused_boundary_cannot_relabel_native_bytes(self):
        from cas_forex_measurement.inventory import LinuxInventory
        from support import reference
        session=Mock()
        with self.assertRaises(ContractError):
            LinuxInventory()._reused_boundary((reference(b'raw','NATIVE_CAPTURE_BYTES'),{}),session=session)
        session.sink.readback.assert_not_called()
    def test_reused_boundary_requires_exact_current_session_membership(self):
        from cas_forex_measurement.inventory import LinuxInventory
        from support import reference
        from types import SimpleNamespace
        op={'kind':'PROCESS_BOUNDARY','data':{},'started':stamp()}
        session=SimpleNamespace(sink=Mock(),operations=[])
        with unittest.mock.patch('cas_forex_measurement.inventory.c.decode',return_value=SimpleNamespace(payload=lambda:op)):
            with self.assertRaises(ContractError):
                LinuxInventory()._reused_boundary((reference(b'public operation','CANONICAL_PAYLOAD'),{}),session=session)
