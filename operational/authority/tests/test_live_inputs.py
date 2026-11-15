"""Public fake-status and real-file unit sources. NOT_RUN; no live authority.

PIDfd/proc/crypto interactions are mocked; file tests use a declared directory
seam and therefore do not prove protected-root isolation or real process liveness.
"""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from threading import Thread, Event
from tempfile import TemporaryDirectory
from unittest import TestCase, skipUnless
from unittest.mock import patch, Mock
import os

from cas_forex_operational_contracts import checkpoint as ck
from cas_forex_operational_contracts.common import canonical_bytes
from cas_forex_authority.authentication import AuthorityError, LiveAuthorityView, OriginalGuard
from cas_forex_authority.live_inputs import (StatusFileSelection, SelectedStatusFile,
    PidfdAuthorityFeed, MailboxStatusProvider)
from support import fixture, fixture_preloaded_verifier, signed_rpc, process, stamp


def setup_feed():
    f=fixture();v=fixture_preloaded_verifier(f)
    mailbox=LiveAuthorityView(selection=f.auth.selection,budget=f.budget,verifier=v)
    selection=StatusFileSelection(Path.cwd()/"public-status-fixture","current-status.json",1,2,1000,1000,
        canonical_bytes(process("CHECKPOINT_CUSTODIAN",30,1000)))
    source=SelectedStatusFile(selection)
    feed=PidfdAuthorityFeed(source=source,mailbox=mailbox,guard=f.guard,execution_gate=lambda:None)
    envelope=signed_rpc(f.status,ck.AUTHORITY_STATUS_DOMAIN,bytes([4])*32)
    return f,mailbox,source,feed,envelope


@contextmanager
def public_feed_io(feed,source,envelope):
    # These are public unit seams, not substitutes accepted by deployment.
    with patch("cas_forex_authority.live_inputs.os.name","posix"), \
         patch("cas_forex_authority.live_inputs.os.pidfd_open",return_value=100,create=True) as opened, \
         patch("cas_forex_authority.live_inputs.os.get_inheritable",return_value=False), \
         patch("cas_forex_authority.live_inputs.os.close") as closed, \
         patch("cas_forex_authority.live_inputs.select.select",return_value=([],[],[])) as polled, \
         patch.object(feed._peers,"observe",side_effect=lambda value:value), \
         patch.object(source,"read_current",return_value=envelope) as read:
        yield opened,closed,polled,read


@contextmanager
def held_by_other_thread(lock):
    held,release=Event(),Event()
    def holder():
        with lock:
            held.set();release.wait(2)
    thread=Thread(target=holder);thread.start()
    try:
        if not held.wait(1):raise AssertionError("test thread did not acquire fixture lock")
        yield
    finally:
        release.set();thread.join(2)
        if thread.is_alive():raise AssertionError("test thread did not finish")


class AuthorityFeedTests(TestCase):
    def test_constructor_never_attaches_or_reads(self):
        with patch("cas_forex_authority.live_inputs.os.pidfd_open",create=True) as opened:
            f,mailbox,source,feed,envelope=setup_feed()
            opened.assert_not_called()
            with self.assertRaises(AuthorityError):mailbox.current_authority(stamp(1))

    def test_absent_execution_approval_rejects_before_attachment(self):
        f,mailbox,source,feed,envelope=setup_feed()
        feed.gate=lambda:False
        with public_feed_io(feed,source,envelope) as (opened,_,_,read):
            with self.assertRaises(AuthorityError):feed.open()
            opened.assert_not_called();read.assert_not_called()
        with self.assertRaises(AuthorityError):mailbox.current_authority(stamp(1))

    def test_exit_after_publication_invalidates_that_publication(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with public_feed_io(feed,source,envelope) as (_,closed,polled,_):
            polled.side_effect=[([],[],[]),([],[],[]),([],[],[]),([100],[],[])]
            feed.open()
            with self.assertRaises(AuthorityError):feed.refresh()
            closed.assert_called_once_with(100)
            with self.assertRaises(AuthorityError):mailbox.current_envelope(stamp(1))

    def test_refresh_requires_explicit_open(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with self.assertRaises(AuthorityError):feed.refresh()
        with self.assertRaises(AuthorityError):mailbox.publish_authenticated(envelope,observed=stamp(1))

    def test_selected_signed_file_refresh_retains_exact_signature(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with public_feed_io(feed,source,envelope) as (opened,closed,polled,read):
            feed.open();self.assertEqual(feed.refresh(),canonical_bytes(envelope))
            self.assertEqual(mailbox.current_envelope(stamp(1)),envelope)
            opened.assert_called_once_with(30,0);read.assert_called_once()
            feed.close();closed.assert_called_once_with(100)
        with self.assertRaises(AuthorityError):mailbox.current_envelope(stamp(1))

    def test_read_failure_invalidates_existing_snapshot(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with public_feed_io(feed,source,envelope) as (_,closed,_,read):
            feed.open();feed.refresh();read.side_effect=OSError("public fixture missing")
            with self.assertRaises(OSError):feed.refresh()
            closed.assert_called_once_with(100)
            with self.assertRaises(AuthorityError):mailbox.current_envelope(stamp(1))

    def test_pidfd_exit_rejects_before_file_refresh(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with public_feed_io(feed,source,envelope) as (_,closed,polled,read):
            feed.open();polled.return_value=([100],[],[])
            with self.assertRaises(AuthorityError):feed.refresh()
            read.assert_not_called();closed.assert_called_once_with(100)

    def test_changed_signature_invalidates_prior_valid_observation(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with public_feed_io(feed,source,envelope) as (_,closed,_,read):
            feed.open();feed.refresh();read.return_value={**envelope,"signature_hex":"00"*64}
            with self.assertRaises(Exception):feed.refresh()
            with self.assertRaises(AuthorityError):mailbox.current_authority(stamp(1))

    def test_withdrawn_status_is_terminal_for_the_mailbox(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with public_feed_io(feed,source,envelope) as (_,closed,_,read):
            feed.open();feed.refresh();f.status["status"]="WITHDRAWN";f.status["revision"]+=1
            read.return_value=signed_rpc(f.status,ck.AUTHORITY_STATUS_DOMAIN,bytes([4])*32)
            with self.assertRaises(AuthorityError):feed.refresh()
            f.status["status"]="ACTIVE";f.status["revision"]+=1
            again=signed_rpc(f.status,ck.AUTHORITY_STATUS_DOMAIN,bytes([4])*32)
            with self.assertRaises(AuthorityError):mailbox.publish_authenticated(again,observed=stamp(1))

    def test_failed_feed_never_reattaches_implicitly(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with public_feed_io(feed,source,envelope) as (opened,_,_,read):
            feed.open();read.side_effect=OSError("public fixture unavailable")
            with self.assertRaises(OSError):feed.refresh()
            with self.assertRaises(AuthorityError):feed.open()
            opened.assert_called_once()

    def test_original_deadline_expiry_invalidates_feed(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with public_feed_io(feed,source,envelope):
            feed.open();feed.refresh();f.clock.now=stamp(180)
            with self.assertRaises(AuthorityError):feed.refresh()
            with self.assertRaises(AuthorityError):mailbox.current_authority(stamp(1))

    def test_busy_feed_rejects_without_wait_and_invalidates(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with public_feed_io(feed,source,envelope):
            feed.open();feed.refresh()
            with held_by_other_thread(feed._lock):
                with self.assertRaises(AuthorityError):feed.refresh()
            with self.assertRaises(AuthorityError):mailbox.current_authority(stamp(1))
            feed.close()

    def test_invalidation_during_verification_cannot_be_overwritten_by_publish(self):
        f,mailbox,source,feed,envelope=setup_feed();verify=mailbox.verifier.verify
        def invalidate(**kwargs):
            result=verify(**kwargs);mailbox.invalidate();return result
        with patch.object(mailbox.verifier,"verify",side_effect=invalidate):
            with self.assertRaises(AuthorityError):mailbox.publish_authenticated(envelope,observed=stamp(1))
        with self.assertRaises(AuthorityError):mailbox.current_authority(stamp(1))

    def test_provider_returns_original_envelope_with_two_time_checks(self):
        f,mailbox,source,feed,envelope=setup_feed()
        mailbox.publish_authenticated(envelope,observed=stamp(1))
        provider=MailboxStatusProvider(mailbox=mailbox,guard=f.guard)
        with patch.object(f.guard,"check",wraps=f.guard.check) as clock:
            self.assertEqual(provider(),envelope);self.assertEqual(clock.call_count,2)

    def test_guard_can_fail_on_lock_contention_before_clock_io(self):
        f=fixture();guard=OriginalGuard(f.budget,clock=f.clock,nonblocking_lock=True)
        with patch.object(f.clock,"observe",wraps=f.clock.observe) as observation:
            with held_by_other_thread(guard._lock):
                with self.assertRaises(AuthorityError):guard.check()
            observation.assert_not_called()

    def test_status_revision_lock_can_fail_without_wait(self):
        f=fixture();f.auth._nonblocking_status_lock=True
        with held_by_other_thread(f.auth._lock):
            with self.assertRaises(AuthorityError) as caught:f.auth.current()
        self.assertEqual(caught.exception.code,"AUTHORITY_STATUS_BUSY")

    def test_new_lock_mode_does_not_turn_domain_mismatch_into_a_cached_success(self):
        f=fixture();guard=OriginalGuard(f.budget,clock=f.clock,nonblocking_lock=True)
        f.clock.domain={**f.clock.domain,"time_namespace_inode":78}
        with self.assertRaises(AuthorityError):guard.check()

    def test_slow_file_observation_cannot_receive_a_new_freshness_stamp(self):
        f,mailbox,source,feed,envelope=setup_feed()
        with public_feed_io(feed,source,envelope) as (_,closed,_,read):
            feed.open()
            def delayed():
                f.clock.now=stamp(2);return envelope
            read.side_effect=delayed
            with self.assertRaises(AuthorityError) as caught:feed.refresh()
            self.assertEqual(caught.exception.code,"AUTHORITY_SOURCE_STALE")
            self.assertIsNone(mailbox._value)
            closed.assert_called_once_with(100)

    def test_slow_authentication_rechecks_age_at_fresh_finish_time(self):
        f,mailbox,source,feed,envelope=setup_feed();verify=mailbox.verifier.verify
        with public_feed_io(feed,source,envelope):
            feed.open()
            def delayed(**kwargs):
                result=verify(**kwargs);f.clock.now=stamp(2);return result
            with patch.object(mailbox.verifier,"verify",side_effect=delayed):
                with self.assertRaises(AuthorityError):feed.refresh()
            with self.assertRaises(AuthorityError):mailbox.current_authority(stamp(2))

    def test_source_selector_cannot_escape_with_filename(self):
        f,mailbox,source,feed,envelope=setup_feed()
        for bad in ("..","../status","sub/status","sub\\status"):
            with self.subTest(bad=bad),self.assertRaises(AuthorityError):
                SelectedStatusFile(replace(source.selection,filename=bad))


@skipUnless(os.name=="posix","Linux file reader source tests")
class StatusFileTests(TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        f=fixture();self.envelope=signed_rpc(f.status,ck.AUTHORITY_STATUS_DOMAIN,bytes([4])*32)
        info=self.root.stat();self.selection=StatusFileSelection(self.root,"current.json",info.st_dev,info.st_ino,os.getuid(),os.getgid(),canonical_bytes(process("CHECKPOINT_CUSTODIAN",30,1000)))
        self.source=SelectedStatusFile(self.selection)
        # Explicit seam: temporary ancestors are not protected production roots.
        self.source._directory=lambda:os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        self.path=self.root/"current.json";self.path.write_bytes(canonical_bytes(self.envelope));self.path.chmod(0o600)

    def test_exact_signed_file_shape_read(self):self.assertEqual(self.source.read_current(),self.envelope)

    def test_noncanonical_file_is_rejected(self):
        self.path.write_bytes(b" " + canonical_bytes(self.envelope))
        with self.assertRaises(Exception):self.source.read_current()

    def test_symlink_is_rejected(self):
        self.path.unlink();self.path.symlink_to(self.root/"other.json")
        with self.assertRaises(OSError):self.source.read_current()

    def test_group_writable_file_is_rejected(self):
        self.path.chmod(0o660)
        with self.assertRaises(AuthorityError):self.source.read_current()

    def test_hard_link_is_rejected(self):
        os.link(self.path,self.root/"alias.json")
        with self.assertRaises(AuthorityError):self.source.read_current()

    def test_oversized_file_is_rejected_before_decode(self):
        self.path.write_bytes(b"x"*65537)
        with self.assertRaises(AuthorityError):self.source.read_current()

    def test_file_changed_during_read_is_rejected(self):
        read=os.read;changed=False
        def mutate(fd,size):
            nonlocal changed
            raw=read(fd,size)
            if raw and not changed:
                changed=True;self.path.write_bytes(b"{}")
            return raw
        with patch("cas_forex_authority.live_inputs.os.read",side_effect=mutate):
            with self.assertRaises(AuthorityError):self.source.read_current()
