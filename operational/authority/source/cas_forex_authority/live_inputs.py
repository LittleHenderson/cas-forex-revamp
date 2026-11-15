"""Explicit Linux current-status acquisition outside the NR12 final gap.

Uses the existing signed RpcSignature/AuthorityStatus wire, never a new domain.
Construction is inert. No thread, status publisher, security setup or scheduler
is installed here. The selected source is public signed authority status only.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
import os
import select
import stat

from cas_forex_operational_contracts import checkpoint as ck, capture
from cas_forex_operational_contracts.common import canonical_bytes, decode_canonical, utc
from .authentication import AuthorityError, LiveAuthorityView, need, same, micros, stamp_le
from .checkpoint_service import LinuxPeerObserver


@dataclass(frozen=True)
class StatusFileSelection:
    """Private deployment selection; not an attestation or shared wire record.

    The selected file must be the authoritative current-status register, not a
    periodic copy or cache. That route and its independent publisher must be
    selected by approved pinned host bootstrap, never by the workload. Reading
    the file cannot establish those external deployment facts by itself.
    """
    directory: Path
    filename: str
    directory_device: int
    directory_inode: int
    owner_uid: int
    owner_gid: int
    delivery_process_raw: bytes
    maximum_bytes: int = 65536


class SelectedStatusFile:
    """Read-only source. The selector cannot come from a workload request."""
    def __init__(self, selection: StatusFileSelection):
        need(type(selection) is StatusFileSelection and selection.directory.is_absolute()
             and type(selection.filename) is str and selection.filename not in ("", ".", "..")
             and Path(selection.filename).name == selection.filename
             and "/" not in selection.filename and "\\" not in selection.filename,
             "AUTHORITY_SOURCE_UNAVAILABLE")
        need(type(selection.maximum_bytes) is int and 0 < selection.maximum_bytes <= 65536
             and all(type(x) is int and x >= 0 for x in (selection.owner_uid,selection.owner_gid,selection.directory_device))
             and type(selection.directory_inode) is int and selection.directory_inode > 0,
             "AUTHORITY_SOURCE_UNAVAILABLE")
        capture.decode("CaptureSubject", selection.delivery_process_raw)
        self.selection = selection

    def _directory(self):
        """Open every component relative to the previous protected directory."""
        need(os.name == "posix" and hasattr(os,"O_NOFOLLOW"), "AUTHORITY_SOURCE_UNAVAILABLE")
        s=self.selection
        flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
        current=os.open(s.directory.anchor,flags)
        try:
            anchor=os.fstat(current)
            need(stat.S_ISDIR(anchor.st_mode) and anchor.st_uid in (0,s.owner_uid)
                 and not anchor.st_mode & 0o022,"AUTHORITY_SOURCE_UNAVAILABLE")
            for component in s.directory.parts[1:]:
                need(component not in (".",".."),"AUTHORITY_SOURCE_UNAVAILABLE")
                opened=os.open(component,flags,dir_fd=current)
                try:
                    info=os.fstat(opened)
                    need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,s.owner_uid)
                         and not info.st_mode & 0o022,"AUTHORITY_SOURCE_UNAVAILABLE")
                except BaseException:
                    os.close(opened);raise
                os.close(current);current=opened
            info=os.fstat(current)
            need((info.st_dev,info.st_ino)==(s.directory_device,s.directory_inode)
                 and info.st_uid==s.owner_uid and info.st_gid==s.owner_gid,
                 "AUTHORITY_SOURCE_UNAVAILABLE")
            result=current;current=None;return result
        finally:
            if current is not None:os.close(current)

    @staticmethod
    def _identity(info):
        return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,
                info.st_mode,info.st_uid,info.st_gid,info.st_nlink)

    def read_current(self) -> ck.RpcSignature:
        """Bounded actual file read; may block on storage, so never in final gap."""
        s=self.selection;directory=self._directory();descriptor=None
        try:
            descriptor=os.open(s.filename,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=directory)
            before=os.fstat(descriptor)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1
                 and before.st_uid==s.owner_uid and before.st_gid==s.owner_gid
                 and stat.S_IMODE(before.st_mode) in (0o600,0o640)
                 and 0<before.st_size<=s.maximum_bytes,"AUTHORITY_SOURCE_UNAVAILABLE")
            data=bytearray()
            while len(data)<=s.maximum_bytes:
                chunk=os.read(descriptor,min(16384,s.maximum_bytes+1-len(data)))
                if not chunk:break
                data.extend(chunk)
            after=os.fstat(descriptor)
            current=os.stat(s.filename,dir_fd=directory,follow_symlinks=False)
            need(0<len(data)<=s.maximum_bytes and len(data)==before.st_size
                 and self._identity(before)==self._identity(after)==self._identity(current),
                 "AUTHORITY_SOURCE_CHANGED")
            # Re-resolve the selected directory after I/O, not only its held FD.
            check=self._directory()
            try:need((os.fstat(check).st_dev,os.fstat(check).st_ino)==(s.directory_device,s.directory_inode),"AUTHORITY_SOURCE_CHANGED")
            finally:os.close(check)
            return ck.decode("RpcSignature",bytes(data)).payload()
        finally:
            if descriptor is not None:os.close(descriptor)
            os.close(directory)


class PidfdAuthorityFeed:
    """One-attempt explicit refreshes; any observed failure is terminal.

    A live PIDfd proves only that the selected delivery process has not exited.
    It is not a heartbeat or proof that the external authorizer remains healthy.
    Freshness is the bounded successful current-file observation in the mailbox.
    The delivery route, signed file and scheduling are independently selected.
    """
    def __init__(self, *, source: SelectedStatusFile, mailbox: LiveAuthorityView,
                 guard, execution_gate):
        need(type(source) is SelectedStatusFile and type(mailbox) is LiveAuthorityView
             and callable(execution_gate),"AUTHORITY_SOURCE_UNAVAILABLE")
        self.source,self.mailbox,self.guard,self.gate=source,mailbox,guard,execution_gate
        self._subject_raw=source.selection.delivery_process_raw
        self._lock=Lock();self._pidfd=None;self._state="NEW";self._failed=False
        self._peers=LinuxPeerObserver()
        need(same(decode_canonical(mailbox._budget),guard.budget),"CONTEXT_MISMATCH")

    def _alive(self):
        need(self._pidfd is not None and not self._failed,"AUTHORITY_SOURCE_UNAVAILABLE")
        readable,_,exceptional=select.select([self._pidfd],[],[self._pidfd],0)
        need(not readable and not exceptional,"AUTHORITY_DELIVERY_PROCESS_EXITED")

    def _fail(self):
        self._failed=True
        self.mailbox.invalidate()

    def open(self) -> None:
        """Explicit approved read-only attachment, never process creation."""
        if not self._lock.acquire(blocking=False):
            self._fail();raise AuthorityError("AUTHORITY_SOURCE_BUSY")
        try:
            need(self._state=="NEW" and not self._failed,"AUTHORITY_SOURCE_UNAVAILABLE")
            self._state="OPENING"
            need(self.gate() is None,"RUNTIME_APPROVAL_ABSENT")
            self.guard.check()
            need(os.name=="posix" and hasattr(os,"pidfd_open"),"AUTHORITY_SOURCE_UNAVAILABLE")
            subject=capture.decode("CaptureSubject",self._subject_raw).payload()
            self._peers.observe(subject)
            self._pidfd=os.pidfd_open(subject["pid"],0)
            need(not os.get_inheritable(self._pidfd),"AUTHORITY_SOURCE_UNAVAILABLE")
            self._peers.observe(subject);self._alive();self.guard.check()
            need(not self._failed,"AUTHORITY_SOURCE_UNAVAILABLE")
            self._state="OPEN"
        except BaseException:
            self._fail();self._state="FAILED"
            descriptor,self._pidfd=self._pidfd,None
            if descriptor is not None:os.close(descriptor)
            raise
        finally:self._lock.release()

    def refresh(self) -> bytes:
        """Acquire current status outside final gap, then authenticate/publish."""
        if not self._lock.acquire(blocking=False):
            self._fail();raise AuthorityError("AUTHORITY_SOURCE_BUSY")
        try:
            need(self._state=="OPEN" and not self._failed,"AUTHORITY_SOURCE_UNAVAILABLE")
            need(self.gate() is None,"RUNTIME_APPROVAL_ABSENT")
            self.guard.check();self._alive()
            subject=capture.decode("CaptureSubject",self._subject_raw).payload()
            self._peers.observe(subject)
            # Conservative interval start: slow acquisition must not turn an
            # old file observation into a newly stamped freshness lease.
            observed=self.guard.check()
            envelope=self.source.read_current()
            self._peers.observe(subject);self._alive()
            acquired=self.guard.check()
            need(stamp_le(observed,acquired)
                 and acquired["boottime_ns"]-observed["boottime_ns"]<=self.mailbox.maximum_age_ns
                 and micros(utc(acquired["utc"])-utc(observed["utc"]))*1000<=self.mailbox.maximum_age_ns,
                 "AUTHORITY_SOURCE_STALE")
            need(not self._failed,"AUTHORITY_SOURCE_UNAVAILABLE")
            self.mailbox.publish_authenticated(envelope,observed=observed)
            self._alive();finished=self.guard.check()
            need(not self._failed,"AUTHORITY_SOURCE_UNAVAILABLE")
            # Recheck age after authentication too, using fresh current time.
            # Withdrawal or a stale publication terminates this attempt.
            self.mailbox.current_authority(finished)
            return canonical_bytes(envelope)
        except BaseException:
            self._fail();self._state="FAILED"
            descriptor,self._pidfd=self._pidfd,None
            if descriptor is not None:os.close(descriptor)
            raise
        finally:self._lock.release()

    def close(self) -> None:
        """Invalidate first. Descriptor cleanup failure never means continuity."""
        self._fail()
        if not self._lock.acquire(blocking=False):raise AuthorityError("AUTHORITY_SOURCE_BUSY")
        try:
            self._state="CLOSED"
            descriptor,self._pidfd=self._pidfd,None
            if descriptor is not None:os.close(descriptor)
        finally:self._lock.release()


class MailboxStatusProvider:
    """Exact existing MethodAuthenticator.current_status callback binding.

    Current clock/domain acquisition is deliberately not invented here. The
    injected OriginalGuard must satisfy its call site's acquisition restrictions.
    A LinuxOriginalClock-backed provider is for outside the final gap only.
    """
    def __init__(self, *, mailbox, guard):
        need(type(mailbox) is LiveAuthorityView,"AUTHORITY_SOURCE_UNAVAILABLE")
        need(same(decode_canonical(mailbox._budget),guard.budget),"CONTEXT_MISMATCH")
        self.mailbox,self.guard=mailbox,guard

    def __call__(self) -> ck.RpcSignature:
        before=self.guard.check()
        envelope=self.mailbox.current_envelope(before)
        after=self.guard.check()
        need(same(envelope,self.mailbox.current_envelope(after)),"APPOINTMENT_EXPIRED_OR_UNAVAILABLE")
        return envelope
