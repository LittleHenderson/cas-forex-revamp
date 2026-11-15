"""Linux protected-record reader. No I/O at construction or import.

This is a source proposal, NOT_RUN. It checks storage properties, not publisher
authority. No permission/mount/credential changes. Read descriptor bytes only
after a no-follow walk of every ancestor and a read-only/root-owned check.
"""
import os
import stat
import sys
from pathlib import PurePosixPath

from .evidence_types import Blocked, decode, need, raw_digest, reference


class ProtectedResolver:
    def __init__(self, selected_base, *, require_remaining):
        self.base = PurePosixPath(selected_base)
        need(str(self.base) == selected_base and self.base.parent == PurePosixPath("/opt/cas-forex"))
        # Independently selected original UTC/monotonic window guard. No clock
        # is created/reset here. An outer watchdog must bound stalled kernel I/O.
        need(callable(require_remaining), "ORIGINAL_DEADLINE_GUARD_REQUIRED")
        self.require_remaining = require_remaining

    def _remaining(self):
        need(self.require_remaining() is None, "ORIGINAL_DEADLINE_GUARD_PROTOCOL")

    @staticmethod
    def _metadata(info, *, directory):
        need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
             and info.st_uid == 0 and info.st_mode & 0o022 == 0, "PIN_MISMATCH")
        if not directory:
            need(info.st_nlink == 1, "PIN_MISMATCH")

    @staticmethod
    def _stable(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink,
                info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _open_regular(self, name, *, dir_fd, descriptors):
        """Metadata first; never wait for a FIFO writer or read a special file.

        Caller owns the accumulated descriptors, including on failure. The only
        production caller is read(), after its confined no-follow ancestor walk.
        """
        self._remaining()
        metadata_fd = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
        descriptors.append(metadata_fd)
        selected = os.fstat(metadata_fd)
        self._metadata(selected, directory=False)
        self._remaining()
        # If the directory entry changes to a FIFO after metadata validation,
        # the nonblocking data open still cannot wait for a writer. Type and
        # inode metadata are rechecked before any read by the caller.
        target = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
        descriptors.append(target)
        before = os.fstat(target)
        self._metadata(before, directory=False)
        need(self._stable(selected) == self._stable(before), "PIN_MISMATCH")
        self._remaining()
        return target, before

    def read(self, row):
        self._remaining()
        reference(row)
        path = PurePosixPath(row["path"])
        need(path.is_relative_to(self.base) and path != self.base, "PIN_MISMATCH")
        need(sys.platform == "linux" and all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_PATH")),
             "PROTECTED_READER_UNSUPPORTED")
        descriptors = []
        try:
            self._remaining()
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            descriptors.append(fd)
            self._metadata(os.fstat(fd), directory=True)
            for part in path.parts[1:-1]:
                self._remaining()
                fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                descriptors.append(fd)
                self._metadata(os.fstat(fd), directory=True)
            target, before = self._open_regular(path.name, dir_fd=fd, descriptors=descriptors)
            need(os.fstatvfs(target).f_flag & os.ST_RDONLY, "PIN_MISMATCH")
            need(before.st_size == row["bytes"], "PIN_MISMATCH")
            chunks, remaining = [], row["bytes"] + 1
            while remaining:
                self._remaining()
                block = os.read(target, min(65536, remaining))
                self._remaining()
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            raw = b"".join(chunks)
            after = os.fstat(target)
            need(self._stable(before) == self._stable(after) and len(raw) == row["bytes"]
                 and raw_digest(raw) == row["sha256"], "PIN_MISMATCH")
            self._remaining()
            value = decode(raw)
            self._remaining()
            return raw, value
        except OSError:
            raise Blocked("EVIDENCE_UNAVAILABLE") from None
        finally:
            for fd in reversed(descriptors):
                os.close(fd)

