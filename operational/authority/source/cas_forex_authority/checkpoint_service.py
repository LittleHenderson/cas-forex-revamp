"""Explicit same-host Unix RPC, inspected ancillary data on every fragment.

No socket, thread or service is created on import/construction. The approved
bootstrap must separately supply the listener and selected process identities.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import array
import os
import socket
import stat
import struct

from cas_forex_operational_contracts import checkpoint as ck, capture
from cas_forex_operational_contracts.common import MAX_OBJECT, canonical_bytes, digest
from .authentication import AuthorityError, need, same


def _process_stat(pid):
    raw = Path(f"/proc/{pid}/stat").read_bytes()
    end = raw.rfind(b")")
    need(end > 0 and raw[:raw.find(b" ")] == str(pid).encode("ascii"), "SOURCE_OR_EXEC_IDENTITY_MISMATCH")
    fields = raw[end + 2:].split()
    return int(fields[1]), int(fields[19])


class LinuxPeerObserver:
    def observe(self, selected: capture.CaptureSubject) -> capture.CaptureSubject:
        """Read actual PID/start/parent/UID/GID and shared clock/PID namespaces."""
        try:
            capture.validate("CaptureSubject", selected)
            need(os.name == "posix", "SOURCE_OR_EXEC_IDENTITY_MISMATCH")
            pid = selected["pid"]
            before = _process_stat(pid)
            parent_pid, start_ticks = before
            parent_before = _process_stat(parent_pid)
            status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
            fields = {line.split(":", 1)[0]: line.split(":", 1)[1].split() for line in status.splitlines() if ":" in line}
            uids, gids = [int(x) for x in fields["Uid"]], [int(x) for x in fields["Gid"]]
            need(len(uids) == len(gids) == 4 and len(set(uids)) == len(set(gids)) == 1, "SOURCE_OR_EXEC_IDENTITY_MISMATCH")
            for namespace in ("time", "pid"):
                need(os.stat(f"/proc/{pid}/ns/{namespace}").st_ino == os.stat(f"/proc/self/ns/{namespace}").st_ino,
                     "CLOCK_DOMAIN_UNSUPPORTED")
            actual = {"role": selected["role"], "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                      "pid": pid, "start_ticks": start_ticks, "parent_pid": parent_pid,
                      "parent_start_ticks": parent_before[1], "uid": uids[0], "gid": gids[0]}
            need(before == _process_stat(pid) and parent_before == _process_stat(parent_pid)
                 and same(actual, selected), "SOURCE_OR_EXEC_IDENTITY_MISMATCH")
            return actual
        except AuthorityError:
            raise
        except Exception:
            raise AuthorityError("SOURCE_OR_EXEC_IDENTITY_MISMATCH") from None


@dataclass(frozen=True)
class EndpointSelection:
    """Trusted bootstrap's filesystem/socket identity, not request-supplied paths."""
    path: Path
    parent_device: int
    parent_inode: int
    socket_device: int
    socket_inode: int
    owner_uid: int
    owner_gid: int
    binding_sha256: str

    def verify(self):
        need(self.path.is_absolute() and os.name == "posix", "CHECKPOINT_AUTHORITY_UNAVAILABLE")
        current = Path(self.path.anchor)
        for part in self.path.parts[1:-1]:
            current = current / part
            value = current.lstat()
            need(stat.S_ISDIR(value.st_mode) and value.st_uid in (0, self.owner_uid)
                 and not value.st_mode & 0o022, "CHECKPOINT_AUTHORITY_UNAVAILABLE")
        parent, endpoint = self.path.parent.lstat(), self.path.lstat()
        need((parent.st_dev, parent.st_ino) == (self.parent_device, self.parent_inode)
             and (endpoint.st_dev, endpoint.st_ino) == (self.socket_device, self.socket_inode)
             and stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid == self.owner_uid
             and endpoint.st_gid == self.owner_gid and not endpoint.st_mode & 0o007,
             "CHECKPOINT_AUTHORITY_UNAVAILABLE")


def peer_credentials(connection):
    try:
        return struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    except Exception:
        raise AuthorityError("SOURCE_OR_EXEC_IDENTITY_MISMATCH") from None


class CredentialFramer:
    def __init__(self, *, guard, peers):
        self.guard, self.peers = guard, peers

    def _peer(self, connection, expected):
        need(peer_credentials(connection) == (expected["pid"], expected["uid"], expected["gid"]), "SOURCE_OR_EXEC_IDENTITY_MISMATCH")
        self.peers.observe(expected)
        self.guard.check()

    @staticmethod
    def _ancillary(ancillary, flags, expected):
        rights, credentials, other = [], [], False
        for level, kind, raw in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                values = array.array("i")
                values.frombytes(raw[:len(raw) - len(raw) % values.itemsize])
                rights.extend(values)
                other = True
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(raw) == struct.calcsize("3i"):
                credentials.append(struct.unpack("3i", raw))
            else:
                other = True
        close_failed = False
        # Close every actually delivered descriptor once, including truncation.
        # Never retry an uncertain close on a possibly reused descriptor number.
        for descriptor in dict.fromkeys(rights):
            try:
                os.close(descriptor)
            except OSError:
                close_failed = True
        need(not close_failed, "CALIBRATION_DESCRIPTOR_CLEANUP_INCOMPLETE")
        need(not other and not rights and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "DESCRIPTOR_IDENTITY_MISMATCH")
        need(credentials == [(expected["pid"], expected["uid"], expected["gid"])], "SOURCE_OR_EXEC_IDENTITY_MISMATCH")

    def receive(self, connection, *, expected, deadline):
        self._peer(connection, expected)
        data = bytearray()
        target = 4
        while len(data) < target:
            connection.settimeout(self.guard.remaining(deadline))
            chunk, ancillary, flags, _ = connection.recvmsg(target - len(data), socket.CMSG_SPACE(256 * 4) + socket.CMSG_SPACE(12), socket.MSG_CMSG_CLOEXEC)
            self._ancillary(ancillary, flags, expected)
            self._peer(connection, expected)
            need(bool(chunk), "CHECKPOINT_AUTHORITY_UNAVAILABLE")
            data.extend(chunk)
            if len(data) == 4 and target == 4:
                length = int.from_bytes(data, "big")
                need(0 < length and length + 4 <= MAX_OBJECT, "RAW_BYTES_MISMATCH")
                target = length + 4
        self.guard.remaining(deadline)
        return ck.decode_frame(bytes(data)).payload()

    def send(self, connection, envelope, *, expected, deadline):
        frame = ck.encode_frame(envelope)
        offset = 0
        while offset < len(frame):
            self._peer(connection, expected)
            connection.settimeout(self.guard.remaining(deadline))
            written = connection.send(frame[offset:])
            need(written > 0, "CHECKPOINT_AUTHORITY_UNAVAILABLE")
            offset += written
        self._peer(connection, expected)


class CheckpointService:
    def __init__(self, *, authentication, store, signer, peers, own_process):
        self.auth, self.store, self.signer = authentication, store, signer
        self.peers, self.own_process = peers, own_process
        self.framer = CredentialFramer(guard=authentication.guard, peers=peers)
        self.authority_id = authentication.principal("INDEPENDENT_CHECKPOINT_CUSTODIAN")["principal_id"]
        self._seen = set()

    def handle(self, envelope, *, actual_peer, now):
        """Internal handler; serve_connection supplies an independently read peer."""
        self.auth.current(now)
        candidates = [g for g in self.auth.access["callers"] if same(g["actual_process"], actual_peer)]
        need(len(candidates) == 1, "SIGNER_UNAPPOINTED")
        grant = candidates[0]
        self.peers.observe(grant["actual_process"])
        key = self.auth.key(grant["principal_id"])
        need(digest(key) == grant["signer_public_sha256"], "SIGNER_UNAPPOINTED")
        request = self.auth.verify_rpc(envelope, domain=ck.REQUEST_DOMAIN, public_key=key, type_name="CheckpointRpcRequest")
        need(request["caller_id"] == grant["principal_id"] and request["operation"] in grant["operations"]
             and request["use"] in grant["uses"], "PURPOSE_MISMATCH")
        nonce = (grant["principal_id"], request["nonce_hex"])
        need(len(self._seen) < 1024 and nonce not in self._seen, "REPLAY_OR_EQUIVOCATION")
        self._seen.add(nonce)
        self.auth.guard.remaining(request["deadline"])
        operation = {"READ_CURRENT": self.store.read_current, "ADVANCE": self.store.compare_and_append,
                     "LOOKUP_TRANSITION": self.store.lookup_exact}[request["operation"]]
        result = operation(request, authenticated_caller=grant, now=self.auth.guard.check())
        self.auth.current()
        self.peers.observe(grant["actual_process"])
        raw = ck.validate("CheckpointRpcResponse", result).raw
        signature = self.signer.sign(domain=ck.RESPONSE_DOMAIN, canonical_body=raw)
        self.auth.current()
        self.auth.guard.remaining(request["deadline"])
        return ck.validate("RpcSignature", {"body_utf8": raw.decode("utf-8"), "signer_sha256": digest(self.auth.key(self.authority_id)),
                                           "algorithm": "Ed25519", "signature_hex": signature.hex()}).payload(), request["deadline"]

    def serve_connection(self, connection):
        """Exactly one request; failure closes connection and exposes no fallback."""
        with connection:
            need(connection.family == socket.AF_UNIX and connection.type & socket.SOCK_STREAM, "CHECKPOINT_AUTHORITY_UNAVAILABLE")
            need(connection.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1, "SOURCE_OR_EXEC_IDENTITY_MISMATCH")
            need(self.own_process["pid"] == os.getpid() and self.own_process["role"] == "CHECKPOINT_CUSTODIAN"
                 and self.own_process["uid"] == self.store.database.selection.owner_uid
                 and self.own_process["gid"] == self.store.database.selection.owner_gid, "SIGNER_UNAPPOINTED")
            self.peers.observe(self.own_process)
            credentials = peer_credentials(connection)
            grants = [g for g in self.auth.access["callers"] if credentials == tuple(g["actual_process"][k] for k in ("pid", "uid", "gid"))]
            need(len(grants) == 1, "SIGNER_UNAPPOINTED")
            expected = grants[0]["actual_process"]
            envelope = self.framer.receive(connection, expected=expected, deadline=self.auth.guard.budget["deadline"])
            response, deadline = self.handle(envelope, actual_peer=self.peers.observe(expected), now=self.auth.guard.check())
            self.framer.send(connection, response, expected=expected, deadline=deadline)

    def serve_one(self, listener):
        """Approved host bootstrap supplies the bound/listening AF_UNIX socket.

        SO_PASSCRED must already be set before any client can send a fragment.
        There is no initialization, bind, reset, permission change or IP listener.
        """
        need(listener.family == socket.AF_UNIX and listener.type & socket.SOCK_STREAM
             and listener.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) == 1, "CHECKPOINT_AUTHORITY_UNAVAILABLE")
        self.auth.current()
        listener.settimeout(self.auth.guard.remaining())
        connection, _ = listener.accept()
        self.serve_connection(connection)


class UnixCheckpointTransport:
    def __init__(self, *, endpoint: EndpointSelection, authentication, peers, server_process):
        self.endpoint, self.auth, self.peers, self.server_process = endpoint, authentication, peers, server_process
        need(endpoint.binding_sha256 == authentication.access["endpoint_binding_sha256"], "CONTEXT_MISMATCH")
        self.framer = CredentialFramer(guard=authentication.guard, peers=peers)

    def exchange(self, request, *, deadline):
        self.auth.current()
        body = ck.decode("CheckpointRpcRequest", request["body_utf8"].encode("utf-8")).payload()
        grants = [g for g in self.auth.access["callers"] if g["principal_id"] == body["caller_id"]]
        need(len(grants) == 1 and grants[0]["actual_process"]["pid"] == os.getpid(), "SIGNER_UNAPPOINTED")
        self.peers.observe(grants[0]["actual_process"])
        self.endpoint.verify()
        self.peers.observe(self.server_process)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                connection.settimeout(self.auth.guard.remaining(deadline))
                connection.connect(str(self.endpoint.path))
                self.endpoint.verify()
                self.framer.send(connection, request, expected=self.server_process, deadline=deadline)
                result = self.framer.receive(connection, expected=self.server_process, deadline=deadline)
                self.auth.current()
                self.endpoint.verify()
                return result
        except AuthorityError:
            raise
        except Exception:
            # A lost reply may follow a durable commit. No retry or new ADVANCE.
            raise AuthorityError("CHECKPOINT_ADVANCE_UNCONFIRMED") from None
