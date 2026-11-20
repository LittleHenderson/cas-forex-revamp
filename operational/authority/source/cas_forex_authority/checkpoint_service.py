"""Explicit same-host Unix RPC, inspected ancillary data on every fragment.

No socket, thread or service is created on import/construction. The approved
bootstrap must separately supply the listener and selected process identities.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
import array
import os
import socket
import stat
import struct

from cas_forex_operational_contracts import checkpoint as ck, capture
from cas_forex_operational_contracts.common import MAX_OBJECT, canonical_bytes, digest, utc
from .authentication import AuthorityError, need, same, stamp_le


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


def _stamp_expired(actual, deadline) -> bool:
    """Return True once ``actual`` has reached or passed ``deadline`` in UTC or boottime_ns.

    Matches OriginalGuard.remaining() which requires strictly positive remaining time in both
    clocks; once expired, any replayed request with that deadline is rejected with
    SETUP_DEADLINE_EXPIRED before replay-cache consultation.
    """
    return utc(actual["utc"]) >= utc(deadline["utc"]) or actual["boottime_ns"] >= deadline["boottime_ns"]


class CheckpointService:
    DEFAULT_PER_PRINCIPAL_READ_CAPACITY = 256
    DEFAULT_PER_PRINCIPAL_RATE_LIMIT = 256
    DEFAULT_RATE_WINDOW_NS = 1_000_000_000  # 1s sliding rate window per principal

    def __init__(
        self,
        *,
        authentication,
        store,
        signer,
        peers,
        own_process,
        per_principal_read_capacity: int = DEFAULT_PER_PRINCIPAL_READ_CAPACITY,
        per_principal_rate_limit: int = DEFAULT_PER_PRINCIPAL_RATE_LIMIT,
        rate_window_ns: int = DEFAULT_RATE_WINDOW_NS,
    ):
        need(type(per_principal_read_capacity) is int and per_principal_read_capacity >= 1, "CONTEXT_MISMATCH")
        need(type(per_principal_rate_limit) is int and per_principal_rate_limit >= 1, "CONTEXT_MISMATCH")
        need(type(rate_window_ns) is int and rate_window_ns >= 1, "CONTEXT_MISMATCH")
        self.auth, self.store, self.signer = authentication, store, signer
        self.peers, self.own_process = peers, own_process
        self.framer = CredentialFramer(guard=authentication.guard, peers=peers)
        self.authority_id = authentication.principal("INDEPENDENT_CHECKPOINT_CUSTODIAN")["principal_id"]
        self._per_principal_read_capacity = per_principal_read_capacity
        self._per_principal_rate_limit = per_principal_rate_limit
        self._rate_window_ns = rate_window_ns
        self._lock = RLock()
        # Isolated per-principal expiring replay windows for READ_CURRENT / LOOKUP_TRANSITION.
        # Filling Principal A's capacity NEVER exhausts or affects Principal B.
        self._read_replay_by_principal: dict[str, dict[str, dict]] = {
            g["principal_id"]: {} for g in self.auth.access["callers"]
        }
        # Isolated per-principal sliding-window rate limiter (boottime_ns timestamps).
        self._rate_window_by_principal: dict[str, deque[int]] = {
            g["principal_id"]: deque() for g in self.auth.access["callers"]
        }
        # Operation-aware durable mutation nonce ledger for ADVANCE (never evicted on cache maintenance).
        self._advance_nonces_by_principal: dict[str, dict[str, str]] = {
            g["principal_id"]: {} for g in self.auth.access["callers"]
        }

    def _prune_principal_unlocked(self, principal_id: str, actual) -> int:
        read_map = self._read_replay_by_principal.setdefault(principal_id, {})
        expired = [n for n, dl in read_map.items() if _stamp_expired(actual, dl)]
        for n in expired:
            del read_map[n]
        rate_q = self._rate_window_by_principal.setdefault(principal_id, deque())
        cutoff_ns = actual["boottime_ns"] - self._rate_window_ns
        while rate_q and rate_q[0] <= cutoff_ns:
            rate_q.popleft()
        return len(expired)

    def expire_replay_windows(self, *, now=None) -> int:
        """Expire all past-deadline read/lookup replay entries across principals.

        Mutating ADVANCE nonces are preserved intact across cache maintenance.
        """
        _, actual = self.auth.current(now)
        removed = 0
        with self._lock:
            for principal_id in list(self._read_replay_by_principal.keys()):
                removed += self._prune_principal_unlocked(principal_id, actual)
        return removed

    def replay_cache_stats(self) -> dict[str, dict[str, int]]:
        with self._lock:
            principals = set(self._read_replay_by_principal) | set(self._advance_nonces_by_principal)
            return {
                pid: {
                    "active_read_nonces": len(self._read_replay_by_principal.get(pid, {})),
                    "read_capacity": self._per_principal_read_capacity,
                    "durable_advance_nonces": len(self._advance_nonces_by_principal.get(pid, {})),
                    "rate_window_count": len(self._rate_window_by_principal.get(pid, ())),
                    "rate_limit": self._per_principal_rate_limit,
                }
                for pid in sorted(principals)
            }

    def _record_durable_advance_nonce(self, *, principal_id: str, nonce_hex: str, request_sha256: str, issued, deadline) -> None:
        database = getattr(self.store, "database", None)
        tx_fn = getattr(database, "transaction", None)
        if not callable(tx_fn):
            return
        with tx_fn(final_guard=self.auth.current) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS rpc_advance_nonces ("
                "principal_id TEXT NOT NULL,"
                "nonce_hex TEXT NOT NULL,"
                "request_sha256 TEXT NOT NULL,"
                "issued_utc TEXT NOT NULL,"
                "deadline_utc TEXT NOT NULL,"
                "PRIMARY KEY (principal_id, nonce_hex))"
            )
            existing = db.execute(
                "SELECT request_sha256 FROM rpc_advance_nonces WHERE principal_id=? AND nonce_hex=?",
                (principal_id, nonce_hex),
            ).fetchone()
            need(existing is None, "REPLAY_OR_EQUIVOCATION")
            db.execute(
                "INSERT INTO rpc_advance_nonces VALUES (?,?,?,?,?)",
                (principal_id, nonce_hex, request_sha256, issued["utc"], deadline["utc"]),
            )

    def handle(self, envelope, *, actual_peer, now):
        """Internal handler; serve_connection supplies an independently read peer."""
        _, actual = self.auth.current(now)
        candidates = [g for g in self.auth.access["callers"] if same(g["actual_process"], actual_peer)]
        need(len(candidates) == 1, "SIGNER_UNAPPOINTED")
        grant = candidates[0]
        self.peers.observe(grant["actual_process"])
        key = self.auth.key(grant["principal_id"])
        need(digest(key) == grant["signer_public_sha256"], "SIGNER_UNAPPOINTED")
        request = self.auth.verify_rpc(envelope, domain=ck.REQUEST_DOMAIN, public_key=key, type_name="CheckpointRpcRequest")
        need(request["caller_id"] == grant["principal_id"] and request["operation"] in grant["operations"]
             and request["use"] in grant["uses"], "PURPOSE_MISMATCH")
        # Validate authenticated issue/deadline timestamps BEFORE allocating replay-window capacity.
        self.auth.guard.remaining(request["deadline"])
        need(stamp_le(request["issued"], actual)
             and stamp_le(request["issued"], request["deadline"])
             and request["issued"] != request["deadline"], "CONTEXT_MISMATCH")

        principal_id = grant["principal_id"]
        nonce_hex = request["nonce_hex"]
        op_name = request["operation"]
        request_sha256 = digest(canonical_bytes(request))

        with self._lock:
            self._prune_principal_unlocked(principal_id, actual)
            rate_q = self._rate_window_by_principal.setdefault(principal_id, deque())
            need(len(rate_q) < self._per_principal_rate_limit, "REPLAY_OR_EQUIVOCATION")
            if op_name == "ADVANCE":
                adv_map = self._advance_nonces_by_principal.setdefault(principal_id, {})
                need(nonce_hex not in adv_map, "REPLAY_OR_EQUIVOCATION")
                self._record_durable_advance_nonce(
                    principal_id=principal_id,
                    nonce_hex=nonce_hex,
                    request_sha256=request_sha256,
                    issued=request["issued"],
                    deadline=request["deadline"],
                )
                adv_map[nonce_hex] = request_sha256
                rate_q.append(actual["boottime_ns"])
            else:
                read_map = self._read_replay_by_principal.setdefault(principal_id, {})
                need(nonce_hex not in read_map, "REPLAY_OR_EQUIVOCATION")
                need(len(read_map) < self._per_principal_read_capacity, "REPLAY_OR_EQUIVOCATION")
                read_map[nonce_hex] = dict(request["deadline"])
                rate_q.append(actual["boottime_ns"])

        operation = {"READ_CURRENT": self.store.read_current, "ADVANCE": self.store.compare_and_append,
                     "LOOKUP_TRANSITION": self.store.lookup_exact}[op_name]
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
