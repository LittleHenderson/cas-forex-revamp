"""Explicit durable byte retention and one pending output per original attempt.

The consumer never initializes, writes or restores the checkpoint database.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
import os
import sqlite3
import stat

from cas_forex_operational_contracts import method
from cas_forex_operational_contracts.common import canonical_bytes, decode_canonical, digest, MAX_GRAPH, MAX_OBJECT
from .authentication import AuthorityError, need, ref, same


@dataclass(frozen=True)
class StoreSelection:
    root: Path
    filename: str
    owner_uid: int
    owner_gid: int
    store_instance_id: str
    root_binding_sha256: str
    initialization_id: str
    initialization_sha256: str


class DurableDatabase:
    """Private local mechanism. Construction has no filesystem side effects."""

    def __init__(self, selection: StoreSelection, *, schema: str, guard):
        self.selection, self.schema, self.guard = selection, schema, guard
        need(selection.root.is_absolute() and selection.filename.endswith(".sqlite3")
             and Path(selection.filename).name == selection.filename, "RETENTION_UNAVAILABLE")
        self.path = selection.root / selection.filename
        self._lock = RLock()

    def _verify_path(self, *, existing=True):
        need(os.name == "posix", "RETENTION_UNAVAILABLE")
        current = Path(self.selection.root.anchor)
        for component in self.selection.root.parts[1:]:
            current = current / component
            info = current.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, self.selection.owner_uid)
                 and not info.st_mode & 0o022, "RETENTION_UNAVAILABLE")
        root = self.selection.root.lstat()
        need(root.st_uid == self.selection.owner_uid and root.st_gid == self.selection.owner_gid
             and stat.S_IMODE(root.st_mode) == 0o700, "RETENTION_UNAVAILABLE")
        if existing:
            info = self.path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == self.selection.owner_uid
                 and info.st_gid == self.selection.owner_gid and stat.S_IMODE(info.st_mode) == 0o600,
                 "RETENTION_UNAVAILABLE")
            return info.st_dev, info.st_ino

    def _connect(self):
        identity = self._verify_path()
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                             timeout=min(5.0, self.guard.remaining()), isolation_level=None)
        try:
            db.execute("PRAGMA synchronous=EXTRA")
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA trusted_schema=OFF")
            need(db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"
                 and db.execute("PRAGMA synchronous").fetchone()[0] == 3
                 and db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
                 and db.execute("PRAGMA trusted_schema").fetchone()[0] == 0, "RETENTION_UNAVAILABLE")
            need(identity == self._verify_path(), "RETENTION_UNAVAILABLE")
            return db
        except BaseException:
            db.close()
            raise

    def initialize(self, statements: tuple[str, ...], *, consume_initialization):
        """Deployment-only exclusive creation after independent one-use approval.

        consume_initialization must durably consume an externally authenticated
        initialization grant outside this database. No RPC reaches this method.
        """
        need(consume_initialization is not None, "RUNTIME_APPROVAL_ABSENT")
        self.guard.check()
        with self._lock:
            self._verify_path(existing=False)
            result = consume_initialization(self.selection)
            need(result is None, "RUNTIME_APPROVAL_ABSENT")
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
            # Failure leaves the file in place; normal reopen will fail closed.
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute("CREATE TABLE store_meta (name TEXT PRIMARY KEY,value BLOB NOT NULL)")
                for name, value in self._metadata().items():
                    db.execute("INSERT INTO store_meta VALUES (?,?)", (name, value))
                for statement in statements:
                    db.execute(statement)
                self.guard.check()
                db.commit()
                self.guard.check()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    def _metadata(self):
        s = self.selection
        return {"schema": self.schema, "store_instance_id": s.store_instance_id,
                "root_binding_sha256": s.root_binding_sha256,
                "initialization_id": s.initialization_id, "initialization_sha256": s.initialization_sha256}

    @contextmanager
    def transaction(self, *, write=True, final_guard=None):
        self.guard.check()
        with self._lock:
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
                need(dict(db.execute("SELECT name,value FROM store_meta")) == self._metadata(), "RETENTION_UNAVAILABLE")
                yield db
                (final_guard or self.guard.check)()
                db.commit()
                (final_guard or self.guard.check)()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    def reopen(self):
        with self.transaction(write=False) as db:
            need(db.execute("PRAGMA quick_check").fetchone()[0] == "ok", "RETENTION_UNAVAILABLE")


CONSUMER_SCHEMA = (
    "CREATE TABLE objects (sha TEXT PRIMARY KEY,raw BLOB NOT NULL)",
    "CREATE TABLE preparations (transition_id TEXT PRIMARY KEY,logical_id TEXT NOT NULL UNIQUE,key_raw BLOB NOT NULL,raw BLOB NOT NULL,sha TEXT NOT NULL,confirmed BLOB,attempted INTEGER NOT NULL DEFAULT 0 CHECK(attempted IN (0,1)))",
    "CREATE TABLE events (key_raw BLOB NOT NULL,sequence INTEGER NOT NULL,raw BLOB NOT NULL,sha TEXT NOT NULL,transition_id TEXT NOT NULL UNIQUE REFERENCES preparations(transition_id),PRIMARY KEY(key_raw,sequence))",
    "CREATE TABLE attempt_state (key_raw BLOB PRIMARY KEY,binding_raw BLOB NOT NULL,budget_raw BLOB NOT NULL)",
    "CREATE TABLE authority_highwater (appointment TEXT PRIMARY KEY,revision INTEGER NOT NULL,sha TEXT NOT NULL)",
)


class ConsumerStore:
    def __init__(self, selection: StoreSelection, *, guard):
        self.database = DurableDatabase(selection, schema="cas-fx-consumer/1", guard=guard)
        self.guard = guard

    def initialize(self, *, consume_initialization):
        self.database.initialize(CONSUMER_SCHEMA, consume_initialization=consume_initialization)

    def reopen(self):
        self.database.reopen()

    @staticmethod
    def _retain(db, reference, raw):
        method.validate("ObjectRef", reference)
        need(type(raw) is bytes and 0 < len(raw) <= MAX_OBJECT and reference["object_id"] == reference["sha256"] == digest(raw)
             and reference["bytes"] == len(raw), "RAW_BYTES_MISMATCH")
        row = db.execute("SELECT raw FROM objects WHERE sha=?", (reference["sha256"],)).fetchone()
        if row is not None:
            need(bytes(row[0]) == raw, "REPLAY_OR_EQUIVOCATION")
            return
        total = db.execute("SELECT COALESCE(SUM(length(raw)),0) FROM objects").fetchone()[0]
        need(total + len(raw) <= MAX_GRAPH, "RETENTION_UNAVAILABLE")
        db.execute("INSERT INTO objects VALUES (?,?)", (reference["sha256"], raw))

    def retain_exact(self, reference, raw):
        with self.database.transaction() as db:
            self._retain(db, reference, raw)
        need(self.resolve(reference) == raw, "RETENTION_COMMIT_FAILED")
        return dict(reference)

    def resolve(self, reference):
        method.validate("ObjectRef", reference)
        with self.database.transaction(write=False) as db:
            row = db.execute("SELECT raw FROM objects WHERE sha=?", (reference["sha256"],)).fetchone()
            need(row is not None, "RAW_EVIDENCE_UNAVAILABLE")
            raw = bytes(row[0])
            need(ref(raw, reference["artifact_kind"]) == reference, "RAW_BYTES_MISMATCH")
            return raw

    @staticmethod
    def remember_authority(db, status):
        encoded = canonical_bytes(status)
        row = db.execute("SELECT revision,sha FROM authority_highwater WHERE appointment=?", (status["appointment_sha256"],)).fetchone()
        need(row is None or status["revision"] > row[0]
             or (status["revision"] == row[0] and digest(encoded) == row[1]), "REPLAY_OR_EQUIVOCATION")
        db.execute("INSERT INTO authority_highwater VALUES (?,?,?) ON CONFLICT(appointment) DO UPDATE SET revision=excluded.revision,sha=excluded.sha",
                   (status["appointment_sha256"], status["revision"], digest(encoded)))

    def bind_attempt(self, key, binding, budget):
        with self.database.transaction() as db:
            values = tuple(canonical_bytes(v) for v in (key, binding, budget))
            row = db.execute("SELECT binding_raw,budget_raw FROM attempt_state WHERE key_raw=?", (values[0],)).fetchone()
            need(row is None or tuple(bytes(x) for x in row) == values[1:], "BUDGET_ALREADY_CLAIMED")
            db.execute("INSERT OR IGNORE INTO attempt_state VALUES (?,?,?)", values)

    def prepare(self, record: dict, *, artifacts: tuple[tuple[dict, bytes], ...], status: dict):
        """Internal exact preparation; this record is never a public authority wire."""
        raw = canonical_bytes(record, limit=MAX_OBJECT)
        key_raw = canonical_bytes(record["transition"]["original_setup_key"])
        transition_id = record["transition"]["transition_id"]
        with self.database.transaction() as db:
            self.remember_authority(db, status)
            row = db.execute("SELECT raw FROM preparations WHERE logical_id=?", (record["logical_id"],)).fetchone()
            if row is not None:
                need(bytes(row[0]) == raw, "REPLAY_OR_EQUIVOCATION")
                return
            need(db.execute("SELECT 1 FROM preparations WHERE key_raw=? AND confirmed IS NULL", (key_raw,)).fetchone() is None,
                 "CHECKPOINT_ADVANCE_UNCONFIRMED")
            for reference, data in artifacts:
                self._retain(db, reference, data)
            db.execute("INSERT INTO preparations VALUES (?,?,?,?,?,NULL,0)",
                       (transition_id, record["logical_id"], key_raw, raw, digest(raw)))

    def claim_advance(self, transition_id):
        with self.database.transaction() as db:
            changed = db.execute("UPDATE preparations SET attempted=1 WHERE transition_id=? AND attempted=0 AND confirmed IS NULL",
                                 (transition_id,)).rowcount
            need(changed == 1, "CHECKPOINT_ADVANCE_UNCONFIRMED")

    def prepared(self, *, logical_id=None, output=None):
        with self.database.transaction(write=False) as db:
            rows = db.execute("SELECT raw,sha,confirmed FROM preparations ORDER BY rowid").fetchall()
            matches = []
            for raw, sha, confirmed in rows:
                raw = bytes(raw)
                need(digest(raw) == sha, "RETENTION_UNAVAILABLE")
                value = decode_canonical(raw, limit=MAX_OBJECT)
                if (logical_id is not None and value["logical_id"] == logical_id) or (output is not None and same(value["transition"]["output"], output)):
                    matches.append((value, decode_canonical(bytes(confirmed), limit=MAX_OBJECT) if confirmed else None))
            need(len(matches) <= 1, "REPLAY_OR_EQUIVOCATION")
            return matches[0] if matches else None

    def confirm(self, preparation, *, certificate, envelope, event=None, final_guard):
        raw = canonical_bytes({"checkpoint": certificate, "envelope": envelope})
        tid = preparation["transition"]["transition_id"]
        with self.database.transaction(final_guard=final_guard) as db:
            row = db.execute("SELECT raw,confirmed FROM preparations WHERE transition_id=?", (tid,)).fetchone()
            need(row is not None and bytes(row[0]) == canonical_bytes(preparation, limit=MAX_OBJECT), "CHECKPOINT_LEDGER_DIVERGENCE")
            need(row[1] is None or bytes(row[1]) == raw, "REPLAY_OR_EQUIVOCATION")
            for value, kind in ((certificate, "CHECKPOINT_CERTIFICATE"), (envelope, "SIGNED_ENVELOPE")):
                data = canonical_bytes(value)
                self._retain(db, ref(data, kind), data)
            db.execute("UPDATE preparations SET confirmed=? WHERE transition_id=?", (raw, tid))
            if event is not None:
                event_raw = method.validate("Event", event).raw
                key_raw = canonical_bytes(preparation["transition"]["original_setup_key"])
                old = db.execute("SELECT raw FROM events WHERE key_raw=? AND sequence=?", (key_raw, event["sequence"])).fetchone()
                need(old is None or bytes(old[0]) == event_raw, "REPLAY_OR_EQUIVOCATION")
                db.execute("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?)", (key_raw, event["sequence"], event_raw, digest(event_raw), tid))

    def accepted_events(self, key):
        with self.database.transaction(write=False) as db:
            result, previous = [], "0" * 64
            for sequence, raw, sha in db.execute("SELECT sequence,raw,sha FROM events WHERE key_raw=? ORDER BY sequence", (canonical_bytes(key),)):
                raw = bytes(raw)
                value = method.decode("Event", raw).payload()
                need(digest(raw) == sha and sequence == len(result) + 1 and value["previous_record_sha256"] == previous,
                     "CHECKPOINT_LEDGER_DIVERGENCE")
                result.append(value)
                previous = sha
            return tuple(result)

    def assert_history(self, response):
        """An ahead independent head cannot rebuild missing local preparations."""
        with self.database.transaction(write=False) as db:
            local = {}
            for raw, sha in db.execute("SELECT raw,sha FROM preparations WHERE key_raw=?", (canonical_bytes(response["original_setup_key"]),)):
                raw = bytes(raw)
                need(digest(raw) == sha, "RETENTION_UNAVAILABLE")
                value = decode_canonical(raw, limit=MAX_OBJECT)
                local[digest(canonical_bytes(value["transition"]))] = value
            for item in response["history"]:
                value = local.get(item["request_sha256"])
                need(value is not None, "CHECKPOINT_LEDGER_DIVERGENCE")
                for reference in value["artifact_refs"]:
                    row = db.execute("SELECT raw FROM objects WHERE sha=?", (reference["sha256"],)).fetchone()
                    need(row is not None and ref(bytes(row[0]), reference["artifact_kind"]) == reference, "RAW_EVIDENCE_UNAVAILABLE")
