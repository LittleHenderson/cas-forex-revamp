"""Explicit SQLite IO. Constructors/imports do not open or create stores."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields, is_dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
import json
from pathlib import Path
import sqlite3
from types import UnionType
from typing import Union, get_args, get_origin, get_type_hints

from cas_forex_revamp.contracts import AccountRunKey, AuthorizedCommand, canonical_bytes, content_digest, parse_decimal
from .records import AccountRecord, CommandRecord, CoreError, CoreEvent, IdentityConflict, OwnerApproval

SCHEMA_VERSION = "core.sqlite/1"
_TABLES = {"metadata", "accounts", "commands", "owner_requests", "controls", "events", "receipts"}


def encode(value: object) -> str:
    return canonical_bytes(value).decode("utf-8")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CoreError("duplicate durable JSON key")
        result[key] = value
    return result


def _reject(value):
    raise CoreError("non-integer JSON number in core store")


def _typed(value, expected):
    origin = get_origin(expected)
    if origin in (Union, UnionType):
        if value is None and type(None) in get_args(expected):
            return None
        choices = [x for x in get_args(expected) if x is not type(None)]
        if len(choices) != 1:
            raise CoreError("unsupported durable union")
        return _typed(value, choices[0])
    if origin is tuple:
        if type(value) is not list:
            raise CoreError("durable tuple is not an array")
        return tuple(_typed(x, get_args(expected)[0]) for x in value)
    if expected is Decimal:
        return parse_decimal(value)
    if expected is datetime:
        if type(value) is not str:
            raise CoreError("invalid durable timestamp")
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    if isinstance(expected, type) and issubclass(expected, Enum):
        return expected(value)
    if is_dataclass(expected):
        # The only accepted older shape predates the optional execution ceiling.
        # None allows recovery of its effects, never authorization to dispatch.
        if (expected is AuthorizedCommand and type(value) is dict
                and set(value) == {f.name for f in fields(expected)} - {"risk_price_ceiling"}):
            value = {**value, "risk_price_ceiling": None}
        if type(value) is not dict or set(value) != {f.name for f in fields(expected)}:
            raise CoreError("durable record fields differ from schema")
        hints = get_type_hints(expected)
        return expected(**{k: _typed(v, hints[k]) for k, v in value.items()})
    if expected in (str, int, bool) and type(value) is expected:
        return value
    raise CoreError("invalid durable scalar")


def decode(raw: str, expected):
    """Decode only the caller's fixed record type; no pickle/dynamic imports."""
    try:
        return _typed(json.loads(raw, object_pairs_hook=_pairs,
                                 parse_float=_reject, parse_constant=_reject), expected)
    except (TypeError, ValueError, KeyError, RecursionError) as exc:
        raise CoreError("CORE_STORE_INVALID_RECORD") from exc


class SQLiteStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if str(path) == ":memory:" or str(path).startswith("\\\\"):
            raise ValueError("core requires a persistent local SQLite file")

    def _connect(self, *, create: bool = False) -> sqlite3.Connection:
        # mode=rw prevents missing/deleted ledgers becoming empty accounts.
        uri = self.path.absolute().as_uri() + ("?mode=rwc" if create else "?mode=rw")
        db = sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def initialize(self, *, create: bool = False) -> None:
        """Explicitly create a NEW schema, or validate an existing schema."""
        if create:
            try:
                # Exclusive creation also protects an existing empty/corrupt
                # file. Failed initialization leaves evidence, never deletes it.
                with self.path.open("xb"):
                    pass
            except FileExistsError as exc:
                raise CoreError("CORE_STORE_ALREADY_EXISTS") from exc
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            names = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if names:
                if create:
                    raise CoreError("CORE_STORE_ALREADY_EXISTS")
                self._schema(db)
            else:
                if not create:
                    raise CoreError("CORE_STORE_EMPTY")
                for sql in (
                    "CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
                    "CREATE TABLE accounts (account_key TEXT PRIMARY KEY, record TEXT NOT NULL, record_sha256 TEXT NOT NULL)",
                    "CREATE TABLE commands (ordinal INTEGER PRIMARY KEY, account_key TEXT NOT NULL REFERENCES accounts(account_key), command_id TEXT NOT NULL, intent_id TEXT NOT NULL, payload_sha256 TEXT NOT NULL, record TEXT NOT NULL, record_sha256 TEXT NOT NULL, UNIQUE(account_key,command_id), UNIQUE(account_key,intent_id))",
                        "CREATE TABLE owner_requests (account_key TEXT NOT NULL REFERENCES accounts(account_key), request_id TEXT NOT NULL, subject_sha256 TEXT NOT NULL, binding TEXT NOT NULL, approval TEXT NOT NULL, approval_sha256 TEXT NOT NULL, PRIMARY KEY(account_key,request_id))",
                        "CREATE TABLE events (sequence INTEGER PRIMARY KEY, account_key TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, previous_sha256 TEXT NOT NULL, event_sha256 TEXT NOT NULL)",
                    "CREATE TABLE controls (account_key TEXT NOT NULL REFERENCES accounts(account_key), barrier_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(account_key,barrier_id))",
                    "CREATE TABLE receipts (account_key TEXT NOT NULL, command_id TEXT NOT NULL, venue_sequence INTEGER NOT NULL, receipt_id TEXT NOT NULL, payload TEXT NOT NULL, PRIMARY KEY(account_key,command_id,venue_sequence), UNIQUE(account_key,receipt_id))",
                ):
                    db.execute(sql)
                db.execute("INSERT INTO metadata VALUES ('schema', ?)", (SCHEMA_VERSION,))
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _schema(db):
        names = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not _TABLES <= names:
            raise CoreError("CORE_STORE_MISSING_TABLE")
        row = db.execute("SELECT value FROM metadata WHERE name='schema'").fetchone()
        if row is None or row[0] != SCHEMA_VERSION:
            raise CoreError("CORE_STORE_SCHEMA_MISMATCH")

    @contextmanager
    def transaction(self):
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            self._schema(db)
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @contextmanager
    def read(self):
        """Read-only snapshot for venue callbacks; never acquire a write lock."""
        uri = self.path.absolute().as_uri() + "?mode=ro"
        db = sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            self._schema(db)
            yield db
        finally:
            db.close()

    @staticmethod
    def key(key: AccountRunKey) -> str:
        return encode(key)

    def account(self, db, key: AccountRunKey) -> AccountRecord:
        row = db.execute("SELECT record,record_sha256 FROM accounts WHERE account_key=?", (self.key(key),)).fetchone()
        if row is None:
            raise CoreError("ACCOUNT_NOT_INITIALIZED")
        record = decode(row[0], AccountRecord)
        if content_digest(record) != row[1]:
            raise CoreError("ACCOUNT_RECORD_CHECKSUM_MISMATCH")
        if record.scope.key != key:
            raise CoreError("ACCOUNT_KEY_MISMATCH")
        return record

    def save_account(self, db, account: AccountRecord) -> None:
        db.execute("INSERT INTO accounts VALUES (?, ?, ?) ON CONFLICT(account_key) DO UPDATE SET record=excluded.record,record_sha256=excluded.record_sha256",
                   (self.key(account.scope.key), encode(account), content_digest(account)))

    @staticmethod
    def _checked_command(raw: str, checksum: str) -> CommandRecord:
        record = decode(raw, CommandRecord)
        actual = content_digest(record)
        if actual != checksum:
            original = json.loads(raw, object_pairs_hook=_pairs, parse_float=_reject, parse_constant=_reject)
            if "risk_price_ceiling" not in original["command"]:
                # Verify the original canonical checksum without rewriting the
                # old bytes or event prefix simply because a field was added.
                previous_shape = json.loads(encode(record))
                del previous_shape["command"]["risk_price_ceiling"]
                actual = content_digest(previous_shape)
        if actual != checksum:
            raise CoreError("COMMAND_RECORD_CHECKSUM_MISMATCH")
        return record

    def commands(self, db, key: AccountRunKey) -> tuple[CommandRecord, ...]:
        result = []
        for row in db.execute("SELECT command_id,payload_sha256,record,record_sha256,intent_id FROM commands WHERE account_key=? ORDER BY ordinal", (self.key(key),)):
            record = self._checked_command(row[2], row[3])
            command = record.command
            if command.intent.scope.key != key or command.command_id != row[0] or command.payload_sha256 != row[1] or content_digest(command.intent) != row[1] or command.intent.intent_id != row[4]:
                raise CoreError("COMMAND_STORE_IDENTITY_MISMATCH")
            result.append(record)
        count = db.execute("SELECT count(*) FROM events WHERE account_key=? AND kind='ADMISSION'", (self.key(key),)).fetchone()[0]
        if len(result) != count:
            raise CoreError("COMMAND_ADMISSION_COUNT_MISMATCH")
        return tuple(result)

    def save_command(self, db, record: CommandRecord) -> None:
        c = record.command
        key = self.key(c.intent.scope.key)
        row = db.execute("SELECT payload_sha256,record,record_sha256 FROM commands WHERE account_key=? AND command_id=?", (key, c.command_id)).fetchone()
        if row is not None:
            if row[0] != c.payload_sha256:
                raise IdentityConflict("COMMAND_PAYLOAD_CONFLICT")
            if self._checked_command(row[1], row[2]).command != c:
                raise IdentityConflict("AUTHORIZED_COMMAND_CONFLICT")
        intent_row = db.execute("SELECT command_id FROM commands WHERE account_key=? AND intent_id=?", (key, c.intent.intent_id)).fetchone()
        if intent_row is not None and intent_row[0] != c.command_id:
            raise IdentityConflict("INTENT_ALREADY_BOUND_TO_COMMAND")
        db.execute("INSERT INTO commands(account_key,command_id,intent_id,payload_sha256,record,record_sha256) VALUES (?,?,?,?,?,?) ON CONFLICT(account_key,command_id) DO UPDATE SET record=excluded.record,record_sha256=excluded.record_sha256",
                   (key, c.command_id, c.intent.intent_id, c.payload_sha256, encode(record), content_digest(record)))

    def bind_owner(self, db, approval: OwnerApproval, binding: str) -> None:
        key = self.key(approval.scope.key)
        row = db.execute("SELECT subject_sha256,binding,approval_sha256 FROM owner_requests WHERE account_key=? AND request_id=?", (key, approval.request_id)).fetchone()
        if row is not None and tuple(row) != (approval.subject_sha256, binding, content_digest(approval)):
            raise IdentityConflict("OWNER_REQUEST_ALREADY_BOUND")
        db.execute("INSERT OR IGNORE INTO owner_requests VALUES (?,?,?,?,?,?)",
                   (key, approval.request_id, approval.subject_sha256, binding, encode(approval), content_digest(approval)))

    def owner_approval(self, db, key: AccountRunKey, request_id: str, binding: str) -> OwnerApproval:
        row = db.execute("SELECT approval,approval_sha256,binding FROM owner_requests WHERE account_key=? AND request_id=?",
                         (self.key(key), request_id)).fetchone()
        if row is None or row[2] != binding:
            raise CoreError("OWNER_BINDING_MISSING")
        approval = decode(row[0], OwnerApproval)
        if content_digest(approval) != row[1] or approval.scope.key != key or approval.request_id != request_id:
            raise CoreError("OWNER_APPROVAL_CHECKSUM_MISMATCH")
        return approval

    def event(self, db, key: AccountRunKey, kind: str, payload: object) -> None:
        last = db.execute("SELECT event_sha256 FROM events WHERE account_key=? ORDER BY sequence DESC LIMIT 1", (self.key(key),)).fetchone()
        previous = last[0] if last else "0" * 64
        sequence = db.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM events").fetchone()[0]
        raw = encode(payload)
        event_hash = content_digest((key, sequence, kind, raw, previous))
        db.execute("INSERT INTO events VALUES (?,?,?,?,?,?)", (sequence, self.key(key), kind, raw, previous, event_hash))

    def events(self, db, key: AccountRunKey) -> tuple[CoreEvent, ...]:
        result = []
        previous = "0" * 64
        for row in db.execute("SELECT sequence,kind,payload,previous_sha256,event_sha256 FROM events WHERE account_key=? ORDER BY sequence", (self.key(key),)):
            if row[3] != previous or row[4] != content_digest((key, row[0], row[1], row[2], previous)):
                raise CoreError("CORE_EVENT_PREFIX_CORRUPT")
            result.append(CoreEvent(row[0], key, row[1], row[2], row[3], row[4]))
            previous = row[4]
        return tuple(result)

