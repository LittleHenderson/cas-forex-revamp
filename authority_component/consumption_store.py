"""Controller-local NR12 one-use state. This is not the authority checkpoint DB.

Constructors do no I/O. Explicit initialize is deployment work, never an RPC.
An existing preparation cannot acquire a new request, attempt, session or clock.
Reopening permits audit reads only; it never reconstructs exposure capability.
Local checksums are corruption checks, not protection against whole-file rollback.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import os
import sqlite3
import stat
from typing import Iterator

from cas_forex_operational_contracts.common import (
    ContractError, canonical_bytes, decode_canonical, digest, require,
)

SCHEMA = "forex.controller-consumption-sqlite/1"
STATES = ("PREPARED", "READ_STARTED", "COMMITTED", "CHECKED", "EXPOSURE_STARTED", "FAILED")
TRANSITIONS = {
    "PREPARED": ("READ_STARTED", "FAILED"),
    "READ_STARTED": ("COMMITTED", "FAILED"),
    "COMMITTED": ("CHECKED", "FAILED"),
    "CHECKED": ("EXPOSURE_STARTED", "FAILED"),
    "EXPOSURE_STARTED": ("FAILED",),
    "FAILED": (),
}


class ConsumptionStore:
    def __init__(self, path: Path, *, store_id: str, binding_sha256: str,
                 busy_seconds: float = 0.05) -> None:
        require(isinstance(path, Path) and path.is_absolute(), "STORE_PATH")
        require(path.name.endswith(".release-consumption.sqlite3"), "STORE_SUFFIX")
        require(type(store_id) is str and bool(store_id), "STORE_ID")
        require(type(binding_sha256) is str and len(binding_sha256) == 64, "STORE_BINDING")
        require(type(busy_seconds) in (int, float) and 0 <= busy_seconds <= 0.1, "STORE_BUSY_BOUND")
        self.path, self.store_id = path, store_id
        self.binding_sha256, self.busy_seconds = binding_sha256, busy_seconds
        self._identity: tuple[int, int] | None = None
        self._active = False
        self._claimed: set[str] = set()
        self._highwater: dict[str, int] = {}

    def _path_check(self, *, present: bool = True) -> None:
        require(".." not in self.path.parts, "STORE_PATH")
        for parent in self.path.parents:
            require(parent.is_dir() and not parent.is_symlink(), "STORE_PARENT")
        if present:
            info = self.path.lstat()
            require(stat.S_ISREG(info.st_mode) and not self.path.is_symlink(), "STORE_FILE")
            require(info.st_nlink == 1, "STORE_HARDLINK")
            if self._identity is not None:
                require((info.st_dev, info.st_ino) == self._identity, "STORE_REPLACED")

    def _open(self, *, read_only: bool = False) -> sqlite3.Connection:
        self._path_check()
        mode = "ro" if read_only else "rw"
        db = sqlite3.connect(self.path.as_uri() + "?mode=" + mode, uri=True,
                             timeout=self.busy_seconds, isolation_level=None)
        try:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA foreign_keys=ON")
            if read_only:
                db.execute("PRAGMA query_only=ON")
            else:
                # Do not change an existing store's journal mode during consumption.
                require(db.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete",
                        "STORE_JOURNAL")
                db.execute("PRAGMA synchronous=EXTRA")
                require(db.execute("PRAGMA synchronous").fetchone()[0] == 3, "STORE_SYNC")
            require(db.execute("PRAGMA trusted_schema").fetchone()[0] == 0, "STORE_TRUST")
            require(db.execute("PRAGMA foreign_keys").fetchone()[0] == 1, "STORE_FOREIGN_KEYS")
            if self._identity is not None:
                require(db.execute("SELECT * FROM meta").fetchall() ==
                        [(1, SCHEMA, self.store_id, self.binding_sha256)], "STORE_METADATA")
            self._path_check()
            return db
        except BaseException:
            db.close()
            raise

    def initialize(self, *, create: bool = False) -> None:
        """Explicit NEW creation only. A normal reopen is audit-only for this cut."""
        require(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "UNSUPPORTED_STORE_PLATFORM")
        require(not self._active and self._identity is None, "STORE_ALREADY_OPEN")
        self._path_check(present=not create)
        if create:
            flags = os.O_CREAT | os.O_EXCL | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, 0o600)
            os.close(fd)
        db = self._open()
        try:
            if create:
                db.execute("BEGIN IMMEDIATE")
                db.execute("CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_id TEXT NOT NULL, store_id TEXT NOT NULL, binding_sha256 TEXT NOT NULL)")
                db.execute("CREATE TABLE attempts (attempt_id TEXT PRIMARY KEY, release_id TEXT UNIQUE NOT NULL, preparation_id TEXT UNIQUE NOT NULL, request_id TEXT UNIQUE NOT NULL, nonce TEXT UNIQUE NOT NULL, original_key_sha256 TEXT UNIQUE NOT NULL, revision INTEGER NOT NULL, state TEXT NOT NULL, body BLOB NOT NULL, body_sha256 TEXT NOT NULL)")
                db.execute("INSERT INTO meta VALUES (1,?,?,?)", (SCHEMA, self.store_id, self.binding_sha256))
                db.commit()
            require(db.execute("SELECT * FROM meta").fetchall() ==
                    [(1, SCHEMA, self.store_id, self.binding_sha256)], "STORE_METADATA")
            require(db.execute("PRAGMA quick_check").fetchall() == [("ok",)], "STORE_CORRUPT")
            for row in db.execute("SELECT attempt_id,revision,state,body,body_sha256 FROM attempts"):
                self._decode(row)
        finally:
            db.close()
        info = self.path.lstat()
        self._identity = (info.st_dev, info.st_ino)
        # A new instance reopening this file cannot resume a PREPARED attempt.
        self._active = create

    def _decode(self, row) -> dict:
        require(row is not None, "ATTEMPT_NOT_RETAINED")
        attempt_id, revision, state, raw, hashed = row
        require(type(raw) is bytes and digest(raw) == hashed, "STORE_ROW_HASH")
        data = decode_canonical(raw)
        require(type(data) is dict and data["preparation"]["consume_attempt_id"] == attempt_id,
                "STORE_ROW_ID")
        require(type(revision) is int and revision >= 0 and state in STATES, "STORE_ROW_STATE")
        require(revision >= self._highwater.get(attempt_id, 0), "LOCAL_STORE_ROLLBACK")
        require(data["revision"] == revision and data["state"] == state, "STORE_ROW_BINDING")
        expected_status = ("UNAVAILABLE",) if state in ("PREPARED", "READ_STARTED") else \
            ("SPENT_NO_EXPOSURE",) if state == "COMMITTED" else \
            ("CONSUMED_VALID",) if state in ("CHECKED", "EXPOSURE_STARTED") else \
            ("UNAVAILABLE", "SPENT_NO_EXPOSURE")
        require(data["record"]["status"] in expected_status, "STORE_RECORD_STATE")
        self._highwater[attempt_id] = revision
        return data

    def _get(self, db, attempt_id: str) -> dict:
        return self._decode(db.execute(
            "SELECT attempt_id,revision,state,body,body_sha256 FROM attempts WHERE attempt_id=?",
            (attempt_id,)).fetchone())

    def read(self, attempt_id: str) -> dict:
        require(self._identity is not None, "STORE_NOT_INITIALIZED")
        db = self._open(read_only=True)
        try:
            db.execute("BEGIN")
            value = self._get(db, attempt_id)
            db.rollback()
            return value
        finally:
            db.close()

    def prepare(self, preparation: dict, receipt: dict, request: dict, record: dict) -> None:
        require(self._active, "STORE_AUDIT_ONLY")
        data = {"preparation": preparation, "receipt": receipt, "request": request,
                "record": record, "state": "PREPARED", "revision": 0}
        raw = canonical_bytes(data)
        db = self._open()
        try:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT attempt_id FROM attempts WHERE attempt_id=?",
                               (preparation["consume_attempt_id"],)).fetchone()
            if prior is not None:
                require(self._get(db, prior[0]) == data, "PREPARATION_CONFLICT")
                db.rollback()
                return
            db.execute("INSERT INTO attempts VALUES (?,?,?,?,?,?,?,?,?,?)", (
                preparation["consume_attempt_id"], receipt["release_id"], preparation["preparation_id"],
                request["request_id"], request["nonce_hex"],
                digest(canonical_bytes(preparation["original_setup_key"])), 0, "PREPARED", raw, digest(raw)))
            db.commit()
        except sqlite3.IntegrityError:
            raise ContractError("CONSUMPTION_IDENTITY_REUSED") from None
        finally:
            db.close()

    def _replace(self, db, prior: dict, *, state: str, record: dict) -> dict:
        require(state in TRANSITIONS[prior["state"]], "STORE_STATE")
        updated = {**prior, "state": state, "revision": prior["revision"] + 1, "record": record}
        raw = canonical_bytes(updated)
        changed = db.execute("UPDATE attempts SET revision=?,state=?,body=?,body_sha256=? WHERE attempt_id=? AND revision=? AND state=?",
            (updated["revision"], state, raw, digest(raw), prior["preparation"]["consume_attempt_id"], prior["revision"], prior["state"]))
        require(changed.rowcount == 1, "STORE_CONCURRENT_CHANGE")
        return updated

    def transition(self, attempt_id: str, *, expected: tuple[str, ...], state: str, record: dict) -> dict:
        require(self._active, "STORE_AUDIT_ONLY")
        if state == "READ_STARTED":
            require(attempt_id not in self._claimed, "READ_ALREADY_CLAIMED")
            self._claimed.add(attempt_id)  # Before any possibly ambiguous write.
        db = self._open()
        try:
            db.execute("BEGIN IMMEDIATE")
            prior = self._get(db, attempt_id)
            require(prior["state"] in expected, "CONSUMPTION_ALREADY_ATTEMPTED")
            updated = self._replace(db, prior, state=state, record=record)
            db.commit()
            self._highwater[attempt_id] = updated["revision"]
            return updated
        finally:
            db.close()

    @contextmanager
    def final_commit(self, attempt_id: str) -> Iterator["FinalCommit"]:
        """Acquire/read the exact local row BEFORE the final external read."""
        require(self._active, "STORE_AUDIT_ONLY")
        db = self._open()
        try:
            db.execute("BEGIN IMMEDIATE")
            prior = self._get(db, attempt_id)
            require(prior["state"] == "READ_STARTED", "CONSUMPTION_ALREADY_ATTEMPTED")
            slot = FinalCommit(self, db, prior)
            yield slot
        finally:
            db.close()


class FinalCommit:
    def __init__(self, store: ConsumptionStore, db: sqlite3.Connection, prior: dict) -> None:
        self._store, self._db, self.prior, self._used = store, db, prior, False

    def commit(self, record: dict) -> None:
        require(not self._used, "COMMIT_ALREADY_ATTEMPTED")
        self._used = True  # Set before SQLite: an ambiguous commit is never repeated.
        self._store._replace(self._db, self.prior, state="COMMITTED", record=record)
        self._db.commit()
        self._store._highwater[self.prior["preparation"]["consume_attempt_id"]] = self.prior["revision"] + 1
