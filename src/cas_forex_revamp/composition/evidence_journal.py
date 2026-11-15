"""Independent append-only integration evidence. It never grants authority."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import sqlite3

from ..contracts import AccountRunKey, ContractError, RunScope, canonical_bytes, content_digest
from ..contracts.primitives import identifier, utc_time


@dataclass(frozen=True, slots=True)
class EvidenceEntry:
    sequence: int
    event_id: str
    kind: str
    scope: dict
    recorded_at: str
    payload: dict
    previous_sha256: str
    event_sha256: str


class EvidenceJournal:
    """Separate bounded-run store, with explicit new/reopen and verified reads.

    A local chain detects corruption, not whole-file rollback without an
    externally held checkpoint. No imported JSON appoints this writer.
    """

    def __init__(self, path: Path, key: AccountRunKey) -> None:
        self.path = Path(path)
        self.key = key
        if not self.path.is_absolute() or not self.path.name.endswith(".evidence.sqlite3"):
            raise ContractError("explicit absolute *.evidence.sqlite3 path required")

    @contextmanager
    def _connection(self, *, create=False, readonly=False):
        mode = "rwc" if create else "ro" if readonly else "rw"
        db = sqlite3.connect(self.path.as_uri() + "?mode=" + mode, uri=True,
                             timeout=5, isolation_level=None)
        try:
            if readonly:
                db.execute("PRAGMA query_only=ON")
            else:
                db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN" if readonly else "BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def initialize(self, *, create=False, expected_checkpoint=None) -> None:
        if create:
            if expected_checkpoint is not None:
                raise ContractError("new evidence cannot restore an old checkpoint")
            # Exclusive creation preserves even an existing empty/corrupt file.
            with self.path.open("xb"):
                pass
        with self._connection() as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not tables and create:
                db.execute("CREATE TABLE metadata (version TEXT NOT NULL, run_key TEXT NOT NULL)")
                db.execute("INSERT INTO metadata VALUES (?,?)", ("integration.evidence/1", content_digest(self.key)))
                db.execute("CREATE TABLE entries (sequence INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, record TEXT NOT NULL)")
            elif tables != {"metadata", "entries"}:
                raise ContractError("evidence store missing or incompatible; never reset history")
            self._read(db)
            if expected_checkpoint is not None:
                seq, digest = expected_checkpoint
                entries = self._read(db)
                if type(seq) is not int or seq < 0 or (seq == 0 and digest != "0" * 64):
                    raise ContractError("invalid external evidence checkpoint")
                if seq > len(entries) or (seq and entries[seq - 1].event_sha256 != digest):
                    raise ContractError("evidence history precedes or differs from external checkpoint")

    def _read(self, db) -> tuple[EvidenceEntry, ...]:
        metadata = db.execute("SELECT version,run_key FROM metadata").fetchall()
        if metadata != [("integration.evidence/1", content_digest(self.key))]:
            raise ContractError("evidence store scope/schema mismatch")
        result = []
        previous = "0" * 64
        for sequence, event_id, raw in db.execute("SELECT sequence,event_id,record FROM entries ORDER BY sequence"):
            record = json.loads(raw)
            entry = EvidenceEntry(**record)
            body = {k: v for k, v in record.items() if k != "event_sha256"}
            if (sequence != len(result) + 1 or entry.sequence != sequence or entry.event_id != event_id
                    or entry.previous_sha256 != previous or content_digest(body) != entry.event_sha256
                    or canonical_bytes(record).decode("utf-8") != raw):
                raise ContractError("evidence chain corrupt or incomplete")
            if (entry.scope.get("account_id"), entry.scope.get("run_id"), entry.scope.get("environment")) != (
                self.key.account_id, self.key.run_id, self.key.environment.value
            ):
                raise ContractError("evidence entry has another durable run")
            result.append(entry)
            previous = entry.event_sha256
        return tuple(result)

    def records(self) -> tuple[EvidenceEntry, ...]:
        with self._connection(readonly=True) as db:
            return self._read(db)

    def checkpoint(self) -> tuple[int, str]:
        records = self.records()
        return (records[-1].sequence, records[-1].event_sha256) if records else (0, "0" * 64)

    def append(self, event_id: str, kind: str, scope: RunScope, payload: object, *, now: datetime) -> EvidenceEntry:
        identifier(event_id, "evidence event_id")
        identifier(kind, "evidence kind")
        utc_time(now, "evidence timestamp")
        if scope.key != self.key:
            raise ContractError("evidence writer scope differs from journal run")
        # Round-trip shared wire data; fixed caller types, never pickle or imports.
        frozen = json.loads(canonical_bytes(payload))
        if type(frozen) is not dict or len(canonical_bytes(frozen)) > 1_048_576:
            raise ContractError("evidence event requires a bounded object")
        scope_wire = json.loads(canonical_bytes(scope))
        at = now.isoformat().replace("+00:00", "Z")
        with self._connection() as db:
            entries = self._read(db)
            existing = next((x for x in entries if x.event_id == event_id), None)
            if existing is not None:
                if (existing.kind, existing.scope, existing.payload) != (kind, scope_wire, frozen):
                    raise ContractError("evidence identity payload conflict")
                return existing
            body = {"sequence": len(entries) + 1, "event_id": event_id, "kind": kind,
                    "scope": scope_wire, "recorded_at": at, "payload": frozen,
                    "previous_sha256": entries[-1].event_sha256 if entries else "0" * 64}
            record = {**body, "event_sha256": content_digest(body)}
            db.execute("INSERT INTO entries VALUES (?,?,?)", (body["sequence"], event_id,
                                                              canonical_bytes(record).decode("utf-8")))
            return EvidenceEntry(**record)
