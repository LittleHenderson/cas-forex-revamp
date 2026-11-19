"""Explicit durable model evidence and one-shot call accounting; no core authority."""
from __future__ import annotations
from contextlib import contextmanager
from datetime import datetime
from hashlib import sha256
import hmac
import json
from pathlib import Path
import sqlite3
from cas_forex_revamp.contracts import ContractError, canonical_bytes, content_digest
from cas_forex_revamp.contracts.primitives import digest, identifier, utc_time

PHASE_LIMITS = {"probe": (2, 600), "acceptance": (32, 5400)}
OBSERVER_ONLY_KINDS = frozenset({
    "MODEL_HTTP_ATTEMPT",
    "MODEL_HTTP_RESPONSE",
    "MODEL_HTTP_ERROR",
    "MODEL_TOKEN_PREFLIGHT",
    "MODEL_RUNTIME_OBSERVATION",
    "MODEL_INFERENCE_RECEIPT",
    "MODEL_TRANSPORT_REQUEST_SENT",
    "MODEL_TRANSPORT_RESPONSE_CAPTURE",
    "MODEL_TRANSPORT_PENDING_WINDOW",
})


class ModelEvidenceStore:
    """Constructor is inert. Explicit initialize creates or opens only this store.

    The externally selected path/run/deadline and retained checkpoint are the trust
    root. The local hash chain detects corruption, not whole-store rollback.
    This journal does not observe model memory or grant any action authority.
    """
    def __init__(self, path: Path, *, run_id: str, deadline: datetime, observer_key: bytes | None = None):
        self.path = Path(path)
        self.run_id = identifier(run_id, "run_id")
        self.deadline = utc_time(deadline, "deadline")
        if not self.path.is_absolute() or not self.path.name.endswith(".model-evidence.sqlite3"):
            raise ContractError("explicit absolute model evidence store required")
        self._observer_key: bytes | None = None
        if observer_key is not None:
            self.bind_observer_key(observer_key)

    @property
    def has_observer_key(self) -> bool:
        return self._observer_key is not None

    def bind_observer_key(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
            raise ContractError("observer_key must be at least 32 random bytes")
        self._observer_key = bytes(key)

    def _compute_observer_mac(self, receipt_id: str, kind: str, record_sha256: str) -> str:
        if self._observer_key is None:
            raise ContractError("observer_key not bound")
        msg = f"cas-forex-observer/1|{self.run_id}|{receipt_id}|{kind}|{record_sha256}".encode("utf-8")
        return hmac.new(self._observer_key, msg, sha256).hexdigest()

    def _ensure_attestation_table(self, db: sqlite3.Connection) -> None:
        db.execute(
            "CREATE TABLE IF NOT EXISTS observer_attestations ("
            "receipt_id TEXT PRIMARY KEY, kind TEXT NOT NULL, observer_mac TEXT NOT NULL)"
        )

    def _check_observer_write(self, kind: str, observer_token: bytes | None) -> None:
        if self._observer_key is not None and kind in OBSERVER_ONLY_KINDS:
            if not isinstance(observer_token, (bytes, bytearray)) or not hmac.compare_digest(
                bytes(observer_token), self._observer_key
            ):
                raise ContractError(
                    f"OBSERVER_PROVENANCE_REQUIRED: untrusted writer cannot append observation kind {kind!r}"
                )

    def verify_observer_provenance(self, receipt_id: str) -> bool:
        if self._observer_key is None:
            return True
        identifier(receipt_id, "receipt_id")
        with self._db(readonly=True) as db:
            records = self._read(db)
            rec = next((r for r in records if r["receipt_id"] == receipt_id), None)
            if rec is None:
                return False
            tbl = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='observer_attestations'"
            ).fetchone()
            if tbl is None:
                return False
            row = db.execute(
                "SELECT kind, observer_mac FROM observer_attestations WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if row is None or str(row[0]) != rec["kind"]:
                return False
            expected = self._compute_observer_mac(receipt_id, rec["kind"], rec["sha256"])
            return hmac.compare_digest(str(row[1]), expected)

    def require_observer_provenance(self, receipt_id: str) -> dict:
        rec = self.resolve(receipt_id)
        if not self.verify_observer_provenance(receipt_id):
            raise ContractError(
                f"OBSERVER_PROVENANCE_MISSING: receipt {receipt_id!r} lacks trusted controller observer attestation"
            )
        return rec

    @contextmanager
    def _db(self, *, readonly=False):
        mode = "ro" if readonly else "rw"
        db = sqlite3.connect(self.path.as_uri() + "?mode=" + mode, uri=True, timeout=5, isolation_level=None)
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

    def initialize(self, *, create=False, expected_checkpoint=None):
        if not create and expected_checkpoint is None:
            raise ContractError("restart requires independently retained evidence checkpoint")
        if create:
            if expected_checkpoint is not None:
                raise ContractError("new model store cannot restore an old checkpoint")
            with self.path.open("xb"):
                pass
        with self._db() as db:
            names = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if create and not names:
                db.execute("CREATE TABLE meta (run_id TEXT NOT NULL, deadline TEXT NOT NULL)")
                db.execute("INSERT INTO meta VALUES (?,?)", (self.run_id, self.deadline.isoformat()))
                db.execute("CREATE TABLE receipts (sequence INTEGER PRIMARY KEY, receipt_id TEXT UNIQUE NOT NULL, raw TEXT NOT NULL)")
            elif not ({"meta", "receipts"} <= names <= {"meta", "receipts", "observer_attestations"}):
                raise ContractError("model evidence store missing or incompatible")
            records = self._read(db)
            if expected_checkpoint is not None:
                seq, pin = expected_checkpoint
                digest(pin)
                if type(seq) is not int or seq < 0 or seq > len(records) or (seq == 0 and pin != "0" * 64):
                    raise ContractError("invalid model evidence checkpoint")
                if seq and records[seq - 1]["sha256"] != pin:
                    raise ContractError("model evidence rollback/checkpoint mismatch")

    def _read(self, db):
        if db.execute("SELECT run_id,deadline FROM meta").fetchall() != [(self.run_id, self.deadline.isoformat())]:
            raise ContractError("model evidence run/deadline mismatch")
        records, previous = [], "0" * 64
        for sequence, receipt_id, raw in db.execute("SELECT sequence,receipt_id,raw FROM receipts ORDER BY sequence"):
            if len(records) >= 512 or len(raw.encode("utf-8")) > 4194304:
                raise ContractError("model evidence exceeds bounded run capacity")
            record = json.loads(raw)
            body = {key: value for key, value in record.items() if key != "sha256"}
            if (record.get("sequence") != len(records) + 1 or sequence != record["sequence"]
                or record.get("receipt_id") != receipt_id or record.get("previous_sha256") != previous
                or record.get("run_id") != self.run_id or record.get("sha256") != content_digest(body)
                or canonical_bytes(record).decode() != raw):
                raise ContractError("model evidence chain corrupt")
            records.append(record)
            previous = record["sha256"]
        return tuple(records)

    def records(self):
        with self._db(readonly=True) as db:
            return self._read(db)

    def resolve(self, receipt_id):
        identifier(receipt_id, "receipt_id")
        records = self.records()
        found = next((r for r in records if r["receipt_id"] == receipt_id), None)
        if found is None:
            raise ContractError("independent model receipt unavailable")
        return found

    def checkpoint(self):
        records = self.records()
        return (len(records), records[-1]["sha256"] if records else "0" * 64)

    def _insert(self, db, records, receipt_id, kind, payload, now, *, observer_token=None):
        identifier(receipt_id, "receipt_id")
        identifier(kind, "kind")
        self._check_observer_write(kind, observer_token)
        utc_time(now, "now")
        if now >= self.deadline:
            raise ContractError("model evidence window expired")
        frozen = json.loads(canonical_bytes(payload))
        if type(frozen) is not dict:
            raise ContractError("model evidence object required")
        existing = next((r for r in records if r["receipt_id"] == receipt_id), None)
        if existing:
            if (existing["kind"], existing["payload"]) != (kind, frozen):
                raise ContractError("model receipt identity conflict")
            return existing
        body = {"sequence": len(records) + 1, "receipt_id": receipt_id, "kind": kind,
                "run_id": self.run_id, "recorded_at": now.isoformat().replace("+00:00", "Z"),
                "previous_sha256": records[-1]["sha256"] if records else "0" * 64, "payload": frozen}
        record = {**body, "sha256": content_digest(body)}
        raw = canonical_bytes(record)
        if len(records) >= 512 or len(raw) > 4194304:
            raise ContractError("model evidence capacity exhausted")
        db.execute("INSERT INTO receipts VALUES (?,?,?)", (record["sequence"], receipt_id, raw.decode()))
        if self._observer_key is not None and kind in OBSERVER_ONLY_KINDS:
            self._ensure_attestation_table(db)
            mac = self._compute_observer_mac(receipt_id, kind, record["sha256"])
            db.execute(
                "INSERT OR REPLACE INTO observer_attestations(receipt_id, kind, observer_mac) VALUES (?,?,?)",
                (receipt_id, kind, mac),
            )
        return record

    def append(self, receipt_id, kind, payload, *, now, observer_token=None):
        with self._db() as db:
            return self._insert(db, self._read(db), receipt_id, kind, payload, now, observer_token=observer_token)

    def begin_http(self, *, phase, operation, invocation_sha256, body_sha256, timeout_seconds, now, observer_token=None):
        """Atomic reservation BEFORE any transport. Failed/unknown calls stay spent.

        Each invocation gets at most one render, tokenize and generation attempt.
        No generation is spent for render/tokenize. They do consume phase wall time.
        Duplicate invocation IDs cannot be moved to another phase to retry.
        """
        if phase not in PHASE_LIMITS or operation not in {"render", "tokenize", "generation"}:
            raise ContractError("unapproved model phase or HTTP operation")
        digest(invocation_sha256)
        digest(body_sha256)
        utc_time(now, "now")
        calls, seconds = PHASE_LIMITS[phase]
        if type(timeout_seconds) is not int or not 0 < timeout_seconds <= seconds:
            raise ContractError("invalid phase call timeout")
        receipt_id = operation + "-attempt-" + invocation_sha256
        with self._db() as db:
            records = self._read(db)
            attempts = [r for r in records if r["kind"] == "MODEL_HTTP_ATTEMPT"]
            if any(r["receipt_id"] == receipt_id for r in attempts):
                raise ContractError("model HTTP attempt already consumed; retries disabled")
            own = [r for r in attempts if r["payload"]["phase"] == phase]
            same_op = [r for r in own if r["payload"]["operation"] == operation]
            if len(same_op) >= calls:
                raise ContractError("phase operation budget exhausted")
            start = datetime.fromisoformat(own[0]["recorded_at"].replace("Z", "+00:00")) if own else now
            if now < start or (now - start).total_seconds() + timeout_seconds > seconds or (self.deadline - now).total_seconds() < timeout_seconds:
                raise ContractError("phase or absolute time budget exhausted")
            spent = sum(r["payload"]["reserved_seconds"] for r in own if r["payload"]["operation"] == "generation")
            if operation == "generation" and spent + timeout_seconds > seconds:
                raise ContractError("reserved generation time budget exhausted")
            payload = {"phase": phase, "operation": operation, "invocation_sha256": invocation_sha256,
                       "body_sha256": body_sha256, "reserved_seconds": timeout_seconds if operation == "generation" else 0,
                       "requested_timeout_seconds": timeout_seconds}
            return self._insert(db, records, receipt_id, "MODEL_HTTP_ATTEMPT", payload, now, observer_token=observer_token)


class ObserverAuthorizedModelStore:
    """Trusted controller-only write handle to ModelEvidenceStore carrying the private observer_key (Finding [4])."""

    def __init__(self, store: ModelEvidenceStore, observer_key: bytes) -> None:
        self._store = store
        self._observer_key = bytes(observer_key)

    @property
    def run_id(self) -> str:
        return self._store.run_id

    @property
    def deadline(self) -> datetime:
        return self._store.deadline

    @property
    def path(self) -> Path:
        return self._store.path

    @property
    def has_observer_key(self) -> bool:
        return self._store.has_observer_key

    def records(self):
        return self._store.records()

    def resolve(self, receipt_id):
        return self._store.resolve(receipt_id)

    def checkpoint(self):
        return self._store.checkpoint()

    def verify_observer_provenance(self, receipt_id: str) -> bool:
        return self._store.verify_observer_provenance(receipt_id)

    def require_observer_provenance(self, receipt_id: str):
        return self._store.require_observer_provenance(receipt_id)

    def append(self, receipt_id, kind, payload, *, now):
        return self._store.append(receipt_id, kind, payload, now=now, observer_token=self._observer_key)

    def begin_http(self, **kwargs):
        return self._store.begin_http(**kwargs, observer_token=self._observer_key)
