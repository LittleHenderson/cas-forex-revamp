"""B07 controller journal capacity, preserving the frozen operator record format.

The operator store remains unchanged. This controller-only subclass keeps the
same transaction, identity, hash-chain, size, deadline and checkpoint checks.
Its fixed 2048-record ceiling accommodates private cross-role evidence; it
does not increase any generation, token, time, retry or cost allowance.
"""
import json
from ..contracts import ContractError, canonical_bytes, content_digest
from ..contracts.primitives import identifier, utc_time
from ..operator.model_evidence import ModelEvidenceStore, OBSERVER_ONLY_KINDS

MAX_RECORDS=2048


class CustodyModelEvidenceStore(ModelEvidenceStore):
    def _read(self, db):
        if db.execute("SELECT run_id,deadline FROM meta").fetchall() != [(self.run_id, self.deadline.isoformat())]:
            raise ContractError("model evidence run/deadline mismatch")
        records, previous = [], "0" * 64
        for sequence, receipt_id, raw in db.execute("SELECT sequence,receipt_id,raw FROM receipts ORDER BY sequence"):
            if len(records) >= MAX_RECORDS or len(raw.encode("utf-8")) > 4194304:
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
        if len(records) >= MAX_RECORDS or len(raw) > 4194304:
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
