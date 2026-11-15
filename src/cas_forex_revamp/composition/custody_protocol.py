"""Accepted public custody contracts, strict shapes, durable one-use delivery.

The caller is the pinned trusted controller. A hash alone never authenticates
the producer. Runtime protected-root issuer/observer resolution is separate.
"""
from datetime import datetime, timezone
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import re
import sqlite3

from ..contracts import canonical_bytes, content_digest
from .role_channel import need, unpack_json

PINS = {
    'release': 'ccf5caf5c9fcdc8c006029ec7fbf17e686e50637c018bbd08ed1467eba908179',
    'channel': '2f421005ceb8eadf9fc3c527d2a0c5ce44209f501c0df265a045eb95df7daef0',
    'aggregate-result': '47af5ceb3e4b16b374ac379d67b84a7d6571110f6b94077ca22dcd71869f9a9d',
}


def contract(name):
    raw = (Path(__file__).parents[3]/'docs/contracts/custody-execution-01'/f'{name}.contract.json').read_bytes()
    need(sha256(raw).hexdigest() == PINS[name], 'public custody contract pin differs')
    return unpack_json(raw)


def timestamp(text):
    need(type(text) is str and text.endswith('Z'), 'UTC Z timestamp required')
    value = datetime.fromisoformat(text[:-1]+'+00:00')
    need(value.utcoffset().total_seconds() == 0, 'UTC required')
    return value


def stamp(now):
    need(now.utcoffset().total_seconds() == 0, 'UTC clock required')
    return now.isoformat().replace('+00:00', 'Z')


def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'exact SHA256 required')


def identifier(value):
    need(type(value) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}', value), 'opaque identifier required')


def shape(value, names):
    need(type(value) is dict and set(value) == set(names), 'unknown or missing fields')


def validate_release(receipt, *, expected, now, deadline):
    description = contract('release')
    shape(receipt, description['required_receipt_fields'])
    need(receipt['format'] == description['receipt_format'], 'release format differs')
    for name, kind in description['required_receipt_fields'].items():
        if kind == 'sha256': digest(receipt[name])
        elif kind == 'opaque_id': identifier(receipt[name])
        elif kind == 'positive_integer':
            need(type(receipt[name]) is int and receipt[name] > 0, 'positive release epoch required')
        elif kind == 'utc_timestamp': timestamp(receipt[name])
    need(timestamp(receipt['issued_at_utc']) <= timestamp(receipt['not_before_utc']) <= now
         < timestamp(receipt['expires_at_utc']) <= deadline, 'release time outside original window')
    # All identity/digest bindings come from authenticated external records,
    # never from the receipt itself. Times are bounded above independently.
    required = set(receipt) - {'format', 'release_id', 'issued_at_utc', 'not_before_utc', 'expires_at_utc'}
    need(set(expected) == required and all(receipt[k] == expected[k] for k in required),
         'unresolved or changed release binding')
    return receipt


def validate_message(message, *, binding, now):
    doc = contract('channel')
    shape(message, {*doc['common_required_fields'], 'payload'})
    need(message['format'] == 'forex.custody-current-channel/1', 'current channel format differs')
    need(message['kind'] in doc['message_kinds'], 'unknown current channel kind')
    for name in ('message_id', 'channel_id', 'run_id', 'request_id'): identifier(message[name])
    for name in ('scope_sha256', 'release_receipt_sha256', 'payload_sha256'): digest(message[name])
    for name in ('epoch', 'sequence'):
        need(type(message[name]) is int and message[name] > 0, 'positive channel integer required')
    need(all(message[k] == binding[k] for k in ('channel_id', 'run_id', 'epoch', 'scope_sha256', 'release_receipt_sha256')),
         'current channel binding differs')
    need(timestamp(message['not_before_utc']) <= now < timestamp(message['expires_at_utc'])
         <= timestamp(binding['expires_at_utc']), 'current channel expired')
    payload = message['payload']
    shape(payload, doc['message_kinds'][message['kind']]['required_payload_fields'])
    need(content_digest(payload) == message['payload_sha256'], 'channel payload changed')
    for name, value in payload.items():
        if name.endswith('_sha256') and value is not None: digest(value)
        if name.endswith('_id') and value is not None: identifier(value)
    kind = message['kind']
    if kind == 'CURRENT_FRAME':
        packet = payload['current_packet']
        shape(packet, ('schema','request_id','opportunity_set_id','source_state_id','state','options','facts','evidence','exact_request_sha256'))
        need(packet['schema'] == 'forex.current-decision-packet/2'
             and packet['request_id'] == message['request_id']
             and packet['opportunity_set_id'] == payload['opportunity_set_id']
             and content_digest(packet) == payload['current_packet_sha256']
             and content_digest(packet['state']) == payload['source_state_reference_sha256'], 'current projection binding differs')
        need(all(v is not None for v in payload.values()), 'current source binding unavailable')
    elif kind == 'PENDING_APPLIED_ACK':
        need(type(payload['event_ordinal']) is int and payload['event_ordinal'] > 0
             and payload['changed_domain'] in ('MARKET', 'CONTEXT', 'POLICY'), 'invalid applied acknowledgement')
        need(all(v is not None for k,v in payload.items() if k != 'previous_event_receipt_sha256'), 'missing observed effect')
    elif kind == 'DECISION_RESULT':
        status = payload['result_status']; need(status in ('COMPLETE', 'FAILED', 'UNKNOWN'), 'unknown result status')
        digest(payload['attempt_outcome_receipt_sha256'])
        if status == 'COMPLETE':
            shape(payload['selection'], ('request_id','opportunity_set_id','source_state_id','selected_action_ref','reason','evidence_ids'))
            for name in ('raw_response_receipt_sha256','transport_capture_receipt_sha256','token_usage_receipt_sha256','current_state_readback_sha256'):
                digest(payload[name])
        else: need(payload['selection'] is None, 'failed/unknown result cannot contain a selection')
    else:
        need(all(v is not None for v in payload.values()), 'complete send proof unavailable')
    return message


def envelope(kind, payload, *, binding, request_id, sequence, now):
    result = {k: binding[k] for k in ('channel_id','run_id','epoch','scope_sha256','release_receipt_sha256','expires_at_utc')}
    result.update(format='forex.custody-current-channel/1', kind=kind, message_id='message-'+str(sequence),
        request_id=request_id, sequence=sequence, not_before_utc=stamp(now), payload=payload, payload_sha256=content_digest(payload))
    return validate_message(result, binding=binding, now=now)


class ReleaseLedger:
    """One dedicated controller database. No automatic create/reopen/retry."""
    def __init__(self, path):
        self.path = Path(path)
        need(self.path.is_absolute() and self.path.name.endswith('.custody.sqlite3'), 'dedicated custody store required')

    def initialize(self):
        with self.path.open('xb'): pass
        with self._db() as db:
            db.execute('CREATE TABLE release (identity TEXT PRIMARY KEY, digest TEXT NOT NULL, raw TEXT NOT NULL)')
            db.execute('CREATE TABLE messages (identity TEXT PRIMARY KEY, digest TEXT NOT NULL, raw TEXT NOT NULL, ack TEXT)')

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True, timeout=5)
        try:
            db.execute('PRAGMA synchronous=FULL'); db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback();raise
        finally:db.close()

    def consume(self, receipt):
        with self._db() as db:
            need(db.execute('SELECT count(*) FROM release').fetchone()[0] == 0, 'release already consumed or outcome unknown')
            db.execute('INSERT INTO release VALUES (?,?,?)', (receipt['release_id'],content_digest(receipt),canonical_bytes(receipt).decode()))

    def expose(self, identity, value):
        """Commit before delivery. Exact repeat returns ACK only, never redelivery."""
        with self._db() as db:
            need(db.execute('SELECT count(*) FROM release').fetchone()[0] == 1, 'release not consumed')
            row = db.execute('SELECT digest,ack FROM messages WHERE identity=?',(identity,)).fetchone()
            if row is not None:
                need(row[0] == content_digest(value), 'conflicting exposure identity')
                need(row[1] is not None, 'unknown prior exposure; no blind resend')
                return unpack_json(row[1].encode())
            db.execute('INSERT INTO messages VALUES (?,?,?,NULL)',(identity,content_digest(value),canonical_bytes(value).decode()))
        return None

    def acknowledge(self, identity, value):
        with self._db() as db:
            row = db.execute('SELECT ack FROM messages WHERE identity=?',(identity,)).fetchone()
            need(row is not None, 'ack lacks durable exposure intent')
            raw = canonical_bytes(value).decode()
            need(row[0] is None or row[0] == raw, 'acknowledgement conflict')
            db.execute('UPDATE messages SET ack=? WHERE identity=?',(raw,identity))


def public_aggregate(value, *, approved_digest, final):
    doc = contract('aggregate-result')
    shape(value, doc['required_fields'])
    need(final is True and value['format'] == 'forex.stage-b-public-aggregate/1', 'public result only after final/abort')
    need(value['status'] in ('BLOCKED','INCOMPLETE','FAIL','ACCEPT'), 'public status invalid')
    identifier(value['run_id'])
    for name in ('source_freeze_manifest_sha256','custody_public_manifest_sha256','retained_evaluation_bundle_sha256','independent_redaction_receipt_sha256'): digest(value[name])
    codes = value['broad_failure_codes']
    need(type(codes) is list and len(set(codes)) == len(codes) and set(codes) <= set(doc['broad_failure_code_enum']), 'private/unknown public diagnostic')
    for name, cap in (('generation_attempts_spent',32),('mandatory_steps_accounted',30),('mandatory_steps_incomplete',30)):
        need(type(value[name]) is int and 0 <= value[name] <= cap, 'public aggregate count invalid')
    need(value['mandatory_steps_accounted'] + value['mandatory_steps_incomplete'] == 30
         and type(value['all_mandatory_assertions_passed']) is bool, 'aggregate denominator differs')
    complete=(value['mandatory_steps_incomplete']==0 and value['mandatory_steps_accounted']==30
              and value['generation_attempts_spent']==32)
    need(not value['all_mandatory_assertions_passed'] or complete,'incomplete pass claim forbidden')
    need(value['status'] != 'ACCEPT' or (value['all_mandatory_assertions_passed'] and complete
         and not codes), 'incomplete acceptance forbidden')
    # Approval binds all data fields; its own raw receipt hash is excluded to
    # avoid a circular self-hash. The caller separately pins that receipt.
    approved_body={k:v for k,v in value.items() if k!='independent_redaction_receipt_sha256'}
    need(content_digest(approved_body) == approved_digest, 'independent exact redaction approval unavailable')
    return value
