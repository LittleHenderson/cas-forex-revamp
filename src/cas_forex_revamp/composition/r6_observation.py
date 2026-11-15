"""Read-only observation of the frozen simulator checkpoint format.

The public venue port omits closed positions. This adapter reads the checkpoint
whose hash was independently returned by inspect_journal, in a read-only SQLite
transaction. It never derives an expected answer, repairs storage, or writes a
venue record. Source layout is pinned by the complete execution source archive.
"""
from __future__ import annotations

from decimal import Decimal
from pathlib import Path
import json
import sqlite3

from ..contracts import ContractError, canonical_bytes, content_digest


def need(ok, message):
    if not ok:
        raise ContractError(message)


def wire(value):
    return json.loads(canonical_bytes(value))


def read_venue_state(venue, key, *, now, path: Path):
    """Retain actual open AND terminal records plus independent receipt history.

    No timestamp is refreshed by a market event here. Snapshot observed_at is
    the read time; market observed/available timestamps remain their originals.
    A concurrent writer changes the cursor and makes the read unavailable.
    """
    first = venue.inspect_journal(key)
    need(first, 'venue checkpoint unavailable')
    anchor = first[-1]
    need(path.is_absolute() and path.is_file() and not path.is_symlink(), 'explicit regular venue file required')
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, isolation_level=None, timeout=1)
    try:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        row = db.execute('SELECT document, sha256 FROM checkpoints WHERE sequence=?', (anchor.sequence,)).fetchone()
        need(row is not None and row[1] == anchor.checkpoint_sha256, 'venue checkpoint anchor differs')
        document = json.loads(row[0])
        need(content_digest(document) == anchor.checkpoint_sha256
             and document['key'] == wire(key) and document['sequence'] == anchor.sequence
             and content_digest(document['state']) == anchor.state_sha256,
             'venue checkpoint bytes do not bind the independent anchor')
        state = document['state']
        need(state['storage_version'] == 1 and state['key'] == wire(key)
             and state['sequence'] == anchor.sequence, 'unsupported venue checkpoint layout')
        db.commit()
    finally:
        db.close()
    snapshot = venue.snapshot(key, now=now)
    receipts = venue.receipt_history(key)
    last = venue.inspect_journal(key)
    need(last[-1] == anchor and snapshot.sequence == anchor.sequence, 'venue changed during read binding')
    records = list(state['positions'].values())
    need(len(records) == len({r['position_id'] for r in records}), 'duplicate position records')
    open_records = [r for r in records if Decimal(r['quantity']) > 0]
    need({r['position_id']: r for r in open_records} == {r.position_id: wire(r) for r in snapshot.positions},
         'snapshot and checkpoint position records disagree')
    need(snapshot.balance.amount == Decimal(state['opening_balance']) + Decimal(state['realized']),
         'snapshot and checkpoint balance disagree')
    orders = [{name: order[name] for name in ('command_id', 'position_id', 'kind', 'filled', 'remaining', 'pending')}
              for order in state['commands'].values()]
    return {'snapshot': wire(snapshot), 'retained_positions': records, 'orders': orders,
            'receipts': wire(receipts), 'checkpoint': wire(anchor),
            'checkpoint_state_sha256': content_digest(state),
            'position_record_availability': 'READ_FROM_VERIFIED_VENUE_CHECKPOINT',
            'core_generated': False}


def effect_fingerprint(observed):
    """Economic/order/position/fence truth; excludes snapshot read timestamp."""
    snapshot = observed['snapshot']
    return content_digest({name: snapshot[name] for name in (
        'key', 'sequence', 'balance', 'equity', 'positions', 'open_command_ids', 'market', 'fence')})


def actual_state(observed, *, policy_version, context_version, position_id=None):
    """Projection of observations only. Missing terminal facts stay unavailable."""
    snap = observed['snapshot']
    opens = snap['positions']
    quantity = sum((Decimal(p['quantity']) for p in opens), Decimal(0))
    candidates = [p for p in observed['retained_positions'] if p['position_id'] == position_id] if position_id else opens
    position = candidates[0] if len(candidates) == 1 else None
    return {'open_positions': len(opens), 'open_quantity': str(quantity),
            'realized_balance': snap['balance']['amount'],
            'pending_quantity': str(sum((Decimal(o['remaining']) for o in observed['orders'] if o['pending']), Decimal(0))),
            'position_id': position['position_id'] if position else None,
            'position_version': position['version'] if position else None,
            'side': position['side'] if position else None,
            'stop': position['stop_price'] if position else None,
            'terminal_record_available': bool(position and Decimal(position['quantity']) == 0),
            'policy_version': policy_version, 'context_version': context_version,
            'venue_sequence': snap['sequence'], 'checkpoint_sha256': observed['checkpoint']['checkpoint_sha256']}
