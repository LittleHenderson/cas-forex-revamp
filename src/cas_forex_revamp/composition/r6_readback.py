"""Read retained attempt, core, venue and model evidence through separate stores.

The caller pins the final per-trajectory checkpoint in the controller journal.
Local hashes detect mismatch against that anchor, not authenticity by themselves.
No initialize, reconcile, grant, model request or database write occurs here.
"""
from datetime import datetime
import json
from pathlib import Path
import sqlite3

from ..contracts import RunScope, canonical_bytes, content_digest
from ..core.storage import SQLiteStore, decode
from ..venue import SQLiteVenue
from .custody_adapter import need
from .evidence_journal import EvidenceJournal
from .r6_observation import wire, actual_state
from .r6_runtime import packet_json
from .r6_shadow import decide as shadow_decide
from .generation_transport import pending_ordering


class AttemptReader:
    def __init__(self, *, root, controller_journal, model_reader):
        self.root = Path(root)
        self.controller_journal, self.model_reader = controller_journal, model_reader

    def __call__(self, attempt):
        try:
            return self.verify(attempt)
        except (ValueError, KeyError, TypeError, IndexError, RuntimeError, OSError, sqlite3.Error):
            return False

    def verify(self, attempt):
        cid, sid = attempt['case_id'], attempt['step_id']
        anchors = [r.payload for r in self.controller_journal.records()
                   if r.kind == 'R6_TRAJECTORY_CHECKPOINT' and r.payload['case_id'] == cid]
        need(len(anchors) == 1, 'unique independent trajectory anchor missing')
        anchor = anchors[0]; scope = decode(canonical_bytes(anchor['scope']).decode(), RunScope)
        directory = self.root/('trajectory-'+cid)
        need(directory.is_relative_to(self.root) and directory.resolve() == directory,
             'trajectory evidence path must remain in retained state')
        for name in ('account.evidence.sqlite3','account.venue.sqlite3','account.core.sqlite3'):
            need((directory/name).is_file() and not (directory/name).is_symlink(), 'regular retained ledger required')
        journal = EvidenceJournal(directory/'account.evidence.sqlite3', scope.key)
        need(list(journal.checkpoint()) == anchor['evidence_checkpoint'], 'trajectory rollback or divergence')
        rows = [r.payload for r in journal.records() if r.kind == 'R6_FIRST_ATTEMPT' and r.payload['step_id'] == sid]
        need(len(rows) == 1 and rows[0] == attempt, 'attempt differs from durable first attempt')
        if not attempt.get('actual_receipt_verified'):
            return None
        source = self.model_reader(attempt['request'], attempt['result'])
        need(content_digest(source) == attempt['inference_source_sha256'], 'independent inference changed')
        if attempt.get('pending_events') or 'pending_ordering_verified' in attempt:
            ordering = pending_ordering(attempt.get('pending_events',[]),source.get('transport',{}))
            need(attempt.get('pending_ordering_verified') is ordering, 'pending ordering label differs from transport')
            saved = [r.payload for r in journal.records() if r.kind=='R6_PENDING_EVENT'
                     and r.payload.get('transport_receipt_id') in {e.get('transport_receipt_id') for e in attempt.get('pending_events',[])}]
            need(saved == attempt.get('pending_events',[]), 'pending changes differ from retained trajectory events')
        from ..contracts import DecisionRequest
        request = decode(canonical_bytes(attempt['request']).decode(), DecisionRequest)
        need(packet_json(request) == attempt['packet_json'] == source['receipt']['payload']['invocation']['packet_json'],
             'packet routes disagree')
        need(shadow_decide(attempt['packet_json']) == attempt['shadow'], 'shadow used another packet/controller')
        selected_ref = attempt['result']['selection']['selected_action_ref']
        option = next((o for o in request.options if o.action_ref == selected_ref), None)
        need(selected_ref is None or option is not None, 'selected option is not in actual request')
        need(attempt['selected_action_ref'] == selected_ref
             and attempt['evidence_ids'] == attempt['result']['selection']['evidence_ids']
             and attempt['selected_intent'] == (wire(option.intent) if option else None)
             and attempt['action_kind'] == (option.intent.kind.value if option else None)
             and attempt['selected_strategy_id'] == (option.strategy_id if option else None)
             and attempt['selected_timeframe'] == (option.timeframe if option else None),
             'selected action metadata differs from actual model result/request')
        packets = [r.payload for r in journal.records() if r.kind == 'R6_CURRENT_PACKET'
                   and r.payload['request']['request_id'] == request.request_id]
        need(len(packets) == 1 and packets[0]['request'] == attempt['request']
             and packets[0]['current_view'] == attempt['current_view']
             and packets[0]['binding'] == attempt['binding_before'], 'current packet source differs')
        venue = SQLiteVenue(directory/'account.venue.sqlite3')
        history = venue.inspect_journal(scope.key)
        need(wire(history[-1]) == anchor['venue_checkpoint'], 'independent venue high-water mark differs')
        observations = [attempt[k] for k in ('observed_before','observed_after','observed_before_preparation','observed_before_after_events')]
        if attempt.get('previous_observation'): observations.append(attempt['previous_observation'])
        for event in attempt.get('pending_events', []): observations.extend((event['before'],event['after']))
        with sqlite3.connect((directory/'account.venue.sqlite3').as_uri()+'?mode=ro', uri=True) as db:
            db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
            for observed in observations:
                cp = observed['checkpoint']
                need(any(wire(h) == cp for h in history), 'historical venue checkpoint missing')
                raw, digest = db.execute('SELECT document,sha256 FROM checkpoints WHERE sequence=?',(cp['sequence'],)).fetchone()
                doc = json.loads(raw); state = doc['state']
                need(content_digest(doc) == digest == cp['checkpoint_sha256'], 'historical venue bytes differ')
                at = datetime.fromisoformat(observed['snapshot']['observed_at'].replace('Z','+00:00'))
                # Frozen venue-owned arithmetic projects its actual persisted state;
                # it never generates or modifies an expected custody answer.
                need(wire(venue._snapshot(state, at)) == observed['snapshot'], 'snapshot differs from venue checkpoint')
                receipts = sorted([r for o in state['commands'].values() for r in o['receipts']], key=lambda r:r['venue_sequence'])
                orders = [{k:o[k] for k in ('command_id','position_id','kind','filled','remaining','pending')} for o in state['commands'].values()]
                need(receipts == observed['receipts'] and list(state['positions'].values()) == observed['retained_positions']
                     and orders == observed['orders'], 'retained receipt/order/terminal state differs')
        store = SQLiteStore(directory/'account.core.sqlite3')
        with store.read() as db:
            events = wire(store.events(db, scope.key)); commands = wire(store.commands(db, scope.key))
            need(events[-1]['event_sha256'] == anchor['core_event_sha256'], 'core high-water mark differs')
            by_id = {c['command']['command_id']:c for c in commands}
            for name in ('core_before','core_after'):
                cut = attempt[name]
                prefix = [e for e in events if e['sequence'] <= cut['event_sequence']]
                need(prefix == cut['events'] and prefix[-1]['event_sha256'] == cut['event_sha256'], 'core prefix differs')
                admissions = [json.loads(e['payload_json'])['command'] for e in prefix if e['kind'] == 'ADMISSION']
                need([c['command'] for c in cut['commands']] == admissions, 'core commands differ from admission events')
                need(all(c['command'] == by_id[c['command']['command_id']]['command'] for c in cut['commands']), 'immutable command changed')
                claimed = {json.loads(e['payload_json'])['command']['command_id'] for e in prefix if e['kind'] == 'DISPATCH_CLAIM'}
                need(all(c['attempted'] is (c['command']['command_id'] in claimed) for c in cut['commands']), 'dispatch flags differ from actual claims')
        before_ids = {r['command']['command_id'] for r in attempt['core_before']['commands']}
        new_commands = [r for r in attempt['core_after']['commands'] if r['command']['command_id'] not in before_ids]
        need(new_commands == attempt['new_core_commands']
             and type(attempt['admission_count']) is int and attempt['admission_count'] == len(new_commands)
             and type(attempt['dispatch_count']) is int
             and attempt['dispatch_count'] == sum(r['attempted'] is True for r in new_commands),
             'command counts differ from independent core records')
        command_id = attempt.get('command_id')
        receipts = [r for r in attempt['observed_after']['receipts'] if r['command_id'] == command_id] if command_id else []
        receipt = receipts[-1] if receipts else None
        changed = bool(receipt and receipt['effect'] in ('PARTIALLY_FILLED','FILLED','APPLIED','CANCELLED'))
        need(attempt['command_receipts'] == receipts and attempt['receipt'] == receipt
             and attempt['effect'] == (receipt['effect'] if receipt else None)
             and attempt['decision_venue_changed'] is changed,
             'claimed command effect differs from independent venue receipts')
        if command_id:
            need(command_id == 'command-'+sid and len(new_commands) == 1
                 and new_commands[0]['command']['command_id'] == command_id,
                 'dispatched identity differs from this first attempt')
        for before in (True,False):
            binding = attempt['binding_before' if before else 'binding_after']
            expected = actual_state(attempt['observed_before' if before else 'observed_after'],
                policy_version=binding['policy_revision'], context_version=binding['context_version'],
                position_id=attempt['prior_position_id' if before else 'position_id'])
            need(expected == attempt['actual_before' if before else 'actual_after'], 'actual-state projection differs')
        return True
