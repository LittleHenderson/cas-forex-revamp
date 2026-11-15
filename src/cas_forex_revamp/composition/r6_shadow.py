"""Frozen current-packet heuristic; no core, venue, model or hidden-key ports.

Reports shadow choice agreement only, not a closed-loop baseline or RPA gain.
Arbitrary policy prose is not interpreted; resulting misses remain visible.
"""
import json
from decimal import Decimal
from ..contracts import content_digest

CONTROLLER_ID = 'r6-current-packet-heuristic-1'


def decide(packet_text):
    packet = json.loads(packet_text)
    sid = packet['request_id'][len('request-'):]
    facts = {f['fact_id'][:-(len(sid)+1)]: json.loads(f['value']) for f in packet['facts']}
    context, required = facts['context'], facts['policy-accounting_required']
    missing = [name for name in required if facts.get('observed-'+name) is None]
    positions, options = facts['observed-position_inventory'], packet['options']
    selected, disposition = None, 'WAIT'
    if missing:
        disposition = 'STAND_DOWN'
    elif positions and context['thesis_valid'] and not any(context[k] for k in ('exit_due', 'trim_due', 'protection_due')):
        disposition = 'HOLD'
    else:
        desired = ('CLOSE' if context['exit_due'] else 'REDUCE' if context['trim_due'] else
                   'AMEND_STOP' if context['protection_due'] else 'OPEN' if not positions else None)
        candidates = [x for x in options if x['kind'] == desired]
        if desired == 'OPEN':
            candidates = [x for x in candidates if Decimal(x['quantity']) <= Decimal(facts['policy-max_entry_quantity'])]
            if facts['policy-new_risk_permission'] != 'ALLOWED' or max(Decimal(context['trend_score']), Decimal(context['range_score'])) <= 0:
                candidates = []
        elif facts['policy-management_permission'] != 'ALLOWED':
            candidates = []
        if desired == 'AMEND_STOP' and 'protection_band' in context:
            low, high = map(Decimal, context['protection_band'])
            candidates = [x for x in candidates if low <= Decimal(x['stop_price']) <= high]
        if desired == 'REDUCE':
            candidates = [x for x in candidates if Decimal(x['quantity']) == Decimal(context['trim_quantity'])]
        candidates.sort(key=lambda x: (Decimal(x['quantity'] or '0'), x['side'] or '',
            Decimal(x['stop_price'] or '0'), Decimal(x['limit_price'] or '0'), x['timeframe'], x['action_ref']))
        if candidates:
            selected, disposition = candidates[0]['action_ref'], 'ACT'
    return {'controller_id': CONTROLLER_ID, 'comparison_mode': 'SHADOW_CURRENT_REQUEST',
            'packet_sha256': content_digest(packet), 'selected_action_ref': selected,
            'disposition': disposition, 'dispatch_count': 0, 'model_calls': 0,
            'policy_prose_interpretation_claim': False, 'closed_loop_claim': False}
