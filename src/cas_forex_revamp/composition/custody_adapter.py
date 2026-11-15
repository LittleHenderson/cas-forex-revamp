"""Lossless controller-only custody adapter for model-suite/2.

No oracle, counterpart role or future frame is an input to the packet builder.
Sparse independent expectations remain sparse; this code supplies no answers.
"""
from copy import deepcopy
from collections import Counter
from decimal import Decimal

from ..contracts import ContractError, content_digest, parse_decimal
from .custody_schema import CustodySchemas

FORMATS = {
    'suite': 'custody-trajectories-v1.schema.json',
    'schedules': 'custody-schedules-v1.schema.json',
    'keys': 'custody-independent-keys-v1.schema.json',
    'counterparts': 'custody-counterparts-v1.schema.json',
    'predicates': 'custody-predicate-catalogue-v1.schema.json'}
PROFILE = {'price_ceiling': '10', 'price_tick': '0.0001', 'quantity_step': '1',
           'money_quantum': '0.01', 'observation_ttl_seconds': 300}


def need(ok, message):
    if not ok:
        raise ContractError(message)


def amount(value, *, positive=False, nonnegative=False):
    result = parse_decimal(value)
    need(not positive or result > 0, 'positive decimal required')
    need(not nonnegative or result >= 0, 'nonnegative decimal required')
    return result


def validate_quote(quote):
    bid, ask = amount(quote['bid'], positive=True), amount(quote['ask'], positive=True)
    need(bid <= ask <= amount(PROFILE['price_ceiling']), 'quote outside frozen simulator profile')
    need(all(x % amount(PROFILE['price_tick']) == 0 for x in (bid, ask)), 'quote tick differs')


def validate_context(context):
    amount(context['trend_score']); amount(context['range_score'])
    if context['protection_due']:
        need('protection_band' in context, 'protection trigger lacks a declared band')
    if context['trim_due']:
        need('trim_quantity' in context, 'trim trigger lacks quantity')
    if 'protection_band' in context:
        low, high = (amount(x, positive=True) for x in context['protection_band'])
        need(low <= high, 'reversed protection band')
    if 'trim_quantity' in context:
        need(amount(context['trim_quantity'], positive=True) % amount(PROFILE['quantity_step']) == 0,
             'trim geometry differs')


def normalize_member(case, schedules, key_case, member):
    """Compare declared counterpart semantics using the private role map only here.

    This function belongs to validation/scoring; neither map nor normalized keys
    is returned in the executable case. Presentation and independent explanation
    text are excluded. All actual facts, rules, geometry and expected values stay.
    """
    replacements = {case['case_id']: 'CASE', case['account_id']: 'ACCOUNT', case['plan_id']: 'PLAN'}
    for role, identity in member['strategy_role_map'].items():
        need(identity not in replacements, 'duplicate private strategy role identity')
        replacements[identity] = 'STRATEGY:' + role
    declared_steps = {row['step_id']: row for row in member['steps']}
    need(set(declared_steps) == {s['step_id'] for s in case['steps']}, 'counterpart step coverage differs')
    for index, step in enumerate(case['steps']):
        sid = step['step_id']; mapping = declared_steps[sid]
        replacements[sid] = 'STEP:' + str(index)
        need(mapping['ordered_action_refs'] == [x['action_ref'] for x in step['options']], 'private order map differs')
        need(set(mapping['semantic_action_refs'].values()) == {x['action_ref'] for x in step['options']}
             and len(mapping['semantic_action_refs']) == len(step['options']), 'private action role mapping is not bijective')
        for role, ref in mapping['semantic_action_refs'].items():
            replacements[ref] = 'ACTION:' + str(index) + ':' + role
    def convert(value):
        if type(value) is str:
            for old in sorted(replacements, key=len, reverse=True):
                value = value.replace(old, replacements[old])
            return value
        if type(value) is list:
            return [convert(x) for x in value]
        if type(value) is dict:
            return {convert(k): convert(v) for k, v in value.items()}
        return value
    normalized = deepcopy(case)
    for step in normalized['steps']:
        step.pop('presentation_note')
        step['options'] = sorted(step['options'], key=lambda x: replacements[x['action_ref']])
    expected = deepcopy(key_case)
    expected.pop('variant')
    for step in expected['steps']:
        step.pop('independent_reason')
        step['permissible_action_refs'] = sorted(step['permissible_action_refs'], key=lambda x: '' if x is None else replacements[x])
    return convert({'case': normalized, 'schedule': schedules, 'independent_keys': expected})


def adapt_custody(documents, *, schema_directory, definitions, reviewed_binding):
    """Run only inside the approved controller. Implementation authors read none.

    reviewed_binding is independently selected, hash-pinned controller evidence;
    caller-supplied PASS strings alone cannot clear the guest authorization gate.
    """
    need(set(documents) == set(FORMATS), 'exact five custody documents required')
    validators = CustodySchemas(schema_directory)
    for key, schema in FORMATS.items():
        validators.validate(schema, documents[key])
    from .r6_design import validate_recovered_design
    validate_recovered_design(definitions)
    source = documents['suite']; cases = source['trajectories']
    digest_set = {name: content_digest(document) for name, document in documents.items()}
    need(reviewed_binding.get('canonical_document_sha256') == digest_set
         and reviewed_binding.get('source_semantics_and_predicates_checked') is True
         and reviewed_binding.get('counterpart_semantics_checked') is True
         and reviewed_binding.get('independent_reviewer_id')
         and reviewed_binding.get('final_order_independence_established') is True,
         'complete independent custody/source/order review remains required')
    schedule_rows = documents['schedules']['steps']
    schedule = {(x['case_id'], x['step_id']): x for x in schedule_rows}
    key_cases = {x['case_id']: x for x in documents['keys']['cases']}
    expected_ids = {(c['case_id'], s['step_id']) for c in cases for s in c['steps']}
    need(len(expected_ids) == 30 and len(schedule) == len(schedule_rows) == 30
         and set(schedule) == expected_ids, '30 unique scheduled first decisions required')
    need(len({c['case_id'] for c in cases}) == len(key_cases) == 16
         and set(key_cases) == {c['case_id'] for c in cases}, '16 unique corresponding trajectories required')
    all_steps, all_actions, accounts, plans = set(), set(), set(), set()
    runnable = []
    obligations = {x['obligation_id']: set(x['assertions']) for x in definitions['obligations']}
    predicates = set(documents['predicates']['assertions'])
    need(predicates == set().union(*obligations.values()), 'predicate catalogue differs from recovered R6')
    pair_counts = Counter()
    for case in cases:
        cid = case['case_id']; key_case = key_cases[cid]
        need(case['account_id'] not in accounts and case['plan_id'] not in plans, 'case account/plan reuse')
        accounts.add(case['account_id']); plans.add(case['plan_id'])
        need(key_case['account_id'] == case['account_id'] and key_case['plan_id'] == case['plan_id'], 'key account/plan differs')
        pair_counts[(key_case['obligation_id'], key_case['variant'])] += 1
        keys = {s['step_id']: s for s in key_case['steps']}
        need(len(keys) == len(case['steps']) and set(keys) == {s['step_id'] for s in case['steps']}, 'key step coverage differs')
        need(set().union(*(set(k['mandatory_assertions']) for k in keys.values())) == obligations[key_case['obligation_id']],
             'complete exact named obligation coverage required')
        initial = case['initial_account']
        for role in ('balance', 'equity'):
            amount(initial[role])
        need(amount(initial['equity']) == amount(initial['balance']) and initial['position_inventory'] == [],
             'declared initial account is not the supported independently created flat account')
        if initial['available_margin'] is not None:
            amount(initial['available_margin'], nonnegative=True)
        validate_quote(case['initial_market'])
        amount(case['policy']['max_entry_quantity'], nonnegative=True)
        current_policy = deepcopy(case['policy'])
        executable = deepcopy(case)
        for step in executable['steps']:
            sid = step['step_id']; key = keys[sid]; timing = schedule[(cid, sid)]
            need(sid not in all_steps, 'global step reuse'); all_steps.add(sid)
            need(step['policy_revision'] == current_policy['policy_revision'], 'step policy revision lacks declared lineage')
            validate_context(step['context']); validate_quote(step['current_market'])
            refs = {o['action_ref'] for o in step['options']}
            need(not refs & all_actions, 'global action reuse'); all_actions |= refs
            need(set(key['permissible_action_refs']) <= refs | {None}, 'key names an unsupplied action')
            evidence = {prefix + sid for prefix in ('evidence-', 'case-', 'policy-')}
            need(set(key['required_evidence_ids']) <= evidence, 'key names unavailable source evidence')
            for expected in (key['expected_pre'], key['expected_post']):
                if expected is None:
                    continue  # preserve explicit absence, never synthesize it
                for field in ('balance', 'open_quantity', 'pending_quantity', 'prior_position_terminal_quantity'):
                    if field in expected:
                        amount(expected[field], nonnegative=field != 'balance')
                stop = expected['stop_price']
                if type(stop) is dict:
                    need(set(stop['by_action_ref']) <= refs & set(key['permissible_action_refs']), 'expected stop branch outside permitted references')
                    for value in stop['by_action_ref'].values(): amount(value, positive=True)
                elif stop is not None: amount(stop, positive=True)
            for option in step['options']:
                for field in ('limit_price', 'stop_price'):
                    if field in option:
                        value = amount(option[field], positive=True)
                        need(value <= amount(PROFILE['price_ceiling']) and value % amount(PROFILE['price_tick']) == 0, 'option price geometry outside profile')
                if option.get('quantity') not in (None, 'ALL'):
                    need(amount(option['quantity'], positive=True) % amount(PROFILE['quantity_step']) == 0, 'option quantity geometry differs')
            if timing['before_mode'] == 'REUSE_LAST_OBSERVATION':
                need(not timing['before_events'], 'REUSE cannot advance or refresh a market')
            for event in timing['before_events'] + timing['after_events']:
                validate_quote(event['quote'])
            if timing['fill_quotas'] is not None:
                for quota in timing['fill_quotas']:
                    need(amount(quota, nonnegative=True) % amount(PROFILE['quantity_step']) == 0, 'fill quota geometry differs')
            pending = timing['pending_change']
            if pending:
                need('stale_proof' in key and not key['current_decision_must_dispatch'], 'pending change lacks no-admission stale requirements')
                need({e['type'] for e in pending['events']} == {'MARKET', 'CONTEXT_CHANGE', 'POLICY_CHANGE'}, 'all three pending change domains required')
                for event in pending['events']:
                    if event['type'] == 'MARKET': validate_quote(event['quote'])
                    elif event['type'] == 'CONTEXT_CHANGE': validate_context(event['context'])
                    else:
                        patch = event['changes']
                        need(patch['policy_revision'] == current_policy['policy_revision'] + 1, 'policy revision is not the next revision')
                        amount(patch['max_entry_quantity'], nonnegative=True)
                        current_policy.update(patch)
            else:
                need('stale_proof' not in key, 'stale proof lacks pending schedule')
            step['schedule'] = deepcopy(timing)
        # No oracle, obligation, variant or counterpart roles cross this boundary.
        runnable.append(executable)
    need(pair_counts == Counter({(o, v): 1 for o in obligations for v in ('PRIMARY', 'COUNTERPART')}), 'eight exact pairs required')
    pairs, consumed_cases, pair_hashes = documents['counterparts']['pairs'], set(), {}
    need({p['obligation_id'] for p in pairs} == set(obligations), 'counterpart obligation coverage differs')
    case_map = {c['case_id']: c for c in cases}
    for pair in pairs:
        members = pair['members']; normalized = []
        identity = content_digest(tuple(sorted(m['case_id'] for m in members)))
        for member in members:
            cid = member['case_id']
            need(cid in case_map and cid not in consumed_cases and key_cases[cid]['obligation_id'] == pair['obligation_id'], 'counterpart membership differs')
            consumed_cases.add(cid); pair_hashes[cid] = identity
            rows = [schedule[(cid, s['step_id'])] for s in case_map[cid]['steps']]
            normalized.append(normalize_member(case_map[cid], rows, key_cases[cid], member))
        need(normalized[0] == normalized[1], 'counterpart normalization differs; no semantic guessing')
    need(consumed_cases == set(case_map), 'counterpart coverage incomplete')
    need(sorted(len(c['steps']) for c in cases) == sorted([1, 2, 1, 1, 2, 2, 5, 1]*2), 'fixed 30-call graph differs')
    return {'schema': 'forex.model-suite/2', 'trajectories': runnable,
            'source_digests': digest_set, 'planned_calls': 30,
            'validation': {'counterparts_normalized': True, 'exact_graph': True},
            'expected_values_source': 'UNCHANGED_INDEPENDENT_CUSTODY',
            'pair_consumption_ids': pair_hashes, 'profile': deepcopy(PROFILE)}
