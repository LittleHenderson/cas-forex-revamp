"""Data-only sealed-suite validation and first-attempt scoring. No execution.

The actual independently reviewed R6 case pool is an external, pinned input.
Development cases cannot be promoted by changing a payload label. The trusted
guest configuration must pin the suite, keys, review and exposure-register files.
"""
from __future__ import annotations

from collections import Counter
import re
from ..contracts import ContractError, content_digest, parse_decimal


def need(ok, message):
    if not ok:
        raise ContractError(message)


def validate_suite(suite, review, exposure, *, suite_sha256, keys_sha256):
    need(suite.get('schema') == 'forex.model-suite/1', 'unknown B suite')
    need(suite.get('purpose') == 'SEALED_B_ACCEPTANCE', 'development material is not sealed acceptance')
    cases = suite.get('trajectories')
    need(type(cases) is list and len(cases) == 16, 'exactly 16 planned trajectories required')
    obligations = suite.get('obligations')
    need(type(obligations) is list and len(obligations) == 8 and len(set(obligations)) == 8,
         'eight independently defined R6 obligations required')
    need(review.get('suite_sha256') == suite_sha256 and review.get('keys_sha256') == keys_sha256
         and review.get('r6_definition_sha256') == suite.get('r6_definition_sha256')
         and review.get('independent_reviewer_id') and review.get('counterpart_semantics_checked') is True
         and review.get('answer_leakage_checked') is True and review.get('material_options_checked') is True
         and review.get('causal_facts_checked') is True, 'pinned independent R6/counterpart review missing')
    need(exposure.get('suite_sha256') == suite_sha256 and type(exposure.get('previous_generation_attempts')) is int
         and exposure.get('previous_generation_attempts') == 0
         and exposure.get('development_exposure') is False, 'exposed cases cannot count as untouched')
    seen, pairs, planned, continuous, stale = set(), Counter(), 0, 0, 0
    global_steps = set()
    for case in cases:
        cid = case.get('case_id')
        need(type(cid) is str and len(cid) == 32 and all(c in '0123456789abcdef' for c in cid)
             and cid not in seen, 'unique opaque trajectory IDs required')
        seen.add(cid)
        need(case.get('obligation_id') in obligations and case.get('wording') in ('A', 'B'), 'unknown obligation/counterpart')
        pairs[(case['obligation_id'], case['wording'])] += 1
        steps = case.get('steps')
        need(type(steps) is list and 1 <= len(steps) <= 4, 'one to four explicit decisions per trajectory')
        planned += len(steps)
        need(type(case.get('continuous_required')) is bool, 'explicit continuous-case classification required')
        continuous += case['continuous_required']
        local_ids = set()
        for step in steps:
            need(type(step.get('step_id')) is str and re.fullmatch('[a-f0-9]{24}', step['step_id'])
                 and step['step_id'] not in global_steps, 'globally unique opaque step IDs required')
            local_ids.add(step['step_id'])
            global_steps.add(step['step_id'])
            need(type(step.get('invalidate_while_pending')) is bool, 'explicit stale-inference schedule required')
            stale += step['invalidate_while_pending']
            options = step.get('options')
            need(type(options) is list and 2 <= len(options) <= 8, 'two genuine alternatives plus implicit WAIT required')
            need(len({(x['strategy_id'], x['timeframe']) for x in options}) >= 2, 'distinct strategy/timeframe alternatives required')
            need(len({x['action_ref'] for x in options}) == len(options), 'duplicate action choices')
            need(all(len(x['action_ref']) == 24 and all(c in '0123456789abcdef' for c in x['action_ref']) for x in options), 'opaque permuted choices required')
            need(type(step.get('facts')) is list and 1 <= len(step['facts']) <= 8, 'bounded causal facts required')
            need(type(step.get('market_after')) is list and len(step['market_after']) <= 3, 'bounded subsequent market schedule')
            # The runner forwards only facts/options/current observation, never these
            # schedule/classification fields or reviewer/hidden answer material.
            need(not any(k in step for k in ('correct_action', 'permissible_actions', 'answer_key')), 'answer key leaked into case payload')
    need(pairs == Counter({(o, w): 1 for o in obligations for w in ('A', 'B')}), 'eight exact wording pairs required')
    for obligation in obligations:
        left, right = [c for c in cases if c['obligation_id'] == obligation]
        need(left['continuous_required'] == right['continuous_required']
             and len(left['steps']) == len(right['steps'])
             and [s['invalidate_while_pending'] for s in left['steps']] == [s['invalidate_while_pending'] for s in right['steps']],
             'wording counterparts differ in planned causal schedule')
    need(continuous >= 1 and stale >= 1 and planned <= 32, 'continuous/stale coverage must fit 32 first calls')
    need(review.get('planned_calls') == planned, 'reviewed coverage/call count differs')
    return planned


def validate_keys(suite, keys):
    """Validate an independently supplied complete oracle; never infer missing answers."""
    need(keys.get('schema') == 'forex.model-keys/1' and type(keys.get('steps')) is list, 'independent keys unavailable')
    expected = {(c['case_id'], s['step_id']): s for c in suite['trajectories'] for s in c['steps']}
    rows = {(r['case_id'], r['step_id']): r for r in keys['steps']}
    need(len(rows) == len(keys['steps']) and set(rows) == set(expected), 'complete unique key coverage required')
    for ident, row in rows.items():
        step = expected[ident]
        permitted = row.get('permissible_action_refs')
        available = {o['action_ref'] for o in step['options']} | {None}
        need(type(permitted) is list and permitted and len(set(permitted)) == len(permitted)
             and set(permitted) <= available, 'explicit nonempty permissible action set required')
        need(type(row.get('required_evidence_ids')) is list
             and set(row['required_evidence_ids']) <= {'evidence-' + step['step_id'], 'case-' + step['step_id']},
             'required evidence must name supplied causal sources')
        need(type(row.get('must_change_venue')) is bool and 'required_effect' in row
             and 'required_action_kind' in row, 'explicit effect/action obligations required, including null')
        need(row['required_effect'] in (None, 'ACKNOWLEDGED', 'PARTIALLY_FILLED', 'FILLED', 'APPLIED', 'CANCELLED', 'REJECTED'), 'unsupported expected effect')
        need(row['required_action_kind'] in (None, 'WAIT', 'OPEN', 'ADD', 'REDUCE', 'CLOSE', 'AMEND_STOP', 'CANCEL_ORDER'), 'unsupported expected kind')
        need(not step['invalidate_while_pending'] or not row['must_change_venue'], 'stale reply cannot be required to dispatch')
        need(type(row.get('obligation_assertions')) is dict and row['obligation_assertions'], 'named R6 assertions must not be omitted')
        allowed = {'model_choice', 'stale_result', 'dispatch', 'effect', 'kind', 'no_error'}
        need(all(type(k) is str and v in allowed for k, v in row['obligation_assertions'].items()),
             'unknown assertion mapping requires reviewed evaluator source, never automatic success')
    return rows


def validate_obligations(suite, keys, definitions):
    need(definitions.get('schema') == 'forex.r6-obligations/1', 'actual reviewed R6 definitions required')
    obligations = definitions.get('obligations')
    need(type(obligations) is list and len(obligations) == 8, 'eight complete R6 definitions required')
    by_id = {o['obligation_id']: o for o in obligations}
    need(len(by_id) == 8 and set(by_id) == set(suite['obligations']), 'R6 definition identities differ')
    rows = validate_keys(suite, keys)
    for case in suite['trajectories']:
        definition = by_id[case['obligation_id']]
        required = definition.get('assertions')
        need(type(definition.get('definition')) is str and definition['definition'].strip()
             and type(required) is list and required and len(set(required)) == len(required), 'complete obligation wording/assertions required')
        mapped = {name for step in case['steps'] for name in rows[(case['case_id'], step['step_id'])]['obligation_assertions']}
        need(mapped == set(required), 'every named R6 assertion must have explicit evaluator coverage')
    return True


def score_suite(suite, keys, attempts):
    """Only after execution: no key influences packet building or dispatch."""
    key_rows = validate_keys(suite, keys)
    expected = {(c['case_id'], s['step_id']) for c in suite['trajectories'] for s in c['steps']}
    need(len(key_rows) == len(keys['steps']) and set(key_rows) == expected, 'key coverage differs from all planned decisions')
    first = {}
    for a in attempts:
        ident = a['case_id'], a['step_id']
        need(ident in expected and ident not in first, 'duplicate/unknown first-attempt result')
        first[ident] = a
    trajectories = []
    for case in suite['trajectories']:
        results = []
        for step in case['steps']:
            ident = case['case_id'], step['step_id']; a = first.get(ident); key = key_rows[ident]
            if a is None:
                results.append({'step_id': step['step_id'], 'status': 'INCOMPLETE'}); continue
            valid = (a.get('actual_receipt_verified') is True
                     and a.get('selected_action_ref') in key['permissible_action_refs']
                     and set(key['required_evidence_ids']).issubset(a.get('evidence_ids', [])))
            claims = {'model_choice': valid,
                      'stale_result': a.get('stale_rejected') is True if step['invalidate_while_pending'] else a.get('stale_rejected') is False,
                      'dispatch': not key.get('must_change_venue') or a.get('venue_changed') is True,
                      'effect': key.get('required_effect') is None or a.get('effect') == key['required_effect'],
                      'kind': key.get('required_action_kind') is None or a.get('action_kind') == key['required_action_kind'],
                      'no_error': a.get('error_type') is None or (step['invalidate_while_pending'] and a.get('error_type') == 'StaleDecision')}
            named = {name: claims[source] for name, source in key['obligation_assertions'].items()}
            results.append({'step_id': step['step_id'], 'status': 'PASS' if all(claims.values()) else 'FAIL',
                            'assertions': claims, 'named_obligation_assertions': named})
        case_attempts = [first.get((case['case_id'], s['step_id']), {}) for s in case['steps']]
        continuous = True
        if case['continuous_required']:
            entered = next((a for a in case_attempts if a.get('action_kind') == 'OPEN' and a.get('effect') == 'FILLED'), None)
            reduced = next((a for a in case_attempts if a.get('action_kind') == 'REDUCE' and a.get('effect') == 'FILLED'), None)
            closed = next((a for a in case_attempts if a.get('action_kind') == 'CLOSE' and a.get('effect') == 'FILLED'), None)
            continuous = bool(entered and reduced and closed and entered.get('position_id')
                == reduced.get('position_id') == closed.get('position_id')
                and reduced.get('positions_after') == 1 and parse_decimal(reduced.get('position_quantity_after', '0')) > 0
                and closed.get('positions_after') == 0 and closed.get('position_quantity_after') == '0'
                and case_attempts.index(entered) < case_attempts.index(reduced) < case_attempts.index(closed)
                and any(a.get('stale_rejected') is True for a in
                        case_attempts[case_attempts.index(entered)+1:case_attempts.index(closed)])
                and all(a.get('request_state_sha256') for a in case_attempts)
                and len({a.get('request_state_sha256') for a in case_attempts}) == len(case_attempts))
        status = 'INCOMPLETE' if any(x['status'] == 'INCOMPLETE' for x in results) else 'PASS' if continuous and all(x['status'] == 'PASS' for x in results) else 'FAIL'
        trajectories.append({'case_id': case['case_id'], 'status': status, 'continuous': continuous, 'steps': results})
    status = 'PASS' if all(c['status'] == 'PASS' for c in trajectories) else 'INCOMPLETE' if any(c['status'] == 'INCOMPLETE' for c in trajectories) else 'FAIL'
    return {'schema': 'forex.model-suite-result/1', 'status': status, 'planned_trajectories': 16,
            'planned_decisions': len(expected), 'first_attempts': len(first), 'trajectories': trajectories,
            'u0': 'NOT_RUN_SEPARATE_OWNER_STUDY', 'u1': 'NOT_RUN_SEPARATE_APPROVAL_AND_CALL_BUDGET',
            'profit_or_learning_claim': False, 'keys_digest': content_digest(keys)}
