"""Recovered public design and explicit acceptance-readiness boundary.

These source-local IDs do not number the original prose and carry no case keys.
The no-argument readiness helper is the preserved legacy /1 gate; the /2 guest
driver uses native custody validation and independent final-source approval.
No runtime payload, reviewer label or source hash can fill an evaluator gap.
"""
from ..contracts import ContractError


R6_DESIGN = (
    ('R6-01', 'select strategy/timeframe A'),
    ('R6-02', 'select materially different B after a relevant change'),
    ('R6-03', 'wait when none is eligible'),
    ('R6-04', 'stand down on missing safety facts'),
    ('R6-05', 'retain/hold a valid existing position'),
    ('R6-06', 'modify its protection after changed context'),
    ('R6-07', 'partial then full exit through successive observed states'),
    ('R6-08', 'reject an attempted envelope expansion'),
)

# Exact public generation01 presentation variants. This explicit list maps the
# custodian's public definition file; it never interprets unseen case/answer data.
PUBLIC_CUSTODIAN_CLAUSES = {
    'select materially different strategy/timeframe B after a relevant change': R6_DESIGN[1][1],
    'wait when no strategy is eligible': R6_DESIGN[2][1],
    'stand down when safety facts are missing': R6_DESIGN[3][1],
    'hold a valid existing position': R6_DESIGN[4][1],
    'modify protection after changed context': R6_DESIGN[5][1],
}

# This is source capability, not a reviewer-controlled input. Removing an item
# requires the actual implementation and independent review, then a new freeze.
R6_SOURCE_GAPS = (
    'V2_FIVE_STEP_RUNNER_AND_GRAPH_VALIDATION',
    'CONTEXT_POLICY_AND_TARGET_VERSION_BINDING',
    'PARTIAL_ENTRY_PLAN_AND_REUSE_MARKET_BINDING',
    'INDEPENDENT_NO_ACTION_STATE_OBSERVATIONS',
    'TYPED_R6_ASSERTIONS_AND_EXACT_EFFECT_SCORING',
    'PENDING_TARGET_FILL_THEN_FRESH_VALID_INFERENCE',
    'PREDECLARED_SAME_INPUT_FIXED_CONTROLLER_BASELINE',
    'FROZEN_CANDIDATE_PROMPT_AND_PERMUTATION_PROVENANCE',
)


def _clause(text):
    if type(text) is not str:
        raise ContractError('R6 definition must be actual recovered text')
    value = text.strip().rstrip('.;').strip()
    value = value[:1].lower() + value[1:]
    if value.startswith('and '):
        value = value[4:]
    return PUBLIC_CUSTODIAN_CLAUSES.get(value, value)


def validate_recovered_design(definitions):
    """Bind external local IDs to all eight exact accepted clauses.

    Normalize terminal prose punctuation/conjunction and the exact public custody
    variants above. New task meanings, duplicate clauses and arbitrary replacements
    fail. Required typed
    assertions and case completeness are separate /2 semantic-validation work.
    """
    if type(definitions) is not dict or definitions.get('schema', definitions.get('format')) not in (
        'forex.r6-obligations/1', 'forex.r6-obligations/2'
    ):
        raise ContractError('versioned R6 obligation mapping required')
    if 'schema' in definitions and 'format' in definitions and definitions['schema'] != definitions['format']:
        raise ContractError('conflicting definition format identifiers')
    rows = definitions.get('obligations')
    if type(rows) is not list or len(rows) != len(R6_DESIGN):
        raise ContractError('all eight accepted R6 clauses required')
    ids = [row.get('obligation_id') if type(row) is dict else None for row in rows]
    if any(type(value) is not str or not value for value in ids) or len(set(ids)) != 8:
        raise ContractError('eight unique local obligation IDs required')
    phrases = [_clause(row.get('definition')) for row in rows]
    design = {phrase: local_id for local_id, phrase in R6_DESIGN}
    if len(set(phrases)) != 8 or set(phrases) != set(design):
        raise ContractError('definition mapping differs from the accepted R6 design')
    return {row['obligation_id']: design[phrase] for row, phrase in zip(rows, phrases)}


def require_r6_evaluator_readiness():
    """No B generation until the real /2 binding exists in reviewed source."""
    if R6_SOURCE_GAPS:
        raise ContractError('R6_EVALUATOR_SOURCE_INCOMPLETE: ' + ','.join(R6_SOURCE_GAPS))

