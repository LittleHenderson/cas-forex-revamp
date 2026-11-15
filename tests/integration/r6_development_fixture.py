"""New public development data, unrelated to sealed cases. NOT_RUN."""
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from cas_forex_revamp.contracts import DecisionSelection,DecisionProvenance,DecisionResult,DecisionOrigin,content_digest
from cas_forex_revamp.operator.decisions import DecisionProposal


class Clock:
    def __init__(self): self.value=datetime(2030,1,1,tzinfo=timezone.utc)
    def __call__(self): return self.value
    def advance(self,seconds=1): self.value+=timedelta(seconds=seconds)


def context(**overrides):
    value=dict(trend_score='3',range_score='1',thesis_valid=True,
                protection_due=False,trim_due=False,exit_due=False)
    value.update(overrides);return value


def option(index=1,kind='OPEN',**changes):
    value=dict(action_ref=f'{index:024x}',strategy_id='strategy-'+f'{index:024x}',timeframe='M5',label='Development option',kind=kind)
    if kind=='OPEN':value.update(side='BUY',quantity='10',limit_price='1.2',stop_price='1.0')
    elif kind=='AMEND_STOP':value.update(stop_price='1.05')
    else:value.update(side='SELL',quantity='ALL' if kind=='CLOSE' else '4',limit_price='1.0')
    value.update(changes);return value


def step(index=1,kind='OPEN',**changes):
    value=dict(step_id=f'{index:024x}',context=context(),options=[option(index,kind)],
        current_market={'bid':'1.1000','ask':'1.1002'},policy_revision=1,
        observation_binding='FRESH_INDEPENDENT_VENUE_SNAPSHOT',presentation_note='Development fixture',
        schedule=dict(before_mode='REUSE_LAST_OBSERVATION',before_events=[],after_events=[],fill_quotas=None,pending_change=None))
    value.update(changes);return value


def case(steps=None):
    return dict(case_id='a'*32,account_id='acct-'+'a'*24,plan_id='plan-'+'a'*24,instrument='EURUSD',
        initial_account=dict(balance='10000',equity='10000.00',available_margin='9000',position_inventory=[]),
        initial_market={'bid':'1.1','ask':'1.1002'},policy=dict(policy_revision=1,max_entry_quantity='20',
            new_risk_permission='ALLOWED',management_permission='ALLOWED',
            accounting_required=['balance','equity','available_margin','position_inventory'],
            strategy_rules={'strategy-'+'0'*23+'1':'Development text only'},management_rules={},rules=['No expansion']),
        steps=steps or [step()])


def submit(runtime, current_step):
    request,observed,binding,view,_=runtime.prepare(current_step)
    selection=DecisionSelection(request.request_id,request.opportunity_set_id,request.state.state_id,
        request.options[0].action_ref,'Development scripted fixture',tuple(x.evidence_id for x in request.evidence))
    provenance=DecisionProvenance(DecisionOrigin.SCRIPTED,'development',content_digest(request),content_digest(selection),
        'development',runtime.clock(),runtime.clock())
    result=DecisionResult(request.options[0].intent.decision_id,selection,provenance)
    proposal=DecisionProposal(request,result,request.options[0].intent)
    runtime.admit_dispatch(proposal,binding,view,'command-'+current_step['step_id'])
    return request,observed
