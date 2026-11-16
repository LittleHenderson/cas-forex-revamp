"""Five-step real-model controller; no keys, pair roles or scoring inputs."""
from copy import deepcopy
from datetime import datetime, timezone

from ..contracts import ContractError, content_digest
from ..operator.decisions import StaleDecision
from .custody_adapter import need
from .r6_runtime import CaseRuntime, packet_json
from .r6_observation import actual_state, effect_fingerprint, wire
from .r6_shadow import decide as shadow_decide
from .generation_transport import pending_ordering


def utc_now():
    return datetime.now(timezone.utc)


def pending_tick(runtime, session, request, schedule, pending_changes):
    need(pending_changes is not None, 'transport-owned pending bridge required')
    def apply(event):
        before = runtime.observe()
        old_context, old_policy = content_digest(runtime.context), content_digest(runtime.policy)
        if event['type'] == 'MARKET': runtime.market(event['quote'])
        elif event['type'] == 'CONTEXT_CHANGE':
            need(runtime.set_context(event['context']), 'declared pending context did not change')
        elif event['type'] == 'POLICY_CHANGE': runtime.change_policy(event['changes'])
        else: raise ContractError('unsupported pending event')
        return {'before': before, 'after': runtime.observe(), 'context_before_sha256': old_context,
            'context_after_sha256': content_digest(runtime.context), 'policy_before_sha256': old_policy,
            'policy_after_sha256': content_digest(runtime.policy),
            'policy_revision_after': runtime.policy['policy_revision'], 'context_version_after': runtime.context_version}
    with pending_changes.register(content_digest(request),events=schedule['pending_change']['events'],apply=apply) as plan:
        try:
            proposal,error=session.tick(request),None
        except StaleDecision as exc:
            proposal,error=None,type(exc).__name__
        for item in plan.observations:runtime.append('R6_PENDING_EVENT',item)
        return proposal,error,deepcopy(plan.observations)


def run_trajectory(case, *, directory, execution_id, build_id, adapter, model_store, model_reader, pending_changes=None, clock=utc_now, valve_gate=None):
    runtime = CaseRuntime(case, directory=directory, execution_id=execution_id,
                          build_id=build_id, adapter=adapter, clock=clock, valve_gate=valve_gate)
    runtime.initialize()
    rows = []
    for step in case['steps']:
        sid = step['step_id']
        row = {'case_id': case['case_id'], 'step_id': sid, 'account_id': case['account_id'],
            'plan_id': case['plan_id'], 'actual_receipt_verified': False,
            'admission_count': 0, 'dispatch_count': 0, 'error_type': None,
            'stale_rejected': False, 'first_attempt_only': True}
        rows.append(row)
        try:
            request, before, binding, view, before_preparation = runtime.prepare(step)
            packet = packet_json(request)
            row.update(request=wire(request), packet_json=packet,
                current_view=view, context_before=deepcopy(runtime.context), policy_before=deepcopy(runtime.policy),
                binding_before=binding, observed_before=before, observed_before_preparation=before_preparation,
                previous_observation=runtime.previous_observation,
                request_sha256=content_digest(request), request_state_sha256=content_digest(request.state),
                shadow=shadow_decide(packet), core_before=wire(runtime.core.read_snapshot(runtime.scope.key)),
                prior_position_id=runtime.last_position_id,
                actual_before=actual_state(before, policy_version=runtime.policy['policy_revision'],
                    context_version=runtime.context_version, position_id=runtime.last_position_id))
            if hasattr(adapter, 'prepare_source_binding'):
                adapter.prepare_source_binding(request, binding, before, runtime.current_state)
            session = runtime.new_operator()
            if step['schedule']['pending_change'] is not None:
                proposal, error, changes = pending_tick(runtime, session, request, step['schedule'], pending_changes)
                row['error_type'], row['pending_events'] = error, changes
                need(session.attempts, 'pending inference lacks a retained valid response')
                result = session.attempts[-1].result
            else:
                proposal = session.tick(request); result = proposal.result
                row['pending_events'] = []
            source = model_reader(wire(request), wire(result))
            invocation = source['receipt']['payload']['invocation']
            need(invocation['packet_json'] == packet, 'actual inference used a different current packet')
            selected = next((o for o in request.options if o.action_ref == result.selection.selected_action_ref), None)
            row.update(result=wire(result), actual_receipt_verified=True,
                inference_receipt_id=result.provenance.inference_receipt_id,
                inference_source_sha256=content_digest(source), inference_source=wire(source),
                selected_action_ref=result.selection.selected_action_ref,
                evidence_ids=list(result.selection.evidence_ids),
                action_kind=selected.intent.kind.value if selected else None,
                selected_strategy_id=selected.strategy_id if selected else None,
                selected_timeframe=selected.timeframe if selected else None,
                selected_intent=wire(selected.intent) if selected else None)
            runtime.append('R6_MODEL_DECISION', {'request': request, 'result': result, 'source': source})
            if step['schedule']['pending_change'] is not None:
                changes = row['pending_events']
                row['pending_ordering_verified'] = bool(len(changes) == len(step['schedule']['pending_change']['events'])
                    and pending_ordering(changes,source['transport']))
                row['stale_rejected'] = proposal is None and row['error_type'] == 'StaleDecision'
                need(row['pending_ordering_verified'] and row['stale_rejected'], 'mandatory pending stale proof failed')
            elif proposal.intent is not None:
                command = 'command-'+sid
                try:
                    runtime.admit_dispatch(proposal, binding, view, command)
                    row['command_id'] = command
                    if runtime.last_valve_decision is not None:
                        row['valve_decision'] = runtime.last_valve_decision
                        row['valve_blocked'] = False
                except Exception as valve_exc:
                    if type(valve_exc).__name__ == 'ValveRefusalError':
                        row['valve_blocked'] = True
                        row['error_type'] = 'ValveRefusalError'
                        row['valve_decision'] = runtime.last_valve_decision
                    else:
                        raise
            elif valve_gate is not None:
                dec = valve_gate.evaluate(
                    proposal,
                    current_view=view,
                    policy=runtime.effective_valve_policy(),
                    now=runtime.clock(),
                )
                row['valve_decision'] = wire(dec.to_dict())
                row['valve_blocked'] = False
            decision_read = runtime.observe()
            for event in step['schedule']['after_events']: runtime.market(event['quote'])
            after = runtime.observe(); core_after = runtime.core.read_snapshot(runtime.scope.key)
            before_ids = {r['command']['command_id'] for r in row['core_before']['commands']}
            new_commands = [wire(r) for r in core_after.commands if r.command.command_id not in before_ids]
            row['admission_count'] = len(new_commands)
            row['dispatch_count'] = sum(r['attempted'] is True for r in new_commands)
            row['new_core_commands'] = new_commands
            command = row.get('command_id')
            receipts = [r for r in after['receipts'] if r['command_id'] == command] if command else []
            receipt = receipts[-1] if receipts else None
            if receipt and receipt['position_id']: runtime.last_position_id = receipt['position_id']
            position_id = runtime.last_position_id
            row.update(observed_after=after, observed_before_after_events=decision_read,
                core_after=wire(core_after), command_receipts=receipts, receipt=receipt,
                effect=receipt['effect'] if receipt else None, position_id=position_id,
                observed_after_policy=deepcopy(runtime.policy), observed_after_context=deepcopy(runtime.context),
                binding_after={'scope': wire(runtime.scope), 'policy_sha256': content_digest(runtime.policy),
                    'policy_revision': runtime.policy['policy_revision'], 'context_sha256': content_digest(runtime.context),
                    'context_version': runtime.context_version, 'state': wire(runtime.current_state())},
                actual_after=actual_state(after, policy_version=runtime.policy['policy_revision'],
                    context_version=runtime.context_version, position_id=position_id),
                decision_venue_changed=bool(receipt and receipt['effect'] in ('PARTIALLY_FILLED', 'FILLED', 'APPLIED', 'CANCELLED')),
                before_fingerprint=effect_fingerprint(before), after_fingerprint=effect_fingerprint(after))
            if row['stale_rejected']:
                need(row['admission_count'] == row['dispatch_count'] == 0, 'stale response created a command or reservation')
            runtime.previous_observation = after
            runtime.append('R6_OBSERVED_OUTCOME', row)
        except Exception as exc:
            row['error_type'] = type(exc).__name__
            runtime.append('R6_TRAJECTORY_FAILURE', row)
            break
        finally:
            runtime.append('R6_FIRST_ATTEMPT', row)
    return rows, {'schema': 'forex.trajectory-read/2', 'case_id': case['case_id'],
        'scope': wire(runtime.scope), 'core': wire(runtime.core.read_snapshot(runtime.scope.key)),
        'venue': runtime.observe(), 'evidence_checkpoint': runtime.journal.checkpoint(),
        'directory': str(directory), 'remaining_steps_preserved_as_incomplete': len(case['steps'])-len(rows)}
