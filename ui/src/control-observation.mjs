/** Pure display checks against existing shared FenceRequest/FenceReceipt fields.
 * The caller must obtain the observation from an explicitly attached trusted bridge.
 * Imported cockpit/Review JSON must never call this as a source-authentication shortcut.
 */
import { isUTCTimestamp, utcMicroseconds } from './wire.mjs';
const identifier = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$/.test(value);

function sameKey(left, right) {
  return left?.environment === 'DISCONNECTED_SIMULATION' && right?.environment === 'DISCONNECTED_SIMULATION'
    && identifier(left.account_id) && identifier(left.run_id)
    && left.account_id === right.account_id && left.run_id === right.run_id;
}

/** A shape/identity comparison only; it neither submits nor reads a control. */
export function compareFenceReadback(request, receipt, expectedPermissions) {
  if (!request || !receipt) return { matches: false, reason: 'Independent fence readback unavailable.' };
  if (!identifier(request.barrier_id) || !identifier(request.owner_request_id)) return { matches: false, reason: 'Exact control identity is unavailable.' };
  if (!sameKey(request.key, receipt.key)) return { matches: false, reason: 'Fence belongs to a different account/run.' };
  if (!Number.isSafeInteger(request.expected_generation) || request.expected_generation < 0 || !Number.isSafeInteger(request.next_generation) || request.next_generation !== request.expected_generation + 1) return { matches: false, reason: 'Invalid requested generation.' };
  if (receipt.barrier_id !== request.barrier_id || receipt.generation !== request.next_generation) return { matches: false, reason: 'Requested barrier was not observed. It may have been superseded.' };
  if (receipt.applied !== true || typeof receipt.new_risk_allowed !== 'boolean' || typeof receipt.management_allowed !== 'boolean' || !Number.isSafeInteger(receipt.venue_sequence) || receipt.venue_sequence < 0) return { matches: false, reason: 'Fence application is not established.' };
  if (!isUTCTimestamp(request.requested_at) || !isUTCTimestamp(receipt.observed_at) || utcMicroseconds(receipt.observed_at) < utcMicroseconds(request.requested_at)) return { matches: false, reason: 'Fence observation predates the request or has an invalid time.' };
  if (!expectedPermissions || typeof expectedPermissions.new_risk_allowed !== 'boolean' || typeof expectedPermissions.management_allowed !== 'boolean') return { matches: false, reason: 'Exact expected permission result is unavailable.' };
  if (receipt.new_risk_allowed !== expectedPermissions.new_risk_allowed || receipt.management_allowed !== expectedPermissions.management_allowed) return { matches: false, reason: 'Observed permissions differ from the requested result.' };
  if (request.control === 'STOP_AUTOMATION' && (receipt.new_risk_allowed || receipt.management_allowed)) return { matches: false, reason: 'Stop requires both automated permissions to be disabled.' };
  if (request.control === 'PAUSE_NEW_RISK' && receipt.new_risk_allowed) return { matches: false, reason: 'Pause requires new risk to be disabled.' };
  if (!['PAUSE_NEW_RISK', 'STOP_AUTOMATION', 'RESUME_NEW_RISK', 'RESUME_MANAGEMENT'].includes(request.control)) return { matches: false, reason: 'Unsupported control.' };
  if (request.control === 'RESUME_NEW_RISK' && !receipt.new_risk_allowed) return { matches: false, reason: 'New-risk permission was not observed.' };
  if (request.control === 'RESUME_MANAGEMENT' && !receipt.management_allowed) return { matches: false, reason: 'Management permission was not observed.' };
  return { matches: true, reason: 'Exact requested fence and permission result observed.' };
}
