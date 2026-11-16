// Broker & MetaTrader 5 routing summary for the 03 Setup page.
// Pure data helpers: no DOM, no network, no storage. Every field is normalized to a
// whitelisted string/boolean shape before rendering, and the renderer escapes all text.

export const MAX_BROKER_ROUTING_BYTES = 65536;
const BROKER_IDS = Object.freeze(['HUGOSWAY_MT5', 'LHFX_MT5', 'OANDA_PRACTICE']);
const STATUS_WORDS = Object.freeze(['ACTIVE', 'STANDBY', 'NOT_CONFIGURED', 'FAILED', 'DISCONNECTED', 'FROZEN', 'LIVE_FORBIDDEN', 'NOT_CONNECTED']);

const str = (value, fallback = 'Unknown') => (typeof value === 'string' && value.length > 0 && value.length <= 200 ? value : fallback);

export const STATIC_BROKER_ROUTING = Object.freeze({
  connected: false,
  platform: 'MetaTrader 5',
  demoOnly: true,
  liveLocked: true,
  architecture: 'DUAL_SHIELD_BARBELL',
  primaryBroker: 'HUGOSWAY_MT5',
  activeBroker: 'None',
  transportMode: 'AUTO',
  valve: Object.freeze({ controller: 'tks_meta_valve_controller', parameters: '161', threshold: '0.55' }),
  chain: Object.freeze([
    Object.freeze({ brokerId: 'HUGOSWAY_MT5', priority: '1', role: 'PRIMARY_MAIN', label: "Hugo's Way", platform: 'MetaTrader 5', server: 'Hugo demo PRO5', leverage: '1:500', accountType: 'ECN demo', configured: false, status: 'NOT_CONNECTED' }),
    Object.freeze({ brokerId: 'LHFX_MT5', priority: '2', role: 'SECONDARY_MT5', label: 'LHFX', platform: 'MetaTrader 5', server: 'LHFXSA-Demo', leverage: '1:500', accountType: 'STP/ECN demo', configured: false, status: 'NOT_CONNECTED' }),
    Object.freeze({ brokerId: 'OANDA_PRACTICE', priority: '3', role: 'TERTIARY_REST_FALLBACK', label: 'OANDA', platform: 'OANDA v20 REST', server: 'https://api-fxpractice.oanda.com/v3', leverage: '1:50', accountType: 'fxPractice', configured: false, status: 'NOT_CONNECTED' }),
  ]),
  shield: Object.freeze({
    reference: 'OANDA_PRACTICE', majorBps: '15', crossBps: '25', spreadMultiple: '3.0',
    reserveShare: '0.80', hugoswayShare: '0.12', lhfxShare: '0.08', maxStopRiskPct: '1.00',
    safeHarbor: 'OANDA_PRACTICE', safeHarborLeverage: '1:50', degradations: '0', offsetPlanner: true,
  }),
});

function normalizeChainItem(item) {
  if (!item || typeof item !== 'object' || Array.isArray(item)) throw new Error('Broker routing chain entries must be objects.');
  if (!BROKER_IDS.includes(item.broker_id)) throw new Error('Unknown broker in routing chain.');
  if (!Number.isSafeInteger(item.priority) || item.priority < 1 || item.priority > 3) throw new Error('Broker priority must be 1..3.');
  if (typeof item.max_leverage !== 'string' || !/^1:[0-9]{1,4}$/.test(item.max_leverage)) throw new Error('Broker leverage must look like 1:500.');
  if (typeof item.configured !== 'boolean') throw new Error('Broker configured flag must be boolean.');
  const status = STATUS_WORDS.includes(item.status) ? item.status : 'NOT_CONNECTED';
  return Object.freeze({
    brokerId: item.broker_id, priority: String(item.priority), role: str(item.role), label: str(item.label),
    platform: str(item.platform), server: str(item.server, 'Not set'), leverage: item.max_leverage,
    accountType: str(item.account_type), configured: item.configured, status,
  });
}

function normalizeShield(doc) {
  const shield = doc.dual_shield;
  if (!shield || typeof shield !== 'object') return STATIC_BROKER_ROUTING.shield;
  const oracle = shield.quote_truth_oracle ?? {};
  const barbell = shield.barbell ?? {};
  const harbor = shield.safe_harbor ?? {};
  const degradations = Array.isArray(harbor.recent_degradations) ? harbor.recent_degradations.length : 0;
  return Object.freeze({
    reference: str(oracle.reference_source), majorBps: str(oracle.max_divergence_bps_major), crossBps: str(oracle.max_divergence_bps_cross),
    spreadMultiple: str(oracle.max_oanda_spread_multiple), reserveShare: str(barbell.oanda_reserve_share), hugoswayShare: str(barbell.hugosway_share),
    lhfxShare: str(barbell.lhfx_share), maxStopRiskPct: str(barbell.max_stop_loss_equity_risk_pct), safeHarbor: str(harbor.broker_id),
    safeHarborLeverage: str(harbor.leverage), degradations: String(degradations), offsetPlanner: Boolean(shield.offset_planner),
  });
}

/** Validate a parsed /api/broker-routing document into a frozen, display-only shape. */
export function normalizeBrokerRouting(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('Broker routing must be a JSON object.');
  if (typeof doc.schema !== 'string' || !doc.schema.startsWith('cas-forex.broker-routing/')) throw new Error('Unexpected broker routing schema.');
  if (doc.demo_only !== true || doc.live_trading_locked !== true) throw new Error('Broker routing must be demo-only with live trading locked.');
  if (!Array.isArray(doc.chain) || doc.chain.length < 1 || doc.chain.length > 3) throw new Error('Broker routing chain must list 1..3 brokers.');
  const valve = doc.valve ?? {};
  return Object.freeze({
    connected: true,
    platform: str(doc.platform),
    demoOnly: true,
    liveLocked: true,
    architecture: str(doc.architecture, 'PRIORITY_FAILOVER'),
    primaryBroker: BROKER_IDS.includes(doc.primary_broker) ? doc.primary_broker : 'Unknown',
    activeBroker: BROKER_IDS.includes(doc.active_broker) ? doc.active_broker : 'None',
    transportMode: str(doc.transport_mode),
    valve: Object.freeze({ controller: str(valve.controller), parameters: Number.isSafeInteger(valve.parameters) ? String(valve.parameters) : 'Unknown', threshold: str(valve.threshold) }),
    chain: Object.freeze(doc.chain.map(normalizeChainItem)),
    shield: normalizeShield(doc),
  });
}
