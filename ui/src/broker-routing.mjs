// Broker & MetaTrader 5 routing summary for 01 Operate and 03 Setup.
// Pure data helpers: no DOM, no network, no storage. Every field is normalized to a
// whitelisted string/boolean shape before rendering, and the renderer escapes all text.

export const MAX_BROKER_ROUTING_BYTES = 65536;
const BROKER_IDS = Object.freeze(['HUGOSWAY_MT5', 'LHFX_MT5', 'OANDA_PRACTICE', 'OANDA_LIVE']);
const STATUS_WORDS = Object.freeze(['ACTIVE', 'STANDBY', 'NOT_CONFIGURED', 'FAILED', 'DISCONNECTED', 'BROKER_OFFLINE', 'FROZEN', 'LIVE_FORBIDDEN', 'NOT_CONNECTED']);

const str = (value, fallback = 'Unknown', maxLen = 200) => (
  typeof value === 'string' && value.length > 0 && value.length <= maxLen ? value : fallback
);
const strSlice = (value, fallback = 'Unknown', maxLen = 400) => (
  typeof value === 'string' && value.trim().length > 0 ? value.trim().slice(0, maxLen) : fallback
);

export const STATIC_LIVE_READINESS = Object.freeze({
  executionMode: 'DEMO',
  liveArmed: false,
  requiredArmPhrase: 'ARM_LIVE_REAL_MONEY_TRADING',
  allGatesReady: false,
  gates: Object.freeze([
    Object.freeze({
      id: 'LIVE_CREDENTIALS_STAGED',
      step: 1,
      title: 'Real-Money Broker Credentials Staged',
      passed: false,
      detail: "Stage OANDA Live v20 credentials plus Hugo's Way (Hugosway-Real3) and LHFX (LHFXSA-Live) logins on cloud host.",
    }),
    Object.freeze({
      id: 'OWNER_ED25519_LIVE_TICKETS',
      step: 2,
      title: 'Owner Ed25519 Live Venue Authorization Tickets',
      passed: false,
      detail: 'Requires signed CAS_FOREX_HUGOSWAY_MT5_LIVE_TICKET, CAS_FOREX_LHFX_MT5_LIVE_TICKET, and CAS_FOREX_OANDA_LIVE_TICKET.',
    }),
    Object.freeze({
      id: 'REAL_BARBELL_80_12_8_CUSTODY',
      step: 3,
      title: 'Real 80% / 12% / 8% Barbell Custody Allocation',
      passed: false,
      detail: "Disable demo virtual sleeve and verify OANDA (80%), Hugo's Way (12%), and LHFX (8%) live balances within ±2% tolerance.",
    }),
    Object.freeze({
      id: 'VALVE_AND_DURABLE_JOURNALS',
      step: 4,
      title: '161-Param ForexMetaValveGate & Durable SQLite Journals',
      passed: false,
      detail: 'Requires active tks_meta_valve_controller (threshold 0.55) and durable SQLite mutation journals on MT5 and OANDA.',
    }),
    Object.freeze({
      id: 'TWO_KEY_LIVE_ARMED',
      step: 5,
      title: 'Two-Key Real-Money Execution Mode Armed',
      passed: false,
      detail: 'Requires CAS_FOREX_EXECUTION_MODE=LIVE plus Key 2 confirmation phrase ARM_LIVE_REAL_MONEY_TRADING.',
    }),
  ]),
});

export const STATIC_BROKER_ROUTING = Object.freeze({
  connected: false,
  platform: 'MetaTrader 5',
  executionMode: 'DEMO',
  demoOnly: true,
  liveLocked: true,
  liveArmed: false,
  architecture: 'DUAL_SHIELD_BARBELL',
  primaryBroker: 'HUGOSWAY_MT5',
  activeBroker: 'None',
  transportMode: 'AUTO',
  valve: Object.freeze({ controller: 'tks_meta_valve_controller', parameters: '161', threshold: '0.55' }),
  chain: Object.freeze([
    Object.freeze({ brokerId: 'HUGOSWAY_MT5', priority: '1', role: 'PRIMARY_MAIN', label: "Hugo's Way", platform: 'MetaTrader 5', server: 'Hugosway-Demo', leverage: '1:500', accountType: 'ECN demo', configured: false, status: 'NOT_CONNECTED' }),
    Object.freeze({ brokerId: 'LHFX_MT5', priority: '2', role: 'SECONDARY_MT5', label: 'LHFX', platform: 'MetaTrader 5', server: 'LHFXSA-Trade', leverage: '1:500', accountType: 'STP/ECN demo', configured: false, status: 'NOT_CONNECTED' }),
    Object.freeze({ brokerId: 'OANDA_PRACTICE', priority: '3', role: 'TERTIARY_REST_FALLBACK', label: 'OANDA', platform: 'OANDA v20 REST', server: 'https://api-fxpractice.oanda.com/v3', leverage: '1:50', accountType: 'fxPractice', configured: false, status: 'NOT_CONNECTED' }),
  ]),
  shield: Object.freeze({
    reference: 'OANDA_PRACTICE', majorBps: '15', crossBps: '25', spreadMultiple: '3.0',
    reserveShare: '0.80', hugoswayShare: '0.12', lhfxShare: '0.08', maxStopRiskPct: '1.00',
    safeHarbor: 'OANDA_PRACTICE', safeHarborLeverage: '1:50', degradations: '0', offsetPlanner: true, totalEquity: null,
    offlineBrokers: Object.freeze([]), onlineEquity: null, equityIncomplete: false,
  }),
  liveReadiness: STATIC_LIVE_READINESS,
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
  const rawEq = shield.allocation?.total_equity;
  const totalEquity = typeof rawEq === 'string' && /^-?[0-9]+(\.[0-9]+)?$/.test(rawEq) ? rawEq : null;
  const rawOnlineEq = shield.allocation?.online_equity;
  const onlineEquity = typeof rawOnlineEq === 'string' && /^-?[0-9]+(\.[0-9]+)?$/.test(rawOnlineEq) ? rawOnlineEq : totalEquity;
  const offlineBrokers = Object.freeze(
    Array.isArray(shield.allocation?.offline_brokers)
      ? shield.allocation.offline_brokers.filter((b) => typeof b === 'string' && BROKER_IDS.includes(b))
      : [],
  );
  const equityIncomplete = typeof shield.allocation?.equity_incomplete === 'boolean'
    ? shield.allocation.equity_incomplete
    : offlineBrokers.length > 0;
  return Object.freeze({
    reference: str(oracle.reference_source), majorBps: str(oracle.max_divergence_bps_major), crossBps: str(oracle.max_divergence_bps_cross),
    spreadMultiple: str(oracle.max_oanda_spread_multiple), reserveShare: str(barbell.oanda_reserve_share), hugoswayShare: str(barbell.hugosway_share),
    lhfxShare: str(barbell.lhfx_share), maxStopRiskPct: str(barbell.max_stop_loss_equity_risk_pct), safeHarbor: str(harbor.broker_id),
    safeHarborLeverage: str(harbor.leverage), degradations: String(degradations), offsetPlanner: Boolean(shield.offset_planner),
    totalEquity, offlineBrokers, onlineEquity, equityIncomplete,
  });
}

function normalizeLiveReadiness(doc, isLive) {
  const lr = doc.live_readiness;
  if (!lr || typeof lr !== 'object' || Array.isArray(lr)) return STATIC_LIVE_READINESS;
  const rawGates = Array.isArray(lr.gates) && lr.gates.length > 0 ? lr.gates.slice(0, 10) : STATIC_LIVE_READINESS.gates;
  const gates = rawGates.map((g, idx) => {
    const fallbackGate = STATIC_LIVE_READINESS.gates[idx] ?? {
      id: `GATE_${idx + 1}`,
      step: idx + 1,
      title: `Gate ${idx + 1}`,
      detail: 'Pending readiness verification.',
    };
    return Object.freeze({
      id: strSlice(g?.id, fallbackGate.id, 80),
      step: Number.isSafeInteger(g?.step) && g.step >= 1 && g.step <= 20 ? g.step : fallbackGate.step,
      title: strSlice(g?.title, fallbackGate.title, 200),
      passed: Boolean(g?.passed),
      detail: strSlice(g?.detail, fallbackGate.detail, 400),
    });
  });
  const allGatesReady = typeof lr.all_gates_ready === 'boolean'
    ? lr.all_gates_ready
    : (gates.length >= 5 && gates.every((g) => g.passed));
  return Object.freeze({
    executionMode: lr.execution_mode === 'LIVE' ? 'LIVE' : (isLive ? 'LIVE' : 'DEMO'),
    liveArmed: typeof lr.live_armed === 'boolean' ? lr.live_armed : isLive,
    requiredArmPhrase: strSlice(lr.required_arm_phrase, 'ARM_LIVE_REAL_MONEY_TRADING', 80),
    allGatesReady,
    gates: Object.freeze(gates),
  });
}

/** Validate a parsed /api/broker-routing document into a frozen, display-only shape. */
export function normalizeBrokerRouting(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new Error('Broker routing must be a JSON object.');
  if (typeof doc.schema !== 'string' || !doc.schema.startsWith('cas-forex.broker-routing/')) throw new Error('Unexpected broker routing schema.');
  const mode = doc.execution_mode ?? (doc.demo_only === true ? 'DEMO' : 'INVALID');
  const isDemo = mode === 'DEMO' && doc.demo_only === true && doc.live_trading_locked === true && doc.live_trading_armed !== true;
  const isLive = mode === 'LIVE' && doc.execution_mode === 'LIVE' && doc.live_trading_armed === true && doc.demo_only === false && doc.live_trading_locked === false;
  if (!isDemo && !isLive) throw new Error('Broker routing mode and lock flags are inconsistent or unauthorized.');
  if (!Array.isArray(doc.chain) || doc.chain.length < 1 || doc.chain.length > 3) throw new Error('Broker routing chain must list 1..3 brokers.');
  const valve = doc.valve ?? {};
  return Object.freeze({
    connected: true,
    platform: str(doc.platform),
    executionMode: isLive ? 'LIVE' : 'DEMO',
    demoOnly: isDemo,
    liveLocked: isDemo,
    liveArmed: isLive,
    architecture: str(doc.architecture, 'PRIORITY_FAILOVER'),
    primaryBroker: BROKER_IDS.includes(doc.primary_broker) ? doc.primary_broker : 'Unknown',
    activeBroker: BROKER_IDS.includes(doc.active_broker) ? doc.active_broker : 'None',
    transportMode: str(doc.transport_mode),
    valve: Object.freeze({ controller: str(valve.controller), parameters: Number.isSafeInteger(valve.parameters) ? String(valve.parameters) : 'Unknown', threshold: str(valve.threshold) }),
    chain: Object.freeze(doc.chain.map(normalizeChainItem)),
    shield: normalizeShield(doc),
    liveReadiness: normalizeLiveReadiness(doc, isLive),
  });
}
