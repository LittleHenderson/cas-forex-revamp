# CAS Forex MetaTrader 5 Bridge (demo accounts only)

`CasForexMt5Bridge.mq5` is the MetaTrader 5 Expert Advisor side of the Phase 6 broker bridge
(`src/cas_forex_revamp/venue/mt5_broker_bridge.py`). It lets the Python
`Mt5SpoolBridgeTransport` drive a **demo** MetaTrader 5 terminal through plain JSON files, which
works on any operating system that can share a folder with the terminal (no DLLs, no sockets).

| Priority | Broker id        | Broker     | Platform        | Demo server                           | Max leverage |
|----------|------------------|------------|-----------------|---------------------------------------|--------------|
| 1        | `HUGOSWAY_MT5`   | Hugo's Way | MetaTrader 5    | `Hugo demo PRO5`                      | 1:500        |
| 2        | `LHFX_MT5`       | LHFX       | MetaTrader 5    | `LHFXSA-Demo`                         | 1:500        |
| 3        | `OANDA_PRACTICE` | OANDA      | OANDA v20 REST  | `https://api-fxpractice.oanda.com/v3` | 1:50         |

## Why MetaTrader 5 and not MetaTrader 4

- MetaQuotes publishes an official `MetaTrader5` Python package (`Mt5NativePythonTransport`);
  MetaTrader 4 has no official Python API.
- Both demo brokers (Hugo's Way and LHFX) run MetaTrader 5 servers, so one EA serves both.
- MetaTrader 5 has 21 chart timeframes (MetaTrader 4 has 9).
- MetaTrader 5 trade actions map one-to-one onto CAS intents: `TRADE_ACTION_DEAL` (OPEN),
  `TRADE_ACTION_SLTP` (AMEND_STOP), partial close by ticket (REDUCE) and close by ticket (CLOSE).

## Safety rules built into the EA

1. `OnInit` and every `OnTimer` cycle check `ACCOUNT_TRADE_MODE == ACCOUNT_TRADE_MODE_DEMO` **and**
   that the server name contains `demo` and does not contain `live` or `real`. Otherwise the EA
   refuses to start (or removes itself). Live servers such as `Hugo PRO5` or `LHFXSA-Live` are refused.
2. Every request carries `request_sha256`; the EA recomputes SHA-256 over the canonical request and
   rejects any mismatch.
3. Each request is claimed by renaming it to `processing_<id>.json` **before** execution. After a
   restart, a leftover claim produces an `UNKNOWN` receipt; the order is never executed twice.
4. OPEN requires a protective stop and is capped by `InpMaxVolumeLots`.
5. No password, token or login secret is ever written to the spool. The EA runs inside a terminal
   you have already logged into; Python only verifies the published login, server and DEMO mode.
6. Python still requires a ForexMetaValveGate (`tks_meta_valve_controller`, 161 parameters,
   threshold 0.55) decision before it writes any request, plus the dual-shield checks
   (OANDA quote truth, 80/12/8 barbell, 1% stop-loss risk cap).

## Spool protocol `cas-forex-mt5-spool/1`

Folder: `<Terminal>\Common\Files\cas_forex_spool\<channel>\` when `InpUseCommonFolder=true`
(default), otherwise `<Terminal data folder>\MQL5\Files\cas_forex_spool\<channel>\`.
`<channel>` is `hugosway_mt5` or `lhfx_mt5`.

| File                        | Direction   | Shape                                                                                   |
|-----------------------------|-------------|-----------------------------------------------------------------------------------------|
| `order_request_<id>.json`   | Python → EA | Flat JSON, every value a string: `action`, `symbol`, `side`, `volume`, `sl`, `position_ticket`, `request_sha256`, ... |
| `order_receipt_<id>.json`   | EA → Python | Flat JSON, every value a string: `status` (`FILLED`/`PARTIAL`/`MODIFIED`/`REJECTED`/`UNKNOWN`), `retcode`, tickets, `price` |
| `market_ticks.json`         | EA → Python | Account (`login`, `balance`, `equity`, `margin`, `margin_free`, `leverage`), 16-pair ticks, positions |

All numbers are written as decimal strings (never JSON floats) so Python can parse them exactly
with `Decimal`. Every file is written to a dot-prefixed `.tmp` name first and then moved into place.

## Setup (demo only)

1. Open a demo account: Hugo's Way (`Hugo demo PRO5`) and/or LHFX (`LHFXSA-Demo`).
2. Copy `CasForexMt5Bridge.mq5` into `<Terminal data folder>\MQL5\Experts\`, compile it in MetaEditor,
   enable Algo Trading, and attach it to any chart. Set `InpBrokerChannel` to `hugosway_mt5` for
   Hugo's Way or `lhfx_mt5` for LHFX. Set `InpSymbolSuffix` if your broker adds a suffix.
3. On the Python side set (in the process environment, never in a committed file):
   - `CAS_FOREX_MT5_TRANSPORT_MODE=SPOOL_BRIDGE`
   - `CAS_FOREX_MT5_SPOOL_DIR=<Terminal>\Common\Files\cas_forex_spool`
   - `CAS_FOREX_HUGOSWAY_MT5_LOGIN` / `CAS_FOREX_LHFX_MT5_LOGIN` (the demo login numbers)
4. Or, on Windows with the official package installed, use `CAS_FOREX_MT5_TRANSPORT_MODE=NATIVE_PYTHON`
   and also set the matching `*_PASSWORD` variables at runtime.

Offline tests use `Mt5SpoolPaperTerminalEmulator`, a Python twin of this EA that never connects anywhere.
