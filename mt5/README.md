# MetaTrader 5 Bridge (`Hugo's Way` + `LHFX`)

MetaTrader **5** (`MT5`) is the required terminal platform for CAS Forex Revamp:

| Priority | Broker ID | Broker | Platform | Demo Server | Live Server | Max Leverage |
| :-: | :--- | :--- | :--- | :--- | :--- | :---: |
| 1 (Main) | `HUGOSWAY_MT5` | Hugo's Way | MetaTrader 5 | `Hugo demo PRO5` | `Hugo PRO5` | 1:500 |
| 2 | `LHFX_MT5` | LHFX | MetaTrader 5 | `LHFXSA-Demo` | `LHFXSA-Live` | 1:500 |

Regulated `OANDA` (`OANDA_PRACTICE` in DEMO / `OANDA_LIVE` in LIVE, 1:50 max) acts as the 80% Barbell safety reserve, quote-truth shield, safe-harbor fallback, and freeze offset venue.

## Two Execution Modes (Strict Isolation)

1. **`DEMO` Mode (Default)**:
   - Leave `CAS_FOREX_EXECUTION_MODE=DEMO` (or unset) and `InpLiveExecutionMode=false`.
   - Refuses real-money servers and `ACCOUNT_TRADE_MODE_REAL`.
2. **`LIVE` Real-Money Mode (Explicit Two-Key Arming)**:
   - Requires BOTH `CAS_FOREX_EXECUTION_MODE=LIVE` AND `CAS_FOREX_LIVE_ARM_PHRASE=I_AUTHORIZE_LIVE_REAL_MONEY_TRADING`.
   - In `CasForexMt5Bridge.mq5`, set `InpLiveExecutionMode=true` AND `InpLiveArmPhrase="I_AUTHORIZE_LIVE_REAL_MONEY_TRADING"`.
   - Refuses demo servers and `ACCOUNT_TRADE_MODE_DEMO`.

## Quick Setup (Spool Bridge or Windows Native Python)

1. Log in to your MT5 terminal(s) on `Hugo demo PRO5` / `LHFXSA-Demo` (Demo) or `Hugo PRO5` / `LHFXSA-Live` (Live).
2. Copy `mt5/CasForexMt5Bridge.mq5` to `MQL5/Experts/CasForexMt5Bridge.mq5`, compile (`F7`), enable **Algo Trading**, and attach with `InpBrokerChannel=hugosway_mt5` or `lhfx_mt5`.
3. Alternatively on Windows with the official `MetaTrader5` Python package installed, set `CAS_FOREX_MT5_TRANSPORT_MODE=NATIVE_PYTHON` (or `AUTO`).
