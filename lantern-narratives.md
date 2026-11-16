## 01 Operate Cockpit & 16-Pair Live Candlestick Stream

The browser cockpit (`ui/index.html`, `ui/src/app.mjs`, `ui/src/render.mjs`, `ui/src/chart.mjs`) renders under a strict `default-src 'none'` Content Security Policy with safe DOM parsing (`DOMParser` + `replaceChildren`), displaying all 16 G10 currency pairs with exact fixed-point decimal strings and zero executable model authority.

## ForexMetaValveGate Safety Controller

Every proposed FX command from the model layer is intercepted by `ForexMetaValveGate` (`src/cas_forex_revamp/valve/`), which rejects missing margin, paused risk states, oversized quantities, missing or inverted stops, and out-of-policy overrides before reaching paper execution.

## ExternalPaperBrokerVenue & Multi-Source Quote Pinning

Live spot quotes and candles (`src/cas_forex_revamp/venue/external_paper_broker.py`, `src/cas_forex_revamp/venue/live_market_stream.py`) are pulled exclusively over HTTPS TLS 1.2+ from pinned public endpoints, cross-checked against ECB/Frankfurter reference rates using entity-free XML parsing, and sealed into hash-chained SQLite audit journals.

## Air-Gapped Stage B Linux Custody Ceremony

During AWS EC2 validation (`ceremony_generator.py`, `external_stageb_ceremony_observer.py`, `approved_stageb_ceremony_driver.py`), worker processes run confined under Landlock (`role_boundary.py`), non-root service accounts (`source_runtime/`), zero egress after bootstrap, and Ed25519 custody signatures verified with `cryptography==50.0.2`.

## Continuous AI-Agent PR Verifier & Merger

Automated maintenance (`scripts/agent_pr_merger.py`) checks repository pull requests for leaked secrets, inline style violations, JSON contract validity, and syntax hygiene, squash-merging verified branches into `main` until `docs/REVAMP_COMPLETION_GATE.json` marks `revamp_completed: true`.

## MetaTrader 5 Hugo's Way + LHFX Dual-Shield Broker Bridge

Phase 6 adds a demo-only MetaTrader 5 bridge (`src/cas_forex_revamp/venue/mt5_broker_bridge.py`, `mt5/CasForexMt5Bridge.mq5`) with Hugo's Way (`Hugo demo PRO5`, 1:500) as the primary venue, LHFX (`LHFXSA-Demo`, 1:500) as the secondary venue, and the existing OANDA practice client as the regulated safe harbor. Live servers (`Hugo PRO5`, `LHFXSA-Live`, any `live`/`real` server, `api-fxtrade.oanda.com`) and non-DEMO accounts are refused in code; credentials are read only from runtime environment mappings and wrapped in `_RedactedSecret`; the file spool uses atomic renames, a `0o700` directory verified through `os.lstat` + `stat.S_ISDIR`, SHA-256 bound requests, and hash-chained receipts. The dual-shield layer (`src/cas_forex_revamp/venue/dual_shield_router.py`) cross-checks every offshore quote against OANDA's regulated reference (`OandaQuoteTruthOracle`), enforces an 80% OANDA reserve / 12% Hugo's Way / 8% LHFX barbell with a 1% stop-loss equity-risk cap (`BarbellCapitalPolicy`), degrades to the OANDA safe harbor when an offshore venue fails a check, and plans delta-neutral OANDA offsets if an MT5 terminal freezes (`OandaProtectiveOffsetPlanner`). Every order still requires a matching admitted `ForexMetaValveGate` decision, so 1:500 leverage never bypasses the Valve; the cockpit shows the routing read-only through loopback `GET /api/broker-routing`.

## Phase 6 Security Hardening (9-Finding Remediation)

Remediation across `ceremony_generator.py`, `external_stageb_ceremony_observer.py`, `authority_component/ceremony_release_gate.py`, `approved_stageb_ceremony_driver.py`, `source_runtime/source_test_launcher.py`, `operational/measurement/`, `src/cas_forex_revamp/`, and `ui/src/` enforces out-of-band random Ed25519 role keys and pinned trust roots, symlink-refusing `O_NOFOLLOW` staging, durable SQLite peak-equity drawdown gating (`PeakEquityStore` + `ForexMetaValveGate` `max_drawdown_pct=0.10`), atomic venue source-cursor equality (`STALE_SOURCE_CURSOR`), exact pinned HTTPS public-feed allowlists with `NoRedirectHandler` and fail-closed ECB reference deviation bounds, independent signed semantic reviews, verified `systemd-run` cgroup memory/CPU/task ceilings, and per-launch constant-time bearer/cookie authentication with exact loopback `Host`/`Origin` checks on `LoopbackCockpitServer`.
