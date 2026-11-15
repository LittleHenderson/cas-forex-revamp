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
