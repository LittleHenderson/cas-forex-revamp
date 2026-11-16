# Security Policy

## Defense-in-Depth Guardrails

- **Practice / Paper Trading Only**: `src/cas_forex_revamp/venue/external_paper_broker.py`, `src/cas_forex_revamp/venue/live_market_stream.py`, and `src/cas_forex_revamp/venue/mt5_broker_bridge.py` enforce an explicit TLS 1.2+ pinned-host/path allowlist (`NoRedirectHandler`, global-unicast IP checks, fail-closed ECB reference age/deviation bounds) and strictly reject any live trading endpoint (`api-fxtrade`, `stream-fxtrade`, `Hugo PRO5`, `LHFXSA-Live`, or URL-embedded credentials).
- **Fail-Closed Safety Valve & High-Water Drawdown Gate (`ForexMetaValveGate` & `PeakEquityStore`)**: Model trade proposals never execute directly; every proposal passes deterministic risk, spread, durable peak-equity drawdown (`max_drawdown_pct`, default `10%`, requiring authenticated owner recovery to re-arm), atomic venue cursor equality (`STALE_SOURCE_CURSOR`), protective-stop, and `161`-parameter valve-probability gates before admission.
- **Out-of-Band Stage B Custody & Linux Role Confinement**: `ceremony_generator.py`, `external_stageb_ceremony_observer.py`, `role_boundary.py`, and `source_runtime/` enforce out-of-band `os.urandom(32)` Ed25519 role keys, pinned external trust roots, independent full-object signed semantic reviews, symlink-refusing `O_NOFOLLOW` regular-file staging, Landlock filesystem rules, non-root UIDs, zero Linux capabilities, loopback-only namespaces, and verified cgroup memory/CPU/task ceilings (`MemoryMax`, `MemorySwapMax=0`, `CPUQuota`, `TasksMax`, `OOMPolicy=kill`).
- **Authenticated Loopback Cockpit & Strict Content Security Policy**: `LoopbackCockpitServer` enforces exact literal loopback `Host`/`Origin` checks before body reads and per-launch constant-time `hmac.compare_digest` bearer/cookie authentication with session-epoch rotation across all `/api/*` routes; `ui/index.html` enforces `default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'` with zero inline HTML or style injection vectors.

## Reporting a Vulnerability

Do not open a public issue with sensitive reproduction details, credentials, or private keys. Rotate any affected token immediately and report security issues confidentially through repository maintainer channels (`LittleHenderson/cas-forex-revamp`).
