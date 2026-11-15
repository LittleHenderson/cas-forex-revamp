# Security Policy

## Defense-in-Depth Guardrails

- **Practice / Paper Trading Only**: `src/cas_forex_revamp/venue/external_paper_broker.py` and `src/cas_forex_revamp/venue/live_market_stream.py` enforce an explicit TLS 1.2+ pinned-host allowlist and strictly reject any live trading endpoint (`api-fxtrade`, `stream-fxtrade`, or URL-embedded credentials).
- **Fail-Closed Safety Valve (`ForexMetaValveGate`)**: Model trade proposals never execute directly; every proposal passes deterministic risk, spread, drawdown, protective-stop, and valve-probability gates before admission.
- **Linux Role Confinement**: `role_boundary.py` and `source_runtime/` enforce Landlock filesystem rules, non-root UIDs, zero Linux capabilities, and loopback-only namespaces inside Stage B AWS workers.
- **Strict Content Security Policy**: `ui/index.html` enforces `default-src 'none'; script-src 'self'; style-src 'self'; object-src 'none'` with zero inline HTML injection vectors.

## Reporting a Vulnerability

Do not open a public issue with sensitive reproduction details, credentials, or private keys. Rotate any affected token immediately and report security issues confidentially through repository maintainer channels (`LittleHenderson/cas-forex-revamp`).
