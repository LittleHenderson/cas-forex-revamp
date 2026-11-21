# CAS Forex Revamp

Deterministic Spot-FX execution engine, **ForexMetaValveGate** safety boundary, **Stage B** cryptographic custody ceremony, and strict-CSP **01 Operate** multi-currency live candlestick cockpit.

## Architecture Highlights

- **Core & Contracts (`src/cas_forex_revamp/contracts`, `core`)**: Canonical JSON serialization, exact fixed-point integer/decimal pricing (zero binary float drift), and append-only SQLite evidence journals.
- **Safety Gate (`ForexMetaValveGate`, Phase 3)**: Fail-closed safety valve between model proposals and execution admission; enforces bounded risk, drawdown fences, and independent barrier verification.
- **External Paper Broker & Stage B Custody (Phase 5)**: Sealed live FX venue ingestion with SHA-256 wire receipts, ECB/Frankfurter cross-checks, and Ed25519 Stage B custody ceremonies (`cryptography==50.0.2`).
- **16-Pair Live Market Stream & Candlestick Cockpit (Phase 6)**:
  - Expands spot-FX coverage across 16 major and cross currency pairs (`EUR/USD`, `GBP/USD`, `USD/JPY`, `USD/CHF`, `AUD/USD`, `USD/CAD`, `NZD/USD`, `EUR/GBP`, `EUR/JPY`, `GBP/JPY`, `EUR/CHF`, `EUR/AUD`, `EUR/CAD`, `AUD/JPY`, `CHF/JPY`, `CAD/JPY`).
  - Zero-dependency strict-CSP SVG candlestick + volume + 14-EMA + live Bid/Ask + Entry/Protective Stop + `ForexMetaValveGate` status chart (`ui/src/chart.mjs`) wired into `01 Operate` with `Single` and `4x Quad` views.
- **Continuous AI-Agent PR Auto-Merger (`scripts/agent_pr_merger.py`; documented template `docs/github-workflows/agent-pr-automerge.yml`, not active `.github/workflows/...`)**:
  - Runs on `*/15 * * * *` / CI completion to verify and `--match-head-commit` squash-merge passing non-draft PRs only after enforcing immutable GitHub user/App IDs, exact `headRepository.nameWithOwner` matching, SHA-bound owner `APPROVED` review/event verification (labels are intent-only), and provenance-verified paginated checks (`15368` + trusted workflow paths/IDs) until `docs/REVAMP_COMPLETION_GATE.json` marks `revamp_completed: true`.

## Verification Suites

```bash
# UI strict-CSP & contract tests (Node >= 20)
node --test tests/ui/*.test.mjs

# Python deterministic unit & contract suites (Python >= 3.11, cryptography==50.0.2)
PYTHONPATH=".:src:shared-interface:authority_component/provider_source04:operational/authority/source:operational/measurement/source:operational/custody/source:operational/policy-inheritance02/source" \
  python -m unittest discover -s tests/contracts -p "test_*.py"
```
