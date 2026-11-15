# CAS personal cockpit

Source status: AUTHORED. Runtime, browser, accessibility and visual verification: NOT_RUN.

The interface is a dependency-free ES-module application with Operate, Review and Setup. It starts with the real steward-owned disconnected cockpit fixture. No third-party UI framework, package install, lockfile, build server or model client is required by this source slice.

The only entry point is `ui/index.html`. `src/app.mjs` runs when that document is explicitly opened. Pure reader/model/render modules do not boot a UI. The browser entry point reads four fixed same-origin static assets, with credentials omitted and redirects rejected:

- `docs/contracts/cockpit.schema.json`
- `docs/contracts/initial-cockpit.json`
- `docs/contracts/decision-read.schema.json`
- `docs/contracts/initial-decision-read.json`

The default path has no POST or control endpoint. There is no broker API, arbitrary URL input, external font, worker, saved grant, old runtime import or inference client. Only explicit trusted bootstrap may attach the scoped bridge documented in `docs/ui/TRANSPORT.md`. The only recurring UI task updates displayed read age; it does not fetch observations or change source times. Attached freshness compares the observation with the independently read simulator clock. Local monotonic elapsed time invalidates the held display after 30 seconds, without advancing simulation; hidden/restored tabs also require an explicit new read. Interruption stays reachable. Imported snapshots remain visibly unbound. Fixtures are not observations from a running service.

## Owner-selected modernist design - 2026-11-05

The owner-supplied CAS Harness design canvases now guide the Forex presentation. `modernist.css` overrides the preserved earlier stylesheet with an off-white, charcoal and vermilion palette, square ruled grids, a horizontal masthead and vertical status marks. Operate, Review and Setup retain their source data and control boundaries. `explainer.css` styles the optional local guide.

Review adds All, Decisions, Events / core and Evidence filters with actual supplied-record counts. Both List and Atlas use the same filtered collection. Filtering never changes coverage or the retained source. Decision payloads and DECISION-kind event records are separated by their stable record-ID namespaces.

The Explainer can be dragged, docked, collapsed, restored and moved using the keyboard. It shows authored guidance and the supplied JSON record. It has no AI provider, model call, execution capability or trading authority. Its disabled model input states that limitation. Only `{edge, frac, collapsed}` is saved under `cas.forex.explainer.layout.v1` in browser local storage; account data, records, credentials and permissions are not saved there. Storage failure is nonfatal. Theme remains in the current tab.

The local font stack names Archivo and IBM Plex Mono, with local fallbacks. Those reference fonts were not installed or bundled, and the existing CSP was retained. Exact typography and visual fidelity are therefore not established. The written Explainer interaction specification takes precedence over conflicting prototype constants. See `docs/ui/MODERNIST_REDESIGN_2026-11-05.md` for the mapping, deviations and required verification.

## Inspecting after execution approval

Use the approved execution target and an explicit static-asset preview route that preserves the relative `ui/` and `docs/contracts/` paths. Serve only the needed static files. No server has been started or supplied by this lane. Do not expose the whole workspace. An HTTP(S) origin is required for module/static reads; Review hash inspection also requires browser Web Crypto support in an appropriate context. File-URL opening reports the unavailable route instead of substituting data.

Use `ui/index.html#operate`, `#review`, or `#setup`. Unknown hashes fall back to Operate. Query parameters cannot set account scope, restore authority, choose a backend or submit actions. Historical route aliases are not guessed.

On Setup, a local exported cockpit JSON may be loaded after the shared schema. A decision-read file must match that cockpit's exact account/run/epoch/build/policy/scenario/adapter and state. File and fixture loads are disabled while a bridge is attached. Cockpit loads clear dependent Review data and inspection. Latest-request guards reject delayed reads. Failed loads show unavailable data; the last valid snapshot can be explicitly reopened as historical inspection.

Review defaults to List. The optional Atlas uses exactly the same records and inspector. Candidates keep evaluation, eligibility and disposition separate. All supplied source content is inspectable. The first Atlas is a grouped record layout, not a native RPA graph or typed hypothetical-transition implementation. Above 64 visible records, Atlas reports incomplete and offers the complete List; it never silently cuts records. No U0 or U1 benefit is claimed.

## Controls and trust

Pause and Stop are distinct direct controls, unavailable by default. With an explicitly attached scoped bridge they prepare and send the exact request on the click, then independently read its fence. Optional About dialogs are never prerequisites. Reviewed Close first prepares and shows the exact target/version/BASE_UNITS, intent digest and expiry; only a separate review click submits it. Independent command reads expose cumulative actual quantities. Modal interruption controls use the same bridge capabilities. Acceptance never establishes an effect, and unknown outcomes are never automatically resubmitted.

The UI distinguishes reported core command state, reservation and receipt references. A referenced receipt is not an independently read fill. Unknown money and inventory remain Unknown; an empty observed array means only no positions in that snapshot. P/L lacks period/cost/cashflow coverage in current contracts and says so. A/B validation stays NOT_RUN.

Read JSON must pass the shared schema and display-boundary semantic checks. Decimal strings are never converted to floating-point amounts. Timestamp ordering preserves microseconds. Decision-read canonical bytes are checked against the supplied digest using Web Crypto. This proves self-consistency only. Imported files have no external source trust, even if a packet labels itself PASS. Explicit bridge reads may match the pinned schema and scope/domain/cursor anchor; the optional `resolveEvidence` extension additionally checks each exact non-null catalog reference, producer/read identity and canonical payload hash. Array payloads such as independent venue history are retained intact. Missing extensions, absent references and individual failures stay explicit. MATCHED_REFERENCES concerns supplied references only; semantic verification remains NOT_ESTABLISHED and does not establish current state, inference or fulfilled effects. Supplied URLs, paths, HTML and adapter names are inert text.

## Tests, authored but NOT_RUN

The Node standard-library suite lives at `tests/ui/`. On the approved target only, from this `ui/` directory:

```text
npm test
```

That command runs tests; it was not run during this source-preparation task. No `npm install` is needed. Node 22+ is the authored test target; no installed runtime compatibility claim is made. Browser/visual/keyboard/phone verification remains separate; see `docs/ui/ACCEPTANCE.md`.

The consumer intentionally supports only the JSON Schema keywords currently published by the steward. New unsupported keywords fail closed and require a reviewed consumer update. It is not a general JSON Schema implementation or an execution authorization boundary.
