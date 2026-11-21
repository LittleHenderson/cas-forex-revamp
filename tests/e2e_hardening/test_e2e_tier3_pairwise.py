"""E2E Tier 3: Cross-Feature Pairwise Combination Tests (12 tests: E2E-T3-01 .. E2E-T3-12)."""
from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
import json
from pathlib import Path
import shutil
import subprocess  # nosec B404: invokes local node binary to validate /api/boot rendering without shell
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cas_forex_revamp.composition.autonomous_trader import AutonomousAiTrader
from cas_forex_revamp.composition.live_cockpit_server import LoopbackCockpitServer
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.composition.state_store import OwnerRecoveryVerifier
from cas_forex_revamp.composition.trend_regime import REGIME_STRONG_TREND
from cas_forex_revamp.contracts import ActionKind, Side
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.treasury import CoinbaseOfframpClient, ProfitSweepVault, RAIL_COINBASE_ACH
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore, QUOTA_STATUS_LOCKED
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    PeakEquityStore,
    ValveRefusalError,
    load_default_forex_valve_gate,
)
from cas_forex_revamp.venue.dual_shield_router import (
    DualShieldBrokerRouter,
    OandaQuoteTruthOracle,
    OffMarketBrokerQuoteError,
)
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    Mt5Credentials,
    Mt5OrderRequest,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5ValveClearanceError,
    OrderIntent,
    Mt5PaperBrokerVenue,
)

try:
    from tests.e2e_hardening._e2e_support import (
        D,
        DualBrokerTestRig,
        QUOTES_20,
        REPO_ROOT,
        SYNTH_API_KEY,
        SteppingClock,
        T0,
        build_scoped_ui_service,
        build_valve_proposal,
        clean_demo_environ,
        default_policy,
        default_view,
        is_integrated_mode,
        loopback_http_request,
        require_or_skip_unmerged,
        resolve_node_bin,
        safe_temp_dir,
        stub_frontier_http_post,
    )
except ImportError:  # pragma: no cover
    from _e2e_support import (
        D,
        DualBrokerTestRig,
        QUOTES_20,
        REPO_ROOT,
        SYNTH_API_KEY,
        SteppingClock,
        T0,
        build_scoped_ui_service,
        build_valve_proposal,
        clean_demo_environ,
        default_policy,
        default_view,
        is_integrated_mode,
        loopback_http_request,
        require_or_skip_unmerged,
        resolve_node_bin,
        safe_temp_dir,
        stub_frontier_http_post,
    )


def _ephemeral_ec_pem(path: Path) -> None:
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    if hasattr(Path, "chmod"):
        path.chmod(0o600)  # nosec B103: owner-only 0o600 test key


class Tier3PairwiseE2ETests(unittest.TestCase):
    def test_e2e_t3_01_parallel_tiers_plus_peak_equity_drawdown_refusal(self) -> None:
        with safe_temp_dir() as td:
            db_path = Path(td) / "tiers.sqlite3"
            gate = load_default_forex_valve_gate()
            eng = ParallelTierEngine(db_path, valve_gate=gate, clock=SteppingClock(T0))
            eng._peak_store.observe_equity("tier:TIER_1_CURRENT", current_equity=D("400000"), opening_balance=D("400000"), now=T0)
            try:
                snap = eng.process_tick(
                    quotes=QUOTES_20,
                    signal={
                        "symbol": "EURUSD",
                        "side": "BUY",
                        "stop_price": "1.09510",
                        "take_profit_price": "1.11000",
                        "regime": REGIME_STRONG_TREND,
                    },
                    now=T0 + timedelta(seconds=1),
                )
            except AttributeError as exc:
                if "refusal_reason" in str(exc):
                    require_or_skip_unmerged(
                        self,
                        "ParallelTierEngine valve refusal handling under drawdown (M1)",
                    )
                raise
            by_id = {r["tier_id"]: r for r in snap["tiers"]}
            self.assertEqual(by_id["TIER_1_CURRENT"]["open_positions"], 0)
            self.assertIn("VALVE_REFUSED", str(by_id["TIER_1_CURRENT"]["last_skip_reason"]))

    def test_e2e_t3_02_parallel_tiers_quota_locked_allows_winning_close_to_vault(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            eng = ParallelTierEngine(Path(td) / "tiers.sqlite3", valve_gate=gate, clock=SteppingClock(T0))
            eng.process_tick(
                quotes=QUOTES_20,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.10500",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            q1 = eng._quotas["TIER_1_CURRENT"]
            q1.observe_day_start(D("300000"), now=T0)
            locked = q1.record_realized_trade(D("8000"), symbol="EURUSD", ticket="pre-lock", starting_equity=D("300000"), now=T0)
            self.assertEqual(locked["status"], QUOTA_STATUS_LOCKED)

            win_q = dict(QUOTES_20)
            win_q["EURUSD"] = (D("1.10520"), D("1.10530"))
            after = eng.process_tick(quotes=win_q, signal=None, now=T0 + timedelta(seconds=10))
            by_id = {r["tier_id"]: r for r in after["tiers"]}
            self.assertEqual(by_id["TIER_1_CURRENT"]["open_positions"], 0)
            self.assertGreater(Decimal(by_id["TIER_1_CURRENT"]["bank_sweep_reserved_usd"]), Decimal("0"))

    def test_e2e_t3_03_parallel_tiers_close_feeds_vault_verify_audit_chain(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            eng = ParallelTierEngine(Path(td) / "tiers.sqlite3", valve_gate=gate, clock=SteppingClock(T0))
            eng.process_tick(
                quotes=QUOTES_20,
                signal={
                    "symbol": "EURUSD",
                    "side": "BUY",
                    "stop_price": "1.09510",
                    "take_profit_price": "1.10500",
                    "regime": REGIME_STRONG_TREND,
                },
                now=T0,
            )
            win_q = dict(QUOTES_20)
            win_q["EURUSD"] = (D("1.10520"), D("1.10530"))
            eng.process_tick(quotes=win_q, signal=None, now=T0 + timedelta(seconds=10))
            vault = eng._vaults["TIER_1_CURRENT"]
            if not hasattr(vault, "verify_audit_chain"):
                require_or_skip_unmerged(self, "ProfitSweepVault.verify_audit_chain() (M2)")
            audit = vault.verify_audit_chain()
            self.assertTrue(audit["valid"])
            self.assertGreaterEqual(audit["checked_rows"], 1)

    def test_e2e_t3_04_valve_decision_sha_embedded_and_enforced_across_mt5_spool(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            spool_dir = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool_dir,
                server="Hugosway-Demo",
                login=7001234,
                quotes=QUOTES_20,
                balance=D("10000"),
                trade_mode="DEMO",
            )
            emu.publish_market()
            transport = Mt5SpoolBridgeTransport(
                spool_dir,
                sleep=emu.sleep_hook,
                poll_interval_seconds=0.01,
                receipt_timeout_seconds=5,
            )
            creds = Mt5Credentials(broker_id=BROKER_HUGOSWAY_MT5, login=7001234, server="Hugosway-Demo")
            venue = Mt5PaperBrokerVenue(
                broker_id=BROKER_HUGOSWAY_MT5,
                credentials=creds,
                transport=transport,
                valve_gate=gate,
                clock=SteppingClock(T0),
            )
            venue.connect()
            order = OrderIntent(
                order_id="ord-t3-04",
                action_ref="act-t3-04",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
            )
            prop = build_valve_proposal(order_id=order.order_id, action_ref=order.action_ref, limit_price=None, stop_price=order.stop_price, take_profit_price=None)
            dec = gate.require_admissible(prop, current_view=default_view(), policy=default_policy(), now=T0 + timedelta(seconds=1))
            res = venue.execute(order, valve_decision=dec)
            self.assertTrue(res.accepted)

            import dataclasses
            bad_dec = dataclasses.replace(dec, selected_action_ref="tampered-ref")
            with self.assertRaises(Mt5ValveClearanceError):
                venue.execute(order, valve_decision=bad_dec)

    def test_e2e_t3_05_vault_ach_payout_consistent_with_cockpit_treasury_and_audit(self) -> None:
        with safe_temp_dir() as td:
            root = Path(td)
            pem_p = root / "cb_ec.pem"
            _ephemeral_ec_pem(pem_p)
            clk = SteppingClock(T0)
            vault = ProfitSweepVault(root / "vault.sqlite3", clock=clk)
            vault.record_realized_close(trade_id="tr-t3-05", symbol="EURUSD", broker_id=BROKER_HUGOSWAY_MT5, realized_net_usd=D("500.00"))
            cb = CoinbaseOfframpClient(
                key_name="organizations/org-e2e/apiKeys/key-e2e",
                private_key_file=pem_p,
                linked_bank_account_id="pm-bank-e2e-01",
                http_call=lambda m, u, h, b, t: (200, json.dumps({"id": "cb-t3-05"}).encode("utf-8")),
                resolve_dns=lambda _h: ["104.18.0.1"],
                clock=clk,
            )
            rec = OwnerRecoveryVerifier(db_path=root / "vault.sqlite3", clock=clk)
            prep_t3 = vault.prepare_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("150.00"),
                owner_request_id="req-t3-05",
                reason="Pairwise ACH test",
                coinbase_client=cb,
                idempotency_key="idem-t3-05",
            )
            tok = rec.mint_token(action_scope="TREASURY_SWEEP", target_ref=prep_t3["intent_sha256"], now=T0)
            vault.execute_offramp_ach_payout(
                rail=RAIL_COINBASE_ACH,
                amount_usd=D("150.00"),
                owner_request_id="req-t3-05",
                reason="Pairwise ACH test",
                verifier=rec,
                recovery_token=tok,
                coinbase_client=cb,
                idempotency_key="idem-t3-05",
                intent_id=prep_t3["intent_id"],
                intent_sha256=prep_t3["intent_sha256"],
            )
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0, profit_vault=vault)
            srv.start()
            self.addCleanup(srv.stop)

            st_tr, _, body_tr = loopback_http_request(srv, "GET", "/api/treasury", headers=srv.auth_headers())
            self.assertEqual(st_tr, 200)
            tr_doc = json.loads(body_tr.decode("utf-8"))
            self.assertEqual(Decimal(tr_doc["pending_disbursement_usd"]), D("100.00"))

            st_av, _, body_av = loopback_http_request(srv, "GET", "/api/audit-verify", headers=srv.auth_headers())
            if st_av == 404:
                require_or_skip_unmerged(self, "LoopbackCockpitServer /api/audit-verify consistency (M2)")
            self.assertEqual(st_av, 200)
            av_doc = json.loads(body_av.decode("utf-8"))
            self.assertTrue(av_doc["valid"])
            self.assertGreaterEqual(av_doc["checked_rows"], 3)

    def test_e2e_t3_06_parallel_tiers_snapshot_matches_cockpit_api_endpoint(self) -> None:
        gate = load_default_forex_valve_gate()
        with safe_temp_dir() as td:
            eng = ParallelTierEngine(Path(td) / "tiers.sqlite3", valve_gate=gate, clock=SteppingClock(T0))
            eng.process_tick(
                quotes=QUOTES_20,
                signal={"symbol": "EURUSD", "side": "BUY", "stop_price": "1.09510", "take_profit_price": "1.11000", "regime": REGIME_STRONG_TREND},
                now=T0,
            )
            expected = eng.snapshot()
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0, parallel_tiers=eng)
            srv.start()
            self.addCleanup(srv.stop)
            st, _, body = loopback_http_request(srv, "GET", "/api/parallel-tiers", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            self.assertEqual(json.loads(body.decode("utf-8")), expected)

    def test_e2e_t3_07_cockpit_select_ai_model_updates_registry_and_explainer_redacts_secrets(self) -> None:
        with safe_temp_dir() as td:
            reg = FrontierModelRegistry(
                environ=clean_demo_environ(CAS_FOREX_GEMINI_API_KEY=SYNTH_API_KEY, CAS_FOREX_ANTHROPIC_API_KEY=SYNTH_API_KEY),
                clock=SteppingClock(T0),
                http_post=stub_frontier_http_post,
                ollama_http_post=stub_frontier_http_post,
                resolve_dns=lambda _h: None,
            )
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0, ai_model_registry=reg)
            srv.start()
            self.addCleanup(srv.stop)

            sel_raw = json.dumps({"model_id": "gemini-carbon"}).encode("utf-8")
            hdrs = srv.auth_headers()
            hdrs["Content-Type"] = "application/json"
            hdrs["Content-Length"] = str(len(sel_raw))
            st_sel, _, body_sel = loopback_http_request(srv, "POST", "/api/select-ai-model", headers=hdrs, body=sel_raw)
            self.assertEqual(st_sel, 200)
            self.assertEqual(json.loads(body_sel.decode("utf-8"))["active_model_id"], "gemini-carbon")

            st_cat, _, body_cat = loopback_http_request(srv, "GET", "/api/ai-models", headers=srv.auth_headers())
            self.assertEqual(st_cat, 200)
            self.assertNotIn(SYNTH_API_KEY, body_cat.decode("utf-8"))

            ask_raw = json.dumps({"question": "Which model is selected?"}).encode("utf-8")
            hdrs["Content-Length"] = str(len(ask_raw))
            st_ask, _, body_ask = loopback_http_request(srv, "POST", "/api/explainer-ask", headers=hdrs, body=ask_raw)
            self.assertEqual(st_ask, 200)
            self.assertTrue(json.loads(body_ask.decode("utf-8"))["read_only"])

    def test_e2e_t3_08_cockpit_boot_payload_renders_in_node_explainer_under_strict_csp(self) -> None:
        node_bin = resolve_node_bin()
        if not node_bin:
            if is_integrated_mode():
                self.fail("M4 INTEGRATED GATE FAILURE: node executable not installed")
            self.skipTest("node executable not installed")
        with safe_temp_dir() as td:
            ui_svc = build_scoped_ui_service(Path(td) / "ui_state", clock=SteppingClock(T0))
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0, ui_service=ui_svc)
            srv.start()
            self.addCleanup(srv.stop)
            st, _, body = loopback_http_request(srv, "GET", "/api/boot", headers=srv.auth_headers())
            self.assertEqual(st, 200)
            boot_doc = json.loads(body.decode("utf-8"))

            js_script = (
                "import { createExplainer } from './ui/src/explainer.mjs';\n"
                "import assert from 'node:assert/strict';\n"
                "const camelToKebab=str=>String(str).replace(/[A-Z]/g,m=>'-'+m.toLowerCase());\n"
                "class N{constructor(t){this.tagName=t.toUpperCase();this.childNodes=[];this.attributes=new Map();this.listeners=new Map();this.style={};this._txt='';const s=this;this.classList={add(){},remove(){},toggle(){},contains(){return false}};this.dataset=new Proxy({},{get:(_,p)=>s.attributes.get('data-'+camelToKebab(p)),set:(_,p,v)=>{s.attributes.set('data-'+camelToKebab(p),String(v));return true},deleteProperty:(_,p)=>s.attributes.delete('data-'+camelToKebab(p))})}get id(){return this.attributes.get('id')||''}set id(v){this.attributes.set('id',v)}get className(){return this.attributes.get('class')||''}set className(v){this.attributes.set('class',v)}get hidden(){return this.attributes.has('hidden')}set hidden(v){if(v)this.attributes.set('hidden','');else this.attributes.delete('hidden')}get disabled(){return this.attributes.has('disabled')}set disabled(v){if(v)this.attributes.set('disabled','');else this.attributes.delete('disabled')}get textContent(){return this._txt||this.childNodes.map(c=>c.textContent).join('')}set textContent(v){this.childNodes=[];this._txt=String(v??'')}setAttribute(k,v){this.attributes.set(k,String(v))}getAttribute(k){return this.attributes.get(k)??null}hasAttribute(k){return this.attributes.has(k)}removeAttribute(k){this.attributes.delete(k)}appendChild(c){c.parentNode=this;this.childNodes.push(c);return c}append(...xs){xs.forEach(x=>this.appendChild(x))}insertBefore(n,r){const i=this.childNodes.indexOf(r);n.parentNode=this;this.childNodes.splice(i<0?0:i,0,n)}replaceChildren(...xs){this.childNodes=[];xs.forEach(x=>this.appendChild(x))}replaceWith(n){if(this.parentNode){const i=this.parentNode.childNodes.indexOf(this);n.parentNode=this.parentNode;this.parentNode.childNodes[i]=n}}remove(){}contains(x){return x===this||this.childNodes.some(c=>c.contains(x))}addEventListener(t,fn){if(!this.listeners.has(t))this.listeners.set(t,[]);this.listeners.get(t).push(fn)}removeEventListener(t,fn){const ls=this.listeners.get(t);if(ls)this.listeners.set(t,ls.filter(f=>f!==fn))}click(){for(const fn of this.listeners.get('click')||[])fn({type:'click',target:this,currentTarget:this,preventDefault(){}})}getBoundingClientRect(){return{top:0,left:0,right:100,bottom:30,width:100,height:30}}scrollTo(){}focus(){}querySelectorAll(q){const o=[];const walk=n=>{for(const c of n.childNodes){if(q.startsWith('#')&&c.id===q.slice(1))o.push(c);else if(q.startsWith('.')&&c.className.split(/\\s+/).includes(q.slice(1)))o.push(c);else if(q.startsWith('[')){const inner=q.slice(1,-1);const eq=inner.indexOf('=');if(eq<0){if(c.hasAttribute(inner))o.push(c)}else{const ak=inner.slice(0,eq);const av=inner.slice(eq+1).replace(/^[\x22']|[\x22']$/g,'');if(c.getAttribute(ak)===av)o.push(c)}}else if(q.endsWith(' pre')&&c.tagName==='PRE')o.push(c);walk(c)}};walk(this);return o}querySelector(q){return this.querySelectorAll(q)[0]||null}closest(){return null}}\n"
                "const b=new N('body');const app=new N('main');app.id='app';b.appendChild(app);const d=new N('html');d.clientWidth=1280;d.appendChild(b);\n"
                "globalThis.localStorage={getItem:()=>null,setItem(){}};globalThis.DOMParser=class{parseFromString(){const r=new N('body');const mk=(t,c)=>{const e=new N(t);if(c)e.className=c;return e};const m=mk('button','forex-explainer-mark');const p=mk('aside','forex-explainer-panel');const x=mk('button','forex-explainer-close');const a=mk('div');a.setAttribute('data-guide-announcement','');const q=mk('h3','forex-explainer-question');const ans=mk('p','forex-explainer-answer');const src=mk('dd');src.setAttribute('data-guide-source','');const acc=mk('dd');acc.setAttribute('data-guide-account','');const run=mk('dd');run.setAttribute('data-guide-run','');const st=mk('dd');st.setAttribute('data-guide-state','');const mod=mk('dd');mod.setAttribute('data-guide-model','');const sub=mk('p');sub.setAttribute('data-guide-subtitle','');const rec=mk('div','forex-explainer-record');rec.appendChild(mk('pre'));const inp=mk('input');inp.id='forex-explainer-prompt';const btn=mk('button');btn.setAttribute('data-explainer-ask-submit','');const note=mk('p');note.id='forex-explainer-unavailable';const t1=mk('button');t1.setAttribute('data-explainer-topic','overview');t1.textContent='Overview';r.append(m,p,x,a,q,ans,src,acc,run,st,mod,sub,rec,inp,btn,note,t1);return{body:r}}};\n"
                "globalThis.document={documentElement:d,body:b,createElement:t=>new N(t),getElementById:id=>b.querySelector('#'+id),querySelector:s=>b.querySelector(s),querySelectorAll:s=>b.querySelectorAll(s),addEventListener(){},removeEventListener(){}};\n"
                "globalThis.window={scrollX:0,scrollY:0,innerWidth:1280,innerHeight:800,scrollTo(){},matchMedia:()=>({matches:true,addEventListener(){},removeEventListener(){}}),addEventListener(){},removeEventListener(){},setTimeout};\n"
                f"const boot = {json.dumps(boot_doc)};\n"
                "const proj = boot.cockpit ?? boot;\n"
                "const exp = createExplainer({ getContext: () => ({ route: 'operate', source: 'LoopbackCockpitServer', projection: proj }) });\n"
                "b.querySelector('.forex-explainer-mark').click();\n"
                "exp.sync();\n"
                "assert.equal(b.querySelector('[data-guide-source]').textContent, 'LoopbackCockpitServer');\n"
                "assert.equal(b.querySelector('[data-guide-account]').textContent, String(proj.scope.account_id));\n"
                "assert.equal(b.querySelector('[data-guide-run]').textContent, String(proj.scope.run_id));\n"
                "assert.equal(b.querySelector('[data-guide-state]').textContent, String(proj.state_id ?? 'Unknown'));\n"
                "const parsedRec = JSON.parse(b.querySelector('.forex-explainer-record pre').textContent);\n"
                "assert.deepEqual(parsedRec, { cockpit: proj, decision_read: null });\n"
                "exp.destroy();\n"
            )
            res = subprocess.run(  # nosec B603: fixed argv list invoking resolved node binary without shell
                [node_bin, "--input-type=module", "-e", js_script],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(res.returncode, 0, f"stderr={res.stderr}")

    def test_e2e_t3_09_frontier_proposal_missing_stop_blocked_by_valve_gate(self) -> None:
        gate = load_default_forex_valve_gate()
        no_stop = build_valve_proposal(kind=ActionKind.OPEN, stop_price=None)
        with self.assertRaises(ValveRefusalError) as ctx:
            gate.require_admissible(no_stop, current_view=default_view(), policy=default_policy(), now=T0 + timedelta(seconds=1))
        self.assertIn("MISSING_PROTECTIVE_STOP", ctx.exception.decision.hard_veto_reasons)

    def test_e2e_t3_10_dual_shield_router_routes_mt5_demo_and_rejects_off_market_spike(self) -> None:
        with safe_temp_dir() as td:
            rig = DualBrokerTestRig(td)
            router = rig.dual_router()
            router.activate()
            order = OrderIntent(
                order_id="ord-t3-10",
                action_ref="act-t3-10",
                kind=ActionKind.OPEN,
                symbol="EURUSD",
                quantity_units=D("10000"),
                side=Side.BUY,
                stop_price=D("1.09500"),
                take_profit_price=D("1.11000"),
            )
            prop = build_valve_proposal(order_id=order.order_id, action_ref=order.action_ref, limit_price=None, stop_price=order.stop_price, take_profit_price=order.take_profit_price)
            dec = rig.gate.require_admissible(prop, current_view=default_view(), policy=default_policy(), now=T0 + timedelta(seconds=1))
            res = router.execute_open(order, valve_decision=dec)
            self.assertEqual(res.executed_on, BROKER_HUGOSWAY_MT5)

            rig.emus[BROKER_HUGOSWAY_MT5].set_quote("EURUSD", D("1.15000"), D("1.15010"))
            rig.emus[BROKER_HUGOSWAY_MT5].publish_market()
            with self.assertRaises(OffMarketBrokerQuoteError):
                router.oracle().require_truthful(BROKER_HUGOSWAY_MT5, "EURUSD", D("1.15000"), D("1.15010"))

    def test_e2e_t3_11_agent_pr_merger_lightweight_passes_on_e2e_hardening_snapshot(self) -> None:
        from scripts.agent_pr_merger import verify_worktree_lightweight
        with safe_temp_dir() as td:
            snap_dir = Path(td)
            e2e_dst = snap_dir / "tests/e2e_hardening"
            e2e_dst.mkdir(parents=True, exist_ok=True)
            for p in Path(__file__).resolve().parent.glob("*"):
                if p.is_file() and p.suffix in (".py", ".mjs"):
                    shutil.copy2(p, e2e_dst / p.name)
            ui_dst = snap_dir / "ui"
            ui_dst.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / "ui/index.html", ui_dst / "index.html")
            ok, notes = verify_worktree_lightweight(snap_dir)
            self.assertTrue(ok, notes)
            self.assertIn("secret_scan=CLEAN", notes[0])
            self.assertIn("csp_inline_style=0", notes[0])

    def test_e2e_t3_12_quota_lock_unlocked_once_via_cockpit_and_replay_rejected(self) -> None:
        with safe_temp_dir() as td:
            root = Path(td)
            clk = SteppingClock(T0)
            rig = DualBrokerTestRig(root / "rig")
            router = rig.dual_router()
            reg = FrontierModelRegistry(
                environ=clean_demo_environ(CAS_FOREX_ANTHROPIC_API_KEY=SYNTH_API_KEY),
                clock=clk,
                http_post=stub_frontier_http_post,
                ollama_http_post=stub_frontier_http_post,
                resolve_dns=lambda _h: None,
            )
            quota = DailyQuotaGovernanceStore(path=root / "quota.sqlite3", max_consecutive_losses=3)
            quota.observe_day_start(D("20000"), now=T0)
            for i in range(3):
                quota.record_realized_trade(D("-50"), symbol="EURUSD", ticket=f"loss-{i}", now=T0)
            rec = OwnerRecoveryVerifier(db_path=root / "owner.sqlite3", clock=clk)
            quota.bind_owner_verifier(rec)
            trader = AutonomousAiTrader(
                router=router,
                model_registry=reg,
                valve_gate=rig.gate,
                quota_store=quota,
                execution_gate=DurableModelExecutionGate(db_path=root / "mg.sqlite3"),
                owner_verifier=rec,
                clock=clk,
            )
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                host="127.0.0.1",
                port=0,
                autonomous_trader=trader,
                owner_recovery=rec,
            )
            srv.start()
            self.addCleanup(srv.stop)

            tok = rec.mint_token(action_scope="UNLOCK_QUOTA_SESSION", now=T0)
            body_raw = json.dumps({
                "action": "UNLOCK_QUOTA_SESSION",
                "owner_request_id": "req-unlock-t3-12",
                "reason": "Owner verified unlock",
                "recovery_token": tok,
            }).encode("utf-8")
            hdrs = srv.auth_headers()
            hdrs["Content-Type"] = "application/json"
            hdrs["Content-Length"] = str(len(body_raw))
            st1, _, _ = loopback_http_request(srv, "POST", "/api/ai-overseer-action", headers=hdrs, body=body_raw)
            self.assertEqual(st1, 200)

            st2, _, _ = loopback_http_request(srv, "POST", "/api/ai-overseer-action", headers=hdrs, body=body_raw)
            self.assertIn(st2, (400, 403))


if __name__ == "__main__":
    unittest.main()
