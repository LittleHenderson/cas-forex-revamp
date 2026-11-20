"""E2E FA-5: ui/src/explainer.mjs Contract, Node UI Execution, and Strict CSP Compliance (10 tests)."""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess  # nosec B404: invokes local node binary to run offline CSP UI tests without shell
import tempfile
import unittest

from cas_forex_revamp.composition.live_cockpit_server import STRICT_CSP, LoopbackCockpitServer

try:
    from tests.e2e_hardening._e2e_support import (
        REPO_ROOT,
        SYNTH_API_KEY,
        SteppingClock,
        T0,
        build_scoped_ui_service,
        clean_demo_environ,
        is_integrated_mode,
        loopback_http_request,
        require_or_skip_unmerged,
        resolve_node_bin,
        stub_frontier_http_post,
    )
except ImportError:  # pragma: no cover
    from _e2e_support import (
        REPO_ROOT,
        SYNTH_API_KEY,
        SteppingClock,
        T0,
        build_scoped_ui_service,
        clean_demo_environ,
        is_integrated_mode,
        loopback_http_request,
        require_or_skip_unmerged,
        resolve_node_bin,
        stub_frontier_http_post,
    )
from cas_forex_revamp.operator.frontier_backends import FrontierModelRegistry


class UiCspE2ETests(unittest.TestCase):
    # --- Tier 1: Feature Coverage (5 tests) ---

    def test_e2e_t1_fa5_01_node_explainer_csp_suite_passes(self) -> None:
        node_bin = resolve_node_bin()
        if not node_bin:
            if is_integrated_mode():
                self.fail("M4 INTEGRATED GATE FAILURE: node executable not installed on PATH")
            self.skipTest("node executable not installed on PATH")
        test_mjs = REPO_ROOT / "tests/e2e_hardening/e2e_explainer_csp.test.mjs"
        res = subprocess.run(  # nosec B603: fixed argv list invoking resolved node binary without shell
            [node_bin, "--test", str(test_mjs)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(res.returncode, 0, f"stdout={res.stdout}\nstderr={res.stderr}")
        self.assertIn("pass 10", res.stdout)

    def test_e2e_t1_fa5_02_ui_index_meta_csp_matches_server_strict_csp(self) -> None:
        index_html = (REPO_ROOT / "ui/index.html").read_text(encoding="utf-8")
        m = re.search(r'<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"', index_html)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), STRICT_CSP)
        self.assertIn("default-src 'none'", STRICT_CSP)
        self.assertIn("object-src 'none'", STRICT_CSP)

    def test_e2e_t1_fa5_03_cockpit_serves_ui_html_and_explainer_mjs_with_strict_csp(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ui_svc = build_scoped_ui_service(Path(td) / "ui_state", clock=SteppingClock(T0))
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0, ui_service=ui_svc)
            srv.start()
            self.addCleanup(srv.stop)

            pair_doc = srv.mint_pairing_code()
            st_html, hdr_html, body_html = loopback_http_request(srv, "GET", f"/ui/index.html?pair_code={pair_doc['pair_code']}")
            self.assertEqual(st_html, 200)
            self.assertEqual(hdr_html.get("content-security-policy"), STRICT_CSP)
            self.assertEqual(hdr_html.get("x-frame-options"), "SAMEORIGIN")
            self.assertIn(b"explainer", body_html.lower())

            st_mjs, hdr_mjs, body_mjs = loopback_http_request(srv, "GET", "/ui/src/explainer.mjs")
            self.assertEqual(st_mjs, 200)
            self.assertEqual(hdr_mjs.get("content-security-policy"), STRICT_CSP)
            self.assertIn("javascript", hdr_mjs.get("content-type", ""))
            self.assertIn(b"createExplainer", body_mjs)

    def test_e2e_t1_fa5_04_explainer_and_render_use_safe_dom_parser_mounting(self) -> None:
        render_mjs = (REPO_ROOT / "ui/src/render.mjs").read_text(encoding="utf-8")
        explainer_mjs = (REPO_ROOT / "ui/src/explainer.mjs").read_text(encoding="utf-8")
        self.assertIn("new DOMParser().parseFromString", render_mjs)
        self.assertIn("replaceChildren", render_mjs)
        self.assertIn("replaceSafeHTML", explainer_mjs)
        self.assertIn("Object.freeze({", explainer_mjs)

    def test_e2e_t1_fa5_05_m2_unit_explainer_test_mjs_contract(self) -> None:
        m2_test = REPO_ROOT / "tests/ui/explainer.test.mjs"
        if not m2_test.is_file():
            require_or_skip_unmerged(self, "tests/ui/explainer.test.mjs (M2)")
        node_bin = resolve_node_bin()
        if not node_bin:
            if is_integrated_mode():
                self.fail("M4 INTEGRATED GATE FAILURE: node executable not installed on PATH")
            self.skipTest("node executable not installed on PATH")
        res = subprocess.run(  # nosec B603: fixed argv list invoking resolved node binary without shell
            [node_bin, "--test", str(m2_test)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(res.returncode, 0, f"stdout={res.stdout}\nstderr={res.stderr}")

    # --- Tier 2: Boundary & Corner Cases (5 tests) ---

    def test_e2e_t2_fa5_01_zero_innerhtml_outerhtml_or_inline_style_across_ui(self) -> None:
        ui_dir = REPO_ROOT / "ui"
        bad_inner = "." + "inner" + "HTML"
        bad_outer = "." + "outer" + "HTML"
        bad_eval = "ev" + "al("
        style_pat = re.compile(r"\bsty" + r'le\s*=\s*["\x27]')
        for p in sorted(ui_dir.rglob("*")):
            if not p.is_file() or p.suffix not in (".html", ".mjs", ".js"):
                continue
            txt = p.read_text(encoding="utf-8")
            self.assertNotIn(bad_inner, txt, p.name)
            self.assertNotIn(bad_outer, txt, p.name)
            self.assertNotIn(bad_eval, txt, p.name)
            self.assertIsNone(style_pat.search(txt), f"Inline style attr in {p.name}")

    def test_e2e_t2_fa5_02_cockpit_rejects_bad_bootstrap_query_token_on_ui_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ui_svc = build_scoped_ui_service(Path(td) / "ui_state", clock=SteppingClock(T0))
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0, ui_service=ui_svc)
            srv.start()
            self.addCleanup(srv.stop)

            st_bad, _, _ = loopback_http_request(srv, "GET", "/ui/index.html?token=wrong-token-value")
            self.assertEqual(st_bad, 401)
            st_api_tok, _, _ = loopback_http_request(srv, "GET", f"/api/cockpit?token={srv.auth_token}")
            self.assertEqual(st_api_tok, 401)

    def test_e2e_t2_fa5_03_explainer_ask_endpoint_sanitizes_control_chars_and_rejects_empty(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            reg = FrontierModelRegistry(
                environ=clean_demo_environ(CAS_FOREX_ANTHROPIC_API_KEY=SYNTH_API_KEY),
                http_post=stub_frontier_http_post,
                ollama_http_post=stub_frontier_http_post,
                resolve_dns=lambda _h: None,
            )
            ui_svc = build_scoped_ui_service(Path(td) / "ui_state", clock=SteppingClock(T0))
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                host="127.0.0.1",
                port=0,
                ui_service=ui_svc,
                ai_model_registry=reg,
            )
            srv.start()
            self.addCleanup(srv.stop)

            bad_raw = json.dumps({"question": "   \n\t  "}).encode("utf-8")
            hdrs = srv.auth_headers()
            hdrs["Content-Type"] = "application/json"
            hdrs["Content-Length"] = str(len(bad_raw))
            st_bad, _, _ = loopback_http_request(srv, "POST", "/api/explainer-ask", headers=hdrs, body=bad_raw)
            self.assertEqual(st_bad, 400)

            long_raw = json.dumps({"question": "x" * 501}).encode("utf-8")
            hdrs["Content-Length"] = str(len(long_raw))
            st_long, _, _ = loopback_http_request(srv, "POST", "/api/explainer-ask", headers=hdrs, body=long_raw)
            self.assertEqual(st_long, 400)

    def test_e2e_t2_fa5_04_ui_static_disallows_disallowed_extensions_and_parent_escape(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, host="127.0.0.1", port=0)
            srv.start()
            self.addCleanup(srv.stop)
            for bad_path in ("/ui/../pyproject.toml", "/ui/nonexistent.py", "/ui/src/../styles.css.bak"):
                st, _, _ = loopback_http_request(srv, "GET", bad_path, headers=srv.auth_headers())
                self.assertIn(st, (403, 404), bad_path)

    def test_e2e_t2_fa5_05_explainer_has_zero_fetch_or_trading_mutation_calls(self) -> None:
        explainer_mjs = (REPO_ROOT / "ui/src/explainer.mjs").read_text(encoding="utf-8")
        for forbidden_call in ("fetch(", "XMLHttpRequest", "WebSocket", "/api/request-control", "/api/request-reviewed-close"):
            self.assertNotIn(forbidden_call, explainer_mjs)


if __name__ == "__main__":
    unittest.main()
