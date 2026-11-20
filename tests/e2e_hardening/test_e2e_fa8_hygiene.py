"""E2E FA-8: Secret & Lantern 0.11.0 Static Hygiene Self-Audit (10 tests)."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import re
import io
import shutil
import subprocess  # nosec B404: invokes git diff read-only to verify zero .github/workflows edits without shell
import tokenize
import unittest

try:
    from tests.e2e_hardening._e2e_support import REPO_ROOT
except ImportError:  # pragma: no cover
    from _e2e_support import REPO_ROOT

E2E_DIR = Path(__file__).resolve().parent
RAW_TMP_LITERAL = "/" + "tmp"
SECRET_REGEXES = (
    re.compile(r"\b(AK" + r"IA|AS" + r"IA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(gh" + r"p_[A-Za-z0-9]{30,}|github_" + r"pat_[A-Za-z0-9_]{30,})\b"),
    re.compile(r"BEG" + r"IN [A-Z ]*PRIVATE " + r"KEY"),
    re.compile(r"\bs" + r"k-[A-Za-z0-9]{20,}\b"),
)


def _e2e_py_files() -> list[Path]:
    return sorted(E2E_DIR.glob("*.py"))


class LanternStaticHygieneE2ETests(unittest.TestCase):
    # --- Tier 1: Feature Coverage (E2E-T1-36 .. E2E-T1-40) ---

    def test_e2e_t1_36_zero_bare_assert_statements_in_e2e_hardening(self) -> None:
        hits: list[str] = []
        for p in _e2e_py_files():
            tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
            for node in ast.walk(tree):
                if isinstance(node, ast.Assert):
                    hits.append(f"{p.name}:{node.lineno}")
        self.assertEqual(hits, [], f"Bandit B101 assert found: {hits}")

    def test_e2e_t1_37_zero_secret_patterns_or_raw_tmp_literals(self) -> None:
        for p in sorted(E2E_DIR.rglob("*")):
            if not p.is_file() or "__pycache__" in p.parts:
                continue
            txt = p.read_text(encoding="utf-8")
            for pat in SECRET_REGEXES:
                self.assertIsNone(pat.search(txt), f"Secret regex hit in {p.name}")
            if p.suffix == ".py":
                tree = ast.parse(txt, filename=str(p))
                for node in ast.walk(tree):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str):
                        self.assertNotIn(RAW_TMP_LITERAL, node.value, f"Bandit B108 literal in {p.name}")

    def test_e2e_t1_38_zero_silent_except_pass_or_shell_true(self) -> None:
        for p in _e2e_py_files():
            tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler):
                    if len(node.body) == 1 and isinstance(node.body[0], (ast.Pass, ast.Continue)):
                        self.fail(f"Bandit B110/B112 silent except in {p.name}:{node.lineno}")
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self.fail(f"Bandit B602 shell=True in {p.name}:{node.lineno}")

    def test_e2e_t1_39_zero_unsafe_dir_helper_names_and_all_nosec_have_reasons(self) -> None:
        banned_word = "ch" + "mod"
        bad_defs: list[str] = []
        bad_nosec: list[str] = []
        for search_dir in (E2E_DIR, REPO_ROOT / "src"):
            for p in sorted(search_dir.rglob("*.py")):
                txt = p.read_text(encoding="utf-8")
                tree = ast.parse(txt, filename=str(p))
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and banned_word in node.name.lower():
                        bad_defs.append(f"{p.name}:{node.name}")
                for tok in tokenize.generate_tokens(io.StringIO(txt).readline):
                    if tok.type == tokenize.COMMENT and "# nosec" in tok.string:
                        tail = tok.string.split("# nosec", 1)[1]
                        if ":" not in tail or not tail.split(":", 1)[1].strip():
                            bad_nosec.append(f"{p.name}:{tok.start[0]}")
        self.assertEqual(bad_defs, [])
        self.assertEqual(bad_nosec, [])

    def test_e2e_t1_40_lockfile_parity_and_zero_ui_inline_styles(self) -> None:
        reqs = (REPO_ROOT / "requirements.txt").read_text(encoding="utf-8")
        req_lines = [ln.strip() for ln in reqs.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        self.assertTrue(req_lines)
        for ln in req_lines:
            self.assertIn("==", ln, f"Unpinned requirement: {ln}")
        self.assertTrue(any("cryptography==" in ln for ln in req_lines))

        lock = json.loads((REPO_ROOT / "ui/package-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock.get("lockfileVersion"), 3)

        style_pat = re.compile(r"\bsty" + r'le\s*=\s*["\x27]')
        for ui_file in sorted((REPO_ROOT / "ui").rglob("*")):
            if ui_file.is_file() and ui_file.suffix in (".html", ".mjs", ".js"):
                txt = ui_file.read_text(encoding="utf-8")
                self.assertIsNone(style_pat.search(txt), f"Inline style in {ui_file.name}")

    # --- Tier 2: Boundary & Corner Cases (E2E-T2-36 .. E2E-T2-40) ---

    def test_e2e_t2_36_zero_xss_dom_sinks_in_e2e_mjs_files(self) -> None:
        bad_inner = "." + "inner" + "HTML"
        bad_outer = "." + "outer" + "HTML"
        style_pat = re.compile(r"\bsty" + r'le\s*=\s*["\x27]')
        for mjs in sorted(E2E_DIR.glob("*.mjs")):
            txt = mjs.read_text(encoding="utf-8")
            self.assertNotIn(bad_inner, txt, mjs.name)
            self.assertNotIn(bad_outer, txt, mjs.name)
            self.assertIsNone(style_pat.search(txt), mjs.name)

    def test_e2e_t2_37_zero_xml_etree_imports_in_e2e_hardening(self) -> None:
        banned_mod = "xml.etree." + "ElementTree"
        for p in _e2e_py_files():
            tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotEqual(alias.name, banned_mod, p.name)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertFalse(node.module.startswith("xml.etree"), p.name)

    def test_e2e_t2_38_zero_unannotated_urlopen_in_e2e_hardening(self) -> None:
        for p in _e2e_py_files():
            for idx, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if "url" + "open(" in line and "# nosec B310:" not in line:
                    self.fail(f"Unannotated urlopen at {p.name}:{idx}")

    def test_e2e_t2_39_zero_unsafe_eval_exec_or_pickle_loads_in_e2e_hardening(self) -> None:
        banned_calls = {"ev" + "al", "ex" + "ec"}
        for p in _e2e_py_files():
            tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in banned_calls:
                        self.fail(f"Unsafe builtin {node.func.id} in {p.name}:{node.lineno}")
                    if isinstance(node.func, ast.Attribute) and node.func.attr == "loads":
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "pic" + "kle":
                            self.fail(f"Unsafe pickle.loads in {p.name}:{node.lineno}")

    def test_e2e_t2_40_zero_github_workflows_modifications(self) -> None:
        if not (REPO_ROOT / ".git").exists():
            self.assertFalse((REPO_ROOT / ".github" / "workflows").exists())
            return
        git_bin = shutil.which("git") or "git"
        res = subprocess.run(  # nosec B603, B607: fixed read-only git diff argv without shell
            [git_bin, "-C", str(REPO_ROOT), "diff", "--name-only", "origin/main...HEAD", "--", ".github/workflows"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if res.returncode == 0:
            changed = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
            self.assertEqual(changed, [])


if __name__ == "__main__":
    unittest.main()
