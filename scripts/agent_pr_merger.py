"""Periodic AI-Agent PR Verifier & Auto-Merger for LittleHenderson/cas-forex-revamp.

Continuously inspects open PRs targeting `main`, enforces completion-gate & owner-branch safety,
verifies Secret/Strict-CSP/Syntax/Contract gates (plus any GitHub check-runs), updates behind branches,
and squash-merges passing AI-agent PRs until `docs/REVAMP_COMPLETION_GATE.json` marks `revamp_completed: true`.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
from typing import Any
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile

REPO_SLUG = "LittleHenderson/cas-forex-revamp"

SECRET_PATTERNS = [
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
]


def gh_json(args: list[str]):
    res = subprocess.run(["gh"] + args, capture_output=True, text=True, check=True, timeout=60)
    return json.loads(res.stdout) if res.stdout.strip() else {}


def verify_worktree_lightweight(wt_dir: Path) -> tuple[bool, list[str]]:
    """Fast, low-memory (<25 MB) deterministic gate safe for lightweight orchestration hosts:
    1. Zero leaked credentials/keys across all tracked text files.
    2. Strict CSP enforcement: zero inline `style=` attributes across `ui/`.
    3. Valid AST syntax across all `.py` files.
    4. Valid strict JSON across all `.json` contracts & `node --check` syntax across `ui/src/*.mjs`.
    """
    notes: list[str] = []
    py_count = 0
    json_count = 0
    mjs_count = 0

    for p in sorted(wt_dir.rglob("*")):
        if ".git" in p.parts or not p.is_file():
            continue
        try:
            txt = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        for pat in SECRET_PATTERNS:
            if pat.search(txt):
                return False, [f"SECRET_DETECTED:{p.relative_to(wt_dir).as_posix()}"]

        if p.suffix == ".py":
            try:
                ast.parse(txt, filename=str(p))
                py_count += 1
            except SyntaxError as exc:
                return False, [f"PYTHON_SYNTAX_ERROR:{p.relative_to(wt_dir).as_posix()}:{exc}"]
        elif p.suffix == ".json":
            try:
                json.loads(txt)
                json_count += 1
            except Exception as exc:
                return False, [f"JSON_INVALID:{p.relative_to(wt_dir).as_posix()}:{exc}"]

    ui_dir = wt_dir / "ui"
    if ui_dir.is_dir():
        for ui_file in sorted(ui_dir.rglob("*")):
            if ui_file.is_file() and ui_file.suffix in (".html", ".mjs", ".js"):
                txt = ui_file.read_text(encoding="utf-8")
                if re.search(r'\bstyle\s*=\s*["\']', txt):
                    return False, [f"CSP_INLINE_STYLE_VIOLATION:{ui_file.relative_to(wt_dir).as_posix()}"]
                if ui_file.suffix == ".mjs" and shutil.which("node"):
                    chk = subprocess.run(["node", "--check", str(ui_file)], capture_output=True, text=True, timeout=30)
                    if chk.returncode != 0:
                        return False, [f"NODE_SYNTAX_ERROR:{ui_file.relative_to(wt_dir).as_posix()}:{chk.stderr.strip()}"]
                    mjs_count += 1

    notes.append(f"secret_scan=CLEAN, csp_inline_style=0, py_ast_ok={py_count}, json_ok={json_count}, mjs_syntax_ok={mjs_count}")
    return True, notes


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    subprocess.run(["git", "fetch", "origin", "--prune"], cwd=str(repo_root), check=True, timeout=60)

    # 1. Check completion gate on origin/main
    gate_raw = subprocess.run(
        ["git", "show", "origin/main:docs/REVAMP_COMPLETION_GATE.json"],
        cwd=str(repo_root), capture_output=True, text=True, check=True, timeout=30,
    ).stdout
    gate = json.loads(gate_raw)
    if gate.get("revamp_completed") is True:
        print(json.dumps({"status": "HALTED_REVAMP_COMPLETED", "gate": gate}, indent=2))
        return 0

    owner = REPO_SLUG.split("/")[0]
    prs = gh_json([
        "pr", "list",
        "--repo", REPO_SLUG,
        "--base", "main",
        "--state", "open",
        "--json", "number,title,isDraft,headRefName,headRefOid,headRepositoryOwner,mergeable,mergeStateStatus,labels,author",
    ])

    actions = []
    for pr in sorted(prs, key=lambda x: x["number"]):
        num = pr["number"]
        title = pr["title"]
        if pr.get("isDraft"):
            actions.append({"pr": num, "action": "SKIP_DRAFT"})
            continue

        head_owner = (pr.get("headRepositoryOwner") or {}).get("login", "")
        if head_owner != owner:
            actions.append({"pr": num, "action": "SKIP_EXTERNAL_FORK", "owner": head_owner})
            continue

        labels = {lb["name"] for lb in (pr.get("labels") or [])}
        author_login = (pr.get("author") or {}).get("login", "")
        if "do-not-merge" in labels or "hold" in labels:
            actions.append({"pr": num, "action": "SKIP_HOLD_LABEL"})
            continue
        if not ("agent-pr" in labels or "automerge-ready" in labels or author_login == owner or author_login.endswith("[bot]")):
            actions.append({"pr": num, "action": "SKIP_UNLABELED"})
            continue

        merge_state = pr.get("mergeStateStatus") or ""
        if merge_state == "BEHIND":
            subprocess.run(
                ["gh", "api", f"repos/{REPO_SLUG}/pulls/{num}/update-branch", "-X", "PUT"],
                capture_output=True, text=True, timeout=60,
            )
            actions.append({"pr": num, "action": "UPDATED_BEHIND_BRANCH"})
            continue

        required_jobs = {
            "Secret & Strict-CSP Gate",
            "Node UI Suite",
            "Python Unit & Contract Suites",
        }

        def _evaluate_checks_fail_closed(commit_sha: str) -> tuple[bool, dict[str, Any]]:
            cr_doc = gh_json(["api", f"repos/{REPO_SLUG}/commits/{commit_sha}/check-runs?per_page=100"])
            check_runs = cr_doc.get("check_runs", [])
            if not check_runs:
                return False, {"action": "WAITING_CI_CHECKS_EMPTY", "reason": "zero check_runs recorded"}
            latest_by_name: dict[str, dict[str, Any]] = {}
            for cr in check_runs:
                cname = cr.get("name", "")
                if cname == "Periodically Verify & Merge Passing AI-Agent PRs":
                    continue
                prev = latest_by_name.get(cname)
                if prev is None or int(cr.get("id", 0)) > int(prev.get("id", 0)):
                    latest_by_name[cname] = cr
            missing = sorted(required_jobs - set(latest_by_name.keys()))
            if missing:
                return False, {"action": "WAITING_REQUIRED_CI_JOBS", "missing": missing}
            bad = [
                f"{cname}:{cr.get('status')}/{cr.get('conclusion')}"
                for cname, cr in latest_by_name.items()
                if cr.get("status") != "completed" or cr.get("conclusion") != "success"
            ]
            if bad:
                return False, {"action": "WAITING_CI_CHECKS", "pending_or_failed": bad}
            return True, {}

        sha = pr["headRefOid"]
        checks_ok, check_fail_info = _evaluate_checks_fail_closed(sha)
        if not checks_ok:
            actions.append({"pr": num, **check_fail_info})
            continue

        # Verify PR head in temporary worktree
        tmp_wt = Path(tempfile.mkdtemp(prefix=f"cas_pr_{num}_", dir=str(repo_root.parent)))
        try:
            subprocess.run(["git", "worktree", "add", "--detach", str(tmp_wt), sha], cwd=str(repo_root), check=True, capture_output=True, timeout=60)
            ok, notes = verify_worktree_lightweight(tmp_wt)
        finally:
            subprocess.run(["git", "worktree", "remove", "--force", str(tmp_wt)], cwd=str(repo_root), capture_output=True, timeout=60)
            if tmp_wt.exists():
                shutil.rmtree(tmp_wt, ignore_errors=True)

        if not ok:
            actions.append({"pr": num, "action": "BLOCKED_VERIFICATION", "reasons": notes})
            continue

        comment_body = (
            f"Automated AI-Agent PR Verification PASSED on `{sha[:12]}` "
            f"({'; '.join(notes)}). Squash-merging into `main` under active `REVAMP_COMPLETION_GATE`."
        )
        subprocess.run(["gh", "pr", "comment", str(num), "--repo", REPO_SLUG, "--body", comment_body], capture_output=True, text=True, timeout=60)

        live_pr = gh_json([
            "pr", "view", str(num), "--repo", REPO_SLUG,
            "--json", "headRefOid,baseRefName,state,isDraft,labels",
        ])
        live_labels = {lb["name"] for lb in (live_pr.get("labels") or [])}
        if (
            live_pr.get("state") != "OPEN"
            or live_pr.get("isDraft")
            or live_pr.get("baseRefName") != "main"
            or live_pr.get("headRefOid") != sha
            or ("do-not-merge" in live_labels or "hold" in live_labels)
        ):
            actions.append({"pr": num, "action": "ABORTED_HEAD_OR_BASE_CHANGED", "expected_sha": sha, "live_pr": live_pr})
            continue
        rechecks_ok, recheck_fail_info = _evaluate_checks_fail_closed(sha)
        if not rechecks_ok:
            actions.append({"pr": num, "action": "ABORTED_PREMERGE_RECHECK", **recheck_fail_info})
            continue

        m_res = subprocess.run(
            ["gh", "pr", "merge", str(num), "--repo", REPO_SLUG, "--squash", "--delete-branch", "--match-head-commit", sha],
            capture_output=True, text=True, timeout=60,
        )
        if m_res.returncode == 0:
            subprocess.run(["git", "checkout", "main"], cwd=str(repo_root), capture_output=True, timeout=30)
            subprocess.run(["git", "pull", "--ff-only", "origin", "main"], cwd=str(repo_root), capture_output=True, timeout=60)
            actions.append({"pr": num, "title": title, "sha": sha, "action": "MERGED", "notes": notes})
            # Merge one PR per cycle so any remaining open PRs cleanly rebase onto new main next cycle
            break
        else:
            actions.append({"pr": num, "action": "MERGE_ERROR", "stderr": m_res.stderr.strip()})

    print(json.dumps({"status": "CYCLE_COMPLETE", "open_prs_seen": len(prs), "actions": actions}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
