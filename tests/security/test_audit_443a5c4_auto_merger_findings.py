"""Verification suite for PR #32 Security Audit Findings [14] and [15] (commit 443a5c4)."""
from __future__ import annotations

import ast
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import agent_pr_merger  # noqa: E402

SHA_A = "a" * 40
SHA_B = "b" * 40
OWNER_ID = 98265490
REPO = "LittleHenderson/cas-forex-revamp"


def _make_rest_pr(
    *,
    num: int = 101,
    state: str = "open",
    draft: bool = False,
    base_ref: str = "main",
    head_sha: str = SHA_A,
    head_repo_full_name: str = REPO,
    head_repo_id: int = 1459043969,
    base_repo_full_name: str = REPO,
    base_repo_id: int = 1459043969,
    fork: bool = False,
    user_id: int | str | bool | None = OWNER_ID,
    user_login: str = "LittleHenderson",
    user_type: str = "User",
    app_id: int | None = None,
    labels: list[str] | None = None,
    mergeable_state: str = "clean",
) -> dict:
    user_doc: dict = {"login": user_login, "type": user_type}
    if user_id is not None:
        user_doc["id"] = user_id
    if app_id is not None:
        user_doc["app_id"] = app_id
    return {
        "number": num,
        "title": f"PR #{num}",
        "state": state,
        "draft": draft,
        "user": user_doc,
        "labels": [{"name": lb} for lb in (labels if labels is not None else ["agent-ready"])],
        "base": {
            "ref": base_ref,
            "repo": {"id": base_repo_id, "full_name": base_repo_full_name},
        },
        "head": {
            "ref": "fix/security-audit",
            "sha": head_sha,
            "repo": {"id": head_repo_id, "full_name": head_repo_full_name, "fork": fork},
        },
        "mergeable_state": mergeable_state,
    }


def _make_check_run(
    *,
    cr_id: int,
    name: str,
    status: str = "completed",
    conclusion: str = "success",
    app_id: int | None = 15368,
    head_sha: str = SHA_A,
    suite_id: int = 5001,
    run_id: int = 7001,
    include_inline_suite: bool = False,
    include_details_url: bool = True,
) -> dict:
    cr: dict = {
        "id": cr_id,
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "head_sha": head_sha,
        "check_suite": {"id": suite_id},
    }
    if include_inline_suite:
        cr["check_suite"]["head_sha"] = head_sha
        cr["check_suite"]["app"] = {"id": app_id}
    if app_id is not None:
        cr["app"] = {"id": app_id}
    if include_details_url:
        cr["details_url"] = f"https://github.com/{REPO}/actions/runs/{run_id}/job/{cr_id}"
    return cr


def _make_workflow_run(
    *,
    run_id: int = 7001,
    suite_id: int = 5001,
    workflow_id: int = 8801,
    path: str = ".github/workflows/ci.yml",
    event: str = "pull_request",
    head_sha: str = SHA_A,
    repo_full_name: str = REPO,
    head_repo_full_name: str | None = REPO,
) -> dict:
    wr: dict = {
        "id": run_id,
        "check_suite_id": suite_id,
        "workflow_id": workflow_id,
        "path": path,
        "event": event,
        "head_sha": head_sha,
        "repository": {"full_name": repo_full_name},
    }
    if head_repo_full_name is not None:
        wr["head_repository"] = {"full_name": head_repo_full_name}
    return wr


def _make_suite(
    *,
    suite_id: int = 5001,
    head_sha: str = SHA_A,
    app_id: int = 15368,
) -> dict:
    return {"id": suite_id, "head_sha": head_sha, "app": {"id": app_id}}


class Audit443a5c4AutoMergerFindingsTests(unittest.TestCase):
    def test_f14_rejects_same_owner_different_repo_and_forks(self) -> None:
        pol = agent_pr_merger.AutomergePolicy()

        # Same owner, DIFFERENT repo -> must be rejected!
        same_owner_diff_repo = {
            "number": 10,
            "state": "OPEN",
            "isDraft": False,
            "baseRefName": "main",
            "headRefOid": SHA_A,
            "headRepository": {"nameWithOwner": "LittleHenderson/other-repo"},
            "headRepositoryOwner": {"login": "LittleHenderson"},
            "author": {"id": OWNER_ID, "login": "LittleHenderson"},
            "labels": [{"name": "auto-merge"}],
        }
        ok, info = agent_pr_merger.authorize_pr_principal_and_repo(
            agent_pr_merger.normalize_pr_record(same_owner_diff_repo), pol
        )
        self.assertFalse(ok)
        self.assertEqual(info["action"], "SKIP_UNTRUSTED_HEAD_REPO")

        # External fork -> rejected
        fork_pr = _make_rest_pr(head_repo_full_name="attacker/cas-forex-revamp", fork=True)
        ok_f, info_f = agent_pr_merger.authorize_pr_principal_and_repo(
            agent_pr_merger.normalize_pr_record(fork_pr), pol
        )
        self.assertFalse(ok_f)
        self.assertEqual(info_f["action"], "SKIP_UNTRUSTED_HEAD_REPO")

        # Empty headRepository.nameWithOwner -> rejected (fail closed)
        empty_repo = dict(same_owner_diff_repo, headRepository={"nameWithOwner": ""})
        ok_e, info_e = agent_pr_merger.authorize_pr_principal_and_repo(
            agent_pr_merger.normalize_pr_record(empty_repo), pol
        )
        self.assertFalse(ok_e)
        self.assertEqual(info_e["action"], "SKIP_UNTRUSTED_HEAD_REPO")

        # head.repo.id mismatch against base.repo.id -> rejected
        id_mismatch = _make_rest_pr(head_repo_id=9999999)
        ok_id, _ = agent_pr_merger.authorize_pr_principal_and_repo(
            agent_pr_merger.normalize_pr_record(id_mismatch), pol
        )
        self.assertFalse(ok_id)

        # Exact case-insensitive owner+repo match -> accepted
        ci_match = _make_rest_pr(head_repo_full_name="littlehenderson/CAS-FOREX-REVAMP")
        ok_ci, _ = agent_pr_merger.authorize_pr_principal_and_repo(
            agent_pr_merger.normalize_pr_record(ci_match), pol
        )
        self.assertTrue(ok_ci)

    def test_f14_requires_immutable_numeric_author_and_bot_app_ids(self) -> None:
        pol = agent_pr_merger.AutomergePolicy()

        # Spoofed login matching owner but wrong numeric user ID
        spoof_login = _make_rest_pr(user_id=77777777, user_login="LittleHenderson")
        ok, info = agent_pr_merger.authorize_pr_principal_and_repo(
            agent_pr_merger.normalize_pr_record(spoof_login), pol
        )
        self.assertFalse(ok)
        self.assertEqual(info["action"], "SKIP_UNTRUSTED_AUTHOR")

        # Non-numeric GraphQL node ID string or bool rejected
        for bad_uid in ("U_kgDOBdtpkg", "98265490", True, 0, None):
            bad_pr = _make_rest_pr(user_id=bad_uid, user_login="LittleHenderson")
            ok_b, _ = agent_pr_merger.authorize_pr_principal_and_repo(
                agent_pr_merger.normalize_pr_record(bad_pr), pol
            )
            self.assertFalse(ok_b, f"Must reject non-numeric/invalid author id {bad_uid!r}")

        # Arbitrary *[bot] suffix rejected when bot app ID is not allowlisted
        evil_bot = _make_rest_pr(user_id=444444, user_login="evil-ci[bot]", user_type="Bot", app_id=55555)
        ok_bot, info_bot = agent_pr_merger.authorize_pr_principal_and_repo(
            agent_pr_merger.normalize_pr_record(evil_bot), pol
        )
        self.assertFalse(ok_bot)
        self.assertEqual(info_bot["action"], "SKIP_UNTRUSTED_AUTHOR")

        # Allowlisted bot App ID loaded from origin/main policy succeeds
        pol_with_bot = agent_pr_merger.load_automerge_policy({
            "revamp_completed": False,
            "automerge_policy": {
                "allowed_author_user_ids": [OWNER_ID],
                "allowed_approver_user_ids": [OWNER_ID],
                "allowed_bot_app_ids": [55555],
            },
        })
        ok_allowed_bot, _ = agent_pr_merger.authorize_pr_principal_and_repo(
            agent_pr_merger.normalize_pr_record(evil_bot), pol_with_bot
        )
        self.assertTrue(ok_allowed_bot)

    def test_f14_policy_validation_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            agent_pr_merger.load_automerge_policy({"automerge_policy": {"allowed_author_user_ids": []}})
        with self.assertRaises(ValueError):
            agent_pr_merger.load_automerge_policy({"automerge_policy": {"allowed_approver_user_ids": ["98265490"]}})
        with self.assertRaises(ValueError):
            agent_pr_merger.load_automerge_policy({"automerge_policy": {"trusted_workflow_paths": ["evil.yml"]}})

    def test_f14_labels_intent_only_and_sha_bound_approval_required(self) -> None:
        pol = agent_pr_merger.AutomergePolicy()

        # Labels auto-merge / agent-ready alone NEVER authorize merge
        ok_none, info_none = agent_pr_merger.verify_sha_bound_approval(101, SHA_A, [], [], pol)
        self.assertFalse(ok_none)
        self.assertEqual(info_none["action"], "SKIP_UNAPPROVED")

        # Labeled timeline event by owner does NOT satisfy SHA-bound approval
        labeled_ev = [{"id": 1, "event": "labeled", "actor": {"id": OWNER_ID}, "label": {"name": "auto-merge"}}]
        ok_lbl, _ = agent_pr_merger.verify_sha_bound_approval(101, SHA_A, [], labeled_ev, pol)
        self.assertFalse(ok_lbl)

        # Stale SHA approval rejected
        stale_rev = [{"id": 1, "state": "APPROVED", "commit_id": SHA_B, "user": {"id": OWNER_ID}}]
        ok_stale, _ = agent_pr_merger.verify_sha_bound_approval(101, SHA_A, stale_rev, [], pol)
        self.assertFalse(ok_stale)

        # Cross-PR review rejected
        cross_pr_rev = [{
            "id": 2,
            "state": "APPROVED",
            "commit_id": SHA_A,
            "user": {"id": OWNER_ID},
            "pull_request_url": f"https://api.github.com/repos/{REPO}/pulls/100",
        }]
        ok_xpr, _ = agent_pr_merger.verify_sha_bound_approval(101, SHA_A, cross_pr_rev, [], pol)
        self.assertFalse(ok_xpr)

        # Unallowlisted approver rejected even with owner login text
        wrong_approver = [{"id": 3, "state": "APPROVED", "commit_id": SHA_A, "user": {"id": 999, "login": "LittleHenderson"}}]
        ok_wa, _ = agent_pr_merger.verify_sha_bound_approval(101, SHA_A, wrong_approver, [], pol)
        self.assertFalse(ok_wa)

        # APPROVED then CHANGES_REQUESTED -> blocked
        superseded = [
            {"id": 1, "state": "APPROVED", "commit_id": SHA_A, "submitted_at": "2026-11-21T10:00:00Z", "user": {"id": OWNER_ID}},
            {"id": 2, "state": "CHANGES_REQUESTED", "commit_id": SHA_A, "submitted_at": "2026-11-21T10:05:00Z", "user": {"id": OWNER_ID}},
        ]
        ok_sup, info_sup = agent_pr_merger.verify_sha_bound_approval(101, SHA_A, superseded, [], pol)
        self.assertFalse(ok_sup)
        self.assertEqual(info_sup["action"], "SKIP_CHANGES_REQUESTED")

        # APPROVED then COMMENTED -> still valid
        valid_with_comment = [
            {"id": 1, "state": "APPROVED", "commit_id": SHA_A, "submitted_at": "2026-11-21T10:00:00Z", "user": {"id": OWNER_ID}},
            {"id": 2, "state": "COMMENTED", "commit_id": SHA_A, "submitted_at": "2026-11-21T10:05:00Z", "user": {"id": OWNER_ID}},
        ]
        ok_vc, info_vc = agent_pr_merger.verify_sha_bound_approval(101, SHA_A, valid_with_comment, [], pol)
        self.assertTrue(ok_vc)
        self.assertEqual(info_vc["approver_id"], OWNER_ID)

        # Timeline SHA-bound /approve command works and /hold revokes it
        tl_approve = [{"id": 10, "event": "commented", "created_at": "2026-11-21T10:00:00Z", "actor": {"id": OWNER_ID}, "body": f"/approve {SHA_A} pr=#101"}]
        ok_tl, _ = agent_pr_merger.verify_sha_bound_approval(101, SHA_A, [], tl_approve, pol)
        self.assertTrue(ok_tl)

        tl_revoked = tl_approve + [{"id": 11, "event": "commented", "created_at": "2026-11-21T10:01:00Z", "actor": {"id": OWNER_ID}, "body": "/hold"}]
        ok_rev, _ = agent_pr_merger.verify_sha_bound_approval(101, SHA_A, [], tl_revoked, pol)
        self.assertFalse(ok_rev)

        # Missing intent label -> SKIP_UNLABELED even with allowlisted author
        unlabeled = _make_rest_pr(labels=[])
        ok_ul, info_ul = agent_pr_merger.authorize_pr_principal_and_repo(
            agent_pr_merger.normalize_pr_record(unlabeled), pol
        )
        self.assertFalse(ok_ul)
        self.assertEqual(info_ul["action"], "SKIP_UNLABELED")

        # Hold label always blocks
        held = _make_rest_pr(labels=["auto-merge", "hold"])
        ok_hl, info_hl = agent_pr_merger.authorize_pr_principal_and_repo(
            agent_pr_merger.normalize_pr_record(held), pol
        )
        self.assertFalse(ok_hl)
        self.assertEqual(info_hl["action"], "SKIP_HOLD_LABEL")

    def test_f14_premerge_revalidation_aborts_on_race_mutations(self) -> None:
        pol = agent_pr_merger.AutomergePolicy()
        cases = [
            ("head_sha_changed", _make_rest_pr(head_sha=SHA_B)),
            ("turned_draft", _make_rest_pr(draft=True)),
            ("closed", _make_rest_pr(state="closed")),
            ("base_changed", _make_rest_pr(base_ref="develop")),
            ("head_repo_changed", _make_rest_pr(head_repo_full_name="LittleHenderson/other-repo")),
            ("hold_added", _make_rest_pr(labels=["auto-merge", "do-not-merge"])),
            ("author_changed", _make_rest_pr(user_id=999999)),
        ]
        for label, live_pr in cases:
            with self.subTest(case=label):
                ok, info = agent_pr_merger.revalidate_pr_before_merge(
                    live_pr, expected_pr_number=101, expected_sha=SHA_A, policy=pol
                )
                self.assertFalse(ok)
                self.assertEqual(info["action"], "ABORTED_HEAD_OR_BASE_CHANGED")

    def test_f15_paginates_all_check_runs_and_workflow_runs_beyond_100(self) -> None:
        # Page 1 has 100 filler passing checks; Page 2 has required CI checks (first failing, then passing)
        page1_crs = [
            _make_check_run(cr_id=1000 + i, name=f"Auxiliary Job {i}", run_id=7001)
            for i in range(100)
        ]
        page2_fail = [
            _make_check_run(cr_id=2001, name="Secret & Strict-CSP Gate", run_id=7001),
            _make_check_run(cr_id=2002, name="Node UI Suite", run_id=7001),
            _make_check_run(cr_id=2003, name="Python Unit & Contract Suites", conclusion="failure", run_id=7002),
        ]
        page1_wrs = [_make_workflow_run(run_id=7001, suite_id=5001)] * 100
        page2_wrs = [_make_workflow_run(run_id=7002, suite_id=5001)]
        suites = [_make_suite(suite_id=5001)]
        workflows = [{"id": 8801, "path": ".github/workflows/ci.yml", "state": "active"}]

        pr = _make_rest_pr()
        rev = [{"id": 1, "state": "APPROVED", "commit_id": SHA_A, "user": {"id": OWNER_ID}}]

        def fake_gh_json(args):
            ep = args[1] if args[0] == "api" else ""
            if ep.startswith(f"repos/{REPO}/pulls?"):
                return [pr]
            if ep == f"repos/{REPO}/pulls/101/reviews?per_page=100&page=1":
                return rev
            if ep == f"repos/{REPO}/commits/{SHA_A}/check-runs?per_page=100&page=1":
                return {"check_runs": page1_crs}
            if ep == f"repos/{REPO}/commits/{SHA_A}/check-runs?per_page=100&page=2":
                return {"check_runs": page2_fail}
            if ep == f"repos/{REPO}/actions/runs?head_sha={SHA_A}&per_page=100&page=1":
                return {"workflow_runs": page1_wrs}
            if ep == f"repos/{REPO}/actions/runs?head_sha={SHA_A}&per_page=100&page=2":
                return {"workflow_runs": page2_wrs}
            if ep.startswith(f"repos/{REPO}/actions/workflows"):
                return {"workflows": workflows}
            if ep.startswith(f"repos/{REPO}/commits/{SHA_A}/check-suites"):
                return {"check_suites": suites}
            raise AssertionError(f"Unexpected gh_json call: {args}")

        def fake_subp_run(cmd, **_kw):
            if len(cmd) >= 3 and cmd[1] == "show":
                return subprocess.CompletedProcess(cmd, 0, stdout='{"revamp_completed": false}', stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch.object(agent_pr_merger.subprocess, "run", side_effect=fake_subp_run):
            with patch.object(agent_pr_merger, "gh_json", side_effect=fake_gh_json):
                buf: list[str] = []
                with patch("builtins.print", side_effect=lambda s: buf.append(s)):
                    rc = agent_pr_merger.main()
        self.assertEqual(rc, 0)
        rep = json.loads("".join(buf))
        self.assertEqual(rep["actions"][0]["action"], "WAITING_CI_CHECKS")
        self.assertIn("Python Unit & Contract Suites:completed/failure", rep["actions"][0]["pending_or_failed"])

    def test_f15_rejects_spoofed_checks_and_prevents_shadowing_genuine_failures(self) -> None:
        pol = agent_pr_merger.AutomergePolicy()
        wf_ids = {".github/workflows/ci.yml": {8801}}
        genuine_wr = _make_workflow_run(run_id=7001, suite_id=5001, workflow_id=8801)
        genuine_suite = _make_suite(suite_id=5001)

        genuine_checks = [
            _make_check_run(cr_id=101, name="Secret & Strict-CSP Gate", conclusion="failure", run_id=7001, suite_id=5001),
            _make_check_run(cr_id=102, name="Node UI Suite", conclusion="success", run_id=7001, suite_id=5001),
            _make_check_run(cr_id=103, name="Python Unit & Contract Suites", conclusion="success", run_id=7001, suite_id=5001),
        ]

        spoof_variants = [
            (
                "untrusted_app_id",
                _make_check_run(cr_id=90001, name="Secret & Strict-CSP Gate", app_id=14658, suite_id=5001, run_id=7001),
                [],
                [],
            ),
            (
                "wrong_check_run_head_sha",
                _make_check_run(cr_id=90002, name="Secret & Strict-CSP Gate", head_sha=SHA_B, suite_id=5001, run_id=7001),
                [],
                [],
            ),
            (
                "untrusted_check_suite_app",
                _make_check_run(cr_id=90003, name="Secret & Strict-CSP Gate", suite_id=5002, run_id=7002),
                [_make_workflow_run(run_id=7002, suite_id=5002, workflow_id=8801)],
                [_make_suite(suite_id=5002, app_id=99999)],
            ),
            (
                "wrong_check_suite_head_sha",
                _make_check_run(cr_id=90004, name="Secret & Strict-CSP Gate", suite_id=5003, run_id=7003),
                [_make_workflow_run(run_id=7003, suite_id=5003, workflow_id=8801)],
                [_make_suite(suite_id=5003, head_sha=SHA_B)],
            ),
            (
                "untrusted_workflow_path",
                _make_check_run(cr_id=90005, name="Secret & Strict-CSP Gate", suite_id=5004, run_id=7004),
                [_make_workflow_run(run_id=7004, suite_id=5004, workflow_id=8801, path=".github/workflows/evil.yml")],
                [_make_suite(suite_id=5004)],
            ),
            (
                "wrong_workflow_id",
                _make_check_run(cr_id=90006, name="Secret & Strict-CSP Gate", suite_id=5005, run_id=7005),
                [_make_workflow_run(run_id=7005, suite_id=5005, workflow_id=9999)],
                [_make_suite(suite_id=5005)],
            ),
            (
                "untrusted_workflow_event",
                _make_check_run(cr_id=90007, name="Secret & Strict-CSP Gate", suite_id=5006, run_id=7006),
                [_make_workflow_run(run_id=7006, suite_id=5006, workflow_id=8801, event="pull_request_target")],
                [_make_suite(suite_id=5006)],
            ),
            (
                "wrong_workflow_repo",
                _make_check_run(cr_id=90008, name="Secret & Strict-CSP Gate", suite_id=5007, run_id=7007),
                [_make_workflow_run(run_id=7007, suite_id=5007, workflow_id=8801, repo_full_name="LittleHenderson/other-repo")],
                [_make_suite(suite_id=5007)],
            ),
            (
                "wrong_workflow_head_repo",
                _make_check_run(cr_id=90009, name="Secret & Strict-CSP Gate", suite_id=5008, run_id=7008),
                [_make_workflow_run(run_id=7008, suite_id=5008, workflow_id=8801, head_repo_full_name="attacker/cas-forex-revamp")],
                [_make_suite(suite_id=5008)],
            ),
            (
                "wrong_workflow_head_sha",
                _make_check_run(cr_id=90010, name="Secret & Strict-CSP Gate", suite_id=5009, run_id=7009),
                [_make_workflow_run(run_id=7009, suite_id=5009, workflow_id=8801, head_sha=SHA_B)],
                [_make_suite(suite_id=5009)],
            ),
            (
                "details_url_run_mismatch",
                _make_check_run(cr_id=90011, name="Secret & Strict-CSP Gate", suite_id=5001, run_id=7999),
                [],
                [],
            ),
        ]

        for label, spoof_cr, extra_wrs, extra_suites in spoof_variants:
            with self.subTest(spoof=label):
                ok, info = agent_pr_merger.evaluate_checks_fail_closed(
                    SHA_A,
                    genuine_checks + [spoof_cr],
                    [genuine_wr] + extra_wrs,
                    pol,
                    check_suites=[genuine_suite] + extra_suites,
                    trusted_workflow_ids_by_path=wf_ids,
                )
                self.assertFalse(ok)
                self.assertEqual(info["action"], "WAITING_CI_CHECKS")
                self.assertIn("Secret & Strict-CSP Gate:completed/failure", info["pending_or_failed"])
                self.assertTrue(len(info["rejected_untrusted_checks"]) >= 1)

        # If ALL check runs are spoofed, verified set is empty -> WAITING_CI_CHECKS_EMPTY
        only_spoofed = [
            _make_check_run(cr_id=91001, name="Secret & Strict-CSP Gate", app_id=14658),
            _make_check_run(cr_id=91002, name="Node UI Suite", app_id=14658),
            _make_check_run(cr_id=91003, name="Python Unit & Contract Suites", app_id=14658),
        ]
        ok_empty, info_empty = agent_pr_merger.evaluate_checks_fail_closed(
            SHA_A, only_spoofed, [genuine_wr], pol, check_suites=[genuine_suite], trusted_workflow_ids_by_path=wf_ids
        )
        self.assertFalse(ok_empty)
        self.assertEqual(info_empty["action"], "WAITING_CI_CHECKS_EMPTY")

    def test_f14_and_f15_end_to_end_happy_path_merges_with_match_head_commit(self) -> None:
        pr = _make_rest_pr(num=105, labels=["auto-merge"])
        rev = [{"id": 1, "state": "APPROVED", "commit_id": SHA_A, "user": {"id": OWNER_ID}}]
        crs = [
            _make_check_run(cr_id=201, name="Secret & Strict-CSP Gate"),
            _make_check_run(cr_id=202, name="Node UI Suite"),
            _make_check_run(cr_id=203, name="Python Unit & Contract Suites"),
        ]
        wrs = [_make_workflow_run(run_id=7001, suite_id=5001, workflow_id=8801)]
        suites = [_make_suite(suite_id=5001)]
        workflows = [{"id": 8801, "path": ".github/workflows/ci.yml", "state": "active"}]

        merge_cmds: list[list[str]] = []

        def fake_gh_json(args):
            ep = args[1] if args[0] == "api" else ""
            if ep.startswith(f"repos/{REPO}/pulls?"):
                return [pr]
            if ep == f"repos/{REPO}/pulls/105":
                return pr
            if ep == f"repos/{REPO}/pulls/105/reviews?per_page=100&page=1":
                return rev
            if ep == f"repos/{REPO}/commits/{SHA_A}/check-runs?per_page=100&page=1":
                return {"check_runs": crs}
            if ep == f"repos/{REPO}/actions/runs?head_sha={SHA_A}&per_page=100&page=1":
                return {"workflow_runs": wrs}
            if ep.startswith(f"repos/{REPO}/actions/workflows"):
                return {"workflows": workflows}
            if ep.startswith(f"repos/{REPO}/commits/{SHA_A}/check-suites"):
                return {"check_suites": suites}
            raise AssertionError(f"Unexpected gh_json call: {args}")

        def fake_subp_run(cmd, **_kw):
            if len(cmd) >= 3 and cmd[1] == "show":
                return subprocess.CompletedProcess(cmd, 0, stdout='{"revamp_completed": false}', stderr="")
            if len(cmd) >= 3 and cmd[0] == "gh" and cmd[1] == "pr" and cmd[2] == "merge":
                merge_cmds.append(list(cmd))
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch.object(agent_pr_merger.subprocess, "run", side_effect=fake_subp_run):
            with patch.object(agent_pr_merger, "gh_json", side_effect=fake_gh_json):
                with patch.object(agent_pr_merger, "verify_worktree_lightweight", return_value=(True, ["secret_scan=CLEAN"])):
                    buf: list[str] = []
                    with patch("builtins.print", side_effect=lambda s: buf.append(s)):
                        rc = agent_pr_merger.main()
        self.assertEqual(rc, 0)
        rep = json.loads("".join(buf))
        self.assertEqual(rep["actions"][0]["action"], "MERGED")
        self.assertEqual(len(merge_cmds), 1)
        self.assertIn("--match-head-commit", merge_cmds[0])
        self.assertIn(SHA_A, merge_cmds[0])

    def test_docs_workflow_and_readme_parity_and_no_active_github_workflow(self) -> None:
        self.assertFalse((REPO_ROOT / ".github" / "workflows").exists())

        wf_path = REPO_ROOT / "docs" / "github-workflows" / "agent-pr-automerge.yml"
        wf_txt = wf_path.read_text(encoding="utf-8")
        self.assertNotIn('or author_login.endswith("[bot]")', wf_txt)
        self.assertNotIn("head_owner != owner", wf_txt)
        self.assertIn("allowed_bot_app_ids", wf_txt)
        self.assertIn("15368", wf_txt)
        self.assertIn("98265490", wf_txt)
        self.assertIn(".github/workflows/ci.yml", wf_txt)
        self.assertIn("actions/runs", wf_txt)
        self.assertIn("check-suites", wf_txt)
        self.assertIn("APPROVED", wf_txt)
        self.assertIn("--match-head-commit", wf_txt)
        self.assertIn("WAITING_CI_CHECKS_EMPTY", wf_txt)

        wf_lines = wf_txt.splitlines()
        py_start = next(i for i, ln in enumerate(wf_lines) if ln.strip() == "run: |") + 1
        py_block = "\n".join(ln[10:] if len(ln) >= 10 else "" for ln in wf_lines[py_start:])
        ast.parse(py_block, filename=str(wf_path))

        # Execute the documented workflow Python logic under mocked gh responses
        same_owner_other_repo = _make_rest_pr(num=1, head_repo_full_name="LittleHenderson/other-repo")
        untrusted_bot = _make_rest_pr(num=2, user_id=333333, user_login="evil[bot]", user_type="Bot", app_id=4444)
        unapproved_labeled = _make_rest_pr(num=3, labels=["auto-merge", "agent-ready"])
        passing_auth_pr = _make_rest_pr(num=4, labels=["auto-merge"])

        def fake_wf_subp(cmd, **_kw):
            if cmd[:2] == ["gh", "api"]:
                ep = cmd[2]
                if ep.startswith(f"repos/{REPO}/actions/workflows"):
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"workflows": [{"id": 8801, "path": ".github/workflows/ci.yml", "state": "active"}]}), stderr="")
                if ep.startswith(f"repos/{REPO}/pulls?"):
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([same_owner_other_repo, untrusted_bot, unapproved_labeled, passing_auth_pr]), stderr="")
                if ep.startswith(f"repos/{REPO}/pulls/3/reviews"):
                    return subprocess.CompletedProcess(cmd, 0, stdout="[]", stderr="")
                if ep.startswith(f"repos/{REPO}/issues/3/timeline"):
                    return subprocess.CompletedProcess(cmd, 0, stdout="[]", stderr="")
                if ep.startswith(f"repos/{REPO}/pulls/4/reviews"):
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps([{"id": 1, "state": "APPROVED", "commit_id": SHA_A, "user": {"id": OWNER_ID}}]), stderr="")
                if ep == f"repos/{REPO}/pulls/4":
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(passing_auth_pr), stderr="")
                if ep.startswith(f"repos/{REPO}/commits/{SHA_A}/check-runs"):
                    crs = [
                        _make_check_run(cr_id=10, name="Secret & Strict-CSP Gate", conclusion="failure"),
                        _make_check_run(cr_id=99, name="Secret & Strict-CSP Gate", conclusion="success", app_id=14658),
                        _make_check_run(cr_id=11, name="Node UI Suite"),
                        _make_check_run(cr_id=12, name="Python Unit & Contract Suites"),
                    ]
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"check_runs": crs}), stderr="")
                if ep.startswith(f"repos/{REPO}/actions/runs"):
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"workflow_runs": [_make_workflow_run()]}), stderr="")
                if ep.startswith(f"repos/{REPO}/commits/{SHA_A}/check-suites"):
                    return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"check_suites": [_make_suite()]}), stderr="")
            raise AssertionError(f"Unexpected command in workflow execution test: {cmd}")

        orig_read_text = Path.read_text
        def fake_read_text(self_path, *args, **kwargs):
            if self_path.as_posix().endswith("docs/REVAMP_COMPLETION_GATE.json"):
                return '{"revamp_completed": false}'
            return orig_read_text(self_path, *args, **kwargs)

        captured: list[str] = []
        with patch("os.environ", {"REPO": REPO, "GH_TOKEN": "stub-token-value"}):
            with patch("subprocess.run", side_effect=fake_wf_subp):
                with patch("pathlib.Path.is_file", return_value=True):
                    with patch("pathlib.Path.read_text", fake_read_text):
                        with patch("builtins.print", side_effect=lambda *a: captured.append(" ".join(str(x) for x in a))):
                            exec(compile(py_block, str(wf_path), "exec"), {})  # nosec B102: intentional execution of pinned workflow YAML Python block against mocked gh subprocess in test
        joined = "\n".join(captured)
        self.assertIn("SKIP_UNTRUSTED_HEAD_REPO:LittleHenderson/other-repo", joined)
        self.assertIn("SKIP_UNTRUSTED_BOT_AUTHOR:333333:4444", joined)
        self.assertIn("missing SHA-bound owner approval", joined)
        self.assertIn("WAITING_CI_CHECKS:['Secret & Strict-CSP Gate:completed/failure']", joined)

        readme_lines = (REPO_ROOT / "README.md").read_text(encoding="utf-8").splitlines()
        readme_pair = "\n".join(readme_lines[12:14])
        self.assertIn("docs/github-workflows/agent-pr-automerge.yml", readme_pair)
        self.assertIn("not active `.github/workflows/...`", readme_pair)
        self.assertIn("headRepository.nameWithOwner", readme_pair)
        self.assertIn("APPROVED", readme_pair)
        self.assertIn("15368", readme_pair)


if __name__ == "__main__":
    unittest.main()
