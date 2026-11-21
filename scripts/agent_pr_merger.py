"""Periodic AI-Agent PR Verifier & Auto-Merger for LittleHenderson/cas-forex-revamp.

Continuously inspects open PRs targeting `main`, enforces completion-gate & immutable principal/head-repo
authorization, requires SHA-bound owner approval (labels are intent-only), verifies Secret/Strict-CSP/Syntax/
Contract gates plus provenance-verified paginated GitHub checks, updates behind branches, and squash-merges
passing PRs with `--match-head-commit` until `docs/REVAMP_COMPLETION_GATE.json` marks `revamp_completed: true`.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

REPO_SLUG = "LittleHenderson/cas-forex-revamp"

OWNER_USER_ID = 98265490  # Immutable GitHub numeric user ID for LittleHenderson
GITHUB_ACTIONS_APP_ID = 15368  # Immutable GitHub Actions App ID

ALLOWED_AUTHOR_USER_IDS: frozenset[int] = frozenset({OWNER_USER_ID})
ALLOWED_APPROVER_USER_IDS: frozenset[int] = frozenset({OWNER_USER_ID})
ALLOWED_BOT_APP_IDS: frozenset[int] = frozenset()

TRUSTED_CHECK_APP_IDS: frozenset[int] = frozenset({GITHUB_ACTIONS_APP_ID})
TRUSTED_WORKFLOW_PATHS: frozenset[str] = frozenset({".github/workflows/ci.yml"})
TRUSTED_WORKFLOW_IDS: frozenset[int] = frozenset()
TRUSTED_WORKFLOW_EVENTS: frozenset[str] = frozenset({"pull_request", "push"})

REQUIRED_CI_JOBS: frozenset[str] = frozenset({
    "Secret & Strict-CSP Gate",
    "Node UI Suite",
    "Python Unit & Contract Suites",
})

INTENT_LABELS: frozenset[str] = frozenset({
    "agent-pr",
    "automerge-ready",
    "auto-merge",
    "agent-ready",
})
HOLD_LABELS: frozenset[str] = frozenset({"do-not-merge", "hold"})

_SHA40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_APPROVE_CMD_RE = re.compile(
    r"^/approve\s+([0-9a-fA-F]{40})(?:\s+pr=#?(\d+))?$",
    re.IGNORECASE,
)
_REVOKE_CMD_RE = re.compile(r"^/(?:hold|reject|cancel)(?:\s|$)", re.IGNORECASE)
_RUN_URL_RE = re.compile(r"/actions/runs/(\d+)")
_PR_URL_NUM_RE = re.compile(r"(?:/repos/([^/]+/[^/]+))?/(?:pulls|issues)/(\d+)$")

SECRET_PATTERNS = [
    re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\b(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
]


@dataclass(frozen=True)
class AutomergePolicy:
    """Immutable authorization and CI provenance policy loaded from origin/main."""

    allowed_author_user_ids: frozenset[int] = ALLOWED_AUTHOR_USER_IDS
    allowed_approver_user_ids: frozenset[int] = ALLOWED_APPROVER_USER_IDS
    allowed_bot_app_ids: frozenset[int] = ALLOWED_BOT_APP_IDS
    trusted_check_app_ids: frozenset[int] = TRUSTED_CHECK_APP_IDS
    trusted_workflow_paths: frozenset[str] = TRUSTED_WORKFLOW_PATHS
    trusted_workflow_ids: frozenset[int] = TRUSTED_WORKFLOW_IDS
    trusted_workflow_events: frozenset[str] = TRUSTED_WORKFLOW_EVENTS
    required_ci_jobs: frozenset[str] = REQUIRED_CI_JOBS


def _is_positive_int(val: Any) -> bool:
    return isinstance(val, int) and not isinstance(val, bool) and val > 0


def _is_valid_sha(val: Any) -> bool:
    return isinstance(val, str) and bool(_SHA40_RE.fullmatch(val.strip()))


def _parse_int_id_set(raw: Any, field_name: str, *, allow_empty: bool = False) -> frozenset[int]:
    if not isinstance(raw, list):
        raise ValueError(f"{field_name} must be a list of positive integers")
    parsed: set[int] = set()
    for item in raw:
        if not _is_positive_int(item):
            raise ValueError(f"{field_name} contains non-positive or non-int ID: {item!r}")
        parsed.add(item)
    if not allow_empty and not parsed:
        raise ValueError(f"{field_name} must not be empty")
    return frozenset(parsed)


def _parse_str_set(raw: Any, field_name: str, *, allow_empty: bool = False) -> frozenset[str]:
    if not isinstance(raw, list):
        raise ValueError(f"{field_name} must be a list of strings")
    parsed: set[str] = set()
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{field_name} contains empty or non-string entry: {item!r}")
        parsed.add(item.strip())
    if not allow_empty and not parsed:
        raise ValueError(f"{field_name} must not be empty")
    return frozenset(parsed)


def load_automerge_policy(gate_doc: dict[str, Any]) -> AutomergePolicy:
    """Resolve automerge authorization & CI provenance policy strictly from origin/main gate JSON."""
    if not isinstance(gate_doc, dict):
        raise ValueError("gate_doc must be a JSON object")
    raw_pol = gate_doc.get("automerge_policy")
    if raw_pol is None:
        return AutomergePolicy()
    if not isinstance(raw_pol, dict):
        raise ValueError("automerge_policy must be a JSON object")

    author_ids = (
        _parse_int_id_set(raw_pol["allowed_author_user_ids"], "allowed_author_user_ids")
        if "allowed_author_user_ids" in raw_pol
        else ALLOWED_AUTHOR_USER_IDS
    )
    approver_ids = (
        _parse_int_id_set(raw_pol["allowed_approver_user_ids"], "allowed_approver_user_ids")
        if "allowed_approver_user_ids" in raw_pol
        else ALLOWED_APPROVER_USER_IDS
    )
    bot_app_ids = (
        _parse_int_id_set(raw_pol["allowed_bot_app_ids"], "allowed_bot_app_ids", allow_empty=True)
        if "allowed_bot_app_ids" in raw_pol
        else ALLOWED_BOT_APP_IDS
    )
    check_app_ids = (
        _parse_int_id_set(raw_pol["trusted_check_app_ids"], "trusted_check_app_ids")
        if "trusted_check_app_ids" in raw_pol
        else TRUSTED_CHECK_APP_IDS
    )
    wf_paths = (
        _parse_str_set(raw_pol["trusted_workflow_paths"], "trusted_workflow_paths")
        if "trusted_workflow_paths" in raw_pol
        else TRUSTED_WORKFLOW_PATHS
    )
    for wf_path in wf_paths:
        if not wf_path.startswith(".github/workflows/"):
            raise ValueError(f"trusted_workflow_paths entry must reside under .github/workflows/: {wf_path!r}")
    wf_ids = (
        _parse_int_id_set(raw_pol["trusted_workflow_ids"], "trusted_workflow_ids", allow_empty=True)
        if "trusted_workflow_ids" in raw_pol
        else TRUSTED_WORKFLOW_IDS
    )
    wf_events = (
        _parse_str_set(raw_pol["trusted_workflow_events"], "trusted_workflow_events")
        if "trusted_workflow_events" in raw_pol
        else TRUSTED_WORKFLOW_EVENTS
    )
    req_jobs = (
        _parse_str_set(raw_pol["required_ci_jobs"], "required_ci_jobs")
        if "required_ci_jobs" in raw_pol
        else REQUIRED_CI_JOBS
    )
    return AutomergePolicy(
        allowed_author_user_ids=author_ids,
        allowed_approver_user_ids=approver_ids,
        allowed_bot_app_ids=bot_app_ids,
        trusted_check_app_ids=check_app_ids,
        trusted_workflow_paths=wf_paths,
        trusted_workflow_ids=wf_ids,
        trusted_workflow_events=wf_events,
        required_ci_jobs=req_jobs,
    )


def gh_json(args: list[str]):
    res = subprocess.run(["gh"] + args, capture_output=True, text=True, check=True, timeout=60)
    return json.loads(res.stdout) if res.stdout.strip() else {}


def gh_paginate(
    endpoint_base: str,
    *,
    item_key: str | None = None,
    per_page: int = 100,
    max_pages: int = 100,
) -> list[dict[str, Any]]:
    """Fetch ALL pages from a GitHub REST API endpoint using explicit per_page/page pagination."""
    sep = "&" if "?" in endpoint_base else "?"
    items: list[dict[str, Any]] = []
    for page in range(1, max_pages + 1):
        url = f"{endpoint_base}{sep}per_page={per_page}&page={page}"
        doc = gh_json(["api", url])
        if item_key is None:
            if not isinstance(doc, list):
                raise ValueError(f"Expected list response from {url}, got {type(doc).__name__}")
            batch = doc
        else:
            if not isinstance(doc, dict) or not isinstance(doc.get(item_key, []), list):
                raise ValueError(f"Expected dict[{item_key!r}] list from {url}")
            batch = doc.get(item_key, [])
        items.extend(batch)
        if len(batch) < per_page:
            return items
    raise RuntimeError(f"Pagination exceeded max_pages={max_pages} for {endpoint_base}")


def normalize_pr_record(raw_pr: dict[str, Any]) -> dict[str, Any]:
    """Normalize either GitHub REST PR JSON or gh CLI GraphQL PR JSON into a canonical record."""
    if not isinstance(raw_pr, dict):
        return {}
    num = raw_pr.get("number")
    title = str(raw_pr.get("title") or "")
    raw_state = str(raw_pr.get("state") or "").strip().upper()

    if "isDraft" in raw_pr:
        is_draft = bool(raw_pr.get("isDraft"))
    elif "draft" in raw_pr:
        is_draft = bool(raw_pr.get("draft"))
    else:
        is_draft = True

    base_obj = raw_pr.get("base") if isinstance(raw_pr.get("base"), dict) else {}
    head_obj = raw_pr.get("head") if isinstance(raw_pr.get("head"), dict) else {}
    base_repo_obj = base_obj.get("repo") if isinstance(base_obj.get("repo"), dict) else {}
    head_repo_rest = head_obj.get("repo") if isinstance(head_obj.get("repo"), dict) else {}
    head_repo_gql = raw_pr.get("headRepository") if isinstance(raw_pr.get("headRepository"), dict) else {}
    base_repo_gql = raw_pr.get("baseRepository") if isinstance(raw_pr.get("baseRepository"), dict) else {}

    base_ref = str(raw_pr.get("baseRefName") or base_obj.get("ref") or "").strip()
    head_ref = str(raw_pr.get("headRefName") or head_obj.get("ref") or "").strip()
    head_sha = str(raw_pr.get("headRefOid") or head_obj.get("sha") or "").strip()

    head_repo_name = str(
        head_repo_gql.get("nameWithOwner") or head_repo_rest.get("full_name") or ""
    ).strip()
    base_repo_name = str(
        base_repo_gql.get("nameWithOwner") or base_repo_obj.get("full_name") or ""
    ).strip()

    head_repo_id = head_repo_rest.get("id")
    base_repo_id = base_repo_obj.get("id")
    is_fork_repo = bool(head_repo_rest.get("fork") is True or raw_pr.get("isCrossRepository") is True)

    actor = raw_pr.get("author") if isinstance(raw_pr.get("author"), dict) else raw_pr.get("user")
    if not isinstance(actor, dict):
        actor = {}
    raw_author_id = actor.get("id") if _is_positive_int(actor.get("id")) else actor.get("databaseId")
    author_id = raw_author_id if _is_positive_int(raw_author_id) else None
    author_login = str(actor.get("login") or "").strip()
    actor_type = str(actor.get("type") or "").strip()
    is_bot = bool(actor.get("is_bot") is True or actor_type == "Bot" or author_login.endswith("[bot]"))

    raw_bot_app_id = actor.get("app_id") if actor.get("app_id") is not None else raw_pr.get("author_app_id")
    bot_app_id = raw_bot_app_id if _is_positive_int(raw_bot_app_id) else None

    labels: set[str] = set()
    for lb in (raw_pr.get("labels") or []):
        if isinstance(lb, dict) and isinstance(lb.get("name"), str) and lb["name"].strip():
            labels.add(lb["name"].strip().lower())

    merge_state = str(raw_pr.get("mergeStateStatus") or raw_pr.get("mergeable_state") or "").strip().upper()

    return {
        "number": num if _is_positive_int(num) else None,
        "title": title,
        "state": raw_state,
        "is_draft": is_draft,
        "base_ref": base_ref,
        "base_repo_name": base_repo_name,
        "base_repo_id": base_repo_id if _is_positive_int(base_repo_id) else None,
        "head_ref": head_ref,
        "head_sha": head_sha,
        "head_repo_name": head_repo_name,
        "head_repo_id": head_repo_id if _is_positive_int(head_repo_id) else None,
        "is_fork_repo": is_fork_repo,
        "author_id": author_id,
        "author_login": author_login,
        "is_bot": is_bot,
        "bot_app_id": bot_app_id,
        "labels": frozenset(labels),
        "merge_state": merge_state,
    }


def authorize_pr_principal_and_repo(
    pr_norm: dict[str, Any],
    policy: AutomergePolicy,
    *,
    repo_slug: str = REPO_SLUG,
) -> tuple[bool, dict[str, Any]]:
    """Enforce exact headRepository.nameWithOwner, immutable author/bot IDs, and label intent rules."""
    if not _is_positive_int(pr_norm.get("number")):
        return False, {"action": "SKIP_INVALID_PR", "reason": "missing_pr_number"}
    if pr_norm.get("state") != "OPEN":
        return False, {"action": "SKIP_NOT_OPEN", "state": pr_norm.get("state")}
    if pr_norm.get("is_draft"):
        return False, {"action": "SKIP_DRAFT"}
    if pr_norm.get("base_ref") != "main":
        return False, {"action": "SKIP_WRONG_BASE", "base_ref": pr_norm.get("base_ref")}
    if not _is_valid_sha(pr_norm.get("head_sha")):
        return False, {"action": "SKIP_INVALID_HEAD_SHA"}

    head_repo_name = pr_norm.get("head_repo_name") or ""
    if (
        pr_norm.get("is_fork_repo")
        or not head_repo_name
        or head_repo_name.lower() != repo_slug.lower()
    ):
        return False, {
            "action": "SKIP_UNTRUSTED_HEAD_REPO",
            "head_repository": head_repo_name,
            "expected_repository": repo_slug,
        }

    base_repo_name = pr_norm.get("base_repo_name") or ""
    if base_repo_name and base_repo_name.lower() != repo_slug.lower():
        return False, {
            "action": "SKIP_UNTRUSTED_BASE_REPO",
            "base_repository": base_repo_name,
            "expected_repository": repo_slug,
        }

    head_repo_id = pr_norm.get("head_repo_id")
    base_repo_id = pr_norm.get("base_repo_id")
    if head_repo_id is not None and base_repo_id is not None and head_repo_id != base_repo_id:
        return False, {
            "action": "SKIP_UNTRUSTED_HEAD_REPO",
            "reason": "head_repo_id_mismatch",
            "head_repo_id": head_repo_id,
            "base_repo_id": base_repo_id,
        }

    author_id = pr_norm.get("author_id")
    bot_app_id = pr_norm.get("bot_app_id")
    is_bot = bool(pr_norm.get("is_bot"))

    if is_bot:
        app_allowed = bot_app_id is not None and bot_app_id in policy.allowed_bot_app_ids
        user_allowed = (
            author_id is not None
            and author_id in policy.allowed_author_user_ids
            and (bot_app_id is None or bot_app_id in policy.allowed_bot_app_ids)
        )
        if not (app_allowed or user_allowed):
            return False, {
                "action": "SKIP_UNTRUSTED_AUTHOR",
                "reason": "bot_not_in_immutable_allowlist",
                "author_id": author_id,
                "bot_app_id": bot_app_id,
            }
    else:
        if author_id is None or author_id not in policy.allowed_author_user_ids:
            return False, {
                "action": "SKIP_UNTRUSTED_AUTHOR",
                "reason": "author_id_not_in_immutable_allowlist",
                "author_id": author_id,
            }

    labels: frozenset[str] = pr_norm.get("labels") or frozenset()
    if labels & HOLD_LABELS:
        return False, {"action": "SKIP_HOLD_LABEL"}
    if not (labels & INTENT_LABELS):
        return False, {"action": "SKIP_UNLABELED"}

    return True, {}


def _extract_actor_id(record: dict[str, Any]) -> int | None:
    for key in ("user", "author", "actor"):
        obj = record.get(key)
        if isinstance(obj, dict):
            raw_id = obj.get("id") if _is_positive_int(obj.get("id")) else obj.get("databaseId")
            if _is_positive_int(raw_id):
                return raw_id
    return None


def _matches_pr_number(record: dict[str, Any], pr_number: int, repo_slug: str = REPO_SLUG) -> bool:
    explicit_pr = record.get("pull_request_number") or record.get("pr_number")
    if explicit_pr is not None and explicit_pr != pr_number:
        return False
    for url_key in ("pull_request_url", "issue_url"):
        url_val = record.get(url_key)
        if url_val is not None:
            if not isinstance(url_val, str):
                return False
            m = _PR_URL_NUM_RE.search(url_val.strip())
            if not m:
                return False
            url_repo, url_num = m.group(1), int(m.group(2))
            if url_num != pr_number:
                return False
            if url_repo is not None and url_repo.lower() != repo_slug.lower():
                return False
    return True


def verify_sha_bound_approval(
    pr_number: int,
    head_sha: str,
    reviews: list[dict[str, Any]],
    timeline_events: list[dict[str, Any]],
    policy: AutomergePolicy,
    *,
    repo_slug: str = REPO_SLUG,
) -> tuple[bool, dict[str, Any]]:
    """Require immutable allowlisted approver event strictly bound to (pr_number, head_sha)."""
    if not _is_positive_int(pr_number) or not _is_valid_sha(head_sha):
        return False, {"action": "SKIP_UNAPPROVED", "reason": "invalid_pr_or_sha"}
    target_sha = head_sha.lower()

    if not isinstance(reviews, list) or not isinstance(timeline_events, list):
        return False, {"action": "SKIP_UNAPPROVED", "reason": "malformed_review_or_timeline_payload"}

    latest_review_by_approver: dict[int, tuple[str, str, int]] = {}
    ordered_reviews: list[tuple[str, int, int, dict[str, Any]]] = []
    for idx, rev in enumerate(reviews):
        if not isinstance(rev, dict) or not _matches_pr_number(rev, pr_number, repo_slug=repo_slug):
            continue
        ts = str(rev.get("submitted_at") or rev.get("created_at") or "")
        rid = rev.get("id") if _is_positive_int(rev.get("id")) else idx + 1
        ordered_reviews.append((ts, rid, idx, rev))
    ordered_reviews.sort(key=lambda item: (item[0], item[1], item[2]))

    for _ts, rid, _idx, rev in ordered_reviews:
        approver_id = _extract_actor_id(rev)
        if approver_id is None or approver_id not in policy.allowed_approver_user_ids:
            continue
        state = str(rev.get("state") or "").strip().upper()
        commit_obj = rev.get("commit") if isinstance(rev.get("commit"), dict) else {}
        rev_sha = str(rev.get("commit_id") or commit_obj.get("oid") or "").strip().lower()
        if state in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest_review_by_approver[approver_id] = (state, rev_sha, rid)

    ordered_timeline: list[tuple[str, int, int, dict[str, Any]]] = []
    for idx, ev in enumerate(timeline_events):
        if not isinstance(ev, dict) or not _matches_pr_number(ev, pr_number, repo_slug=repo_slug):
            continue
        ts = str(ev.get("submitted_at") or ev.get("created_at") or "")
        eid = ev.get("id") if _is_positive_int(ev.get("id")) else idx + 1
        ordered_timeline.append((ts, eid, idx, ev))
    ordered_timeline.sort(key=lambda item: (item[0], item[1], item[2]))

    sha_bound_comment_approvals: dict[int, tuple[str, int]] = {}
    for ts, eid, idx, ev in ordered_timeline:
        ev_type = str(ev.get("event") or "").strip().lower()
        approver_id = _extract_actor_id(ev)
        if approver_id is None or approver_id not in policy.allowed_approver_user_ids:
            continue
        if ev_type == "reviewed":
            state = str(ev.get("state") or "").strip().upper()
            rev_sha = str(ev.get("commit_id") or "").strip().lower()
            if state in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
                latest_review_by_approver[approver_id] = (state, rev_sha, eid)
        elif ev_type == "commented":
            body = str(ev.get("body") or "")
            for raw_line in body.splitlines():
                line = raw_line.strip()
                m = _APPROVE_CMD_RE.fullmatch(line)
                if m:
                    cmd_sha = m.group(1).lower()
                    cmd_pr = int(m.group(2)) if m.group(2) is not None else pr_number
                    if cmd_sha == target_sha and cmd_pr == pr_number:
                        sha_bound_comment_approvals[approver_id] = (ts, idx)
                elif _REVOKE_CMD_RE.match(line):
                    sha_bound_comment_approvals.pop(approver_id, None)

    for approver_id, (state, _rev_sha, _rid) in latest_review_by_approver.items():
        if state == "CHANGES_REQUESTED":
            return False, {
                "action": "SKIP_CHANGES_REQUESTED",
                "approver_id": approver_id,
                "pr": pr_number,
                "head_sha": head_sha,
            }

    for approver_id, (state, rev_sha, rid) in sorted(latest_review_by_approver.items()):
        if state == "APPROVED" and rev_sha == target_sha:
            return True, {
                "approval_source": "pr_review",
                "approver_id": approver_id,
                "review_id": rid,
                "pr": pr_number,
                "head_sha": head_sha,
            }

    if sha_bound_comment_approvals:
        approver_id = sorted(sha_bound_comment_approvals.keys())[0]
        return True, {
            "approval_source": "timeline_sha_approval",
            "approver_id": approver_id,
            "pr": pr_number,
            "head_sha": head_sha,
        }

    return False, {
        "action": "SKIP_UNAPPROVED",
        "reason": "missing_sha_bound_owner_approval",
        "pr": pr_number,
        "head_sha": head_sha,
    }


def resolve_trusted_workflow_ids(
    workflows: list[dict[str, Any]],
    policy: AutomergePolicy,
) -> dict[str, set[int]]:
    """Map default-branch workflow paths in policy.trusted_workflow_paths to immutable workflow IDs."""
    by_path: dict[str, set[int]] = {}
    if not isinstance(workflows, list):
        return by_path
    for wf in workflows:
        if not isinstance(wf, dict):
            continue
        wf_id = wf.get("id")
        wf_path = str(wf.get("path") or "").strip()
        wf_state = str(wf.get("state") or "active").strip().lower()
        if (
            _is_positive_int(wf_id)
            and wf_path in policy.trusted_workflow_paths
            and wf_state == "active"
        ):
            by_path.setdefault(wf_path, set()).add(wf_id)
    return by_path


def _extract_run_id_from_urls(cr: dict[str, Any]) -> int | None:
    for url_key in ("details_url", "html_url"):
        val = cr.get(url_key)
        if isinstance(val, str):
            m = _RUN_URL_RE.search(val)
            if m:
                return int(m.group(1))
    return None


def _validate_check_run_provenance(
    cr: dict[str, Any],
    *,
    commit_sha: str,
    policy: AutomergePolicy,
    repo_slug: str,
    suites_by_id: dict[int, dict[str, Any]],
    runs_by_id: dict[int, dict[str, Any]],
    runs_by_suite_id: dict[int, list[dict[str, Any]]],
    trusted_workflow_ids_by_path: dict[str, set[int]],
) -> tuple[bool, str]:
    if not isinstance(cr, dict):
        return False, "non_dict_check_run"
    if not _is_positive_int(cr.get("id")):
        return False, "invalid_check_run_id"
    if not isinstance(cr.get("name"), str) or not cr["name"].strip():
        return False, "missing_check_run_name"

    app_obj = cr.get("app") if isinstance(cr.get("app"), dict) else {}
    app_id = app_obj.get("id")
    if not _is_positive_int(app_id) or app_id not in policy.trusted_check_app_ids:
        return False, f"untrusted_app_id:{app_id!r}"

    cr_sha = str(cr.get("head_sha") or "").strip().lower()
    if cr_sha != commit_sha.lower():
        return False, f"head_sha_mismatch:{cr_sha!r}"

    cr_suite = cr.get("check_suite")
    if not isinstance(cr_suite, dict) or not _is_positive_int(cr_suite.get("id")):
        return False, "missing_check_suite"
    suite_id: int = cr_suite["id"]

    inline_suite_sha = cr_suite.get("head_sha")
    inline_suite_app = (cr_suite.get("app") or {}).get("id") if isinstance(cr_suite.get("app"), dict) else None
    fetched_suite = suites_by_id.get(suite_id)

    if inline_suite_sha is not None and str(inline_suite_sha).strip().lower() != commit_sha.lower():
        return False, "inline_check_suite_sha_mismatch"
    if inline_suite_app is not None and (
        not _is_positive_int(inline_suite_app) or inline_suite_app not in policy.trusted_check_app_ids
    ):
        return False, f"inline_check_suite_untrusted_app:{inline_suite_app!r}"

    if fetched_suite is not None:
        fs_sha = str(fetched_suite.get("head_sha") or "").strip().lower()
        fs_app = (fetched_suite.get("app") or {}).get("id") if isinstance(fetched_suite.get("app"), dict) else None
        if fs_sha != commit_sha.lower():
            return False, "fetched_check_suite_sha_mismatch"
        if not _is_positive_int(fs_app) or fs_app not in policy.trusted_check_app_ids:
            return False, f"fetched_check_suite_untrusted_app:{fs_app!r}"
    elif inline_suite_sha is None or inline_suite_app is None:
        return False, f"unverified_check_suite:{suite_id}"

    url_run_id = _extract_run_id_from_urls(cr)
    if url_run_id is not None:
        wr = runs_by_id.get(url_run_id)
        if wr is None or wr.get("check_suite_id") != suite_id:
            return False, f"workflow_run_url_mismatch:{url_run_id}"
    else:
        candidates = runs_by_suite_id.get(suite_id) or []
        if len(candidates) != 1:
            return False, f"ambiguous_or_missing_workflow_run_for_suite:{suite_id}:{len(candidates)}"
        wr = candidates[0]

    wr_repo = ((wr.get("repository") or {}).get("full_name") or "") if isinstance(wr.get("repository"), dict) else ""
    if wr_repo.strip().lower() != repo_slug.lower():
        return False, f"workflow_run_repo_mismatch:{wr_repo!r}"

    if isinstance(wr.get("head_repository"), dict):
        wr_head_repo = str(wr["head_repository"].get("full_name") or "").strip()
        if wr_head_repo.lower() != repo_slug.lower():
            return False, f"workflow_run_head_repo_mismatch:{wr_head_repo!r}"

    wr_sha = str(wr.get("head_sha") or "").strip().lower()
    if wr_sha != commit_sha.lower():
        return False, f"workflow_run_sha_mismatch:{wr_sha!r}"

    wr_event = str(wr.get("event") or "").strip()
    if wr_event not in policy.trusted_workflow_events:
        return False, f"untrusted_workflow_event:{wr_event!r}"

    wr_path = str(wr.get("path") or "").strip()
    if wr_path not in policy.trusted_workflow_paths:
        return False, f"untrusted_workflow_path:{wr_path!r}"

    wr_wf_id = wr.get("workflow_id")
    if not _is_positive_int(wr_wf_id):
        return False, f"invalid_workflow_id:{wr_wf_id!r}"

    if policy.trusted_workflow_ids and wr_wf_id not in policy.trusted_workflow_ids:
        return False, f"untrusted_policy_workflow_id:{wr_wf_id}"

    expected_path_ids = trusted_workflow_ids_by_path.get(wr_path)
    if expected_path_ids and wr_wf_id not in expected_path_ids:
        return False, f"workflow_id_mismatch_for_path:{wr_wf_id}"

    return True, "ok"


def evaluate_checks_fail_closed(
    commit_sha: str,
    check_runs: list[dict[str, Any]],
    workflow_runs: list[dict[str, Any]],
    policy: AutomergePolicy,
    *,
    check_suites: list[dict[str, Any]] | None = None,
    trusted_workflow_ids_by_path: dict[str, set[int]] | None = None,
    repo_slug: str = REPO_SLUG,
) -> tuple[bool, dict[str, Any]]:
    """Verify all required CI check runs with strict App/check_suite/workflow_run provenance."""
    if not _is_valid_sha(commit_sha):
        return False, {"action": "WAITING_CI_CHECKS_EMPTY", "reason": "invalid commit_sha"}
    if not check_runs:
        return False, {"action": "WAITING_CI_CHECKS_EMPTY", "reason": "zero check_runs recorded"}

    suites_by_id: dict[int, dict[str, Any]] = {}
    for cs in (check_suites or []):
        if isinstance(cs, dict) and _is_positive_int(cs.get("id")):
            suites_by_id[cs["id"]] = cs

    runs_by_id: dict[int, dict[str, Any]] = {}
    runs_by_suite_id: dict[int, list[dict[str, Any]]] = {}
    for wr in (workflow_runs or []):
        if not isinstance(wr, dict) or not _is_positive_int(wr.get("id")):
            continue
        runs_by_id[wr["id"]] = wr
        cs_id = wr.get("check_suite_id")
        if _is_positive_int(cs_id):
            runs_by_suite_id.setdefault(cs_id, []).append(wr)

    wf_id_map = trusted_workflow_ids_by_path or {}
    latest_by_name: dict[str, dict[str, Any]] = {}
    rejected_checks: list[dict[str, Any]] = []

    for cr in check_runs:
        cname = str(cr.get("name") or "") if isinstance(cr, dict) else ""
        if cname == "Periodically Verify & Merge Passing AI-Agent PRs":
            continue
        ok, reason = _validate_check_run_provenance(
            cr,
            commit_sha=commit_sha,
            policy=policy,
            repo_slug=repo_slug,
            suites_by_id=suites_by_id,
            runs_by_id=runs_by_id,
            runs_by_suite_id=runs_by_suite_id,
            trusted_workflow_ids_by_path=wf_id_map,
        )
        if not ok:
            rejected_checks.append({
                "id": cr.get("id") if isinstance(cr, dict) else None,
                "name": cname,
                "reason": reason,
            })
            continue
        prev = latest_by_name.get(cname)
        if prev is None or int(cr["id"]) > int(prev["id"]):
            latest_by_name[cname] = cr

    if not latest_by_name:
        return False, {
            "action": "WAITING_CI_CHECKS_EMPTY",
            "reason": "zero provenance-verified check_runs recorded",
            "rejected_untrusted_checks": rejected_checks,
        }

    missing = sorted(policy.required_ci_jobs - set(latest_by_name.keys()))
    if missing:
        return False, {
            "action": "WAITING_REQUIRED_CI_JOBS",
            "missing": missing,
            "rejected_untrusted_checks": rejected_checks,
        }

    bad = [
        f"{cname}:{cr.get('status')}/{cr.get('conclusion')}"
        for cname, cr in sorted(latest_by_name.items())
        if cr.get("status") != "completed" or cr.get("conclusion") != "success"
    ]
    if bad:
        return False, {
            "action": "WAITING_CI_CHECKS",
            "pending_or_failed": bad,
            "rejected_untrusted_checks": rejected_checks,
        }

    return True, {"verified_check_ids": {k: v["id"] for k, v in sorted(latest_by_name.items())}}


def revalidate_pr_before_merge(
    live_pr_raw: dict[str, Any],
    *,
    expected_pr_number: int,
    expected_sha: str,
    policy: AutomergePolicy,
    repo_slug: str = REPO_SLUG,
) -> tuple[bool, dict[str, Any]]:
    """Revalidate all PR state, head-repo, principal, and label invariants immediately before merge."""
    live_norm = normalize_pr_record(live_pr_raw)
    if live_norm.get("number") not in (None, expected_pr_number):
        return False, {"action": "ABORTED_HEAD_OR_BASE_CHANGED", "reason": "pr_number_mismatch"}
    if live_norm.get("number") is None:
        live_norm["number"] = expected_pr_number
    if live_norm.get("head_sha", "").lower() != expected_sha.lower():
        return False, {
            "action": "ABORTED_HEAD_OR_BASE_CHANGED",
            "expected_sha": expected_sha,
            "live_sha": live_norm.get("head_sha"),
        }
    ok, fail_info = authorize_pr_principal_and_repo(live_norm, policy, repo_slug=repo_slug)
    if not ok:
        detail = dict(fail_info)
        reason_action = detail.pop("action", "REVALIDATION_FAILED")
        return False, {
            "action": "ABORTED_HEAD_OR_BASE_CHANGED",
            "reason_action": reason_action,
            "expected_sha": expected_sha,
            **detail,
        }
    return True, {}


def _fetch_checks_for_sha(
    commit_sha: str,
    policy: AutomergePolicy,
    *,
    trusted_workflow_ids_by_path: dict[str, set[int]] | None = None,
    repo_slug: str = REPO_SLUG,
) -> tuple[bool, dict[str, Any], dict[str, set[int]]]:
    check_runs = gh_paginate(f"repos/{repo_slug}/commits/{commit_sha}/check-runs", item_key="check_runs")
    if not check_runs:
        return False, {"action": "WAITING_CI_CHECKS_EMPTY", "reason": "zero check_runs recorded"}, trusted_workflow_ids_by_path or {}

    workflow_runs = gh_paginate(f"repos/{repo_slug}/actions/runs?head_sha={commit_sha}", item_key="workflow_runs")

    if trusted_workflow_ids_by_path is None:
        workflows = gh_paginate(f"repos/{repo_slug}/actions/workflows", item_key="workflows")
        trusted_workflow_ids_by_path = resolve_trusted_workflow_ids(workflows, policy)

    needs_suites = any(
        not isinstance(cr.get("check_suite"), dict)
        or cr["check_suite"].get("head_sha") is None
        or cr["check_suite"].get("app") is None
        for cr in check_runs
        if isinstance(cr, dict)
    )
    check_suites = (
        gh_paginate(f"repos/{repo_slug}/commits/{commit_sha}/check-suites", item_key="check_suites")
        if needs_suites
        else []
    )
    ok, info = evaluate_checks_fail_closed(
        commit_sha,
        check_runs,
        workflow_runs,
        policy,
        check_suites=check_suites,
        trusted_workflow_ids_by_path=trusted_workflow_ids_by_path,
        repo_slug=repo_slug,
    )
    return ok, info, trusted_workflow_ids_by_path


def _fetch_and_verify_approval(
    pr_number: int,
    head_sha: str,
    policy: AutomergePolicy,
    *,
    repo_slug: str = REPO_SLUG,
) -> tuple[bool, dict[str, Any]]:
    reviews = gh_paginate(f"repos/{repo_slug}/pulls/{pr_number}/reviews")
    ok_rev, info_rev = verify_sha_bound_approval(
        pr_number, head_sha, reviews, [], policy, repo_slug=repo_slug
    )
    if ok_rev or info_rev.get("action") == "SKIP_CHANGES_REQUESTED":
        return ok_rev, info_rev
    timeline = gh_paginate(f"repos/{repo_slug}/issues/{pr_number}/timeline")
    return verify_sha_bound_approval(
        pr_number, head_sha, reviews, timeline, policy, repo_slug=repo_slug
    )


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

    # 1. Check completion gate & immutable policy on origin/main
    gate_raw = subprocess.run(
        ["git", "show", "origin/main:docs/REVAMP_COMPLETION_GATE.json"],
        cwd=str(repo_root), capture_output=True, text=True, check=True, timeout=30,
    ).stdout
    gate = json.loads(gate_raw)
    if gate.get("revamp_completed") is True:
        print(json.dumps({"status": "HALTED_REVAMP_COMPLETED", "gate": gate}, indent=2))
        return 0

    policy = load_automerge_policy(gate)

    prs = gh_paginate(f"repos/{REPO_SLUG}/pulls?state=open&base=main")

    actions: list[dict[str, Any]] = []
    trusted_wf_ids_by_path: dict[str, set[int]] | None = None

    for raw_pr in sorted(prs, key=lambda x: x["number"]):
        pr_norm = normalize_pr_record(raw_pr)
        num = pr_norm.get("number")
        if not _is_positive_int(num):
            actions.append({"pr": raw_pr.get("number"), "action": "SKIP_INVALID_PR"})
            continue

        title = pr_norm["title"]
        auth_ok, auth_fail = authorize_pr_principal_and_repo(pr_norm, policy, repo_slug=REPO_SLUG)
        if not auth_ok:
            actions.append({"pr": num, **auth_fail})
            continue

        sha = pr_norm["head_sha"]
        approval_ok, approval_info = _fetch_and_verify_approval(num, sha, policy, repo_slug=REPO_SLUG)
        if not approval_ok:
            actions.append({"pr": num, **approval_info})
            continue

        if not pr_norm["merge_state"]:
            detail_pr = gh_json(["api", f"repos/{REPO_SLUG}/pulls/{num}"])
            detail_norm = normalize_pr_record(detail_pr)
            if detail_norm.get("head_sha", "").lower() != sha.lower():
                actions.append({"pr": num, "action": "ABORTED_HEAD_OR_BASE_CHANGED", "expected_sha": sha})
                continue
            detail_ok, detail_fail = authorize_pr_principal_and_repo(detail_norm, policy, repo_slug=REPO_SLUG)
            if not detail_ok:
                actions.append({"pr": num, **detail_fail})
                continue
            pr_norm = detail_norm

        if pr_norm["merge_state"] == "BEHIND":
            subprocess.run(
                ["gh", "api", f"repos/{REPO_SLUG}/pulls/{num}/update-branch", "-X", "PUT"],
                capture_output=True, text=True, timeout=60,
            )
            actions.append({"pr": num, "action": "UPDATED_BEHIND_BRANCH"})
            continue

        checks_ok, check_fail_info, trusted_wf_ids_by_path = _fetch_checks_for_sha(
            sha,
            policy,
            trusted_workflow_ids_by_path=trusted_wf_ids_by_path,
            repo_slug=REPO_SLUG,
        )
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

        live_pr = gh_json(["api", f"repos/{REPO_SLUG}/pulls/{num}"])
        reval_ok, reval_fail = revalidate_pr_before_merge(
            live_pr,
            expected_pr_number=num,
            expected_sha=sha,
            policy=policy,
            repo_slug=REPO_SLUG,
        )
        if not reval_ok:
            actions.append({"pr": num, **reval_fail})
            continue

        reapproval_ok, reapproval_fail = _fetch_and_verify_approval(num, sha, policy, repo_slug=REPO_SLUG)
        if not reapproval_ok:
            actions.append({"pr": num, "action": "ABORTED_PREMERGE_APPROVAL", **reapproval_fail})
            continue

        rechecks_ok, recheck_fail_info, trusted_wf_ids_by_path = _fetch_checks_for_sha(
            sha,
            policy,
            trusted_workflow_ids_by_path=trusted_wf_ids_by_path,
            repo_slug=REPO_SLUG,
        )
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
            actions.append({"pr": num, "title": title, "sha": sha, "action": "MERGED", "notes": notes, "approval": approval_info})
            # Merge one PR per cycle so any remaining open PRs cleanly rebase onto new main next cycle
            break
        else:
            actions.append({"pr": num, "action": "MERGE_ERROR", "stderr": m_res.stderr.strip()})

    print(json.dumps({"status": "CYCLE_COMPLETE", "open_prs_seen": len(prs), "actions": actions}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
