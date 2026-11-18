"""Shared fail-closed systemd cgroup & rlimit ceilings for source-role and Stage B units."""
from __future__ import annotations

import subprocess
from typing import Any, Callable

SOURCE_UNIT_CEILINGS: dict[str, str] = {
    "MemoryHigh": "1536M",
    "MemoryMax": "2048M",
    "MemorySwapMax": "0",
    "CPUQuota": "200%",
    "TasksMax": "256",
    "LimitNPROC": "256",
    "LimitNOFILE": "1024",
    "OOMPolicy": "kill",
    "KillMode": "control-group",
}

STAGEB_UNIT_CEILINGS: dict[str, str] = {
    "MemoryHigh": "8G",
    "MemoryMax": "12G",
    "MemorySwapMax": "0",
    "CPUQuota": "400%",
    "TasksMax": "512",
    "LimitNPROC": "512",
    "LimitNOFILE": "4096",
    "OOMPolicy": "kill",
    "KillMode": "control-group",
}

SYSTEMCTL_CGROUP_QUERY = (
    "MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,CPUQuota,"
    "TasksMax,LimitNPROC,LimitNOFILE,OOMPolicy,KillMode"
)

_PROFILE_SPECS: dict[str, dict[str, Any]] = {
    "source": {
        "properties": SOURCE_UNIT_CEILINGS,
        "exact": {
            "MemoryHigh": frozenset({"1610612736", "1536M"}),
            "MemoryMax": frozenset({"2147483648", "2048M"}),
            "MemorySwapMax": frozenset({"0", "0B"}),
            "TasksMax": frozenset({"256"}),
            "LimitNPROC": frozenset({"256"}),
            "LimitNOFILE": frozenset({"1024"}),
            "OOMPolicy": frozenset({"kill"}),
            "KillMode": frozenset({"control-group"}),
        },
        "cpu_quota": "200%",
        "cpu_usec": frozenset({"2s", "2000ms", "2000000", "2000000us", "200%"}),
    },
    "stageb": {
        "properties": STAGEB_UNIT_CEILINGS,
        "exact": {
            "MemoryHigh": frozenset({"8589934592", "8G"}),
            "MemoryMax": frozenset({"12884901888", "12G"}),
            "MemorySwapMax": frozenset({"0", "0B"}),
            "TasksMax": frozenset({"512"}),
            "LimitNPROC": frozenset({"512"}),
            "LimitNOFILE": frozenset({"4096"}),
            "OOMPolicy": frozenset({"kill"}),
            "KillMode": frozenset({"control-group"}),
        },
        "cpu_quota": "400%",
        "cpu_usec": frozenset({"4s", "4000ms", "4000000", "4000000us", "400%"}),
    },
}


def parse_systemctl_show_output(output: str, *, fail_fn: Callable[[bool, str], None] | None = None) -> dict[str, str]:
    def fail(cond: bool, msg: str) -> None:
        if fail_fn is not None:
            fail_fn(cond, msg)
        elif not cond:
            raise RuntimeError(msg)

    fail(type(output) is str and bool(output.strip()), "Empty systemctl cgroup property output")
    parsed: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        fail("=" in line, "Malformed systemctl property line")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        fail(bool(key) and key not in parsed, "Duplicate or empty systemctl property key")
        parsed[key] = value
    return parsed


def verify_unit_effective_ceilings(
    unit: str,
    *,
    profile: str = "source",
    timeout_seconds: float = 3.0,
    runner: Callable[..., Any] = subprocess.run,
    fail_fn: Callable[[bool, str], None] | None = None,
) -> dict[str, str]:
    def fail(cond: bool, msg: str) -> None:
        if fail_fn is not None:
            fail_fn(cond, msg)
        elif not cond:
            raise RuntimeError(msg)

    fail(profile in _PROFILE_SPECS, f"Unknown cgroup ceiling profile: {profile}")
    spec = _PROFILE_SPECS[profile]
    result = runner(
        ["/usr/bin/systemctl", "show", unit, "--property=" + SYSTEMCTL_CGROUP_QUERY],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    props = parse_systemctl_show_output(result.stdout, fail_fn=fail_fn)
    for key, allowed in spec["exact"].items():
        fail(props.get(key) in allowed, f"Effective unit property {key} missing or mismatched")
    raw_quota = props.get("CPUQuota")
    raw_usec = props.get("CPUQuotaPerSecUSec")
    if raw_quota not in (None, "", "[not set]"):
        fail(raw_quota == spec["cpu_quota"], "Effective unit CPUQuota mismatched")
    if raw_usec not in (None, "", "[not set]"):
        fail(raw_usec in spec["cpu_usec"], "Effective unit CPUQuotaPerSecUSec mismatched")
    fail(
        (raw_quota == spec["cpu_quota"]) or (raw_usec in spec["cpu_usec"]),
        "Effective unit CPUQuota ceiling missing",
    )
    return props
