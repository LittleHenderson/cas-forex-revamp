"""Durable owner-only shared SQLite WAL state directory (`[3]`) & single-use OwnerRecoveryVerifier (`[10]`)."""
from __future__ import annotations

import base64
import ctypes
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
from threading import RLock
from typing import Any

from cas_forex_revamp.contracts import ContractError, canonical_bytes
from cas_forex_revamp.contracts.primitives import identifier, utc_time
from cas_forex_revamp.composition.parallel_tiers import ParallelTierEngine
from cas_forex_revamp.operator.frontier_backends import ENV_THINKING_DEPTH, VALID_THINKING_DEPTHS
from cas_forex_revamp.operator.model import DurableModelExecutionGate
from cas_forex_revamp.treasury.profit_sweep import (
    DEFAULT_SWEEP_RATIO,
    ENV_PROFIT_SWEEP_AUTO_ENABLED,
    ENV_PROFIT_SWEEP_PREFERRED_RAIL,
    ENV_PROFIT_SWEEP_RATIO,
    ProfitSweepVault,
    RAIL_BROKER_2FA_MANUAL,
    VALID_PAYOUT_RAILS,
)
from cas_forex_revamp.valve.daily_quota import DailyQuotaGovernanceStore
from cas_forex_revamp.venue.external_paper_broker import OandaMutationJournal
from cas_forex_revamp.venue.mt5_broker_bridge import Mt5MutationJournal
from cas_forex_revamp.valve.tks_meta_valve_controller import (
    DEFAULT_MAX_DRAWDOWN_PCT,
    ForexMetaValveGate,
    PeakEquityStore,
    load_default_forex_valve_gate,
)

ENV_STATE_DIR = "CAS_FOREX_STATE_DIR"
ENV_TRUSTED_STATE_ROOT = "CAS_FOREX_TRUSTED_STATE_ROOT"
ENV_MODEL_MAX_CALLS_PER_DAY = "CAS_FOREX_MODEL_MAX_CALLS_PER_DAY"
ENV_MODEL_MAX_DAILY_SPEND_USD = "CAS_FOREX_MODEL_MAX_DAILY_SPEND_USD"
DEFAULT_WINDOWS_STATE_DIR = r"D:\MetaTrader5\cas_forex_state"
MAX_POLICY_MODEL_CALLS_PER_DAY = 100_000
MAX_POLICY_MODEL_DAILY_SPEND_USD = Decimal("10000.00")
_WIN_UNTRUSTED_BROAD_SIDS = frozenset({
    "S-1-1-0",       # Everyone
    "S-1-5-7",       # Anonymous Logon
    "S-1-5-11",      # Authenticated Users
    "S-1-5-32-545",  # BUILTIN\Users
    "S-1-5-32-546",  # BUILTIN\Guests
})
_WIN_PRIVILEGED_OWNER_SIDS = frozenset({
    "S-1-5-18",      # NT AUTHORITY\SYSTEM
    "S-1-5-32-544",  # BUILTIN\Administrators
})
VALID_RECOVERY_SCOPES = frozenset({"UNLOCK_QUOTA_SESSION", "REARM_DRAWDOWN", "UPDATE_QUOTA_TARGETS", "TREASURY_SWEEP"})
MAX_RECOVERY_TTL_SECONDS = 900


def _is_symlink_or_reparse(path: Path, st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) != 0:
        return True
    is_junc = getattr(path, "is_junction", None)
    return bool(callable(is_junc) and is_junc())


_WIN_READ_CONTROL = 0x00020000
_WIN_WRITE_DAC = 0x00040000
_WIN_FILE_SHARE_ALL = 0x00000007
_WIN_OPEN_EXISTING = 3
_WIN_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_WIN_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_WIN_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_WIN_SE_FILE_OBJECT = 1
_WIN_OWNER_SECURITY_INFORMATION = 0x00000001
_WIN_DACL_SECURITY_INFORMATION = 0x00000004
_WIN_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_WIN_SE_DACL_PRESENT = 0x0004
_WIN_ACE_TYPE_ACCESS_ALLOWED = 0
_WIN_ACE_TYPE_ACCESS_DENIED = 1
_WIN_OBJECT_INHERIT_ACE = 0x01
_WIN_CONTAINER_INHERIT_ACE = 0x02
_WIN_INHERIT_ONLY_ACE = 0x08
_WIN_INHERIT_PROPAGATION_FLAGS = _WIN_OBJECT_INHERIT_ACE | _WIN_CONTAINER_INHERIT_ACE | _WIN_INHERIT_ONLY_ACE
_WIN_OWNER_RIGHTS_SID = "S-1-3-4"


def _open_windows_no_reparse_handle(path: Path, desired_access: int) -> int:
    """Open a Win32 handle with FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS and reject reparse points."""
    import ctypes.wintypes as wt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        wt.DWORD,
        ctypes.c_void_p,
        wt.DWORD,
        wt.DWORD,
        wt.HANDLE,
    ]
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wt.BOOL

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wt.DWORD),
            ("ftCreationTime", wt.FILETIME),
            ("ftLastAccessTime", wt.FILETIME),
            ("ftLastWriteTime", wt.FILETIME),
            ("dwVolumeSerialNumber", wt.DWORD),
            ("nFileSizeHigh", wt.DWORD),
            ("nFileSizeLow", wt.DWORD),
            ("nNumberOfLinks", wt.DWORD),
            ("nFileIndexHigh", wt.DWORD),
            ("nFileIndexLow", wt.DWORD),
        ]

    kernel32.GetFileInformationByHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wt.BOOL

    invalid_ptr = ctypes.c_void_p(-1).value
    flags = _WIN_FILE_FLAG_OPEN_REPARSE_POINT | _WIN_FILE_FLAG_BACKUP_SEMANTICS
    raw_h = kernel32.CreateFileW(
        str(path),
        desired_access,
        _WIN_FILE_SHARE_ALL,
        None,
        _WIN_OPEN_EXISTING,
        flags,
        None,
    )
    if raw_h is None or int(raw_h) == invalid_ptr or int(raw_h) == -1:
        err = ctypes.get_last_error()
        if err in (2, 3):
            raise FileNotFoundError(f"Windows path not found (err={err}): {path}")
        raise ContractError(f"Windows CreateFileW failed for {path} (err={err})")
    handle_int = int(raw_h)
    info = _ByHandleFileInformation()
    if not kernel32.GetFileInformationByHandle(ctypes.c_void_p(handle_int), ctypes.byref(info)):
        err = ctypes.get_last_error()
        kernel32.CloseHandle(ctypes.c_void_p(handle_int))
        raise ContractError(f"Windows GetFileInformationByHandle failed for {path} (err={err})")
    if bool(info.dwFileAttributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT):
        kernel32.CloseHandle(ctypes.c_void_p(handle_int))
        raise ContractError(f"Refusing symlink or reparse point on Windows handle check: {path}")
    return handle_int


def _windows_sid_and_dacl_info(
    path_or_handle: Path | int,
) -> tuple[str, bool, bool, list[tuple[int, int, int, str]]]:
    """Query Windows owner SID, DACL presence/NULL flags, and full ACE list via handle-based GetSecurityInfo."""
    import ctypes.wintypes as wt

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    advapi32.GetSecurityInfo.argtypes = [
        ctypes.c_void_p,
        wt.DWORD,
        wt.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetSecurityInfo.restype = wt.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wt.WORD),
        ctypes.POINTER(wt.DWORD),
    ]
    advapi32.GetSecurityDescriptorControl.restype = wt.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wt.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wt.BOOL
    advapi32.GetAclInformation.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, wt.DWORD]
    advapi32.GetAclInformation.restype = wt.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wt.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAce.restype = wt.BOOL

    class _AclSizeInfo(ctypes.Structure):
        _fields_ = [("AceCount", wt.DWORD), ("AclBytesInUse", wt.DWORD), ("AclBytesFree", wt.DWORD)]

    class _AceHeader(ctypes.Structure):
        _fields_ = [("AceType", wt.BYTE), ("AceFlags", wt.BYTE), ("AceSize", wt.WORD)]

    class _StandardAce(ctypes.Structure):
        _fields_ = [("Header", _AceHeader), ("Mask", wt.DWORD), ("SidStart", wt.DWORD)]

    def _sid_str(psid: ctypes.c_void_p) -> str:
        if not psid.value:
            return ""
        pstr = wt.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(pstr)):
            raise ContractError(f"Windows SID conversion failed (err={ctypes.get_last_error()})")
        try:
            return str(pstr.value or "")
        finally:
            kernel32.LocalFree(pstr)

    owned_handle: int | None = None
    if isinstance(path_or_handle, int) and not isinstance(path_or_handle, bool):
        handle_val = path_or_handle
    else:
        owned_handle = _open_windows_no_reparse_handle(Path(path_or_handle), _WIN_READ_CONTROL)
        handle_val = owned_handle

    p_owner = ctypes.c_void_p()
    p_dacl = ctypes.c_void_p()
    p_sd = ctypes.c_void_p()
    try:
        rc = advapi32.GetSecurityInfo(
            ctypes.c_void_p(handle_val),
            _WIN_SE_FILE_OBJECT,
            _WIN_OWNER_SECURITY_INFORMATION | _WIN_DACL_SECURITY_INFORMATION,
            ctypes.byref(p_owner),
            None,
            ctypes.byref(p_dacl),
            None,
            ctypes.byref(p_sd),
        )
        if rc != 0:
            raise ContractError(f"Windows GetSecurityInfo failed for {path_or_handle} (rc={rc})")
        try:
            owner_sid = _sid_str(p_owner)
            sd_ctrl = wt.WORD(0)
            sd_rev = wt.DWORD(0)
            if not advapi32.GetSecurityDescriptorControl(p_sd, ctypes.byref(sd_ctrl), ctypes.byref(sd_rev)):
                raise ContractError(
                    f"Windows GetSecurityDescriptorControl failed for {path_or_handle} (err={ctypes.get_last_error()})"
                )
            dacl_present = bool(sd_ctrl.value & _WIN_SE_DACL_PRESENT)
            dacl_is_null = (not dacl_present) or (not bool(p_dacl.value))
            aces: list[tuple[int, int, int, str]] = []
            if dacl_present and not dacl_is_null:
                info = _AclSizeInfo()
                if not advapi32.GetAclInformation(p_dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
                    raise ContractError(f"Windows GetAclInformation failed for {path_or_handle}")
                for idx in range(info.AceCount):
                    p_ace = ctypes.c_void_p()
                    if not advapi32.GetAce(p_dacl, idx, ctypes.byref(p_ace)) or not p_ace.value:
                        raise ContractError(f"Windows GetAce failed at index {idx} for {path_or_handle}")
                    hdr = ctypes.cast(p_ace, ctypes.POINTER(_AceHeader)).contents
                    ace_type = int(hdr.AceType)
                    ace_flags = int(hdr.AceFlags)
                    if ace_type in (_WIN_ACE_TYPE_ACCESS_ALLOWED, _WIN_ACE_TYPE_ACCESS_DENIED):
                        std_ace = ctypes.cast(p_ace, ctypes.POINTER(_StandardAce)).contents
                        sid_addr = p_ace.value + _StandardAce.SidStart.offset
                        aces.append((ace_type, ace_flags, int(std_ace.Mask), _sid_str(ctypes.c_void_p(sid_addr))))
                    else:
                        aces.append((ace_type, ace_flags, 0xFFFFFFFF, f"<UNSUPPORTED_ACE_TYPE:{ace_type}>"))
            return owner_sid, dacl_present, dacl_is_null, aces
        finally:
            if p_sd.value:
                kernel32.LocalFree(p_sd)
    finally:
        if owned_handle is not None:
            kernel32.CloseHandle(ctypes.c_void_p(owned_handle))


def _windows_current_user_sid() -> str:
    import ctypes.wintypes as wt

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wt.HANDLE
    advapi32.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    advapi32.OpenProcessToken.restype = wt.BOOL
    advapi32.GetTokenInformation.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
    advapi32.GetTokenInformation.restype = wt.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.LPWSTR)]
    advapi32.ConvertSidToStringSidW.restype = wt.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wt.HANDLE]

    tok = wt.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):
        raise ContractError("Windows OpenProcessToken failed")
    try:
        needed = wt.DWORD(0)
        advapi32.GetTokenInformation(tok, 1, None, 0, ctypes.byref(needed))
        buf = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(tok, 1, buf, needed.value, ctypes.byref(needed)):
            raise ContractError("Windows GetTokenInformation failed")
        psid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        pstr = wt.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(psid, ctypes.byref(pstr)):
            raise ContractError("Windows ConvertSidToStringSidW failed")
        try:
            return str(pstr.value or "")
        finally:
            kernel32.LocalFree(pstr)
    finally:
        kernel32.CloseHandle(tok)


def _evaluate_windows_security_descriptor(
    owner_sid: str,
    cur_sid: str,
    dacl_present: bool,
    dacl_is_null: bool,
    aces: Sequence[tuple[int, int, int, str]],
    label: str = "state path",
    path: str | Path = "",
) -> None:
    """Pure-Python fail-closed evaluator for Windows owner SID, DACL presence, ACE types, masks & inheritance (Finding [5])."""
    clean_owner = str(owner_sid or "").strip()
    clean_cur = str(cur_sid or "").strip()
    if not clean_owner or not clean_cur:
        raise ContractError(f"Refusing {label} with empty Windows owner/current SID: {path}")
    if not dacl_present or dacl_is_null:
        raise ContractError(f"Refusing {label} with missing or NULL Windows DACL: {path}")
    if clean_owner != clean_cur and clean_owner not in _WIN_PRIVILEGED_OWNER_SIDS:
        raise ContractError(f"Refusing {label} owned by foreign Windows SID {clean_owner}: {path}")

    trusted_sids = frozenset({clean_owner, clean_cur, *tuple(_WIN_PRIVILEGED_OWNER_SIDS)})
    denied_direct: dict[str, int] = {}
    denied_inherit: dict[str, int] = {}
    trusted_allow_count = 0

    for raw_entry in aces:
        if not isinstance(raw_entry, tuple) or len(raw_entry) != 4:
            raise ContractError(f"Refusing {label} with malformed Windows ACE tuple: {path}")
        ace_type, ace_flags, access_mask, raw_sid = raw_entry
        if type(ace_type) is bool or not isinstance(ace_type, int):
            raise ContractError(f"Refusing {label} with invalid Windows ACE type {ace_type!r}: {path}")
        if ace_type not in (_WIN_ACE_TYPE_ACCESS_ALLOWED, _WIN_ACE_TYPE_ACCESS_DENIED):
            raise ContractError(f"Refusing {label} with unsupported Windows ACE type {ace_type}: {path}")
        flags = int(ace_flags) & 0xFF
        mask = int(access_mask) & 0xFFFFFFFF
        sid_str = str(raw_sid or "").strip()
        if not sid_str:
            raise ContractError(f"Refusing {label} with empty ACE SID: {path}")
        # S-1-3-4 (OWNER RIGHTS) resolves dynamically in Windows SeAccessCheck to the verified object owner_sid
        eff_sid = clean_owner if sid_str == _WIN_OWNER_RIGHTS_SID else sid_str

        applies_directly = not bool(flags & _WIN_INHERIT_ONLY_ACE)
        propagates_inherit = bool(flags & _WIN_INHERIT_PROPAGATION_FLAGS)

        if ace_type == _WIN_ACE_TYPE_ACCESS_DENIED:
            if applies_directly:
                denied_direct[eff_sid] = denied_direct.get(eff_sid, 0) | mask
            if propagates_inherit:
                denied_inherit[eff_sid] = denied_inherit.get(eff_sid, 0) | mask
        else:
            eff_direct = (mask & ~denied_direct.get(eff_sid, 0)) if applies_directly else 0
            eff_inherit = (mask & ~denied_inherit.get(eff_sid, 0)) if propagates_inherit else 0
            if eff_sid not in trusted_sids:
                if eff_direct != 0 or eff_inherit != 0:
                    raise ContractError(
                        f"Refusing {label} with permissive Windows DACL for untrusted principal {sid_str} "
                        f"(direct=0x{eff_direct:08x}, inherit=0x{eff_inherit:08x}): {path}"
                    )
            else:
                if eff_direct != 0:
                    trusted_allow_count += 1

    if trusted_allow_count <= 0:
        raise ContractError(f"Refusing {label} with empty Windows DACL or zero effective trusted allow ACEs: {path}")


def _apply_windows_protected_owner_dacl(path_or_handle: Path | int, *, is_dir: bool) -> None:
    """Apply an explicit protected owner-only DACL (D:P + SYSTEM + Administrators + current user) on Windows."""
    if os.name != "nt":
        return
    import ctypes.wintypes as wt

    cur_sid = _windows_current_user_sid()
    if not cur_sid.startswith("S-1-"):
        raise ContractError(f"Invalid current Windows SID {cur_sid!r}")
    if is_dir:
        sddl = f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{cur_sid})"
    else:
        sddl = f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{cur_sid})"

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wt.ULONG),
    ]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wt.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wt.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wt.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wt.BOOL
    advapi32.SetSecurityInfo.argtypes = [
        ctypes.c_void_p,
        wt.DWORD,
        wt.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetSecurityInfo.restype = wt.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = wt.BOOL

    p_sd = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(p_sd), None):
        raise ContractError(f"Windows SDDL conversion failed (err={ctypes.get_last_error()})")
    try:
        dacl_present = wt.BOOL(0)
        dacl_defaulted = wt.BOOL(0)
        p_dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            p_sd, ctypes.byref(dacl_present), ctypes.byref(p_dacl), ctypes.byref(dacl_defaulted)
        ) or not dacl_present.value or not p_dacl.value:
            raise ContractError("Windows GetSecurityDescriptorDacl failed for protected owner SDDL")

        owned_handle: int | None = None
        if isinstance(path_or_handle, int) and not isinstance(path_or_handle, bool):
            handle_val = path_or_handle
        else:
            owned_handle = _open_windows_no_reparse_handle(
                Path(path_or_handle), _WIN_WRITE_DAC | _WIN_READ_CONTROL
            )
            handle_val = owned_handle
        try:
            rc = advapi32.SetSecurityInfo(
                ctypes.c_void_p(handle_val),
                _WIN_SE_FILE_OBJECT,
                _WIN_DACL_SECURITY_INFORMATION | _WIN_PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                p_dacl,
                None,
            )
            if rc != 0:
                raise ContractError(f"Windows SetSecurityInfo failed for {path_or_handle} (rc={rc})")
        finally:
            if owned_handle is not None:
                kernel32.CloseHandle(ctypes.c_void_p(owned_handle))
    finally:
        if p_sd.value:
            kernel32.LocalFree(p_sd)


def verify_windows_owner_and_dacl(
    path: Path,
    *,
    label: str = "state path",
    ignore_missing: bool = False,
) -> None:
    """Enforce owner SID and strict owner-only DACL on Windows via handle-based GetSecurityInfo (Finding [5])."""
    if os.name != "nt":
        return
    try:
        info = _windows_sid_and_dacl_info(path)
    except FileNotFoundError as exc:
        if ignore_missing:
            return
        raise ContractError(f"Missing {label} during Windows DACL verification: {path}") from exc
    cur_sid = _windows_current_user_sid()
    if len(info) == 2:
        # Backwards compatibility if a legacy test mocks _windows_sid_and_dacl_info -> (owner_sid, allowed_sids)
        legacy_owner, legacy_sids = info  # type: ignore[misc]
        synth_aces = [(_WIN_ACE_TYPE_ACCESS_ALLOWED, 0, 0x1F01FF, str(s)) for s in legacy_sids]
        if not synth_aces:
            synth_aces = [(_WIN_ACE_TYPE_ACCESS_ALLOWED, 0, 0x1F01FF, str(legacy_owner))]
        _evaluate_windows_security_descriptor(
            str(legacy_owner), cur_sid, True, False, synth_aces, label=label, path=path
        )
        return
    owner_sid, dacl_present, dacl_is_null, aces = info
    _evaluate_windows_security_descriptor(
        owner_sid, cur_sid, dacl_present, dacl_is_null, aces, label=label, path=path
    )

def _verify_posix_ancestor_stat(st: os.stat_result, euid: int, path_label: str) -> None:
    if not stat.S_ISDIR(st.st_mode):
        raise ContractError(f"Refusing non-directory ancestor for {path_label}")
    if st.st_uid not in (euid, 0):
        raise ContractError(f"Refusing {path_label} beneath foreign-owned ancestor (uid={st.st_uid}, expected {euid} or 0)")
    if (st.st_mode & 0o022) != 0:
        is_sticky_root = st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
        if not is_sticky_root:
            raise ContractError(f"Refusing {path_label} beneath group/world-writable non-sticky ancestor (mode={oct(st.st_mode & 0o7777)})")


def _audit_directory_children_custody(
    directory: Path,
    *,
    dir_fd: int | None,
    label: str = "state_dir",
) -> None:
    """Audit every existing child entry inside ``directory`` before hardening or opening DBs (Finding [13])."""
    if os.name == "posix" and dir_fd is not None:
        euid = os.geteuid()
        dup_fd = os.dup(dir_fd)
        with os.scandir(dup_fd) as it:
            for entry in it:
                name = entry.name
                if name in (".", ".."):
                    continue
                try:
                    cst = os.lstat(name, dir_fd=dir_fd)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(cst.st_mode):
                    raise ContractError(
                        f"Refusing pre-positioned child symlink {name!r} inside {label}: {directory / name}"
                    )
                if not stat.S_ISREG(cst.st_mode) and not stat.S_ISDIR(cst.st_mode):
                    raise ContractError(
                        f"Refusing special/non-regular child entry {name!r} inside {label}: {directory / name}"
                    )
                if cst.st_uid != euid:
                    raise ContractError(
                        f"Refusing foreign-owned child entry {name!r} (uid={cst.st_uid}, expected {euid}) in {label}"
                    )
                if (cst.st_mode & 0o022) != 0:
                    raise ContractError(
                        f"Refusing group/world-writable child entry {name!r} (mode={oct(cst.st_mode & 0o7777)}) in {label}"
                    )
                if stat.S_ISREG(cst.st_mode) and cst.st_nlink != 1:
                    raise ContractError(
                        f"Refusing hard-linked child entry {name!r} (nlink={cst.st_nlink}) in {label}"
                    )
        return

    if not directory.exists():
        return
    with os.scandir(directory) as it:
        for entry in it:
            cpath = directory / entry.name
            try:
                cst = os.lstat(cpath)
            except FileNotFoundError:
                continue
            if _is_symlink_or_reparse(cpath, cst):
                raise ContractError(
                    f"Refusing pre-positioned child symlink or reparse point {entry.name!r} inside {label}: {cpath}"
                )
            if not stat.S_ISREG(cst.st_mode) and not stat.S_ISDIR(cst.st_mode):
                raise ContractError(
                    f"Refusing special/non-regular child entry {entry.name!r} inside {label}: {cpath}"
                )
            if stat.S_ISREG(cst.st_mode) and cst.st_nlink > 1:
                raise ContractError(
                    f"Refusing hard-linked child entry {entry.name!r} (nlink={cst.st_nlink}) in {label}"
                )
            verify_windows_owner_and_dacl(
                cpath,
                label=f"child {entry.name!r} in {label}",
                ignore_missing=entry.name.endswith(("-wal", "-shm", "-journal")),
            )


def verify_non_symlink_sqlite_target(
    db_path: str | Path,
    *,
    create_parent: bool = True,
    label: str = "safety SQLite DB",
) -> Path:
    """Validate parent & leaf SQLite target without Path.resolve() symlink dereferencing (Finding [13])."""
    if not isinstance(db_path, (str, Path)):
        raise ContractError(f"{label} path must be a filesystem path")
    raw_str = str(db_path).strip()
    if not raw_str or raw_str == ":memory:" or raw_str.startswith("file:") or "\x00" in raw_str:
        raise ContractError(f"{label} must be a concrete on-disk SQLite file path")
    expanded = os.path.expanduser(raw_str)
    raw_target = Path(expanded)
    if ".." in raw_target.parts:
        raise ContractError(f"Refusing parent-traversal '..' in {label}: {raw_target}")
    if not raw_target.is_absolute():
        raw_target = Path(os.getcwd()) / raw_target
    db_name = raw_target.name
    if not db_name or db_name in (".", ".."):
        raise ContractError(f"Invalid {label} filename: {raw_target}")

    parent_dir, dir_fd = open_verified_directory_fd(
        raw_target.parent, create=create_parent, label=f"parent of {label}"
    )
    try:
        candidates = (db_name, f"{db_name}-wal", f"{db_name}-shm", f"{db_name}-journal")
        if os.name == "posix" and dir_fd is not None:
            euid = os.geteuid()
            for cname in candidates:
                try:
                    cst = os.lstat(cname, dir_fd=dir_fd)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(cst.st_mode) or not stat.S_ISREG(cst.st_mode):
                    raise ContractError(f"Refusing symlink or non-regular {label} artifact {cname!r}")
                if cst.st_uid != euid:
                    raise ContractError(f"Refusing foreign-owned {label} artifact {cname!r} (uid={cst.st_uid})")
                if cst.st_nlink != 1:
                    raise ContractError(f"Refusing hard-linked {label} artifact {cname!r} (nlink={cst.st_nlink})")
                if (cst.st_mode & 0o077) != 0:
                    raise ContractError(f"Refusing {label} artifact {cname!r} with unsafe permissions")
        else:
            for cname in candidates:
                cpath = parent_dir / cname
                is_sidecar = cname != db_name
                if os.path.lexists(cpath):
                    try:
                        cst = os.lstat(cpath)
                    except FileNotFoundError:
                        if is_sidecar:
                            continue
                        raise
                    if _is_symlink_or_reparse(cpath, cst) or not stat.S_ISREG(cst.st_mode):
                        raise ContractError(f"Refusing symlink/reparse or non-regular {label} artifact: {cpath}")
                    if cst.st_nlink > 1:
                        raise ContractError(f"Refusing hard-linked {label} artifact (nlink={cst.st_nlink}): {cpath}")
                    verify_windows_owner_and_dacl(
                        cpath,
                        label=f"{label} ({cname})",
                        ignore_missing=is_sidecar,
                    )
    finally:
        if dir_fd is not None:
            os.close(dir_fd)
    return parent_dir / db_name


def open_verified_sqlite_connection(
    db_path: str | Path,
    *,
    read_only: bool = False,
    timeout: float = 5.0,
    create_parent: bool = True,
    label: str = "safety SQLite DB",
) -> sqlite3.Connection:
    """Open SQLite DB relative to verified parent dir_fd with O_NOFOLLOW and post-open inode verification (Finding [13])."""
    target = verify_non_symlink_sqlite_target(
        db_path, create_parent=(create_parent and not read_only), label=label
    )
    parent_dir = target.parent
    db_name = target.name
    _, held_dir_fd = open_verified_directory_fd(
        parent_dir, create=(create_parent and not read_only), label=f"parent of {label}"
    )
    try:
        expected_id: tuple[int, int] | None = None
        if os.name == "posix" and held_dir_fd is not None:
            euid = os.geteuid()
            for sc in (f"{db_name}-wal", f"{db_name}-shm", f"{db_name}-journal"):
                try:
                    sc_st = os.lstat(sc, dir_fd=held_dir_fd)
                except FileNotFoundError:
                    continue
                if (
                    stat.S_ISLNK(sc_st.st_mode)
                    or not stat.S_ISREG(sc_st.st_mode)
                    or sc_st.st_uid != euid
                    or sc_st.st_nlink != 1
                    or (sc_st.st_mode & 0o077) != 0
                ):
                    raise ContractError(f"Refusing unsafe {label} sidecar {sc!r}")
            open_flags = (
                (os.O_RDONLY if read_only else (os.O_RDWR | os.O_CREAT))
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                db_fd = os.open(db_name, open_flags, 0o600, dir_fd=held_dir_fd)
            except OSError as exc:
                raise ContractError(f"Refusing symlink or inaccessible {label} {db_name!r}: {exc}") from exc
            try:
                if not read_only:
                    os.fchmod(db_fd, 0o600)
                st_db = os.fstat(db_fd)
                if not stat.S_ISREG(st_db.st_mode):
                    raise ContractError(f"Refusing non-regular {label}: {target}")
                if st_db.st_uid != euid:
                    raise ContractError(f"Refusing foreign-owned {label} (uid={st_db.st_uid}): {target}")
                if st_db.st_nlink != 1:
                    raise ContractError(f"Refusing hard-linked {label} (nlink={st_db.st_nlink}): {target}")
                if (st_db.st_mode & 0o077) != 0:
                    raise ContractError(f"Refusing {label} with unsafe group/world permissions: {target}")
                expected_id = (int(st_db.st_dev), int(st_db.st_ino))
            finally:
                os.close(db_fd)
        else:
            if os.path.lexists(target):
                st_pre = os.lstat(target)
                if _is_symlink_or_reparse(target, st_pre) or not stat.S_ISREG(st_pre.st_mode) or st_pre.st_nlink > 1:
                    raise ContractError(f"Refusing symlink/reparse or hard-linked {label}: {target}")
                verify_windows_owner_and_dacl(target, label=label)
                if int(getattr(st_pre, "st_ino", 0)) != 0:
                    expected_id = (int(st_pre.st_dev), int(st_pre.st_ino))
            elif read_only:
                raise ContractError(f"Missing read-only {label}: {target}")

        if read_only:
            ro_uri = f"{target.as_uri()}?mode=ro"
            conn = sqlite3.connect(ro_uri, uri=True, timeout=timeout, isolation_level=None)
        else:
            conn = sqlite3.connect(str(target), timeout=timeout, isolation_level=None)
        try:
            if os.name == "posix" and held_dir_fd is not None:
                st_post = os.lstat(db_name, dir_fd=held_dir_fd)
                if (
                    stat.S_ISLNK(st_post.st_mode)
                    or not stat.S_ISREG(st_post.st_mode)
                    or st_post.st_nlink != 1
                    or (expected_id is not None and (int(st_post.st_dev), int(st_post.st_ino)) != expected_id)
                ):
                    raise ContractError(f"{label} inode changed or became symlink during SQLite open: {target}")
            else:
                st_post_w = os.lstat(target)
                if _is_symlink_or_reparse(target, st_post_w) or not stat.S_ISREG(st_post_w.st_mode) or st_post_w.st_nlink > 1:
                    raise ContractError(f"{label} became symlink/reparse or hard-linked during open: {target}")
                if expected_id is not None and int(getattr(st_post_w, "st_ino", 0)) != 0:
                    if (int(st_post_w.st_dev), int(st_post_w.st_ino)) != expected_id:
                        raise ContractError(f"{label} file identity changed during SQLite open: {target}")
                if not read_only:
                    _apply_windows_protected_owner_dacl(target, is_dir=False)
                    verify_windows_owner_and_dacl(target, label=label)
                for sc in (f"{db_name}-wal", f"{db_name}-shm", f"{db_name}-journal"):
                    sc_p = parent_dir / sc
                    if os.path.lexists(sc_p):
                        verify_windows_owner_and_dacl(sc_p, label=f"{label} sidecar {sc}", ignore_missing=True)
            return conn
        except Exception:
            conn.close()
            raise
    finally:
        if held_dir_fd is not None:
            os.close(held_dir_fd)


def open_verified_directory_fd(
    directory: str | Path,
    *,
    create: bool = False,
    trusted_root: str | Path | None = None,
    label: str = "state_dir",
) -> tuple[Path, int | None]:
    """Traverse every ancestor without following symlinks, verify owner custody, and return (Path, held_dir_fd)."""
    if not isinstance(directory, (str, Path)) or not str(directory).strip():
        raise ContractError(f"{label} must be a non-empty absolute path")
    raw_str = str(directory).strip()
    if "\x00" in raw_str:
        raise ContractError(f"{label} contains NUL byte")
    target = Path(raw_str)
    if not target.is_absolute():
        raise ContractError(f"Refusing relative {label}; an absolute path is required: {target}")
    if ".." in target.parts:
        raise ContractError(f"Refusing parent-traversal component '..' in {label}: {target}")

    if trusted_root is not None and str(trusted_root).strip():
        troot = Path(str(trusted_root).strip())
        if not troot.is_absolute():
            raise ContractError(f"trusted_root must be absolute: {troot}")
        try:
            target.relative_to(troot)
        except ValueError as exc:
            raise ContractError(f"Refusing {label} outside trusted root {troot}: {target}") from exc

    if os.name == "posix":
        euid = os.geteuid()
        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        parts = [p for p in target.parts if p and p != "/"]
        cur_fd = os.open("/", dir_flags)
        try:
            _verify_posix_ancestor_stat(os.fstat(cur_fd), euid, label)
            for idx, part in enumerate(parts):
                is_leaf = idx == len(parts) - 1
                try:
                    nxt_fd = os.open(part, dir_flags, dir_fd=cur_fd)
                except FileNotFoundError:
                    if not create:
                        raise ContractError(f"Missing {label} component {part!r} in {target}") from None
                    os.mkdir(part, 0o700, dir_fd=cur_fd)
                    nxt_fd = os.open(part, dir_flags, dir_fd=cur_fd)
                except OSError as exc:
                    raise ContractError(f"Refusing symlink or inaccessible component {part!r} in {label}: {exc}") from exc
                os.close(cur_fd)
                cur_fd = nxt_fd
                st = os.fstat(cur_fd)
                if not is_leaf:
                    _verify_posix_ancestor_stat(st, euid, label)
                else:
                    if not stat.S_ISDIR(st.st_mode):
                        raise ContractError(f"Refusing non-directory {label}: {target}")
                    if st.st_uid != euid:
                        raise ContractError(
                            f"Refusing attacker/foreign-owned {label} (uid={st.st_uid}, expected euid={euid}): {target}"
                        )
                    if (st.st_mode & 0o022) != 0:
                        raise ContractError(
                            f"Refusing {label} that is initially group/world-writable "
                            f"(mode={oct(st.st_mode & 0o7777)}): {target}"
                        )
                    _audit_directory_children_custody(target, dir_fd=cur_fd, label=label)
                    if (st.st_mode & 0o077) != 0:
                        os.fchmod(cur_fd, 0o700)
                        st = os.fstat(cur_fd)
                        if (st.st_mode & 0o077) != 0:
                            raise ContractError(f"{label} permissions must forbid group/other access")
            return target, cur_fd
        except Exception:
            os.close(cur_fd)
            raise

    parts = target.parts
    if not parts:
        raise ContractError(f"Invalid empty {label}")
    cur = Path(parts[0])
    for idx, part in enumerate(parts[1:], start=1):
        cur = cur / part
        is_leaf = idx == len(parts) - 1
        if os.path.lexists(cur):
            st = os.lstat(cur)
            if _is_symlink_or_reparse(cur, st) or not stat.S_ISDIR(st.st_mode):
                raise ContractError(f"Refusing symlink/reparse or non-directory component in {label}: {cur}")
            created_now = False
        else:
            if not create:
                raise ContractError(f"Missing {label} component: {cur}")
            cur.mkdir(mode=0o700)
            st = os.lstat(cur)
            if _is_symlink_or_reparse(cur, st) or not stat.S_ISDIR(st.st_mode):
                raise ContractError(f"Created {label} component invalid: {cur}")
            _apply_windows_protected_owner_dacl(cur, is_dir=True)
            created_now = True
        if is_leaf:
            verify_windows_owner_and_dacl(cur, label=label)
            _audit_directory_children_custody(cur, dir_fd=None, label=label)
            if create and not created_now:
                _apply_windows_protected_owner_dacl(cur, is_dir=True)
    if len(parts) == 1:
        verify_windows_owner_and_dacl(cur, label=label)
        _audit_directory_children_custody(cur, dir_fd=None, label=label)
    return cur, None


def verify_and_read_owner_only_file(
    parent_dir: Path,
    filename: str,
    *,
    dir_fd: int | None = None,
    label: str = "secret file",
    max_bytes: int = 65536,
) -> tuple[bytes, tuple[int, int]]:
    """Open an existing owner-only regular file relative to verified parent with O_NOFOLLOW + fstat custody checks."""
    if not filename or "/" in filename or "\\" in filename or filename in (".", ".."):
        raise ContractError(f"Invalid {label} filename: {filename!r}")
    if os.name == "posix":
        euid = os.geteuid()
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        opened_dir_fd: int | None = None
        use_fd = dir_fd
        if use_fd is None:
            _, opened_dir_fd = open_verified_directory_fd(parent_dir, create=False, label=f"parent of {label}")
            use_fd = opened_dir_fd
        try:
            try:
                fd = os.open(filename, flags, dir_fd=use_fd)
            except OSError as exc:
                raise ContractError(f"Refusing symlink or unreadable {label} {filename!r}: {exc}") from exc
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise ContractError(f"Refusing non-regular {label}: {filename!r}")
                if st.st_uid != euid:
                    raise ContractError(f"Refusing foreign-owned {label} (uid={st.st_uid}, expected {euid}): {filename!r}")
                if (st.st_mode & 0o077) != 0:
                    raise ContractError(f"Refusing {label} with unsafe group/world permissions ({oct(st.st_mode & 0o777)}): {filename!r}")
                if st.st_nlink != 1:
                    raise ContractError(f"Refusing hard-linked {label} (nlink={st.st_nlink}): {filename!r}")
                if st.st_size > max_bytes:
                    raise ContractError(f"Refusing oversized {label} ({st.st_size} bytes)")
                data = os.read(fd, max_bytes + 1)
                if len(data) > max_bytes:
                    raise ContractError(f"Refusing oversized {label}")
                return data, (int(st.st_dev), int(st.st_ino))
            finally:
                os.close(fd)
        finally:
            if opened_dir_fd is not None:
                os.close(opened_dir_fd)

    open_verified_directory_fd(parent_dir, create=False, label=f"parent of {label}")
    fpath = parent_dir / filename
    st_l = os.lstat(fpath)
    if _is_symlink_or_reparse(fpath, st_l) or not stat.S_ISREG(st_l.st_mode):
        raise ContractError(f"Refusing symlink/reparse or non-regular {label}: {fpath}")
    verify_windows_owner_and_dacl(fpath, label=label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    fd = os.open(str(fpath), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise ContractError(f"Refusing non-regular or hard-linked {label} (nlink={st.st_nlink}): {fpath}")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise ContractError(f"Refusing oversized {label}")
        return data, (int(st.st_dev), int(st.st_ino))
    finally:
        os.close(fd)


def read_owner_only_file_no_follow(
    parent_dir: Path,
    filename: str,
    *,
    dir_fd: int | None = None,
    label: str = "secret file",
    max_bytes: int = 65536,
) -> tuple[bytes, tuple[int, int]]:
    """Descriptor-relative O_NOFOLLOW owner-only file reader (alias for verify_and_read_owner_only_file)."""
    return verify_and_read_owner_only_file(
        parent_dir,
        filename,
        dir_fd=dir_fd,
        label=label,
        max_bytes=max_bytes,
    )


def create_owner_only_file_atomic(
    parent_dir: Path,
    filename: str,
    content: bytes,
    *,
    dir_fd: int | None = None,
    replace_existing: bool = False,
    label: str = "secret file",
) -> None:
    """Create (or atomically replace) a 0o600 regular file relative to a verified parent directory descriptor."""
    if not filename or "/" in filename or "\\" in filename or filename in (".", ".."):
        raise ContractError(f"Invalid {label} filename: {filename!r}")
    if os.name == "posix":
        euid = os.geteuid()
        opened_dir_fd: int | None = None
        use_fd = dir_fd
        if use_fd is None:
            _, opened_dir_fd = open_verified_directory_fd(parent_dir, create=True, label=f"parent of {label}")
            use_fd = opened_dir_fd
        try:
            try:
                st_existing = os.lstat(filename, dir_fd=use_fd)
            except FileNotFoundError:
                st_existing = None
            if st_existing is not None:
                if not replace_existing:
                    raise ContractError(f"Refusing to overwrite existing {label}: {filename!r}")
                if stat.S_ISLNK(st_existing.st_mode) or not stat.S_ISREG(st_existing.st_mode):
                    raise ContractError(
                        f"Refusing to replace symlink or non-regular {label}: {parent_dir / filename}"
                    )
                if st_existing.st_uid != euid:
                    raise ContractError(
                        f"Refusing to replace foreign-owned {label} (uid={st_existing.st_uid}): {parent_dir / filename}"
                    )
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            target_name = filename if not replace_existing else f".{filename}.tmp.{secrets.token_hex(8)}"
            try:
                fd = os.open(target_name, flags, 0o600, dir_fd=use_fd)
            except OSError as exc:
                raise ContractError(f"Unable to create {label} {filename!r} safely: {exc}") from exc
            try:
                os.fchmod(fd, 0o600)
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != euid or (st.st_mode & 0o077) != 0 or st.st_nlink != 1:
                    raise ContractError(f"Newly created {label} failed custody fstat verification")
                view = memoryview(content)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            except Exception:
                os.close(fd)
                if replace_existing:
                    try:
                        os.unlink(target_name, dir_fd=use_fd)
                    except OSError as exc:
                        _cleanup_err = str(exc)  # best-effort temp unlink
                raise
            os.close(fd)
            if replace_existing:
                try:
                    st_pre_rep = os.lstat(filename, dir_fd=use_fd)
                except FileNotFoundError:
                    st_pre_rep = None
                if st_pre_rep is not None and (
                    stat.S_ISLNK(st_pre_rep.st_mode)
                    or not stat.S_ISREG(st_pre_rep.st_mode)
                    or st_pre_rep.st_uid != euid
                ):
                    try:
                        os.unlink(target_name, dir_fd=use_fd)
                    except OSError as exc_rm:
                        _rm_err = str(exc_rm)
                    raise ContractError(
                        f"Refusing atomic replace over symlink, directory, or foreign {label}: {parent_dir / filename}"
                    )
                os.replace(target_name, filename, src_dir_fd=use_fd, dst_dir_fd=use_fd)
                os.fsync(use_fd)
        finally:
            if opened_dir_fd is not None:
                os.close(opened_dir_fd)
        return

    open_verified_directory_fd(parent_dir, create=True, label=f"parent of {label}")
    dest_path = parent_dir / filename
    if os.path.lexists(dest_path):
        if not replace_existing:
            raise ContractError(f"Refusing to overwrite existing {label}: {dest_path}")
        st_dest = os.lstat(dest_path)
        if _is_symlink_or_reparse(dest_path, st_dest) or not stat.S_ISREG(st_dest.st_mode):
            raise ContractError(f"Refusing to replace symlink/reparse or non-regular {label}: {dest_path}")
        verify_windows_owner_and_dacl(dest_path, label=label)

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    target_path = parent_dir / (filename if not replace_existing else f".{filename}.tmp.{secrets.token_hex(8)}")
    try:
        fd = os.open(str(target_path), flags, 0o600)
    except OSError as exc:
        raise ContractError(f"Unable to create {label} safely at {target_path}: {exc}") from exc
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    except Exception:
        os.close(fd)
        if replace_existing:
            try:
                target_path.unlink()
            except OSError as exc:
                _cleanup_err = str(exc)  # best-effort temp unlink
        raise
    os.close(fd)
    try:
        _apply_windows_protected_owner_dacl(target_path, is_dir=False)
        verify_windows_owner_and_dacl(target_path, label=label)
        if replace_existing:
            if os.path.lexists(dest_path):
                st_dest2 = os.lstat(dest_path)
                if _is_symlink_or_reparse(dest_path, st_dest2) or not stat.S_ISREG(st_dest2.st_mode):
                    raise ContractError(f"Refusing atomic replace over symlink/reparse or directory {label}: {dest_path}")
            os.replace(str(target_path), str(dest_path))
    except Exception:
        if target_path.exists():
            try:
                target_path.unlink()
            except OSError as exc_u:
                _u_err = str(exc_u)
        raise


def ensure_secure_state_directory(
    state_dir: str | Path,
    *,
    trusted_root: str | Path | None = None,
) -> Path:
    """Create and verify an ancestor-safe, non-symlink owner-only (`0o700`) persistent state directory."""
    if not isinstance(state_dir, (str, Path)) or not str(state_dir).strip():
        raise ContractError(f"{ENV_STATE_DIR} / --state-dir must be a non-empty path")
    verified, dir_fd = open_verified_directory_fd(
        state_dir, create=True, trusted_root=trusted_root, label="state_dir"
    )
    if dir_fd is not None:
        os.close(dir_fd)
    return verified


def resolve_state_dir(
    environ: Mapping[str, str] | None = None,
    *,
    explicit_state_dir: str | Path | None = None,
    allow_windows_default: bool = True,
    trusted_root: str | Path | None = None,
) -> Path:
    raw = str(explicit_state_dir).strip() if explicit_state_dir is not None else ""
    if not raw and environ is not None:
        raw = str(environ.get(ENV_STATE_DIR, "")).strip()
    if not raw and allow_windows_default and os.name == "nt":
        raw = DEFAULT_WINDOWS_STATE_DIR
    if not raw:
        raise ContractError(
            f"Persistent owner-only state directory required: pass --state-dir or set {ENV_STATE_DIR}"
        )
    eff_root = trusted_root
    if eff_root is None and environ is not None:
        env_root = str(environ.get(ENV_TRUSTED_STATE_ROOT, "")).strip()
        if env_root:
            eff_root = env_root
    return ensure_secure_state_directory(raw, trusted_root=eff_root)


def _load_or_create_recovery_key(key_path: Path, *, dir_fd: int | None = None) -> bytes:
    parent = key_path.parent
    fname = key_path.name
    opened_dir_fd: int | None = None
    use_fd = dir_fd
    if os.name == "posix" and use_fd is None:
        _, opened_dir_fd = open_verified_directory_fd(parent, create=True, label="owner recovery directory")
        use_fd = opened_dir_fd
    try:
        exists = False
        if os.name == "posix" and use_fd is not None:
            try:
                os.lstat(fname, dir_fd=use_fd)
                exists = True
            except FileNotFoundError:
                exists = False
        else:
            exists = os.path.lexists(key_path)
        if exists:
            raw_bytes, _ = verify_and_read_owner_only_file(
                parent, fname, dir_fd=use_fd, label="owner recovery file", max_bytes=4096
            )
            raw = raw_bytes.strip()
            key = bytes.fromhex(raw.decode("ascii")) if len(raw) == 64 else raw
            if len(key) < 32:
                raise ContractError("Owner recovery key shorter than 32 bytes")
            return key
        key = secrets.token_bytes(32)
        create_owner_only_file_atomic(
            parent, fname, (key.hex() + "\n").encode("ascii"),
            dir_fd=use_fd, replace_existing=False, label="owner recovery file",
        )
        return key
    finally:
        if opened_dir_fd is not None:
            os.close(opened_dir_fd)


_RECOVERY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS owner_recovery_tokens (
    token_id TEXT PRIMARY KEY,
    action_scope TEXT NOT NULL,
    target_ref TEXT NOT NULL,
    issued_at_utc TEXT NOT NULL,
    expires_at_utc TEXT NOT NULL,
    hmac_sha256 TEXT NOT NULL,
    consumed_at_utc TEXT,
    consumed_by TEXT
)
"""


class OwnerRecoveryVerifier:
    """Single-use, expiring, scope-bound HMAC recovery verifier stored transactionally in SQLite."""

    def __init__(
        self,
        *,
        db_path: str | Path,
        key_path: str | Path | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._db_path = Path(db_path)
        self._key_path = Path(key_path) if key_path is not None else (self._db_path.parent / ".owner_recovery.key")
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = RLock()
        self._initialized = False

    @property
    def db_path(self) -> Path:
        return self._db_path

    def ensure_initialized(self) -> None:
        with self._lock:
            if self._initialized and self._db_path.exists():
                return
            conn = self._connect()
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path), timeout=10.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        if not self._initialized:
            conn.execute(_RECOVERY_TABLE_SQL)
            self._initialized = True
        return conn

    def mint_token(
        self,
        *,
        action_scope: str,
        target_ref: str = "*",
        ttl_seconds: int = 900,
        now: datetime | None = None,
    ) -> str:
        scope = action_scope.strip().upper()
        if scope not in VALID_RECOVERY_SCOPES:
            raise ContractError(f"action_scope must be one of {sorted(VALID_RECOVERY_SCOPES)}")
        if type(ttl_seconds) is not int or not (30 <= ttl_seconds <= MAX_RECOVERY_TTL_SECONDS):
            raise ContractError(f"recovery ttl_seconds must be in 30..{MAX_RECOVERY_TTL_SECONDS}")
        raw_ref = target_ref.strip() if isinstance(target_ref, str) else ""
        if scope == "TREASURY_SWEEP":
            if not raw_ref or raw_ref == "*":
                raise ContractError(
                    "OWNER_RECOVERY_TARGET_REQUIRED: TREASURY_SWEEP tokens must bind an exact non-wildcard transaction digest or transfer_id"
                )
            ref_clean = raw_ref
        else:
            ref_clean = raw_ref or "*"
        ts = utc_time(self._clock(), "clock") if now is None else utc_time(now, "now")
        exp = ts + timedelta(seconds=ttl_seconds)
        issued_str = ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expires_str = exp.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        token_id = "rec-" + secrets.token_hex(12)
        with self._lock:
            key = _load_or_create_recovery_key(self._key_path)
            msg = f"cas-forex-owner-recovery/1|{token_id}|{scope}|{ref_clean}|{issued_str}|{expires_str}"
            sig = hmac.new(key, msg.encode("utf-8"), sha256).hexdigest()
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """
                    INSERT INTO owner_recovery_tokens (
                        token_id, action_scope, target_ref, issued_at_utc, expires_at_utc, hmac_sha256, consumed_at_utc, consumed_by
                    ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
                    """,
                    (token_id, scope, ref_clean, issued_str, expires_str, sig),
                )
                conn.commit()
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()
        payload = {
            "protocol": "cas-forex-owner-recovery/1",
            "token_id": token_id,
            "action_scope": scope,
            "target_ref": ref_clean,
            "issued_at_utc": issued_str,
            "expires_at_utc": expires_str,
            "hmac_sha256": sig,
        }
        b64 = base64.urlsafe_b64encode(canonical_bytes(payload)).decode("ascii").rstrip("=")
        return f"casrx1.{b64}"

    def _decode_token(self, raw_token: str) -> dict[str, str]:
        if not isinstance(raw_token, str) or not raw_token.strip():
            raise ContractError("OWNER_RECOVERY_TOKEN_REQUIRED: missing owner recovery token")
        text = raw_token.strip()
        if text.startswith("casrx1."):
            b64 = text[7:]
            b64 += "=" * (-len(b64) % 4)
            try:
                obj = json.loads(base64.urlsafe_b64decode(b64).decode("utf-8"))
            except Exception as exc:
                raise ContractError("OWNER_RECOVERY_TOKEN_MALFORMED") from exc
        else:
            try:
                obj = json.loads(text)
            except Exception as exc:
                raise ContractError("OWNER_RECOVERY_TOKEN_MALFORMED") from exc
        if type(obj) is not dict or obj.get("protocol") != "cas-forex-owner-recovery/1":
            raise ContractError("OWNER_RECOVERY_TOKEN_PROTOCOL_INVALID")
        return {str(k): str(v) for k, v in obj.items()}

    def _validate_token_for_consume(
        self,
        raw_token: str,
        *,
        expected_scope: str,
        target_ref: str | None = None,
        require_exact_target: bool = False,
        owner_request_id: str,
        now: datetime | None = None,
    ) -> tuple[str, str, str, str]:
        identifier(owner_request_id, "owner_request_id")
        scope = expected_scope.strip().upper()
        if scope not in VALID_RECOVERY_SCOPES:
            raise ContractError(f"unsupported recovery scope {expected_scope!r}")
        fields = self._decode_token(raw_token)
        if fields.get("action_scope") != scope:
            raise ContractError("OWNER_RECOVERY_SCOPE_MISMATCH: token scope does not match action")
        tok_target = fields.get("target_ref", "*")
        must_match_exact = bool(require_exact_target or scope == "TREASURY_SWEEP")
        if must_match_exact:
            if not target_ref or not target_ref.strip() or target_ref.strip() == "*":
                raise ContractError("OWNER_RECOVERY_TARGET_REQUIRED: exact target_ref required")
            if tok_target == "*" or tok_target != target_ref.strip():
                raise ContractError("OWNER_RECOVERY_TARGET_MISMATCH: token must be explicitly bound to this exact target")
        elif target_ref is not None and tok_target != "*" and tok_target != target_ref.strip():
            raise ContractError("OWNER_RECOVERY_TARGET_MISMATCH: token bound to a different target")
        token_id = fields.get("token_id", "")
        issued_str = fields.get("issued_at_utc", "")
        expires_str = fields.get("expires_at_utc", "")
        actual_sig = fields.get("hmac_sha256", "").lower()
        exp_dt = utc_time(datetime.fromisoformat(expires_str.replace("Z", "+00:00")), "expires_at_utc")
        iss_dt = utc_time(datetime.fromisoformat(issued_str.replace("Z", "+00:00")), "issued_at_utc")
        ts = utc_time(self._clock(), "clock") if now is None else utc_time(now, "now")
        if ts < iss_dt - timedelta(seconds=30) or ts > exp_dt:
            raise ContractError("OWNER_RECOVERY_TOKEN_EXPIRED")
        key = _load_or_create_recovery_key(self._key_path)
        msg = f"cas-forex-owner-recovery/1|{token_id}|{scope}|{tok_target}|{issued_str}|{expires_str}"
        expected_sig = hmac.new(key, msg.encode("utf-8"), sha256).hexdigest()
        if len(actual_sig) != 64 or not hmac.compare_digest(expected_sig, actual_sig):
            raise ContractError("OWNER_RECOVERY_SIGNATURE_INVALID")
        ts_str = ts.isoformat().replace("+00:00", "Z")
        return token_id, scope, expected_sig, ts_str

    def consume_on_connection(
        self,
        conn: sqlite3.Connection,
        raw_token: str,
        *,
        expected_scope: str,
        target_ref: str | None = None,
        require_exact_target: bool = False,
        owner_request_id: str,
        now: datetime | None = None,
    ) -> dict[str, str]:
        """Mark a verified recovery token consumed inside caller's active SQLite transaction (same-DB atomic commit)."""
        with self._lock:
            token_id, scope, expected_sig, ts_str = self._validate_token_for_consume(
                raw_token,
                expected_scope=expected_scope,
                target_ref=target_ref,
                require_exact_target=require_exact_target,
                owner_request_id=owner_request_id,
                now=now,
            )
            cur = conn.execute(
                """
                UPDATE owner_recovery_tokens
                   SET consumed_at_utc = ?, consumed_by = ?
                 WHERE token_id = ?
                   AND action_scope = ?
                   AND hmac_sha256 = ?
                   AND consumed_at_utc IS NULL
                """,
                (ts_str, owner_request_id, token_id, scope, expected_sig),
            )
            if cur.rowcount != 1:
                raise ContractError("OWNER_RECOVERY_TOKEN_UNKNOWN_OR_REPLAYED")
            return {
                "token_id": token_id,
                "action_scope": scope,
                "consumed_by": owner_request_id,
                "consumed_at_utc": ts_str,
            }

    @contextmanager
    def atomic_consume(
        self,
        raw_token: str,
        *,
        expected_scope: str,
        target_ref: str | None = None,
        require_exact_target: bool = False,
        owner_request_id: str,
        now: datetime | None = None,
    ) -> Iterator[dict[str, str]]:
        """Hold an uncommitted BEGIN IMMEDIATE token consumption across a dependent reservation, rolling back on failure."""
        with self._lock:
            token_id, scope, expected_sig, ts_str = self._validate_token_for_consume(
                raw_token,
                expected_scope=expected_scope,
                target_ref=target_ref,
                require_exact_target=require_exact_target,
                owner_request_id=owner_request_id,
                now=now,
            )
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    """
                    UPDATE owner_recovery_tokens
                       SET consumed_at_utc = ?, consumed_by = ?
                     WHERE token_id = ?
                       AND action_scope = ?
                       AND hmac_sha256 = ?
                       AND consumed_at_utc IS NULL
                    """,
                    (ts_str, owner_request_id, token_id, scope, expected_sig),
                )
                if cur.rowcount != 1:
                    conn.rollback()
                    raise ContractError("OWNER_RECOVERY_TOKEN_UNKNOWN_OR_REPLAYED")
                receipt = {
                    "token_id": token_id,
                    "action_scope": scope,
                    "consumed_by": owner_request_id,
                    "consumed_at_utc": ts_str,
                }
                yield receipt
                conn.commit()
            except Exception:
                if conn.in_transaction:
                    conn.rollback()
                raise
            finally:
                conn.close()

    def verify_and_consume(
        self,
        raw_token: str,
        *,
        expected_scope: str,
        target_ref: str | None = None,
        require_exact_target: bool = False,
        owner_request_id: str,
        now: datetime | None = None,
    ) -> dict[str, str]:
        with self.atomic_consume(
            raw_token,
            expected_scope=expected_scope,
            target_ref=target_ref,
            require_exact_target=require_exact_target,
            owner_request_id=owner_request_id,
            now=now,
        ) as receipt:
            return receipt


@dataclass(slots=True)
class SharedRuntimeState:
    state_dir: Path
    db_path: Path
    peak_equity_store: PeakEquityStore
    quota_store: DailyQuotaGovernanceStore
    model_gate: DurableModelExecutionGate
    owner_recovery: OwnerRecoveryVerifier
    valve_gate: ForexMetaValveGate
    profit_vault: ProfitSweepVault
    parallel_tiers: ParallelTierEngine
    thinking_depth_path: Path
    initial_thinking_depth: str
    oanda_mutation_journal: OandaMutationJournal
    mt5_mutation_journal: Mt5MutationJournal


def initialize_shared_runtime_state(
    environ: Mapping[str, str],
    *,
    explicit_state_dir: str | Path | None = None,
    scope_id: str = "dual-shield-barbell",
    max_drawdown_pct: Decimal = DEFAULT_MAX_DRAWDOWN_PCT,
    clock: Any | None = None,
) -> SharedRuntimeState:
    """Initialize verified SQLite WAL shared state + recovery verifier inside `state_dir` (fail closed)."""
    raw_dir = str(explicit_state_dir).strip() if explicit_state_dir is not None else ""
    if not raw_dir:
        raw_dir = str(environ.get(ENV_STATE_DIR, "")).strip()
    if not raw_dir and os.name == "nt":
        raw_dir = DEFAULT_WINDOWS_STATE_DIR
    if not raw_dir:
        raise ContractError(
            f"Persistent owner-only state directory required: pass --state-dir or set {ENV_STATE_DIR}"
        )
    env_troot = str(environ.get(ENV_TRUSTED_STATE_ROOT, "")).strip() or None
    sdir, held_dir_fd = open_verified_directory_fd(raw_dir, create=True, trusted_root=env_troot, label="state_dir")
    db_name = "cas_forex_state.sqlite3"
    db_path = sdir / db_name
    try:
        if os.name == "posix" and held_dir_fd is not None:
            euid = os.geteuid()
            db_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            db_fd = os.open(db_name, db_flags, 0o600, dir_fd=held_dir_fd)
            try:
                st_db = os.fstat(db_fd)
                if not stat.S_ISREG(st_db.st_mode):
                    raise ContractError(f"Refusing non-regular state DB: {db_path}")
                if st_db.st_uid != euid:
                    raise ContractError(f"Refusing foreign-owned state DB (uid={st_db.st_uid}): {db_path}")
                if st_db.st_nlink != 1:
                    raise ContractError(f"Refusing hard-linked state DB (nlink={st_db.st_nlink}): {db_path}")
                if (st_db.st_mode & 0o077) != 0:
                    raise ContractError(f"Refusing state DB with unsafe group/world permissions: {db_path}")
                expected_id = (int(st_db.st_dev), int(st_db.st_ino))
            finally:
                os.close(db_fd)
            _load_or_create_recovery_key(sdir / ".owner_recovery.key", dir_fd=held_dir_fd)
        else:
            if os.path.lexists(db_path):
                st_db = os.lstat(db_path)
                if _is_symlink_or_reparse(db_path, st_db) or not stat.S_ISREG(st_db.st_mode):
                    raise ContractError(f"Refusing symlink or non-regular state DB: {db_path}")
                if st_db.st_nlink != 1:
                    raise ContractError(f"Refusing hard-linked state DB: {db_path}")
                verify_windows_owner_and_dacl(db_path, label="state DB")
            for sc_n in (f"{db_name}-wal", f"{db_name}-shm", f"{db_name}-journal"):
                sc_full = sdir / sc_n
                if os.path.lexists(sc_full):
                    verify_windows_owner_and_dacl(sc_full, label=f"state DB sidecar {sc_n}", ignore_missing=True)
            expected_id = None

        conn = sqlite3.connect(str(db_path), timeout=10.0, isolation_level=None)
        try:
            if expected_id is not None and held_dir_fd is not None:
                st_post = os.lstat(db_name, dir_fd=held_dir_fd)
                if (int(st_post.st_dev), int(st_post.st_ino)) != expected_id:
                    raise ContractError("State DB inode changed during open (possible path-replacement race)")
            if os.name == "nt":
                _apply_windows_protected_owner_dacl(db_path, is_dir=False)
                verify_windows_owner_and_dacl(db_path, label="state DB")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            row = conn.execute("PRAGMA quick_check").fetchone()
            if row is None or str(row[0]).lower() != "ok":
                raise ContractError(f"State SQLite integrity check failed: {row}")
        finally:
            conn.close()
    finally:
        if held_dir_fd is not None:
            os.close(held_dir_fd)

    owner_recovery = OwnerRecoveryVerifier(db_path=db_path, key_path=sdir / ".owner_recovery.key", clock=clock)
    peak_store = PeakEquityStore(db_path)
    valve_gate = load_default_forex_valve_gate(max_drawdown_pct=max_drawdown_pct, peak_equity_store=peak_store)
    quota_store = DailyQuotaGovernanceStore.from_environ(environ, path=db_path, scope_id=scope_id)
    quota_store.bind_owner_verifier(owner_recovery)

    if ENV_MODEL_MAX_CALLS_PER_DAY in environ:
        raw_calls = str(environ[ENV_MODEL_MAX_CALLS_PER_DAY]).strip()
        if not raw_calls or not raw_calls.isascii() or not raw_calls.isdigit():
            raise ContractError(
                f"Invalid explicit {ENV_MODEL_MAX_CALLS_PER_DAY}={environ[ENV_MODEL_MAX_CALLS_PER_DAY]!r}: "
                f"must be a positive integer in 1..{MAX_POLICY_MODEL_CALLS_PER_DAY}"
            )
        max_calls = int(raw_calls)
        if max_calls <= 0 or max_calls > MAX_POLICY_MODEL_CALLS_PER_DAY:
            raise ContractError(
                f"Invalid explicit {ENV_MODEL_MAX_CALLS_PER_DAY}={max_calls}: must be in 1..{MAX_POLICY_MODEL_CALLS_PER_DAY}"
            )
    else:
        max_calls = 5000

    if ENV_MODEL_MAX_DAILY_SPEND_USD in environ:
        raw_spend = str(environ[ENV_MODEL_MAX_DAILY_SPEND_USD]).strip()
        if not raw_spend:
            raise ContractError(f"Invalid explicit empty {ENV_MODEL_MAX_DAILY_SPEND_USD}")
        try:
            max_spend = Decimal(raw_spend)
        except (InvalidOperation, ValueError) as exc:
            raise ContractError(f"Invalid explicit {ENV_MODEL_MAX_DAILY_SPEND_USD}={raw_spend!r}") from exc
        if not max_spend.is_finite() or max_spend <= Decimal("0") or max_spend > MAX_POLICY_MODEL_DAILY_SPEND_USD:
            raise ContractError(
                f"Invalid explicit {ENV_MODEL_MAX_DAILY_SPEND_USD}={raw_spend!r}: "
                f"must be finite in (0, {MAX_POLICY_MODEL_DAILY_SPEND_USD}]"
            )
    else:
        max_spend = Decimal("25.00")
    model_gate = DurableModelExecutionGate(
        db_path,
        max_calls_per_day=max_calls,
        max_daily_spend_usd=max_spend,
        scope_id=scope_id,
        clock=clock,
    )
    raw_ratio = str(environ.get(ENV_PROFIT_SWEEP_RATIO, "")).strip()
    sweep_ratio = Decimal(raw_ratio) if raw_ratio else DEFAULT_SWEEP_RATIO
    raw_auto = str(environ.get(ENV_PROFIT_SWEEP_AUTO_ENABLED, "true")).strip().lower()
    auto_sweep = raw_auto not in ("0", "false", "no", "off")
    raw_rail = str(environ.get(ENV_PROFIT_SWEEP_PREFERRED_RAIL, RAIL_BROKER_2FA_MANUAL)).strip().upper()
    if raw_rail not in VALID_PAYOUT_RAILS:
        raw_rail = RAIL_BROKER_2FA_MANUAL

    profit_vault = ProfitSweepVault(
        sdir / "profit_vault.sqlite3",
        scope_id=scope_id,
        sweep_ratio=sweep_ratio,
        auto_sweep_enabled=auto_sweep,
        preferred_rail=raw_rail,
        clock=clock,
    )
    parallel_tiers = ParallelTierEngine(
        sdir / "parallel_tiers.sqlite3",
        valve_gate=valve_gate,
        sweep_ratio=sweep_ratio,
        clock=clock,
    )
    td_path = sdir / "thinking_depth.json"
    env_td = str(environ.get(ENV_THINKING_DEPTH, "")).strip().upper()
    if env_td in VALID_THINKING_DEPTHS:
        init_td = env_td
    elif td_path.is_file() and not td_path.is_symlink():
        try:
            saved_td = str(json.loads(td_path.read_text(encoding="utf-8")).get("thinking_depth", "AUTO")).strip().upper()
            init_td = saved_td if saved_td in VALID_THINKING_DEPTHS else "AUTO"
        except (OSError, ValueError, TypeError):
            init_td = "AUTO"
    else:
        init_td = "AUTO"

    oanda_mutation_journal = OandaMutationJournal(db_path)
    mt5_mutation_journal = Mt5MutationJournal(db_path)
    return SharedRuntimeState(
        state_dir=sdir,
        db_path=db_path,
        peak_equity_store=peak_store,
        quota_store=quota_store,
        model_gate=model_gate,
        owner_recovery=owner_recovery,
        valve_gate=valve_gate,
        profit_vault=profit_vault,
        parallel_tiers=parallel_tiers,
        thinking_depth_path=td_path,
        initial_thinking_depth=init_td,
        oanda_mutation_journal=oanda_mutation_journal,
        mt5_mutation_journal=mt5_mutation_journal,
    )
