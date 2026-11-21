"""Regression tests for PR #32 Security Audit (443a5c4) Cockpit & Custody findings: [5], [7], [10], [11], [12]."""

from __future__ import annotations

import ctypes
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any
import unittest
from unittest import mock

from cas_forex_revamp.composition.live_cockpit_server import (
    MAX_TRACKED_PRE_AUTH_KEYS,
    LoopbackCockpitServer,
    _BoundedPreAuthRateTracker,
    _ExclusiveThreadingHTTPServer,
    _canonical_pre_auth_principal,
    run_cockpit_cli as cockpit_cli_main,
    write_live_auth_ticket_bundle_atomic,
)
from cas_forex_revamp.composition.state_store import (
    _evaluate_windows_security_descriptor,
    _windows_current_user_sid,
    _windows_sid_and_dacl_info,
    create_owner_only_file_atomic,
    ensure_secure_state_directory,
    initialize_shared_runtime_state,
    open_verified_directory_fd,
    open_verified_sqlite_connection,
    verify_non_symlink_sqlite_target,
    verify_windows_owner_and_dacl,
)
from cas_forex_revamp.contracts import ContractError

REPO_ROOT = Path(__file__).resolve().parents[2]


def _http_json(
    port: int,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body_obj: Any = None,
    timeout: float = 5.0,
) -> tuple[int, dict[str, Any]]:
    req_hdrs = dict(headers or {})
    payload: bytes | None = None
    if body_obj is not None:
        payload = json.dumps(body_obj).encode("utf-8")
        req_hdrs.setdefault("Content-Type", "application/json")
        req_hdrs["Content-Length"] = str(len(payload))
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request(method, path, body=payload, headers=req_hdrs)
        resp = conn.getresponse()
        raw = resp.read()
        doc = json.loads(raw.decode("utf-8")) if raw else {}
        return int(resp.status), doc
    finally:
        conn.close()


def _set_windows_sddl_or_null_dacl(target: Path, *, sddl: str | None) -> None:
    """Test helper applying either a NULL DACL (sddl=None) or explicit SDDL DACL on Windows."""
    import ctypes.wintypes as wt

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    advapi32.SetNamedSecurityInfoW.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        wt.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    advapi32.SetNamedSecurityInfoW.restype = wt.DWORD

    if sddl is None:
        # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION with pDacl=NULL -> true NULL DACL
        rc = advapi32.SetNamedSecurityInfoW(
            str(target),
            1,
            0x00000004 | 0x80000000,
            None,
            None,
            None,
            None,
        )
        if rc != 0:
            raise RuntimeError(f"SetNamedSecurityInfoW NULL DACL failed rc={rc}")
        return

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
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    p_sd = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(p_sd), None):
        raise RuntimeError(f"ConvertStringSecurityDescriptorToSecurityDescriptorW failed err={ctypes.get_last_error()}")
    try:
        present = wt.BOOL(0)
        defaulted = wt.BOOL(0)
        p_dacl = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            p_sd, ctypes.byref(present), ctypes.byref(p_dacl), ctypes.byref(defaulted)
        ):
            raise RuntimeError("GetSecurityDescriptorDacl failed")
        rc = advapi32.SetNamedSecurityInfoW(
            str(target),
            1,
            0x00000004 | 0x80000000,
            None,
            None,
            p_dacl,
            None,
        )
        if rc != 0:
            raise RuntimeError(f"SetNamedSecurityInfoW SDDL failed rc={rc}")
    finally:
        if p_sd.value:
            kernel32.LocalFree(p_sd)


class Audit443a5c4CockpitAndCustodyFindingsTests(unittest.TestCase):
    """Security regression suite covering PR #32 Findings [5], [7], [10], [11], [12]."""

    def test_finding_05_pure_windows_dacl_evaluator_rejects_null_foreign_inherit_and_empty(self) -> None:
        cur = "S-1-5-21-1000-2000-3000-1001"
        foreign_user = "S-1-5-21-1000-2000-3000-1002"
        power_users = "S-1-5-32-547"
        builtin_users = "S-1-5-32-545"

        # 1. Valid protected owner-only DACL (SYSTEM + Administrators + current user) succeeds
        valid_aces = [
            (0, 0x03, 0x1F01FF, "S-1-5-18"),
            (0, 0x03, 0x1F01FF, "S-1-5-32-544"),
            (0, 0x03, 0x1F01FF, cur),
        ]
        _evaluate_windows_security_descriptor(cur, cur, True, False, valid_aces, label="state_dir", path="D:\\state")

        # 2. Missing DACL and NULL DACL MUST fail closed
        with self.assertRaises(ContractError):
            _evaluate_windows_security_descriptor(cur, cur, False, False, valid_aces, label="state_dir", path="D:\\s")
        with self.assertRaises(ContractError):
            _evaluate_windows_security_descriptor(cur, cur, True, True, [], label="state_dir", path="D:\\s")

        # 3. Foreign owner SID MUST fail closed
        with self.assertRaises(ContractError):
            _evaluate_windows_security_descriptor(
                foreign_user, cur, True, False, valid_aces, label="state_dir", path="D:\\s"
            )

        # 4. Specific foreign user SID, Power Users, or BUILTIN\Users with even 1 read bit MUST fail closed
        for untrusted_sid in (foreign_user, power_users, builtin_users, "S-1-1-0", "S-1-5-11"):
            with self.assertRaises(ContractError):
                _evaluate_windows_security_descriptor(
                    cur,
                    cur,
                    True,
                    False,
                    [*valid_aces, (0, 0x00, 0x00000001, untrusted_sid)],
                    label="state_dir",
                    path="D:\\s",
                )

        # 5. INHERIT_ONLY_ACE (0x08 | 0x01) for a foreign SID MUST also fail closed
        with self.assertRaises(ContractError):
            _evaluate_windows_security_descriptor(
                cur,
                cur,
                True,
                False,
                [*valid_aces, (0, 0x09, 0x00120089, foreign_user)],
                label="state_dir",
                path="D:\\s",
            )

        # 6. Preceding ACCESS_DENIED_ACE covering exact mask neutralizes later allow; partial deny still fails closed
        _evaluate_windows_security_descriptor(
            cur,
            cur,
            True,
            False,
            [(1, 0x03, 0x1F01FF, foreign_user), *valid_aces, (0, 0x03, 0x0001, foreign_user)],
            label="state_dir",
            path="D:\\s",
        )
        with self.assertRaises(ContractError):
            _evaluate_windows_security_descriptor(
                cur,
                cur,
                True,
                False,
                [(1, 0x00, 0x0001, foreign_user), *valid_aces, (0, 0x00, 0x0003, foreign_user)],
                label="state_dir",
                path="D:\\s",
            )

        # 7. Empty DACL or inherit-only trusted ACEs (zero direct allow) or unsupported ACE type MUST fail closed
        with self.assertRaises(ContractError):
            _evaluate_windows_security_descriptor(cur, cur, True, False, [], label="state_dir", path="D:\\s")
        with self.assertRaises(ContractError):
            _evaluate_windows_security_descriptor(
                cur, cur, True, False, [(0, 0x08, 0x1F01FF, cur)], label="state_dir", path="D:\\s"
            )
        with self.assertRaises(ContractError):
            _evaluate_windows_security_descriptor(
                cur, cur, True, False, [*valid_aces, (9, 0x00, 0x1F01FF, cur)], label="state_dir", path="D:\\s"
            )

    def test_finding_05_windows_handle_custody_rejects_null_dacl_and_foreign_ace_on_dir_and_wal(self) -> None:
        if os.name != "nt":
            # Cross-platform verification of verify_windows_owner_and_dacl delegation when running on Linux EC2
            cur_sim = "S-1-5-21-777-888-999-1001"
            with (
                mock.patch("cas_forex_revamp.composition.state_store.os.name", "nt"),
                mock.patch("cas_forex_revamp.composition.state_store._windows_current_user_sid", return_value=cur_sim),
                mock.patch(
                    "cas_forex_revamp.composition.state_store._windows_sid_and_dacl_info",
                    return_value=(cur_sim, True, True, []),
                ),
            ):
                with self.assertRaises(ContractError):
                    verify_windows_owner_and_dacl(REPO_ROOT / "simulated_null_dacl_target")
            return

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cur_sid = _windows_current_user_sid()

            # 1. Protected DACL applied on ensure_secure_state_directory & create_owner_only_file_atomic
            good_dir = ensure_secure_state_directory(root / "good_state")
            owner_sid, present, is_null, aces = _windows_sid_and_dacl_info(good_dir)
            self.assertEqual(owner_sid, cur_sid)
            self.assertIs(present, True)
            self.assertIs(is_null, False)
            ace_sids = {a[3] for a in aces}
            self.assertTrue(ace_sids.issubset({cur_sid, "S-1-5-18", "S-1-5-32-544"}))

            # 2. NULL-DACL directory MUST fail closed
            null_dir = root / "null_dacl_state"
            null_dir.mkdir()
            try:
                _set_windows_sddl_or_null_dacl(null_dir, sddl=None)
                with self.assertRaises(ContractError):
                    verify_windows_owner_and_dacl(null_dir)
                with self.assertRaises(ContractError):
                    open_verified_directory_fd(null_dir, create=True)
                with self.assertRaises(ContractError):
                    initialize_shared_runtime_state({}, explicit_state_dir=null_dir)
            finally:
                _set_windows_sddl_or_null_dacl(
                    null_dir,
                    sddl=f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{cur_sid})",
                )

            # 3. Directory or SQLite -wal sidecar granting BUILTIN\Users (BU) read access MUST fail closed
            foreign_sddl = f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{cur_sid})(A;;FR;;;BU)"
            db_dir = ensure_secure_state_directory(root / "wal_check_state")
            db_file = db_dir / "safety.sqlite3"
            conn = open_verified_sqlite_connection(db_file)
            conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            conn.commit()
            conn.close()

            wal_file = db_dir / "safety.sqlite3-wal"
            wal_file.write_bytes(b"")
            try:
                _set_windows_sddl_or_null_dacl(wal_file, sddl=foreign_sddl)
                with self.assertRaises(ContractError):
                    verify_non_symlink_sqlite_target(db_file)
                with self.assertRaises(ContractError):
                    open_verified_sqlite_connection(db_file)
                with self.assertRaises(ContractError):
                    ensure_secure_state_directory(db_dir)
            finally:
                _set_windows_sddl_or_null_dacl(
                    wal_file,
                    sddl=f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{cur_sid})",
                )

    def test_finding_07_live_ticket_output_refuses_symlink_directory_and_unsafe_parent(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sdir = ensure_secure_state_directory(root / "state")
            victim = root / "privileged_target.conf"
            sentinel = b"PRIVILEGED_DO_NOT_OVERWRITE\n"
            victim.write_bytes(sentinel)

            out_dir = ensure_secure_state_directory(root / "ticket_out")
            out_file = out_dir / "live_auth_bundle.json"

            # 1. Pre-positioned symlink or junction at explicit ticket output MUST fail closed without touching victim
            link_created = False
            try:
                os.symlink(victim, out_file)
                link_created = True
            except OSError:
                if os.name == "nt":
                    junc_dir = root / "junc_target"
                    junc_dir.mkdir()
                    proc = subprocess.run(
                        ["cmd", "/c", "mklink", "/J", str(out_file), str(junc_dir)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if proc.returncode == 0 and os.path.lexists(out_file):
                        link_created = True

            if link_created:
                with self.assertRaises(ContractError):
                    write_live_auth_ticket_bundle_atomic(out_file, {"tickets": []})
                with self.assertRaises(ContractError):
                    create_owner_only_file_atomic(
                        out_dir, out_file.name, b"{}\n", replace_existing=True, label="LIVE auth ticket output"
                    )
                self.assertEqual(victim.read_bytes(), sentinel)
                if out_file.is_symlink() or os.name == "posix":
                    out_file.unlink()
                else:
                    os.rmdir(out_file)
            else:
                out_file.write_bytes(b"existing")
                with mock.patch(
                    "cas_forex_revamp.composition.state_store._is_symlink_or_reparse",
                    side_effect=lambda p, *_a, **_kw: Path(p).name == out_file.name,
                ):
                    with self.assertRaises(ContractError):
                        write_live_auth_ticket_bundle_atomic(out_file, {"tickets": []})
                self.assertEqual(victim.read_bytes(), sentinel)
                out_file.unlink()

            # 2. Directory at ticket output leaf MUST fail closed on replace_existing=True
            out_file.mkdir()
            with self.assertRaises(ContractError):
                write_live_auth_ticket_bundle_atomic(out_file, {"tickets": []})
            out_file.rmdir()

            # 3. On POSIX, world-writable explicit output parent MUST fail closed without creating ticket
            if os.name == "posix":
                unsafe_parent = root / "unsafe_ticket_parent"
                unsafe_parent.mkdir(mode=0o700)
                os.chmod(unsafe_parent, 0o777)  # nosec B103: intentional world-writable output parent fixture to verify rejection
                with self.assertRaises(ContractError):
                    write_live_auth_ticket_bundle_atomic(unsafe_parent / "bundle.json", {"tickets": []})

            # 4. End-to-end CLI --mint-live-auth-ticket succeeds safely in verified owner-only output directory
            env_patch = {
                "CAS_FOREX_LIVE_AUTH_TICKET_FILE": str(out_file),
                "CAS_FOREX_OANDA_LIVE_ACCOUNT_ID": "001-001-9999999-001",
            }
            with mock.patch.dict(os.environ, env_patch, clear=False):
                rc = cockpit_cli_main(["--state-dir", str(sdir), "--mint-live-auth-ticket"])
            self.assertEqual(rc, 0)
            self.assertTrue(out_file.is_file())
            parsed = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertIn("tickets", parsed)
            if os.name == "posix":
                self.assertEqual(os.lstat(out_file).st_mode & 0o077, 0)

    def test_finding_11_loopback_aliases_canonicalized_global_throttle_and_bounded_maps(self) -> None:
        # 1. Canonicalizer collapses all 127.0.0.0/8, ::1, and ::ffff:127.0.0.0/104 aliases to "loopback"
        for alias in (
            "127.0.0.1",
            "127.0.0.2",
            "127.19.88.204",
            "127.255.255.254",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:127.99.1.7",
        ):
            self.assertEqual(_canonical_pre_auth_principal(alias), "loopback")

        # 2. Tracker bounds keys, deletes expired histories, and never allocates keys on rate-rejection
        clock_val = [100.0]
        tracker = _BoundedPreAuthRateTracker(
            per_principal_limit=4,
            global_limit=4,
            window_seconds=10.0,
            max_keys=8,
        )
        for i in range(4):
            alias_ip = f"127.0.{i}.9"
            self.assertTrue(tracker.try_consume(_canonical_pre_auth_principal(alias_ip), clock_val[0]))
        self.assertEqual(list(tracker.per_key.keys()), ["loopback"])
        # 5th alias hits limit and allocates zero new map entries
        self.assertFalse(tracker.try_consume(_canonical_pre_auth_principal("127.99.88.77"), clock_val[0]))
        self.assertEqual(len(tracker.per_key), 1)
        # Advance clock past window -> empty histories deleted completely
        clock_val[0] += 11.0
        tracker.prune(clock_val[0])
        self.assertEqual(len(tracker.per_key), 0)
        self.assertEqual(len(tracker.global_times), 0)

        # Synthetic non-loopback keys are strictly bounded by max_keys LRU
        many_tracker = _BoundedPreAuthRateTracker(
            per_principal_limit=1000,
            global_limit=1000,
            window_seconds=60.0,
            max_keys=MAX_TRACKED_PRE_AUTH_KEYS,
        )
        for idx in range(600):
            many_tracker.try_consume(f"10.0.{idx // 256}.{idx % 256}", 200.0)
        self.assertLessEqual(len(many_tracker.per_key), MAX_TRACKED_PRE_AUTH_KEYS)

        # 3. Capacity-rejected sockets on _ExclusiveThreadingHTTPServer allocate ZERO persistent map entries
        class _NoopHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:
                return

        httpd = _ExclusiveThreadingHTTPServer(
            ("127.0.0.1", 0),
            _NoopHandler,
            ordinary_slots=1,
            peer_rate_limit_per_window=5,
            global_rate_limit_per_window=5,
            mono_clock=lambda: clock_val[0],
        )
        self.addCleanup(httpd.server_close)

        # Hold the single worker semaphore slot and send 50 distinct 127/8 aliases -> 503 capacity rejection, 0 map keys!
        self.assertTrue(httpd._ordinary_conn_sem.acquire(blocking=False))
        try:
            for idx in range(50):
                s_a, s_b = socket.socketpair()
                try:
                    httpd.process_request(s_a, (f"127.1.{idx // 250}.{(idx % 250) + 1}", 50000 + idx))
                    resp_b = s_b.recv(1024)
                    self.assertIn(b"503", resp_b)
                finally:
                    s_b.close()
            self.assertEqual(len(httpd._peer_conn_times), 0)
        finally:
            httpd._ordinary_conn_sem.release()

        # 4. Pair-exchange cycling through 500 distinct 127/8 aliases shares one "loopback" bucket & stays len <= 1
        srv = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0)
        srv.start()
        self.addCleanup(srv.stop)
        statuses: list[int] = []
        for idx in range(25):
            st_pe, _ = srv.exchange_pairing_code(
                "pair-" + "a" * 28,
                peer_key=f"127.2.{idx // 250}.{(idx % 250) + 1}",
            )
            statuses.append(st_pe)
        self.assertIn(429, statuses)
        self.assertEqual(list(srv._pair_exchange_attempts.keys()), ["loopback"])

    def test_finding_10_emergency_channel_unstarvable_under_slow_header_saturation_and_unix_ipc(self) -> None:
        class _EmergencyUiService:
            def __init__(self) -> None:
                self.calls: list[dict[str, Any]] = []

            def requestControl(self, body: dict[str, Any]) -> dict[str, Any]:
                self.calls.append(dict(body))
                return {"ok": True, "action": str(body.get("action", ""))}

            def __getattr__(self, _name: str) -> Any:
                return lambda *_a, **_kw: {"ok": True}

        ui_svc = _EmergencyUiService()
        with tempfile.TemporaryDirectory() as td:
            unix_sock_path = (Path(td) / "emerg.sock") if os.name == "posix" else None
            srv = LoopbackCockpitServer(
                repo_root=REPO_ROOT,
                port=0,
                ui_service=ui_svc,
                max_emergency_connections=2,
                emergency_header_deadline_seconds=0.35,
                emergency_unix_socket=unix_sock_path,
            )
            srv.start()
            self.addCleanup(srv.stop)
            emerg_port = srv.emergency_port

            # 1. Unauthenticated / oversized / slow-header clients rejected in selector with 0 emergency worker usage
            st_401, _ = _http_json(
                emerg_port,
                "POST",
                "/api/request-control",
                body_obj={"action": "PAUSE_NEW_RISK"},
                timeout=2.0,
            )
            self.assertEqual(st_401, 401)
            if srv._emergency_httpd is None:
                self.fail("Expected _emergency_httpd")
            self.assertEqual(srv._emergency_httpd._peak_workers, 0)

            with socket.create_connection(("127.0.0.1", emerg_port), timeout=2.0) as big_hdr_sock:
                big_hdr_sock.sendall(
                    f"POST /api/request-control HTTP/1.1\r\nHost: 127.0.0.1:{emerg_port}\r\n".encode("ascii")
                    + b"X-Pad: " + (b"A" * 8500) + b"\r\n\r\n"
                )
                resp_431 = big_hdr_sock.recv(4096)
            self.assertIn(b"431", resp_431.splitlines()[0] if resp_431 else b"")
            self.assertEqual(srv._emergency_httpd._peak_workers, 0)

            # 2. Continuous saturation: hold > max_emergency_connections (20 concurrent slow-header sockets + replacement thread)
            stop_flood = threading.Event()
            flood_socks: list[socket.socket] = []
            flood_lock = threading.Lock()

            def _flood_worker() -> None:
                partial = (
                    f"POST /api/request-control HTTP/1.1\r\nHost: 127.0.0.1:{emerg_port}\r\nX-Slow: ".encode("ascii")
                )
                while not stop_flood.is_set():
                    with flood_lock:
                        alive: list[socket.socket] = []
                        for fs in flood_socks:
                            try:
                                fs.send(b"z")
                                alive.append(fs)
                            except OSError:
                                try:
                                    fs.close()
                                except OSError:
                                    pass
                        flood_socks[:] = alive
                        need = 20 - len(flood_socks)
                    for _ in range(max(0, need)):
                        if stop_flood.is_set():
                            break
                        try:
                            s = socket.create_connection(("127.0.0.1", emerg_port), timeout=1.0)
                            s.sendall(partial)
                            with flood_lock:
                                flood_socks.append(s)
                        except OSError:
                            pass
                    time.sleep(0.03)

            flood_thread = threading.Thread(target=_flood_worker, daemon=True)
            flood_thread.start()
            try:
                time.sleep(0.12)
                # Authenticated owner emergency actions MUST succeed within fixed deadline despite 20x worker-count flood
                for seq in range(5):
                    t0 = time.monotonic()
                    st_em, doc_em = _http_json(
                        emerg_port,
                        "POST",
                        "/api/request-control",
                        headers=srv.auth_headers(),
                        body_obj={"action": "PAUSE_NEW_RISK", "seq": seq},
                        timeout=2.0,
                    )
                    elapsed = time.monotonic() - t0
                    self.assertEqual(st_em, 200)
                    self.assertIs(doc_em.get("ok"), True)
                    self.assertLess(elapsed, 1.0)
                self.assertEqual(len(ui_svc.calls), 5)

                # On POSIX, also verify owner-only 0o600 Unix domain IPC emergency socket works under TCP flood
                if os.name == "posix" and unix_sock_path is not None:
                    self.assertEqual(os.lstat(unix_sock_path).st_mode & 0o777, 0o600)
                    body_b = b'{"action":"STOP_AUTOMATION"}'
                    req_b = (
                        b"POST /api/request-control HTTP/1.1\r\n"
                        b"Host: localhost\r\n"
                        + f"Authorization: Bearer {srv.auth_token}\r\n".encode("ascii")
                        + b"Content-Type: application/json\r\n"
                        + f"Content-Length: {len(body_b)}\r\n\r\n".encode("ascii")
                        + body_b
                    )
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as us:
                        us.settimeout(2.0)
                        us.connect(str(unix_sock_path))
                        us.sendall(req_b)
                        uresp = us.recv(4096)
                    self.assertIn(b"200 OK", uresp)
            finally:
                stop_flood.set()
                flood_thread.join(timeout=2.0)
                with flood_lock:
                    for fs in flood_socks:
                        try:
                            fs.close()
                        except OSError:
                            pass

            srv.stop()
            if os.name == "posix" and unix_sock_path is not None:
                self.assertFalse(unix_sock_path.exists())

    def test_finding_12_concurrent_old_epoch_rotate_token_permits_at_most_one_transition(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tok_file = Path(td) / "cockpit.token"
            srv = LoopbackCockpitServer(repo_root=REPO_ROOT, port=0, token_file=tok_file)
            srv.start()
            self.addCleanup(srv.stop)

            # 1. Direct synchronized barrier across 8 old-epoch compare-and-rotate callers
            tok_a = srv.auth_token
            epoch_a = srv.session_epoch
            barrier = threading.Barrier(8)
            results: list[dict[str, Any]] = []
            res_lock = threading.Lock()

            def _race_direct() -> None:
                barrier.wait(timeout=3.0)
                r = srv.rotate_auth_token_detailed(
                    expected_bearer=tok_a,
                    expected_epoch=epoch_a,
                    drain_timeout_seconds=0.05,
                )
                with res_lock:
                    results.append(r)

            threads = [threading.Thread(target=_race_direct, daemon=True) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5.0)

            self.assertEqual(len(results), 8)
            winners = [r for r in results if r.get("rotated") is True]
            stales = [r for r in results if r.get("status") == "STALE_ROTATE_EPOCH" and r.get("rotated") is False]
            self.assertEqual(len(winners), 1)
            self.assertEqual(len(stales), 7)

            # Replacement token B from the single winning rotation MUST still be the active owner bearer!
            tok_b = str(winners[0]["new_token"])
            self.assertEqual(srv.auth_token, tok_b)
            self.assertEqual(tok_file.read_text(encoding="utf-8").strip(), tok_b)

            # 2. Concurrent HTTP POST /api/rotate-token race with tok_b -> exactly one 200, rest 401/closed, final token preserved
            http_barrier = threading.Barrier(6)
            http_statuses: list[int] = []

            def _race_http() -> None:
                http_barrier.wait(timeout=3.0)
                try:
                    st_code, _ = _http_json(
                        srv.bound_port,
                        "POST",
                        "/api/rotate-token",
                        headers={"Authorization": f"Bearer {tok_b}"},
                        body_obj={},
                        timeout=3.0,
                    )
                except (OSError, http.client.HTTPException):
                    st_code = 401
                with res_lock:
                    http_statuses.append(st_code)

            http_threads = [threading.Thread(target=_race_http, daemon=True) for _ in range(6)]
            for ht in http_threads:
                ht.start()
            for ht in http_threads:
                ht.join(timeout=5.0)

            self.assertEqual(http_statuses.count(200), 1)
            self.assertEqual(http_statuses.count(401), 5)
            tok_c = tok_file.read_text(encoding="utf-8").strip()
            self.assertEqual(srv.auth_token, tok_c)
            st_health, _ = _http_json(
                srv.bound_port,
                "GET",
                "/api/metrics",
                headers={"Authorization": f"Bearer {tok_c}"},
            )
            self.assertEqual(st_health, 200)


if __name__ == "__main__":
    unittest.main()
