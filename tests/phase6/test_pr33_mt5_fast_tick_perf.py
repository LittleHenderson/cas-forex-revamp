"""Performance and zero-weakening regression tests for PR #33 fast-tick / HTTP hotfix."""
from __future__ import annotations

from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import http.client
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from cas_forex_revamp.composition.live_cockpit_server import (
    LoopbackCockpitServer,
    _ExclusiveThreadingHTTPServer,
    _build_mt5_index_snapshot_from_router,
)
from cas_forex_revamp.venue import mt5_broker_bridge as bridge_mod
from cas_forex_revamp.venue.mt5_broker_bridge import (
    BROKER_HUGOSWAY_MT5,
    Mt5Credentials,
    Mt5PreDispatchTransportError,
    Mt5SnapshotIntegrityError,
    Mt5SpoolBridgeTransport,
    Mt5SpoolPaperTerminalEmulator,
    Mt5Tick,
    Mt5TransportError,
    SpoolPathCustodyObservation,
    _atomic_write_bytes,
    sign_mt5_market_snapshot_doc,
)

D = Decimal
T0 = datetime(2026, 11, 21, 14, 0, 0, tzinfo=timezone.utc)
REPO_ROOT = Path(__file__).resolve().parents[2]


class _MutableClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


class _MutableMono:
    def __init__(self, start: float = 100.0) -> None:
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> float:
        self.now += float(seconds)
        return self.now


class Pr33Mt5FastTickPerfTests(unittest.TestCase):
    def test_symbol_ticks_batch_single_read_parity_and_per_symbol_errors(self) -> None:
        clock = _MutableClock(T0)
        quotes = {
            "NAS100": (D("21000.25"), D("21001.50")),
            "US30": (D("44100.00"), D("44102.00")),
            "SPX500": (D("6010.10"), D("6010.60")),
            "XAUUSD": (D("2700.10"), D("2700.40")),
        }
        with tempfile.TemporaryDirectory() as td:
            spool = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool,
                server="Hugo demo PRO5",
                login=7001234,
                quotes=quotes,
                balance=D("12000"),
                clock=clock,
            )
            emu.publish_market()
            tr = Mt5SpoolBridgeTransport(spool, sleep=emu.sleep_hook, poll_interval_seconds=0.01, clock=clock)
            creds = Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugo demo PRO5")
            tr.connect(creds)

            with mock.patch.object(tr, "_market_doc", wraps=tr._market_doc) as wrapped_doc:
                found, errors = tr.symbol_ticks_batch(("NAS100", "US30", "SPX500", "XAUUSD"))
                self.assertEqual(wrapped_doc.call_count, 1)
                self.assertEqual(errors, {})
                self.assertEqual(set(found.keys()), {"NAS100", "US30", "SPX500", "XAUUSD"})

            for sym in ("NAS100", "US30", "SPX500", "XAUUSD"):
                single = tr.symbol_tick(sym)
                self.assertEqual(found[sym], single)

            # Empty batch short-circuits cleanly
            empty_found, empty_errors = tr.symbol_ticks_batch(())
            self.assertEqual(empty_found, {})
            self.assertEqual(empty_errors, {})

            # Disconnected terminal still raises Mt5PreDispatchTransportError (publish as seq=2 via emulator first)
            emu.set_connected(False)
            emu.publish_market()
            with self.assertRaises(Mt5PreDispatchTransportError):
                tr.symbol_ticks_batch(("NAS100",))

            # Mixed fresh + stale + future + missing ticks rejected cleanly per symbol (reconnected, seq=4 after seq=3)
            emu.set_connected(True)
            emu.publish_market()
            doc = json.loads((spool / "market_ticks.json").read_text(encoding="utf-8"))
            old_ms = str(int((clock() - timedelta(seconds=120)).timestamp() * 1000))
            future_ms = str(int((clock() + timedelta(seconds=20)).timestamp() * 1000))
            new_ticks = []
            for item in doc["ticks"]:
                sym = item["symbol"]
                if sym == "US30":
                    item = {**item, "time_msc": old_ms}
                elif sym == "SPX500":
                    item = {**item, "time_msc": future_ms}
                elif sym == "XAUUSD":
                    continue
                new_ticks.append(item)
            doc["ticks"] = new_ticks
            signed = sign_mt5_market_snapshot_doc(doc, spool_dir=spool, snapshot_seq=4, observed_at=clock())
            (spool / "market_ticks.json").write_text(json.dumps(signed), encoding="utf-8")

            found2, errors2 = tr.symbol_ticks_batch(("NAS100", "US30", "SPX500", "XAUUSD"))
            self.assertEqual(set(found2.keys()), {"NAS100"})
            self.assertEqual(
                errors2,
                {
                    "US30": "Mt5SnapshotIntegrityError",
                    "SPX500": "Mt5SnapshotIntegrityError",
                    "XAUUSD": "Mt5TransportError",
                },
            )

    def test_snapshot_seq_fast_path_security_and_custody_recheck_window(self) -> None:
        clock = _MutableClock(T0)
        mono = _MutableMono(100.0)
        with tempfile.TemporaryDirectory() as td:
            spool = Path(td) / "hugosway_mt5"
            emu = Mt5SpoolPaperTerminalEmulator(
                spool,
                server="Hugo demo PRO5",
                login=7001234,
                quotes={"NAS100": (D("21000.25"), D("21001.50"))},
                balance=D("12000"),
                clock=clock,
            )
            emu.publish_market()
            tr = Mt5SpoolBridgeTransport(
                spool,
                sleep=emu.sleep_hook,
                poll_interval_seconds=0.01,
                clock=clock,
                monotonic=mono,
            )
            creds = Mt5Credentials(BROKER_HUGOSWAY_MT5, 7001234, "Hugo demo PRO5")
            tr.connect(creds)

            raw_doc = json.loads((spool / "market_ticks.json").read_text(encoding="utf-8"))
            seq1_mac = raw_doc["snapshot_hmac_sha256"].lower()

            # Warm fast-path: same (seq=1, mac) within 5s custody window skips _read_spool_json & _atomic_write_json on seq ledger
            with (
                mock.patch("cas_forex_revamp.venue.mt5_broker_bridge._read_spool_json", wraps=bridge_mod._read_spool_json) as mock_read,
                mock.patch("cas_forex_revamp.venue.mt5_broker_bridge._atomic_write_json", wraps=bridge_mod._atomic_write_json) as mock_write,
            ):
                tr._verify_and_record_snapshot_seq(1, seq1_mac)
                tr._verify_and_record_snapshot_seq(1, seq1_mac)
                self.assertEqual(mock_read.call_count, 0)
                self.assertEqual(mock_write.call_count, 0)

                # Same-seq equivocation STILL rejected immediately on fast-path
                with self.assertRaises(Mt5SnapshotIntegrityError):
                    tr._verify_and_record_snapshot_seq(1, "f" * 64)

                # Advance to seq=2, then rollback to seq=1 STILL rejected immediately
                emu.publish_market()
                doc2 = json.loads((spool / "market_ticks.json").read_text(encoding="utf-8"))
                seq2_mac = doc2["snapshot_hmac_sha256"].lower()
                tr._verify_and_record_snapshot_seq(2, seq2_mac)
                with self.assertRaises(Mt5SnapshotIntegrityError):
                    tr._verify_and_record_snapshot_seq(1, seq1_mac)

            # After >= 5.0s elapsed, custody & disk ledger re-verification runs again
            mono.advance(5.5)
            with mock.patch("cas_forex_revamp.venue.mt5_broker_bridge._read_spool_json", wraps=bridge_mod._read_spool_json) as mock_read_after:
                tr._verify_and_record_snapshot_seq(2, seq2_mac)
                self.assertEqual(mock_read_after.call_count, 1)

            # External tampering on .snapshot_seq.json detected immediately via lstat signature mismatch even within < 5.0s
            tr._snapshot_seq_path.write_text('{"last_snapshot_seq":"bad","last_snapshot_hmac":"0"}', encoding="utf-8")
            with self.assertRaises(Mt5SnapshotIntegrityError):
                tr._verify_and_record_snapshot_seq(2, seq2_mac)

    def test_atomic_write_bytes_retries_transient_windows_permission_error_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "seq.json"

            def no_op_inspector(p: Path) -> SpoolPathCustodyObservation:
                return SpoolPathCustodyObservation(
                    path=str(p),
                    platform="posix",
                    exists=False,
                    is_dir=False,
                    is_reg=False,
                    is_reparse_or_symlink=False,
                )

            real_replace = os.replace
            calls = {"n": 0}

            def flaky_replace(src: Path, dst: Path) -> None:
                calls["n"] += 1
                if calls["n"] < 3:
                    raise PermissionError("simulated transient AV/indexer lock")
                real_replace(src, dst)

            with (
                mock.patch("cas_forex_revamp.venue.mt5_broker_bridge.os.name", "nt"),
                mock.patch("cas_forex_revamp.venue.mt5_broker_bridge.os.replace", side_effect=flaky_replace),
                mock.patch("cas_forex_revamp.venue.mt5_broker_bridge.time.sleep"),
            ):
                _atomic_write_bytes(target, b'{"ok":true}\n', custody_inspector=no_op_inspector)
            self.assertEqual(calls["n"], 3)
            self.assertEqual(target.read_bytes(), b'{"ok":true}\n')

            # Persistent PermissionError fails closed after 5 retries and removes .tmp files
            with (
                mock.patch("cas_forex_revamp.venue.mt5_broker_bridge.os.name", "nt"),
                mock.patch("cas_forex_revamp.venue.mt5_broker_bridge.os.replace", side_effect=PermissionError("locked")),
                mock.patch("cas_forex_revamp.venue.mt5_broker_bridge.time.sleep"),
            ):
                with self.assertRaises(Mt5TransportError):
                    _atomic_write_bytes(target, b'{"fail":true}\n', custody_inspector=no_op_inspector)
            leftover_tmps = [p for p in Path(td).iterdir() if p.name.startswith(".") and p.name.endswith(".tmp")]
            self.assertEqual(leftover_tmps, [])

    def test_build_mt5_index_snapshot_caches_by_stat_throttles_logs_and_skips_redundant_candles(self) -> None:
        mono = _MutableMono(50.0)
        with tempfile.TemporaryDirectory() as td:
            spool = Path(td) / "hugosway_mt5"
            spool.mkdir()
            ticks_path = spool / "market_ticks.json"
            ticks_path.write_text('{"seq":1}\n', encoding="utf-8")

            sample_ticks = {
                "NAS100": Mt5Tick("NAS100", D("21000.25"), D("21001.50"), "1700000000000"),
                "US30": Mt5Tick("US30", D("44100.00"), D("44102.00"), "1700000000000"),
            }
            sample_errors = {"SPX500": "Mt5SnapshotIntegrityError", "XAUUSD": "Mt5TransportError"}

            tr = mock.MagicMock()
            tr.spool_dir = spool
            tr.symbol_ticks_batch.return_value = (sample_ticks, sample_errors)
            bar_pair = [
                {"t": "2026-11-21T14:00:00Z", "o": "21000", "h": "21001", "l": "20999", "c": "21000.5", "v": "1", "n": 1},
                {"t": "2026-11-21T14:01:00Z", "o": "21000.5", "h": "21002", "l": "21000", "c": "21001", "v": "1", "n": 1},
            ]
            tr.read_index_candles.return_value = {
                "candles_m1": bar_pair,
                "candles_m5": bar_pair,
                "candles_h1": bar_pair,
            }

            venue = SimpleNamespace(_transport=tr, account=object())
            router = SimpleNamespace(venues={BROKER_HUGOSWAY_MT5: venue}, _status={BROKER_HUGOSWAY_MT5: "ACTIVE"})
            poll_cache: dict[str, dict[str, object]] = {}
            log_throttle: dict[tuple[str, str, str], tuple[float, int]] = {}

            buf = io.StringIO()
            with redirect_stdout(buf):
                snap1, q1 = _build_mt5_index_snapshot_from_router(
                    router,
                    prev_stream=None,
                    poll_cache=poll_cache,
                    log_throttle=log_throttle,
                    mono_clock=mono,
                )
                self.assertIsNotNone(snap1)
                self.assertEqual(set(q1.keys()), {"NAS100", "US30"})
                self.assertEqual(tr.symbol_ticks_batch.call_count, 1)
                self.assertEqual(tr.read_index_candles.call_count, 2)

                # Subsequent 50ms polls within <1.0s with unchanged file skip batch read & candles, and throttle logs
                for _ in range(5):
                    mono.advance(0.05)
                    snap2, q2 = _build_mt5_index_snapshot_from_router(
                        router,
                        prev_stream=snap1,
                        poll_cache=poll_cache,
                        log_throttle=log_throttle,
                        mono_clock=mono,
                    )
                    self.assertIsNotNone(snap2)
                    self.assertEqual(set(q2.keys()), {"NAS100", "US30"})
                self.assertEqual(tr.symbol_ticks_batch.call_count, 1)
                self.assertEqual(tr.read_index_candles.call_count, 2)

                # File modification triggers fresh batch read immediately, while candles remain skipped via prev_stream
                ticks_path.write_text('{"seq":2,"updated":true}\n', encoding="utf-8")
                snap3, _ = _build_mt5_index_snapshot_from_router(
                    router,
                    prev_stream=snap1,
                    poll_cache=poll_cache,
                    log_throttle=log_throttle,
                    mono_clock=mono,
                )
                self.assertIsNotNone(snap3)
                self.assertEqual(tr.symbol_ticks_batch.call_count, 2)
                self.assertEqual(tr.read_index_candles.call_count, 2)

                # Re-checks after >= 1.0s even without file modification
                mono.advance(1.1)
                _build_mt5_index_snapshot_from_router(
                    router,
                    prev_stream=snap1,
                    poll_cache=poll_cache,
                    log_throttle=log_throttle,
                    mono_clock=mono,
                )
                self.assertEqual(tr.symbol_ticks_batch.call_count, 3)

                # 5 + 1 + 1 = 7 repeats suppressed while inside 60s window; next poll after 60s prints suppressed count
                mono.advance(60.5)
                _build_mt5_index_snapshot_from_router(
                    router,
                    prev_stream=snap1,
                    poll_cache=poll_cache,
                    log_throttle=log_throttle,
                    mono_clock=mono,
                )

            logged = buf.getvalue()
            spx_lines = [ln for ln in logged.splitlines() if "SPX500" in ln]
            self.assertEqual(len(spx_lines), 2)
            self.assertIn("suppressed 7 repeats", spx_lines[1])

    def test_deadline_rfile_allows_slow_within_deadline_and_keepalive_and_aborts_slowloris(self) -> None:
        self.assertGreaterEqual(int(_ExclusiveThreadingHTTPServer.request_queue_size), 64)
        srv = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            port=0,
            header_deadline_seconds=1.2,
        )
        srv.start()
        self.addCleanup(srv.stop)

        # Delayed first request (> 0.10s old CPython timeout, < 1.2s deadline) and second keep-alive request succeed
        conn = http.client.HTTPConnection("127.0.0.1", srv.bound_port, timeout=3.0)
        try:
            conn.connect()
            time.sleep(0.25)
            conn.request("GET", "/api/health", headers={"Host": f"127.0.0.1:{srv.bound_port}", "Connection": "keep-alive"})
            r1 = conn.getresponse()
            r1.read()
            self.assertEqual(r1.status, 200)

            time.sleep(0.25)
            conn.request("GET", "/api/health", headers={"Host": f"127.0.0.1:{srv.bound_port}", "Connection": "close"})
            r2 = conn.getresponse()
            r2.read()
            self.assertEqual(r2.status, 200)
        finally:
            conn.close()

        # True slowloris still aborts at deadline
        srv_slow = LoopbackCockpitServer(
            repo_root=REPO_ROOT,
            port=0,
            header_deadline_seconds=0.30,
        )
        srv_slow.start()
        self.addCleanup(srv_slow.stop)

        with socket.create_connection(("127.0.0.1", srv_slow.bound_port), timeout=2.0) as s_slow:
            s_slow.sendall(b"GET /api/health HTTP/1.1\r\n")
            s_slow.settimeout(1.2)
            data = s_slow.recv(1024)
            self.assertEqual(data, b"")
        time.sleep(0.05)
        self.assertGreaterEqual(int(srv_slow.pre_auth_timeouts_total), 1)
