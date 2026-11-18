"""Cryptographic LIVE real-money authorization key & ticket verification (`cas-forex-live-auth/1`).

Enforces owner-only key file permissions (`0o600` POSIX, non-symlink regular file >= 32 bytes)
and constant-time HMAC-SHA256 ticket verification bound to exact `(broker_id, account_login,
server, execution_mode=LIVE)` and bounded TTL (`<= 86400s`), replacing sole reliance on static
confirmation phrases.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Any

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.contracts.primitives import utc_time

ENV_LIVE_AUTH_KEY_FILE = "CAS_FOREX_LIVE_AUTH_KEY_FILE"  # nosec B105: env var name constant
ENV_LIVE_AUTH_TICKET_FILE = "CAS_FOREX_LIVE_AUTH_TICKET_FILE"  # nosec B105: env var name constant
ENV_LIVE_AUTH_TICKET = "CAS_FOREX_LIVE_AUTH_TICKET"  # nosec B105: env var name constant

LIVE_AUTH_PROTOCOL = "cas-forex-live-auth/1"
LIVE_AUTH_BUNDLE_PROTOCOL = "cas-forex-live-auth-bundle/1"
MAX_LIVE_TICKET_TTL_SECONDS = 86_400


class LiveAuthTicketError(ContractError):
    """Raised when LIVE authorization key material or ticket verification fails closed."""


class _RedactedLiveKey:
    """In-memory HMAC key wrapper whose repr/str never reveal secret bytes."""

    __slots__ = ("_key_bytes",)

    def __init__(self, key_bytes: bytes) -> None:
        if not isinstance(key_bytes, (bytes, bytearray)) or len(key_bytes) < 32:
            raise LiveAuthTicketError("LIVE auth key must be >= 32 bytes")
        self._key_bytes = bytes(key_bytes)

    def hmac_hex(self, canonical_payload: str) -> str:
        return hmac.new(self._key_bytes, canonical_payload.encode("utf-8"), sha256).hexdigest()

    def hex_key(self) -> str:
        return self._key_bytes.hex()

    def __repr__(self) -> str:
        return "[REDACTED_LIVE_AUTH_KEY]"

    def __str__(self) -> str:
        return "[REDACTED_LIVE_AUTH_KEY]"


def _is_symlink_or_reparse(path: Path, st: os.stat_result) -> bool:
    if stat.S_ISLNK(st.st_mode) or getattr(st, "st_reparse_tag", 0) != 0:
        return True
    is_junc = getattr(path, "is_junction", None)
    return bool(callable(is_junc) and is_junc())


def _canonical_ticket_message(fields: Mapping[str, Any]) -> str:
    ordered = (
        str(fields.get("protocol", "")),
        str(fields.get("execution_mode", "")),
        str(fields.get("broker_id", "")),
        str(fields.get("account_login", "")),
        str(fields.get("server", "")).strip(),
        str(fields.get("issued_at_utc", "")),
        str(fields.get("expires_at_utc", "")),
        str(fields.get("nonce", "")),
    )
    return "|".join(ordered)


def provision_live_auth_key(key_file: str | Path) -> Path:
    """Create a cryptographically random 32-byte owner-only (`0o600`) LIVE auth HMAC key file."""
    target = Path(key_file)
    target.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        pst = os.lstat(target.parent)
        if not _is_symlink_or_reparse(target.parent, pst) and stat.S_ISDIR(pst.st_mode):
            os.chmod(target.parent, 0o700)  # nosec B103: verified non-symlink S_ISDIR owner-only key directory
    if os.path.lexists(target):
        st = os.lstat(target)
        if _is_symlink_or_reparse(target, st) or not stat.S_ISREG(st.st_mode):
            raise LiveAuthTicketError(f"Refusing non-regular or symlink LIVE auth key path: {target}")
        load_live_auth_key(target)
        return target
    raw = (secrets.token_bytes(32).hex() + "\n").encode("ascii")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_BINARY", 0)
    )
    fd = os.open(target, flags, 0o600)
    try:
        os.write(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name == "posix":
        os.chmod(target, 0o600)  # nosec B103: owner-only 0o600 key verified on newly created regular fd
    return target


def load_live_auth_key(key_file: str | Path) -> _RedactedLiveKey:
    """Load owner-only LIVE auth key file; rejects symlinks, weak perms (`& 0o077`), and <32B keys."""
    if not isinstance(key_file, (str, Path)) or not str(key_file).strip():
        raise LiveAuthTicketError(f"{ENV_LIVE_AUTH_KEY_FILE} is required for LIVE real-money mode")
    target = Path(str(key_file).strip())
    if not os.path.lexists(target):
        raise LiveAuthTicketError(f"LIVE auth key file missing: {target}")
    st = os.lstat(target)
    if _is_symlink_or_reparse(target, st) or not stat.S_ISREG(st.st_mode):
        raise LiveAuthTicketError(f"Refusing non-regular or symlink LIVE auth key file: {target}")
    if os.name == "posix" and (st.st_mode & 0o077) != 0:
        raise LiveAuthTicketError(
            f"LIVE auth key file has unsafe group/world permissions ({oct(stat.S_IMODE(st.st_mode))}); require 0o600/0o400"
        )
    if st.st_size > 4096:
        raise LiveAuthTicketError("LIVE auth key file exceeds 4096 bytes")
    raw_bytes = target.read_bytes().strip()
    if len(raw_bytes) == 64 and all(b in b"0123456789abcdefABCDEF" for b in raw_bytes):
        return _RedactedLiveKey(bytes.fromhex(raw_bytes.decode("ascii")))
    if len(raw_bytes) < 32:
        raise LiveAuthTicketError("LIVE auth key material must be >= 32 bytes (or 64 hex chars)")
    return _RedactedLiveKey(raw_bytes)


def _iso_utc(dt: datetime) -> str:
    return utc_time(dt, "timestamp").replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso_utc(raw: Any, field: str) -> datetime:
    if not isinstance(raw, str) or not raw.strip():
        raise LiveAuthTicketError(f"LIVE auth ticket missing {field}")
    text = raw.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise LiveAuthTicketError(f"invalid ISO UTC {field} in LIVE auth ticket") from exc
    return utc_time(dt, field)


def mint_live_authorization_ticket(
    *,
    key_file: str | Path,
    broker_id: str,
    account_login: str | int,
    server: str,
    ttl_seconds: int = 3600,
    issued_at: datetime | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Mint an HMAC-SHA256 LiveAuthorizationTicket bound to broker/login/server/LIVE/expiry."""
    if not isinstance(broker_id, str) or not broker_id.strip():
        raise LiveAuthTicketError("broker_id must be a non-empty string")
    login_txt = str(account_login).strip()
    srv_txt = str(server).strip()
    if not login_txt or not srv_txt:
        raise LiveAuthTicketError("account_login and server are required")
    if type(ttl_seconds) is not int or not (60 <= ttl_seconds <= MAX_LIVE_TICKET_TTL_SECONDS):
        raise LiveAuthTicketError(f"ttl_seconds must be in 60..{MAX_LIVE_TICKET_TTL_SECONDS}")
    key = load_live_auth_key(key_file)
    now_dt = datetime.now(timezone.utc) if issued_at is None else utc_time(issued_at, "issued_at")
    exp_dt = now_dt + timedelta(seconds=ttl_seconds)
    nonce_txt = nonce if (isinstance(nonce, str) and len(nonce.strip()) >= 16) else secrets.token_hex(16)
    ticket: dict[str, str] = {
        "protocol": LIVE_AUTH_PROTOCOL,
        "execution_mode": "LIVE",
        "broker_id": broker_id.strip().upper(),
        "account_login": login_txt,
        "server": srv_txt,
        "issued_at_utc": _iso_utc(now_dt),
        "expires_at_utc": _iso_utc(exp_dt),
        "nonce": nonce_txt.strip(),
    }
    ticket["hmac_sha256"] = key.hmac_hex(_canonical_ticket_message(ticket))
    return ticket


def mint_live_authorization_bundle(
    *,
    key_file: str | Path,
    targets: list[tuple[str, str | int, str]],
    ttl_seconds: int = 3600,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    """Mint a multi-broker bundle of individually HMAC-signed LIVE tickets."""
    if not targets:
        raise LiveAuthTicketError("at least one (broker_id, account_login, server) target is required")
    now_dt = datetime.now(timezone.utc) if issued_at is None else utc_time(issued_at, "issued_at")
    tickets = [
        mint_live_authorization_ticket(
            key_file=key_file,
            broker_id=bid,
            account_login=login,
            server=srv,
            ttl_seconds=ttl_seconds,
            issued_at=now_dt,
        )
        for bid, login, srv in targets
    ]
    return {"protocol": LIVE_AUTH_BUNDLE_PROTOCOL, "tickets": tickets}


def parse_live_ticket_payload(raw_doc: Any) -> list[dict[str, str]]:
    if isinstance(raw_doc, str):
        try:
            raw_doc = json.loads(raw_doc)
        except Exception as exc:
            raise LiveAuthTicketError("malformed LIVE auth ticket JSON") from exc
    if not isinstance(raw_doc, Mapping):
        raise LiveAuthTicketError("LIVE auth ticket must be a JSON object")
    if raw_doc.get("protocol") == LIVE_AUTH_BUNDLE_PROTOCOL:
        items = raw_doc.get("tickets")
        if type(items) is not list or not items:
            raise LiveAuthTicketError("LIVE auth ticket bundle missing tickets list")
        return [dict(x) for x in items if isinstance(x, Mapping)]
    return [dict(raw_doc)]


def verify_live_authorization_ticket(
    ticket: Mapping[str, Any] | str,
    *,
    key_file: str | Path,
    expected_broker_id: str | None = None,
    expected_account_login: str | int | None = None,
    expected_server: str | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    """Verify HMAC-SHA256 signature, TTL window, and optional broker/login/server binding."""
    key = load_live_auth_key(key_file)
    candidates = parse_live_ticket_payload(ticket)
    if not candidates:
        raise LiveAuthTicketError("no LIVE auth ticket entries present")

    check_now = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
    last_error = "no matching LIVE auth ticket"
    for item in candidates:
        if any(not isinstance(k, str) or not isinstance(v, str) for k, v in item.items()):
            last_error = "LIVE auth ticket values must be strings"
            continue
        if item.get("protocol") != LIVE_AUTH_PROTOCOL or item.get("execution_mode") != "LIVE":
            last_error = "LIVE auth ticket protocol or execution_mode mismatch"
            continue
        if not item.get("nonce") or len(item["nonce"].strip()) < 16:
            last_error = "LIVE auth ticket nonce missing or too short"
            continue
        issued_dt = _parse_iso_utc(item.get("issued_at_utc"), "issued_at_utc")
        expires_dt = _parse_iso_utc(item.get("expires_at_utc"), "expires_at_utc")
        if expires_dt <= issued_dt or (expires_dt - issued_dt).total_seconds() > MAX_LIVE_TICKET_TTL_SECONDS:
            last_error = "LIVE auth ticket TTL window invalid or exceeds 86400s"
            continue
        if check_now < issued_dt - timedelta(seconds=30) or check_now > expires_dt:
            last_error = "LIVE auth ticket expired or not yet valid"
            continue
        expected_sig = key.hmac_hex(_canonical_ticket_message(item))
        actual_sig = str(item.get("hmac_sha256", "")).lower()
        if len(actual_sig) != 64 or not hmac.compare_digest(expected_sig, actual_sig):
            last_error = "LIVE auth ticket HMAC-SHA256 verification failed"
            continue
        if expected_broker_id is not None and item.get("broker_id", "").upper() != expected_broker_id.strip().upper():
            last_error = f"LIVE auth ticket broker_id mismatch for {expected_broker_id}"
            continue
        if expected_account_login is not None and item.get("account_login", "").strip() != str(expected_account_login).strip():
            last_error = f"LIVE auth ticket account_login mismatch for {expected_broker_id or 'broker'}"
            continue
        if expected_server is not None and item.get("server", "").strip().casefold() != expected_server.strip().casefold():
            last_error = f"LIVE auth ticket server mismatch for {expected_broker_id or 'broker'}"
            continue
        return dict(item)
    raise LiveAuthTicketError(last_error)


def verify_live_environ_authorization(
    environ: Mapping[str, str] | None,
    *,
    expected_broker_id: str | None = None,
    expected_account_login: str | int | None = None,
    expected_server: str | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    """Verify LIVE auth key + ticket from `CAS_FOREX_LIVE_AUTH_KEY_FILE` & ticket env/file."""
    if environ is None:
        raise LiveAuthTicketError(f"{ENV_LIVE_AUTH_KEY_FILE} is required for LIVE mode")
    key_file = str(environ.get(ENV_LIVE_AUTH_KEY_FILE, "")).strip()
    ticket_file = str(environ.get(ENV_LIVE_AUTH_TICKET_FILE, "")).strip()
    inline_ticket = str(environ.get(ENV_LIVE_AUTH_TICKET, "")).strip()
    if ticket_file:
        tpath = Path(ticket_file)
        if not os.path.lexists(tpath):
            raise LiveAuthTicketError(f"LIVE auth ticket file missing: {tpath}")
        tst = os.lstat(tpath)
        if _is_symlink_or_reparse(tpath, tst) or not stat.S_ISREG(tst.st_mode):
            raise LiveAuthTicketError(f"Refusing non-regular or symlink LIVE auth ticket file: {tpath}")
        raw_ticket: str | Mapping[str, Any] = tpath.read_text(encoding="utf-8")
    elif inline_ticket:
        raw_ticket = inline_ticket
    else:
        raise LiveAuthTicketError(
            f"LIVE mode requires {ENV_LIVE_AUTH_TICKET_FILE} or {ENV_LIVE_AUTH_TICKET} signed with {ENV_LIVE_AUTH_KEY_FILE}"
        )
    return verify_live_authorization_ticket(
        raw_ticket,
        key_file=key_file,
        expected_broker_id=expected_broker_id,
        expected_account_login=expected_account_login,
        expected_server=expected_server,
        now=now,
    )
