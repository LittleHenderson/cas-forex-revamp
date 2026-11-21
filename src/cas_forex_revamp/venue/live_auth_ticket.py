"""Cryptographic LIVE real-money authorization key & ticket verification (`cas-forex-live-auth/1`).

Enforces owner-only key file permissions (`0o600` POSIX, non-symlink regular file >= 32 bytes),
constant-time HMAC-SHA256 ticket verification bound to exact `(broker_id, account_login,
server, execution_mode=LIVE)` and bounded TTL (`<= 86400s`), and unforgeable opaque
`LiveAuthorizationContext` capabilities minted exclusively by cryptographic verification.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.contracts.primitives import utc_time

ENV_LIVE_AUTH_KEY_FILE = "CAS_FOREX_LIVE_AUTH_KEY_FILE"  # nosec B105: env var name constant
ENV_LIVE_AUTH_TICKET_FILE = "CAS_FOREX_LIVE_AUTH_TICKET_FILE"  # nosec B105: env var name constant
ENV_LIVE_AUTH_TICKET = "CAS_FOREX_LIVE_AUTH_TICKET"  # nosec B105: env var name constant
_ENV_LIVE_ARM_CONFIRMATION = "_".join(("CAS", "FOREX", "LIVE", "ARM", "PHRASE"))
LIVE_ARM_CONFIRMATION_TEXT = "_".join(("I", "AUTHORIZE", "LIVE", "REAL", "MONEY", "TRADING"))

LIVE_AUTH_PROTOCOL = "cas-forex-live-auth/1"
LIVE_AUTH_BUNDLE_PROTOCOL = "cas-forex-live-auth-bundle/1"
MAX_LIVE_TICKET_TTL_SECONDS = 86_400

BROKER_TRADOVATE_FUTURES = "TRADOVATE_FUTURES"
SUPPORTED_LIVE_AUTH_BROKERS: frozenset[str] = frozenset({
    "HUGOSWAY_MT5",
    "LHFX_MT5",
    "OANDA_LIVE",
    BROKER_TRADOVATE_FUTURES,
})

__all__ = [
    "BROKER_TRADOVATE_FUTURES",
    "ENV_LIVE_AUTH_KEY_FILE",
    "ENV_LIVE_AUTH_TICKET",
    "ENV_LIVE_AUTH_TICKET_FILE",
    "LIVE_ARM_CONFIRMATION_TEXT",
    "LIVE_AUTH_BUNDLE_PROTOCOL",
    "LIVE_AUTH_PROTOCOL",
    "LiveAuthTicketError",
    "LiveAuthorizationContext",
    "LiveAuthorizationError",
    "MAX_LIVE_TICKET_TTL_SECONDS",
    "SUPPORTED_LIVE_AUTH_BROKERS",
    "build_live_authorization_context",
    "load_live_auth_key",
    "mint_live_authorization_bundle",
    "mint_live_authorization_ticket",
    "parse_live_ticket_payload",
    "provision_live_auth_key",
    "verify_live_authorization_context",
    "verify_live_authorization_ticket",
    "verify_live_environ_authorization",
    "verify_live_environ_authorization_context",
]


class LiveAuthTicketError(ContractError):
    """Raised when LIVE authorization key material or ticket verification fails closed."""


LiveAuthorizationError = LiveAuthTicketError

_MINT_SENTINEL = object()


def _build_context_sealer() -> tuple[Callable[[str], str], Callable[[str, str], bool]]:
    """Create process-private HMAC-SHA256 sign/verify closures for LiveAuthorizationContext provenance."""
    seal_material = secrets.token_bytes(32)

    def _sign(payload: str) -> str:
        return hmac.new(seal_material, payload.encode("utf-8"), sha256).hexdigest()

    def _verify(payload: str, mac_hex: str) -> bool:
        if not isinstance(mac_hex, str) or len(mac_hex) != 64:
            return False
        return hmac.compare_digest(_sign(payload), mac_hex.lower())

    return _sign, _verify


_seal_context_payload, _verify_context_seal = _build_context_sealer()


def _normalize_supported_broker_id(broker_id: Any) -> str:
    if not isinstance(broker_id, str) or not broker_id.strip():
        raise LiveAuthTicketError("broker_id must be a non-empty string")
    norm = broker_id.strip().upper()
    if norm not in SUPPORTED_LIVE_AUTH_BROKERS:
        raise LiveAuthTicketError(
            f"unsupported LIVE auth broker_id {norm!r}; allowed={sorted(SUPPORTED_LIVE_AUTH_BROKERS)}"
        )
    return norm


def _arm_confirmation_matches(candidate: Any) -> bool:
    if not isinstance(candidate, str) or not candidate.strip():
        return False
    return hmac.compare_digest(
        candidate.strip().encode("utf-8"),
        LIVE_ARM_CONFIRMATION_TEXT.encode("utf-8"),
    )


def _format_file_identity(ident: tuple[int, int] | None) -> str:
    if ident is None:
        return ""
    return f"{int(ident[0])}:{int(ident[1])}"


def _valid_file_identity(ident: Any) -> bool:
    return (
        isinstance(ident, tuple)
        and len(ident) == 2
        and type(ident[0]) is int
        and type(ident[1]) is int
        and ident[0] >= 0
        and ident[1] >= 0
    )


def _canonical_context_seal_input(
    *,
    broker_id: str,
    account_id: str,
    server: str,
    execution_mode: str,
    issued_at: datetime,
    expires_at: datetime,
    ticket_sha256: str,
    arm_phrase_verified: bool,
    ticket_nonce: str,
    key_file_text: str,
    key_file_identity: tuple[int, int] | None = None,
    ticket_file_text: str = "",
    ticket_file_identity: tuple[int, int] | None = None,
) -> str:
    return "|".join((
        "cas-forex-live-ctx/3",
        broker_id,
        account_id,
        server.strip(),
        execution_mode,
        _iso_utc(issued_at),
        _iso_utc(expires_at),
        ticket_sha256.lower(),
        "ARMED" if arm_phrase_verified else "UNARMED",
        ticket_nonce,
        key_file_text,
        _format_file_identity(key_file_identity),
        ticket_file_text,
        _format_file_identity(ticket_file_identity),
    ))


@dataclass(frozen=True, slots=True, repr=False)
class LiveAuthorizationContext:
    """Opaque, immutable verified LIVE authorization capability revalidated before every dispatch sink.

    Cannot be instantiated directly by callers: requires the unexported module-private
    provenance sentinel and process-private HMAC-SHA256 provenance seal minted exclusively
    inside cryptographic ticket verification.
    """

    broker_id: str
    account_id: str
    server: str
    execution_mode: str
    issued_at: datetime
    expires_at: datetime
    ticket_sha256: str
    arm_phrase_verified: bool = False
    key_file_identity: tuple[int, int] | None = field(default=None, repr=False, compare=False)
    ticket_file_identity: tuple[int, int] | None = field(default=None, repr=False, compare=False)
    _provenance_seal: str = field(default="", repr=False, compare=False)
    _mint_token: object = field(default=None, repr=False, compare=False)
    _key_file: Path | None = field(default=None, repr=False, compare=False)
    _ticket_file: Path | None = field(default=None, repr=False, compare=False)
    _ticket_json: str | None = field(default=None, repr=False, compare=False)
    _ticket_nonce: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._mint_token is not _MINT_SENTINEL:
            raise LiveAuthorizationError(
                "LiveAuthorizationContext cannot be constructed directly; "
                "must be minted by verify_live_authorization_context / verify_live_environ_authorization_context"
            )
        _normalize_supported_broker_id(self.broker_id)
        if not isinstance(self.account_id, str) or not self.account_id.strip():
            raise LiveAuthorizationError("LiveAuthorizationContext requires a non-empty account_id")
        if not isinstance(self.server, str) or not self.server.strip():
            raise LiveAuthorizationError("LiveAuthorizationContext requires a non-empty server")
        if self.execution_mode != "LIVE":
            raise LiveAuthorizationError("LiveAuthorizationContext is valid only for execution_mode='LIVE'")
        if type(self.arm_phrase_verified) is not bool:
            raise LiveAuthorizationError("LiveAuthorizationContext arm_phrase_verified must be bool")
        issued = utc_time(self.issued_at, "issued_at")
        expires = utc_time(self.expires_at, "expires_at")
        if expires <= issued or (expires - issued).total_seconds() > MAX_LIVE_TICKET_TTL_SECONDS:
            raise LiveAuthorizationError("LiveAuthorizationContext TTL window invalid or exceeds 86400s")
        if not isinstance(self.ticket_sha256, str) or len(self.ticket_sha256) != 64:
            raise LiveAuthorizationError("LiveAuthorizationContext requires a 64-char hex ticket_sha256")
        if any(ch not in "0123456789abcdef" for ch in self.ticket_sha256.lower()):
            raise LiveAuthorizationError("LiveAuthorizationContext ticket_sha256 must be lowercase hex")
        if not isinstance(self._ticket_nonce, str) or len(self._ticket_nonce.strip()) < 16:
            raise LiveAuthorizationError("LiveAuthorizationContext requires a valid ticket nonce")
        if self.key_file_identity is not None and not _valid_file_identity(self.key_file_identity):
            raise LiveAuthorizationError("LiveAuthorizationContext key_file_identity must be (st_dev, st_ino)")
        if self.ticket_file_identity is not None and not _valid_file_identity(self.ticket_file_identity):
            raise LiveAuthorizationError("LiveAuthorizationContext ticket_file_identity must be (st_dev, st_ino)")
        if self._key_file is not None and self.key_file_identity is None:
            raise LiveAuthorizationError("LiveAuthorizationContext requires key_file_identity when _key_file is bound")
        if self._ticket_file is not None and self.ticket_file_identity is None:
            raise LiveAuthorizationError("LiveAuthorizationContext requires ticket_file_identity when _ticket_file is bound")
        self._verify_seal_only()

    def _seal_payload(self) -> str:
        key_txt = "" if self._key_file is None else str(self._key_file)
        ticket_txt = "" if self._ticket_file is None else str(self._ticket_file)
        return _canonical_context_seal_input(
            broker_id=self.broker_id,
            account_id=self.account_id,
            server=self.server,
            execution_mode=self.execution_mode,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            ticket_sha256=self.ticket_sha256,
            arm_phrase_verified=self.arm_phrase_verified,
            ticket_nonce=self._ticket_nonce,
            key_file_text=key_txt,
            key_file_identity=self.key_file_identity,
            ticket_file_text=ticket_txt,
            ticket_file_identity=self.ticket_file_identity,
        )

    def _verify_seal_only(self) -> None:
        if self._mint_token is not _MINT_SENTINEL:
            raise LiveAuthorizationError("LiveAuthorizationContext failed provenance sentinel verification")
        if not isinstance(self._provenance_seal, str) or not _verify_context_seal(
            self._seal_payload(), self._provenance_seal
        ):
            raise LiveAuthorizationError("LiveAuthorizationContext failed cryptographic provenance seal verification")

    def verify_provenance(
        self,
        *,
        now: datetime | None = None,
        reverify_ticket: bool = True,
        require_arm_phrase: bool = False,
    ) -> None:
        """Cryptographically prove this context was minted by ticket verification and optionally re-verify ticket."""
        self._verify_seal_only()
        _normalize_supported_broker_id(self.broker_id)
        if self.execution_mode != "LIVE":
            raise LiveAuthorizationError("LiveAuthorizationContext execution_mode must be LIVE")
        if require_arm_phrase and not self.arm_phrase_verified:
            raise LiveAuthorizationError(
                f"LIVE authorization for {self.broker_id} lacks verified arm confirmation"
            )
        if reverify_ticket:
            if self._key_file is not None:
                _, actual_key_ident = _load_live_auth_key_with_identity(self._key_file)
                if self.key_file_identity is None or actual_key_ident != self.key_file_identity:
                    raise LiveAuthorizationError(
                        "LIVE authorization key file identity changed since context minting; refusing dispatch"
                    )
            if self._ticket_file is not None:
                if self._key_file is None:
                    raise LiveAuthorizationError("LIVE authorization ticket file re-verification requires bound key_file")
                reread_ticket, actual_ticket_ident = _read_ticket_file_with_identity(self._ticket_file)
                if self.ticket_file_identity is None or actual_ticket_ident != self.ticket_file_identity:
                    raise LiveAuthorizationError(
                        "LIVE authorization ticket file identity changed since context minting; refusing dispatch"
                    )
                verified_disk = _verify_live_ticket_internal(
                    reread_ticket,
                    key_file=self._key_file,
                    expected_broker_id=self.broker_id,
                    expected_account_login=self.account_id,
                    expected_server=self.server,
                    now=now,
                    check_time_window=(now is not None),
                )
                canonical_disk = json.dumps(
                    dict(verified_disk), ensure_ascii=True, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                if not hmac.compare_digest(sha256(canonical_disk).hexdigest(), self.ticket_sha256.lower()):
                    raise LiveAuthorizationError(
                        "LIVE authorization ticket file digest mismatch during sink re-verification"
                    )
            if self._key_file is not None and self._ticket_json is not None:
                verified = _verify_live_ticket_internal(
                    self._ticket_json,
                    key_file=self._key_file,
                    expected_broker_id=self.broker_id,
                    expected_account_login=self.account_id,
                    expected_server=self.server,
                    now=now,
                    check_time_window=(now is not None),
                )
                canonical_raw = json.dumps(
                    dict(verified), ensure_ascii=True, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                if not hmac.compare_digest(sha256(canonical_raw).hexdigest(), self.ticket_sha256.lower()):
                    raise LiveAuthorizationError("LIVE authorization ticket digest mismatch during sink re-verification")

    def assert_valid_at(
        self,
        now: datetime | None = None,
        *,
        expected_broker_id: str | None = None,
        expected_account_id: str | int | None = None,
        expected_server: str | None = None,
        require_arm_phrase: bool = False,
        reverify_ticket: bool = True,
    ) -> None:
        """Fail closed with LiveAuthorizationError if forged, expired, not yet valid, or mismatched."""
        check_now = datetime.now(timezone.utc) if now is None else utc_time(now, "now")
        self.verify_provenance(
            now=check_now,
            reverify_ticket=reverify_ticket,
            require_arm_phrase=require_arm_phrase,
        )
        if check_now < self.issued_at - timedelta(seconds=30) or check_now > self.expires_at:
            raise LiveAuthorizationError(
                f"LIVE authorization expired or not yet valid for {self.broker_id} "
                f"(expires_at={_iso_utc(self.expires_at)}, checked_at={_iso_utc(check_now)})"
            )
        if expected_broker_id is not None and self.broker_id.strip().upper() != expected_broker_id.strip().upper():
            raise LiveAuthorizationError(f"LIVE authorization broker_id mismatch for {expected_broker_id}")
        if expected_account_id is not None and self.account_id.strip() != str(expected_account_id).strip():
            raise LiveAuthorizationError(f"LIVE authorization account_id mismatch for {self.broker_id}")
        if expected_server is not None and self.server.strip().casefold() != expected_server.strip().casefold():
            raise LiveAuthorizationError(f"LIVE authorization server mismatch for {self.broker_id}")

    def to_wire_dict(self) -> dict[str, str]:
        return {
            "broker_id": self.broker_id,
            "account_id": self.account_id,
            "server": self.server,
            "execution_mode": self.execution_mode,
            "issued_at": _iso_utc(self.issued_at),
            "expires_at": _iso_utc(self.expires_at),
            "ticket_sha256": self.ticket_sha256,
        }

    def __repr__(self) -> str:
        return (
            f"LiveAuthorizationContext(broker_id={self.broker_id!r}, account_id={self.account_id!r}, "
            f"server={self.server!r}, execution_mode={self.execution_mode!r}, "
            f"arm_phrase_verified={self.arm_phrase_verified!r}, expires_at={_iso_utc(self.expires_at)!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


def _mint_verified_context(
    verified_ticket: Mapping[str, str],
    *,
    key_file: Path | None = None,
    key_file_identity: tuple[int, int] | None = None,
    ticket_file: Path | None = None,
    ticket_file_identity: tuple[int, int] | None = None,
    arm_phrase_verified: bool = False,
) -> LiveAuthorizationContext:
    canonical_json = json.dumps(
        dict(verified_ticket), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    broker_id = _normalize_supported_broker_id(verified_ticket.get("broker_id", ""))
    account_id = str(verified_ticket.get("account_login", "")).strip()
    server = str(verified_ticket.get("server", "")).strip()
    execution_mode = str(verified_ticket.get("execution_mode", "")).strip()
    issued_at = _parse_iso_utc(verified_ticket.get("issued_at_utc"), "issued_at_utc")
    expires_at = _parse_iso_utc(verified_ticket.get("expires_at_utc"), "expires_at_utc")
    ticket_sha256 = sha256(canonical_json.encode("utf-8")).hexdigest()
    ticket_nonce = str(verified_ticket.get("nonce", "")).strip()
    key_txt = "" if key_file is None else str(key_file)
    ticket_txt = "" if ticket_file is None else str(ticket_file)
    seal = _seal_context_payload(
        _canonical_context_seal_input(
            broker_id=broker_id,
            account_id=account_id,
            server=server,
            execution_mode=execution_mode,
            issued_at=issued_at,
            expires_at=expires_at,
            ticket_sha256=ticket_sha256,
            arm_phrase_verified=bool(arm_phrase_verified),
            ticket_nonce=ticket_nonce,
            key_file_text=key_txt,
            key_file_identity=key_file_identity,
            ticket_file_text=ticket_txt,
            ticket_file_identity=ticket_file_identity,
        )
    )
    return LiveAuthorizationContext(
        broker_id=broker_id,
        account_id=account_id,
        server=server,
        execution_mode=execution_mode,
        issued_at=issued_at,
        expires_at=expires_at,
        ticket_sha256=ticket_sha256,
        arm_phrase_verified=bool(arm_phrase_verified),
        key_file_identity=key_file_identity,
        ticket_file_identity=ticket_file_identity,
        _provenance_seal=seal,
        _mint_token=_MINT_SENTINEL,
        _key_file=key_file,
        _ticket_file=ticket_file,
        _ticket_json=canonical_json,
        _ticket_nonce=ticket_nonce,
    )


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


def _split_verified_path(file_path: str | Path, *, label: str) -> tuple[Path, str]:
    if not isinstance(file_path, (str, Path)) or not str(file_path).strip():
        raise LiveAuthTicketError(f"{label} path must be a non-empty path")
    raw = str(file_path).strip()
    if "\x00" in raw:
        raise LiveAuthTicketError(f"{label} path contains NUL byte")
    target = Path(raw)
    if not target.is_absolute():
        raise LiveAuthTicketError(f"Refusing relative {label} path; an absolute path is required: {target}")
    if ".." in target.parts or not target.name or target.name in (".", ".."):
        raise LiveAuthTicketError(f"Invalid {label} path: {target}")
    return target.parent, target.name


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
    from cas_forex_revamp.composition.state_store import (
        create_owner_only_file_atomic,
        open_verified_directory_fd,
    )

    parent_dir, filename = _split_verified_path(key_file, label="LIVE auth key")
    target = parent_dir / filename
    try:
        verified_parent, dir_fd = open_verified_directory_fd(
            parent_dir, create=True, label="parent of LIVE auth key"
        )
    except LiveAuthTicketError:
        raise
    except (ContractError, OSError) as exc:
        raise LiveAuthTicketError(str(exc)) from exc
    try:
        exists = False
        if dir_fd is not None:
            try:
                os.lstat(filename, dir_fd=dir_fd)
                exists = True
            except FileNotFoundError:
                exists = False
        else:
            exists = os.path.lexists(verified_parent / filename)
        if exists:
            _load_live_auth_key_with_identity(target, dir_fd=dir_fd)
            return target
        raw = (secrets.token_bytes(32).hex() + "\n").encode("ascii")
        try:
            create_owner_only_file_atomic(
                verified_parent,
                filename,
                raw,
                replace_existing=False,
                label="LIVE auth key",
            )
        except LiveAuthTicketError:
            raise
        except (ContractError, OSError) as exc:
            raise LiveAuthTicketError(str(exc)) from exc
        return target
    finally:
        if dir_fd is not None:
            os.close(dir_fd)


def _load_live_auth_key_with_identity(
    key_file: str | Path,
    *,
    dir_fd: int | None = None,
) -> tuple[_RedactedLiveKey, tuple[int, int]]:
    from cas_forex_revamp.composition.state_store import verify_and_read_owner_only_file

    if not isinstance(key_file, (str, Path)) or not str(key_file).strip():
        raise LiveAuthTicketError(f"{ENV_LIVE_AUTH_KEY_FILE} is required for LIVE real-money mode")
    parent_dir, filename = _split_verified_path(key_file, label="LIVE auth key")
    try:
        raw_data, file_identity = verify_and_read_owner_only_file(
            parent_dir,
            filename,
            dir_fd=dir_fd,
            max_bytes=4096,
            label="LIVE auth key",
        )
    except LiveAuthTicketError:
        raise
    except (ContractError, OSError) as exc:
        raise LiveAuthTicketError(str(exc)) from exc
    raw_bytes = raw_data.strip()
    if len(raw_bytes) == 64 and all(b in b"0123456789abcdefABCDEF" for b in raw_bytes):
        return _RedactedLiveKey(bytes.fromhex(raw_bytes.decode("ascii"))), file_identity
    if len(raw_bytes) < 32:
        raise LiveAuthTicketError("LIVE auth key material must be >= 32 bytes (or 64 hex chars)")
    return _RedactedLiveKey(raw_bytes), file_identity


def load_live_auth_key(key_file: str | Path) -> _RedactedLiveKey:
    """Load owner-only LIVE auth key file via descriptor-relative O_NOFOLLOW; rejects symlinks, weak perms, and <32B keys."""
    key, _ = _load_live_auth_key_with_identity(key_file)
    return key


def _read_ticket_file_with_identity(ticket_file: str | Path) -> tuple[str, tuple[int, int]]:
    from cas_forex_revamp.composition.state_store import verify_and_read_owner_only_file

    parent_dir, filename = _split_verified_path(ticket_file, label="LIVE auth ticket")
    try:
        raw_bytes, file_identity = verify_and_read_owner_only_file(
            parent_dir,
            filename,
            max_bytes=65536,
            label="LIVE auth ticket",
        )
    except LiveAuthTicketError:
        raise
    except (ContractError, OSError) as exc:
        raise LiveAuthTicketError(str(exc)) from exc
    try:
        return raw_bytes.decode("utf-8"), file_identity
    except UnicodeDecodeError as exc:
        raise LiveAuthTicketError("LIVE auth ticket file is not valid UTF-8") from exc


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
    norm_broker = _normalize_supported_broker_id(broker_id)
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
        "broker_id": norm_broker,
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


def _verify_live_ticket_internal(
    ticket: Mapping[str, Any] | str,
    *,
    key_file: str | Path,
    expected_broker_id: str | None = None,
    expected_account_login: str | int | None = None,
    expected_server: str | None = None,
    now: datetime | None = None,
    check_time_window: bool = True,
) -> dict[str, str]:
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
        broker_norm = item.get("broker_id", "").strip().upper()
        if broker_norm not in SUPPORTED_LIVE_AUTH_BROKERS:
            last_error = f"LIVE auth ticket unsupported broker_id {broker_norm!r}"
            continue
        if not item.get("nonce") or len(item["nonce"].strip()) < 16:
            last_error = "LIVE auth ticket nonce missing or too short"
            continue
        issued_dt = _parse_iso_utc(item.get("issued_at_utc"), "issued_at_utc")
        expires_dt = _parse_iso_utc(item.get("expires_at_utc"), "expires_at_utc")
        if expires_dt <= issued_dt or (expires_dt - issued_dt).total_seconds() > MAX_LIVE_TICKET_TTL_SECONDS:
            last_error = "LIVE auth ticket TTL window invalid or exceeds 86400s"
            continue
        if check_time_window and (check_now < issued_dt - timedelta(seconds=30) or check_now > expires_dt):
            last_error = "LIVE auth ticket expired or not yet valid"
            continue
        expected_sig = key.hmac_hex(_canonical_ticket_message(item))
        actual_sig = str(item.get("hmac_sha256", "")).lower()
        if len(actual_sig) != 64 or not hmac.compare_digest(expected_sig, actual_sig):
            last_error = "LIVE auth ticket HMAC-SHA256 verification failed"
            continue
        if expected_broker_id is not None and broker_norm != expected_broker_id.strip().upper():
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
    return _verify_live_ticket_internal(
        ticket,
        key_file=key_file,
        expected_broker_id=expected_broker_id,
        expected_account_login=expected_account_login,
        expected_server=expected_server,
        now=now,
        check_time_window=True,
    )


def _verify_live_authorization_context_with_identities(
    ticket: Mapping[str, Any] | str,
    *,
    key_file: str | Path,
    ticket_file: Path | None = None,
    ticket_file_identity: tuple[int, int] | None = None,
    expected_broker_id: str | None = None,
    expected_account_login: str | int | None = None,
    expected_server: str | None = None,
    live_arm_phrase: str | None = None,
    require_arm_phrase: bool = False,
    now: datetime | None = None,
) -> tuple[dict[str, str], LiveAuthorizationContext]:
    _, key_identity = _load_live_auth_key_with_identity(key_file)
    verified = verify_live_authorization_ticket(
        ticket,
        key_file=key_file,
        expected_broker_id=expected_broker_id,
        expected_account_login=expected_account_login,
        expected_server=expected_server,
        now=now,
    )
    arm_ok = _arm_confirmation_matches(live_arm_phrase)
    if require_arm_phrase and not arm_ok:
        raise LiveAuthorizationError("LIVE authorization requires exact arm confirmation phrase")
    if live_arm_phrase is not None and str(live_arm_phrase).strip() and not arm_ok:
        raise LiveAuthorizationError("LIVE authorization arm confirmation phrase mismatch")
    key_path = Path(str(key_file).strip())
    ctx = _mint_verified_context(
        verified,
        key_file=key_path,
        key_file_identity=key_identity,
        ticket_file=ticket_file,
        ticket_file_identity=ticket_file_identity,
        arm_phrase_verified=arm_ok,
    )
    ctx.assert_valid_at(
        now,
        expected_broker_id=expected_broker_id,
        expected_account_id=expected_account_login,
        expected_server=expected_server,
        require_arm_phrase=require_arm_phrase,
        reverify_ticket=False,
    )
    return verified, ctx


def verify_live_authorization_context(
    ticket: Mapping[str, Any] | str,
    *,
    key_file: str | Path,
    ticket_file: str | Path | None = None,
    expected_broker_id: str | None = None,
    expected_account_login: str | int | None = None,
    expected_server: str | None = None,
    live_arm_phrase: str | None = None,
    require_arm_phrase: bool = False,
    now: datetime | None = None,
) -> tuple[dict[str, str], LiveAuthorizationContext]:
    """Cryptographically verify a LIVE ticket and mint an opaque sealed LiveAuthorizationContext."""
    eff_ticket_path: Path | None = None
    eff_ticket_ident: tuple[int, int] | None = None
    eff_ticket: Mapping[str, Any] | str = ticket
    if ticket_file is not None and str(ticket_file).strip():
        t_text, eff_ticket_ident = _read_ticket_file_with_identity(ticket_file)
        eff_ticket_path = Path(str(ticket_file).strip())
        eff_ticket = t_text
    return _verify_live_authorization_context_with_identities(
        eff_ticket,
        key_file=key_file,
        ticket_file=eff_ticket_path,
        ticket_file_identity=eff_ticket_ident,
        expected_broker_id=expected_broker_id,
        expected_account_login=expected_account_login,
        expected_server=expected_server,
        live_arm_phrase=live_arm_phrase,
        require_arm_phrase=require_arm_phrase,
        now=now,
    )


def _read_environ_live_inputs_with_identity(
    environ: Mapping[str, str] | None,
) -> tuple[str, str | Mapping[str, Any], Path | None, tuple[int, int] | None]:
    if environ is None:
        raise LiveAuthTicketError(f"{ENV_LIVE_AUTH_KEY_FILE} is required for LIVE mode")
    key_file = str(environ.get(ENV_LIVE_AUTH_KEY_FILE, "")).strip()
    ticket_file = str(environ.get(ENV_LIVE_AUTH_TICKET_FILE, "")).strip()
    inline_ticket = str(environ.get(ENV_LIVE_AUTH_TICKET, "")).strip()
    if ticket_file:
        raw_ticket, ticket_identity = _read_ticket_file_with_identity(ticket_file)
        return key_file, raw_ticket, Path(ticket_file), ticket_identity
    if inline_ticket:
        return key_file, inline_ticket, None, None
    raise LiveAuthTicketError(
        f"LIVE mode requires {ENV_LIVE_AUTH_TICKET_FILE} or {ENV_LIVE_AUTH_TICKET} signed with {ENV_LIVE_AUTH_KEY_FILE}"
    )


def _read_environ_live_inputs(environ: Mapping[str, str] | None) -> tuple[str, str | Mapping[str, Any]]:
    key_file, raw_ticket, _, _ = _read_environ_live_inputs_with_identity(environ)
    return key_file, raw_ticket


def verify_live_environ_authorization(
    environ: Mapping[str, str] | None,
    *,
    expected_broker_id: str | None = None,
    expected_account_login: str | int | None = None,
    expected_server: str | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    """Verify LIVE auth key + ticket from `CAS_FOREX_LIVE_AUTH_KEY_FILE` & ticket env/file."""
    key_file, raw_ticket = _read_environ_live_inputs(environ)
    return verify_live_authorization_ticket(
        raw_ticket,
        key_file=key_file,
        expected_broker_id=expected_broker_id,
        expected_account_login=expected_account_login,
        expected_server=expected_server,
        now=now,
    )


def build_live_authorization_context(
    verified_ticket: Mapping[str, Any] | str,
    *,
    key_file: str | Path | None = None,
    expected_broker_id: str | None = None,
    expected_account_login: str | int | None = None,
    expected_server: str | None = None,
    live_arm_phrase: str | None = None,
    require_arm_phrase: bool = False,
    now: datetime | None = None,
) -> LiveAuthorizationContext:
    """Cryptographically verify a ticket against `key_file` and return an opaque LiveAuthorizationContext.

    Refuses unverified ticket mappings when `key_file` is omitted so callers cannot forge contexts.
    """
    if key_file is None or not str(key_file).strip():
        raise LiveAuthorizationError(
            "build_live_authorization_context requires key_file to verify HMAC ticket provenance; "
            "unverified ticket mappings are refused"
        )
    _, ctx = verify_live_authorization_context(
        verified_ticket,
        key_file=key_file,
        expected_broker_id=expected_broker_id,
        expected_account_login=expected_account_login,
        expected_server=expected_server,
        live_arm_phrase=live_arm_phrase,
        require_arm_phrase=require_arm_phrase,
        now=now,
    )
    return ctx


def verify_live_environ_authorization_context(
    environ: Mapping[str, str] | None,
    *,
    expected_broker_id: str | None = None,
    expected_account_login: str | int | None = None,
    expected_server: str | None = None,
    live_arm_phrase: str | None = None,
    require_arm_phrase: bool = False,
    now: datetime | None = None,
) -> tuple[dict[str, str], LiveAuthorizationContext]:
    """Verify LIVE env ticket and return both verified ticket dict and opaque LiveAuthorizationContext."""
    key_file, raw_ticket, ticket_path, ticket_identity = _read_environ_live_inputs_with_identity(environ)
    eff_arm = (
        live_arm_phrase
        if live_arm_phrase is not None
        else (str(environ.get(_ENV_LIVE_ARM_CONFIRMATION, "")).strip() if environ is not None else None)
    )
    return _verify_live_authorization_context_with_identities(
        raw_ticket,
        key_file=key_file,
        ticket_file=ticket_path,
        ticket_file_identity=ticket_identity,
        expected_broker_id=expected_broker_id,
        expected_account_login=expected_account_login,
        expected_server=expected_server,
        live_arm_phrase=eff_arm,
        require_arm_phrase=require_arm_phrase,
        now=now,
    )
