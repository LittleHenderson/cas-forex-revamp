"""50%/50% Profit-Sweep Bank Vault (SQLite WAL) & Coinbase ES256 / Kraken HMAC-SHA512 ACH Off-Ramps.

Security invariants:
- No crypto address / external wallet transfer methods exist anywhere in this module.
- Coinbase and Kraken clients can ONLY convert funds to USD and withdraw via ACH strictly to an
  owner-linked bank payment method ID pinned in environment/configuration.
- Hostnames (``api.coinbase.com``, ``api.kraken.com``) are strictly pinned, HTTPS-only,
  private/loopback IPs rejected, and HTTP redirects unconditionally blocked.
- Broker 2FA withdrawals and off-ramp disbursements require single-use ``OwnerRecoveryVerifier``
  confirmation (scope ``TREASURY_SWEEP``) and immutable SHA-256 chained audit logging.
"""
from __future__ import annotations

import base64
from contextlib import closing
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP, localcontext
from hashlib import sha256, sha512
import hmac
import ipaddress
import json
import os
from pathlib import Path
import socket
import sqlite3
import stat
from threading import RLock
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from cas_forex_revamp.contracts import ContractError, canonical_bytes, decimal_text
from cas_forex_revamp.contracts.primitives import decimal_value, utc_time

DEFAULT_SWEEP_RATIO = Decimal("0.50")
MAX_OFFRAMP_WIRE_BYTES = 2 * 1024 * 1024
GENESIS_AUDIT_SHA256 = "0" * 64

RAIL_BROKER_2FA_MANUAL = "BROKER_2FA_MANUAL"
RAIL_COINBASE_ACH = "COINBASE_ACH"
RAIL_KRAKEN_ACH = "KRAKEN_ACH"
VALID_PAYOUT_RAILS = (RAIL_BROKER_2FA_MANUAL, RAIL_COINBASE_ACH, RAIL_KRAKEN_ACH)

COINBASE_API_HOST = "api.coinbase.com"
KRAKEN_API_HOST = "api.kraken.com"

ENV_PROFIT_SWEEP_RATIO = "CAS_FOREX_PROFIT_SWEEP_RATIO"
ENV_PROFIT_SWEEP_AUTO_ENABLED = "CAS_FOREX_PROFIT_SWEEP_AUTO_ENABLED"
ENV_PROFIT_SWEEP_PREFERRED_RAIL = "CAS_FOREX_PROFIT_SWEEP_PREFERRED_RAIL"

ENV_COINBASE_KEY_NAME = "CAS_FOREX_COINBASE_KEY_NAME"
ENV_COINBASE_PRIVATE_KEY_FILE = "CAS_FOREX_COINBASE_PRIVATE_KEY_FILE"
ENV_COINBASE_BANK_ACCOUNT_ID = "CAS_FOREX_COINBASE_BANK_ACCOUNT_ID"

ENV_KRAKEN_API_KEY = "CAS_FOREX_KRAKEN_API_KEY"
ENV_KRAKEN_API_SECRET = "CAS_FOREX_KRAKEN_API_SECRET"  # nosec B105: env var name constant, not a secret value
ENV_KRAKEN_BANK_ACCOUNT_ID = "CAS_FOREX_KRAKEN_BANK_ACCOUNT_ID"


class OfframpSecurityError(ContractError):
    """Raised on untrusted URL/IP/redirect, unpinned bank destination, or key-permission violation."""


class OfframpTransportError(RuntimeError):
    """Raised on HTTP/network failure communicating with Coinbase or Kraken API."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return utc_time(dt, "timestamp").isoformat().replace("+00:00", "Z")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _ensure_owner_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)  # nosec B103: owner-only 0o700 vault directory


def _ensure_owner_file(path: Path) -> None:
    if os.name == "posix" and path.exists():
        os.chmod(path, 0o600)  # nosec B103: owner-only 0o600 SQLite vault file


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise OfframpSecurityError(f"HTTP redirect ({code}) blocked on off-ramp endpoint")


def _validate_pinned_https_url(url: str, *, expected_host: str) -> str:
    if not isinstance(url, str) or not url:
        raise OfframpSecurityError("URL must be a non-empty string")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        raise OfframpSecurityError("Only HTTPS off-ramp URLs are permitted")
    if parsed.username is not None or parsed.password is not None:
        raise OfframpSecurityError("Userinfo is forbidden in off-ramp URLs")
    if (parsed.hostname or "").lower() != expected_host.lower():
        raise OfframpSecurityError(f"Off-ramp host must equal pinned {expected_host!r}")
    if parsed.port not in (None, 443):
        raise OfframpSecurityError("Only default TLS port 443 is allowed on off-ramp URLs")
    return url


def _verify_public_dns(host: str, resolve_dns: Callable[[str], list[str] | None] | None) -> None:
    ips: list[str] = []
    if resolve_dns is not None:
        custom = resolve_dns(host)
        if custom is None:
            return
        ips = list(custom)
    else:
        try:
            infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise OfframpTransportError(f"DNS resolution failed for {host!r}") from exc
        ips = [str(info[4][0]) for info in infos if info and info[4]]
    for ip_str in ips:
        clean = ip_str.split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(clean)
        except ValueError as exc:
            raise OfframpSecurityError(f"Unparseable resolved IP for {host!r}") from exc
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            raise OfframpSecurityError(f"Refusing non-public IP {clean} resolved for {host!r}")


def _pinned_https_request(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    *,
    expected_host: str,
    resolve_dns: Callable[[str], list[str] | None] | None = None,
    timeout: float = 10.0,
) -> tuple[int, bytes]:
    _validate_pinned_https_url(url, expected_host=expected_host)
    _verify_public_dns(expected_host, resolve_dns)
    opener = urllib.request.build_opener(_NoRedirectHandler())
    req = urllib.request.Request(url=url, data=body, headers=dict(headers), method=method.upper())
    try:
        with opener.open(req, timeout=timeout) as resp:  # nosec B310: verified https scheme and pinned coinbase/kraken host
            status = int(getattr(resp, "status", 200))
            raw = resp.read(MAX_OFFRAMP_WIRE_BYTES + 1)
            if len(raw) > MAX_OFFRAMP_WIRE_BYTES:
                raise OfframpTransportError("Off-ramp response exceeded max byte limit")
            return status, raw
    except urllib.error.HTTPError as exc:
        raw_err = exc.read(65536) if hasattr(exc, "read") else b""
        return int(exc.code), raw_err
    except OfframpSecurityError:
        raise
    except Exception as exc:
        raise OfframpTransportError(f"Off-ramp HTTPS request failed: {type(exc).__name__}") from exc


def _read_owner_pem(path: Path) -> ec.EllipticCurvePrivateKey:
    if not isinstance(path, Path):
        path = Path(str(path))
    if path.is_symlink() or not path.exists() or not path.is_file():
        raise OfframpSecurityError("Coinbase private key PEM must reference a real regular file")
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise OfframpSecurityError("Coinbase private key PEM cannot be a symlink")
    if os.name == "posix" and (st.st_mode & 0o077) != 0:
        raise OfframpSecurityError("Coinbase private key PEM must have owner-only permissions (0600)")
    pem_bytes = path.read_bytes()
    loaded = serialization.load_pem_private_key(pem_bytes, password=None)
    if not isinstance(loaded, ec.EllipticCurvePrivateKey):
        raise OfframpSecurityError("Coinbase CDP key must be an ECDSA P-256 private key")
    if loaded.curve.name != "secp256r1":
        raise OfframpSecurityError(f"Coinbase CDP ES256 requires secp256r1 curve, got {loaded.curve.name}")
    return loaded


class CoinbaseOfframpClient:
    """Verified Coinbase Advanced Trade CDP v3 ES256 client restricted to USD conversion + owner bank ACH."""

    def __init__(
        self,
        *,
        key_name: str,
        private_key_file: Path,
        linked_bank_account_id: str,
        http_call: Callable[[str, str, dict[str, str], bytes | None, float], tuple[int, bytes]] | None = None,
        resolve_dns: Callable[[str], list[str] | None] | None = None,
        clock: Callable[[], datetime] | None = None,
        base_url: str = f"https://{COINBASE_API_HOST}",
    ) -> None:
        if not key_name or not isinstance(key_name, str) or "organizations/" not in key_name:
            raise OfframpSecurityError("CAS_FOREX_COINBASE_KEY_NAME must be a valid CDP key resource name")
        if not linked_bank_account_id or not isinstance(linked_bank_account_id, str):
            raise OfframpSecurityError("CAS_FOREX_COINBASE_BANK_ACCOUNT_ID must be configured")
        clean_base = _validate_pinned_https_url(base_url.rstrip("/"), expected_host=COINBASE_API_HOST)
        self._key_name = key_name.strip()
        self._private_key_file = Path(private_key_file)
        self._private_key = _read_owner_pem(self._private_key_file)
        self._bank_account_id = linked_bank_account_id.strip()
        self._http_call = http_call
        self._resolve_dns = resolve_dns
        self._clock = clock or _utc_now
        self._base_url = clean_base

    @classmethod
    def from_environ(
        cls,
        environ: Mapping[str, str],
        *,
        http_call: Callable[[str, str, dict[str, str], bytes | None, float], tuple[int, bytes]] | None = None,
        resolve_dns: Callable[[str], list[str] | None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> "CoinbaseOfframpClient":
        return cls(
            key_name=str(environ.get(ENV_COINBASE_KEY_NAME, "")).strip(),
            private_key_file=Path(str(environ.get(ENV_COINBASE_PRIVATE_KEY_FILE, "")).strip()),
            linked_bank_account_id=str(environ.get(ENV_COINBASE_BANK_ACCOUNT_ID, "")).strip(),
            http_call=http_call,
            resolve_dns=resolve_dns,
            clock=clock,
        )

    @property
    def linked_bank_account_id(self) -> str:
        return self._bank_account_id

    def build_es256_jwt(self, *, method: str, request_path: str, nonce: str | None = None) -> str:
        """Build a CDP v3 ES256 JWT with canonical 64-byte raw IEEE P1363 R||S signature."""
        now_ts = int(self._clock().timestamp())
        header = {
            "alg": "ES256",
            "kid": self._key_name,
            "nonce": nonce or uuid.uuid4().hex,
            "typ": "JWT",
        }
        claims = {
            "sub": self._key_name,
            "iss": "cdp",
            "nbf": now_ts,
            "exp": now_ts + 120,
            "uri": f"{method.upper()} {COINBASE_API_HOST}{request_path}",
        }
        signing_input = f"{_b64url(canonical_bytes(header))}.{_b64url(canonical_bytes(claims))}".encode("ascii")
        der_sig = self._private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r_val, s_val = decode_dss_signature(der_sig)
        raw_rs = r_val.to_bytes(32, "big") + s_val.to_bytes(32, "big")
        return f"{signing_input.decode('ascii')}.{_b64url(raw_rs)}"

    def _call(self, method: str, request_path: str, payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        url = _validate_pinned_https_url(f"{self._base_url}{request_path}", expected_host=COINBASE_API_HOST)
        jwt_tok = self.build_es256_jwt(method=method, request_path=request_path)
        headers = {
            "Authorization": f"Bearer {jwt_tok}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        body = None if payload is None else canonical_bytes(payload)
        try:
            if self._http_call is not None:
                status, raw = self._http_call(method.upper(), url, dict(headers), body, 10.0)
            else:
                status, raw = _pinned_https_request(
                    method.upper(), url, headers, body, expected_host=COINBASE_API_HOST, resolve_dns=self._resolve_dns
                )
        finally:
            headers.clear()
        if status < 200 or status >= 300:
            raise OfframpTransportError(f"Coinbase API {request_path} failed with HTTP {status}")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise OfframpTransportError("Coinbase API returned non-JSON payload") from exc
        if not isinstance(doc, dict):
            raise OfframpTransportError("Coinbase API returned unexpected JSON structure")
        return doc

    def get_linked_payment_method(self) -> dict[str, Any]:
        return self._call("GET", f"/api/v3/brokerage/payment_methods/{urllib.parse.quote(self._bank_account_id, safe='')}")

    def convert_to_usd(
        self,
        *,
        from_currency: str,
        amount: Decimal,
        from_account_uuid: str,
        usd_account_uuid: str,
        commit: bool = True,
    ) -> dict[str, Any]:
        decimal_value(amount, "amount", positive=True)
        cur = str(from_currency).strip().upper()
        if cur not in ("USDC", "USDT", "BTC", "ETH"):
            raise OfframpSecurityError(f"Unsupported source asset {cur!r} for USD conversion")
        quote_doc = self._call(
            "POST",
            "/api/v3/brokerage/convert/quote",
            {
                "from_account": str(from_account_uuid).strip(),
                "to_account": str(usd_account_uuid).strip(),
                "amount": decimal_text(amount),
                "from_currency": cur,
                "to_currency": "USD",
            },
        )
        trade = quote_doc.get("trade") if isinstance(quote_doc.get("trade"), dict) else quote_doc
        trade_id = str(trade.get("id") or "")
        if not commit or not trade_id:
            return quote_doc
        return self._call(
            "POST",
            f"/api/v3/brokerage/convert/trade/{urllib.parse.quote(trade_id, safe='')}",
            {
                "from_account": str(from_account_uuid).strip(),
                "to_account": str(usd_account_uuid).strip(),
            },
        )

    def withdraw_usd_to_linked_bank_ach(
        self,
        *,
        amount_usd: Decimal,
        payment_method_id: str | None = None,
        client_reference_id: str | None = None,
    ) -> dict[str, Any]:
        """Withdraw USD strictly via ACH to the owner-pinned bank payment method (no crypto addresses)."""
        decimal_value(amount_usd, "amount_usd", positive=True)
        if payment_method_id is not None and payment_method_id.strip() != self._bank_account_id:
            raise OfframpSecurityError("Cannot override pinned Coinbase bank payment_method_id")
        return self._call(
            "POST",
            "/api/v3/brokerage/withdrawals/fiat",
            {
                "currency": "USD",
                "amount": decimal_text(amount_usd.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
                "payment_method_id": self._bank_account_id,
                "rail": "ACH",
                "client_reference_id": client_reference_id or f"cas-ach-{uuid.uuid4().hex[:12]}",
            },
        )


class KrakenOfframpClient:
    """Verified Kraken REST HMAC-SHA512 client restricted to USD market conversion + owner bank ACH."""

    def __init__(
        self,
        *,
        api_key: str,
        api_secret_b64: str,
        linked_bank_key: str,
        http_call: Callable[[str, str, dict[str, str], bytes | None, float], tuple[int, bytes]] | None = None,
        resolve_dns: Callable[[str], list[str] | None] | None = None,
        clock: Callable[[], datetime] | None = None,
        base_url: str = f"https://{KRAKEN_API_HOST}",
    ) -> None:
        if not api_key or not isinstance(api_key, str):
            raise OfframpSecurityError("CAS_FOREX_KRAKEN_API_KEY must be configured")
        if not api_secret_b64 or not isinstance(api_secret_b64, str):
            raise OfframpSecurityError("CAS_FOREX_KRAKEN_API_SECRET must be configured")
        if not linked_bank_key or not isinstance(linked_bank_key, str):
            raise OfframpSecurityError("CAS_FOREX_KRAKEN_BANK_ACCOUNT_ID must be configured")
        clean_base = _validate_pinned_https_url(base_url.rstrip("/"), expected_host=KRAKEN_API_HOST)
        try:
            self._secret_bytes = base64.b64decode(api_secret_b64.strip(), validate=True)
        except Exception as exc:
            raise OfframpSecurityError("CAS_FOREX_KRAKEN_API_SECRET must be valid base64") from exc
        if len(self._secret_bytes) < 16:
            raise OfframpSecurityError("Kraken API secret is too short")
        self._api_key = api_key.strip()
        self._bank_key = linked_bank_key.strip()
        self._http_call = http_call
        self._resolve_dns = resolve_dns
        self._clock = clock or _utc_now
        self._base_url = clean_base
        self._nonce_seq = 0
        self._lock = RLock()

    @classmethod
    def from_environ(
        cls,
        environ: Mapping[str, str],
        *,
        http_call: Callable[[str, str, dict[str, str], bytes | None, float], tuple[int, bytes]] | None = None,
        resolve_dns: Callable[[str], list[str] | None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> "KrakenOfframpClient":
        return cls(
            api_key=str(environ.get(ENV_KRAKEN_API_KEY, "")).strip(),
            api_secret_b64=str(environ.get(ENV_KRAKEN_API_SECRET, "")).strip(),
            linked_bank_key=str(environ.get(ENV_KRAKEN_BANK_ACCOUNT_ID, "")).strip(),
            http_call=http_call,
            resolve_dns=resolve_dns,
            clock=clock,
        )

    @property
    def linked_bank_account_id(self) -> str:
        return self._bank_key

    def _next_nonce(self) -> str:
        with self._lock:
            now_ms = int(self._clock().timestamp() * 1000)
            self._nonce_seq = max(self._nonce_seq + 1, now_ms)
            return str(self._nonce_seq)

    def sign_request(self, *, url_path: str, nonce: str, post_data: str) -> str:
        """Compute official Kraken HMAC-SHA512 ``API-Sign`` header."""
        encoded = (nonce + post_data).encode("utf-8")
        message = url_path.encode("utf-8") + sha256(encoded).digest()
        sig_digest = hmac.new(self._secret_bytes, message, sha512).digest()
        return base64.b64encode(sig_digest).decode("ascii")

    def _private_post(self, url_path: str, params: Mapping[str, str]) -> dict[str, Any]:
        url = _validate_pinned_https_url(f"{self._base_url}{url_path}", expected_host=KRAKEN_API_HOST)
        nonce = self._next_nonce()
        body_params = {"nonce": nonce}
        for k, v in params.items():
            if k != "nonce":
                body_params[str(k)] = str(v)
        post_data = urllib.parse.urlencode(body_params)
        api_sign = self.sign_request(url_path=url_path, nonce=nonce, post_data=post_data)
        headers = {
            "API-Key": self._api_key,
            "API-Sign": api_sign,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        try:
            if self._http_call is not None:
                status, raw = self._http_call("POST", url, dict(headers), post_data.encode("utf-8"), 10.0)
            else:
                status, raw = _pinned_https_request(
                    "POST", url, headers, post_data.encode("utf-8"), expected_host=KRAKEN_API_HOST, resolve_dns=self._resolve_dns
                )
        finally:
            headers.clear()
        if status < 200 or status >= 300:
            raise OfframpTransportError(f"Kraken API {url_path} failed with HTTP {status}")
        try:
            doc = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise OfframpTransportError("Kraken API returned non-JSON payload") from exc
        if not isinstance(doc, dict) or doc.get("error"):
            raise OfframpTransportError(f"Kraken API error on {url_path}: {doc.get('error') if isinstance(doc, dict) else 'invalid'}")
        result = doc.get("result")
        return dict(result) if isinstance(result, dict) else doc

    def convert_to_usd(self, *, pair: str = "USDCUSD", volume: Decimal) -> dict[str, Any]:
        decimal_value(volume, "volume", positive=True)
        clean_pair = str(pair).strip().upper()
        if clean_pair not in ("USDCUSD", "USDTUSD", "XBTUSD", "ETHUSD"):
            raise OfframpSecurityError(f"Unsupported conversion pair {clean_pair!r}; only USD pairs permitted")
        return self._private_post(
            "/0/private/AddOrder",
            {
                "pair": clean_pair,
                "type": "sell",
                "ordertype": "market",
                "volume": decimal_text(volume),
            },
        )

    def withdraw_usd_to_linked_bank_ach(
        self,
        *,
        amount_usd: Decimal,
        key_id: str | None = None,
    ) -> dict[str, Any]:
        """Submit Kraken ZUSD ACH withdrawal strictly to the owner-linked bank key."""
        decimal_value(amount_usd, "amount_usd", positive=True)
        if key_id is not None and key_id.strip() != self._bank_key:
            raise OfframpSecurityError("Cannot override pinned Kraken bank withdrawal key")
        return self._private_post(
            "/0/private/Withdraw",
            {
                "asset": "ZUSD",
                "key": self._bank_key,
                "amount": decimal_text(amount_usd.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
            },
        )


class ProfitSweepVault:
    """Persistent 50%/50% compounding vs bank-vault reserve ledger in SQLite WAL."""

    def __init__(
        self,
        db_path: Path,
        *,
        scope_id: str = "default",
        sweep_ratio: Decimal = DEFAULT_SWEEP_RATIO,
        auto_sweep_enabled: bool = True,
        preferred_rail: str = RAIL_BROKER_2FA_MANUAL,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(db_path, Path):
            db_path = Path(str(db_path))
        decimal_value(sweep_ratio, "sweep_ratio")
        if sweep_ratio < Decimal("0") or sweep_ratio > Decimal("0.90"):
            raise ContractError("sweep_ratio must be in [0, 0.90]")
        if preferred_rail not in VALID_PAYOUT_RAILS:
            raise ContractError(f"preferred_rail must be one of {VALID_PAYOUT_RAILS}")
        _ensure_owner_dir(db_path.parent)
        self.db_path = db_path
        self.scope_id = str(scope_id).strip() or "default"
        self._clock = clock or _utc_now
        self._lock = RLock()
        self._init_db(
            default_ratio=sweep_ratio,
            default_auto=auto_sweep_enabled,
            default_rail=preferred_rail,
        )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self, *, default_ratio: Decimal, default_auto: bool, default_rail: str) -> None:
        with self._lock, closing(self._connect()) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS vault_config (
                    scope_id TEXT PRIMARY KEY,
                    sweep_ratio_text TEXT NOT NULL,
                    auto_sweep_enabled INTEGER NOT NULL,
                    preferred_rail TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sweep_events (
                    trade_id TEXT NOT NULL,
                    scope_id TEXT NOT NULL,
                    symbol TEXT NOT NULL,
                    broker_id TEXT NOT NULL,
                    realized_net_usd_text TEXT NOT NULL,
                    retained_trading_usd_text TEXT NOT NULL,
                    bank_sweep_usd_text TEXT NOT NULL,
                    occurred_at TEXT NOT NULL,
                    PRIMARY KEY (scope_id, trade_id)
                );
                CREATE TABLE IF NOT EXISTS bank_transfers (
                    transfer_id TEXT PRIMARY KEY,
                    scope_id TEXT NOT NULL,
                    rail TEXT NOT NULL,
                    broker_id TEXT,
                    destination_bank_id TEXT NOT NULL,
                    amount_usd_text TEXT NOT NULL,
                    status TEXT NOT NULL,
                    provider_tx_id TEXT,
                    owner_request_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    settled_at TEXT
                );
                CREATE TABLE IF NOT EXISTS vault_audit (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    prev_sha256 TEXT NOT NULL,
                    entry_sha256 TEXT NOT NULL,
                    scope_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            row = conn.execute("SELECT scope_id FROM vault_config WHERE scope_id = ?", (self.scope_id,)).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO vault_config(scope_id, sweep_ratio_text, auto_sweep_enabled, preferred_rail, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        self.scope_id,
                        decimal_text(default_ratio),
                        1 if default_auto else 0,
                        default_rail,
                        _iso(self._clock()),
                    ),
                )
        _ensure_owner_file(self.db_path)

    def _append_audit(self, conn: sqlite3.Connection, event_type: str, payload: Mapping[str, Any], ts: str) -> None:
        prev_row = conn.execute("SELECT entry_sha256 FROM vault_audit ORDER BY seq DESC LIMIT 1").fetchone()
        prev_sha = str(prev_row["entry_sha256"]) if prev_row is not None else GENESIS_AUDIT_SHA256
        payload_bytes = canonical_bytes(dict(payload))
        entry_sha = sha256(f"{prev_sha}|{self.scope_id}|{event_type}|".encode("utf-8") + payload_bytes + f"|{ts}".encode("utf-8")).hexdigest()
        conn.execute(
            """
            INSERT INTO vault_audit(prev_sha256, entry_sha256, scope_id, event_type, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (prev_sha, entry_sha, self.scope_id, event_type, payload_bytes.decode("utf-8"), ts),
        )

    def set_config(
        self,
        *,
        sweep_ratio: Decimal | None = None,
        auto_sweep_enabled: bool | None = None,
        preferred_rail: str | None = None,
    ) -> dict[str, Any]:
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM vault_config WHERE scope_id = ?", (self.scope_id,)).fetchone()
            cur_ratio = Decimal(str(row["sweep_ratio_text"])) if row else DEFAULT_SWEEP_RATIO
            cur_auto = bool(int(row["auto_sweep_enabled"])) if row else True
            cur_rail = str(row["preferred_rail"]) if row else RAIL_BROKER_2FA_MANUAL

            new_ratio = cur_ratio if sweep_ratio is None else decimal_value(sweep_ratio, "sweep_ratio")
            if new_ratio < Decimal("0") or new_ratio > Decimal("0.90"):
                raise ContractError("sweep_ratio must be in [0, 0.90]")
            new_auto = cur_auto if auto_sweep_enabled is None else bool(auto_sweep_enabled)
            new_rail = cur_rail if preferred_rail is None else str(preferred_rail).strip()
            if new_rail not in VALID_PAYOUT_RAILS:
                raise ContractError(f"preferred_rail must be one of {VALID_PAYOUT_RAILS}")

            ts = _iso(self._clock())
            conn.execute(
                """
                UPDATE vault_config
                SET sweep_ratio_text = ?, auto_sweep_enabled = ?, preferred_rail = ?, updated_at = ?
                WHERE scope_id = ?
                """,
                (decimal_text(new_ratio), 1 if new_auto else 0, new_rail, ts, self.scope_id),
            )
            self._append_audit(
                conn,
                "CONFIG_UPDATED",
                {"sweep_ratio": decimal_text(new_ratio), "auto_sweep_enabled": new_auto, "preferred_rail": new_rail},
                ts,
            )
            conn.execute("COMMIT")
        return self.snapshot()

    def record_realized_close(
        self,
        *,
        trade_id: str,
        symbol: str,
        broker_id: str,
        realized_net_usd: Decimal,
        occurred_at: datetime | None = None,
    ) -> dict[str, Any]:
        if not isinstance(trade_id, str) or not trade_id.strip():
            raise ContractError("trade_id must be a non-empty string")
        decimal_value(realized_net_usd, "realized_net_usd")
        ts = _iso(occurred_at or self._clock())
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT 1 FROM sweep_events WHERE scope_id = ? AND trade_id = ?",
                (self.scope_id, trade_id.strip()),
            ).fetchone()
            if existing is not None:
                conn.execute("ROLLBACK")
                return self.snapshot()

            cfg = conn.execute("SELECT * FROM vault_config WHERE scope_id = ?", (self.scope_id,)).fetchone()
            ratio = Decimal(str(cfg["sweep_ratio_text"])) if cfg else DEFAULT_SWEEP_RATIO
            auto_on = bool(int(cfg["auto_sweep_enabled"])) if cfg else True

            if realized_net_usd > Decimal("0") and auto_on and ratio > Decimal("0"):
                with localcontext() as ctx:
                    ctx.prec = 40
                    bank_part = (realized_net_usd * ratio).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                retained_part = realized_net_usd - bank_part
            else:
                bank_part = Decimal("0.00")
                retained_part = realized_net_usd

            conn.execute(
                """
                INSERT INTO sweep_events(
                    trade_id, scope_id, symbol, broker_id, realized_net_usd_text,
                    retained_trading_usd_text, bank_sweep_usd_text, occurred_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trade_id.strip(),
                    self.scope_id,
                    str(symbol),
                    str(broker_id),
                    decimal_text(realized_net_usd),
                    decimal_text(retained_part),
                    decimal_text(bank_part),
                    ts,
                ),
            )
            self._append_audit(
                conn,
                "REALIZED_CLOSE_SWEPT",
                {
                    "trade_id": trade_id.strip(),
                    "symbol": str(symbol),
                    "broker_id": str(broker_id),
                    "realized_net_usd": decimal_text(realized_net_usd),
                    "retained_trading_usd": decimal_text(retained_part),
                    "bank_sweep_usd": decimal_text(bank_part),
                },
                ts,
            )
            conn.execute("COMMIT")
        return self.snapshot()

    def bank_sweep_reserved_usd(self) -> Decimal:
        """Return profits currently swept into Bank Vault that are NOT yet disbursed out of broker equity."""
        snap = self.snapshot()
        return Decimal(snap["pending_disbursement_usd"])

    def deployable_equity(self, total_equity: Decimal) -> Decimal:
        """Compute active trading equity available for risk sizing (total minus unsent bank sweep reserve)."""
        decimal_value(total_equity, "total_equity")
        rem = total_equity - self.bank_sweep_reserved_usd()
        return rem if rem > Decimal("0") else Decimal("0")

    def request_broker_2fa_withdrawal(
        self,
        *,
        broker_id: str,
        amount_usd: Decimal,
        owner_request_id: str,
        reason: str,
        verifier: Any,
        recovery_token: str,
        destination_bank_label: str = "OWNER_LINKED_BANK",
    ) -> dict[str, Any]:
        """Queue an owner-2FA-gated broker withdrawal against accrued Bank Vault reserve."""
        decimal_value(amount_usd, "amount_usd", positive=True)
        if not owner_request_id or not reason:
            raise ContractError("owner_request_id and reason are required")
        verifier.verify_and_consume(recovery_token, expected_scope="TREASURY_SWEEP", owner_request_id=owner_request_id, now=self._clock())
        transfer_id = f"tr2fa-{uuid.uuid4().hex[:16]}"
        ts = _iso(self._clock())
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            pending = self._pending_disbursement_unlocked(conn)
            if amount_usd > pending:
                conn.execute("ROLLBACK")
                raise ContractError(
                    f"Requested sweep ${decimal_text(amount_usd)} exceeds pending Bank Vault ${decimal_text(pending)}"
                )
            conn.execute(
                """
                INSERT INTO bank_transfers(
                    transfer_id, scope_id, rail, broker_id, destination_bank_id, amount_usd_text,
                    status, provider_tx_id, owner_request_id, reason, created_at, settled_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transfer_id,
                    self.scope_id,
                    RAIL_BROKER_2FA_MANUAL,
                    str(broker_id),
                    str(destination_bank_label),
                    decimal_text(amount_usd.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
                    "PENDING_OWNER_BROKER_2FA",
                    None,
                    str(owner_request_id),
                    str(reason)[:240],
                    ts,
                    None,
                ),
            )
            self._append_audit(
                conn,
                "BROKER_2FA_WITHDRAWAL_REQUESTED",
                {"transfer_id": transfer_id, "broker_id": str(broker_id), "amount_usd": decimal_text(amount_usd)},
                ts,
            )
            conn.execute("COMMIT")
        return {"transfer_id": transfer_id, "status": "PENDING_OWNER_BROKER_2FA", "vault": self.snapshot()}

    def confirm_broker_2fa_withdrawal(
        self,
        *,
        transfer_id: str,
        provider_tx_id: str,
    ) -> dict[str, Any]:
        if not transfer_id or not provider_tx_id:
            raise ContractError("transfer_id and provider_tx_id are required")
        ts = _iso(self._clock())
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM bank_transfers WHERE transfer_id = ? AND scope_id = ?",
                (transfer_id, self.scope_id),
            ).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                raise ContractError(f"Unknown transfer_id {transfer_id!r}")
            if str(row["status"]) != "PENDING_OWNER_BROKER_2FA":
                conn.execute("ROLLBACK")
                raise ContractError(f"Transfer {transfer_id!r} is already {row['status']}")
            conn.execute(
                "UPDATE bank_transfers SET status = 'SETTLED', provider_tx_id = ?, settled_at = ? WHERE transfer_id = ?",
                (str(provider_tx_id).strip(), ts, transfer_id),
            )
            self._append_audit(
                conn,
                "BROKER_2FA_WITHDRAWAL_SETTLED",
                {"transfer_id": transfer_id, "provider_tx_id": str(provider_tx_id).strip()},
                ts,
            )
            conn.execute("COMMIT")
        return {"transfer_id": transfer_id, "status": "SETTLED", "vault": self.snapshot()}

    def execute_offramp_ach_payout(
        self,
        *,
        rail: str,
        amount_usd: Decimal,
        owner_request_id: str,
        reason: str,
        verifier: Any,
        recovery_token: str,
        coinbase_client: CoinbaseOfframpClient | None = None,
        kraken_client: KrakenOfframpClient | None = None,
        convert_from_currency: str | None = None,
        convert_amount: Decimal | None = None,
        coinbase_source_account_uuid: str | None = None,
        coinbase_usd_account_uuid: str | None = None,
        kraken_pair: str = "USDCUSD",
    ) -> dict[str, Any]:
        """Convert (optional) to USD and dispatch ACH payout strictly to owner's linked bank ID."""
        decimal_value(amount_usd, "amount_usd", positive=True)
        if rail not in (RAIL_COINBASE_ACH, RAIL_KRAKEN_ACH):
            raise OfframpSecurityError(f"Unsupported automated ACH rail {rail!r}")
        verifier.verify_and_consume(recovery_token, expected_scope="TREASURY_SWEEP", owner_request_id=owner_request_id, now=self._clock())

        with self._lock, closing(self._connect()) as conn:
            pending = self._pending_disbursement_unlocked(conn)
        if amount_usd > pending:
            raise ContractError(
                f"Requested ACH payout ${decimal_text(amount_usd)} exceeds pending Bank Vault ${decimal_text(pending)}"
            )

        if rail == RAIL_COINBASE_ACH:
            if coinbase_client is None:
                raise OfframpSecurityError("CoinbaseOfframpClient is not configured")
            dest_bank = coinbase_client.linked_bank_account_id
            if convert_from_currency is not None and convert_amount is not None:
                if not coinbase_source_account_uuid or not coinbase_usd_account_uuid:
                    raise ContractError("Coinbase source/USD account UUIDs are required for conversion")
                coinbase_client.convert_to_usd(
                    from_currency=convert_from_currency,
                    amount=convert_amount,
                    from_account_uuid=coinbase_source_account_uuid,
                    usd_account_uuid=coinbase_usd_account_uuid,
                )
            resp = coinbase_client.withdraw_usd_to_linked_bank_ach(amount_usd=amount_usd)
            provider_tx = str(resp.get("id") or resp.get("payout_id") or resp.get("refid") or f"cb-{uuid.uuid4().hex[:10]}")
        else:
            if kraken_client is None:
                raise OfframpSecurityError("KrakenOfframpClient is not configured")
            dest_bank = kraken_client.linked_bank_account_id
            if convert_amount is not None:
                kraken_client.convert_to_usd(pair=kraken_pair, volume=convert_amount)
            resp = kraken_client.withdraw_usd_to_linked_bank_ach(amount_usd=amount_usd)
            provider_tx = str(resp.get("refid") or f"krk-{uuid.uuid4().hex[:10]}")

        transfer_id = f"trach-{uuid.uuid4().hex[:16]}"
        ts = _iso(self._clock())
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO bank_transfers(
                    transfer_id, scope_id, rail, broker_id, destination_bank_id, amount_usd_text,
                    status, provider_tx_id, owner_request_id, reason, created_at, settled_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    transfer_id,
                    self.scope_id,
                    rail,
                    None,
                    dest_bank,
                    decimal_text(amount_usd.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
                    "ACH_SUBMITTED",
                    provider_tx,
                    str(owner_request_id),
                    str(reason)[:240],
                    ts,
                    ts,
                ),
            )
            self._append_audit(
                conn,
                "ACH_OFFRAMP_SUBMITTED",
                {
                    "transfer_id": transfer_id,
                    "rail": rail,
                    "destination_bank_id": dest_bank,
                    "amount_usd": decimal_text(amount_usd),
                    "provider_tx_id": provider_tx,
                },
                ts,
            )
            conn.execute("COMMIT")
        return {"transfer_id": transfer_id, "provider_tx_id": provider_tx, "status": "ACH_SUBMITTED", "vault": self.snapshot()}

    def _pending_disbursement_unlocked(self, conn: sqlite3.Connection) -> Decimal:
        swept = Decimal("0")
        for r in conn.execute("SELECT bank_sweep_usd_text FROM sweep_events WHERE scope_id = ?", (self.scope_id,)):
            swept += Decimal(str(r["bank_sweep_usd_text"]))
        disbursed = Decimal("0")
        for r in conn.execute(
            "SELECT amount_usd_text, status FROM bank_transfers WHERE scope_id = ?", (self.scope_id,)
        ):
            if str(r["status"]) in ("SETTLED", "ACH_SUBMITTED"):
                disbursed += Decimal(str(r["amount_usd_text"]))
        rem = swept - disbursed
        return rem if rem > Decimal("0") else Decimal("0.00")

    def snapshot(self) -> dict[str, Any]:
        with self._lock, closing(self._connect()) as conn:
            cfg = conn.execute("SELECT * FROM vault_config WHERE scope_id = ?", (self.scope_id,)).fetchone()
            total_realized = Decimal("0")
            retained = Decimal("0")
            bank_reserved_total = Decimal("0")
            recent_sweeps: list[dict[str, Any]] = []
            rows = conn.execute(
                "SELECT * FROM sweep_events WHERE scope_id = ? ORDER BY rowid DESC", (self.scope_id,)
            ).fetchall()
            for idx, r in enumerate(rows):
                net_v = Decimal(str(r["realized_net_usd_text"]))
                ret_v = Decimal(str(r["retained_trading_usd_text"]))
                bnk_v = Decimal(str(r["bank_sweep_usd_text"]))
                total_realized += net_v
                retained += ret_v
                bank_reserved_total += bnk_v
                if idx < 25:
                    recent_sweeps.append({
                        "trade_id": str(r["trade_id"]),
                        "symbol": str(r["symbol"]),
                        "broker_id": str(r["broker_id"]),
                        "realized_net_usd": decimal_text(net_v),
                        "retained_trading_usd": decimal_text(ret_v),
                        "bank_sweep_usd": decimal_text(bnk_v),
                        "occurred_at": str(r["occurred_at"]),
                    })

            disbursed = Decimal("0")
            pending_2fa = Decimal("0")
            recent_transfers: list[dict[str, Any]] = []
            trows = conn.execute(
                "SELECT * FROM bank_transfers WHERE scope_id = ? ORDER BY rowid DESC", (self.scope_id,)
            ).fetchall()
            for idx, r in enumerate(trows):
                amt = Decimal(str(r["amount_usd_text"]))
                st = str(r["status"])
                if st in ("SETTLED", "ACH_SUBMITTED"):
                    disbursed += amt
                elif st == "PENDING_OWNER_BROKER_2FA":
                    pending_2fa += amt
                if idx < 25:
                    recent_transfers.append({
                        "transfer_id": str(r["transfer_id"]),
                        "rail": str(r["rail"]),
                        "broker_id": r["broker_id"],
                        "destination_bank_id": str(r["destination_bank_id"]),
                        "amount_usd": decimal_text(amt),
                        "status": st,
                        "provider_tx_id": r["provider_tx_id"],
                        "created_at": str(r["created_at"]),
                        "settled_at": r["settled_at"],
                    })

            pending_rem = max(Decimal("0.00"), bank_reserved_total - disbursed)
            ratio = Decimal(str(cfg["sweep_ratio_text"])) if cfg else DEFAULT_SWEEP_RATIO
            return {
                "schema": "cas-forex.profit-vault/1",
                "scope_id": self.scope_id,
                "sweep_ratio": decimal_text(ratio),
                "sweep_ratio_pct": decimal_text((ratio * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
                "auto_sweep_enabled": bool(int(cfg["auto_sweep_enabled"])) if cfg else True,
                "preferred_rail": str(cfg["preferred_rail"]) if cfg else RAIL_BROKER_2FA_MANUAL,
                "total_realized_profit_usd": decimal_text(total_realized),
                "retained_trading_usd": decimal_text(retained),
                "bank_sweep_reserved_usd": decimal_text(bank_reserved_total),
                "disbursed_to_bank_usd": decimal_text(disbursed),
                "pending_2fa_confirmation_usd": decimal_text(pending_2fa),
                "pending_disbursement_usd": decimal_text(pending_rem),
                "recent_sweeps": recent_sweeps,
                "recent_transfers": recent_transfers,
            }
