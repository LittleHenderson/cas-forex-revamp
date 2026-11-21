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
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP, localcontext
from hashlib import sha256, sha512
import hmac
import inspect
import ipaddress
import json
import os
from pathlib import Path
import re
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
from cas_forex_revamp.contracts.primitives import decimal_value, identifier, utc_time

DEFAULT_SWEEP_RATIO = Decimal("0.50")
MAX_OFFRAMP_WIRE_BYTES = 2 * 1024 * 1024
GENESIS_AUDIT_SHA256 = "0" * 64
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

RAIL_BROKER_2FA_MANUAL = "BROKER_2FA_MANUAL"
RAIL_COINBASE_ACH = "COINBASE_ACH"
RAIL_KRAKEN_ACH = "KRAKEN_ACH"
VALID_PAYOUT_RAILS = (RAIL_BROKER_2FA_MANUAL, RAIL_COINBASE_ACH, RAIL_KRAKEN_ACH)

INTENT_ACTION_BROKER_2FA = "BROKER_2FA_WITHDRAWAL"
INTENT_ACTION_OFFRAMP_ACH = "OFFRAMP_ACH_PAYOUT"
MAX_TREASURY_INTENT_TTL_SECONDS = 900

CONVERSION_STATUS_NOT_REQUIRED = "NOT_REQUIRED"
CONVERSION_STATUS_NOT_STARTED = "CONVERSION_NOT_STARTED"
CONVERSION_STATUS_PENDING = "CONVERSION_PENDING"
CONVERSION_STATUS_CONFIRMED = "CONVERSION_CONFIRMED"
CONVERSION_STATUS_OUTCOME_UNKNOWN = "CONVERSION_OUTCOME_UNKNOWN"

WITHDRAWAL_STATUS_NOT_STARTED = "WITHDRAWAL_NOT_STARTED"
WITHDRAWAL_STATUS_PENDING = "WITHDRAWAL_PENDING"
WITHDRAWAL_STATUS_SUBMITTED = "WITHDRAWAL_SUBMITTED"
WITHDRAWAL_STATUS_OUTCOME_UNKNOWN = "WITHDRAWAL_OUTCOME_UNKNOWN"

COINBASE_API_HOST = "api.coinbase.com"
KRAKEN_API_HOST = "api.kraken.com"

ENV_PROFIT_SWEEP_RATIO = "CAS_FOREX_PROFIT_SWEEP_RATIO"
ENV_PROFIT_SWEEP_AUTO_ENABLED = "CAS_FOREX_PROFIT_SWEEP_AUTO_ENABLED"
ENV_PROFIT_SWEEP_PREFERRED_RAIL = "CAS_FOREX_PROFIT_SWEEP_PREFERRED_RAIL"
ENV_INITIAL_CAPITAL_USD = "CAS_FOREX_INITIAL_CAPITAL_USD"

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


def _reject_nonfinite_json(token: str) -> Any:
    raise ValueError(f"non-finite JSON constant {token!r}")


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
        jwt_path = request_path.split("?", 1)[0]
        claims = {
            "sub": self._key_name,
            "iss": "cdp",
            "nbf": now_ts,
            "exp": now_ts + 120,
            "uri": f"{method.upper()} {COINBASE_API_HOST}{jwt_path}",
        }
        signing_input = f"{_b64url(canonical_bytes(header))}.{_b64url(canonical_bytes(claims))}".encode("ascii")
        der_sig = self._private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r_val, s_val = decode_dss_signature(der_sig)
        raw_rs = r_val.to_bytes(32, "big") + s_val.to_bytes(32, "big")
        return f"{signing_input.decode('ascii')}.{_b64url(raw_rs)}"

    def _call(
        self,
        method: str,
        request_path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        extra_headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        url = _validate_pinned_https_url(f"{self._base_url}{request_path}", expected_host=COINBASE_API_HOST)
        jwt_tok = self.build_es256_jwt(method=method, request_path=request_path)
        headers = {
            "Authorization": f"Bearer {jwt_tok}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if extra_headers is not None:
            for hk, hv in extra_headers.items():
                clean_k = str(hk).strip()
                clean_v = str(hv).strip()
                if clean_k and clean_v and clean_k.lower() not in ("authorization", "host"):
                    headers[clean_k] = clean_v
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

    def get_conversion_status(
        self,
        *,
        client_reference_id: str | None = None,
        conversion_tx_id: str | None = None,
    ) -> dict[str, Any]:
        """Read-only Coinbase conversion history lookup by trade ID or client_reference_id."""
        clean_tx = str(conversion_tx_id or "").strip()
        clean_ref = str(client_reference_id or "").strip()
        if clean_tx:
            return self._call(
                "GET",
                f"/api/v3/brokerage/convert/trade/{urllib.parse.quote(clean_tx, safe='')}",
            )
        if clean_ref:
            return self._call(
                "GET",
                f"/api/v3/brokerage/convert/trade?client_reference_id={urllib.parse.quote(clean_ref, safe='')}",
            )
        raise ContractError("conversion_tx_id or client_reference_id is required")

    def get_withdrawal_status(
        self,
        *,
        client_reference_id: str | None = None,
        provider_tx_id: str | None = None,
    ) -> dict[str, Any]:
        """Read-only Coinbase fiat ACH withdrawal lookup by provider_tx_id or client_reference_id."""
        clean_tx = str(provider_tx_id or "").strip()
        clean_ref = str(client_reference_id or "").strip()
        if clean_tx:
            return self._call(
                "GET",
                f"/api/v3/brokerage/withdrawals/fiat/{urllib.parse.quote(clean_tx, safe='')}",
            )
        if clean_ref:
            return self._call(
                "GET",
                f"/api/v3/brokerage/withdrawals/fiat?client_reference_id={urllib.parse.quote(clean_ref, safe='')}",
            )
        raise ContractError("provider_tx_id or client_reference_id is required")

    def convert_to_usd(
        self,
        *,
        from_currency: str,
        amount: Decimal,
        from_account_uuid: str,
        usd_account_uuid: str,
        commit: bool = True,
        client_reference_id: str | None = None,
    ) -> dict[str, Any]:
        decimal_value(amount, "amount", positive=True)
        cur = str(from_currency).strip().upper()
        if cur not in ("USDC", "USDT", "BTC", "ETH"):
            raise OfframpSecurityError(f"Unsupported source asset {cur!r} for USD conversion")
        clean_ref = (
            str(client_reference_id).strip()[:64]
            if client_reference_id is not None and str(client_reference_id).strip()
            else ""
        )
        quote_payload: dict[str, Any] = {
            "from_account": str(from_account_uuid).strip(),
            "to_account": str(usd_account_uuid).strip(),
            "amount": decimal_text(amount),
            "from_currency": cur,
            "to_currency": "USD",
        }
        extra_hdrs = {"Idempotency-Key": clean_ref} if clean_ref else None
        if clean_ref:
            quote_payload["client_reference_id"] = clean_ref
        quote_doc = self._call(
            "POST",
            "/api/v3/brokerage/convert/quote",
            quote_payload,
            extra_headers=extra_hdrs,
        )
        trade = quote_doc.get("trade") if isinstance(quote_doc.get("trade"), dict) else quote_doc
        trade_id = str(trade.get("id") or "")
        if not commit or not trade_id:
            return quote_doc
        commit_payload: dict[str, Any] = {
            "from_account": str(from_account_uuid).strip(),
            "to_account": str(usd_account_uuid).strip(),
        }
        if clean_ref:
            commit_payload["client_reference_id"] = clean_ref
        return self._call(
            "POST",
            f"/api/v3/brokerage/convert/trade/{urllib.parse.quote(trade_id, safe='')}",
            commit_payload,
            extra_headers=extra_hdrs,
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
        clean_ref = (
            str(client_reference_id).strip()[:64]
            if client_reference_id is not None and str(client_reference_id).strip()
            else f"cas-ach-{uuid.uuid4().hex[:12]}"
        )
        return self._call(
            "POST",
            "/api/v3/brokerage/withdrawals/fiat",
            {
                "currency": "USD",
                "amount": decimal_text(amount_usd.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
                "payment_method_id": self._bank_account_id,
                "rail": "ACH",
                "client_reference_id": clean_ref,
            },
            extra_headers={"Idempotency-Key": clean_ref},
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

    def get_conversion_status(
        self,
        *,
        client_reference_id: str | None = None,
        conversion_tx_id: str | None = None,
    ) -> dict[str, Any]:
        """Read-only Kraken order history lookup by txid or cl_ord_id for conversion reconciliation."""
        clean_tx = str(conversion_tx_id or "").strip()
        clean_ref = str(client_reference_id or "").strip()
        if clean_tx:
            return self._private_post("/0/private/QueryOrders", {"txid": clean_tx})
        if clean_ref:
            return self._private_post("/0/private/ClosedOrders", {"cl_ord_id": clean_ref[:64]})
        raise ContractError("conversion_tx_id or client_reference_id is required")

    def get_withdrawal_status(
        self,
        *,
        client_reference_id: str | None = None,
        provider_tx_id: str | None = None,
    ) -> dict[str, Any]:
        """Read-only Kraken ZUSD withdrawal status lookup for ACH withdrawal reconciliation."""
        params: dict[str, str] = {"asset": "ZUSD"}
        if client_reference_id is not None and str(client_reference_id).strip():
            params["client_ref"] = str(client_reference_id).strip()[:64]
        if provider_tx_id is not None and str(provider_tx_id).strip():
            params["refid"] = str(provider_tx_id).strip()[:64]
        return self._private_post("/0/private/WithdrawStatus", params)

    def convert_to_usd(
        self,
        *,
        pair: str = "USDCUSD",
        volume: Decimal,
        client_reference_id: str | None = None,
    ) -> dict[str, Any]:
        decimal_value(volume, "volume", positive=True)
        clean_pair = str(pair).strip().upper()
        if clean_pair not in ("USDCUSD", "USDTUSD", "XBTUSD", "ETHUSD"):
            raise OfframpSecurityError(f"Unsupported conversion pair {clean_pair!r}; only USD pairs permitted")
        params: dict[str, str] = {
            "pair": clean_pair,
            "type": "sell",
            "ordertype": "market",
            "volume": decimal_text(volume),
        }
        if client_reference_id is not None and str(client_reference_id).strip():
            params["cl_ord_id"] = str(client_reference_id).strip()[:64]
        return self._private_post("/0/private/AddOrder", params)

    def withdraw_usd_to_linked_bank_ach(
        self,
        *,
        amount_usd: Decimal,
        key_id: str | None = None,
        client_reference_id: str | None = None,
    ) -> dict[str, Any]:
        """Submit Kraken ZUSD ACH withdrawal strictly to the owner-linked bank key."""
        decimal_value(amount_usd, "amount_usd", positive=True)
        if key_id is not None and key_id.strip() != self._bank_key:
            raise OfframpSecurityError("Cannot override pinned Kraken bank withdrawal key")
        params: dict[str, Any] = {
            "asset": "ZUSD",
            "key": self._bank_key,
            "amount": decimal_text(amount_usd.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
        }
        if client_reference_id is not None and str(client_reference_id).strip():
            params["client_ref"] = str(client_reference_id).strip()[:64]
        return self._private_post("/0/private/Withdraw", params)


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
        initial_capital_usd: Decimal | None = None,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(db_path, Path):
            db_path = Path(str(db_path))
        decimal_value(sweep_ratio, "sweep_ratio")
        if sweep_ratio < Decimal("0") or sweep_ratio > Decimal("0.90"):
            raise ContractError("sweep_ratio must be in [0, 0.90]")
        if preferred_rail not in VALID_PAYOUT_RAILS:
            raise ContractError(f"preferred_rail must be one of {VALID_PAYOUT_RAILS}")
        resolved_init_cap: Decimal | None = None
        if initial_capital_usd is not None:
            resolved_init_cap = decimal_value(
                Decimal(initial_capital_usd), "initial_capital_usd", positive=True
            ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        elif environ is not None:
            raw_init_env = str(environ.get(ENV_INITIAL_CAPITAL_USD, "")).strip()
            if raw_init_env:
                try:
                    parsed_init = Decimal(raw_init_env)
                except Exception as exc:
                    raise ContractError(f"Invalid {ENV_INITIAL_CAPITAL_USD}={raw_init_env!r}") from exc
                resolved_init_cap = decimal_value(
                    parsed_init, ENV_INITIAL_CAPITAL_USD, positive=True
                ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        _ensure_owner_dir(db_path.parent)
        self.db_path = db_path
        self.scope_id = identifier(scope_id, "scope_id")
        self._clock = clock or _utc_now
        self._lock = RLock()
        self._in_flight_transfers: set[str] = set()
        self._init_db(
            default_ratio=sweep_ratio,
            default_auto=auto_sweep_enabled,
            default_rail=preferred_rail,
            default_initial_capital=resolved_init_cap,
        )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5.0, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=5000")
            return conn
        except Exception:
            conn.close()
            raise

    def _connect_ro(self) -> sqlite3.Connection:
        ro_uri = f"{self.db_path.resolve().as_uri()}?mode=ro"
        conn = sqlite3.connect(ro_uri, uri=True, timeout=5.0, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=5000")
            return conn
        except Exception:
            conn.close()
            raise

    def _init_db(
        self,
        *,
        default_ratio: Decimal,
        default_auto: bool,
        default_rail: str,
        default_initial_capital: Decimal | None = None,
    ) -> None:
        with self._lock, closing(self._connect()) as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS vault_config (
                    scope_id TEXT PRIMARY KEY,
                    sweep_ratio_text TEXT NOT NULL,
                    auto_sweep_enabled INTEGER NOT NULL,
                    preferred_rail TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    initial_capital_usd_text TEXT
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
                    session_date TEXT,
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
                    settled_at TEXT,
                    idempotency_key TEXT UNIQUE,
                    error_detail TEXT,
                    conversion_required INTEGER NOT NULL DEFAULT 0,
                    conversion_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED',
                    conversion_client_ref TEXT,
                    conversion_tx_id TEXT,
                    conversion_spec_json TEXT,
                    conversion_error_detail TEXT,
                    withdrawal_status TEXT NOT NULL DEFAULT 'WITHDRAWAL_NOT_STARTED',
                    withdrawal_error_detail TEXT
                );
                CREATE TABLE IF NOT EXISTS treasury_intents (
                    intent_id TEXT PRIMARY KEY,
                    intent_sha256 TEXT NOT NULL UNIQUE,
                    scope_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    transfer_id TEXT NOT NULL,
                    rail TEXT NOT NULL,
                    broker_id TEXT,
                    destination_bank_id TEXT NOT NULL,
                    amount_usd_text TEXT NOT NULL,
                    conversion_json TEXT NOT NULL,
                    idempotency_key TEXT,
                    retry_transfer_id TEXT,
                    owner_request_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    consumed_at TEXT
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
            se_cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(sweep_events)").fetchall()}
            if "session_date" not in se_cols:
                conn.execute("ALTER TABLE sweep_events ADD COLUMN session_date TEXT")
            null_se = conn.execute(
                "SELECT scope_id, trade_id, occurred_at FROM sweep_events WHERE session_date IS NULL OR session_date = ''"
            ).fetchall()
            if null_se:
                from cas_forex_revamp.valve.daily_quota import session_date_for

                for nr in null_se:
                    tid = str(nr["trade_id"])
                    inferred_sdate: str | None = None
                    if tid.startswith("SESSION_SYNC_"):
                        parts = tid.split("_")
                        if len(parts) >= 4 and len(parts[2]) == 10:
                            inferred_sdate = parts[2]
                    if not inferred_sdate:
                        try:
                            r_dt = datetime.fromisoformat(str(nr["occurred_at"]).replace("Z", "+00:00"))
                            inferred_sdate = session_date_for(r_dt)
                        except ValueError:
                            inferred_sdate = str(nr["occurred_at"])[:10] or "1970-01-01"
                    conn.execute(
                        "UPDATE sweep_events SET session_date = ? WHERE scope_id = ? AND trade_id = ?",
                        (inferred_sdate, str(nr["scope_id"]), tid),
                    )
            bt_cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(bank_transfers)").fetchall()}
            if "idempotency_key" not in bt_cols:
                conn.execute("ALTER TABLE bank_transfers ADD COLUMN idempotency_key TEXT")
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_bank_transfers_idem ON bank_transfers(idempotency_key) WHERE idempotency_key IS NOT NULL")
            if "error_detail" not in bt_cols:
                conn.execute("ALTER TABLE bank_transfers ADD COLUMN error_detail TEXT")
            if "conversion_required" not in bt_cols:
                conn.execute("ALTER TABLE bank_transfers ADD COLUMN conversion_required INTEGER NOT NULL DEFAULT 0")
            if "conversion_status" not in bt_cols:
                conn.execute("ALTER TABLE bank_transfers ADD COLUMN conversion_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED'")
            if "conversion_client_ref" not in bt_cols:
                conn.execute("ALTER TABLE bank_transfers ADD COLUMN conversion_client_ref TEXT")
            if "conversion_tx_id" not in bt_cols:
                conn.execute("ALTER TABLE bank_transfers ADD COLUMN conversion_tx_id TEXT")
            if "conversion_spec_json" not in bt_cols:
                conn.execute("ALTER TABLE bank_transfers ADD COLUMN conversion_spec_json TEXT")
            if "conversion_error_detail" not in bt_cols:
                conn.execute("ALTER TABLE bank_transfers ADD COLUMN conversion_error_detail TEXT")
            if "withdrawal_status" not in bt_cols:
                conn.execute("ALTER TABLE bank_transfers ADD COLUMN withdrawal_status TEXT NOT NULL DEFAULT 'WITHDRAWAL_NOT_STARTED'")
            if "withdrawal_error_detail" not in bt_cols:
                conn.execute("ALTER TABLE bank_transfers ADD COLUMN withdrawal_error_detail TEXT")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_bank_transfers_conv_ref "
                "ON bank_transfers(conversion_client_ref) WHERE conversion_client_ref IS NOT NULL"
            )
            conn.execute(
                "UPDATE bank_transfers SET withdrawal_status = 'WITHDRAWAL_SUBMITTED' "
                "WHERE status IN ('ACH_SUBMITTED', 'SETTLED') AND withdrawal_status = 'WITHDRAWAL_NOT_STARTED'"
            )
            conn.execute(
                "UPDATE bank_transfers SET withdrawal_status = 'WITHDRAWAL_OUTCOME_UNKNOWN' "
                "WHERE status = 'OUTCOME_UNKNOWN' AND conversion_status = 'NOT_REQUIRED' "
                "AND withdrawal_status = 'WITHDRAWAL_NOT_STARTED'"
            )
            vc_cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(vault_config)").fetchall()}
            if "initial_capital_usd_text" not in vc_cols:
                conn.execute("ALTER TABLE vault_config ADD COLUMN initial_capital_usd_text TEXT")
            row = conn.execute(
                "SELECT scope_id, initial_capital_usd_text FROM vault_config WHERE scope_id = ?",
                (self.scope_id,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO vault_config(
                        scope_id, sweep_ratio_text, auto_sweep_enabled, preferred_rail, updated_at, initial_capital_usd_text
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self.scope_id,
                        decimal_text(default_ratio),
                        1 if default_auto else 0,
                        default_rail,
                        _iso(self._clock()),
                        None if default_initial_capital is None else decimal_text(default_initial_capital),
                    ),
                )
            elif default_initial_capital is not None and row["initial_capital_usd_text"] in (None, ""):
                conn.execute(
                    "UPDATE vault_config SET initial_capital_usd_text = ?, updated_at = ? WHERE scope_id = ?",
                    (decimal_text(default_initial_capital), _iso(self._clock()), self.scope_id),
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

    def _disbursed_total_unlocked(self, conn: sqlite3.Connection) -> Decimal:
        disbursed = Decimal("0.00")
        for r in conn.execute(
            "SELECT amount_usd_text, status FROM bank_transfers WHERE scope_id = ?",
            (self.scope_id,),
        ):
            if str(r["status"]) in ("SETTLED", "ACH_SUBMITTED", "RESERVED_PENDING_DISPATCH", "OUTCOME_UNKNOWN"):
                disbursed += Decimal(str(r["amount_usd_text"]))
        return disbursed.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    def _confirmed_settled_disbursed_unlocked(self, conn: sqlite3.Connection) -> Decimal:
        """Sum STRICTLY confirmed SETTLED external bank payouts (excludes pending/submitted/unknown)."""
        settled = Decimal("0.00")
        for r in conn.execute(
            "SELECT amount_usd_text, status FROM bank_transfers WHERE scope_id = ?",
            (self.scope_id,),
        ):
            if str(r["status"]) == "SETTLED":
                settled += Decimal(str(r["amount_usd_text"]))
        return settled.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    @staticmethod
    def _resolve_effective_initial_capital(
        cfg_row: sqlite3.Row | None,
        initial_capital_usd: Decimal | None,
    ) -> Decimal | None:
        if initial_capital_usd is not None:
            return decimal_value(
                Decimal(initial_capital_usd), "initial_capital_usd", positive=True
            ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        if cfg_row is not None and cfg_row["initial_capital_usd_text"] not in (None, ""):
            return Decimal(str(cfg_row["initial_capital_usd_text"])).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
        return None

    def _select_session_sweep_rows(
        self,
        conn: sqlite3.Connection,
        sdate: str,
    ) -> list[sqlite3.Row]:
        rows = list(
            conn.execute(
                "SELECT realized_net_usd_text, retained_trading_usd_text, bank_sweep_usd_text, occurred_at "
                "FROM sweep_events WHERE scope_id = ? AND session_date = ?",
                (self.scope_id, sdate),
            ).fetchall()
        )
        if sdate.endswith("-ASIA") and len(sdate) == 15:
            anchor_str = sdate[:-5]
            try:
                from datetime import timedelta as _td

                anchor_dt = datetime.fromisoformat(f"{anchor_str}T00:00:00+00:00")
                asia_start = anchor_dt - _td(hours=2)
                asia_end = anchor_dt + _td(hours=7)
                legacy_rows = conn.execute(
                    "SELECT realized_net_usd_text, retained_trading_usd_text, bank_sweep_usd_text, occurred_at "
                    "FROM sweep_events WHERE scope_id = ? AND session_date = ?",
                    (self.scope_id, anchor_str),
                ).fetchall()
                for lr in legacy_rows:
                    try:
                        occ_dt = datetime.fromisoformat(str(lr["occurred_at"]).replace("Z", "+00:00"))
                        if asia_start <= occ_dt < asia_end:
                            rows.append(lr)
                    except ValueError:
                        continue
            except ValueError:
                pass
        return rows

    def configured_initial_capital_usd(self) -> Decimal | None:
        with self._lock, closing(self._connect()) as conn:
            cfg = conn.execute(
                "SELECT initial_capital_usd_text FROM vault_config WHERE scope_id = ?",
                (self.scope_id,),
            ).fetchone()
            if cfg is not None and cfg["initial_capital_usd_text"] not in (None, ""):
                return Decimal(str(cfg["initial_capital_usd_text"])).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )
        return None

    def set_config(
        self,
        *,
        sweep_ratio: Decimal | None = None,
        auto_sweep_enabled: bool | None = None,
        preferred_rail: str | None = None,
        initial_capital_usd: Decimal | None = None,
    ) -> dict[str, Any]:
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM vault_config WHERE scope_id = ?", (self.scope_id,)).fetchone()
            cur_ratio = Decimal(str(row["sweep_ratio_text"])) if row else DEFAULT_SWEEP_RATIO
            cur_auto = bool(int(row["auto_sweep_enabled"])) if row else True
            cur_rail = str(row["preferred_rail"]) if row else RAIL_BROKER_2FA_MANUAL
            cur_init_cap = (
                Decimal(str(row["initial_capital_usd_text"]))
                if (row and row["initial_capital_usd_text"] not in (None, ""))
                else None
            )

            new_ratio = cur_ratio if sweep_ratio is None else decimal_value(sweep_ratio, "sweep_ratio")
            if new_ratio < Decimal("0") or new_ratio > Decimal("0.90"):
                raise ContractError("sweep_ratio must be in [0, 0.90]")
            new_auto = cur_auto if auto_sweep_enabled is None else bool(auto_sweep_enabled)
            new_rail = cur_rail if preferred_rail is None else str(preferred_rail).strip()
            if new_rail not in VALID_PAYOUT_RAILS:
                raise ContractError(f"preferred_rail must be one of {VALID_PAYOUT_RAILS}")
            new_init_cap = (
                cur_init_cap
                if initial_capital_usd is None
                else decimal_value(Decimal(initial_capital_usd), "initial_capital_usd", positive=True).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )
            )

            ts = _iso(self._clock())
            conn.execute(
                """
                UPDATE vault_config
                SET sweep_ratio_text = ?, auto_sweep_enabled = ?, preferred_rail = ?,
                    initial_capital_usd_text = ?, updated_at = ?
                WHERE scope_id = ?
                """,
                (
                    decimal_text(new_ratio),
                    1 if new_auto else 0,
                    new_rail,
                    None if new_init_cap is None else decimal_text(new_init_cap),
                    ts,
                    self.scope_id,
                ),
            )
            audit_payload: dict[str, Any] = {
                "sweep_ratio": decimal_text(new_ratio),
                "auto_sweep_enabled": new_auto,
                "preferred_rail": new_rail,
            }
            if new_init_cap is not None:
                audit_payload["initial_capital_usd"] = decimal_text(new_init_cap)
            self._append_audit(
                conn,
                "CONFIG_UPDATED",
                audit_payload,
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
        session_date: str | None = None,
        total_equity_usd: Decimal | None = None,
        initial_capital_usd: Decimal | None = None,
    ) -> dict[str, Any]:
        if not isinstance(trade_id, str) or not trade_id.strip():
            raise ContractError("trade_id must be a non-empty string")
        decimal_value(realized_net_usd, "realized_net_usd")
        eq_val = (
            decimal_value(Decimal(total_equity_usd), "total_equity_usd").quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            if total_equity_usd is not None
            else None
        )
        occ_dt = occurred_at or self._clock()
        ts = _iso(occ_dt)
        if session_date is not None and str(session_date).strip():
            eff_sdate = str(session_date).strip()
        else:
            from cas_forex_revamp.valve.daily_quota import session_date_for

            eff_sdate = session_date_for(occ_dt)
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
            eff_init_cap = self._resolve_effective_initial_capital(cfg, initial_capital_usd)

            if realized_net_usd > Decimal("0") and auto_on and ratio > Decimal("0"):
                with localcontext() as ctx:
                    ctx.prec = 40
                    unconstrained_bank = (realized_net_usd * ratio).quantize(
                        Decimal("0.01"), rounding=ROUND_HALF_UP
                    )
            else:
                unconstrained_bank = Decimal("0.00")

            if eq_val is not None and eff_init_cap is not None:
                settled_disbursed = self._confirmed_settled_disbursed_unlocked(conn)
                overall_bank = Decimal("0.00")
                for r_all in conn.execute(
                    "SELECT bank_sweep_usd_text FROM sweep_events WHERE scope_id = ?",
                    (self.scope_id,),
                ):
                    overall_bank += Decimal(str(r_all["bank_sweep_usd_text"]))
                economic_equity = (eq_val + settled_disbursed).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )
                true_surplus = max(
                    Decimal("0.00"),
                    (economic_equity - eff_init_cap).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
                )
                if true_surplus <= Decimal("0.00"):
                    bank_part = Decimal("0.00")
                else:
                    if auto_on and ratio > Decimal("0"):
                        with localcontext() as ctx:
                            ctx.prec = 40
                            max_surplus_reserve = (true_surplus * ratio).quantize(
                                Decimal("0.01"), rounding=ROUND_HALF_UP
                            )
                    else:
                        max_surplus_reserve = Decimal("0.00")
                    desired_overall_bank = max(settled_disbursed, max_surplus_reserve)
                    headroom = max(Decimal("0.00"), desired_overall_bank - overall_bank)
                    bank_part = min(unconstrained_bank, headroom)
                retained_part = realized_net_usd - bank_part
            else:
                bank_part = unconstrained_bank
                retained_part = realized_net_usd - bank_part

            conn.execute(
                """
                INSERT INTO sweep_events(
                    trade_id, scope_id, symbol, broker_id, realized_net_usd_text,
                    retained_trading_usd_text, bank_sweep_usd_text, occurred_at, session_date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    eff_sdate,
                ),
            )
            self._append_audit(
                conn,
                "REALIZED_CLOSE_SWEPT",
                {
                    "trade_id": trade_id.strip(),
                    "session_date": eff_sdate,
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

    def session_totals(self, session_date: str) -> dict[str, str]:
        """Read-only per-session realized, retained, and internal vault reserve totals."""
        if not isinstance(session_date, str) or not session_date.strip():
            raise ContractError("session_date must be a non-empty session identifier")
        sdate = session_date.strip()
        with self._lock, closing(self._connect_ro()) as conn:
            rows = self._select_session_sweep_rows(conn, sdate)
            s_realized = Decimal("0")
            s_retained = Decimal("0")
            s_bank = Decimal("0")
            for r in rows:
                s_realized += Decimal(str(r["realized_net_usd_text"]))
                s_retained += Decimal(str(r["retained_trading_usd_text"]))
                s_bank += Decimal(str(r["bank_sweep_usd_text"]))
        return {
            "session_date": sdate,
            "realized_net_usd": decimal_text(s_realized),
            "retained_trading_usd": decimal_text(s_retained),
            "bank_sweep_usd": decimal_text(max(Decimal("0.00"), s_bank)),
        }

    def reconcile_session_realized_profit(
        self,
        *,
        session_date: str,
        session_realized_net_usd: Decimal,
        occurred_at: datetime | str | None = None,
        total_equity_usd: Decimal | None = None,
        initial_capital_usd: Decimal | None = None,
    ) -> dict[str, Any] | None:
        """Idempotently reconcile session realized net P&L (with Principal High-Water Mark surplus gating when equity & principal are provided)."""
        if not isinstance(session_date, str) or not session_date.strip():
            raise ContractError("session_date must be a non-empty session identifier")
        sdate = session_date.strip()
        target_net = decimal_value(Decimal(session_realized_net_usd), "session_realized_net_usd").quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        eq_val = (
            decimal_value(Decimal(total_equity_usd), "total_equity_usd").quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            if total_equity_usd is not None
            else None
        )

        if occurred_at is None:
            occ_dt = self._clock()
        elif isinstance(occurred_at, datetime):
            occ_dt = occurred_at
        elif isinstance(occurred_at, str) and occurred_at.strip():
            try:
                occ_dt = datetime.fromisoformat(occurred_at.strip().replace("Z", "+00:00"))
            except ValueError as exc:
                raise ContractError("occurred_at must be a valid ISO-8601 UTC timestamp") from exc
        else:
            raise ContractError("occurred_at must be a datetime, ISO-8601 string, or None")
        ts = _iso(occ_dt)

        cents_int = int((target_net * Decimal("100")).to_integral_value())
        cents_tag = f"M{abs(cents_int)}" if cents_int < 0 else str(cents_int)

        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            sess_rows = self._select_session_sweep_rows(conn, sdate)
            session_realized = Decimal("0.00")
            session_bank = Decimal("0.00")
            for r in sess_rows:
                session_realized += Decimal(str(r["realized_net_usd_text"]))
                session_bank += Decimal(str(r["bank_sweep_usd_text"]))

            overall_bank = Decimal("0.00")
            for r_all in conn.execute(
                "SELECT bank_sweep_usd_text FROM sweep_events WHERE scope_id = ?",
                (self.scope_id,),
            ):
                overall_bank += Decimal(str(r_all["bank_sweep_usd_text"]))

            gap = (target_net - session_realized).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

            cfg = conn.execute("SELECT * FROM vault_config WHERE scope_id = ?", (self.scope_id,)).fetchone()
            ratio = Decimal(str(cfg["sweep_ratio_text"])) if cfg else DEFAULT_SWEEP_RATIO
            auto_on = bool(int(cfg["auto_sweep_enabled"])) if cfg else True
            eff_init_cap = self._resolve_effective_initial_capital(cfg, initial_capital_usd)

            if eq_val is not None and eff_init_cap is not None:
                settled_disbursed = self._confirmed_settled_disbursed_unlocked(conn)
                economic_equity = (eq_val + settled_disbursed).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )
                true_surplus = max(
                    Decimal("0.00"),
                    (economic_equity - eff_init_cap).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
                )
                if true_surplus <= Decimal("0.00"):
                    desired_overall_bank = settled_disbursed
                else:
                    if auto_on and ratio > Decimal("0"):
                        with localcontext() as ctx:
                            ctx.prec = 40
                            max_surplus_reserve = (true_surplus * ratio).quantize(
                                Decimal("0.01"), rounding=ROUND_HALF_UP
                            )
                    else:
                        max_surplus_reserve = Decimal("0.00")
                    desired_overall_bank = max(settled_disbursed, max_surplus_reserve)
                bank_delta = (desired_overall_bank - overall_bank).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )
            else:
                if target_net > Decimal("0") and auto_on and ratio > Decimal("0"):
                    with localcontext() as ctx:
                        ctx.prec = 40
                        target_session_bank = (target_net * ratio).quantize(
                            Decimal("0.01"), rounding=ROUND_HALF_UP
                        )
                else:
                    target_session_bank = Decimal("0.00")
                bank_delta = (target_session_bank - session_bank).quantize(
                    Decimal("0.01"), rounding=ROUND_HALF_UP
                )

            if overall_bank + bank_delta < Decimal("0.00"):
                bank_delta = -overall_bank
            retained_delta = gap - bank_delta

            if gap == Decimal("0.00") and bank_delta == Decimal("0.00"):
                conn.execute("ROLLBACK")
                return None

            safe_sdate = sdate.replace("#", "_")
            sync_prefix = f"SESSION_SYNC_{safe_sdate}_"
            seq_row = conn.execute(
                "SELECT COUNT(*) FROM sweep_events WHERE scope_id = ? AND trade_id LIKE ?",
                (self.scope_id, f"{sync_prefix}%"),
            ).fetchone()
            seq_n = (int(seq_row[0]) if seq_row is not None else 0) + 1
            sync_trade_id = f"SESSION_SYNC_{safe_sdate}_{seq_n:04d}_{cents_tag}"

            conn.execute(
                """
                INSERT INTO sweep_events(
                    trade_id, scope_id, symbol, broker_id, realized_net_usd_text,
                    retained_trading_usd_text, bank_sweep_usd_text, occurred_at, session_date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sync_trade_id,
                    self.scope_id,
                    "SESSION_BASKET",
                    "DUAL_SHIELD_BARBELL",
                    decimal_text(gap),
                    decimal_text(retained_delta),
                    decimal_text(bank_delta),
                    ts,
                    sdate,
                ),
            )
            self._append_audit(
                conn,
                "SESSION_PROFIT_RECONCILED",
                {
                    "trade_id": sync_trade_id,
                    "session_date": sdate,
                    "symbol": "SESSION_BASKET",
                    "broker_id": "DUAL_SHIELD_BARBELL",
                    "realized_net_usd": decimal_text(gap),
                    "retained_trading_usd": decimal_text(retained_delta),
                    "bank_sweep_usd": decimal_text(bank_delta),
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

    @staticmethod
    def _build_conversion_spec(
        *,
        rail: str,
        convert_from_currency: str | None = None,
        convert_amount: Decimal | None = None,
        coinbase_source_account_uuid: str | None = None,
        coinbase_usd_account_uuid: str | None = None,
        kraken_pair: str = "USDCUSD",
    ) -> dict[str, Any]:
        if rail == RAIL_COINBASE_ACH:
            if convert_from_currency is not None and convert_amount is not None:
                if not coinbase_source_account_uuid or not coinbase_usd_account_uuid:
                    raise ContractError("Coinbase source/USD account UUIDs are required for conversion")
                conv_amt = decimal_value(convert_amount, "convert_amount", positive=True)
                return {
                    "enabled": True,
                    "from_currency": str(convert_from_currency).strip().upper(),
                    "to_currency": "USD",
                    "amount": decimal_text(conv_amt),
                    "source_account_uuid": str(coinbase_source_account_uuid).strip(),
                    "usd_account_uuid": str(coinbase_usd_account_uuid).strip(),
                }
            return {
                "enabled": False,
                "from_currency": "USD",
                "to_currency": "USD",
                "amount": None,
                "source_account_uuid": None,
                "usd_account_uuid": None,
            }
        if rail == RAIL_KRAKEN_ACH:
            clean_pair = str(kraken_pair).strip().upper()
            if clean_pair not in ("USDCUSD", "USDTUSD", "XBTUSD", "ETHUSD"):
                raise OfframpSecurityError(f"Unsupported conversion pair {clean_pair!r}; only USD pairs permitted")
            if convert_amount is not None:
                conv_amt = decimal_value(convert_amount, "convert_amount", positive=True)
                return {
                    "enabled": True,
                    "pair": clean_pair,
                    "to_currency": "ZUSD",
                    "amount": decimal_text(conv_amt),
                }
            return {
                "enabled": False,
                "pair": clean_pair,
                "to_currency": "ZUSD",
                "amount": None,
            }
        return {
            "enabled": False,
            "from_currency": "USD",
            "to_currency": "USD",
            "amount": None,
        }

    def _canonical_intent_payload(
        self,
        *,
        intent_id: str,
        action: str,
        transfer_id: str,
        amt_q: Decimal,
        rail: str,
        broker_id: str | None,
        destination_bank_id: str,
        conversion_spec: Mapping[str, Any],
        idempotency_key: str | None,
        retry_transfer_id: str | None,
        owner_request_id: str,
    ) -> dict[str, Any]:
        return {
            "protocol": "cas-forex-treasury-intent/1",
            "intent_id": intent_id,
            "scope_id": self.scope_id,
            "action": action,
            "transfer_id": transfer_id,
            "amount_usd": decimal_text(amt_q),
            "rail": rail,
            "broker_id": broker_id,
            "destination_bank_id": destination_bank_id,
            "conversion": dict(conversion_spec),
            "idempotency_key": idempotency_key,
            "retry_transfer_id": retry_transfer_id,
            "owner_request_id": owner_request_id,
        }

    def prepare_broker_2fa_withdrawal(
        self,
        *,
        broker_id: str,
        amount_usd: Decimal,
        owner_request_id: str,
        reason: str,
        destination_bank_label: str = "OWNER_LINKED_BANK",
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        """Persist a canonical broker 2FA withdrawal intent BEFORE owner approval (Finding [13])."""
        amt_q = decimal_value(amount_usd, "amount_usd", positive=True).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        if amt_q <= Decimal("0"):
            raise ContractError("amount_usd must be >= $0.01")
        clean_req_id = identifier(owner_request_id, "owner_request_id")
        clean_reason = str(reason or "").strip()[:240]
        clean_broker = str(broker_id or "").strip()
        clean_dest = str(destination_bank_label or "").strip()
        if not clean_reason or not clean_broker or not clean_dest:
            raise ContractError("broker_id, destination_bank_label, owner_request_id, and reason are required")
        if type(ttl_seconds) is not int or not (30 <= ttl_seconds <= MAX_TREASURY_INTENT_TTL_SECONDS):
            raise ContractError(f"ttl_seconds must be in 30..{MAX_TREASURY_INTENT_TTL_SECONDS}")
        now_dt = utc_time(self._clock(), "clock")
        ts = _iso(now_dt)
        exp_str = _iso(now_dt + timedelta(seconds=ttl_seconds))
        intent_id = f"ti2fa-{uuid.uuid4().hex[:16]}"
        transfer_id = f"tr2fa-{uuid.uuid4().hex[:16]}"
        conv_spec = self._build_conversion_spec(rail=RAIL_BROKER_2FA_MANUAL)
        canon = self._canonical_intent_payload(
            intent_id=intent_id,
            action=INTENT_ACTION_BROKER_2FA,
            transfer_id=transfer_id,
            amt_q=amt_q,
            rail=RAIL_BROKER_2FA_MANUAL,
            broker_id=clean_broker,
            destination_bank_id=clean_dest,
            conversion_spec=conv_spec,
            idempotency_key=None,
            retry_transfer_id=None,
            owner_request_id=clean_req_id,
        )
        intent_sha = sha256(canonical_bytes(canon)).hexdigest()
        conv_json = canonical_bytes(conv_spec).decode("utf-8")
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO treasury_intents(
                    intent_id, intent_sha256, scope_id, action, transfer_id, rail, broker_id,
                    destination_bank_id, amount_usd_text, conversion_json, idempotency_key,
                    retry_transfer_id, owner_request_id, reason, status, created_at, expires_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, 'PREPARED', ?, ?, NULL)
                """,
                (
                    intent_id,
                    intent_sha,
                    self.scope_id,
                    INTENT_ACTION_BROKER_2FA,
                    transfer_id,
                    RAIL_BROKER_2FA_MANUAL,
                    clean_broker,
                    clean_dest,
                    decimal_text(amt_q),
                    conv_json,
                    clean_req_id,
                    clean_reason,
                    ts,
                    exp_str,
                ),
            )
            self._append_audit(
                conn,
                "TREASURY_INTENT_PREPARED",
                {
                    "intent_id": intent_id,
                    "intent_sha256": intent_sha,
                    "action": INTENT_ACTION_BROKER_2FA,
                    "transfer_id": transfer_id,
                    "rail": RAIL_BROKER_2FA_MANUAL,
                    "broker_id": clean_broker,
                    "destination_bank_id": clean_dest,
                    "amount_usd": decimal_text(amt_q),
                    "owner_request_id": clean_req_id,
                },
                ts,
            )
            conn.execute("COMMIT")
        return {
            "intent_id": intent_id,
            "intent_sha256": intent_sha,
            "transfer_id": transfer_id,
            "scope_id": self.scope_id,
            "action": INTENT_ACTION_BROKER_2FA,
            "amount_usd": decimal_text(amt_q),
            "rail": RAIL_BROKER_2FA_MANUAL,
            "broker_id": clean_broker,
            "destination_bank_id": clean_dest,
            "conversion": conv_spec,
            "idempotency_key": None,
            "retry_transfer_id": None,
            "owner_request_id": clean_req_id,
            "expires_at": exp_str,
        }

    def prepare_offramp_ach_payout(
        self,
        *,
        rail: str,
        amount_usd: Decimal,
        owner_request_id: str,
        reason: str,
        coinbase_client: CoinbaseOfframpClient | None = None,
        kraken_client: KrakenOfframpClient | None = None,
        destination_bank_id: str | None = None,
        convert_from_currency: str | None = None,
        convert_amount: Decimal | None = None,
        coinbase_source_account_uuid: str | None = None,
        coinbase_usd_account_uuid: str | None = None,
        kraken_pair: str = "USDCUSD",
        idempotency_key: str | None = None,
        retry_transfer_id: str | None = None,
        ttl_seconds: int = 900,
    ) -> dict[str, Any]:
        """Persist a canonical ACH off-ramp payout intent BEFORE owner approval (Finding [13])."""
        amt_q = decimal_value(amount_usd, "amount_usd", positive=True).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        if amt_q <= Decimal("0"):
            raise ContractError("amount_usd must be >= $0.01")
        clean_req_id = identifier(owner_request_id, "owner_request_id")
        clean_reason = str(reason or "").strip()[:240]
        if not clean_reason:
            raise ContractError("owner_request_id and reason are required")
        if type(ttl_seconds) is not int or not (30 <= ttl_seconds <= MAX_TREASURY_INTENT_TTL_SECONDS):
            raise ContractError(f"ttl_seconds must be in 30..{MAX_TREASURY_INTENT_TTL_SECONDS}")
        if rail not in (RAIL_COINBASE_ACH, RAIL_KRAKEN_ACH):
            raise OfframpSecurityError(f"Unsupported automated ACH rail {rail!r}")
        if rail == RAIL_COINBASE_ACH:
            if coinbase_client is not None:
                dest_bank = coinbase_client.linked_bank_account_id
                if destination_bank_id is not None and str(destination_bank_id).strip() != dest_bank:
                    raise OfframpSecurityError("Cannot override pinned Coinbase linked bank account ID")
            elif destination_bank_id is not None and str(destination_bank_id).strip():
                dest_bank = str(destination_bank_id).strip()
            else:
                raise OfframpSecurityError("CoinbaseOfframpClient is not configured")
        else:
            if kraken_client is not None:
                dest_bank = kraken_client.linked_bank_account_id
                if destination_bank_id is not None and str(destination_bank_id).strip() != dest_bank:
                    raise OfframpSecurityError("Cannot override pinned Kraken bank withdrawal key")
            elif destination_bank_id is not None and str(destination_bank_id).strip():
                dest_bank = str(destination_bank_id).strip()
            else:
                raise OfframpSecurityError("KrakenOfframpClient is not configured")

        conv_spec = self._build_conversion_spec(
            rail=rail,
            convert_from_currency=convert_from_currency,
            convert_amount=convert_amount,
            coinbase_source_account_uuid=coinbase_source_account_uuid,
            coinbase_usd_account_uuid=coinbase_usd_account_uuid,
            kraken_pair=kraken_pair,
        )
        retry_ref = str(retry_transfer_id).strip() if retry_transfer_id is not None and str(retry_transfer_id).strip() else None
        transfer_id = retry_ref if retry_ref is not None else f"trach-{uuid.uuid4().hex[:16]}"
        now_dt = utc_time(self._clock(), "clock")
        ts = _iso(now_dt)
        exp_str = _iso(now_dt + timedelta(seconds=ttl_seconds))
        intent_id = f"tiach-{uuid.uuid4().hex[:16]}"
        conv_json = canonical_bytes(conv_spec).decode("utf-8")

        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            if retry_ref is not None:
                existing = conn.execute(
                    "SELECT idempotency_key FROM bank_transfers WHERE transfer_id = ? AND scope_id = ?",
                    (retry_ref, self.scope_id),
                ).fetchone()
                if existing is not None and existing["idempotency_key"]:
                    eff_idem = str(existing["idempotency_key"])
                elif idempotency_key is not None and str(idempotency_key).strip():
                    eff_idem = str(idempotency_key).strip()
                else:
                    eff_idem = f"ach-{transfer_id}"
            else:
                eff_idem = (
                    str(idempotency_key).strip()
                    if idempotency_key is not None and str(idempotency_key).strip()
                    else "ach-" + sha256(
                        f"{self.scope_id}|{rail}|{clean_req_id}|{decimal_text(amt_q)}|{transfer_id}".encode("utf-8")
                    ).hexdigest()[:24]
                )
            canon = self._canonical_intent_payload(
                intent_id=intent_id,
                action=INTENT_ACTION_OFFRAMP_ACH,
                transfer_id=transfer_id,
                amt_q=amt_q,
                rail=rail,
                broker_id=None,
                destination_bank_id=dest_bank,
                conversion_spec=conv_spec,
                idempotency_key=eff_idem,
                retry_transfer_id=retry_ref,
                owner_request_id=clean_req_id,
            )
            intent_sha = sha256(canonical_bytes(canon)).hexdigest()
            conn.execute(
                """
                INSERT INTO treasury_intents(
                    intent_id, intent_sha256, scope_id, action, transfer_id, rail, broker_id,
                    destination_bank_id, amount_usd_text, conversion_json, idempotency_key,
                    retry_transfer_id, owner_request_id, reason, status, created_at, expires_at, consumed_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, 'PREPARED', ?, ?, NULL)
                """,
                (
                    intent_id,
                    intent_sha,
                    self.scope_id,
                    INTENT_ACTION_OFFRAMP_ACH,
                    transfer_id,
                    rail,
                    dest_bank,
                    decimal_text(amt_q),
                    conv_json,
                    eff_idem,
                    retry_ref,
                    clean_req_id,
                    clean_reason,
                    ts,
                    exp_str,
                ),
            )
            self._append_audit(
                conn,
                "TREASURY_INTENT_PREPARED",
                {
                    "intent_id": intent_id,
                    "intent_sha256": intent_sha,
                    "action": INTENT_ACTION_OFFRAMP_ACH,
                    "transfer_id": transfer_id,
                    "rail": rail,
                    "destination_bank_id": dest_bank,
                    "amount_usd": decimal_text(amt_q),
                    "idempotency_key": eff_idem,
                    "owner_request_id": clean_req_id,
                },
                ts,
            )
            conn.execute("COMMIT")
        return {
            "intent_id": intent_id,
            "intent_sha256": intent_sha,
            "transfer_id": transfer_id,
            "scope_id": self.scope_id,
            "action": INTENT_ACTION_OFFRAMP_ACH,
            "amount_usd": decimal_text(amt_q),
            "rail": rail,
            "broker_id": None,
            "destination_bank_id": dest_bank,
            "conversion": conv_spec,
            "idempotency_key": eff_idem,
            "retry_transfer_id": retry_ref,
            "owner_request_id": clean_req_id,
            "expires_at": exp_str,
        }

    def _lookup_and_verify_prepared_intent_unlocked(
        self,
        conn: sqlite3.Connection,
        *,
        intent_id: str | None,
        intent_sha256: str | None,
        expected_action: str,
        amt_q: Decimal,
        rail: str,
        broker_id: str | None,
        destination_bank_id: str,
        conversion_spec: Mapping[str, Any],
        explicit_idempotency_key: str | None,
        retry_transfer_id: str | None,
        owner_request_id: str,
        now_dt: datetime,
    ) -> tuple[str, str, str, str | None]:
        clean_iid = str(intent_id or "").strip()
        clean_isha = str(intent_sha256 or "").strip().lower()
        if not clean_iid and not clean_isha:
            raise ContractError(
                "TREASURY_INTENT_REQUIRED: persist transfer intent via prepare_* and sign exact intent_sha256 before execution"
            )
        if clean_iid:
            irow = conn.execute(
                "SELECT * FROM treasury_intents WHERE intent_id = ? AND scope_id = ?",
                (clean_iid, self.scope_id),
            ).fetchone()
            if irow is not None and clean_isha and str(irow["intent_sha256"]).lower() != clean_isha:
                raise ContractError("TREASURY_INTENT_MISMATCH: intent_id and intent_sha256 do not match")
        else:
            irow = conn.execute(
                "SELECT * FROM treasury_intents WHERE intent_sha256 = ? AND scope_id = ?",
                (clean_isha, self.scope_id),
            ).fetchone()
        if irow is None:
            raise ContractError("TREASURY_INTENT_NOT_FOUND: unknown prepared intent for this runtime scope")
        if str(irow["status"]) != "PREPARED" or irow["consumed_at"] is not None:
            raise ContractError(f"TREASURY_INTENT_ALREADY_USED: intent status is {irow['status']!r}")
        exp_dt = utc_time(datetime.fromisoformat(str(irow["expires_at"]).replace("Z", "+00:00")), "expires_at")
        if now_dt > exp_dt:
            raise ContractError("TREASURY_INTENT_EXPIRED: prepared treasury intent has expired")
        if str(irow["destination_bank_id"]) != destination_bank_id:
            raise OfframpSecurityError("Treasury destination_bank_id does not match prepared intent")
        stored_iid = str(irow["intent_id"])
        stored_sha = str(irow["intent_sha256"])
        stored_tid = str(irow["transfer_id"])
        stored_idem = str(irow["idempotency_key"]) if irow["idempotency_key"] is not None else None
        if explicit_idempotency_key is not None and str(explicit_idempotency_key).strip():
            eff_idem: str | None = str(explicit_idempotency_key).strip()
        else:
            eff_idem = stored_idem
        recomputed = self._canonical_intent_payload(
            intent_id=stored_iid,
            action=expected_action,
            transfer_id=stored_tid,
            amt_q=amt_q,
            rail=rail,
            broker_id=broker_id,
            destination_bank_id=destination_bank_id,
            conversion_spec=conversion_spec,
            idempotency_key=eff_idem,
            retry_transfer_id=retry_transfer_id,
            owner_request_id=str(owner_request_id).strip(),
        )
        recomputed_sha = sha256(canonical_bytes(recomputed)).hexdigest()
        if (
            str(irow["action"]) != expected_action
            or recomputed_sha != stored_sha
        ):
            raise ContractError(
                "TREASURY_INTENT_MISMATCH: execution parameters differ from prepared canonical intent digest"
            )
        return stored_iid, stored_sha, stored_tid, eff_idem

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
        intent_id: str | None = None,
        intent_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Queue an owner-2FA-gated broker withdrawal bound to a prepared canonical intent digest (Finding [13])."""
        amt_q = decimal_value(amount_usd, "amount_usd", positive=True).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        if amt_q <= Decimal("0"):
            raise ContractError("amount_usd must be >= $0.01")
        if not owner_request_id or not reason:
            raise ContractError("owner_request_id and reason are required")
        if verifier is None or not callable(getattr(verifier, "verify_and_consume", None)):
            raise ContractError("OWNER_RECOVERY_VERIFIER_REQUIRED")
        clean_broker = str(broker_id or "").strip()
        clean_dest = str(destination_bank_label or "").strip()
        clean_req_id = identifier(owner_request_id, "owner_request_id")
        conv_spec = self._build_conversion_spec(rail=RAIL_BROKER_2FA_MANUAL)
        now_dt = utc_time(self._clock(), "clock")
        ts = _iso(now_dt)

        ver_db = getattr(verifier, "db_path", None)
        same_db = (
            isinstance(ver_db, Path)
            and callable(getattr(verifier, "consume_on_connection", None))
            and ver_db.resolve() == self.db_path.resolve()
        )
        if same_db and callable(getattr(verifier, "ensure_initialized", None)):
            verifier.ensure_initialized()

        def _reserve_2fa(*, consume_same_db: bool, consume_fallback: bool) -> str:
            with closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    stored_iid, stored_sha, transfer_id, _ = self._lookup_and_verify_prepared_intent_unlocked(
                        conn,
                        intent_id=intent_id,
                        intent_sha256=intent_sha256,
                        expected_action=INTENT_ACTION_BROKER_2FA,
                        amt_q=amt_q,
                        rail=RAIL_BROKER_2FA_MANUAL,
                        broker_id=clean_broker,
                        destination_bank_id=clean_dest,
                        conversion_spec=conv_spec,
                        explicit_idempotency_key=None,
                        retry_transfer_id=None,
                        owner_request_id=clean_req_id,
                        now_dt=now_dt,
                    )
                    if consume_same_db:
                        verifier.consume_on_connection(
                            conn,
                            recovery_token,
                            expected_scope="TREASURY_SWEEP",
                            target_ref=stored_sha,
                            require_exact_target=True,
                            owner_request_id=clean_req_id,
                            now=now_dt,
                        )
                    pending = self._pending_disbursement_unlocked(conn)
                    if amt_q > pending:
                        raise ContractError(
                            f"Requested sweep ${decimal_text(amt_q)} exceeds pending Bank Vault ${decimal_text(pending)}"
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
                            clean_broker,
                            clean_dest,
                            decimal_text(amt_q),
                            "PENDING_OWNER_BROKER_2FA",
                            None,
                            clean_req_id,
                            str(reason)[:240],
                            ts,
                            None,
                        ),
                    )
                    cur_i = conn.execute(
                        "UPDATE treasury_intents SET status = 'CONSUMED', consumed_at = ? WHERE intent_id = ? AND status = 'PREPARED'",
                        (ts, stored_iid),
                    )
                    if cur_i.rowcount != 1:
                        raise ContractError("TREASURY_INTENT_CONCURRENTLY_CONSUMED")
                    self._append_audit(
                        conn,
                        "BROKER_2FA_WITHDRAWAL_REQUESTED",
                        {
                            "transfer_id": transfer_id,
                            "intent_id": stored_iid,
                            "intent_sha256": stored_sha,
                            "broker_id": clean_broker,
                            "amount_usd": decimal_text(amt_q),
                        },
                        ts,
                    )
                    if consume_fallback:
                        verifier.verify_and_consume(
                            recovery_token,
                            expected_scope="TREASURY_SWEEP",
                            target_ref=stored_sha,
                            require_exact_target=True,
                            owner_request_id=clean_req_id,
                            now=now_dt,
                        )
                    conn.execute("COMMIT")
                    return transfer_id
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise

        with self._lock:
            if same_db:
                transfer_id = _reserve_2fa(consume_same_db=True, consume_fallback=False)
            elif callable(getattr(verifier, "atomic_consume", None)):
                with closing(self._connect_ro()) as ro_conn:
                    _, pre_sha, _, _ = self._lookup_and_verify_prepared_intent_unlocked(
                        ro_conn,
                        intent_id=intent_id,
                        intent_sha256=intent_sha256,
                        expected_action=INTENT_ACTION_BROKER_2FA,
                        amt_q=amt_q,
                        rail=RAIL_BROKER_2FA_MANUAL,
                        broker_id=clean_broker,
                        destination_bank_id=clean_dest,
                        conversion_spec=conv_spec,
                        explicit_idempotency_key=None,
                        retry_transfer_id=None,
                        owner_request_id=clean_req_id,
                        now_dt=now_dt,
                    )
                with verifier.atomic_consume(
                    recovery_token,
                    expected_scope="TREASURY_SWEEP",
                    target_ref=pre_sha,
                    require_exact_target=True,
                    owner_request_id=clean_req_id,
                    now=now_dt,
                ):
                    transfer_id = _reserve_2fa(consume_same_db=False, consume_fallback=False)
            else:
                transfer_id = _reserve_2fa(consume_same_db=False, consume_fallback=True)

        return {"transfer_id": transfer_id, "status": "PENDING_OWNER_BROKER_2FA", "vault": self.snapshot()}

    def confirm_broker_2fa_withdrawal(
        self,
        *,
        transfer_id: str,
        provider_tx_id: str,
        owner_request_id: str,
        verifier: Any,
        recovery_token: str,
        provider_verifier: Callable[[str, str], Mapping[str, Any]],
        epoch_guard: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        """Settle a broker 2FA withdrawal ONLY after transfer-bound recovery auth AND independent provider receipt proof (Finding [11])."""
        tid = str(transfer_id or "").strip()
        ptx = str(provider_tx_id or "").strip()
        if not tid or not ptx:
            raise ContractError("transfer_id and provider_tx_id are required")
        if verifier is None or not callable(getattr(verifier, "verify_and_consume", None)):
            raise ContractError("OWNER_RECOVERY_VERIFIER_REQUIRED: transfer-bound owner recovery authorization required")
        if not isinstance(recovery_token, str) or not recovery_token.strip():
            raise ContractError("OWNER_RECOVERY_TOKEN_REQUIRED: transfer-bound owner recovery token required")
        if provider_verifier is None or not callable(provider_verifier):
            raise OfframpSecurityError("PROVIDER_RECEIPT_VERIFIER_REQUIRED: independent provider settlement proof required")

        # 1. Inspect pending transfer metadata before external lookup
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM bank_transfers WHERE transfer_id = ? AND scope_id = ?",
                (tid, self.scope_id),
            ).fetchone()
        if row is None:
            raise ContractError(f"Unknown transfer_id {tid!r}")
        cur_status = str(row["status"])
        if cur_status not in ("PENDING_OWNER_BROKER_2FA", "BROKER_2FA_VERIFICATION_UNKNOWN"):
            raise ContractError(f"Transfer {tid!r} is already {cur_status}")
        expected_broker = str(row["broker_id"] or "")
        expected_dest = str(row["destination_bank_id"] or "")
        expected_amount = Decimal(str(row["amount_usd_text"])).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        # 2. Enforce fresh, single-use, transfer-bound recovery authorization (exact target_ref == transfer_id, no wildcard '*')
        verifier.verify_and_consume(
            recovery_token,
            expected_scope="TREASURY_SWEEP",
            target_ref=tid,
            require_exact_target=True,
            owner_request_id=owner_request_id,
            now=self._clock(),
        )

        # 3. Independently verify provider settlement status/receipt matching broker, tx, amount, destination, and SETTLED status
        if epoch_guard is not None:
            epoch_guard()
        ts = _iso(self._clock())
        try:
            receipt = provider_verifier(expected_broker, ptx)
        except Exception as exc:
            if type(exc).__name__ == "_SessionRevokedError":
                raise
            with self._lock, closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "UPDATE bank_transfers SET status = 'BROKER_2FA_VERIFICATION_UNKNOWN', error_detail = ? "
                    "WHERE transfer_id = ? AND scope_id = ? AND status IN ('PENDING_OWNER_BROKER_2FA', 'BROKER_2FA_VERIFICATION_UNKNOWN')",
                    (f"PROVIDER_LOOKUP_ERROR:{type(exc).__name__}", tid, self.scope_id),
                )
                self._append_audit(
                    conn,
                    "BROKER_2FA_VERIFICATION_UNKNOWN",
                    {"transfer_id": tid, "provider_tx_id": ptx, "error": type(exc).__name__},
                    ts,
                )
                conn.execute("COMMIT")
            raise OfframpTransportError(f"Provider withdrawal verification failed ({type(exc).__name__}); reserve kept locked") from None

        if not isinstance(receipt, Mapping):
            raise OfframpSecurityError("Provider withdrawal verifier returned malformed receipt")
        rec_status = str(receipt.get("status") or "").strip().upper()
        rec_broker = str(receipt.get("broker_id") or "").strip()
        rec_tx = str(receipt.get("provider_tx_id") or "").strip()
        rec_dest = str(receipt.get("destination_bank_id") or "").strip()
        raw_amt = receipt.get("amount_usd")
        try:
            rec_amt = Decimal(str(raw_amt)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) if raw_amt is not None else None
        except Exception:
            rec_amt = None

        if rec_status in ("PENDING", "UNKNOWN", "PROCESSING"):
            with self._lock, closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "UPDATE bank_transfers SET status = 'BROKER_2FA_VERIFICATION_UNKNOWN', error_detail = ? "
                    "WHERE transfer_id = ? AND scope_id = ? AND status IN ('PENDING_OWNER_BROKER_2FA', 'BROKER_2FA_VERIFICATION_UNKNOWN')",
                    (f"PROVIDER_STATUS_{rec_status}", tid, self.scope_id),
                )
                self._append_audit(
                    conn,
                    "BROKER_2FA_VERIFICATION_UNKNOWN",
                    {"transfer_id": tid, "provider_tx_id": ptx, "provider_status": rec_status},
                    ts,
                )
                conn.execute("COMMIT")
            raise OfframpSecurityError(f"Provider withdrawal status is {rec_status!r}, not SETTLED; reserve kept locked")

        if (
            rec_status != "SETTLED"
            or rec_broker != expected_broker
            or rec_tx != ptx
            or rec_amt != expected_amount
            or (expected_dest and rec_dest != expected_dest)
        ):
            raise OfframpSecurityError(
                "Provider withdrawal receipt mismatch (status/broker/tx/amount/destination); settlement rejected"
            )

        if epoch_guard is not None:
            epoch_guard()
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE bank_transfers SET status = 'SETTLED', provider_tx_id = ?, settled_at = ?, error_detail = NULL "
                "WHERE transfer_id = ? AND scope_id = ? AND status IN ('PENDING_OWNER_BROKER_2FA', 'BROKER_2FA_VERIFICATION_UNKNOWN')",
                (ptx, ts, tid, self.scope_id),
            )
            if cur.rowcount != 1:
                conn.execute("ROLLBACK")
                raise ContractError(f"Transfer {tid!r} state changed concurrently")
            self._append_audit(
                conn,
                "BROKER_2FA_WITHDRAWAL_SETTLED",
                {
                    "transfer_id": tid,
                    "broker_id": expected_broker,
                    "destination_bank_id": expected_dest,
                    "amount_usd": decimal_text(expected_amount),
                    "provider_tx_id": ptx,
                    "owner_request_id": owner_request_id,
                },
                ts,
            )
            conn.execute("COMMIT")
        return {"transfer_id": tid, "provider_tx_id": ptx, "status": "SETTLED", "vault": self.snapshot()}

    @staticmethod
    def _derive_conversion_client_ref(
        scope_id: str, transfer_id: str, withdrawal_idempotency_key: str
    ) -> str:
        """Deterministically derive a provider idempotency key for Phase 1 conversion distinct from withdrawal key."""
        digest = sha256(
            f"cas-forex-conversion/1|{scope_id}|{transfer_id}|{withdrawal_idempotency_key}".encode("utf-8")
        ).digest()
        return str(uuid.UUID(bytes=digest[:16], version=5))

    @staticmethod
    def _accepts_kwarg(fn: Callable[..., Any], kwarg_name: str) -> bool:
        try:
            sig = inspect.signature(fn)
        except (TypeError, ValueError):
            return False
        for param in sig.parameters.values():
            if param.kind == inspect.Parameter.VAR_KEYWORD:
                return True
            if param.name == kwarg_name and param.kind in (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            ):
                return True
        return False

    @staticmethod
    def _extract_conversion_tx_id(*, rail: str, response: Any) -> str:
        """Extract and validate a confirmed conversion transaction ID; return empty string on ambiguous/unconfirmed payloads."""
        if not isinstance(response, Mapping):
            return ""
        ambiguous_or_failed = {
            "FAILED",
            "ERROR",
            "CANCELLED",
            "CANCELED",
            "REJECTED",
            "EXPIRED",
            "PENDING",
            "OPEN",
            "UNKNOWN",
            "PROCESSING",
            "TRADE_STATUS_PENDING",
            "TRADE_STATUS_FAILED",
            "TRADE_STATUS_CANCELED",
            "TRADE_STATUS_EXPIRED",
            "UNSPECIFIED",
        }
        if rail == RAIL_COINBASE_ACH:
            trade_obj = response.get("trade") if isinstance(response.get("trade"), Mapping) else response
            for status_holder in (trade_obj, response):
                raw_st = status_holder.get("status")
                if raw_st is not None and str(raw_st).strip():
                    if str(raw_st).strip().upper() in ambiguous_or_failed:
                        return ""
            raw_tx = (
                trade_obj.get("id")
                or trade_obj.get("trade_id")
                or response.get("id")
                or response.get("trade_id")
                or response.get("txid")
            )
            return str(raw_tx).strip() if isinstance(raw_tx, str) and raw_tx.strip() else ""
        raw_st_k = response.get("status")
        if raw_st_k is not None and str(raw_st_k).strip():
            if str(raw_st_k).strip().upper() in ambiguous_or_failed:
                return ""
        raw_txid = response.get("txid")
        if isinstance(raw_txid, (list, tuple)):
            for item in raw_txid:
                if isinstance(item, str) and item.strip():
                    return item.strip()
            return ""
        raw_k = raw_txid or response.get("order_id") or response.get("id") or response.get("refid")
        return str(raw_k).strip() if isinstance(raw_k, str) and raw_k.strip() else ""

    @staticmethod
    def _parse_optional_decimal(val: Any) -> Decimal | None:
        if val is None or val == "":
            return None
        try:
            d = Decimal(str(val))
        except Exception:
            return None
        if not d.is_finite():
            return None
        return d

    @classmethod
    def _parse_conversion_history_evidence(
        cls,
        *,
        rail: str,
        evidence: Any,
        expected_client_ref: str,
        expected_spec: Mapping[str, Any],
    ) -> tuple[str, str | None, str]:
        """Fail-closed parser for exchange conversion history evidence.

        Returns ``(outcome, conversion_tx_id, detail)`` where outcome is one of
        ``"CONFIRMED"``, ``"NOT_EXECUTED"``, or ``"UNRESOLVED"``.
        """
        if not isinstance(evidence, Mapping):
            return ("UNRESOLVED", None, "non-mapping conversion history payload")

        record: Mapping[str, Any] = evidence
        inferred_tx_id = ""
        history_complete = bool(
            evidence.get("history_complete") is True
            or evidence.get("definitive_not_executed") is True
        )

        # Unwrap Coinbase {"trade": {...}} or {"trades": [...]}
        if isinstance(evidence.get("trade"), Mapping):
            record = evidence["trade"]
        elif isinstance(evidence.get("trades"), list):
            trades = evidence["trades"]
            matched: Mapping[str, Any] | None = None
            for item in trades:
                if not isinstance(item, Mapping):
                    continue
                item_ref = str(
                    item.get("client_reference_id")
                    or item.get("conversion_client_ref")
                    or ""
                ).strip()
                if expected_client_ref and item_ref == expected_client_ref:
                    matched = item
                    break
            if matched is not None:
                record = matched
            elif len(trades) == 0 and history_complete:
                return ("NOT_EXECUTED", None, "empty complete Coinbase conversion history")
            else:
                return ("UNRESOLVED", None, "Coinbase conversion history did not conclusively match client_reference_id")

        # Unwrap Kraken ClosedOrders {"closed": {txid: {...}}} or QueryOrders {txid: {...}}
        elif isinstance(evidence.get("closed"), Mapping):
            closed_map = evidence["closed"]
            matched_k: tuple[str, Mapping[str, Any]] | None = None
            for txk, order_v in closed_map.items():
                if not isinstance(order_v, Mapping):
                    continue
                cl_id = str(order_v.get("cl_ord_id") or order_v.get("client_reference_id") or "").strip()
                if expected_client_ref and cl_id:
                    if cl_id == expected_client_ref:
                        matched_k = (str(txk).strip(), order_v)
                        break
                elif len(closed_map) == 1 and not cl_id:
                    matched_k = (str(txk).strip(), order_v)
                    break
            if matched_k is not None:
                inferred_tx_id, record = matched_k
            elif len(closed_map) == 0 and history_complete:
                return ("NOT_EXECUTED", None, "empty complete Kraken ClosedOrders history")
            else:
                return ("UNRESOLVED", None, "Kraken ClosedOrders history did not conclusively match cl_ord_id")
        elif rail == RAIL_KRAKEN_ACH and "status" not in evidence:
            matched_q: tuple[str, Mapping[str, Any]] | None = None
            for txk, order_v in evidence.items():
                if not isinstance(order_v, Mapping) or "status" not in order_v:
                    continue
                cl_id = str(order_v.get("cl_ord_id") or order_v.get("client_reference_id") or "").strip()
                if expected_client_ref and cl_id and cl_id != expected_client_ref:
                    continue
                matched_q = (str(txk).strip(), order_v)
                break
            if matched_q is not None:
                inferred_tx_id, record = matched_q

        raw_status = record.get("status")
        if raw_status is None or not str(raw_status).strip():
            return ("UNRESOLVED", None, "missing conversion status in exchange history")
        norm_status = str(raw_status).strip().upper()

        rec_ref = str(
            record.get("client_reference_id")
            or record.get("conversion_client_ref")
            or record.get("cl_ord_id")
            or evidence.get("client_reference_id")
            or evidence.get("conversion_client_ref")
            or ""
        ).strip()
        if rec_ref and expected_client_ref and rec_ref != expected_client_ref:
            return ("UNRESOLVED", None, "exchange history client_reference_id mismatch")

        confirmed_statuses = {
            "CONFIRMED",
            "COMPLETED",
            "FILLED",
            "CLOSED",
            "SETTLED",
            "TRADE_STATUS_COMPLETED",
            "EXECUTED",
        }
        not_executed_statuses = {
            "NOT_EXECUTED",
            "NOT_FOUND_DEFINITIVE",
            "CANCELLED",
            "CANCELED",
            "REJECTED",
            "EXPIRED",
            "FAILED_NOT_EXECUTED",
            "TRADE_STATUS_CANCELED",
            "TRADE_STATUS_FAILED",
        }

        raw_vol_exec = record.get("vol_exec") if "vol_exec" in record else record.get("executed_volume")
        vol_exec_dec = cls._parse_optional_decimal(raw_vol_exec)
        if raw_vol_exec is not None and vol_exec_dec is None:
            return ("UNRESOLVED", None, "unparseable executed volume in conversion history")

        expected_amt_dec = cls._parse_optional_decimal(expected_spec.get("amount"))

        if norm_status in confirmed_statuses:
            raw_tx = (
                record.get("conversion_tx_id")
                or record.get("trade_id")
                or record.get("txid")
                or record.get("id")
                or record.get("order_id")
                or inferred_tx_id
            )
            if isinstance(raw_tx, (list, tuple)):
                tx_id = next((str(x).strip() for x in raw_tx if isinstance(x, str) and x.strip()), "")
            else:
                tx_id = str(raw_tx).strip() if isinstance(raw_tx, str) and raw_tx.strip() else ""
            if not tx_id:
                return ("UNRESOLVED", None, "confirmed conversion missing trustworthy tx_id")

            raw_amt = (
                record.get("amount")
                if "amount" in record
                else (record.get("volume") if "volume" in record else record.get("vol"))
            )
            if raw_amt is not None and expected_amt_dec is not None:
                rec_amt_dec = cls._parse_optional_decimal(raw_amt)
                if rec_amt_dec is None or rec_amt_dec != expected_amt_dec:
                    return ("UNRESOLVED", None, "conversion history amount mismatch")
            if vol_exec_dec is not None:
                if vol_exec_dec <= Decimal("0"):
                    return ("UNRESOLVED", None, "confirmed conversion reported non-positive executed volume")
                if expected_amt_dec is not None and vol_exec_dec != expected_amt_dec:
                    return ("UNRESOLVED", None, "conversion history executed volume mismatch")

            rec_from_cur = str(record.get("from_currency") or "").strip().upper()
            exp_from_cur = str(expected_spec.get("from_currency") or "").strip().upper()
            if rec_from_cur and exp_from_cur and rec_from_cur != exp_from_cur:
                return ("UNRESOLVED", None, "conversion history from_currency mismatch")

            descr = record.get("descr") if isinstance(record.get("descr"), Mapping) else {}
            rec_pair = str(record.get("pair") or descr.get("pair") or "").strip().upper()
            exp_pair = str(expected_spec.get("pair") or "").strip().upper()
            if rec_pair and exp_pair and rec_pair != exp_pair:
                return ("UNRESOLVED", None, "conversion history pair mismatch")

            return ("CONFIRMED", tx_id, f"exchange_status={norm_status}")

        if norm_status in not_executed_statuses or (norm_status == "NOT_FOUND" and history_complete):
            if vol_exec_dec is not None and vol_exec_dec > Decimal("0"):
                return ("UNRESOLVED", None, "partial conversion execution detected; manual reconciliation required")
            return ("NOT_EXECUTED", None, f"exchange_status={norm_status}")

        return ("UNRESOLVED", None, f"ambiguous_exchange_status={norm_status}")

    @classmethod
    def _parse_withdrawal_history_evidence(
        cls,
        *,
        evidence: Any,
        expected_client_ref: str,
        expected_amount: Decimal,
        expected_dest_bank: str,
    ) -> tuple[str, str | None, str]:
        """Fail-closed parser for exchange ACH withdrawal history evidence.

        Returns ``(outcome, provider_tx_id, detail)`` where outcome is one of
        ``"SETTLED"``, ``"ACH_SUBMITTED"``, ``"NOT_EXECUTED"``, or ``"UNRESOLVED"``.
        """
        if not isinstance(evidence, Mapping):
            return ("UNRESOLVED", None, "non-mapping withdrawal history payload")

        history_complete = bool(
            evidence.get("history_complete") is True
            or evidence.get("definitive_not_executed") is True
        )
        record: Mapping[str, Any] = evidence
        if isinstance(evidence.get("withdrawal"), Mapping):
            record = evidence["withdrawal"]
        elif isinstance(evidence.get("withdrawals"), list):
            wlist = evidence["withdrawals"]
            matched_w: Mapping[str, Any] | None = None
            for item in wlist:
                if not isinstance(item, Mapping):
                    continue
                iref = str(item.get("client_reference_id") or item.get("client_ref") or "").strip()
                if expected_client_ref and iref == expected_client_ref:
                    matched_w = item
                    break
            if matched_w is not None:
                record = matched_w
            elif len(wlist) == 0 and history_complete:
                return ("NOT_EXECUTED", None, "empty complete withdrawal history")
            else:
                return ("UNRESOLVED", None, "withdrawal history did not match client_reference_id")

        raw_status = record.get("status")
        if raw_status is None or not str(raw_status).strip():
            return ("UNRESOLVED", None, "missing withdrawal status in exchange history")
        norm_status = str(raw_status).strip().upper()

        rec_ref = str(
            record.get("client_reference_id")
            or record.get("client_ref")
            or evidence.get("client_reference_id")
            or ""
        ).strip()
        if rec_ref and expected_client_ref and rec_ref != expected_client_ref:
            return ("UNRESOLVED", None, "withdrawal history client_reference_id mismatch")

        rec_dest = str(
            record.get("destination_bank_id")
            or record.get("payment_method_id")
            or record.get("key")
            or ""
        ).strip()
        if rec_dest and expected_dest_bank and rec_dest != expected_dest_bank:
            return ("UNRESOLVED", None, "withdrawal history destination_bank_id mismatch")

        raw_amt = record.get("amount_usd") if "amount_usd" in record else record.get("amount")
        if raw_amt is not None:
            rec_amt = cls._parse_optional_decimal(raw_amt)
            if rec_amt is None or rec_amt.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) != expected_amount:
                return ("UNRESOLVED", None, "withdrawal history amount mismatch")

        settled_statuses = {"SETTLED", "COMPLETED", "COMPLETE", "SUCCESS", "SUCCESSFUL", "PAID"}
        submitted_statuses = {"ACH_SUBMITTED", "SUBMITTED", "PROCESSING", "PENDING_SETTLEMENT", "IN_PROGRESS", "INITIAL"}
        not_executed_statuses = {
            "NOT_EXECUTED",
            "NOT_FOUND_DEFINITIVE",
            "CANCELLED",
            "CANCELED",
            "REJECTED",
            "FAILED",
            "FAILED_NOT_EXECUTED",
        }

        if norm_status in settled_statuses or norm_status in submitted_statuses:
            raw_tx = (
                record.get("provider_tx_id")
                or record.get("refid")
                or record.get("payout_id")
                or record.get("id")
            )
            tx_id = str(raw_tx).strip() if isinstance(raw_tx, str) and raw_tx.strip() else ""
            if not tx_id:
                return ("UNRESOLVED", None, "withdrawal history missing trustworthy provider_tx_id")
            return (
                "SETTLED" if norm_status in settled_statuses else "ACH_SUBMITTED",
                tx_id,
                f"exchange_status={norm_status}",
            )

        if norm_status in not_executed_statuses or (norm_status == "NOT_FOUND" and history_complete):
            return ("NOT_EXECUTED", None, f"exchange_status={norm_status}")

        return ("UNRESOLVED", None, f"ambiguous_withdrawal_status={norm_status}")

    def reconcile_conversion_outcome(
        self,
        *,
        transfer_id: str,
        coinbase_client: CoinbaseOfframpClient | None = None,
        kraken_client: KrakenOfframpClient | None = None,
        exchange_history_checker: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        owner_request_id: str = "reconcile-conversion",
    ) -> dict[str, Any]:
        """Reconcile a frozen CONVERSION_OUTCOME_UNKNOWN / CONVERSION_PENDING transfer against exchange history (Finding [4])."""
        tid = str(transfer_id or "").strip()
        if not tid:
            raise ContractError("transfer_id is required")
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM bank_transfers WHERE transfer_id = ? AND scope_id = ?",
                (tid, self.scope_id),
            ).fetchone()
        if row is None:
            raise ContractError(f"Unknown transfer_id {tid!r}")

        rail = str(row["rail"])
        cur_status = str(row["status"])
        conv_status = str(row["conversion_status"] or CONVERSION_STATUS_NOT_REQUIRED)
        conv_ref = str(row["conversion_client_ref"] or "")
        conv_tx = str(row["conversion_tx_id"] or "")
        wd_status = str(row["withdrawal_status"] or WITHDRAWAL_STATUS_NOT_STARTED)
        try:
            conv_spec: dict[str, Any] = json.loads(str(row["conversion_spec_json"])) if row["conversion_spec_json"] else {}
        except Exception:
            conv_spec = {}

        if conv_status == CONVERSION_STATUS_NOT_REQUIRED:
            return {
                "transfer_id": tid,
                "reconciliation_outcome": "NOT_REQUIRED",
                "conversion_status": conv_status,
                "conversion_client_ref": conv_ref or None,
                "conversion_tx_id": None,
                "status": cur_status,
                "vault": self.snapshot(),
            }
        if conv_status == CONVERSION_STATUS_CONFIRMED:
            return {
                "transfer_id": tid,
                "reconciliation_outcome": "ALREADY_CONFIRMED",
                "conversion_status": conv_status,
                "conversion_client_ref": conv_ref or None,
                "conversion_tx_id": conv_tx or None,
                "status": cur_status,
                "vault": self.snapshot(),
            }
        if conv_status not in (CONVERSION_STATUS_OUTCOME_UNKNOWN, CONVERSION_STATUS_PENDING):
            raise ContractError(
                f"Transfer {tid!r} conversion_status {conv_status!r} does not require conversion reconciliation"
            )

        query_ctx: dict[str, Any] = {
            "transfer_id": tid,
            "scope_id": self.scope_id,
            "rail": rail,
            "idempotency_key": str(row["idempotency_key"] or ""),
            "conversion_client_ref": conv_ref,
            "conversion_tx_id": conv_tx or None,
            "conversion_spec": conv_spec,
            "amount_usd": str(row["amount_usd_text"]),
            "created_at": str(row["created_at"]),
        }
        ts = _iso(self._clock())
        try:
            if exchange_history_checker is not None:
                if not callable(exchange_history_checker):
                    raise OfframpSecurityError("exchange_history_checker must be callable")
                evidence = exchange_history_checker(query_ctx)
            elif rail == RAIL_COINBASE_ACH:
                if coinbase_client is None or not callable(getattr(coinbase_client, "get_conversion_status", None)):
                    raise OfframpSecurityError(
                        "EXCHANGE_HISTORY_REQUIRED: provide coinbase_client or exchange_history_checker"
                    )
                evidence = coinbase_client.get_conversion_status(
                    client_reference_id=conv_ref or None,
                    conversion_tx_id=conv_tx or None,
                )
            elif rail == RAIL_KRAKEN_ACH:
                if kraken_client is None or not callable(getattr(kraken_client, "get_conversion_status", None)):
                    raise OfframpSecurityError(
                        "EXCHANGE_HISTORY_REQUIRED: provide kraken_client or exchange_history_checker"
                    )
                evidence = kraken_client.get_conversion_status(
                    client_reference_id=conv_ref or None,
                    conversion_tx_id=conv_tx or None,
                )
            else:
                raise OfframpSecurityError(f"Unsupported rail {rail!r} for conversion reconciliation")
        except OfframpSecurityError:
            raise
        except Exception as exc:
            with self._lock, closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "UPDATE bank_transfers SET status = 'OUTCOME_UNKNOWN', conversion_status = ?, "
                    "conversion_error_detail = ?, error_detail = ? "
                    "WHERE transfer_id = ? AND scope_id = ? AND conversion_status IN (?, ?)",
                    (
                        CONVERSION_STATUS_OUTCOME_UNKNOWN,
                        f"RECONCILE_LOOKUP_ERROR:{type(exc).__name__}",
                        f"RECONCILE_LOOKUP_ERROR:{type(exc).__name__}",
                        tid,
                        self.scope_id,
                        CONVERSION_STATUS_OUTCOME_UNKNOWN,
                        CONVERSION_STATUS_PENDING,
                    ),
                )
                self._append_audit(
                    conn,
                    "ACH_CONVERSION_RECONCILIATION_ERROR",
                    {
                        "transfer_id": tid,
                        "conversion_client_ref": conv_ref,
                        "owner_request_id": owner_request_id,
                        "error": type(exc).__name__,
                    },
                    ts,
                )
                conn.execute("COMMIT")
                conn.commit()
            raise OfframpTransportError(
                f"Conversion history lookup failed ({type(exc).__name__}); transfer remains frozen in CONVERSION_OUTCOME_UNKNOWN"
            ) from None

        outcome, rec_tx_id, detail = self._parse_conversion_history_evidence(
            rail=rail,
            evidence=evidence,
            expected_client_ref=conv_ref,
            expected_spec=conv_spec,
        )

        if outcome == "CONFIRMED" and rec_tx_id:
            next_status = "OUTCOME_UNKNOWN" if wd_status == WITHDRAWAL_STATUS_OUTCOME_UNKNOWN else "RESERVED_PENDING_DISPATCH"
            with self._lock, closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "UPDATE bank_transfers "
                    "SET conversion_status = ?, conversion_tx_id = ?, conversion_error_detail = NULL, "
                    "status = ?, error_detail = CASE WHEN withdrawal_status = ? THEN error_detail ELSE NULL END "
                    "WHERE transfer_id = ? AND scope_id = ? AND conversion_status IN (?, ?)",
                    (
                        CONVERSION_STATUS_CONFIRMED,
                        rec_tx_id,
                        next_status,
                        WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
                        tid,
                        self.scope_id,
                        CONVERSION_STATUS_OUTCOME_UNKNOWN,
                        CONVERSION_STATUS_PENDING,
                    ),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    raise ContractError(f"Transfer {tid!r} conversion state changed concurrently")
                self._append_audit(
                    conn,
                    "ACH_CONVERSION_RECONCILED_CONFIRMED",
                    {
                        "transfer_id": tid,
                        "conversion_client_ref": conv_ref,
                        "conversion_tx_id": rec_tx_id,
                        "detail": detail,
                        "owner_request_id": owner_request_id,
                    },
                    ts,
                )
                conn.execute("COMMIT")
                conn.commit()
            return {
                "transfer_id": tid,
                "reconciliation_outcome": "CONFIRMED",
                "conversion_status": CONVERSION_STATUS_CONFIRMED,
                "conversion_client_ref": conv_ref or None,
                "conversion_tx_id": rec_tx_id,
                "status": next_status,
                "vault": self.snapshot(),
            }

        if outcome == "NOT_EXECUTED":
            with self._lock, closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "UPDATE bank_transfers "
                    "SET conversion_status = ?, conversion_tx_id = NULL, conversion_error_detail = ?, "
                    "status = 'RESERVED_PENDING_DISPATCH', error_detail = NULL "
                    "WHERE transfer_id = ? AND scope_id = ? AND conversion_status IN (?, ?)",
                    (
                        CONVERSION_STATUS_NOT_STARTED,
                        f"RECONCILED_NOT_EXECUTED:{detail[:140]}",
                        tid,
                        self.scope_id,
                        CONVERSION_STATUS_OUTCOME_UNKNOWN,
                        CONVERSION_STATUS_PENDING,
                    ),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    raise ContractError(f"Transfer {tid!r} conversion state changed concurrently")
                self._append_audit(
                    conn,
                    "ACH_CONVERSION_RECONCILED_NOT_EXECUTED",
                    {
                        "transfer_id": tid,
                        "conversion_client_ref": conv_ref,
                        "detail": detail,
                        "owner_request_id": owner_request_id,
                    },
                    ts,
                )
                conn.execute("COMMIT")
                conn.commit()
            return {
                "transfer_id": tid,
                "reconciliation_outcome": "NOT_EXECUTED",
                "conversion_status": CONVERSION_STATUS_NOT_STARTED,
                "conversion_client_ref": conv_ref or None,
                "conversion_tx_id": None,
                "status": "RESERVED_PENDING_DISPATCH",
                "vault": self.snapshot(),
            }

        # Fail closed on ambiguous / pending / mismatched exchange history evidence
        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE bank_transfers "
                "SET status = 'OUTCOME_UNKNOWN', conversion_status = ?, "
                "conversion_error_detail = ?, error_detail = ? "
                "WHERE transfer_id = ? AND scope_id = ? AND conversion_status IN (?, ?)",
                (
                    CONVERSION_STATUS_OUTCOME_UNKNOWN,
                    f"RECONCILE_UNRESOLVED:{detail[:140]}",
                    f"RECONCILE_UNRESOLVED:{detail[:140]}",
                    tid,
                    self.scope_id,
                    CONVERSION_STATUS_OUTCOME_UNKNOWN,
                    CONVERSION_STATUS_PENDING,
                ),
            )
            self._append_audit(
                conn,
                "ACH_CONVERSION_RECONCILIATION_UNRESOLVED",
                {
                    "transfer_id": tid,
                    "conversion_client_ref": conv_ref,
                    "detail": detail,
                    "owner_request_id": owner_request_id,
                },
                ts,
            )
            conn.execute("COMMIT")
            conn.commit()
        raise OfframpSecurityError(
            f"Conversion history for {tid!r} remains unresolved ({detail}); transfer stays frozen in CONVERSION_OUTCOME_UNKNOWN"
        )

    def reconcile_withdrawal_outcome(
        self,
        *,
        transfer_id: str,
        coinbase_client: CoinbaseOfframpClient | None = None,
        kraken_client: KrakenOfframpClient | None = None,
        exchange_history_checker: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
        owner_request_id: str = "reconcile-withdrawal",
    ) -> dict[str, Any]:
        """Reconcile a WITHDRAWAL_OUTCOME_UNKNOWN / WITHDRAWAL_PENDING transfer against exchange withdrawal history."""
        tid = str(transfer_id or "").strip()
        if not tid:
            raise ContractError("transfer_id is required")
        with self._lock, closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT * FROM bank_transfers WHERE transfer_id = ? AND scope_id = ?",
                (tid, self.scope_id),
            ).fetchone()
        if row is None:
            raise ContractError(f"Unknown transfer_id {tid!r}")

        rail = str(row["rail"])
        cur_status = str(row["status"])
        conv_status = str(row["conversion_status"] or CONVERSION_STATUS_NOT_REQUIRED)
        wd_status = str(row["withdrawal_status"] or WITHDRAWAL_STATUS_NOT_STARTED)
        idem = str(row["idempotency_key"] or "")
        prov_tx = str(row["provider_tx_id"] or "")
        expected_dest = str(row["destination_bank_id"] or "")
        expected_amount = Decimal(str(row["amount_usd_text"])).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        if conv_status in (CONVERSION_STATUS_OUTCOME_UNKNOWN, CONVERSION_STATUS_PENDING):
            raise OfframpSecurityError(
                f"CONVERSION_OUTCOME_UNKNOWN_REQUIRES_RECONCILIATION: reconcile conversion for {tid!r} before withdrawal"
            )
        if wd_status == WITHDRAWAL_STATUS_SUBMITTED or cur_status in ("ACH_SUBMITTED", "SETTLED"):
            return {
                "transfer_id": tid,
                "reconciliation_outcome": "ALREADY_SUBMITTED",
                "withdrawal_status": WITHDRAWAL_STATUS_SUBMITTED,
                "provider_tx_id": prov_tx or None,
                "status": cur_status,
                "vault": self.snapshot(),
            }
        if wd_status not in (WITHDRAWAL_STATUS_OUTCOME_UNKNOWN, WITHDRAWAL_STATUS_PENDING):
            raise ContractError(
                f"Transfer {tid!r} withdrawal_status {wd_status!r} does not require withdrawal reconciliation"
            )

        query_ctx: dict[str, Any] = {
            "transfer_id": tid,
            "scope_id": self.scope_id,
            "rail": rail,
            "idempotency_key": idem,
            "provider_tx_id": prov_tx or None,
            "destination_bank_id": expected_dest,
            "amount_usd": decimal_text(expected_amount),
            "created_at": str(row["created_at"]),
        }
        ts = _iso(self._clock())
        try:
            if exchange_history_checker is not None:
                if not callable(exchange_history_checker):
                    raise OfframpSecurityError("exchange_history_checker must be callable")
                evidence = exchange_history_checker(query_ctx)
            elif rail == RAIL_COINBASE_ACH:
                if coinbase_client is None or not callable(getattr(coinbase_client, "get_withdrawal_status", None)):
                    raise OfframpSecurityError(
                        "EXCHANGE_HISTORY_REQUIRED: provide coinbase_client or exchange_history_checker"
                    )
                evidence = coinbase_client.get_withdrawal_status(
                    client_reference_id=idem or None,
                    provider_tx_id=prov_tx or None,
                )
            elif rail == RAIL_KRAKEN_ACH:
                if kraken_client is None or not callable(getattr(kraken_client, "get_withdrawal_status", None)):
                    raise OfframpSecurityError(
                        "EXCHANGE_HISTORY_REQUIRED: provide kraken_client or exchange_history_checker"
                    )
                evidence = kraken_client.get_withdrawal_status(
                    client_reference_id=idem or None,
                    provider_tx_id=prov_tx or None,
                )
            else:
                raise OfframpSecurityError(f"Unsupported rail {rail!r} for withdrawal reconciliation")
        except OfframpSecurityError:
            raise
        except Exception as exc:
            with self._lock, closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "UPDATE bank_transfers SET status = 'OUTCOME_UNKNOWN', withdrawal_status = ?, "
                    "withdrawal_error_detail = ?, error_detail = ? "
                    "WHERE transfer_id = ? AND scope_id = ? AND withdrawal_status IN (?, ?)",
                    (
                        WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
                        f"RECONCILE_LOOKUP_ERROR:{type(exc).__name__}",
                        f"RECONCILE_LOOKUP_ERROR:{type(exc).__name__}",
                        tid,
                        self.scope_id,
                        WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
                        WITHDRAWAL_STATUS_PENDING,
                    ),
                )
                self._append_audit(
                    conn,
                    "ACH_WITHDRAWAL_RECONCILIATION_ERROR",
                    {
                        "transfer_id": tid,
                        "idempotency_key": idem,
                        "owner_request_id": owner_request_id,
                        "error": type(exc).__name__,
                    },
                    ts,
                )
                conn.execute("COMMIT")
                conn.commit()
            raise OfframpTransportError(
                f"Withdrawal history lookup failed ({type(exc).__name__}); transfer remains in WITHDRAWAL_OUTCOME_UNKNOWN"
            ) from None

        outcome, rec_tx_id, detail = self._parse_withdrawal_history_evidence(
            evidence=evidence,
            expected_client_ref=idem,
            expected_amount=expected_amount,
            expected_dest_bank=expected_dest,
        )

        if outcome in ("SETTLED", "ACH_SUBMITTED") and rec_tx_id:
            with self._lock, closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "UPDATE bank_transfers "
                    "SET status = ?, withdrawal_status = ?, provider_tx_id = ?, settled_at = ?, "
                    "withdrawal_error_detail = NULL, error_detail = NULL "
                    "WHERE transfer_id = ? AND scope_id = ? AND withdrawal_status IN (?, ?)",
                    (
                        outcome,
                        WITHDRAWAL_STATUS_SUBMITTED,
                        rec_tx_id,
                        ts,
                        tid,
                        self.scope_id,
                        WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
                        WITHDRAWAL_STATUS_PENDING,
                    ),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    raise ContractError(f"Transfer {tid!r} withdrawal state changed concurrently")
                self._append_audit(
                    conn,
                    "ACH_WITHDRAWAL_RECONCILED_SUBMITTED",
                    {
                        "transfer_id": tid,
                        "idempotency_key": idem,
                        "provider_tx_id": rec_tx_id,
                        "status": outcome,
                        "detail": detail,
                        "owner_request_id": owner_request_id,
                    },
                    ts,
                )
                conn.execute("COMMIT")
                conn.commit()
            return {
                "transfer_id": tid,
                "reconciliation_outcome": outcome,
                "withdrawal_status": WITHDRAWAL_STATUS_SUBMITTED,
                "provider_tx_id": rec_tx_id,
                "status": outcome,
                "vault": self.snapshot(),
            }

        if outcome == "NOT_EXECUTED":
            with self._lock, closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "UPDATE bank_transfers "
                    "SET status = 'RESERVED_PENDING_DISPATCH', withdrawal_status = ?, "
                    "withdrawal_error_detail = ?, error_detail = NULL "
                    "WHERE transfer_id = ? AND scope_id = ? AND withdrawal_status IN (?, ?)",
                    (
                        WITHDRAWAL_STATUS_NOT_STARTED,
                        f"RECONCILED_NOT_EXECUTED:{detail[:140]}",
                        tid,
                        self.scope_id,
                        WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
                        WITHDRAWAL_STATUS_PENDING,
                    ),
                )
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK")
                    raise ContractError(f"Transfer {tid!r} withdrawal state changed concurrently")
                self._append_audit(
                    conn,
                    "ACH_WITHDRAWAL_RECONCILED_NOT_EXECUTED",
                    {
                        "transfer_id": tid,
                        "idempotency_key": idem,
                        "detail": detail,
                        "owner_request_id": owner_request_id,
                    },
                    ts,
                )
                conn.execute("COMMIT")
                conn.commit()
            return {
                "transfer_id": tid,
                "reconciliation_outcome": "NOT_EXECUTED",
                "withdrawal_status": WITHDRAWAL_STATUS_NOT_STARTED,
                "provider_tx_id": None,
                "status": "RESERVED_PENDING_DISPATCH",
                "vault": self.snapshot(),
            }

        with self._lock, closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE bank_transfers "
                "SET status = 'OUTCOME_UNKNOWN', withdrawal_status = ?, "
                "withdrawal_error_detail = ?, error_detail = ? "
                "WHERE transfer_id = ? AND scope_id = ? AND withdrawal_status IN (?, ?)",
                (
                    WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
                    f"RECONCILE_UNRESOLVED:{detail[:140]}",
                    f"RECONCILE_UNRESOLVED:{detail[:140]}",
                    tid,
                    self.scope_id,
                    WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
                    WITHDRAWAL_STATUS_PENDING,
                ),
            )
            self._append_audit(
                conn,
                "ACH_WITHDRAWAL_RECONCILIATION_UNRESOLVED",
                {
                    "transfer_id": tid,
                    "idempotency_key": idem,
                    "detail": detail,
                    "owner_request_id": owner_request_id,
                },
                ts,
            )
            conn.execute("COMMIT")
            conn.commit()
        raise OfframpSecurityError(
            f"Withdrawal history for {tid!r} remains unresolved ({detail}); transfer stays in WITHDRAWAL_OUTCOME_UNKNOWN"
        )

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
        idempotency_key: str | None = None,
        retry_transfer_id: str | None = None,
        intent_id: str | None = None,
        intent_sha256: str | None = None,
        epoch_guard: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        """Atomically verify prepared intent, reserve funds, and run separately journaled conversion + ACH withdrawal phases (Findings [4], [9], [12], [13])."""
        amt_q = decimal_value(amount_usd, "amount_usd", positive=True).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        if amt_q <= Decimal("0"):
            raise ContractError("amount_usd must be >= $0.01")
        clean_req_id = identifier(owner_request_id, "owner_request_id")
        if not reason:
            raise ContractError("owner_request_id and reason are required")
        if verifier is None or not callable(getattr(verifier, "verify_and_consume", None)):
            raise ContractError("OWNER_RECOVERY_VERIFIER_REQUIRED")
        if rail not in (RAIL_COINBASE_ACH, RAIL_KRAKEN_ACH):
            raise OfframpSecurityError(f"Unsupported automated ACH rail {rail!r}")
        if rail == RAIL_COINBASE_ACH:
            if coinbase_client is None:
                raise OfframpSecurityError("CoinbaseOfframpClient is not configured")
            dest_bank = coinbase_client.linked_bank_account_id
        else:
            if kraken_client is None:
                raise OfframpSecurityError("KrakenOfframpClient is not configured")
            dest_bank = kraken_client.linked_bank_account_id

        conv_spec = self._build_conversion_spec(
            rail=rail,
            convert_from_currency=convert_from_currency,
            convert_amount=convert_amount,
            coinbase_source_account_uuid=coinbase_source_account_uuid,
            coinbase_usd_account_uuid=coinbase_usd_account_uuid,
            kraken_pair=kraken_pair,
        )
        conv_enabled = bool(conv_spec.get("enabled"))
        conv_spec_json = canonical_bytes(conv_spec).decode("utf-8")
        retry_ref = str(retry_transfer_id).strip() if retry_transfer_id is not None and str(retry_transfer_id).strip() else None
        now_dt = utc_time(self._clock(), "clock")
        ts_reserve = _iso(now_dt)

        ver_db = getattr(verifier, "db_path", None)
        same_db = (
            isinstance(ver_db, Path)
            and callable(getattr(verifier, "consume_on_connection", None))
            and ver_db.resolve() == self.db_path.resolve()
        )
        if same_db and callable(getattr(verifier, "ensure_initialized", None)):
            verifier.ensure_initialized()

        def _reserve_ach(
            *, consume_same_db: bool, consume_fallback: bool
        ) -> tuple[str, str, str, str | None, str | None, bool, str]:
            with closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    stored_iid, stored_sha, planned_tid, resolved_idem = self._lookup_and_verify_prepared_intent_unlocked(
                        conn,
                        intent_id=intent_id,
                        intent_sha256=intent_sha256,
                        expected_action=INTENT_ACTION_OFFRAMP_ACH,
                        amt_q=amt_q,
                        rail=rail,
                        broker_id=None,
                        destination_bank_id=dest_bank,
                        conversion_spec=conv_spec,
                        explicit_idempotency_key=idempotency_key,
                        retry_transfer_id=retry_ref,
                        owner_request_id=clean_req_id,
                        now_dt=now_dt,
                    )
                    if retry_ref is not None:
                        existing = conn.execute(
                            "SELECT * FROM bank_transfers WHERE transfer_id = ? AND scope_id = ?",
                            (retry_ref, self.scope_id),
                        ).fetchone()
                        if existing is None:
                            raise ContractError(f"Unknown retry_transfer_id {retry_transfer_id!r}")
                        existing_status = str(existing["status"])
                        existing_conv_status = str(
                            existing["conversion_status"] or CONVERSION_STATUS_NOT_REQUIRED
                        )
                        existing_conv_required = int(existing["conversion_required"] or 0)
                        existing_conv_ref = (
                            str(existing["conversion_client_ref"])
                            if existing["conversion_client_ref"]
                            else None
                        )
                        existing_conv_tx = (
                            str(existing["conversion_tx_id"])
                            if existing["conversion_tx_id"]
                            else None
                        )
                        existing_conv_spec_json = (
                            str(existing["conversion_spec_json"])
                            if existing["conversion_spec_json"]
                            else None
                        )
                        existing_wd_status = str(
                            existing["withdrawal_status"] or WITHDRAWAL_STATUS_NOT_STARTED
                        )
                        if existing_conv_status in (
                            CONVERSION_STATUS_OUTCOME_UNKNOWN,
                            CONVERSION_STATUS_PENDING,
                        ):
                            raise OfframpSecurityError(
                                f"CONVERSION_OUTCOME_UNKNOWN_REQUIRES_RECONCILIATION: transfer {retry_ref!r} "
                                f"is frozen in {existing_conv_status}; reconcile exchange history via "
                                f"reconcile_conversion_outcome() before retrying conversion or withdrawal"
                            )
                        if existing_status not in ("OUTCOME_UNKNOWN", "RESERVED_PENDING_DISPATCH"):
                            raise ContractError(
                                f"Transfer {retry_transfer_id!r} cannot be retried from status {existing['status']}"
                            )
                        if existing_wd_status == WITHDRAWAL_STATUS_SUBMITTED:
                            raise ContractError(
                                f"Transfer {retry_transfer_id!r} withdrawal is already submitted"
                            )
                        if str(existing["rail"]) != rail or Decimal(str(existing["amount_usd_text"])) != amt_q:
                            raise ContractError("Retry transfer rail/amount does not match persisted intent")
                        if str(existing["destination_bank_id"]) != dest_bank:
                            raise OfframpSecurityError("Retry transfer destination_bank_id does not match persisted intent")
                        if existing_conv_required == 0 and conv_enabled:
                            raise OfframpSecurityError(
                                "Retry transfer cannot add conversion that was not in the original transfer"
                            )
                        if (
                            existing_conv_required == 1
                            and conv_enabled
                            and existing_conv_spec_json
                            and existing_conv_spec_json != conv_spec_json
                        ):
                            raise OfframpSecurityError(
                                "Retry transfer conversion parameters do not match persisted intent"
                            )
                        if (
                            existing_conv_required == 1
                            and existing_conv_status == CONVERSION_STATUS_NOT_STARTED
                            and not conv_enabled
                        ):
                            raise OfframpSecurityError(
                                "Retry transfer requires original conversion parameters while conversion is not confirmed"
                            )
                        transfer_id = str(existing["transfer_id"])
                        if transfer_id in self._in_flight_transfers:
                            raise ContractError(f"Transfer {transfer_id!r} is already in flight")
                        eff_idem = str(existing["idempotency_key"] or resolved_idem or f"ach-{transfer_id}")
                        conv_required_flag = bool(existing_conv_required == 1 or conv_enabled)
                        conv_ref_val = (
                            existing_conv_ref
                            or (
                                self._derive_conversion_client_ref(self.scope_id, transfer_id, eff_idem)
                                if conv_required_flag
                                else None
                            )
                        )
                        if consume_same_db:
                            verifier.consume_on_connection(
                                conn,
                                recovery_token,
                                expected_scope="TREASURY_SWEEP",
                                target_ref=stored_sha,
                                require_exact_target=True,
                                owner_request_id=clean_req_id,
                                now=now_dt,
                            )
                        conn.execute(
                            "UPDATE bank_transfers SET status = 'RESERVED_PENDING_DISPATCH', conversion_client_ref = COALESCE(conversion_client_ref, ?) "
                            "WHERE transfer_id = ? AND scope_id = ?",
                            (conv_ref_val, transfer_id, self.scope_id),
                        )
                        self._append_audit(
                            conn,
                            "ACH_OFFRAMP_RETRY_RESERVED",
                            {
                                "transfer_id": transfer_id,
                                "intent_id": stored_iid,
                                "intent_sha256": stored_sha,
                                "idempotency_key": eff_idem,
                                "conversion_status": existing_conv_status,
                                "conversion_client_ref": conv_ref_val,
                                "withdrawal_status": existing_wd_status,
                                "rail": rail,
                                "destination_bank_id": dest_bank,
                                "amount_usd": decimal_text(amt_q),
                            },
                            ts_reserve,
                        )
                        res_conv_status = existing_conv_status
                        res_conv_ref = conv_ref_val
                        res_conv_tx = existing_conv_tx
                        res_conv_req = conv_required_flag
                        res_prev_wd = existing_wd_status
                    else:
                        pending = self._pending_disbursement_unlocked(conn)
                        if amt_q > pending:
                            raise ContractError(
                                f"Requested ACH payout ${decimal_text(amt_q)} exceeds pending Bank Vault ${decimal_text(pending)}"
                            )
                        transfer_id = planned_tid
                        if transfer_id in self._in_flight_transfers:
                            raise ContractError(f"Transfer {transfer_id!r} is already in flight")
                        eff_idem = resolved_idem or (
                            "ach-" + sha256(
                                f"{self.scope_id}|{rail}|{clean_req_id}|{decimal_text(amt_q)}|{transfer_id}".encode("utf-8")
                            ).hexdigest()[:24]
                        )
                        dup = conn.execute(
                            "SELECT transfer_id, status FROM bank_transfers WHERE idempotency_key = ?",
                            (eff_idem,),
                        ).fetchone()
                        if dup is not None:
                            raise OfframpSecurityError(
                                f"Duplicate ACH idempotency_key {eff_idem!r} already bound to {dup['transfer_id']} ({dup['status']})"
                            )
                        if consume_same_db:
                            verifier.consume_on_connection(
                                conn,
                                recovery_token,
                                expected_scope="TREASURY_SWEEP",
                                target_ref=stored_sha,
                                require_exact_target=True,
                                owner_request_id=clean_req_id,
                                now=now_dt,
                            )
                        init_conv_status = (
                            CONVERSION_STATUS_NOT_STARTED
                            if conv_enabled
                            else CONVERSION_STATUS_NOT_REQUIRED
                        )
                        init_conv_ref = (
                            self._derive_conversion_client_ref(self.scope_id, transfer_id, eff_idem)
                            if conv_enabled
                            else None
                        )
                        conn.execute(
                            """
                            INSERT INTO bank_transfers(
                                transfer_id, scope_id, rail, broker_id, destination_bank_id, amount_usd_text,
                                status, provider_tx_id, owner_request_id, reason, created_at, settled_at,
                                idempotency_key, error_detail,
                                conversion_required, conversion_status, conversion_client_ref,
                                conversion_tx_id, conversion_spec_json, conversion_error_detail,
                                withdrawal_status, withdrawal_error_detail
                            ) VALUES (
                                ?, ?, ?, ?, ?, ?, 'RESERVED_PENDING_DISPATCH', NULL, ?, ?, ?, NULL, ?, NULL,
                                ?, ?, ?, NULL, ?, NULL, ?, NULL
                            )
                            """,
                            (
                                transfer_id,
                                self.scope_id,
                                rail,
                                None,
                                dest_bank,
                                decimal_text(amt_q),
                                clean_req_id,
                                str(reason)[:240],
                                ts_reserve,
                                eff_idem,
                                1 if conv_enabled else 0,
                                init_conv_status,
                                init_conv_ref,
                                conv_spec_json,
                                WITHDRAWAL_STATUS_NOT_STARTED,
                            ),
                        )
                        self._append_audit(
                            conn,
                            "ACH_OFFRAMP_RESERVED",
                            {
                                "transfer_id": transfer_id,
                                "intent_id": stored_iid,
                                "intent_sha256": stored_sha,
                                "idempotency_key": eff_idem,
                                "conversion_required": conv_enabled,
                                "conversion_status": init_conv_status,
                                "conversion_client_ref": init_conv_ref,
                                "withdrawal_status": WITHDRAWAL_STATUS_NOT_STARTED,
                                "rail": rail,
                                "destination_bank_id": dest_bank,
                                "amount_usd": decimal_text(amt_q),
                            },
                            ts_reserve,
                        )
                        res_conv_status = init_conv_status
                        res_conv_ref = init_conv_ref
                        res_conv_tx = None
                        res_conv_req = conv_enabled
                        res_prev_wd = WITHDRAWAL_STATUS_NOT_STARTED
                    cur_i = conn.execute(
                        "UPDATE treasury_intents SET status = 'CONSUMED', consumed_at = ? WHERE intent_id = ? AND status = 'PREPARED'",
                        (ts_reserve, stored_iid),
                    )
                    if cur_i.rowcount != 1:
                        raise ContractError("TREASURY_INTENT_CONCURRENTLY_CONSUMED")
                    if consume_fallback:
                        verifier.verify_and_consume(
                            recovery_token,
                            expected_scope="TREASURY_SWEEP",
                            target_ref=stored_sha,
                            require_exact_target=True,
                            owner_request_id=clean_req_id,
                            now=now_dt,
                        )
                    conn.execute("COMMIT")
                    conn.commit()
                    self._in_flight_transfers.add(transfer_id)
                    return (
                        transfer_id,
                        eff_idem,
                        res_conv_status,
                        res_conv_ref,
                        res_conv_tx,
                        res_conv_req,
                        res_prev_wd,
                    )
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise

        with self._lock:
            if same_db:
                (
                    transfer_id,
                    eff_idem,
                    conv_status,
                    conv_client_ref,
                    conv_tx_id,
                    conv_required,
                    prev_wd_status,
                ) = _reserve_ach(consume_same_db=True, consume_fallback=False)
            elif callable(getattr(verifier, "atomic_consume", None)):
                with closing(self._connect_ro()) as ro_conn:
                    _, pre_sha, _, _ = self._lookup_and_verify_prepared_intent_unlocked(
                        ro_conn,
                        intent_id=intent_id,
                        intent_sha256=intent_sha256,
                        expected_action=INTENT_ACTION_OFFRAMP_ACH,
                        amt_q=amt_q,
                        rail=rail,
                        broker_id=None,
                        destination_bank_id=dest_bank,
                        conversion_spec=conv_spec,
                        explicit_idempotency_key=idempotency_key,
                        retry_transfer_id=retry_ref,
                        owner_request_id=clean_req_id,
                        now_dt=now_dt,
                    )
                with verifier.atomic_consume(
                    recovery_token,
                    expected_scope="TREASURY_SWEEP",
                    target_ref=pre_sha,
                    require_exact_target=True,
                    owner_request_id=clean_req_id,
                    now=now_dt,
                ):
                    (
                        transfer_id,
                        eff_idem,
                        conv_status,
                        conv_client_ref,
                        conv_tx_id,
                        conv_required,
                        prev_wd_status,
                    ) = _reserve_ach(consume_same_db=False, consume_fallback=False)
            else:
                (
                    transfer_id,
                    eff_idem,
                    conv_status,
                    conv_client_ref,
                    conv_tx_id,
                    conv_required,
                    prev_wd_status,
                ) = _reserve_ach(consume_same_db=False, consume_fallback=True)

        try:
            # ------------------------------------------------------------------
            # PHASE 1: Separately journaled USD conversion (skipped if already CONVERSION_CONFIRMED)
            # ------------------------------------------------------------------
            if conv_required and conv_status != CONVERSION_STATUS_CONFIRMED:
                if not conv_client_ref:
                    conv_client_ref = self._derive_conversion_client_ref(self.scope_id, transfer_id, eff_idem)
                ts_conv_start = _iso(self._clock())
                with self._lock, closing(self._connect()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        cur_c = conn.execute(
                            "UPDATE bank_transfers "
                            "SET conversion_status = ?, conversion_client_ref = ?, conversion_error_detail = NULL "
                            "WHERE transfer_id = ? AND scope_id = ? AND conversion_status = ?",
                            (
                                CONVERSION_STATUS_PENDING,
                                conv_client_ref,
                                transfer_id,
                                self.scope_id,
                                CONVERSION_STATUS_NOT_STARTED,
                            ),
                        )
                        if cur_c.rowcount != 1:
                            conn.execute("ROLLBACK")
                            raise OfframpSecurityError(
                                f"Transfer {transfer_id!r} cannot transition to CONVERSION_PENDING from {conv_status!r}"
                            )
                        self._append_audit(
                            conn,
                            "ACH_CONVERSION_PENDING",
                            {
                                "transfer_id": transfer_id,
                                "idempotency_key": eff_idem,
                                "conversion_client_ref": conv_client_ref,
                                "rail": rail,
                                "conversion": conv_spec,
                            },
                            ts_conv_start,
                        )
                        conn.execute("COMMIT")
                        conn.commit()
                    except Exception:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                        raise

                # Finding [12]: Re-verify active session epoch AFTER durable CONVERSION_PENDING commit, BEFORE external I/O!
                if epoch_guard is not None:
                    try:
                        epoch_guard()
                    except Exception as exc:
                        ts_rev_c = _iso(self._clock())
                        rev_status_c = "RESERVED_PENDING_DISPATCH" if retry_ref is not None else "ABORTED_EPOCH_REVOKED"
                        rev_err_c = f"EPOCH_REVOKED_BEFORE_CONVERSION:{type(exc).__name__}"
                        with self._lock, closing(self._connect()) as conn:
                            conn.execute("BEGIN IMMEDIATE")
                            conn.execute(
                                "UPDATE bank_transfers "
                                "SET status = ?, conversion_status = ?, error_detail = ?, conversion_error_detail = ? "
                                "WHERE transfer_id = ? AND scope_id = ?",
                                (
                                    rev_status_c,
                                    CONVERSION_STATUS_NOT_STARTED,
                                    rev_err_c,
                                    rev_err_c,
                                    transfer_id,
                                    self.scope_id,
                                ),
                            )
                            self._append_audit(
                                conn,
                                "ACH_OFFRAMP_EPOCH_REVOKED",
                                {
                                    "transfer_id": transfer_id,
                                    "phase": "CONVERSION",
                                    "conversion_client_ref": conv_client_ref,
                                    "error": type(exc).__name__,
                                },
                                ts_rev_c,
                            )
                            conn.execute("COMMIT")
                            conn.commit()
                        raise

                try:
                    if rail == RAIL_COINBASE_ACH:
                        if coinbase_client is None:
                            raise OfframpSecurityError("CoinbaseOfframpClient is not configured")
                        cb_conv_kwargs: dict[str, Any] = {
                            "from_currency": str(convert_from_currency),
                            "amount": convert_amount,
                            "from_account_uuid": str(coinbase_source_account_uuid),
                            "usd_account_uuid": str(coinbase_usd_account_uuid),
                        }
                        if self._accepts_kwarg(coinbase_client.convert_to_usd, "client_reference_id"):
                            cb_conv_kwargs["client_reference_id"] = conv_client_ref
                        conv_resp = coinbase_client.convert_to_usd(**cb_conv_kwargs)
                    else:
                        if kraken_client is None:
                            raise OfframpSecurityError("KrakenOfframpClient is not configured")
                        krk_conv_kwargs: dict[str, Any] = {
                            "pair": kraken_pair,
                            "volume": convert_amount,
                        }
                        if self._accepts_kwarg(kraken_client.convert_to_usd, "client_reference_id"):
                            krk_conv_kwargs["client_reference_id"] = conv_client_ref
                        conv_resp = kraken_client.convert_to_usd(**krk_conv_kwargs)

                    conv_tx_id = self._extract_conversion_tx_id(rail=rail, response=conv_resp)
                    if not conv_tx_id:
                        raise OfframpSecurityError(
                            f"Provider {rail} conversion response omitted a trustworthy transaction ID; "
                            f"freezing as CONVERSION_OUTCOME_UNKNOWN"
                        )
                except Exception as exc:
                    ts_conv_err = _iso(self._clock())
                    conv_err_txt = f"{type(exc).__name__}:{str(exc)[:180]}"
                    with self._lock, closing(self._connect()) as conn:
                        conn.execute("BEGIN IMMEDIATE")
                        conn.execute(
                            "UPDATE bank_transfers "
                            "SET status = 'OUTCOME_UNKNOWN', conversion_status = ?, "
                            "conversion_error_detail = ?, error_detail = ? "
                            "WHERE transfer_id = ? AND scope_id = ?",
                            (
                                CONVERSION_STATUS_OUTCOME_UNKNOWN,
                                conv_err_txt,
                                conv_err_txt,
                                transfer_id,
                                self.scope_id,
                            ),
                        )
                        self._append_audit(
                            conn,
                            "ACH_CONVERSION_OUTCOME_UNKNOWN",
                            {
                                "transfer_id": transfer_id,
                                "idempotency_key": eff_idem,
                                "conversion_client_ref": conv_client_ref,
                                "rail": rail,
                                "error": type(exc).__name__,
                            },
                            ts_conv_err,
                        )
                        conn.execute("COMMIT")
                        conn.commit()
                    raise

                ts_conv_ok = _iso(self._clock())
                with self._lock, closing(self._connect()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute(
                        "UPDATE bank_transfers "
                        "SET conversion_status = ?, conversion_tx_id = ?, conversion_error_detail = NULL "
                        "WHERE transfer_id = ? AND scope_id = ?",
                        (CONVERSION_STATUS_CONFIRMED, conv_tx_id, transfer_id, self.scope_id),
                    )
                    self._append_audit(
                        conn,
                        "ACH_CONVERSION_CONFIRMED",
                        {
                            "transfer_id": transfer_id,
                            "idempotency_key": eff_idem,
                            "conversion_client_ref": conv_client_ref,
                            "conversion_tx_id": conv_tx_id,
                            "rail": rail,
                        },
                        ts_conv_ok,
                    )
                    conn.execute("COMMIT")
                    conn.commit()
                conv_status = CONVERSION_STATUS_CONFIRMED

            # ------------------------------------------------------------------
            # PHASE 2: Separately journaled ACH withdrawal (direct SQLite durable commit BEFORE external call!)
            # ------------------------------------------------------------------
            ts_wd_start = _iso(self._clock())
            with self._lock, closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    cur_w = conn.execute(
                        "UPDATE bank_transfers "
                        "SET status = 'RESERVED_PENDING_DISPATCH', withdrawal_status = ?, withdrawal_error_detail = NULL "
                        "WHERE transfer_id = ? AND scope_id = ? "
                        "AND conversion_status IN (?, ?) "
                        "AND withdrawal_status != ?",
                        (
                            WITHDRAWAL_STATUS_PENDING,
                            transfer_id,
                            self.scope_id,
                            CONVERSION_STATUS_NOT_REQUIRED,
                            CONVERSION_STATUS_CONFIRMED,
                            WITHDRAWAL_STATUS_SUBMITTED,
                        ),
                    )
                    if cur_w.rowcount != 1:
                        conn.execute("ROLLBACK")
                        raise OfframpSecurityError(
                            f"Transfer {transfer_id!r} cannot enter WITHDRAWAL_PENDING (conversion_status={conv_status!r})"
                        )
                    self._append_audit(
                        conn,
                        "ACH_WITHDRAWAL_PENDING",
                        {
                            "transfer_id": transfer_id,
                            "idempotency_key": eff_idem,
                            "conversion_status": conv_status,
                            "conversion_tx_id": conv_tx_id,
                            "rail": rail,
                            "destination_bank_id": dest_bank,
                            "amount_usd": decimal_text(amt_q),
                        },
                        ts_wd_start,
                    )
                    conn.execute("COMMIT")
                    conn.commit()
                except Exception:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                    raise

            # Finding [12]: Re-verify active session epoch AFTER durable WITHDRAWAL_PENDING commit, BEFORE external ACH I/O!
            if epoch_guard is not None:
                try:
                    epoch_guard()
                except Exception as exc:
                    ts_rev_w = _iso(self._clock())
                    rev_err_w = f"EPOCH_REVOKED_BEFORE_WITHDRAWAL:{type(exc).__name__}"
                    if retry_ref is not None and prev_wd_status == WITHDRAWAL_STATUS_OUTCOME_UNKNOWN:
                        rev_status_w = "OUTCOME_UNKNOWN"
                        rev_wd_st = WITHDRAWAL_STATUS_OUTCOME_UNKNOWN
                    elif conv_status == CONVERSION_STATUS_CONFIRMED or retry_ref is not None:
                        rev_status_w = "RESERVED_PENDING_DISPATCH"
                        rev_wd_st = WITHDRAWAL_STATUS_NOT_STARTED
                    else:
                        rev_status_w = "ABORTED_EPOCH_REVOKED"
                        rev_wd_st = WITHDRAWAL_STATUS_NOT_STARTED
                    with self._lock, closing(self._connect()) as conn:
                        conn.execute("BEGIN IMMEDIATE")
                        conn.execute(
                            "UPDATE bank_transfers "
                            "SET status = ?, withdrawal_status = ?, error_detail = ?, withdrawal_error_detail = ? "
                            "WHERE transfer_id = ? AND scope_id = ?",
                            (
                                rev_status_w,
                                rev_wd_st,
                                rev_err_w,
                                rev_err_w,
                                transfer_id,
                                self.scope_id,
                            ),
                        )
                        self._append_audit(
                            conn,
                            "ACH_OFFRAMP_EPOCH_REVOKED",
                            {
                                "transfer_id": transfer_id,
                                "phase": "WITHDRAWAL",
                                "idempotency_key": eff_idem,
                                "conversion_status": conv_status,
                                "conversion_tx_id": conv_tx_id,
                                "error": type(exc).__name__,
                            },
                            ts_rev_w,
                        )
                        conn.execute("COMMIT")
                        conn.commit()
                    raise

            # External ACH withdrawal executes ONLY after durable WITHDRAWAL_PENDING commit & epoch_guard recheck!
            try:
                if rail == RAIL_COINBASE_ACH:
                    if coinbase_client is None:
                        raise OfframpSecurityError("CoinbaseOfframpClient is not configured")
                    resp = coinbase_client.withdraw_usd_to_linked_bank_ach(
                        amount_usd=amt_q, client_reference_id=eff_idem
                    )
                    raw_tx = resp.get("id") or resp.get("payout_id") or resp.get("refid") if isinstance(resp, Mapping) else None
                else:
                    if kraken_client is None:
                        raise OfframpSecurityError("KrakenOfframpClient is not configured")
                    resp = kraken_client.withdraw_usd_to_linked_bank_ach(
                        amount_usd=amt_q, client_reference_id=eff_idem
                    )
                    raw_tx = resp.get("refid") if isinstance(resp, Mapping) else None
                provider_tx = str(raw_tx).strip() if isinstance(raw_tx, str) and raw_tx.strip() else ""
                if not provider_tx:
                    raise OfframpSecurityError(
                        f"Provider {rail} withdrawal response omitted a trustworthy transaction ID; retaining OUTCOME_UNKNOWN"
                    )
            except Exception as exc:
                ts_err = _iso(self._clock())
                wd_err_txt = f"{type(exc).__name__}:{str(exc)[:180]}"
                with self._lock, closing(self._connect()) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute(
                        "UPDATE bank_transfers "
                        "SET status = 'OUTCOME_UNKNOWN', withdrawal_status = ?, "
                        "withdrawal_error_detail = ?, error_detail = ? "
                        "WHERE transfer_id = ? AND scope_id = ?",
                        (
                            WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
                            wd_err_txt,
                            wd_err_txt,
                            transfer_id,
                            self.scope_id,
                        ),
                    )
                    self._append_audit(
                        conn,
                        "ACH_OFFRAMP_OUTCOME_UNKNOWN",
                        {
                            "transfer_id": transfer_id,
                            "idempotency_key": eff_idem,
                            "conversion_status": conv_status,
                            "conversion_tx_id": conv_tx_id,
                            "withdrawal_status": WITHDRAWAL_STATUS_OUTCOME_UNKNOWN,
                            "error": type(exc).__name__,
                        },
                        ts_err,
                    )
                    conn.execute("COMMIT")
                    conn.commit()
                raise

            ts_done = _iso(self._clock())
            with self._lock, closing(self._connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    "UPDATE bank_transfers "
                    "SET status = 'ACH_SUBMITTED', withdrawal_status = ?, provider_tx_id = ?, "
                    "settled_at = ?, error_detail = NULL, withdrawal_error_detail = NULL "
                    "WHERE transfer_id = ? AND scope_id = ?",
                    (WITHDRAWAL_STATUS_SUBMITTED, provider_tx, ts_done, transfer_id, self.scope_id),
                )
                self._append_audit(
                    conn,
                    "ACH_OFFRAMP_SUBMITTED",
                    {
                        "transfer_id": transfer_id,
                        "idempotency_key": eff_idem,
                        "rail": rail,
                        "destination_bank_id": dest_bank,
                        "amount_usd": decimal_text(amt_q),
                        "provider_tx_id": provider_tx,
                        "conversion_status": conv_status,
                        "conversion_tx_id": conv_tx_id,
                        "withdrawal_status": WITHDRAWAL_STATUS_SUBMITTED,
                    },
                    ts_done,
                )
                conn.execute("COMMIT")
                conn.commit()
            return {
                "transfer_id": transfer_id,
                "idempotency_key": eff_idem,
                "provider_tx_id": provider_tx,
                "status": "ACH_SUBMITTED",
                "conversion_status": conv_status,
                "conversion_client_ref": conv_client_ref,
                "conversion_tx_id": conv_tx_id,
                "withdrawal_status": WITHDRAWAL_STATUS_SUBMITTED,
                "vault": self.snapshot(),
            }
        finally:
            with self._lock:
                self._in_flight_transfers.discard(transfer_id)

    execute_prepared_ach_offramp = execute_offramp_ach_payout

    def _pending_disbursement_unlocked(self, conn: sqlite3.Connection) -> Decimal:
        swept = Decimal("0")
        for r in conn.execute("SELECT bank_sweep_usd_text FROM sweep_events WHERE scope_id = ?", (self.scope_id,)):
            swept += Decimal(str(r["bank_sweep_usd_text"]))
        disbursed = Decimal("0")
        for r in conn.execute(
            "SELECT amount_usd_text, status FROM bank_transfers WHERE scope_id = ?", (self.scope_id,)
        ):
            if str(r["status"]) in (
                "SETTLED",
                "ACH_SUBMITTED",
                "RESERVED_PENDING_DISPATCH",
                "OUTCOME_UNKNOWN",
                "PENDING_OWNER_BROKER_2FA",
                "BROKER_2FA_VERIFICATION_UNKNOWN",
            ):
                disbursed += Decimal(str(r["amount_usd_text"]))
        rem = swept - disbursed
        return rem if rem > Decimal("0") else Decimal("0.00")

    @staticmethod
    def is_reconciliation_sync_event(trade_id: str, symbol: str) -> bool:
        return str(trade_id).startswith("SESSION_SYNC_") or str(symbol) == "SESSION_BASKET"

    def snapshot(self) -> dict[str, Any]:
        from cas_forex_revamp.valve.daily_quota import (
            forex_session_label_for_utc,
            format_pacific_timestamp,
            friendly_broker_label,
        )

        with self._lock, closing(self._connect_ro()) as conn:
            cfg = conn.execute("SELECT * FROM vault_config WHERE scope_id = ?", (self.scope_id,)).fetchone()
            total_realized = Decimal("0")
            retained = Decimal("0")
            bank_reserved_total = Decimal("0")
            recent_sweeps: list[dict[str, Any]] = []
            trade_sweeps: list[dict[str, Any]] = []
            market_agg: dict[str, dict[str, Any]] = {}
            broker_agg: dict[str, dict[str, Any]] = {}
            rows = conn.execute(
                "SELECT * FROM sweep_events WHERE scope_id = ? ORDER BY rowid DESC", (self.scope_id,)
            ).fetchall()
            row_keys_checked = False
            has_sdate_col = False
            for idx, r in enumerate(rows):
                if not row_keys_checked:
                    has_sdate_col = "session_date" in r.keys()
                    row_keys_checked = True
                tid_str = str(r["trade_id"])
                sym_str = str(r["symbol"])
                brk_str = str(r["broker_id"])
                brk_lbl = friendly_broker_label(brk_str)
                occ_str = str(r["occurred_at"])
                sdate_val = str(r["session_date"]) if (has_sdate_col and r["session_date"]) else None
                net_v = Decimal(str(r["realized_net_usd_text"]))
                ret_v = Decimal(str(r["retained_trading_usd_text"]))
                bnk_v = Decimal(str(r["bank_sweep_usd_text"]))
                total_realized += net_v
                retained += ret_v
                bank_reserved_total += bnk_v

                is_sync = self.is_reconciliation_sync_event(tid_str, sym_str)
                occ_pac = format_pacific_timestamp(occ_str)
                sess_lbl = forex_session_label_for_utc(occ_str)
                row_item: dict[str, Any] = {
                    "trade_id": tid_str,
                    "symbol": sym_str,
                    "broker_id": brk_str,
                    "broker_label": brk_lbl,
                    "realized_net_usd": decimal_text(net_v),
                    "retained_trading_usd": decimal_text(ret_v),
                    "bank_sweep_usd": decimal_text(bnk_v),
                    "occurred_at": occ_str,
                    "occurred_at_pacific": occ_pac,
                    "session_label": sess_lbl,
                    "is_reconciliation_sync": is_sync,
                }
                if sdate_val is not None:
                    row_item["session_date"] = sdate_val
                if idx < 25:
                    recent_sweeps.append(row_item)
                if not is_sync:
                    if len(trade_sweeps) < 50:
                        trade_sweeps.append(dict(row_item))
                    m_bucket = market_agg.get(sym_str)
                    if m_bucket is None:
                        market_agg[sym_str] = {
                            "symbol": sym_str,
                            "net_dec": net_v,
                            "trade_count": 1,
                            "win_count": 1 if net_v > Decimal("0") else 0,
                            "loss_count": 1 if net_v < Decimal("0") else 0,
                            "last_occurred_at": occ_str,
                            "last_occurred_at_pacific": occ_pac,
                            "last_session_label": sess_lbl,
                        }
                    else:
                        m_bucket["net_dec"] += net_v
                        m_bucket["trade_count"] += 1
                        if net_v > Decimal("0"):
                            m_bucket["win_count"] += 1
                        elif net_v < Decimal("0"):
                            m_bucket["loss_count"] += 1
                        if occ_str > str(m_bucket["last_occurred_at"]):
                            m_bucket["last_occurred_at"] = occ_str
                            m_bucket["last_occurred_at_pacific"] = occ_pac
                            m_bucket["last_session_label"] = sess_lbl

                    b_bucket = broker_agg.get(brk_str)
                    if b_bucket is None:
                        broker_agg[brk_str] = {
                            "broker_id": brk_str,
                            "broker_label": brk_lbl,
                            "net_dec": net_v,
                            "trade_count": 1,
                            "win_count": 1 if net_v > Decimal("0") else 0,
                            "loss_count": 1 if net_v < Decimal("0") else 0,
                            "last_occurred_at": occ_str,
                            "last_occurred_at_pacific": occ_pac,
                            "last_session_label": sess_lbl,
                        }
                    else:
                        b_bucket["net_dec"] += net_v
                        b_bucket["trade_count"] += 1
                        if net_v > Decimal("0"):
                            b_bucket["win_count"] += 1
                        elif net_v < Decimal("0"):
                            b_bucket["loss_count"] += 1
                        if occ_str > str(b_bucket["last_occurred_at"]):
                            b_bucket["last_occurred_at"] = occ_str
                            b_bucket["last_occurred_at_pacific"] = occ_pac
                            b_bucket["last_session_label"] = sess_lbl

            realized_by_market = [
                {
                    "symbol": str(b["symbol"]),
                    "realized_net_usd": decimal_text(b["net_dec"]),
                    "trade_count": int(b["trade_count"]),
                    "win_count": int(b["win_count"]),
                    "loss_count": int(b["loss_count"]),
                    "last_occurred_at": str(b["last_occurred_at"]),
                    "last_occurred_at_pacific": str(b["last_occurred_at_pacific"]),
                    "last_session_label": str(b["last_session_label"]),
                }
                for b in sorted(
                    market_agg.values(),
                    key=lambda item: (-Decimal(item["net_dec"]), str(item["symbol"])),
                )
            ]
            realized_by_broker = [
                {
                    "broker_id": str(b["broker_id"]),
                    "broker_label": str(b["broker_label"]),
                    "realized_net_usd": decimal_text(b["net_dec"]),
                    "trade_count": int(b["trade_count"]),
                    "win_count": int(b["win_count"]),
                    "loss_count": int(b["loss_count"]),
                    "last_occurred_at": str(b["last_occurred_at"]),
                    "last_occurred_at_pacific": str(b["last_occurred_at_pacific"]),
                    "last_session_label": str(b["last_session_label"]),
                }
                for b in sorted(
                    broker_agg.values(),
                    key=lambda item: (-Decimal(item["net_dec"]), str(item["broker_id"])),
                )
            ]

            disbursed = Decimal("0")
            confirmed_settled = Decimal("0")
            unconfirmed_active = Decimal("0")
            pending_2fa = Decimal("0")
            recent_transfers: list[dict[str, Any]] = []
            trows = conn.execute(
                "SELECT * FROM bank_transfers WHERE scope_id = ? ORDER BY rowid DESC", (self.scope_id,)
            ).fetchall()
            for idx, r in enumerate(trows):
                amt = Decimal(str(r["amount_usd_text"]))
                st = str(r["status"])
                if st == "SETTLED":
                    confirmed_settled += amt
                    disbursed += amt
                elif st in ("ACH_SUBMITTED", "RESERVED_PENDING_DISPATCH", "OUTCOME_UNKNOWN"):
                    disbursed += amt
                    unconfirmed_active += amt
                elif st in ("PENDING_OWNER_BROKER_2FA", "BROKER_2FA_VERIFICATION_UNKNOWN"):
                    pending_2fa += amt
                    unconfirmed_active += amt
                if idx < 25:
                    r_keys = r.keys()
                    t_item: dict[str, Any] = {
                        "transfer_id": str(r["transfer_id"]),
                        "rail": str(r["rail"]),
                        "broker_id": r["broker_id"],
                        "destination_bank_id": str(r["destination_bank_id"]),
                        "amount_usd": decimal_text(amt),
                        "status": st,
                        "provider_tx_id": r["provider_tx_id"],
                        "created_at": str(r["created_at"]),
                        "settled_at": r["settled_at"],
                    }
                    if "conversion_status" in r_keys:
                        t_item["conversion_status"] = str(r["conversion_status"] or CONVERSION_STATUS_NOT_REQUIRED)
                    if "conversion_client_ref" in r_keys:
                        t_item["conversion_client_ref"] = r["conversion_client_ref"]
                    if "conversion_tx_id" in r_keys:
                        t_item["conversion_tx_id"] = r["conversion_tx_id"]
                    if "withdrawal_status" in r_keys:
                        t_item["withdrawal_status"] = str(r["withdrawal_status"] or WITHDRAWAL_STATUS_NOT_STARTED)
                    recent_transfers.append(t_item)

            bank_reserved_total = max(Decimal("0.00"), bank_reserved_total)
            pending_rem = max(Decimal("0.00"), bank_reserved_total - disbursed)
            ratio = Decimal(str(cfg["sweep_ratio_text"])) if cfg else DEFAULT_SWEEP_RATIO
            cfg_init_cap = (
                Decimal(str(cfg["initial_capital_usd_text"]))
                if (cfg is not None and cfg["initial_capital_usd_text"] not in (None, ""))
                else None
            )
            return {
                "schema": "cas-forex.profit-vault/1",
                "scope_id": self.scope_id,
                "sweep_ratio": decimal_text(ratio),
                "sweep_ratio_pct": decimal_text((ratio * Decimal("100")).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
                "auto_sweep_enabled": bool(int(cfg["auto_sweep_enabled"])) if cfg else True,
                "preferred_rail": str(cfg["preferred_rail"]) if cfg else RAIL_BROKER_2FA_MANUAL,
                "initial_capital_usd": None if cfg_init_cap is None else decimal_text(cfg_init_cap),
                "total_realized_profit_usd": decimal_text(total_realized),
                "retained_trading_usd": decimal_text(retained),
                "bank_sweep_reserved_usd": decimal_text(bank_reserved_total),
                "disbursed_to_bank_usd": decimal_text(disbursed),
                "confirmed_settled_disbursed_usd": decimal_text(confirmed_settled),
                "pending_or_unconfirmed_transfers_usd": decimal_text(unconfirmed_active),
                "pending_2fa_confirmation_usd": decimal_text(pending_2fa),
                "pending_disbursement_usd": decimal_text(pending_rem),
                "recent_sweeps": recent_sweeps,
                "trade_sweeps": trade_sweeps,
                "realized_by_market": realized_by_market,
                "realized_by_broker": realized_by_broker,
                "recent_transfers": recent_transfers,
            }

    def verify_audit_chain(self) -> dict[str, object]:
        """Verify the full SHA-256 hash chain and contiguous sequence of ``vault_audit`` (fail closed)."""
        expected_prev = GENESIS_AUDIT_SHA256
        last_hash = GENESIS_AUDIT_SHA256
        expected_seq = 1
        checked_rows = 0

        with self._lock:
            try:
                with closing(self._connect()) as conn:
                    in_tx = False
                    try:
                        conn.execute("BEGIN")
                        in_tx = True
                        rows = conn.execute(
                            """
                            SELECT seq, prev_sha256, entry_sha256, scope_id, event_type, payload_json, created_at
                            FROM vault_audit
                            ORDER BY seq ASC
                            """
                        ).fetchall()
                        has_seq_tbl = (
                            conn.execute(
                                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'"
                            ).fetchone()
                            is not None
                        )
                        seq_row = (
                            conn.execute(
                                "SELECT seq FROM sqlite_sequence WHERE name = 'vault_audit'"
                            ).fetchone()
                            if has_seq_tbl
                            else None
                        )
                    finally:
                        if in_tx and conn.in_transaction:
                            conn.execute("ROLLBACK")
            except sqlite3.Error:
                return {
                    "valid": False,
                    "checked_rows": 0,
                    "broken_at_id": 1,
                    "last_hash": GENESIS_AUDIT_SHA256,
                }

        for row in rows:
            raw_seq = row["seq"]
            if type(raw_seq) is not int or raw_seq <= 0:
                return {
                    "valid": False,
                    "checked_rows": checked_rows + 1,
                    "broken_at_id": raw_seq if type(raw_seq) is int else expected_seq,
                    "last_hash": last_hash,
                }
            if raw_seq != expected_seq:
                broken_id = expected_seq if raw_seq > expected_seq else raw_seq
                return {
                    "valid": False,
                    "checked_rows": checked_rows + 1,
                    "broken_at_id": broken_id,
                    "last_hash": last_hash,
                }

            checked_rows += 1
            prev_sha = row["prev_sha256"]
            entry_sha = row["entry_sha256"]
            row_scope = row["scope_id"]
            event_type = row["event_type"]
            payload_json = row["payload_json"]
            created_at = row["created_at"]

            if (
                type(prev_sha) is not str
                or type(entry_sha) is not str
                or type(row_scope) is not str
                or not row_scope.strip()
                or type(event_type) is not str
                or not event_type.strip()
                or type(payload_json) is not str
                or type(created_at) is not str
                or not created_at.strip()
                or _SHA256_HEX_RE.fullmatch(prev_sha) is None
                or _SHA256_HEX_RE.fullmatch(entry_sha) is None
            ):
                return {
                    "valid": False,
                    "checked_rows": checked_rows,
                    "broken_at_id": raw_seq,
                    "last_hash": last_hash,
                }

            if prev_sha != expected_prev:
                return {
                    "valid": False,
                    "checked_rows": checked_rows,
                    "broken_at_id": raw_seq,
                    "last_hash": last_hash,
                }

            try:
                payload_bytes = payload_json.encode("utf-8")
                parsed_payload = json.loads(payload_json, parse_constant=_reject_nonfinite_json)
                if type(parsed_payload) is not dict or canonical_bytes(parsed_payload) != payload_bytes:
                    return {
                        "valid": False,
                        "checked_rows": checked_rows,
                        "broken_at_id": raw_seq,
                        "last_hash": last_hash,
                    }
                recomputed = sha256(
                    f"{prev_sha}|{row_scope}|{event_type}|".encode("utf-8")
                    + payload_bytes
                    + f"|{created_at}".encode("utf-8")
                ).hexdigest()
            except (ValueError, TypeError, UnicodeError, ContractError):
                return {
                    "valid": False,
                    "checked_rows": checked_rows,
                    "broken_at_id": raw_seq,
                    "last_hash": last_hash,
                }

            if recomputed != entry_sha:
                return {
                    "valid": False,
                    "checked_rows": checked_rows,
                    "broken_at_id": raw_seq,
                    "last_hash": last_hash,
                }

            expected_prev = entry_sha
            last_hash = entry_sha
            expected_seq += 1

        if seq_row is not None:
            recorded_max = seq_row["seq"]
            actual_max = expected_seq - 1
            if type(recorded_max) is not int or recorded_max != actual_max:
                broken_tail = (
                    actual_max + 1
                    if (type(recorded_max) is int and recorded_max > actual_max)
                    else actual_max
                )
                return {
                    "valid": False,
                    "checked_rows": checked_rows,
                    "broken_at_id": broken_tail,
                    "last_hash": last_hash,
                }

        return {
            "valid": True,
            "checked_rows": checked_rows,
            "broken_at_id": None,
            "last_hash": last_hash,
        }
