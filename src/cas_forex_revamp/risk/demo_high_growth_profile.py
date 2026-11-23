"""Opt-in DEMO-only High-Growth Practice Profile (PR #43).

Keeps constitutional LIVE ceilings (1.00% stop risk / 10.00% drawdown) completely
immutable while giving explicit DEMO-mode ($0.00 real money) opt-in access to
10.00% target / 12.00% max risk per trade, 30.00% drawdown pause, 100.00%
compounding (0.00% profit siphon), wider trend protection, and pyramiding.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import json
import os
from pathlib import Path
import stat
from threading import RLock
from typing import Any

from cas_forex_revamp.contracts import ContractError
from cas_forex_revamp.contracts.primitives import decimal_text, utc_time

DEMO_HIGH_GROWTH_SCHEMA = "cas-forex.demo-high-growth-profile/1"
ENV_DEMO_HIGH_GROWTH_PROFILE = "CAS_FOREX_DEMO_HIGH_GROWTH_PROFILE"

DEMO_HIGH_GROWTH_DEFAULT_RISK_PCT = Decimal("10.00")
DEMO_HIGH_GROWTH_MAX_RISK_PCT = Decimal("12.00")
DEMO_HIGH_GROWTH_MAX_DRAWDOWN_PCT = Decimal("0.30")
DEMO_HIGH_GROWTH_SWEEP_RATIO = Decimal("0.00")
DEMO_HIGH_GROWTH_BE_SCALE = Decimal("1.50")
DEMO_HIGH_GROWTH_TRAIL_SCALE = Decimal("1.75")
DEMO_HIGH_GROWTH_TP_SCALE = Decimal("1.50")
DEMO_HIGH_GROWTH_DAILY_GOAL_PCT = Decimal("0.25")
DEMO_HIGH_GROWTH_DAILY_LOSS_BRAKE_PCT = Decimal("0.20")
DEMO_HIGH_GROWTH_POST_LOSS_COOLDOWN_SECONDS = 900
DEMO_HIGH_GROWTH_MAX_POST_LOSS_COOLDOWN_SECONDS = 3600
DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE = "DEMO_HIGH_GROWTH_PROFILE_FORBIDDEN_IN_LIVE_MODE"

_STD_STOP_RISK_PCT = Decimal("1.00")
_STD_DRAWDOWN_PCT = Decimal("0.10")
_Q2 = Decimal("0.01")

_ALLOWED_WIRE_KEYS: frozenset[str] = frozenset(
    {
        "enabled",
        "target_risk_pct",
        "max_risk_pct",
        "max_drawdown_pct",
        "compounding_100pct",
        "let_winners_run",
        "pyramiding_enabled",
        "post_loss_cooldown_seconds",
        "block_us_close_chop",
        "demo_only_locked",
    }
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(ts: datetime) -> str:
    return utc_time(ts, "observed_at").strftime("%Y-%m-%dT%H:%M:%SZ")


def _require_strict_bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        raise ContractError(f"{field} must be a strict bool, got {type(value).__name__}")
    return value


def _require_positive_decimal(value: Any, field: str) -> Decimal:
    if isinstance(value, (bool, float)) or value is None:
        raise ContractError(f"{field} must be an exact Decimal/int/str, not {type(value).__name__}")
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            raise ContractError(f"{field} cannot be empty")
        try:
            dec = Decimal(raw)
        except (InvalidOperation, ValueError) as exc:
            raise ContractError(f"{field} invalid decimal {value!r}") from exc
    elif isinstance(value, (Decimal, int)):
        dec = Decimal(value)
    else:
        raise ContractError(f"{field} must be Decimal/int/str, got {type(value).__name__}")
    if not dec.is_finite() or dec <= Decimal("0"):
        raise ContractError(f"{field} must be finite and > 0, got {dec}")
    return dec


def _q2(val: Decimal) -> Decimal:
    return val.quantize(_Q2, rounding=ROUND_HALF_UP)


@dataclass(frozen=True)
class DemoHighGrowthProfile:
    """Validated opt-in DEMO-only high-growth policy."""

    enabled: bool = False
    target_risk_pct: Decimal = DEMO_HIGH_GROWTH_DEFAULT_RISK_PCT
    max_risk_pct: Decimal = DEMO_HIGH_GROWTH_MAX_RISK_PCT
    max_drawdown_pct: Decimal = DEMO_HIGH_GROWTH_MAX_DRAWDOWN_PCT
    compounding_100pct: bool = True
    let_winners_run: bool = True
    pyramiding_enabled: bool = True
    post_loss_cooldown_seconds: int = DEMO_HIGH_GROWTH_POST_LOSS_COOLDOWN_SECONDS
    block_us_close_chop: bool = True
    demo_only_locked: bool = True

    def __post_init__(self) -> None:
        enabled_b = _require_strict_bool(self.enabled, "enabled")
        comp_b = _require_strict_bool(self.compounding_100pct, "compounding_100pct")
        win_b = _require_strict_bool(self.let_winners_run, "let_winners_run")
        pyr_b = _require_strict_bool(self.pyramiding_enabled, "pyramiding_enabled")
        chop_b = _require_strict_bool(self.block_us_close_chop, "block_us_close_chop")
        cd_raw = self.post_loss_cooldown_seconds
        if type(cd_raw) is not int or not (0 <= cd_raw <= DEMO_HIGH_GROWTH_MAX_POST_LOSS_COOLDOWN_SECONDS):
            raise ContractError(
                f"post_loss_cooldown_seconds must be strict int in 0..{DEMO_HIGH_GROWTH_MAX_POST_LOSS_COOLDOWN_SECONDS}, got {cd_raw!r}"
            )
        demo_b = _require_strict_bool(self.demo_only_locked, "demo_only_locked")
        if demo_b is not True:
            raise ContractError("DemoHighGrowthProfile must enforce demo_only_locked=True")

        target_d = _q2(_require_positive_decimal(self.target_risk_pct, "target_risk_pct"))
        max_r_d = _q2(_require_positive_decimal(self.max_risk_pct, "max_risk_pct"))
        dd_d = _q2(_require_positive_decimal(self.max_drawdown_pct, "max_drawdown_pct"))

        if target_d > max_r_d:
            raise ContractError(
                f"target_risk_pct ({target_d}%) cannot exceed max_risk_pct ({max_r_d}%)"
            )
        if max_r_d > DEMO_HIGH_GROWTH_MAX_RISK_PCT:
            raise ContractError(
                f"max_risk_pct ({max_r_d}%) exceeds DEMO high-growth ceiling {DEMO_HIGH_GROWTH_MAX_RISK_PCT}%"
            )
        if dd_d > DEMO_HIGH_GROWTH_MAX_DRAWDOWN_PCT:
            raise ContractError(
                f"max_drawdown_pct ({dd_d}) exceeds DEMO high-growth ceiling {DEMO_HIGH_GROWTH_MAX_DRAWDOWN_PCT}"
            )
        if enabled_b and dd_d <= (max_r_d / Decimal("100")):
            raise ContractError(
                f"max_drawdown_pct ({dd_d}) must exceed max_risk_pct/100 ({max_r_d / Decimal('100')}) when enabled"
            )

        object.__setattr__(self, "enabled", enabled_b)
        object.__setattr__(self, "target_risk_pct", target_d)
        object.__setattr__(self, "max_risk_pct", max_r_d)
        object.__setattr__(self, "max_drawdown_pct", dd_d)
        object.__setattr__(self, "compounding_100pct", comp_b)
        object.__setattr__(self, "let_winners_run", win_b)
        object.__setattr__(self, "pyramiding_enabled", pyr_b)
        object.__setattr__(self, "post_loss_cooldown_seconds", cd_raw)
        object.__setattr__(self, "block_us_close_chop", chop_b)
        object.__setattr__(self, "demo_only_locked", demo_b)

    def assert_demo_mode(
        self,
        execution_mode: Any,
        *,
        live_trading_armed: bool = False,
        live_trading_locked: bool = True,
    ) -> None:
        if not self.enabled:
            return
        raw_mode = getattr(execution_mode, "value", execution_mode)
        mode_norm = str(raw_mode or "").strip().upper()
        if mode_norm != "DEMO" or bool(live_trading_armed) or not bool(live_trading_locked):
            raise ContractError(DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE)

    def effective_stop_risk_ceiling_pct(self) -> Decimal:
        return self.max_risk_pct if self.enabled else _STD_STOP_RISK_PCT

    def effective_drawdown_ceiling_pct(self) -> Decimal:
        return self.max_drawdown_pct if self.enabled else _STD_DRAWDOWN_PCT

    def effective_sweep_ratio(self, default_ratio: Decimal = Decimal("0.50")) -> Decimal:
        if self.enabled and self.compounding_100pct:
            return DEMO_HIGH_GROWTH_SWEEP_RATIO
        return default_ratio

    def to_wire_dict(self) -> dict[str, Any]:
        sweep_val = self.effective_sweep_ratio()
        dd_display = _q2(self.max_drawdown_pct * Decimal("100"))
        return {
            "schema": DEMO_HIGH_GROWTH_SCHEMA,
            "enabled": self.enabled,
            "demo_only_locked": True,
            "real_money_at_risk_usd": "0.00",
            "target_risk_pct": decimal_text(self.target_risk_pct),
            "max_risk_pct": decimal_text(self.max_risk_pct),
            "max_drawdown_pct": decimal_text(self.max_drawdown_pct),
            "max_drawdown_display_pct": decimal_text(dd_display),
            "compounding_100pct": self.compounding_100pct,
            "sweep_ratio": decimal_text(sweep_val),
            "let_winners_run": self.let_winners_run,
            "pyramiding_enabled": self.pyramiding_enabled,
            "post_loss_cooldown_seconds": self.post_loss_cooldown_seconds,
            "block_us_close_chop": self.block_us_close_chop,
            "be_scale": decimal_text(DEMO_HIGH_GROWTH_BE_SCALE),
            "trail_scale": decimal_text(DEMO_HIGH_GROWTH_TRAIL_SCALE),
            "tp_scale": decimal_text(DEMO_HIGH_GROWTH_TP_SCALE),
            "valve_gate_enforced": True,
            "live_constitutional_ceilings_intact": True,
        }

    @classmethod
    def from_wire_dict(
        cls,
        data: Mapping[str, Any],
        *,
        base: DemoHighGrowthProfile | None = None,
    ) -> DemoHighGrowthProfile:
        if not isinstance(data, Mapping):
            raise ContractError("DemoHighGrowthProfile payload must be a JSON object")
        extra_keys = sorted(set(data.keys()) - _ALLOWED_WIRE_KEYS)
        if extra_keys:
            raise ContractError(f"Unexpected additional properties in DemoHighGrowthProfile: {extra_keys}")
        seed = base if isinstance(base, DemoHighGrowthProfile) else cls()
        return cls(
            enabled=data.get("enabled", seed.enabled),
            target_risk_pct=data.get("target_risk_pct", seed.target_risk_pct),
            max_risk_pct=data.get("max_risk_pct", seed.max_risk_pct),
            max_drawdown_pct=data.get("max_drawdown_pct", seed.max_drawdown_pct),
            compounding_100pct=data.get("compounding_100pct", seed.compounding_100pct),
            let_winners_run=data.get("let_winners_run", seed.let_winners_run),
            pyramiding_enabled=data.get("pyramiding_enabled", seed.pyramiding_enabled),
            post_loss_cooldown_seconds=data.get("post_loss_cooldown_seconds", seed.post_loss_cooldown_seconds),
            block_us_close_chop=data.get("block_us_close_chop", seed.block_us_close_chop),
            demo_only_locked=data.get("demo_only_locked", seed.demo_only_locked),
        )


def resolve_demo_high_growth_profile_from_environ(
    environ: Mapping[str, str],
    *,
    execution_mode: Any = "DEMO",
    live_trading_armed: bool = False,
    live_trading_locked: bool = True,
) -> DemoHighGrowthProfile:
    raw = str(environ.get(ENV_DEMO_HIGH_GROWTH_PROFILE, "")).strip().lower()
    if raw in ("", "0", "false", "no", "off"):
        enabled = False
    elif raw in ("1", "true", "yes", "on"):
        enabled = True
    else:
        raise ContractError(
            f"Invalid {ENV_DEMO_HIGH_GROWTH_PROFILE}={environ.get(ENV_DEMO_HIGH_GROWTH_PROFILE)!r}"
        )
    profile = DemoHighGrowthProfile(enabled=enabled)
    profile.assert_demo_mode(
        execution_mode,
        live_trading_armed=live_trading_armed,
        live_trading_locked=live_trading_locked,
    )
    return profile


def _check_non_symlink_target(path: Path) -> None:
    if path.parent.exists() and path.parent.is_symlink():
        raise ContractError(f"Refusing symlink directory {path.parent}")
    if path.exists():
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise ContractError(f"Refusing non-regular or symlink file {path}")


class DemoHighGrowthProfileStore:
    """Durable, atomic, non-symlink JSON persistence for the DEMO high-growth profile."""

    def __init__(
        self,
        path: str | Path,
        *,
        initial_profile: DemoHighGrowthProfile | None = None,
        execution_mode: Any = "DEMO",
        live_trading_armed: bool = False,
        live_trading_locked: bool = True,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._path = Path(path)
        self._clock = clock or _utc_now
        self._lock = RLock()
        _check_non_symlink_target(self._path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        seed = initial_profile if initial_profile is not None else DemoHighGrowthProfile(enabled=False)
        seed.assert_demo_mode(
            execution_mode,
            live_trading_armed=live_trading_armed,
            live_trading_locked=live_trading_locked,
        )
        loaded: DemoHighGrowthProfile | None = None
        updated_at: str | None = None
        if self._path.is_file():
            raw_doc = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw_doc, Mapping) and isinstance(raw_doc.get("profile"), Mapping):
                loaded = DemoHighGrowthProfile.from_wire_dict(raw_doc["profile"])
                raw_ts = raw_doc.get("updated_at")
                updated_at = str(raw_ts) if isinstance(raw_ts, str) and raw_ts.strip() else None
        if loaded is not None:
            try:
                loaded.assert_demo_mode(
                    execution_mode,
                    live_trading_armed=live_trading_armed,
                    live_trading_locked=live_trading_locked,
                )
            except ContractError:
                loaded = DemoHighGrowthProfile(enabled=False)
        self._profile = loaded if loaded is not None else seed
        self._updated_at = updated_at or _iso_utc(self._clock())

    @property
    def path(self) -> Path:
        return self._path

    def profile(self) -> DemoHighGrowthProfile:
        with self._lock:
            return self._profile

    def update(
        self,
        profile: DemoHighGrowthProfile,
        *,
        execution_mode: Any = "DEMO",
        live_trading_armed: bool = False,
        live_trading_locked: bool = True,
    ) -> DemoHighGrowthProfile:
        if not isinstance(profile, DemoHighGrowthProfile):
            raise ContractError("profile must be a DemoHighGrowthProfile")
        profile.assert_demo_mode(
            execution_mode,
            live_trading_armed=live_trading_armed,
            live_trading_locked=live_trading_locked,
        )
        ts = _iso_utc(self._clock())
        payload = json.dumps(
            {
                "schema": DEMO_HIGH_GROWTH_SCHEMA,
                "profile": {k: profile.to_wire_dict()[k] for k in sorted(_ALLOWED_WIRE_KEYS)},
                "updated_at": ts,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"
        with self._lock:
            _check_non_symlink_target(self._path)
            tmp = self._path.with_name(f".{self._path.name}.tmp.{os.getpid()}")
            tmp.write_bytes(payload.encode("utf-8"))
            if os.name == "posix":
                os.chmod(tmp, 0o600)
            os.replace(tmp, self._path)
            if os.name == "posix":
                os.chmod(self._path, 0o600)
            self._profile = profile
            self._updated_at = ts
            return self._profile

    def snapshot(
        self,
        *,
        execution_mode: Any = "DEMO",
        owner_controls_allowed: bool = False,
        session_scope: str = "UNBOUND",
    ) -> dict[str, Any]:
        with self._lock:
            doc = self._profile.to_wire_dict()
            raw_mode = getattr(execution_mode, "value", execution_mode)
            mode_norm = str(raw_mode or "DEMO").strip().upper() or "DEMO"
            doc["execution_mode"] = mode_norm
            doc["live_mode_blocked"] = mode_norm != "DEMO"
            doc["owner_controls_allowed"] = bool(owner_controls_allowed) and (mode_norm == "DEMO")
            doc["session_scope"] = str(session_scope or "UNBOUND")
            doc["updated_at"] = self._updated_at
            return doc


__all__ = [
    "DEMO_HIGH_GROWTH_BE_SCALE",
    "DEMO_HIGH_GROWTH_DAILY_GOAL_PCT",
    "DEMO_HIGH_GROWTH_DAILY_LOSS_BRAKE_PCT",
    "DEMO_HIGH_GROWTH_DEFAULT_RISK_PCT",
    "DEMO_HIGH_GROWTH_FORBIDDEN_LIVE_CODE",
    "DEMO_HIGH_GROWTH_MAX_DRAWDOWN_PCT",
    "DEMO_HIGH_GROWTH_MAX_POST_LOSS_COOLDOWN_SECONDS",
    "DEMO_HIGH_GROWTH_MAX_RISK_PCT",
    "DEMO_HIGH_GROWTH_POST_LOSS_COOLDOWN_SECONDS",
    "DEMO_HIGH_GROWTH_SCHEMA",
    "DEMO_HIGH_GROWTH_SWEEP_RATIO",
    "DEMO_HIGH_GROWTH_TP_SCALE",
    "DEMO_HIGH_GROWTH_TRAIL_SCALE",
    "DemoHighGrowthProfile",
    "DemoHighGrowthProfileStore",
    "ENV_DEMO_HIGH_GROWTH_PROFILE",
    "resolve_demo_high_growth_profile_from_environ",
]
