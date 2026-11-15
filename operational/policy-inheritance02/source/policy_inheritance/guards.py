"""Pure clock/appointment/envelope-shape rules, never signature authentication."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from .contract import Contract, SPEC_SHA256, canonical_bytes, digest, utc
from .errors import require


def micros(delta: timedelta) -> int:
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def stamp_le(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return utc(left["utc"]) <= utc(right["utc"]) and left["boottime_ns"] <= right["boottime_ns"]


def stamp_lt(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return utc(left["utc"]) < utc(right["utc"]) and left["boottime_ns"] < right["boottime_ns"]


@dataclass(frozen=True)
class PublicGuardSample:
    """Untrusted public analysis premises; not an authenticated clock/authority read.

    JSON bytes prevent callback/caller mutation after construction. There is no
    operational conversion or 'verified=true' field in this type.
    """

    now_json: bytes
    domain_json: bytes
    interval_json: bytes


class GuardModel:
    def __init__(self, contract: Contract, appointment: dict[str, Any],
                 budget: dict[str, Any], *, selected_scope: dict[str, Any],
                 plan_sha256: str) -> None:
        for name, value in [("Appointment", appointment), ("SetupBudget", budget),
                            ("Scope", selected_scope)]:
            contract.validate(name, value)
        require(selected_scope["method_spec_sha256"] == SPEC_SHA256,
                "CONTEXT_MISMATCH", "scope.method_spec")
        require(appointment["scope"] == selected_scope
                and budget["binding"]["scope"] == selected_scope,
                "CONTEXT_MISMATCH", "scope")
        require(budget["binding"]["appointment_sha256"] == digest(canonical_bytes(appointment)),
                "CONTEXT_MISMATCH", "appointment.pin")
        require(appointment["coverage_plan_sha256"] == budget["coverage_plan_sha256"] == plan_sha256,
                "CONTEXT_MISMATCH", "coverage.pin")
        require(appointment["clock_domain"] == budget["clock_domain"],
                "CLOCK_DOMAIN_UNSUPPORTED", "budget.clock")
        start, outer, deadline = budget["started"], budget["outer_deadline"], budget["deadline"]
        start_utc, outer_utc = utc(start["utc"]), utc(outer["utc"])
        expected_utc = outer_utc if micros(outer_utc - start_utc) <= 180_000_000 else start_utc + timedelta(seconds=180)
        expected_ns = min(start["boottime_ns"] + 180_000_000_000, outer["boottime_ns"])
        require(utc(deadline["utc"]) == expected_utc and deadline["boottime_ns"] == expected_ns
                and stamp_lt(start, deadline), "BUDGET_RESET_ATTEMPT", "budget.deadline")
        principals = appointment["principals"]
        ids = [p["principal_id"] for p in principals]
        keys = [p["signer_public_sha256"] for p in principals]
        roles = [p["role"] for p in principals]
        core_roles = {"TRUSTED_CONTROLLER_WITNESS", "INDEPENDENT_SETUP_CONSUMER",
                      "INDEPENDENT_CHECKPOINT_CUSTODIAN"}
        require(len(set(ids)) == len(ids) and len(set(keys)) == len(keys)
                and len(set(roles)) == len(roles) and core_roles <= set(roles)
                and set(roles) <= core_roles | {"SETUP_BUDGET_ISSUER"},
                "SIGNER_UNAPPOINTED", "appointment.principals")
        allowed = contract.spec["role_purpose_allowlists"]
        for p in principals:
            require(len(set(p["allowed_purposes"])) == len(p["allowed_purposes"])
                    and set(p["allowed_purposes"]) <= set(allowed[p["role"]]),
                    "PURPOSE_MISMATCH", "principal.purposes")
            require(utc(p["not_before_utc"]) <= utc(start["utc"])
                    and utc(deadline["utc"]) <= utc(p["expires_at_utc"]),
                    "APPOINTMENT_INTERVAL_INSUFFICIENT", "principal.interval")
        by_id = {p["principal_id"]: p for p in principals}
        require(appointment["checkpoint_authority_id"] in by_id
                and by_id[appointment["checkpoint_authority_id"]]["role"] == "INDEPENDENT_CHECKPOINT_CUSTODIAN",
                "SIGNER_UNAPPOINTED", "checkpoint.principal")
        require(budget["issuer_id"] in by_id and by_id[budget["issuer_id"]]["role"] in
                {"INDEPENDENT_SETUP_CONSUMER", "SETUP_BUDGET_ISSUER"},
                "SIGNER_UNAPPOINTED", "budget.issuer")
        require(len({appointment["producer_staging_root_id"], appointment["consumer_retention_root_id"],
                     appointment["independent_checkpoint_root_id"]}) == 3,
                "CHECKPOINT_AUTHORITY_UNAVAILABLE", "checkpoint.root_identity")
        require(appointment["approved_runtime_topology_ref"]["artifact_kind"] == "TOPOLOGY_APPROVAL"
                and appointment["watchdog_binding_ref"]["artifact_kind"] == "WATCHDOG_BINDING",
                "PURPOSE_MISMATCH", "appointment.refs")
        require(utc(appointment["not_before_utc"]) <= utc(start["utc"])
                and utc(deadline["utc"]) <= utc(appointment["expires_at_utc"]),
                "APPOINTMENT_INTERVAL_INSUFFICIENT", "appointment.interval")
        self.contract = contract
        self._appointment = copy.deepcopy(appointment)
        self._budget = copy.deepcopy(budget)
        self._principals = copy.deepcopy(by_id)
        self._binding = copy.deepcopy(budget["binding"])
        self.budget_sha256 = digest(canonical_bytes(budget))

    @property
    def binding(self) -> dict[str, Any]:
        return copy.deepcopy(self._binding)

    @property
    def budget(self) -> dict[str, Any]:
        return copy.deepcopy(self._budget)

    @property
    def appointment(self) -> dict[str, Any]:
        return copy.deepcopy(self._appointment)

    def role(self, role_name: str) -> str:
        found = [pid for pid, p in self._principals.items() if p["role"] == role_name]
        require(len(found) == 1, "SIGNER_UNAPPOINTED", "principal.role")
        return found[0]

    def check(self, sample: PublicGuardSample, *, previous_ns: int | None = None,
              dependency_expiries: tuple[dict[str, Any], ...] = ()) -> dict[str, Any]:
        require(type(sample) is PublicGuardSample, "APPOINTMENT_EXPIRED_OR_UNAVAILABLE", "guard_sample")
        now = self.contract.decode("Stamp", sample.now_json)
        domain = self.contract.decode("ClockDomain", sample.domain_json)
        interval = self.contract.decode("AuthenticatedInterval", sample.interval_json)
        b, a = self._budget, self._appointment
        require(domain == b["clock_domain"], "CLOCK_DOMAIN_UNSUPPORTED", "current.domain")
        require(interval["binding"] == self.binding and interval["validated_at"] == now,
                "APPOINTMENT_EXPIRED_OR_UNAVAILABLE", "current.interval")
        require(utc(interval["not_before_utc"]) >= max(utc(x["not_before_utc"]) for x in [a, *self._principals.values()])
                and utc(interval["expires_at_utc"]) <= min(utc(x["expires_at_utc"]) for x in [a, *self._principals.values()]),
                "APPOINTMENT_EXPIRED_OR_UNAVAILABLE", "current.interval_intersection")
        require(utc(interval["not_before_utc"]) <= utc(b["started"]["utc"])
                and utc(b["deadline"]["utc"]) <= utc(interval["expires_at_utc"]),
                "APPOINTMENT_INTERVAL_INSUFFICIENT", "current.interval_coverage")
        require(stamp_le(b["started"], now) and stamp_lt(now, b["deadline"])
                and stamp_lt(now, b["outer_deadline"]), "SETUP_DEADLINE_EXPIRED", "current.time")
        if previous_ns is not None:
            require(now["boottime_ns"] >= previous_ns, "CLOCK_DRIFT", "current.monotonic")
        elapsed_utc_ns = micros(utc(now["utc"]) - utc(b["started"]["utc"])) * 1000
        elapsed_boot_ns = now["boottime_ns"] - b["started"]["boottime_ns"]
        require(abs(elapsed_utc_ns - elapsed_boot_ns) <= 1_000_000_000,
                "CLOCK_DRIFT", "current.anchor")
        for item in [a, *self._principals.values(), interval]:
            require(utc(item["not_before_utc"]) <= utc(now["utc"]) < utc(item["expires_at_utc"]),
                    "APPOINTMENT_EXPIRED_OR_UNAVAILABLE", "current.authority")
        for expiry in dependency_expiries:
            self.contract.validate("Stamp", expiry)
            require(stamp_lt(now, expiry), "AUTHENTICATED_INTERVAL_EXPIRED", "dependency.expiry")
        return now

    def envelope_shape(self, record_bytes: bytes, envelope: dict[str, Any], *,
                       purpose: str, producer_id: str, sample: PublicGuardSample,
                       recorded: dict[str, Any], is_budget: bool = False) -> None:
        """Validate bindings/times only. No Ed25519 verification is performed."""
        self.contract.validate("SignedEnvelope", envelope)
        self.contract.validate("Stamp", recorded)
        now = self.check(sample)
        body = envelope["body"]
        require(producer_id in self._principals, "SIGNER_UNAPPOINTED", "envelope.producer")
        principal = self._principals[producer_id]
        require(body["producer_id"] == producer_id and body["purpose"] == purpose
                and purpose in principal["allowed_purposes"], "PURPOSE_MISMATCH", "envelope.purpose")
        require(body["binding"] == self.binding and envelope["signer_sha256"] == principal["signer_public_sha256"],
                "CONTEXT_MISMATCH", "envelope.binding")
        require(body["record_sha256"] == digest(record_bytes) and body["record_bytes"] == len(record_bytes),
                "RAW_BYTES_MISMATCH", "envelope.record")
        require(body["budget_sha256"] == (None if is_budget else self.budget_sha256),
                "CONTEXT_MISMATCH", "envelope.budget")
        require(stamp_le(self._budget["started"], body["issued"])
                and stamp_le(recorded, body["issued"]) and stamp_le(body["issued"], now)
                and stamp_lt(body["issued"], body["expires"]) and stamp_lt(now, body["expires"])
                and stamp_le(body["expires"], self._budget["deadline"]),
                "AUTHENTICATED_INTERVAL_EXPIRED", "envelope.interval")
        require(utc(body["expires"]["utc"]) <= utc(principal["expires_at_utc"])
                and utc(body["expires"]["utc"]) <= utc(self._appointment["expires_at_utc"]),
                "AUTHENTICATED_INTERVAL_EXPIRED", "envelope.authority_interval")
