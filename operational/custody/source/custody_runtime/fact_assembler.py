"""Resolve original protected facts; never create expectations or observations."""
from cas_forex_operational_contracts import common, protected
from .selection_provider import require, same, fresh


class FactAssembler:
    def __init__(self, *, resolver, publishers, finalization_use, shape_validator, clock, current_authority_guard, original_deadline):
        self.resolver = resolver
        self.publishers = common.decode_canonical(common.canonical_bytes(publishers))
        self.finalization_use = common.decode_canonical(common.canonical_bytes(finalization_use))
        self.mapper = shape_validator
        self.clock, self.guard = clock, current_authority_guard
        self.deadline = common.decode_canonical(common.canonical_bytes(original_deadline))

    def _now(self, now): return fresh(self.clock, self.guard, now, self.deadline)

    def fact(self, entry, *, binding, now):
        now = self._now(now)
        entry = protected.validate("RetainedFactUse", entry).payload()
        use = entry["fact"]
        require(use["required_use"] == "RETAINED_EVALUATION" and use["reference"]["record_kind"] == "RETAINED_FACT"
                and use["reference"]["purpose"] == "retained-"+entry["kind"].lower(), "RETAINED_FACT_ROUTE")
        raw = self.resolver.resolve(use, selection=self.publishers, now=now)
        fact = protected.decode("RetainedFact2", raw, shape_validator=self.mapper).payload()
        require(same(fact["binding"], binding) and fact["kind"] == entry["kind"], "RETAINED_FACT_BINDING")
        self._now(now)
        return fact

    def assemble_original(self, facts, *, binding, now):
        now = self._now(now)
        require(type(facts) is tuple and 0 < len(facts) <= 4096, "FACT_DENOMINATOR")
        records = [protected.validate("RetainedFactUse", entry).payload() for entry in facts]
        seen, attempts, outcomes, steps = set(), [], set(), set()
        for entry in records:
            fact = self.fact(entry, binding=binding, now=now)
            require(fact["record_id"] not in seen, "DUPLICATE_ORIGINAL_FACT"); seen.add(fact["record_id"])
            value = fact["payload"]
            if fact["kind"] == "ATTEMPT":
                require(value["attempt_id"] not in attempts, "DUPLICATE_ORIGINAL_ATTEMPT"); attempts.append(value["attempt_id"])
                require(value["attempt_index"] == 1, "RETRY_NOT_ALLOCATED")
            elif fact["kind"] == "OUTCOME":
                require(value["attempt_id"] not in outcomes, "ORIGINAL_OUTCOME_REPLACED"); outcomes.add(value["attempt_id"])
            else:
                key = (fact["step_id"], fact["kind"])
                require(key not in steps, "AMBIGUOUS_ORIGINAL_FACT"); steps.add(key)
        require(len(attempts) <= 32 and set(attempts) == outcomes, "ORIGINAL_ATTEMPT_ACCOUNTING")
        require(self.finalization_use["required_use"] == "RETAINED_EVALUATION"
                and self.finalization_use["reference"]["record_kind"] == "BUNDLE_FINALIZATION"
                and self.finalization_use["reference"]["purpose"] == "retained-bundle-finalization", "FINALIZATION_ROUTE")
        final = protected.decode("BundleFinalization2", self.resolver.resolve(self.finalization_use, selection=self.publishers, now=now)).payload()
        require(same(final["binding"], binding) and final["original_attempt_order"] == attempts
                and final["records_content_sha256"] == common.digest(common.canonical_bytes(records, limit=common.MAX_GRAPH)), "FINALIZATION_ORIGINALS")
        require(common.utc(final["terminal_at_utc"]) <= common.utc(now["utc"]), "FUTURE_FINALIZATION")
        result = {"format": "forex.retained-attempt-bundle/2", "binding": binding, "records": records, "finalization": self.finalization_use}
        self._now(now)
        return protected.validate("RetainedBundle2", result).payload()
