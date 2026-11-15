"""SQLite mechanism regressions only. Authored NOT_RUN; no isolation claim."""
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
from cas_forex_operational_contracts.common import canonical_bytes, digest
from cas_forex_authority.authentication import AuthorityError, ZERO, ref
from cas_forex_authority.checkpoint_client import CheckpointClient
from cas_forex_authority.method_runtime import MethodRuntime
from support import fixture, sqlite_stores, FixtureTransport, stamp


class CheckpointTests(TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.f = fixture(); self.consumer, self.checkpoint = sqlite_stores(self.f, self.temp.name)
        self.transport = FixtureTransport(self.f, self.checkpoint)
        self.client = CheckpointClient(authentication=self.f.auth, transport=self.transport, signer=self.f.consumer_signer, caller_id="consumer")
        self.runtime = self.make_runtime()

    def make_runtime(self):
        return MethodRuntime(authentication=self.f.auth, store=self.consumer, checkpoint_client=self.client,
                             signer=self.f.consumer_signer, plan=self.f.plan, evidence=self.consumer,
                             event_envelope=lambda _: (_ for _ in ()).throw(AssertionError("unexpected event lookup")))

    def reserve(self): return self.runtime.reserve(self.f.initial, self.f.budget, now=self.f.guard.check())

    def read(self):
        request = self.client.request("READ_CURRENT", {"minimum_generation": 0, "minimum_head_sha256": ZERO, "consumption_binding": None}, now=self.f.guard.check())
        return self.client.read_current(request, now=self.f.guard.check())

    def test_reservation_and_claim_are_two_independent_generations(self):
        output = self.reserve(); current = self.read()
        self.assertEqual(current["generation"], 2); self.assertEqual(output["kind"], "SETUP_BUDGET")
        self.assertEqual([x["operation"] for x in self.transport.calls].count("ADVANCE"), 2)
        self.assertEqual(self.consumer.resolve(output["body_ref"]), canonical_bytes(self.f.budget))
        self.assertNotEqual(self.consumer.database.path, self.checkpoint.database.path)

    def test_repeated_reserve_recovers_exact_without_new_advance(self):
        first = self.reserve(); before = len([x for x in self.transport.calls if x["operation"] == "ADVANCE"])
        self.assertEqual(self.reserve(), first)
        self.assertEqual(len([x for x in self.transport.calls if x["operation"] == "ADVANCE"]), before)

    def test_reopen_preserves_prepared_output_identity(self):
        first = self.reserve(); self.consumer.reopen(); self.checkpoint.reopen(); self.runtime = self.make_runtime()
        self.assertEqual(self.runtime.recover_exact({k:first[k] for k in ("kind","body_ref","attestation_ref")}, now=self.f.guard.check()), first)

    def test_lost_reservation_response_does_not_remint_budget(self):
        self.transport.lose_after_commit = True
        with self.assertRaises(TimeoutError): self.reserve()
        self.assertEqual(self.read()["generation"], 1)
        before = len(self.f.consumer_signer.calls)
        with self.assertRaises(AuthorityError): self.reserve()
        self.assertEqual(len(self.f.consumer_signer.calls), before)
        self.assertEqual(len([x for x in self.transport.calls if x["operation"] == "ADVANCE"]), 1)

    def test_lost_claim_response_recovers_exact_claim(self):
        original = self.transport.exchange
        def exchange(request, *, deadline):
            if 'BUDGET_CLAIM' in request["body_utf8"] and 'ADVANCE' in request["body_utf8"]:
                self.transport.lose_after_commit = True
            return original(request, deadline=deadline)
        self.transport.exchange = exchange
        with self.assertRaises(TimeoutError): self.reserve()
        self.transport.exchange = original
        before = len([x for x in self.transport.calls if x["operation"] == "ADVANCE"])
        result = self.reserve()
        self.assertEqual(result["kind"], "SETUP_BUDGET"); self.assertEqual(self.read()["generation"], 2)
        self.assertEqual(len([x for x in self.transport.calls if x["operation"] == "ADVANCE"]), before)

    def test_changed_budget_cannot_reuse_original_key(self):
        self.reserve(); changed = deepcopy(self.f.budget); changed["budget_id"] = "other"
        with self.assertRaises(AuthorityError): self.runtime.reserve(self.f.initial, changed, now=self.f.guard.check())
        self.assertEqual(self.read()["generation"], 2)

    def test_future_minimum_head_fails_closed(self):
        self.reserve(); request = self.client.request("READ_CURRENT", {"minimum_generation": 3, "minimum_head_sha256": "a"*64, "consumption_binding": None}, now=self.f.guard.check())
        with self.assertRaises(AuthorityError): self.client.read_current(request, now=self.f.guard.check())

    def test_deleted_local_preparation_detects_independent_ahead_head(self):
        self.reserve()
        with self.consumer.database.transaction() as db: db.execute("DELETE FROM preparations WHERE logical_id='budget'")
        with self.assertRaises(AuthorityError): self.consumer.assert_history(self.read())

    def test_exact_retention_rejects_changed_content(self):
        raw=b"public retained bytes"; reference=ref(raw,"NATIVE_CAPTURE_BYTES")
        self.consumer.retain_exact(reference,raw)
        with self.assertRaises(AuthorityError): self.consumer.retain_exact(reference,b"changed")
        self.assertEqual(self.consumer.resolve(reference),raw)

    def test_missing_database_is_not_initialized_on_read(self):
        missing = self.consumer.database.path.with_name("missing.sqlite3")
        self.consumer.database.path = missing
        with self.assertRaises(Exception): self.consumer.reopen()
        self.assertFalse(missing.exists())

    def test_expired_recovery_does_not_expose_stored_signature(self):
        first=self.reserve(); self.f.clock.now=stamp(180)
        with self.assertRaises(AuthorityError): self.runtime.recover_exact({k:first[k] for k in ("kind","body_ref","attestation_ref")},now=stamp(180))

    def test_incomplete_prefix_cannot_decide(self):
        self.reserve()
        with self.assertRaises(AuthorityError): self.runtime.decide(binding=self.f.binding,budget_sha256=digest(canonical_bytes(self.f.budget)),now=self.f.guard.check())
        self.assertEqual(self.read()["generation"],2)

    def test_arbitrary_positive_semantics_callback_is_not_accepted(self):
        with self.assertRaises(AuthorityError):
            MethodRuntime(authentication=self.f.auth,store=self.consumer,checkpoint_client=self.client,signer=self.f.consumer_signer,
                          plan=self.f.plan,evidence=self.consumer,event_envelope=lambda _:None,validate_event=lambda **_:(),validate_sealed=lambda **_:{})

    def test_omitted_mandatory_dependency_rejects_before_reservation(self):
        plan=deepcopy(self.f.plan); plan["slots"][11]["after_slots"]=[]
        with self.assertRaises(AuthorityError): MethodRuntime._validate_plan(None,plan)

    def test_two_competing_claims_cannot_advance_same_checkpoint_head(self):
        # Public fixture exercises independent SQLite transactions only.
        # It is not a process-isolation or real-signature test.
        from concurrent.futures import ThreadPoolExecutor
        self.reserve()
        prior=self.read(); budget=self.f.budget
        prepared=self.consumer.prepared(logical_id="budget")[0]
        first=deepcopy(prepared["attachments"])
        from cas_forex_operational_contracts.common import decode_canonical
        from cas_forex_operational_contracts import checkpoint as ck
        original=decode_canonical(first["transition_utf8"].encode())
        # Exact committed replay must retain generation 2. A changed transition
        # at the same old expected head loses the compare-and-append.
        changed=deepcopy(original);changed["transition_id"]="competing-claim"
        raw=canonical_bytes(changed)
        envelope=self.f.auth.attest(raw,purpose="policy-inheritance-checkpoint-transition-v3",
            producer_id="consumer",signer=self.f.consumer_signer,now=self.f.guard.check())
        second=deepcopy(first);second["transition_utf8"]=raw.decode();second["transition_attestation_utf8"]=canonical_bytes(envelope).decode()
        requests=[self.client.request("ADVANCE",body,now=self.f.guard.check()) for body in (first,second)]
        def append(request):
            try:return self.checkpoint.compare_and_append(request,authenticated_caller=self.f.access["callers"][0],now=self.f.guard.check())["generation"]
            except AuthorityError:return "REJECTED"
        with ThreadPoolExecutor(max_workers=2) as workers:results=list(workers.map(append,requests))
        self.assertEqual(results,[2,"REJECTED"])
        self.assertEqual(self.read()["generation"],2)

    def test_consumed_advance_claim_cannot_be_reused(self):
        self.reserve(); prepared=self.consumer.prepared(logical_id="budget")[0]
        with self.assertRaises(AuthorityError):self.consumer.claim_advance(prepared["transition"]["transition_id"])

    def test_reopened_store_rejects_same_revision_authority_rollback(self):
        self.reserve();self.f.status["revision"]=5;self.read()
        self.checkpoint.reopen();self.f.auth._revision=-1;self.f.auth._status_hash=None;self.f.status["revision"]=4
        with self.assertRaises(AuthorityError):self.read()
