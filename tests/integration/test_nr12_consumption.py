"""Source-only NR12 regressions. All tests NOT_RUN; fakes are not authority proof."""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cas_forex_operational_contracts.common import ContractError, canonical_bytes, digest
from authority_component.operational_consumer import ControllerReleaseConsumer, ConsumptionContext, ConsumptionHooks
from authority_component.consumption_store import ConsumptionStore, FinalCommit
from authority_component.release_gate import require_release_enabled
from fixtures_nr12 import FakeClient, FakeDependencies, packet, stamp


class NR12Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.data = packet()
        self.store = ConsumptionStore(Path(self.temp.name) / "controller.release-consumption.sqlite3",
            store_id="public-controller-store", binding_sha256=digest(canonical_bytes(self.data["receipt"]["binding"])))
        self.store.initialize(create=True)
        self.dependencies = FakeDependencies(self.data)
        self.consumer = ControllerReleaseConsumer(store=self.store, context=self.data["context"],
            hooks=self.dependencies.hooks(), clock=self.dependencies.clock)
        self.client = FakeClient(self.data["response"])
        self.prep = self.consumer.prepare(self.data["receipt"], self.data["preparation"], now=stamp(130))

    def consume(self):
        return self.consumer.consume_exact(self.prep, checkpoint_client=self.client, now=stamp(130))


class ConsumptionTests(NR12Fixture):
    def test_valid_public_fakes_allow_one_private_callback(self):
        record = self.consume()
        self.assertEqual(record["status"], "CONSUMED_VALID")
        seen = []
        self.consumer.expose_once(consume_attempt_id=self.prep["consume_attempt_id"], private_action=lambda: seen.append("entered"))
        with self.assertRaises(ContractError):
            self.consumer.expose_once(consume_attempt_id=self.prep["consume_attempt_id"], private_action=lambda: seen.append("again"))
        self.assertEqual(seen, ["entered"])
        self.assertEqual(len(self.client.calls), 1)

    def test_exact_request_is_retained_before_transport(self):
        def inspect():
            row = self.store.read(self.prep["consume_attempt_id"])
            self.assertEqual(row["state"], "READ_STARTED")
            self.assertEqual(row["request"], self.data["request"])
        self.client.on_read = inspect
        self.consume()

    def test_repeated_consumption_does_not_send_again(self):
        first = self.consume()
        self.assertEqual(first, self.consume())
        self.assertEqual(len(self.client.calls), 1)

    def test_lost_read_never_resends(self):
        self.client.failure = TimeoutError("public transport loss")
        with self.assertRaises(ContractError): self.consume()
        self.client.failure = None
        self.assertEqual(self.consume()["status"], "UNAVAILABLE")
        self.assertEqual(len(self.client.calls), 1)

    def test_wrong_nonce_rejected(self):
        self.client.response["nonce_hex"] = "f" * 64
        with self.assertRaises(ContractError): self.consume()

    def test_old_issuer_request_hash_rejected(self):
        self.client.response["request_sha256"] = "e" * 64
        with self.assertRaises(ContractError): self.consume()

    def test_newer_abort_head_rejected(self):
        self.client.response["head_sha256"] = "f" * 64
        with self.assertRaises(ContractError): self.consume()

    def test_incomplete_history_rejected(self):
        self.client.response["history"].pop(3)
        with self.assertRaises(ContractError): self.consume()

    def test_duplicate_history_generation_rejected(self):
        self.client.response["history"][4] = deepcopy(self.client.response["history"][3])
        with self.assertRaises(ContractError): self.consume()

    def test_history_body_changed_rejected(self):
        self.client.response["history"][5]["checkpoint_utf8"] += " "
        with self.assertRaises(ContractError): self.consume()

    def test_history_transition_request_hash_mismatch_rejected(self):
        self.client.response["history"][5]["request_sha256"] = "f" * 64
        with self.assertRaises(ContractError): self.consume()

    def test_elapsed_clock_drift_over_one_second_rejected(self):
        self.dependencies.time["boottime_ns"] += 1_000_001_000
        with self.assertRaises(ContractError): self.consume()
        self.assertEqual(self.client.calls, [])

    def test_extra_authority_principal_rejected_before_read(self):
        self.data["authority"]["principal_ids"].append("unselected-extra-principal")
        with self.assertRaises(ContractError): self.consume()
        self.assertEqual(self.client.calls, [])

    def test_shortened_original_budget_rejected_even_when_other_bindings_match(self):
        data = packet(setup_deadline_seconds=179)
        dependencies = FakeDependencies(data)
        other = ConsumptionStore(Path(self.temp.name) / "shortened.release-consumption.sqlite3",
            store_id="shortened-store", binding_sha256=digest(canonical_bytes(data["receipt"]["binding"])))
        other.initialize(create=True)
        consumer = ControllerReleaseConsumer(store=other, context=data["context"],
            hooks=dependencies.hooks(), clock=dependencies.clock)
        with self.assertRaises(ContractError):
            consumer.prepare(data["receipt"], data["preparation"], now=stamp(130))
        self.assertEqual(dependencies.calls, [])

    def test_earlier_original_outer_bound_is_respected(self):
        data = packet(setup_deadline_seconds=175, outer_deadline_seconds=175)
        dependencies = FakeDependencies(data)
        other = ConsumptionStore(Path(self.temp.name) / "outer.release-consumption.sqlite3",
            store_id="outer-store", binding_sha256=digest(canonical_bytes(data["receipt"]["binding"])))
        other.initialize(create=True)
        consumer = ControllerReleaseConsumer(store=other, context=data["context"],
            hooks=dependencies.hooks(), clock=dependencies.clock)
        self.assertEqual(consumer.prepare(data["receipt"], data["preparation"], now=stamp(130)), data["preparation"])

    def test_other_store_rejected(self):
        self.client.response["store_instance_id"] = "foreign-checkpoint-store"
        with self.assertRaises(ContractError): self.consume()

    def test_other_clock_namespace_rejected(self):
        self.client.response["clock_domain"]["time_namespace_inode"] += 1
        with self.assertRaises(ContractError): self.consume()

    def test_future_response_rejected(self):
        self.client.response["observed"] = stamp(131)
        with self.assertRaises(ContractError): self.consume()

    def test_expiry_during_read_prevents_commit_and_private_entry(self):
        self.client.on_read = lambda: setattr(self.dependencies, "time", stamp(170))
        with self.assertRaises(ContractError): self.consume()
        self.assertEqual(self.store.read(self.prep["consume_attempt_id"])["record"]["status"], "UNAVAILABLE")

    def test_authority_changes_during_read_rejects(self):
        self.client.on_read = lambda: self.data["authority"].update(revision=2)
        with self.assertRaises(ContractError): self.consume()

    def test_authority_withdrawal_before_read_rejects(self):
        self.data["authority"]["status"] = "WITHDRAWN"
        with self.assertRaises(ContractError): self.consume()
        self.assertEqual(self.client.calls, [])

    def test_post_commit_failure_spends_without_exposure(self):
        self.dependencies.fail_after = True
        with self.assertRaises(ContractError): self.consume()
        record = self.consumer.read_retained(consume_attempt_id=self.prep["consume_attempt_id"], now=stamp(130))
        self.assertEqual(record["status"], "SPENT_NO_EXPOSURE")
        self.assertIsNotNone(record["committed_at"])
        self.assertIsNone(record["post_commit_checked_at"])

    def test_certificate_callback_mutation_rejected(self):
        self.dependencies.mutate_certificate = True
        with self.assertRaises(ContractError): self.consume()

    def test_reopen_cannot_regain_exposure_capability(self):
        self.consume()
        reopened = ConsumptionStore(self.store.path, store_id=self.store.store_id,
                                    binding_sha256=self.store.binding_sha256)
        reopened.initialize()
        consumer = ControllerReleaseConsumer(store=reopened, context=self.data["context"],
            hooks=self.dependencies.hooks(), clock=self.dependencies.clock)
        retained = consumer.read_retained(consume_attempt_id=self.prep["consume_attempt_id"], now=stamp(130))
        self.assertEqual(retained["status"], "CONSUMED_VALID")
        with self.assertRaises(ContractError):
            consumer.expose_once(consume_attempt_id=self.prep["consume_attempt_id"], private_action=lambda: self.fail("private entered"))

    def test_reopen_prepared_is_audit_only(self):
        reopened = ConsumptionStore(self.store.path, store_id=self.store.store_id,
                                    binding_sha256=self.store.binding_sha256)
        reopened.initialize()
        consumer = ControllerReleaseConsumer(store=reopened, context=self.data["context"],
            hooks=self.dependencies.hooks(), clock=self.dependencies.clock)
        with self.assertRaises(ContractError):
            consumer.consume_exact(self.prep, checkpoint_client=self.client, now=stamp(130))
        self.assertEqual(self.client.calls, [])

    def test_postcommit_expiry_before_private_entry_spends(self):
        self.consume()
        self.dependencies.time = stamp(170)
        with self.assertRaises(ContractError):
            self.consumer.expose_once(consume_attempt_id=self.prep["consume_attempt_id"], private_action=lambda: self.fail("private entered"))
        self.assertEqual(self.store.read(self.prep["consume_attempt_id"])["record"]["status"], "SPENT_NO_EXPOSURE")

    def test_private_callback_exception_is_not_labeled_no_exposure(self):
        self.consume()
        def entered():
            raise RuntimeError("public fake after private entry")
        with self.assertRaises(ContractError) as caught:
            self.consumer.expose_once(consume_attempt_id=self.prep["consume_attempt_id"], private_action=entered)
        self.assertEqual(self.store.read(self.prep["consume_attempt_id"])["state"], "EXPOSURE_STARTED")
        self.assertNotIn("public fake after private entry", str(caught.exception))

    def test_release_gate_remains_hard_disabled(self):
        with self.assertRaises(RuntimeError): require_release_enabled()

    def test_existing_empty_store_is_preserved_on_create(self):
        path = Path(self.temp.name) / "existing.release-consumption.sqlite3"
        path.write_bytes(b"")
        store = ConsumptionStore(path, store_id="new", binding_sha256="1" * 64)
        with self.assertRaises(FileExistsError): store.initialize(create=True)
        self.assertEqual(path.read_bytes(), b"")

    def test_missing_store_is_not_recreated(self):
        path = Path(self.temp.name) / "missing.release-consumption.sqlite3"
        store = ConsumptionStore(path, store_id="new", binding_sha256="1" * 64)
        with self.assertRaises(FileNotFoundError): store.initialize()
        self.assertFalse(path.exists())

    def test_exact_preparation_retry_cannot_change_release_bytes(self):
        changed = deepcopy(self.data["receipt"])
        changed["scope_sha256"] = "d" * 64
        with self.assertRaises(ContractError):
            self.consumer.prepare(changed, self.prep, now=stamp(130))

    def test_different_channel_cannot_reuse_preparation(self):
        changed = deepcopy(self.prep)
        changed["channel_binding_sha256"] = "e" * 64
        with self.assertRaises(ContractError):
            self.consumer.prepare(self.data["receipt"], changed, now=stamp(130))

    def test_boolean_callback_success_is_rejected(self):
        hooks = ConsumptionHooks(lambda *args: True, self.dependencies.authority,
                                 self.dependencies.certificate, self.dependencies.after)
        consumer = ControllerReleaseConsumer(store=self.store, context=self.data["context"], hooks=hooks, clock=self.dependencies.clock)
        with self.assertRaises(ContractError): consumer.prepare(self.data["receipt"], self.prep, now=stamp(130))

    def test_clock_backwards_is_rejected(self):
        self.dependencies.time = stamp(129)
        with self.assertRaises(ContractError): self.consume()

    def test_lost_commit_return_never_resends_or_exposes(self):
        original = FinalCommit.commit
        def lost_ack(slot, record):
            original(slot, record)
            raise OSError("public fake commit return lost")
        with patch.object(FinalCommit, "commit", lost_ack):
            with self.assertRaises(ContractError): self.consume()
        self.assertEqual(self.consume()["status"], "SPENT_NO_EXPOSURE")
        self.assertEqual(len(self.client.calls), 1)
        with self.assertRaises(ContractError):
            self.consumer.expose_once(consume_attempt_id=self.prep["consume_attempt_id"], private_action=lambda: self.fail("private entered"))

    def test_precommit_failure_does_not_invent_commit_time(self):
        with patch.object(FinalCommit, "commit", side_effect=OSError("public fake before commit")):
            with self.assertRaises(ContractError): self.consume()
        record = self.store.read(self.prep["consume_attempt_id"])["record"]
        self.assertIsNone(record["committed_at"])
        self.assertEqual(record["status"], "UNAVAILABLE")

    def test_error_detail_from_selected_dependency_is_redacted(self):
        self.dependencies.fail_before = True
        with self.assertRaises(ContractError) as caught:
            self.consumer.prepare(self.data["receipt"], self.prep, now=stamp(130))
        self.assertNotIn("public fake dependency failure", str(caught.exception))

    def test_no_transition_can_restore_prepared_state(self):
        record = self.consume()
        with self.assertRaises(ContractError):
            self.store.transition(self.prep["consume_attempt_id"], expected=("CHECKED",), state="PREPARED", record=record)
