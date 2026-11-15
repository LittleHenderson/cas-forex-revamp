"""Future merged-overlay controller tests. Public fakes only. NOT_RUN."""
import unittest

from cas_forex_operational_contracts.common import ContractError
from cas_forex_revamp.composition.operational_release import ControllerReleaseBoundary
from test_nr12_consumption import NR12Fixture


class ControllerBoundaryTests(NR12Fixture):
    def boundary(self, private, guard=lambda: None):
        return ControllerReleaseBoundary(consumer=self.consumer, checkpoint_client=self.client,
            read_private_once=private, continuation_guard=guard)

    def test_boundary_never_reads_private_on_lost_checkpoint_response(self):
        seen = []
        boundary = self.boundary(lambda: seen.append("private"))
        self.client.failure = TimeoutError("public loss")
        with self.assertRaises(ContractError): boundary.open_once(self.prep, now=self.dependencies.clock())
        self.assertEqual(seen, [])

    def test_boundary_does_not_treat_retained_success_as_capability(self):
        self.consume()
        self.consumer.expose_once(consume_attempt_id=self.prep["consume_attempt_id"], private_action=lambda: None)
        seen = []
        boundary = self.boundary(lambda: seen.append("private"))
        with self.assertRaises(ContractError): boundary.open_once(self.prep, now=self.dependencies.clock())
        self.assertEqual(seen, [])

    def test_boundary_continuation_uses_existing_window(self):
        seen = []
        guard_state = {"valid": True}
        def guard():
            if not guard_state["valid"]:
                raise ContractError("EXPIRED")
        boundary = self.boundary(lambda: "public fake private document", guard)
        boundary.open_once(self.prep, now=self.dependencies.clock())
        self.assertEqual(boundary.current_packet(lambda: seen.append("one")), None)
        guard_state["valid"] = False
        with self.assertRaises(ContractError): boundary.current_packet(lambda: seen.append("two"))
        guard_state["valid"] = True
        with self.assertRaises(ContractError): boundary.current_packet(lambda: seen.append("three"))
        self.assertEqual(seen, ["one"])

    def test_boundary_ambiguous_private_callback_is_never_repeated(self):
        seen = []
        def private():
            seen.append("entered")
            raise RuntimeError("public fake private callback loss")
        boundary = self.boundary(private)
        with self.assertRaises(ContractError): boundary.open_once(self.prep, now=self.dependencies.clock())
        with self.assertRaises(ContractError): boundary.open_once(self.prep, now=self.dependencies.clock())
        self.assertEqual(seen, ["entered"])
