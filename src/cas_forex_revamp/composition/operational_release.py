"""Controller entry to NR12. No role spawn or private read on construction.

This replaces the *release boundary* of the predecessor controller only when
explicitly composed with the selected lane implementations. It deliberately
does not call the predecessor broad-denial adapter or the old release ledger.
The operational driver remains disabled pending the complete reviewed wiring.
"""
from __future__ import annotations

from threading import Lock
from typing import Callable

from cas_forex_operational_contracts import checkpoint, method, release
from cas_forex_operational_contracts.common import ContractError, require
from authority_component.operational_consumer import ControllerReleaseConsumer


class ControllerReleaseBoundary:
    def __init__(self, *, consumer: ControllerReleaseConsumer,
                 checkpoint_client: checkpoint.CheckpointClientPort,
                 read_private_once: Callable[[], object],
                 continuation_guard: Callable[[], None]) -> None:
        require(isinstance(consumer, ControllerReleaseConsumer), "SELECTED_CONSUMER_REQUIRED")
        require(callable(read_private_once) and callable(continuation_guard), "MISSING_CONTROLLER_DEPENDENCY")
        self._consumer, self._client = consumer, checkpoint_client
        self._read_private, self._continuation_guard = read_private_once, continuation_guard
        self._attempted, self._active = False, False
        self._lock = Lock()

    def open_once(self, preparation: release.ConsumptionPreparation, *, now: method.Stamp):
        """No private input is read until fresh consume plus postcommit checks."""
        with self._lock:
            require(not self._attempted, "CONTROLLER_RELEASE_ALREADY_ATTEMPTED")
            self._attempted = True
            record = self._consumer.consume_exact(preparation, checkpoint_client=self._client, now=now)
            require(record["status"] == "CONSUMED_VALID", "CONTROLLER_RELEASE_UNAVAILABLE")
            # Retained CONSUMED_VALID data cannot pass expose_once: a live,
            # unspent capability minted by this consume invocation is required.
            def expose():
                require(self._continuation_guard() is None, "CONTINUATION_GUARD")
                value = self._read_private()
                require(self._continuation_guard() is None, "CONTINUATION_GUARD")
                return value
            value = self._consumer.expose_once(consume_attempt_id=record["consume_attempt_id"], private_action=expose)
            self._active = True
            return value

    def current_packet(self, selected_action: Callable[[], object]):
        """Controller-owned action only; never accept a callback from a message.

        Continuation uses the already-fixed model/global window and current
        role/channel guards. It does not reread an expired setup admission or
        grant a new 180-second setup allowance.
        """
        with self._lock:
            require(self._active, "CONTROLLER_NOT_RELEASED")
            try:
                require(self._continuation_guard() is None, "CONTINUATION_GUARD")
                value = selected_action()
                require(self._continuation_guard() is None, "CONTINUATION_GUARD")
                return value
            except Exception:
                self._active = False
                raise ContractError("CONTROLLER_CONTINUATION_STOPPED") from None

    def close(self) -> None:
        with self._lock:
            self._active = False
