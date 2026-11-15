"""Concrete lane composition, with all initialization and stepping explicit."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from ..contracts import AuthorizedCommand, CockpitProjection, DecisionAdapter, DecisionOrigin
from ..core import CoreCoordinator, InstrumentPolicy, OwnerVerifier, RiskPolicy, SQLiteStore
from ..operator.decisions import OperatorSession
from ..venue import FaultSchedule, JournalCheckpoint, SQLiteVenue
from .application import RuntimeConfig
from .rehearsal import RehearsalWiring


@dataclass(frozen=True, slots=True)
class InertSimulation:
    config: RuntimeConfig
    core: CoreCoordinator
    venue: SQLiteVenue
    operator: OperatorSession
    wiring: RehearsalWiring
    core_path: Path
    venue_path: Path
    initial_projection: CockpitProjection
    initialization_performed_by_composition: bool = False
    workers_started_by_composition: bool = False


def assemble_inert_simulation(
    config: RuntimeConfig, *, policy: RiskPolicy, instruments: tuple[InstrumentPolicy, ...],
    decision_adapter: DecisionAdapter, clock: Callable[[], datetime],
    owner_verifier: OwnerVerifier | None = None,
    expected_origin: DecisionOrigin = DecisionOrigin.SCRIPTED,
    faults: FaultSchedule | None = None, max_decisions: int = 256,
    minimum_venue_sequence: int = 0, venue_checkpoint: JournalCheckpoint | None = None,
    valve_gate: object | None = None,
) -> InertSimulation:
    """Construct reviewed new lanes; do not mkdir, initialize, read or run them.

    The two fixed file names establish separate intended stores. The approved
    execution bootstrap must additionally reject symlinks/hardlinks/aliases and
    establish actual path isolation before initializing. No filesystem check is
    hidden in this inert constructor and no owner verifier defaults to allow.
    """
    if not isinstance(config, RuntimeConfig):
        raise TypeError("RuntimeConfig required")
    core_path = config.state_directory / "account.core.sqlite3"
    venue_path = config.state_directory / "account.venue.sqlite3"
    core: CoreCoordinator | None = None

    def verify_reviewed_close(command: AuthorizedCommand, now: datetime) -> bool:
        # Called only from venue acceptance, after core dispatch commits.
        # A read error propagates as unavailable; it cannot create permission.
        return core is not None and core.verify_owner_close(command, now)

    venue = SQLiteVenue(venue_path, faults=faults, owner_close_verifier=verify_reviewed_close,
                        minimum_sequence=minimum_venue_sequence, checkpoint_anchor=venue_checkpoint)
    core = CoreCoordinator(scope=config.scope, store=SQLiteStore(core_path), venue=venue,
                           policy=policy, instruments=instruments, owner_verifier=owner_verifier)
    operator = OperatorSession(decision_adapter,
                               current_state=lambda: core.current_state(config.scope.key, now=clock()),
                               clock=clock, max_decisions=max_decisions)
    wiring = RehearsalWiring(config, core=core, state_reader=core, venue=venue,
                            operator=operator, clock=clock, expected_origin=expected_origin, valve_gate=valve_gate)
    return InertSimulation(config, core, venue, operator, wiring, core_path, venue_path,
                           CockpitProjection(config.scope))
