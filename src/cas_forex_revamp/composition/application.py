"""Source scaffold: assembling this object opens no store and starts no loop."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..contracts import CockpitProjection, ContractError, RunScope


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    scope: RunScope
    state_directory: Path
    decision_atlas_enabled: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.scope, RunScope):
            raise ContractError("runtime scope must use the shared RunScope")
        if not isinstance(self.state_directory, Path) or not self.state_directory.is_absolute():
            raise ContractError("state_directory must be an explicit absolute Path")
        if type(self.decision_atlas_enabled) is not bool:
            raise ContractError("decision_atlas_enabled must be a boolean")


@dataclass(frozen=True, slots=True)
class InertApplication:
    config: RuntimeConfig
    initial_projection: CockpitProjection
    core_attached: bool = False
    venue_attached: bool = False
    operator_attached: bool = False
    workers_started: bool = False


def compose_inert(config: RuntimeConfig) -> InertApplication:
    """No database, socket, thread, subprocess, model or prior runtime-state read.

    A later explicit integration step must wire reviewed lane implementations.
    Unknown permissions reflect lack of observed system-wide fence state, even
    though this newly composed object has no active admissions or workers.
    """
    if not isinstance(config, RuntimeConfig):
        raise ContractError("compose_inert requires RuntimeConfig")
    return InertApplication(config=config, initial_projection=CockpitProjection(scope=config.scope))
