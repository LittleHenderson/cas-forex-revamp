"""Explicit, inert composition. No application instance exists at import time."""

from .application import InertApplication, RuntimeConfig, compose_inert

__all__ = ["InertApplication", "RuntimeConfig", "compose_inert"]
