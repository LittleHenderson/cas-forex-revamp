"""Fail-closed operational boundary. There is deliberately no activation switch.

These methods must be replaced only by a separately reviewed implementation.
No local in-memory fixture or analysis result can be upgraded into authority.
"""

from .errors import UnsupportedAuthority


class OperationalAdapters:
    def authenticate_appointment(self, *args, **kwargs):
        raise UnsupportedAuthority("authenticate_appointment")

    def verify_ed25519(self, *args, **kwargs):
        raise UnsupportedAuthority("verify_ed25519")

    def capture_actual_role(self, *args, **kwargs):
        raise UnsupportedAuthority("capture_actual_role")

    def decode_actual_evidence(self, *args, **kwargs):
        raise UnsupportedAuthority("decode_actual_evidence")

    def reserve_original_setup(self, *args, **kwargs):
        raise UnsupportedAuthority("reserve_original_setup")

    def checkpoint_compare_and_append(self, *args, **kwargs):
        raise UnsupportedAuthority("checkpoint_compare_and_append")

    def checkpoint_read_current(self, *args, **kwargs):
        raise UnsupportedAuthority("checkpoint_read_current")

    def retain_durably(self, *args, **kwargs):
        raise UnsupportedAuthority("retain_durably")

    def issue_setup_budget(self, *args, **kwargs):
        raise UnsupportedAuthority("issue_setup_budget")

    def expose_output(self, *args, **kwargs):
        raise UnsupportedAuthority("expose_output")

    def release_consume(self, *args, **kwargs):
        raise UnsupportedAuthority("release_consume")

    def start_watchdog(self, *args, **kwargs):
        raise UnsupportedAuthority("start_watchdog")
