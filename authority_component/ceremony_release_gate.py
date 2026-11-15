"""Reviewed Stage B Custody Ceremony Release Gate (Successor to B09 Placeholder).

Preserves authority_component/release_gate.py (RELEASE_ENABLED = False) and
authority_provider.py (RELEASE_ENABLED = False) untouched for Phase 1-4 non-release
denial guarantees, while gating the dedicated Stage B ceremony driver behind
cryptographic Ed25519 verification via AuthorityProvider + PinnedEd25519Verifier.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

CEREMONY_RELEASE_ENABLED = True


def require_ceremony_release_enabled(
    *,
    bundle_dir: Path,
    source_root: Path,
    now: datetime | None = None,
    require_pinned_cryptography: bool = True,
) -> dict[str, Any]:
    """Verify Ed25519-signed Owner Stage B Custody Ceremony authority bundle before release."""
    if CEREMONY_RELEASE_ENABLED is not True:
        raise RuntimeError("B09_CEREMONY_RELEASE_DISABLED: Stage B ceremony gate is closed")
    src_root = Path(source_root).resolve()
    if str(src_root) not in sys.path:
        sys.path.insert(0, str(src_root))
    from ceremony_generator import maybe_prepend_guest_python_site, verify_ceremony_authority_bundle

    bdir = Path(bundle_dir).resolve()
    guest_base = bdir.parent if bdir.name in ("ceremony", "ceremony_bundle") else bdir
    maybe_prepend_guest_python_site(guest_base)
    check_now = now if now is not None else datetime.now(timezone.utc)
    result = verify_ceremony_authority_bundle(
        bdir,
        source_root=src_root,
        now=check_now,
        require_pinned_cryptography=require_pinned_cryptography,
    )
    if result.get("authenticated_count", 0) < 16:
        raise RuntimeError("CEREMONY_ATTESTATIONS_INCOMPLETE: fewer than 16 authenticated Ed25519 records")
    return result
