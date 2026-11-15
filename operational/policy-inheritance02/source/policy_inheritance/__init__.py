"""Pure design05 analysis. Importing this package performs no I/O or activation.

No object exported here is a runtime authority, signature verifier or release port.
"""

from .contract import Contract, canonical_bytes, decode_canonical, digest
from .errors import ContractViolation, UnsupportedAuthority
from .plan import Coverage

__all__ = ["Contract", "ContractViolation", "Coverage", "UnsupportedAuthority",
           "canonical_bytes", "decode_canonical", "digest"]
