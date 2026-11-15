"""Inert shared wire contract package. No operational authority is implemented here."""
from .common import ContractError, DependencyUnavailable, StructuralRecord
from .validation import CONTRACT_BUNDLE_SHA256, validate_record, decode_record

__all__ = ["ContractError", "DependencyUnavailable", "StructuralRecord", "CONTRACT_BUNDLE_SHA256", "validate_record", "decode_record"]
