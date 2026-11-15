"""Fixed public errors; never include input bytes, keys or external exceptions."""


class ContractViolation(ValueError):
    def __init__(self, code: str, field: str = "record") -> None:
        self.code = code
        self.field = field
        super().__init__(f"{code}: {field}")


class UnsupportedAuthority(RuntimeError):
    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(f"UNSUPPORTED_AUTHORITY: {operation}")


def require(condition: bool, code: str, field: str = "record") -> None:
    if not condition:
        raise ContractViolation(code, field)
