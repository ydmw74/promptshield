from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    INFO = 0
    WARN = 1
    BLOCK = 2

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        normalized = value.strip().lower()
        if normalized == "info":
            return cls.INFO
        if normalized == "warn":
            return cls.WARN
        if normalized == "block":
            return cls.BLOCK
        raise ValueError(f"Unknown severity: {value}")

    def to_str(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    description: str
    pattern: str
    severity: Severity
    tags: list[str]
    contexts: list[str]
    flags: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    context: str
    view: str
    match: str
    start: int
    end: int
    tags: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Decision:
    action: str
    blocked: bool
    highest_severity: str
    matched_rule_ids: list[str]
    findings_count: int
    sanitized_text: str | None
    notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
