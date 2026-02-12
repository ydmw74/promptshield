from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .types import Rule, Severity

_FLAG_MAP = {
    "i": re.IGNORECASE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
}


@dataclass(frozen=True)
class CompiledRule:
    rule: Rule
    regex: re.Pattern[str]


def _read_json(path: Path) -> list[dict]:
    raw = path.read_text(encoding="utf-8")
    payload = json.loads(raw)
    if not isinstance(payload, list):
        raise ValueError(f"Rule file must be a list: {path}")
    return payload


def load_rules(path: str | Path) -> list[Rule]:
    p = Path(path)
    payload = _read_json(p)
    rules: list[Rule] = []

    for idx, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"Rule at index {idx} is not an object")

        required = ("id", "name", "description", "pattern", "severity")
        missing = [key for key in required if key not in item]
        if missing:
            raise ValueError(f"Rule {idx} missing keys: {missing}")

        rule = Rule(
            id=str(item["id"]),
            name=str(item["name"]),
            description=str(item["description"]),
            pattern=str(item["pattern"]),
            severity=Severity.from_str(str(item["severity"])),
            tags=[str(v) for v in item.get("tags", [])],
            contexts=[str(v) for v in item.get("contexts", [])],
            flags=str(item.get("flags", "")),
        )
        rules.append(rule)

    return rules


def compile_rules(rules: list[Rule]) -> list[CompiledRule]:
    compiled: list[CompiledRule] = []

    for rule in rules:
        flags = 0
        for flag in rule.flags:
            flags |= _FLAG_MAP.get(flag, 0)

        compiled.append(CompiledRule(rule=rule, regex=re.compile(rule.pattern, flags=flags)))

    return compiled
