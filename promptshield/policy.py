from __future__ import annotations

import json
from pathlib import Path

from .types import Decision, Finding, Severity


DEFAULT_POLICY: dict = {
    "default": {
        "block_at": "block",
        "redact_at": "warn",
        "on_block": "quarantine",
    },
    "contexts": {},
}


def load_policy(path: str | Path) -> dict:
    p = Path(path)
    payload = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Policy must be a JSON object: {path}")
    return payload


def _severity_max(findings: list[Finding]) -> Severity | None:
    if not findings:
        return None
    return max(Severity.from_str(f.severity) for f in findings)


def _merge_policy(policy: dict, context: str) -> dict:
    base = dict(DEFAULT_POLICY["default"])
    base.update(policy.get("default", {}))
    ctx = policy.get("contexts", {}).get(context, {})
    base.update(ctx)
    return base


def _redact_ranges(text: str, findings: list[Finding], threshold: Severity) -> str:
    ranges: list[tuple[int, int, str]] = []
    for finding in findings:
        if finding.view != "original":
            continue
        if finding.start < 0 or finding.end <= finding.start:
            continue
        if Severity.from_str(finding.severity) < threshold:
            continue
        ranges.append((finding.start, finding.end, finding.rule_id))

    if not ranges:
        return text

    ranges.sort(key=lambda item: (item[0], item[1]))

    merged: list[tuple[int, int, str]] = []
    cur_start, cur_end, cur_rule = ranges[0]
    for start, end, rule_id in ranges[1:]:
        if start <= cur_end:
            cur_end = max(cur_end, end)
            cur_rule = rule_id
            continue
        merged.append((cur_start, cur_end, cur_rule))
        cur_start, cur_end, cur_rule = start, end, rule_id
    merged.append((cur_start, cur_end, cur_rule))

    parts: list[str] = []
    cursor = 0
    for start, end, rule_id in merged:
        parts.append(text[cursor:start])
        parts.append(f"[REDACTED:{rule_id}]")
        cursor = end
    parts.append(text[cursor:])

    return "".join(parts)


def apply_policy(
    text: str,
    findings: list[Finding],
    context: str,
    policy: dict | None = None,
) -> Decision:
    effective_policy = _merge_policy(policy or DEFAULT_POLICY, context)
    block_at = Severity.from_str(str(effective_policy.get("block_at", "block")))
    redact_at = Severity.from_str(str(effective_policy.get("redact_at", "warn")))
    on_block = str(effective_policy.get("on_block", "quarantine"))

    highest = _severity_max(findings)
    if highest is None:
        return Decision(
            action="allow",
            blocked=False,
            highest_severity="info",
            matched_rule_ids=[],
            findings_count=0,
            sanitized_text=text,
            notes=[],
        )

    rule_ids = sorted({finding.rule_id for finding in findings})
    notes: list[str] = []

    if highest >= block_at:
        return Decision(
            action=on_block,
            blocked=True,
            highest_severity=highest.to_str(),
            matched_rule_ids=rule_ids,
            findings_count=len(findings),
            sanitized_text=None,
            notes=["blocked_by_policy"],
        )

    redacted = _redact_ranges(text, findings, threshold=redact_at)
    action = "allow" if redacted == text else "redact"
    if action == "allow" and any(f.view != "original" for f in findings):
        notes.append("match_found_in_transformed_view")

    return Decision(
        action=action,
        blocked=False,
        highest_severity=highest.to_str(),
        matched_rule_ids=rule_ids,
        findings_count=len(findings),
        sanitized_text=redacted,
        notes=notes,
    )
