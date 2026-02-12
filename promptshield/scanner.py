from __future__ import annotations

from .normalize import build_scan_views
from .rules import CompiledRule
from .types import Finding


def _truncate_match(value: str, limit: int = 140) -> str:
    cleaned = value.strip().replace("\n", " ")
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[: limit - 3]}..."


def scan_text(
    text: str,
    compiled_rules: list[CompiledRule],
    context: str = "chat",
    max_findings: int = 250,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for view_name, view_text in build_scan_views(text).items():
        for compiled in compiled_rules:
            rule = compiled.rule
            if rule.contexts and context not in rule.contexts:
                continue

            for match in compiled.regex.finditer(view_text):
                snippet = _truncate_match(match.group(0))
                dedupe_key = (rule.id, snippet.lower())
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                start = match.start() if view_name == "original" else -1
                end = match.end() if view_name == "original" else -1

                findings.append(
                    Finding(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=rule.severity.to_str(),
                        context=context,
                        view=view_name,
                        match=snippet,
                        start=start,
                        end=end,
                        tags=rule.tags,
                    )
                )

                if len(findings) >= max_findings:
                    return findings

    return findings
