from __future__ import annotations

import hashlib
import json
import tempfile
import urllib.request
from pathlib import Path

_REQUIRED_RULE_KEYS = {"id", "name", "description", "pattern", "severity"}


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json_atomic(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent) as tmp:
        json.dump(payload, tmp, ensure_ascii=False, indent=2)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validate_rules_payload(payload) -> list[dict]:
    if not isinstance(payload, list):
        raise ValueError("Rules payload must be a list")

    validated: list[dict] = []
    for idx, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ValueError(f"Rule at index {idx} is not an object")
        missing = _REQUIRED_RULE_KEYS - set(item)
        if missing:
            raise ValueError(f"Rule at index {idx} missing keys: {sorted(missing)}")
        validated.append(item)

    return validated


def _download_json(url: str, timeout: float) -> tuple[list[dict], str]:
    req = urllib.request.Request(url, headers={"User-Agent": "promptshield-updater/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()

    digest = _sha256_bytes(body)
    parsed = json.loads(body.decode("utf-8"))
    validated = _validate_rules_payload(parsed)
    return validated, digest


def rebuild_active_rules(rules_dir: str | Path) -> dict:
    rules_root = Path(rules_dir)
    base_path = rules_root / "base.json"
    local_path = rules_root / "local.json"
    feeds_dir = rules_root / "feeds"

    merged_by_id: dict[str, dict] = {}
    source_counts: dict[str, int] = {}

    for source_name, source_path in [
        ("base", base_path),
        ("local", local_path),
    ]:
        if not source_path.exists():
            source_counts[source_name] = 0
            continue
        payload = _validate_rules_payload(_read_json(source_path))
        source_counts[source_name] = len(payload)
        for rule in payload:
            merged_by_id[rule["id"]] = rule

    feed_total = 0
    if feeds_dir.exists():
        for feed_file in sorted(feeds_dir.glob("*.json")):
            payload = _validate_rules_payload(_read_json(feed_file))
            feed_total += len(payload)
            for rule in payload:
                merged_by_id[rule["id"]] = rule

    source_counts["feeds"] = feed_total
    merged = sorted(merged_by_id.values(), key=lambda item: item["id"])
    _write_json_atomic(rules_root / "active.json", merged)

    return {
        "active_rules": len(merged),
        "source_counts": source_counts,
    }


def update_from_sources(sources_path: str | Path, rules_dir: str | Path, timeout: float = 10.0) -> dict:
    sources_file = Path(sources_path)
    sources = _read_json(sources_file)
    if not isinstance(sources, list):
        raise ValueError("sources file must be a list")

    rules_root = Path(rules_dir)
    feeds_dir = rules_root / "feeds"
    feeds_dir.mkdir(parents=True, exist_ok=True)

    result = {
        "downloaded": [],
        "skipped": [],
        "errors": [],
    }

    for source in sources:
        if not isinstance(source, dict):
            result["errors"].append({"source": str(source), "error": "invalid source definition"})
            continue

        name = str(source.get("name", "unnamed"))
        url = str(source.get("url", "")).strip()
        expected_sha256 = str(source.get("sha256", "")).strip().lower()
        enabled = bool(source.get("enabled", True))

        if not enabled:
            result["skipped"].append({"source": name, "reason": "disabled"})
            continue
        if not url:
            result["errors"].append({"source": name, "error": "missing url"})
            continue
        if not expected_sha256:
            result["errors"].append({"source": name, "error": "missing sha256"})
            continue

        try:
            payload, actual_sha256 = _download_json(url=url, timeout=timeout)
            if actual_sha256 != expected_sha256:
                result["errors"].append(
                    {
                        "source": name,
                        "error": "sha256 mismatch",
                        "expected": expected_sha256,
                        "actual": actual_sha256,
                    }
                )
                continue

            target = feeds_dir / f"{name}.json"
            _write_json_atomic(target, payload)
            result["downloaded"].append({"source": name, "rules": len(payload), "sha256": actual_sha256})
        except Exception as exc:  # pragma: no cover - network/runtime safety path
            result["errors"].append({"source": name, "error": str(exc)})

    result["rebuild"] = rebuild_active_rules(rules_root)
    return result
