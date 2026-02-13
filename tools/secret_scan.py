#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key_block", re.compile(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----", re.M)),
    ("openai_like_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\b(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("password_assignment", re.compile(r"\b(passwort|password)\b\s*[:=]\s*\S{6,}", re.I)),
    ("secret_assignment", re.compile(r"\b(api[- _]?key|token|secret)\b\s*[:=]\s*\S{10,}", re.I)),
]


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"cmd failed: {' '.join(cmd)}")
    return proc.stdout


def is_probably_binary(data: bytes) -> bool:
    return b"\x00" in data


def iter_files_from_git(staged: bool) -> list[Path]:
    args = ["git", "diff", "--name-only", "--diff-filter=ACM"]
    if staged:
        args.insert(2, "--cached")
    out = run(args)
    files = []
    for line in out.splitlines():
        p = Path(line.strip())
        if not p.as_posix():
            continue
        files.append(p)
    return files


def scan_file(p: Path) -> list[str]:
    if not p.exists() or not p.is_file():
        return []
    # Never allow committing env files.
    if p.name == ".env" or p.name.startswith(".env."):
        return ["env_file"]
    # Common runtime dirs that should not be committed.
    if any(part in {"data", "logs", ".venv", "venv", "node_modules"} for part in p.parts):
        # Not an error by itself, but very likely accidental.
        return ["runtime_path"]

    raw = p.read_bytes()
    if is_probably_binary(raw):
        return []
    if len(raw) > 1_000_000:
        return []
    text = raw.decode("utf-8", errors="replace")

    hits: list[str] = []
    for name, rx in PATTERNS:
        if rx.search(text):
            hits.append(name)
    return hits


def main() -> int:
    ap = argparse.ArgumentParser(description="Lightweight secret scanner for commits.")
    ap.add_argument("--staged", action="store_true", help="Scan staged (git index) files only.")
    args = ap.parse_args()

    files = iter_files_from_git(staged=args.staged)
    if not files:
        return 0

    failed = False
    for p in files:
        hits = scan_file(p)
        if hits:
            failed = True
            print(f"[secret-scan] {p}: {', '.join(hits)}")

    if failed:
        print("[secret-scan] Commit blocked. Remove secrets from the change or move them to env vars/secret manager.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

