from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .policy import apply_policy, load_policy
from .rules import compile_rules, load_rules
from .scanner import scan_text
from .server import ServiceConfig, run_server
from .updater import update_from_sources


def _default_path(*parts: str) -> Path:
    cwd_candidate = Path.cwd().joinpath(*parts)
    if cwd_candidate.exists():
        return cwd_candidate
    return Path(__file__).resolve().parent.parent.joinpath(*parts)


def _load_engine(rules_path: Path, policy_path: Path):
    rules = load_rules(rules_path)
    compiled_rules = compile_rules(rules)
    policy = load_policy(policy_path)
    return compiled_rules, policy


def _read_input(args: argparse.Namespace) -> str:
    provided = [bool(args.text), bool(args.file), bool(args.stdin)]
    if sum(provided) != 1:
        raise ValueError("Use exactly one of --text, --file, --stdin")

    if args.text:
        return args.text
    if args.file:
        return Path(args.file).read_text(encoding="utf-8")
    return sys.stdin.read()


def _cmd_scan(args: argparse.Namespace) -> int:
    text = _read_input(args)
    compiled_rules, policy = _load_engine(Path(args.rules), Path(args.policy))

    findings = scan_text(
        text=text,
        compiled_rules=compiled_rules,
        context=args.context,
        max_findings=args.max_findings,
    )
    decision = apply_policy(text=text, findings=findings, context=args.context, policy=policy)

    payload = {
        "decision": decision.to_dict(),
        "findings": [finding.to_dict() for finding in findings],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 2 if decision.blocked else 0


def _cmd_update_rules(args: argparse.Namespace) -> int:
    summary = update_from_sources(
        sources_path=args.sources,
        rules_dir=args.rules_dir,
        timeout=float(args.timeout),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not summary.get("errors") else 1


def _cmd_serve(args: argparse.Namespace) -> int:
    compiled_rules, policy = _load_engine(Path(args.rules), Path(args.policy))
    config = ServiceConfig(compiled_rules=compiled_rules, policy=policy, max_findings=args.max_findings)
    run_server(host=args.host, port=args.port, config=config)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="promptshield", description="Signature-based prompt-injection scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan text and apply policy")
    scan.add_argument("--text", type=str, help="Inline text to scan")
    scan.add_argument("--file", type=str, help="Path to text file")
    scan.add_argument("--stdin", action="store_true", help="Read input from stdin")
    scan.add_argument("--context", type=str, default="chat", help="Pipeline context")
    scan.add_argument("--rules", type=str, default=str(_default_path("rules", "active.json")))
    scan.add_argument("--policy", type=str, default=str(_default_path("config", "policy.json")))
    scan.add_argument("--max-findings", type=int, default=250)
    scan.set_defaults(func=_cmd_scan)

    update = sub.add_parser("update-rules", help="Download rules from curated sources")
    update.add_argument("--sources", type=str, default=str(_default_path("rules", "sources.json")))
    update.add_argument("--rules-dir", type=str, default=str(_default_path("rules")))
    update.add_argument("--timeout", type=float, default=10.0)
    update.set_defaults(func=_cmd_update_rules)

    serve = sub.add_parser("serve", help="Start HTTP scanning service")
    serve.add_argument("--host", type=str, default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8787)
    serve.add_argument("--rules", type=str, default=str(_default_path("rules", "active.json")))
    serve.add_argument("--policy", type=str, default=str(_default_path("config", "policy.json")))
    serve.add_argument("--max-findings", type=int, default=250)
    serve.set_defaults(func=_cmd_serve)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
