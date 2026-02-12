from __future__ import annotations

import json
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .policy import apply_policy
from .rules import CompiledRule
from .scanner import scan_text


@dataclass
class ServiceConfig:
    compiled_rules: list[CompiledRule]
    policy: dict
    max_findings: int = 250


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def build_handler(config: ServiceConfig):
    class PromptShieldHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/health":
                _json_response(self, 404, {"error": "not found"})
                return
            _json_response(self, 200, {"status": "ok"})

        def do_POST(self):
            if self.path != "/scan":
                _json_response(self, 404, {"error": "not found"})
                return

            try:
                content_length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(content_length)
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                _json_response(self, 400, {"error": "invalid json"})
                return

            text = payload.get("text")
            if not isinstance(text, str):
                _json_response(self, 400, {"error": "field 'text' must be a string"})
                return

            context = str(payload.get("context", "chat"))
            findings = scan_text(text=text, compiled_rules=config.compiled_rules, context=context, max_findings=config.max_findings)
            decision = apply_policy(text=text, findings=findings, context=context, policy=config.policy)

            _json_response(
                self,
                200,
                {
                    "decision": decision.to_dict(),
                    "findings": [finding.to_dict() for finding in findings],
                },
            )

        def log_message(self, format: str, *args):
            return

    return PromptShieldHandler


def run_server(host: str, port: int, config: ServiceConfig) -> None:
    handler_cls = build_handler(config)
    server = ThreadingHTTPServer((host, port), handler_cls)
    try:
        server.serve_forever()
    finally:
        server.server_close()
