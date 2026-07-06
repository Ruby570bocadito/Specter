"""REST API for T-100AI - HTTP interface for external integrations."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Optional
from urllib.parse import urlparse, parse_qs


@dataclass
class APIResponse:
    """Standard API response."""
    status: int
    data: Any = None
    error: str = ""

    def to_json(self) -> str:
        body = {"status": "ok" if self.status < 400 else "error"}
        if self.data is not None:
            body["data"] = self.data
        if self.error:
            body["error"] = self.error
        return json.dumps(body, default=str)


class T100AIAPI:
    """REST API server for T-100AI.

    Provides HTTP endpoints for external tools to interact with T-100AI.

    Endpoints:
        GET  /api/status           - Server status
        GET  /api/sessions         - List sessions
        POST /api/sessions         - Create session
        GET  /api/sessions/<id>    - Get session details
        GET  /api/sessions/<id>/findings - Get session findings
        POST /api/sessions/<id>/findings - Add finding
        GET  /api/iocs             - List IoCs
        POST /api/iocs             - Add IoC
        GET  /api/workflows        - List workflows
        POST /api/workflows/<name>/run - Run workflow
        GET  /api/compliance       - Compliance report
        GET  /api/attack-graph     - Attack graph
        GET  /api/kill-chain       - Kill chain status
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._handlers: dict[str, Callable] = {}
        self._running = False

    def register_handler(self, method: str, path: str, handler: Callable) -> None:
        """Register a custom API handler."""
        self._handlers[f"{method}:{path}"] = handler

    def start(self) -> None:
        """Start the API server in a background thread."""
        api = self

        class APIHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                api._handle_request("GET", self)

            def do_POST(self):
                api._handle_request("POST", self)

            def log_message(self, format, *args):
                pass  # Suppress default logging

        self._server = HTTPServer((self.host, self.port), APIHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self._running = True

    def stop(self) -> None:
        """Stop the API server."""
        if self._server:
            self._server.shutdown()
            self._running = False

    def _handle_request(self, method: str, handler: BaseHTTPRequestHandler) -> None:
        """Route and handle an API request."""
        parsed = urlparse(handler.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        # Check custom handlers
        key = f"{method}:{path}"
        if key in self._handlers:
            response = self._handlers[key](query)
        else:
            response = self._default_handler(method, path, query)

        handler.send_response(response.status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Access-Control-Allow-Origin", "*")
        handler.end_headers()
        handler.wfile.write(response.to_json().encode())

    def _default_handler(self, method: str, path: str, query: dict) -> APIResponse:
        """Default handler for standard endpoints."""
        if path == "/api/status":
            return APIResponse(200, {"status": "running", "endpoints": list(self._handlers.keys())})
        if path == "/api/sessions":
            return APIResponse(200, {"sessions": []})
        if path == "/api/iocs":
            return APIResponse(200, {"iocs": []})
        if path == "/api/workflows":
            return APIResponse(200, {"workflows": []})
        if path == "/api/compliance":
            return APIResponse(200, {"compliance": {}})
        if path == "/api/attack-graph":
            return APIResponse(200, {"graph": {"nodes": 0, "edges": 0}})
        if path == "/api/kill-chain":
            return APIResponse(200, {"kill_chain": []})
        return APIResponse(404, error=f"Endpoint not found: {path}")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"
