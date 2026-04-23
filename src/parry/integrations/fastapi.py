"""FastAPI/Starlette middleware for Parry."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from parry.guard import Guard


class GuardMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware to guard all incoming requests and outgoing responses."""

    def __init__(self, app, guard: Guard | None = None):
        super().__init__(app)
        self.guard = guard or Guard()

    async def dispatch(self, request: Request, call_next):
        # Read request body
        body = await request.body()
        text = body.decode("utf-8") if isinstance(body, bytes) else str(body)
        # Scan input
        report = self.guard.scan_input(text)
        if report.decision.action == "BLOCK":
            return JSONResponse({"error": report.decision.reason}, status_code=400)
        # Continue to endpoint
        response = await call_next(request)
        # Scan output
        if hasattr(response, "body_iterator"):
            # Streaming response — skip
            return response
        resp_body = b""
        async for chunk in response.body_iterator:
            resp_body += chunk
        resp_text = resp_body.decode("utf-8")
        report_out = self.guard.scan_output(resp_text)
        if report_out.decision.action == "BLOCK":
            return JSONResponse({"error": report_out.decision.reason}, status_code=400)
        if report_out.decision.action == "REDACT" and report_out.decision.redacted_text:
            return Response(report_out.decision.redacted_text, status_code=response.status_code)
        return response
