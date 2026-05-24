"""
Mr QR — HTTP Bridge
Thin aiohttp HTTP gateway that the web UI (ui/index.html) calls.

GET  /        -> serves ui/index.html
POST /scan    -> runs the full security pipeline, returns verdict JSON
GET  /health  -> liveness check

The pipeline logic lives in orchestrator.py (VirusTotal -> GMI worker -> Gemini).
When Rocketride's local server is available, replace _run_pipeline() with a
RocketRideClient call and nothing else in this file needs to change.
"""

import os
from pathlib import Path

from aiohttp import web
from aiohttp.web_middlewares import middleware
from dotenv import load_dotenv

ROOT = Path(__file__).parent.parent
load_dotenv(ROOT / ".env")

# Ensure project root is on sys.path so backend.orchestrator resolves
import sys
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Pipeline logic — all the real work happens here
from backend.orchestrator import scan_url, ScanRequest

# ---------------------------------------------------------------------------
# CORS middleware — lets the browser call /scan from any origin (ngrok etc.)
# ---------------------------------------------------------------------------
@middleware
async def cors_middleware(request: web.Request, handler):
    if request.method == "OPTIONS":
        return web.Response(headers={
            "Access-Control-Allow-Origin":  "*",
            "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        })
    response = await handler(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


# ---------------------------------------------------------------------------
# Pipeline runner — swap this function when Rocketride local server is ready
# ---------------------------------------------------------------------------
async def _run_pipeline(url: str) -> dict:
    """
    Runs: VirusTotal -> GMI Playwright worker -> Gemini analysis.
    Returns the verdict dict.

    TO SWITCH TO ROCKETRIDE: replace the body of this function with:
        client = RocketRideClient()
        await client.connect()
        result = await client.use(filepath='pipelines/mr_qr_security.pipe')
        token  = result['token']
        answer = await client.send(token, url)
        await client.disconnect()
        return json.loads(answer['answers'][0])
    """
    result = await scan_url(ScanRequest(url=url))
    return dict(result)


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------
async def handle_ui(request: web.Request) -> web.Response:
    return web.FileResponse(ROOT / "ui" / "index.html")


async def handle_health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "service": "Mr QR Bridge"})


async def handle_scan(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "Invalid JSON body"}, status=400)

    url = (body.get("url") or "").strip()
    if not url:
        return web.json_response({"error": "url field is required"}, status=400)

    try:
        verdict = await _run_pipeline(url)
        return web.json_response(verdict)
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=502)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------
def make_app() -> web.Application:
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get("/",        handle_ui)
    app.router.add_get("/health",  handle_health)
    app.router.add_post("/scan",   handle_scan)
    return app


if __name__ == "__main__":
    port = int(os.environ.get("BRIDGE_PORT", 8000))
    print(f"[bridge] Starting on http://0.0.0.0:{port}")
    web.run_app(make_app(), host="0.0.0.0", port=port)
