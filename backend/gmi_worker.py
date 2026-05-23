"""
Mr QR — GMI Cloud Security Worker
Playwright-based deep security scanner running on GMI Cloud GPU infrastructure
(H100 / H200 nodes).  Exposed as a FastAPI service.

POST /analyze  {"url": "https://...", "capture_screenshot": true}
GET  /health
"""

import asyncio
import base64
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from playwright.async_api import async_playwright

app = FastAPI(title="Mr QR GMI Security Worker", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
RENDER_TIMEOUT_MS = int(os.environ.get("RENDER_TIMEOUT_MS", "15000"))

# File extensions that signal a dangerous auto-download
DANGEROUS_EXTENSIONS = {
    ".apk", ".exe", ".msi", ".bat", ".cmd", ".ps1",
    ".dmg", ".ipa", ".jar", ".vbs", ".sh",
}

# Official FIFA/World Cup domain suffixes used for phishing score shortcut
OFFICIAL_DOMAINS = frozenset({
    "fifa.com", "fifa.org", "fifaworldcup.com", "worldcup2026.com",
    "the26.com", "matchhospitality.com",
})

# FIFA brand keywords that indicate impersonation when found on unofficial domains
FIFA_KEYWORDS = [
    "fifa", "world cup 2026", "worldcup2026", "fan id", "fanid",
    "match hospitality", "official ticket", "fan zone", "host city",
    "stadio", "estadio",
]

# Sensitive form field patterns that raise risk on unofficial domains
SENSITIVE_PATTERNS = [
    "passport", "travel document", "national id", "fan id", "fanid",
    "visa number", "id number",
]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    url: str
    capture_screenshot: bool = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_dangerous_content_disposition(header_value: str) -> bool:
    """Return True if Content-Disposition header would trigger a dangerous download."""
    if "attachment" not in header_value.lower():
        return False
    match = re.search(r'filename=["\']?([^"\';\s]+)', header_value, re.IGNORECASE)
    if match:
        ext = os.path.splitext(match.group(1))[1].lower()
        return ext in DANGEROUS_EXTENSIONS
    return False


def _url_has_dangerous_extension(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in DANGEROUS_EXTENSIONS)


def _is_official_domain(netloc: str) -> bool:
    netloc = netloc.lower().lstrip("www.")
    return any(netloc == d or netloc.endswith("." + d) for d in OFFICIAL_DOMAINS)


def _visual_phishing_score(html: str, netloc: str) -> int:
    """
    Heuristic phishing score 0–100.
    Checks whether an unofficial domain impersonates FIFA / World Cup branding.
    Returns 0 immediately for official domains.
    """
    if _is_official_domain(netloc):
        return 0

    html_lower = html.lower()
    score = 0

    # FIFA brand impersonation
    brand_hits = sum(1 for kw in FIFA_KEYWORDS if kw in html_lower)
    score += min(brand_hits * 12, 55)

    # Sensitive data collection on unofficial domain
    sensitive_hits = sum(1 for p in SENSITIVE_PATTERNS if p in html_lower)
    score += min(sensitive_hits * 10, 30)

    # Payment form on unofficial domain
    payment_terms = ["card number", "cvv", "expiration", "billing address",
                     "credit card", "debit card", "secure payment"]
    if any(t in html_lower for t in payment_terms):
        score += 20

    # Lookalike URL patterns (e.g. "f1fa", "fif-a", "worldcup-2026")
    lookalike_patterns = [r"f[i1]f[a4]", r"world.?cup.?202[56]", r"fifia", r"fifа"]
    domain_lower = netloc.lower()
    for pattern in lookalike_patterns:
        if re.search(pattern, domain_lower):
            score += 25
            break

    return min(score, 100)


# ---------------------------------------------------------------------------
# Main analysis endpoint
# ---------------------------------------------------------------------------
@app.post("/analyze")
async def analyze_url(request: AnalyzeRequest):
    """
    Deep security render using Playwright on GPU-accelerated Chromium:
      • Intercepts all network responses for Content-Disposition / dangerous file types
      • Captures download events and cancels them
      • Records the final redirect URL
      • Extracts full DOM / HTML for Gemini analysis
      • Takes a full-page JPEG screenshot as evidence
      • Computes a visual phishing risk score (0–100)
    """
    url = request.url.strip()

    result = {
        "url":                      url,
        "final_url":                url,
        "has_download_trigger":     False,
        "content_disposition_found": False,
        "suspicious_requests":      [],
        "visual_risk_score":        0,
        "html":                     "",
        "screenshot_b64":           None,
        "error":                    None,
    }

    download_triggered = False
    suspicious_reqs: list[str] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )

        context = await browser.new_context(
            viewport={"width": 1920, "height": 1080},
            # Mimic a FIFA fan on a mobile device
            user_agent=(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.4 Mobile/15E148 Safari/604.1"
            ),
            ignore_https_errors=False,
        )

        page = await context.new_page()

        # ── Network response interception ────────────────────────────────────
        async def on_response(response):
            nonlocal download_triggered
            try:
                content_disp = response.headers.get("content-disposition", "")
                if content_disp and _is_dangerous_content_disposition(content_disp):
                    download_triggered = True
                    result["content_disposition_found"] = True
                    suspicious_reqs.append(f"DRIVE-BY-DOWNLOAD:{response.url}")

                if _url_has_dangerous_extension(response.url):
                    suspicious_reqs.append(f"DANGEROUS-FILE-EXT:{response.url}")
                    download_triggered = True
            except Exception:
                pass

        page.on("response", on_response)

        # ── Download event interception ──────────────────────────────────────
        async def on_download(download):
            nonlocal download_triggered
            download_triggered = True
            suspicious_reqs.append(f"DOWNLOAD-EVENT:{download.url}")
            await download.cancel()

        context.on("download", on_download)

        # ── Navigate ─────────────────────────────────────────────────────────
        try:
            await page.goto(url, wait_until="networkidle", timeout=RENDER_TIMEOUT_MS)
            result["final_url"] = page.url

            # Full DOM for Gemini
            html = await page.content()
            result["html"] = html

            # Visual phishing score
            netloc = urlparse(page.url).netloc.lower().lstrip("www.")
            result["visual_risk_score"] = _visual_phishing_score(html, netloc)

            # Full-page screenshot (JPEG for smaller payload)
            if request.capture_screenshot:
                screenshot_bytes = await page.screenshot(
                    full_page=True,
                    type="jpeg",
                    quality=80,
                )
                result["screenshot_b64"] = base64.b64encode(screenshot_bytes).decode()

        except Exception as exc:
            result["error"] = str(exc)
        finally:
            await context.close()
            await browser.close()

    result["has_download_trigger"] = download_triggered
    result["suspicious_requests"]  = suspicious_reqs[:20]   # cap list size
    return result


@app.get("/health")
async def health():
    return {"status": "ok", "service": "Mr QR GMI Security Worker"}
