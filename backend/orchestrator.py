"""
Mr QR — Security Orchestrator  (Rocketride entry-point)
FastAPI service that coordinates VirusTotal → GMI Cloud → Gemini for
multi-layer QR URL analysis at FIFA World Cup 2026.

POST /scan  {"url": "https://..."}
GET  /health
"""

import asyncio
import json
import os
from pathlib import Path

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# App & CORS
# ---------------------------------------------------------------------------
app = FastAPI(title="Mr QR Security Orchestrator", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Config (injected via .env / Rocketride env vars)
# ---------------------------------------------------------------------------
VT_API_KEY          = os.environ["VIRUSTOTAL_API_KEY"]
GMI_WORKER_URL      = os.environ.get("GMI_WORKER_URL", "http://localhost:8001")
GMI_INFERENCE_URL   = os.environ.get("GMI_INFERENCE_URL", "https://api.gmi-serving.com/v1")
GMI_INFERENCE_KEY   = os.environ["ROCKETRIDE_GMI_API_KEY"]
GMI_ANALYSIS_MODEL  = os.environ.get("GMI_ANALYSIS_MODEL", "google/gemini-3.1-pro-preview")

VT_MALICIOUS_BLOCK = 2   # ≥ N engines say malicious → hard block, skip GMI/Gemini
VT_SUSPICIOUS_MIN  = 1   # ≥ N suspicious  → trigger GMI deep scan


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class ScanRequest(BaseModel):
    url: str
    locale: str = "en"


# ---------------------------------------------------------------------------
# Phase 1 — VirusTotal reputation check  (URL scan + domain reputation, parallel)
# ---------------------------------------------------------------------------
async def _vt_url_scan(client: httpx.AsyncClient, url: str, headers: dict) -> dict:
    """Submit URL for fresh analysis and poll until complete (max ~30 s)."""
    submit = await client.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
    )
    submit.raise_for_status()
    analysis_id = submit.json()["data"]["id"]

    for _ in range(7):
        await asyncio.sleep(3)
        poll = await client.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
        )
        poll.raise_for_status()
        body = poll.json()["data"]["attributes"]
        if body["status"] == "completed":
            s = body["stats"]
            return {
                "malicious":  s.get("malicious",  0),
                "suspicious": s.get("suspicious", 0),
                "harmless":   s.get("harmless",   0),
                "undetected": s.get("undetected", 0),
            }

    return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}


async def _vt_domain_reputation(client: httpx.AsyncClient, domain: str, headers: dict) -> dict:
    """
    Fetch domain's historical reputation from VT.
    Returns richer signal: total malicious votes, categories, and known-bad flags.
    This call is instant (no polling needed).
    """
    try:
        resp = await client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers,
        )
        if resp.status_code == 404:
            return {"domain_malicious": 0, "domain_suspicious": 0, "domain_categories": [], "domain_known_distributor": False}
        resp.raise_for_status()
        attr = resp.json()["data"]["attributes"]
        votes = attr.get("last_analysis_stats", {})
        # VT community votes (crowdsourced — very reliable signal)
        community = attr.get("total_votes", {})
        categories = list(attr.get("categories", {}).values())
        return {
            "domain_malicious":         votes.get("malicious", 0),
            "domain_suspicious":        votes.get("suspicious", 0),
            "domain_harmless":          votes.get("harmless", 0),
            "domain_community_malicious": community.get("malicious", 0),
            "domain_community_harmless":  community.get("harmless", 0),
            "domain_categories":        categories,
            # If ANY engine categorises as malware/phishing at domain level → very strong signal
            "domain_known_bad": any(
                c.lower() in {"malware", "phishing", "malicious", "spam", "scam"}
                for c in categories
            ),
        }
    except Exception:
        return {"domain_malicious": 0, "domain_suspicious": 0, "domain_categories": [],
                "domain_known_bad": False, "domain_community_malicious": 0}


_PRIVATE_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

def _is_private_url(url: str) -> bool:
    from urllib.parse import urlparse
    import ipaddress
    host = urlparse(url).hostname or ""
    if host in _PRIVATE_HOSTS:
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False


async def virustotal_scan(url: str) -> dict:
    """
    Run URL scan and domain reputation check in parallel.
    Merges both signals for a more accurate combined verdict.
    """
    from urllib.parse import urlparse
    domain = urlparse(url).netloc.lower().lstrip("www.")

    # VT rejects private/localhost addresses — return neutral result immediately
    if _is_private_url(url):
        return {
            "status": "skipped",
            "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
            "total_engines": 0, "malicious_ratio": 0.0, "is_noise": True,
            "domain_known_bad": False, "domain_community_malicious": 0,
            "domain_categories": ["localhost"],
        }
    headers = {"x-apikey": VT_API_KEY}

    async with httpx.AsyncClient(timeout=35.0) as client:
        url_result, domain_result = await asyncio.gather(
            _vt_url_scan(client, url, headers),
            _vt_domain_reputation(client, domain, headers),
        )

    # Consensus ratio — the only number that matters for accuracy
    total_votes = url_result["malicious"] + url_result["harmless"] + url_result["suspicious"]
    malicious_ratio = url_result["malicious"] / total_votes if total_votes > 0 else 0.0

    # Combine malicious counts across URL scan and domain reputation
    combined_malicious  = max(url_result["malicious"],  domain_result.get("domain_malicious", 0))
    combined_suspicious = max(url_result["suspicious"], domain_result.get("domain_suspicious", 0))

    # Noise flag: single-engine outlier contradicted by a strong clean majority
    is_noise = (
        combined_malicious <= 2
        and malicious_ratio < 0.05       # < 5% of engines agree
        and url_result["harmless"] >= 10  # meaningful clean consensus exists
        and not domain_result.get("domain_known_bad", False)
    )

    return {
        "status":           "completed",
        "malicious":        combined_malicious,
        "suspicious":       combined_suspicious,
        "harmless":         url_result["harmless"],
        "undetected":       url_result["undetected"],
        "total_engines":    total_votes,
        "malicious_ratio":  round(malicious_ratio, 4),
        "is_noise":         is_noise,
        "domain_known_bad":           domain_result.get("domain_known_bad", False),
        "domain_community_malicious": domain_result.get("domain_community_malicious", 0),
        "domain_categories":          domain_result.get("domain_categories", []),
    }


# ---------------------------------------------------------------------------
# Phase 2 — GMI Cloud deep security worker
# ---------------------------------------------------------------------------
async def gmi_deep_scan(url: str) -> dict:
    """Call the Playwright worker deployed on GMI Cloud GPU infrastructure."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(f"{GMI_WORKER_URL}/analyze", json={"url": url})
        resp.raise_for_status()
        return resp.json()


# ---------------------------------------------------------------------------
# Phase 3 — Gemini 1.5 Flash semantic analysis
# ---------------------------------------------------------------------------
GEMINI_SYSTEM_PROMPT = """
You are an elite cybersecurity analyst for FIFA World Cup 2026.
Protect fans from phishing, fraud, and malicious QR-code destinations.

━━━ TASK ━━━
Analyze the provided HTML content plus security scan results, then return ONE JSON object.

━━━ 1. DOMAIN LEGITIMACY CHECK ━━━
Verify whether the domain belongs to an official FIFA World Cup entity.
Official domains (non-exhaustive — apply logical inference for sub-domains):
  FIFA / Ticketing  : fifa.com, fifa.org, tickets.fifa.com, hospitality.fifa.com,
                      matchhospitality.com
  World Cup 2026    : worldcup2026.com, fifaworldcup.com, the26.com
  Host Cities (USA) : losangeles2026.com, dallas2026.com, miami2026.com,
                      sfbay2026.com, seattle2026.com, boston2026.com,
                      nynjworldcup.com, kansascity2026.com, houston2026.com,
                      philadelphia2026.com, atlanta2026.com
  Host Cities (MX)  : guadalajara2026.com, monterrey2026.com, cdmx2026.com
  Host Cities (CA)  : toronto2026.com, vancouver2026.com

━━━ 2. FORM FIELD MAPPING ━━━
Scan ALL <input>, <select>, <textarea> elements in the HTML.
For EACH field found, map it to exactly one standard data type from:
  full_name, first_name, last_name, passport_id, passport_expiry,
  nationality, date_of_birth, email, phone, fifa_fan_id, address,
  city, country, postal_code, ticket_category,
  payment_card, payment_cvv, payment_expiry, unknown

CRITICAL — handle obfuscated / non-standard HTML attribute names:
  id="p_num_01"   name="passport_no"   placeholder="Enter passport"  →  passport_id
  id="fn_field"   placeholder="First Name"                           →  first_name
  id="dob_entry"  name="birth_date"                                  →  date_of_birth
  id="fanid_box"  name="fan_id_num"                                  →  fifa_fan_id
  id="nat_sel_1"  placeholder="Your nationality"                     →  nationality
  name="cc_num"   placeholder="Card Number"                          →  payment_card
  id="cvv_field"  placeholder="CVV / CVC"                           →  payment_cvv

Use ALL available attributes (id, name, placeholder, aria-label,
data-field, class names, adjacent <label> text) to infer the mapping.
When truly ambiguous, use "unknown".

━━━ 3. PHISHING INDICATORS ━━━
Flag any of:
  • Domain spoofing    (fifa-tickets.xyz, f1fa.com, worldcup-2026.net, etc.)
  • Sensitive data     (passport, payment) collected on a non-official domain
  • HTTP (not HTTPS)   serving payment or ID forms
  • Suspicious iframes loading content from third-party origins
  • Auto-download triggers or suspicious redirects

━━━ RESPONSE FORMAT ━━━
Return ONLY a valid JSON object — no markdown, no preamble:
{
  "verdict":              "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "is_official_entity":   true | false,
  "official_entity_name": "<name or null>",
  "phishing_indicators":  ["<indicator>", ...],
  "field_map": {
    "<element_id_or_name>": "<standard_data_type>"
  },
  "page_purpose": "<one short sentence: what is this page for? e.g. 'FIFA 2026 ticket purchase form' or 'World Cup volunteer registration'>",
  "auto_fill_safe": true | false,
  "risk_summary": "<one sentence>"
}

━━━ VERDICT RULES — apply in order, first match wins ━━━

CONTEXT: This app is used by FIFA World Cup 2026 fans scanning QR codes at watch parties,
raffles, sponsor booths, and local events. Most QR codes point to legitimate third-party
sites (sponsors, venues, event apps) that are NOT official FIFA domains. Being non-official
is NOT a reason to flag anything. Only concrete technical threat signals matter.

KEY CONCEPT — malicious_ratio:
  A single engine flagging a URL that 60+ others mark clean is NOISE, not signal.
    < 5%  with few malicious  = noise / false positive — SAFE
    5–15% corroborated        = weak real signal — SUSPICIOUS
    > 15%                     = real threat — DANGEROUS

IMPORTANT — domain_community_malicious: raw lifetime vote count. Popular sites accumulate
troll votes (google.com has 82 despite 0/64 malicious engine detections). NEVER use it.

IMPORTANT — suspicious_engines count alone is NOT a signal. One or two VT engines calling a
URL "suspicious" while 60+ say clean is a well-known false-positive pattern. Ignore
suspicious_engines < 3 unless corroborated by actual malicious engine detections.

DANGEROUS  if ANY of:
  • domain_known_bad = true  (formal malware/phishing engine categorisation — reliable)
  • malicious_ratio > 0.15  (strong multi-engine consensus)
  • malicious >= 5           (high absolute count)
  • is_official_entity = false AND page collects passport/ID/payment AND malicious_ratio > 0.08
  • visual_risk_score >= 85 AND is_official_entity = false

SUSPICIOUS  only when a concrete signal exists — one of:
  • is_noise = false AND malicious_ratio > 0.05 AND malicious >= 2  (corroborated engines)
  • visual_risk_score >= 70  (clear visual phishing / brand impersonation detected)
  • domain_categories explicitly contain "malware", "phishing", or "scam"
  • is_official_entity = false AND collects passport/ID/payment AND suspicious_engines >= 3

SAFE  (the default for any clean site — sponsors, watch parties, raffles, venues, google.com):
  • Everything that does not meet a SUSPICIOUS or DANGEROUS condition above
  • google.com, spotify.com, local businesses, sponsor sites, raffle pages = SAFE
  • suspicious_engines = 1–2 with malicious = 0 = noise → SAFE
  • Being non-official FIFA is not a reason for anything other than SAFE
  • Only official FIFA domains get auto_fill_safe = true

auto_fill_safe = true  ONLY when verdict=SAFE AND is_official_entity=true
field_map  = {}        always when verdict=DANGEROUS (never help fill malicious forms)
"""


async def gemini_analyze(url: str, html: str, vt: dict, gmi: dict) -> dict:
    """Send all scan context to Gemini via GMI inference API and parse structured JSON."""
    html_excerpt = html[:50_000] if len(html) > 50_000 else html

    prompt = f"""URL: {url}

VIRUSTOTAL URL SCAN:
  malicious engines  : {vt.get('malicious', 0)} / {vt.get('total_engines', 0)} total
  suspicious engines : {vt.get('suspicious', 0)}
  harmless engines   : {vt.get('harmless', 0)}
  malicious_ratio    : {vt.get('malicious_ratio', 0.0):.1%}
  is_noise           : {vt.get('is_noise', False)}  (true = single outlier, contradicted by clean majority)

VIRUSTOTAL DOMAIN REPUTATION:
  domain_known_bad            : {vt.get('domain_known_bad', False)}
  domain_community_malicious  : {vt.get('domain_community_malicious', 0)}
  domain_categories           : {vt.get('domain_categories', [])}

GMI DEEP SCAN RESULTS:
  drive-by download detected : {gmi.get('has_download_trigger', False)}
  visual phishing risk score : {gmi.get('visual_risk_score', 0)}/100
  content-disposition found  : {gmi.get('content_disposition_found', False)}
  suspicious requests        : {gmi.get('suspicious_requests', [])}
  final redirect URL         : {gmi.get('final_url', url)}

PAGE HTML:
{html_excerpt}
"""

    payload = {
        "model": GMI_ANALYSIS_MODEL,
        "messages": [
            {"role": "system", "content": GEMINI_SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {GMI_INFERENCE_KEY}",
        "Content-Type":  "application/json",
    }

    for attempt in range(4):
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{GMI_INFERENCE_URL}/chat/completions",
                headers=headers,
                json=payload,
            )

        if resp.status_code == 429:
            import re
            retry_after = resp.headers.get("retry-after", "")
            wait = int(retry_after) if retry_after.isdigit() else (15 * (2 ** attempt))
            if attempt < 3:
                await asyncio.sleep(wait)
                continue

        resp.raise_for_status()
        break
    else:
        raise RuntimeError("GMI inference rate limit exceeded after retries")

    content = resp.json()["choices"][0]["message"]["content"]

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        text = content.strip()
        if text.startswith("```"):
            parts = text.split("```")
            text = parts[1].lstrip("json").strip() if len(parts) > 1 else text
        return json.loads(text)


# ---------------------------------------------------------------------------
# Phase 4 — Main endpoint
# ---------------------------------------------------------------------------
@app.post("/scan")
async def scan_url(request: ScanRequest):
    """
    Security pipeline:
      1  VirusTotal reputation check
      2  GMI Cloud Playwright deep scan  (if VT inconclusive / suspicious)
      3  Gemini 1.5 Flash semantic analysis
      4  Structured Safe / Dangerous JSON response
    """
    url = request.url.strip()

    _gmi_defaults: dict = {
        "has_download_trigger":      False,
        "content_disposition_found": False,
        "visual_risk_score":         0,
        "suspicious_requests":       [],
        "final_url":                 url,
        "html":                      "",
        "screenshot_b64":            None,
    }

    async def _safe_gmi() -> dict:
        try:
            return await gmi_deep_scan(url)
        except Exception as exc:
            return {**_gmi_defaults, "error": str(exc)}

    # ── Phase 1+2: VT and GMI deep scan in parallel (saves ~15 s) ───────────
    vt, gmi = await asyncio.gather(virustotal_scan(url), _safe_gmi())

    # Hard block — VT confirmed malicious with real consensus
    if vt["malicious"] >= VT_MALICIOUS_BLOCK and not vt.get("is_noise", False):
        return {
            "verdict":      "DANGEROUS",
            "risk_summary": (
                f"Blocked: {vt['malicious']} security engines on VirusTotal "
                "independently flagged this URL as malicious."
            ),
            "phishing_indicators": [],
            "virustotal":     vt,
            "gmi_screenshot": None,
            "field_map":      {},
            "auto_fill_safe": False,
        }

    # Hard block — drive-by download caught by Playwright
    if gmi.get("has_download_trigger"):
        return {
            "verdict":      "DANGEROUS",
            "risk_summary": (
                "Drive-by download attack detected. "
                "This page attempted to automatically download a file to your device."
            ),
            "phishing_indicators": ["drive-by download"],
            "virustotal":     vt,
            "gmi_screenshot": gmi.get("screenshot_b64"),
            "field_map":      {},
            "auto_fill_safe": False,
        }

    # ── Phase 3: Gemini semantic analysis ───────────────────────────────────
    gemini = await gemini_analyze(url, gmi.get("html", ""), vt, gmi)

    # ── Phase 4: Build response ──────────────────────────────────────────────
    verdict = gemini.get("verdict", "SUSPICIOUS")

    if verdict == "DANGEROUS":
        return {
            "verdict":             "DANGEROUS",
            "risk_summary":        gemini.get("risk_summary", "Phishing or malicious content detected."),
            "phishing_indicators": gemini.get("phishing_indicators", []),
            "virustotal":          vt,
            "gmi_screenshot":      gmi.get("screenshot_b64"),
            "field_map":           {},
            "auto_fill_safe":      False,
        }

    field_map = gemini.get("field_map", {})

    # Deduplicated list of vault keys the form needs — phone checks this
    # before showing the auto-fill button so it knows what data is required
    required_vault_keys = list(dict.fromkeys(
        v for v in field_map.values() if v != "unknown"
    ))

    return {
        "verdict":              verdict,
        "is_official_entity":   gemini.get("is_official_entity", False),
        "official_entity_name": gemini.get("official_entity_name"),
        "page_purpose":         gemini.get("page_purpose", ""),
        "risk_summary":         gemini.get("risk_summary", ""),
        "phishing_indicators":  gemini.get("phishing_indicators", []),
        "field_map":            field_map,
        "required_vault_keys":  required_vault_keys,
        "auto_fill_safe":       gemini.get("auto_fill_safe", False),
        "virustotal":           vt,
    }


@app.get("/health")
async def health():
    return {"status": "ok", "service": "Mr QR Security Orchestrator"}
