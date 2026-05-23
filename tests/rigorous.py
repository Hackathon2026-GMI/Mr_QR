"""
Mr QR — Rigorous Test Suite
Simulates real front-end scan requests across every verdict path.
Run with: python tests/rigorous.py
Requires: gmi_worker on :8001, mock server on :9999
"""

import asyncio
import json
import sys
import os
import time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.orchestrator import scan_url, ScanRequest

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
GREY   = "\033[90m"

PASS = f"{GREEN}PASS{RESET}"
FAIL = f"{RED}FAIL{RESET}"


def verdict_colour(v):
    if v == "SAFE":       return f"{GREEN}{BOLD}SAFE{RESET}"
    if v == "SUSPICIOUS": return f"{YELLOW}{BOLD}SUSPICIOUS{RESET}"
    if v == "DANGEROUS":  return f"{RED}{BOLD}DANGEROUS{RESET}"
    return v


TESTS = [
    # ── Group A: Real official FIFA/WC2026 domains ───────────────────────────
    {
        "label":            "A1 — FIFA homepage (real)",
        "url":              "https://www.fifa.com",
        "expect":           "SAFE",
        "expect_autofill":  True,
        "expect_field_map": False,
        "expect_keys":      [],
    },
    {
        "label":            "A2 — FIFA ticketing subdomain (real)",
        "url":              "https://tickets.fifa.com",
        "expect":           "SAFE",
        "expect_autofill":  True,
        "expect_field_map": None,
        "expect_keys":      [],
    },
    {
        "label":            "A3 — WC2026 official site (real)",
        "url":              "https://www.the26.com",
        "expect":           "SAFE",
        "expect_autofill":  True,
        "expect_field_map": None,
        "expect_keys":      [],
    },

    # ── Group B: Real clean non-FIFA domains ─────────────────────────────────
    {
        "label":            "B1 — Google (clean, non-FIFA)",
        "url":              "https://www.google.com",
        "expect":           "SUSPICIOUS",
        "expect_autofill":  False,
        "expect_field_map": None,
        "expect_keys":      [],
    },
    {
        "label":            "B2 — Wikipedia (clean, non-FIFA)",
        "url":              "https://en.wikipedia.org/wiki/2026_FIFA_World_Cup",
        "expect":           "SUSPICIOUS",
        "expect_autofill":  False,
        "expect_field_map": None,
        "expect_keys":      [],
    },

    # ── Group C: Mock server — controlled HTML scenarios ─────────────────────
    {
        "label":            "C1 — Mock: official-style form (field mapping test)",
        "url":              "http://localhost:9999/official-form",
        "expect":           "SUSPICIOUS",
        "expect_autofill":  False,
        "expect_field_map": True,
        "expect_keys":      ["passport_id", "first_name", "last_name",
                             "nationality", "fifa_fan_id", "email"],
    },
    {
        "label":            "C2 — Mock: phishing form (passport + payment)",
        "url":              "http://localhost:9999/phishing-form",
        "expect":           "DANGEROUS",
        "expect_autofill":  False,
        "expect_field_map": False,
        "expect_keys":      [],
    },
    {
        "label":            "C3 — Mock: drive-by APK download",
        "url":              "http://localhost:9999/drive-by",
        "expect":           "DANGEROUS",
        "expect_autofill":  False,
        "expect_field_map": False,
        "expect_keys":      [],
    },
    {
        "label":            "C4 — Mock: redirect chain to phishing form",
        "url":              "http://localhost:9999/redirect",
        "expect":           "DANGEROUS",
        "expect_autofill":  False,
        "expect_field_map": False,
        "expect_keys":      [],
    },
    {
        "label":            "C5 — Mock: clean sponsor form (email only)",
        "url":              "http://localhost:9999/clean-sponsor",
        "expect":           "SUSPICIOUS",
        "expect_autofill":  False,
        "expect_field_map": True,
        "expect_keys":      ["email"],
    },
    {
        "label":            "C6 — Mock: empty page",
        "url":              "http://localhost:9999/empty",
        "expect":           "SUSPICIOUS",
        "expect_autofill":  False,
        "expect_field_map": False,
        "expect_keys":      [],
    },

    # ── Group D: Real lookalike / phishing domains ───────────────────────────
    {
        "label":            "D1 — FIFA lookalike domain (.xyz)",
        "url":              "http://fifa-ticket-worldcup2026.xyz",
        "expect":           "SUSPICIOUS",
        "expect_autofill":  False,
        "expect_field_map": None,
        "expect_keys":      [],
    },
    {
        "label":            "D2 — Known malware test page",
        "url":              "http://malware.wicar.org/data/eicar.com",
        "expect":           "DANGEROUS",
        "expect_autofill":  False,
        "expect_field_map": False,
        "expect_keys":      [],
    },
    {
        "label":            "D3 — HTTP fifa.com (redirects to HTTPS)",
        "url":              "http://www.fifa.com",
        "expect":           "SAFE",
        "expect_autofill":  True,
        "expect_field_map": None,
        "expect_keys":      [],
    },
]


async def run_test(test: dict, idx: int, total: int) -> dict:
    label = test["label"]
    url   = test["url"]
    print(f"\n{BLUE}{'-'*70}{RESET}")
    print(f"{BOLD}[{idx}/{total}] {label}{RESET}")
    print(f"{GREY}  URL: {url}{RESET}")

    start  = time.time()
    result = {}
    error  = None

    try:
        result = await scan_url(ScanRequest(url=url))
    except Exception as exc:
        error = str(exc)

    elapsed = time.time() - start
    passed  = True
    notes   = []

    if error:
        print(f"  {RED}ERROR:{RESET} {error}")
        return {"label": label, "url": url, "passed": False,
                "verdict": "ERROR", "elapsed": elapsed, "notes": [error]}

    verdict      = result.get("verdict", "UNKNOWN")
    auto_fill    = result.get("auto_fill_safe", False)
    field_map    = result.get("field_map", {})
    vault_keys   = result.get("required_vault_keys", [])
    page_purpose = result.get("page_purpose", "")
    risk_summary = result.get("risk_summary", "")
    vt           = result.get("virustotal", {})

    print(f"  Verdict        : {verdict_colour(verdict)}  ({elapsed:.1f}s)")
    print(f"  Page purpose   : {page_purpose or '-'}")
    print(f"  Risk summary   : {risk_summary}")
    print(f"  Auto-fill safe : {auto_fill}")
    print(f"  Field map      : {json.dumps(field_map) if field_map else '(empty)'}")
    print(f"  Vault keys     : {vault_keys or '(none)'}")
    print(f"  VT malicious   : {vt.get('malicious',0)}/{vt.get('total_engines',0)} engines  "
          f"ratio={vt.get('malicious_ratio',0):.1%}  noise={vt.get('is_noise','?')}")
    if result.get("phishing_indicators"):
        print(f"  Phishing flags : {result['phishing_indicators']}")
    if result.get("gmi_screenshot"):
        print(f"  Screenshot     : {GREEN}captured{RESET} ({len(result['gmi_screenshot'])//1024} KB)")

    expected_verdict = test.get("expect")
    if expected_verdict and verdict != expected_verdict:
        notes.append(f"verdict expected {expected_verdict}, got {verdict}")
        passed = False

    if test.get("expect_autofill") is not None:
        if auto_fill != test["expect_autofill"]:
            notes.append(f"auto_fill_safe expected {test['expect_autofill']}, got {auto_fill}")
            passed = False

    if test.get("expect_field_map") is True and not field_map:
        notes.append("expected non-empty field_map, got empty")
        passed = False

    if test.get("expect_field_map") is False and field_map:
        notes.append(f"expected empty field_map, got {list(field_map.keys())}")
        passed = False

    for key in test.get("expect_keys", []):
        if key not in vault_keys:
            notes.append(f"expected '{key}' in required_vault_keys")
            passed = False

    status = PASS if passed else FAIL
    for note in notes:
        print(f"  {FAIL} {note}")
    print(f"  Result: {status}")

    return {
        "label":   label,
        "url":     url,
        "passed":  passed,
        "verdict": verdict,
        "elapsed": elapsed,
        "notes":   notes,
    }


async def main():
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  Mr QR — Rigorous Test Suite{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"  {len(TESTS)} test cases across 4 groups")
    print(f"  Mock server : http://localhost:9999")
    print(f"  GMI worker  : http://localhost:8001\n")

    results = []
    for i, test in enumerate(TESTS, 1):
        r = await run_test(test, i, len(TESTS))
        results.append(r)
        if i < len(TESTS):
            await asyncio.sleep(3)

    passed = [r for r in results if r["passed"]]
    failed = [r for r in results if not r["passed"]]
    avg_t  = sum(r["elapsed"] for r in results) / len(results)

    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{'='*70}")
    print(f"  Passed : {GREEN}{len(passed)}/{len(results)}{RESET}")
    print(f"  Failed : {RED}{len(failed)}/{len(results)}{RESET}")
    print(f"  Avg time per scan : {avg_t:.1f}s")

    counts = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(f"  Verdict breakdown : {counts}")

    if failed:
        print(f"\n{RED}  Failed tests:{RESET}")
        for r in failed:
            print(f"    {r['label']}")
            for note in r.get("notes", []):
                print(f"      -> {note}")

    print(f"\n{'='*70}\n")
    return len(failed) == 0


if __name__ == "__main__":
    ok = asyncio.run(main())
    sys.exit(0 if ok else 1)
