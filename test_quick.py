import asyncio, json, sys
sys.path.insert(0, "c:/Mr_QR")
from backend.orchestrator import scan_url, ScanRequest

async def main():
    tests = [
        ("REAL  — fifa.com",          "https://www.fifa.com"),
        ("PHISH — localhost phishing", "http://localhost:9999/phishing-form"),
    ]
    for label, url in tests:
        print(f"\n{'='*60}")
        print(f"  {label}")
        print(f"  {url}")
        print(f"{'='*60}")
        r = await scan_url(ScanRequest(url=url))
        print(f"  verdict         : {r.get('verdict')}")
        print(f"  auto_fill_safe  : {r.get('auto_fill_safe')}")
        print(f"  page_purpose    : {r.get('page_purpose', '')}")
        print(f"  risk_summary    : {r.get('risk_summary', '')}")
        fm = r.get('field_map', {})
        print(f"  field_map       : {json.dumps(fm) if fm else '(empty)'}")
        print(f"  vault_keys      : {r.get('required_vault_keys', [])}")
        vt = r.get('virustotal', {})
        print(f"  VT malicious    : {vt.get('malicious',0)}/{vt.get('total_engines',0)}  noise={vt.get('is_noise','?')}")

asyncio.run(main())
