import asyncio, json, sys
sys.path.insert(0, 'c:/Mr_QR')
from backend.orchestrator import scan_url, virustotal_scan, ScanRequest

async def test():
    print("--- VT dual-check: FIFA domain ---")
    vt = await virustotal_scan("https://www.fifa.com")
    print(json.dumps(vt, indent=2))

    print()
    print("--- VT dual-check: phishing domain ---")
    vt2 = await virustotal_scan("http://fifa-ticket-worldcup2026.xyz")
    print(json.dumps(vt2, indent=2))

    print()
    print("--- Full pipeline: FIFA ---")
    r1 = await scan_url(ScanRequest(url="https://www.fifa.com"))
    print("  verdict:", r1["verdict"])
    print("  official_entity:", r1.get("official_entity_name"))
    print("  auto_fill_safe:", r1.get("auto_fill_safe"))
    print("  field_map:", r1.get("field_map"))
    print("  summary:", r1.get("risk_summary", r1.get("block_reason")))

    print()
    print("--- Full pipeline: phishing domain ---")
    r2 = await scan_url(ScanRequest(url="http://fifa-ticket-worldcup2026.xyz"))
    print("  verdict:", r2["verdict"])
    print("  summary:", r2.get("risk_summary", r2.get("block_reason")))

asyncio.run(test())
