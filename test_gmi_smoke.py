import asyncio, httpx, sys
sys.path.insert(0, "c:/Mr_QR")
from dotenv import load_dotenv
from pathlib import Path
load_dotenv(Path("c:/Mr_QR/.env"))
import os

KEY   = os.environ["ROCKETRIDE_GMI_API_KEY"]
BASE  = os.environ.get("GMI_INFERENCE_URL", "https://api.gmi-serving.com/v1")
MODEL = os.environ.get("GMI_ANALYSIS_MODEL", "google/gemini-3.1-pro-preview")

async def main():
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{BASE}/chat/completions",
            headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"},
            json={
                "model": MODEL,
                "messages": [{"role": "user", "content": 'Reply with exactly: {"ok": true}'}],
                "temperature": 0.0,
                "response_format": {"type": "json_object"},
            }
        )
    print("Status :", r.status_code)
    body = r.json()
    if r.status_code == 200:
        print("Content:", body["choices"][0]["message"]["content"])
    else:
        print("Error  :", body)

asyncio.run(main())
