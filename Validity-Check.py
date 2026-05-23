import streamlit as st
import cv2
import requests
import os
import av
import time
import threading
from dotenv import load_dotenv
from streamlit_webrtc import webrtc_streamer, VideoProcessorBase

load_dotenv()

GMI_API_URL = "https://api.gmi-serving.com/v1/chat/completions"
GMI_MODEL = "deepseek-ai/DeepSeek-V4-Pro"

SYSTEM_PROMPT = """You are a QR code payload security validator.
Analyze the given QR code payload and assess:
1. What type of content it contains (URL, vCard, text, WiFi credentials, payment, etc.)
2. Whether the content appears legitimate and safe
3. Any potential security risks (phishing URLs, malicious patterns, suspicious data)
4. A clear verdict: VALID, SUSPICIOUS, or INVALID

Start your response with the verdict on its own line, then explain."""


def validate_payload(payload: str, api_key: str) -> str:
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    body = {
        "model": GMI_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Validate this QR code payload:\n\n{payload}"},
        ],
        "temperature": 0,
        "max_tokens": 500,
    }
    resp = requests.post(GMI_API_URL, headers=headers, json=body, timeout=30)
    if not resp.ok:
        try:
            detail = resp.json().get("error", {}).get("message") or resp.text
        except Exception:
            detail = resp.text
        raise ValueError(f"HTTP {resp.status_code}: {detail}")
    content = resp.json().get("choices", [{}])[0].get("message", {}).get("content")
    if not content:
        raise ValueError(f"Unexpected API response: {resp.text[:300]}")
    return content


class QRVideoProcessor(VideoProcessorBase):
    def __init__(self):
        self._detector = cv2.QRCodeDetector()
        self.lock = threading.Lock()
        self.last_detected: str | None = None

    def recv(self, frame: av.VideoFrame) -> av.VideoFrame:
        img = frame.to_ndarray(format="bgr24")
        data, bbox, _ = self._detector.detectAndDecode(img)

        if data:
            with self.lock:
                self.last_detected = data
            if bbox is not None:
                pts = bbox.astype(int).reshape((-1, 1, 2))
                cv2.polylines(img, [pts], True, (0, 255, 0), 3)
            cv2.putText(img, "QR Detected!", (10, 35),
                        cv2.FONT_HERSHEY_SIMPLEX, 1.0, (0, 255, 0), 2)

        return av.VideoFrame.from_ndarray(img, format="bgr24")


# ── Session state ─────────────────────────────────────────────────────────────

for key, default in [("scan_done", False), ("validation", None)]:
    if key not in st.session_state:
        st.session_state[key] = default

# ── UI ────────────────────────────────────────────────────────────────────────

st.set_page_config(page_title="QR Validator", page_icon="🔍", layout="centered")
st.title("QR Code Validator")
st.caption("Auto-validated by DeepSeek-V4-Pro via GMI")

api_key = os.getenv("GMI_API_KEY", "")
if not api_key:
    st.error("GMI_API_KEY not found — add it to your .env file.")
    st.stop()

# ── Results view (camera closed) ──────────────────────────────────────────────

if st.session_state.scan_done:
    payload, result = st.session_state.validation
    upper = (result or "").upper()
    msg = f"**Payload:** `{payload}`\n\n{result}"
    if "SUSPICIOUS" in upper:
        st.warning(msg)
    elif "INVALID" in upper:
        st.error(msg)
    else:
        st.success(msg)

    if st.button("Scan Another QR Code"):
        st.session_state.scan_done = False
        st.session_state.validation = None
        st.rerun()

# ── Camera view ───────────────────────────────────────────────────────────────

else:
    st.info("Point your camera at a QR code — it will be validated automatically.")

    ctx = webrtc_streamer(
        key="qr-scanner",
        video_processor_factory=QRVideoProcessor,
        media_stream_constraints={"video": True, "audio": False},
        async_processing=True,
    )

    status = st.empty()

    if ctx.video_processor:
        while ctx.state.playing:
            with ctx.video_processor.lock:
                detected = ctx.video_processor.last_detected

            if detected:
                status.info(f"**Detected:** `{detected}`\n\nValidating with DeepSeek…")
                try:
                    result = validate_payload(detected, api_key)
                except Exception as e:
                    status.error(f"**API error**\n\n```\n{e}\n```")
                else:
                    st.session_state.validation = (detected, result)
                    st.session_state.scan_done = True
                    st.rerun()

            time.sleep(0.1)
