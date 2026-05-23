# Integration Guide — QR Code Security Validator

A real-time QR code security scanner powered by DeepSeek-V4-Pro via GMI Cloud. Points a webcam at any QR code and returns an AI verdict (VALID / SUSPICIOUS / INVALID) with an explanation.

---

## Architecture

```
Camera (WebRTC)
    │
    ▼
OpenCV QR Detector          ← runs in-browser via streamlit-webrtc
    │  decoded payload
    ▼
GMI Cloud API               ← DeepSeek-V4-Pro model
    │  verdict + explanation
    ▼
Streamlit UI                ← displays result with colour-coded alert
```

There is also an early-stage **RocketRide pipeline** (`Workflow.pipe`) with a webhook source that is intended to extend this into a broader AI pipeline for batch or automated QR validation flows.

---

## Repository Layout

```
Hackathon/
├── Validity-Check.py     # Streamlit app — main entry point
├── Workflow.pipe         # RocketRide pipeline definition (webhook source)
├── requirements.txt      # Python dependencies
├── .env                  # Placeholder only — real keys live outside the repo
└── .rocketride/          # RocketRide SDK schemas and docs
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.10+ | Tested on 3.10–3.12 |
| GMI Cloud account | Get an API key at [gmi-serving.com](https://gmi-serving.com) |
| Webcam | Required for live scanning |
| OS camera permission | Must be granted to the browser |

---

## Setup

### 1. Clone and create a virtual environment

```bash
git clone <repo-url>
cd Hackathon
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Store the GMI API key

The app reads `GMI_API_KEY` from `~/.secrets/gmi.env`. Create that file:

```bash
mkdir -p ~/.secrets
echo "GMI_API_KEY=your_key_here" > ~/.secrets/gmi.env
chmod 600 ~/.secrets/gmi.env
```

> **Do not** put real keys in the repo's `.env` file — it is intentionally left empty as a reminder.

### 4. Run the app

```bash
streamlit run Validity-Check.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser, allow camera access, and point the camera at a QR code.

---

## How It Works

### QR Detection (`Validity-Check.py`)

`QRVideoProcessor` (a `VideoProcessorBase` subclass) runs on every video frame via `streamlit-webrtc`:

- Uses `cv2.QRCodeDetector` to detect and decode QR codes.
- On detection, draws a green bounding box and sets `self.last_detected`.
- The main thread polls `last_detected` every 100 ms; once a payload is found it fires the API call and stops scanning.

### AI Validation

`validate_payload(payload, api_key)` posts to the GMI endpoint:

- **Model:** `deepseek-ai/DeepSeek-V4-Pro`
- **Endpoint:** `https://api.gmi-serving.com/v1/chat/completions`
- **System prompt:** instructs the model to classify the payload as `VALID`, `SUSPICIOUS`, or `INVALID` and explain why.
- **Temperature:** `0` (deterministic output)
- **Max tokens:** `500`

The model response always starts with the verdict keyword on its own line, followed by the explanation.

### UI States

| State | What the user sees |
|---|---|
| No QR detected | Live camera feed with instructions |
| QR detected, awaiting API | Info banner with detected payload |
| API error | Red error box with HTTP details |
| VALID | Green success box |
| SUSPICIOUS | Yellow warning box |
| INVALID | Red error box |

A "Scan Another QR Code" button resets state for the next scan.

---

## Environment Variables

| Variable | Where to set | Required |
|---|---|---|
| `GMI_API_KEY` | `~/.secrets/gmi.env` | Yes |

The app calls `load_dotenv(Path.home() / ".secrets" / "gmi.env")` at startup.

---

## RocketRide Pipeline (`Workflow.pipe`)

The pipeline file is a RocketRide v1 definition currently containing a single **webhook source** component. This is the foundation for a future automated pipeline that could:

- Accept QR payloads via HTTP webhook (e.g., from a scanner device or mobile app)
- Route payloads through AI validation steps
- Fan out results to downstream systems

To extend the pipeline, refer to `.rocketride/docs/` — start with `ROCKETRIDE_README.md`, then `ROCKETRIDE_PIPELINE_RULES.md` and `ROCKETRIDE_COMPONENT_REFERENCE.md`.

---

## Key Dependencies

| Package | Purpose |
|---|---|
| `streamlit` | Web UI framework |
| `streamlit-webrtc` | Browser camera access via WebRTC |
| `opencv-python` | QR code detection on video frames |
| `av` | Video frame decoding (used by streamlit-webrtc) |
| `requests` | HTTP calls to GMI API |
| `python-dotenv` | Loads API keys from `.env` files |

---

## Extending the Project

### Swap the AI model

Change `GMI_MODEL` in `Validity-Check.py:15` to any model supported by GMI Cloud. The request format follows the OpenAI chat completions schema.

### Add batch/webhook mode

Flesh out `Workflow.pipe` using the RocketRide SDK. The webhook source is already wired; add an LLM component pointing to the same GMI endpoint and a sink to store or forward results.

### Add history / logging

`st.session_state` currently holds only the most recent scan. Append results to a list in session state, or write to a local SQLite database, to build a scan history view.

---

## Security Notes

- API keys are stored outside the repository (`~/.secrets/`) and never committed.
- The system prompt is fixed server-side — users cannot inject instructions through QR payloads (the payload is passed as a user message, not as a system prompt).
- WebRTC video is processed locally; raw frames are never sent to any external service — only the decoded text payload is transmitted.
