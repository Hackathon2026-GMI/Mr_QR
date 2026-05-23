# Mr QR — GMI Playwright Security Worker
# Deployed to Cloud Run; called by the Rocketride pipeline for deep page scanning.

FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

# Install Python dependencies (Playwright browsers already in base image)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Chromium via Playwright (ensures version matches the library)
RUN playwright install chromium

COPY gmi_worker.py .

EXPOSE 8001

CMD ["uvicorn", "gmi_worker:app", "--host", "0.0.0.0", "--port", "8001"]
