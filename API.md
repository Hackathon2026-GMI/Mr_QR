# Mr QR — Frontend Integration Guide

Security API for FIFA World Cup 2026 QR code scanning.
The frontend sends a URL, receives a structured verdict, and (when safe) uses the field map to autofill the form on-device from the user's secure vault.

---

## Base URL

```
POST https://<your-rocketride-webhook-url>
```

The exact URL is provided by Rocketride after the pipeline is activated (Settings → Webhook → Copy URL).

---

## Request

### Headers

```
Content-Type: application/json
```

No API key is required from the frontend — auth is handled server-side.

### Body

```json
{
  "url": "https://tickets.fifa.com/en/buy?event=123"
}
```

| Field | Type   | Required | Description                              |
|-------|--------|----------|------------------------------------------|
| `url` | string | Yes      | Full URL decoded from the QR code, including scheme (`https://`) |

---

## Responses

The `verdict` field is always present and is one of `"SAFE"`, `"SUSPICIOUS"`, or `"DANGEROUS"`.

---

### SAFE — Official page, autofill approved

The page is confirmed as an official FIFA / WC2026 entity and all security checks passed. The app may autofill form fields from the user's vault without extra confirmation.

```json
{
  "verdict": "SAFE",
  "is_official_entity": true,
  "official_entity_name": "FIFA Ticketing",
  "page_purpose": "FIFA 2026 ticket purchase form",
  "risk_summary": "The domain is the official FIFA ticketing platform and all security scans indicate it is safe.",
  "phishing_indicators": [],
  "field_map": {
    "passport_field":  "passport_id",
    "fn_input":        "first_name",
    "ln_input":        "last_name",
    "nationality_sel": "nationality",
    "fan_id_box":      "fifa_fan_id",
    "email_addr":      "email"
  },
  "required_vault_keys": ["passport_id", "first_name", "last_name", "nationality", "fifa_fan_id", "email"],
  "auto_fill_safe": true,
  "virustotal": {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 74,
    "malicious_ratio": 0.0,
    "is_noise": true,
    "domain_known_bad": false,
    "domain_community_malicious": 0,
    "domain_categories": ["government", "sports"]
  },
  "gmi_screenshot": "<base64-jpeg-string or null>"
}
```

---

### SUSPICIOUS — Unknown or non-official page

The page is not a confirmed official entity, or weak threat signals were detected. Form fields are mapped but autofill requires an explicit user tap to confirm.

```json
{
  "verdict": "SUSPICIOUS",
  "is_official_entity": false,
  "official_entity_name": null,
  "page_purpose": "World Cup merchandise store",
  "risk_summary": "This domain is not an official FIFA entity. Verify the site before submitting personal information.",
  "phishing_indicators": [],
  "field_map": {
    "email_input": "email",
    "name_field":  "full_name"
  },
  "required_vault_keys": ["email", "full_name"],
  "auto_fill_safe": false,
  "virustotal": {
    "malicious": 0,
    "suspicious": 0,
    "harmless": 12,
    "malicious_ratio": 0.0,
    "is_noise": true,
    "domain_known_bad": false,
    "domain_community_malicious": 0,
    "domain_categories": ["shopping"]
  },
  "gmi_screenshot": "<base64-jpeg-string or null>"
}
```

---

### DANGEROUS — Block immediately

The page is confirmed phishing, malware, or a drive-by download. Block navigation, show the risk summary, and do not assist with any form interaction.

```json
{
  "verdict": "DANGEROUS",
  "risk_summary": "This page is a phishing site impersonating FIFA to steal passport and credit card information.",
  "phishing_indicators": [
    "non-official domain collecting passport data",
    "payment form on HTTP connection"
  ],
  "field_map": {},
  "required_vault_keys": [],
  "auto_fill_safe": false,
  "virustotal": {
    "malicious": 8,
    "suspicious": 3,
    "harmless": 21,
    "malicious_ratio": 0.25,
    "is_noise": false,
    "domain_known_bad": true,
    "domain_community_malicious": 5,
    "domain_categories": ["phishing", "malware"]
  },
  "gmi_screenshot": "<base64-jpeg-string or null>"
}
```

---

## Field Reference

### Top-level fields

| Field                  | Type            | Verdicts          | Description |
|------------------------|-----------------|-------------------|-------------|
| `verdict`              | string          | all               | `"SAFE"` \| `"SUSPICIOUS"` \| `"DANGEROUS"` |
| `risk_summary`         | string          | all               | One human-readable sentence explaining the result. Show this to the user. |
| `is_official_entity`   | boolean         | SAFE, SUSPICIOUS  | Whether the domain is a confirmed official FIFA / WC2026 entity |
| `official_entity_name` | string \| null  | SAFE, SUSPICIOUS  | Display name of the official entity, e.g. `"FIFA Ticketing"` |
| `page_purpose`         | string          | SAFE, SUSPICIOUS  | One-sentence description of what the page is for |
| `phishing_indicators`  | string[]        | all               | List of specific threat signals detected (empty when clean) |
| `field_map`            | object          | SAFE, SUSPICIOUS  | Maps HTML element IDs/names → vault key types (empty `{}` on DANGEROUS) |
| `required_vault_keys`  | string[]        | SAFE, SUSPICIOUS  | Ordered deduplicated list of vault types the form needs (empty on DANGEROUS) |
| `auto_fill_safe`       | boolean         | all               | `true` only when verdict=SAFE and entity is confirmed official — app may autofill without extra confirmation |
| `virustotal`           | object          | all               | Raw VirusTotal stats (see below) |
| `gmi_screenshot`       | string \| null  | all               | Base64 JPEG screenshot of the page, or null if unavailable |

### `virustotal` object

| Field                       | Type    | Description |
|-----------------------------|---------|-------------|
| `malicious`                 | integer | Number of engines that flagged the URL as malicious |
| `suspicious`                | integer | Number of engines that flagged as suspicious |
| `harmless`                  | integer | Number of engines that cleared the URL |
| `malicious_ratio`           | float   | Fraction of engines that flagged (0.0–1.0). < 0.05 = noise |
| `is_noise`                  | boolean | True when the malicious count is a single-engine outlier contradicted by a strong clean majority |
| `domain_known_bad`          | boolean | True if any engine categorises the domain as malware/phishing/scam |
| `domain_community_malicious`| integer | Community vote count for malicious on the domain |
| `domain_categories`         | string[]| VirusTotal category labels for the domain |

### `field_map` vault key types

The values in `field_map` (and the entries in `required_vault_keys`) are always one of these standard types:

| Vault key type    | Meaning |
|-------------------|---------|
| `first_name`      | Given name |
| `last_name`       | Family name |
| `full_name`       | Full name as a single string |
| `passport_id`     | Passport number |
| `passport_expiry` | Passport expiry date |
| `nationality`     | Nationality / country of citizenship |
| `date_of_birth`   | Date of birth |
| `email`           | Email address |
| `phone`           | Phone number |
| `fifa_fan_id`     | FIFA Fan ID |
| `address`         | Street address |
| `city`            | City |
| `country`         | Country of residence |
| `postal_code`     | Postal / ZIP code |
| `ticket_category` | Ticket type or seating category |
| `payment_card`    | Payment card number |
| `payment_cvv`     | Card CVV / CVC |
| `payment_expiry`  | Card expiry date |
| `unknown`         | Could not be mapped — do not autofill |

---

## Autofill Flow

```
1. Call POST /scan with the URL from the QR code.

2. Check verdict:
   - "DANGEROUS"   → block navigation, show risk_summary, stop.
   - "SUSPICIOUS"  → warn the user, show risk_summary.
                     Display field_map / required_vault_keys if you want to
                     let the user manually confirm filling.
   - "SAFE"        → proceed to step 3.

3. Check required_vault_keys against the local vault.
   For each key in required_vault_keys:
     - If the vault slot is empty → prompt the user to add that data first.
     - If all slots have data    → autofill is ready.

4. Use field_map to inject vault data into form fields (on-device only):
   For each entry { "html_element_id": "vault_key_type" } in field_map:
     - Look up vault_key_type in the local vault → get the value.
     - Set the value of the HTML element whose id or name matches html_element_id.

5. Skip any field_map entry whose value is "unknown".

6. IMPORTANT: No vault data is ever sent to Mr QR or any backend.
   Injection happens entirely on-device inside the WebView.
```

### Autofill rules

| Condition                            | `auto_fill_safe` | Recommended UX |
|--------------------------------------|------------------|----------------|
| SAFE + official entity confirmed     | `true`           | Fill silently, show "Autofilled by Mr QR" badge |
| SUSPICIOUS or unconfirmed entity     | `false`          | Show warning, require user tap to fill each field |
| DANGEROUS                            | `false`          | Block — never assist filling |

---

## Timing

The full pipeline involves three sequential external calls with real network latency. Do not use a short timeout.

| Phase                    | Typical | Worst case |
|--------------------------|---------|------------|
| VirusTotal URL scan      | 10–25 s | 30 s (6 polls × 5 s) |
| VirusTotal domain check  | < 1 s   | 2 s        |
| GMI Playwright deep scan | 5–15 s  | 20 s       |
| Gemini semantic analysis | 3–8 s   | 15 s       |
| **Total**                | **20–40 s** | **60 s** |

Recommended client timeout: **90 seconds**.

Show a progress indicator immediately after the QR scan. A spinner with a message like "Checking security…" covers the expected wait time without alarming users.

---

## Error Handling

The pipeline returns HTTP 200 for all analysed URLs (including DANGEROUS ones). A non-200 response means the pipeline itself failed.

| HTTP status | Meaning | Action |
|-------------|---------|--------|
| 200         | Analysis complete — read `verdict` | Normal |
| 408 / 504   | Timeout — pipeline took too long | Retry once, then show generic warning |
| 5xx         | Infrastructure error | Show "Unable to verify this QR code. Do not proceed." |

When the backend is unreachable, **fail closed**: treat the URL as unverified and warn the user before allowing any interaction with the page.

---

## End-to-End Example (pseudocode)

```javascript
async function scanQRCode(rawUrl) {
  showSpinner("Checking security…");

  let result;
  try {
    const response = await fetch(MRQR_WEBHOOK_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url: rawUrl }),
      signal:  AbortSignal.timeout(90_000),
    });
    result = await response.json();
  } catch (err) {
    hideSpinner();
    showError("Unable to verify this QR code. Do not proceed.");
    return;
  }

  hideSpinner();

  if (result.verdict === "DANGEROUS") {
    blockPage();
    showDangerBanner(result.risk_summary, result.phishing_indicators);
    return;
  }

  if (result.verdict === "SUSPICIOUS") {
    showWarningBanner(result.risk_summary);
    // optionally offer manual field-by-field confirmation
  }

  // Navigate to the URL and attempt autofill
  navigateWebView(rawUrl);
  webView.onPageLoaded(() => {
    if (result.auto_fill_safe && result.field_map) {
      for (const [elementId, vaultKey] of Object.entries(result.field_map)) {
        if (vaultKey === "unknown") continue;
        const value = vault.get(vaultKey);
        if (value) webView.setFieldValue(elementId, value);
      }
      showAutofillBadge(`Autofilled by Mr QR — ${result.official_entity_name}`);
    }
  });
}
```

---

## Privacy Guarantees

- **No personal data reaches Mr QR.** Only the raw URL is sent to the backend.
- **Vault data never leaves the device.** `field_map` contains HTML element identifiers and data-type labels only — not actual values.
- **Screenshots** (`gmi_screenshot`) are taken of the target page (not the user's device) and are used only for threat evidence. They are not stored by the backend.
- **VirusTotal** receives the URL for reputation analysis — this is standard industry practice for URL safety checking.
