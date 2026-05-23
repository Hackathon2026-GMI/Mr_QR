"""
Mr QR — Mock Phishing/Test Server
Serves controlled HTML pages for rigorous pipeline testing.
Run with: uvicorn test_mock_server:app --port 9999
"""

from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, FileResponse
import os

app = FastAPI(title="Mr QR Test Server")


# ── Page 1: Legitimate FIFA-style registration form ──────────────────────────
# Realistic obfuscated field names — tests that Gemini maps them correctly
@app.get("/official-form", response_class=HTMLResponse)
async def official_form():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>FIFA World Cup 2026 — Fan Registration</title></head>
    <body>
      <h1>FIFA World Cup 2026 Official Fan Registration</h1>
      <p>Register your FIFA Fan ID to access ticketing services.</p>
      <form action="/submit" method="POST">
        <label for="fn_field">First Name</label>
        <input id="fn_field" name="first_name" type="text" placeholder="Enter first name" required>

        <label for="ln_01">Last Name / Surname</label>
        <input id="ln_01" name="last_name" type="text" placeholder="Enter last name" required>

        <label for="p_num_01">Passport Number</label>
        <input id="p_num_01" name="passport_no" type="text" placeholder="e.g. AB1234567" required>

        <label for="p_exp">Passport Expiry Date</label>
        <input id="p_exp" name="pass_expiry" type="date" required>

        <label for="dob_input">Date of Birth</label>
        <input id="dob_input" name="birth_date" type="date" required>

        <label for="nat_sel_1">Nationality</label>
        <select id="nat_sel_1" name="nationality" required>
          <option value="">Select your country</option>
          <option value="MX">Mexico</option>
          <option value="US">United States</option>
          <option value="CA">Canada</option>
        </select>

        <label for="fanid_entry">FIFA Fan ID</label>
        <input id="fanid_entry" name="fan_id_num" type="text" placeholder="FAN-XXXXXXX">

        <label for="email_01">Email Address</label>
        <input id="email_01" name="user_email" type="email" placeholder="your@email.com" required>

        <label for="tel_num">Phone Number</label>
        <input id="tel_num" name="phone_no" type="tel" placeholder="+1 555 000 0000">

        <button type="submit">Register</button>
      </form>
    </body>
    </html>
    """


# ── Page 2: Phishing page — FIFA branding on a fake domain ───────────────────
# Collects passport + payment data. Visual phishing score should spike.
@app.get("/phishing-form", response_class=HTMLResponse)
async def phishing_form():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>FIFA World Cup 2026 OFFICIAL Ticket Portal</title></head>
    <body style="background:#003087; color:white; font-family:Arial">
      <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/a/aa/FIFA_logo_without_slogan.svg/200px-FIFA_logo_without_slogan.svg.png" alt="FIFA Logo">
      <h1>FIFA World Cup 2026 — OFFICIAL Ticket Purchase</h1>
      <p>Complete your identity verification to claim your match tickets.</p>
      <p><strong>Fan ID</strong> and passport verification required by FIFA security protocols.</p>

      <form action="/steal-data" method="POST">
        <h3>Identity Verification</h3>
        <input id="inp_001" name="field_a" type="text" placeholder="Full Name (as on passport)" required>
        <input id="inp_002" name="field_b" type="text" placeholder="Passport Number" required>
        <input id="inp_003" name="field_c" type="text" placeholder="Nationality / Country of Origin" required>
        <input id="inp_004" name="field_d" type="text" placeholder="FIFA Fan ID / Supporter ID" required>
        <input id="inp_005" name="field_e" type="date" placeholder="Date of Birth" required>

        <h3>Payment Details</h3>
        <input id="inp_006" name="field_f" type="text" placeholder="Credit Card Number" required>
        <input id="inp_007" name="field_g" type="text" placeholder="Expiry Date (MM/YY)" required>
        <input id="inp_008" name="field_h" type="text" placeholder="CVV / CVC Security Code" required>
        <input id="inp_009" name="field_i" type="email" placeholder="Email for ticket delivery" required>

        <button type="submit" style="background:gold; color:black; padding:10px 30px">
          Confirm & Purchase Tickets — Official FIFA Portal
        </button>
      </form>
      <p>© 2026 FIFA World Cup. Official Match Hospitality. Fan Zone Access.</p>
    </body>
    </html>
    """


# ── Page 3: Drive-by download — APK pushed via Content-Disposition ────────────
@app.get("/drive-by")
async def drive_by():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
      <title>FIFA World Cup 2026 App — Install Now</title>
      <meta http-equiv="refresh" content="1; url=/fake-update.apk">
    </head>
    <body>
      <h1>FIFA 2026 Official App Update Required</h1>
      <p>Your FIFA 2026 app is out of date. Downloading update automatically...</p>
      <p>Please install the FIFA Security Update to continue.</p>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/fake-update.apk")
async def fake_apk():
    # Return a harmless 10-byte payload with .apk extension and dangerous headers
    return Response(
        content=b"FAKE_APK_TEST",
        media_type="application/vnd.android.package-archive",
        headers={
            "Content-Disposition": "attachment; filename=fifa2026_security_update.apk"
        },
    )


# ── Page 4: Clean non-FIFA page (e.g. sponsor landing page) ──────────────────
@app.get("/clean-sponsor", response_class=HTMLResponse)
async def clean_sponsor():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Coca-Cola FIFA Partner — Win Tickets</title></head>
    <body>
      <h1>Coca-Cola x FIFA World Cup 2026</h1>
      <p>Enter your email for a chance to win match tickets.</p>
      <form>
        <input id="email" name="email" type="email" placeholder="Your email address">
        <button type="submit">Enter Draw</button>
      </form>
    </body>
    </html>
    """


# ── Page 5: Redirect chain — short URL → phishing ────────────────────────────
@app.get("/redirect")
async def redirect_chain():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/phishing-form", status_code=302)


# ── Page 6: Empty / 404-style page ───────────────────────────────────────────
@app.get("/empty", response_class=HTMLResponse)
async def empty_page():
    return "<html><body></body></html>"
