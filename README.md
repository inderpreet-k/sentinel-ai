# Sentinel AI — Automated Web Security API

> Live multi-tenant security API. Drop it into any website and it screens incoming requests for SQL injection, XSS, and other attacks in real time.

**Live dashboard:** https://sentinel-ai-web.onrender.com
**Live API:** https://sentinel-ai-3xkl.onrender.com
**GitHub:** https://github.com/inderpreet-k/sentinel-ai

---

## What is Sentinel AI?

Sentinel AI is a hosted security middleware service. Register a site, get an API key, and send it incoming request data — it tells you whether to allow or block, using a mix of explicit rules and a trained ML classifier.

Originally built as a single-machine PHP/MySQL project for INFO3235 (Software Quality Assurance) at KPU. It has since been rebuilt into a fully deployed, multi-tenant service so any site — not just one local PHP app — can use it.

---

## Architecture

```
Client site (PHP / JS / Python)
        │
        ▼
  Sentinel SDK  ──►  POST /check  (FastAPI, hosted on Render)
        │                  │
        │        ┌─────────┴─────────┐
        │        │                   │
        │  Explicit Rules       ML Model
        │  (high-confidence     (Random Forest,
        │   signatures)         TF-IDF n-gram)
        │        │                   │
        │        └─────────┬─────────┘
        │                  │
        │        Attack? (confidence > 0.75)
        │                  │
        │           YES ───┼─── NO
        │            │              │
        │      Blacklist IP      Logged as clean
        │      + block            (allowed)
        │            │
        └── Response: { decision, reason, confidence }
```

- **API:** FastAPI, deployed on Render
- **Database:** PostgreSQL (Supabase), multi-tenant — one `sites` row per registered website, scoped `blacklist` and `events` tables per site
- **ML:** Random Forest classifier, character-level TF-IDF n-grams, trained on 24,161 labeled payloads, 92% detection accuracy
- **Dashboard:** static site for registering, viewing your API key, attack log, and blocked IPs

---

## Quick Start — Protect Your Site in 3 Steps

### Step 1 — Get an API key
Register at the [live dashboard](https://sentinel-ai-web.onrender.com). Enter your site name and email, and your API key is generated instantly.

> Note: the API is hosted on Render's free tier, which spins down after inactivity. The first request after a period of no traffic may take up to ~50 seconds while it wakes back up — subsequent requests are fast.

### Step 2 — Download the SDK and drop it in your project
Go to [`/sdks`](https://github.com/inderpreet-k/sentinel-ai/tree/main/sdks), open the folder for your language, and download the SDK file (`sentinel.php`, `sentinel.js`, or `sentinel.py`). Click the file → **Raw** → save it directly into your project folder, next to your main app file.

Then copy the matching snippet below:

**PHP**
```php
<?php
require_once 'sentinel.php';
Sentinel::init('https://sentinel-ai-3xkl.onrender.com', 'sk-your-key-here');
Sentinel::check();
?>
```

**JavaScript (Express / Next.js)**
```js
const sentinel = require('./sentinel');
sentinel.init('https://sentinel-ai-3xkl.onrender.com', 'sk-your-key-here');
app.use(sentinel.middleware());
```

**Python (Flask / Django)**
```python
from sentinel import Sentinel

sentinel = Sentinel('https://sentinel-ai-3xkl.onrender.com', 'sk-your-key-here')

@app.before_request
def protect():
    result = sentinel.check_flask_request(request)
    if result['decision'] == 'block':
        return jsonify({'error': 'Blocked'}), 403
```

### Step 3 — Deploy
Push your changes. Every request to your site now gets screened before it reaches your app logic.

---

## Try It Live

Want to see Sentinel AI actually catch an attack instead of just reading about it? It's protecting a real production app right now:

**[Spending Spotlight](https://spending-spotlight.vercel.app/)** — an AI bank statement analyzer, secured with Sentinel AI.

1. Open the link above
2. In the "Add Custom Category" textbox, try entering: `<script>alert('XSS')</script>`
3. Continue through and upload a **real bank statement PDF** — a test/blank/fake file won't work here, since the app needs actual transaction lines to parse or it will return "no transactions found"
4. Submit to analyze

The request gets screened by Sentinel before it's processed.

> **We do not save any of your data.** Your uploaded statement is processed in memory to extract and classify transactions, then deleted immediately after — nothing is stored on our end.

---

## Detection Capabilities

| Attack Type | Detection Method | Example |
|---|---|---|
| SQL DELETE / DROP / TRUNCATE | Explicit Rule | `delete from users where id=1` |
| SQL Auth Bypass | Explicit Rule | `' OR '1'='1` |
| XSS Script Tag | Explicit Rule | `<script>alert(1)</script>` |
| XSS Image onerror | Explicit Rule | `<img src=x onerror=alert(1)>` |
| UNION Extraction | ML Detection | `union select null, password` |
| Time-based Blind SQLi | ML Detection | `'; WAITFOR DELAY '0:0:5'--` |
| PHP Code Injection | Explicit Rule | `<?php system($_GET['cmd']); ?>` |
| OS Command Injection | Explicit Rule | `system('cat /etc/passwd')` |
| Mixed-case Obfuscation | ML Detection (1.00) | `sElEcT * fRoM users` |

**Known limitations** (from JUnit evaluation, 25 test cases, 92% pass rate):
- `update users set role='admin'` — false negative at ML confidence 0.58 (below 0.75 threshold)
- `Select all vegetarian options please` — false positive at ML confidence 0.76

These reflect the real-world tradeoff between sensitivity and specificity in ML-based security systems.

---

## Tech Stack

- **Python 3.13** — API and ML pipeline
- **FastAPI** — multi-tenant REST API
- **PostgreSQL** (Supabase) — sites, blacklist, and event log storage
- **Scikit-Learn** — Random Forest Classifier (300 trees, balanced weights)
- **TF-IDF Vectorizer** — character-level n-grams (1–4), 80,000 features
- **Render** — hosting for both the API and dashboard
- **Java JUnit 5** — 25 automated integration test cases (from original academic build)

---

## Project Structure

```
sentinel-ai/
├── api/
│   ├── main.py              # FastAPI app, routes, auth
│   ├── db.py                 # PostgreSQL models and queries
│   └── detector.py           # ML + rule-based analysis
├── dashboard/                 # Static frontend (registration, API key, attack log)
├── sdks/
│   ├── php/
│   ├── javascript/
│   └── python/
├── junit_tests/
│   └── SentinelTest.java     # JUnit 5 integration test suite (25 cases)
├── sentinel_model.pkl         # Trained Random Forest model
├── vectorizer.pkl             # Fitted TF-IDF vectorizer
├── training_data_encoded.csv  # Training dataset (24,161 rows)
└── requirements.txt
```

---

## Academic Origins

Originally developed for **INFO3235 Software Quality Assurance** at Kwantlen Polytechnic University (April 2026) as a single-machine PHP/MySQL prototype, demonstrating:

- **Defect Containment** — blocking attackers without patching the vulnerable code
- **Fault Tolerance** — system stays operational for legitimate users under attack
- **Automated Incident Response** — zero human intervention from detection to block
- **Dynamic Testing** — real-time runtime analysis of live traffic
- **Predictive Validation** — quantifiable detection metrics via JUnit

It has since been rebuilt as a production multi-tenant API to demonstrate real-world deployment beyond the original coursework scope.

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

Built by [Inderpreet Kaur](https://github.com/inderpreet-k) · Powered by FastAPI, PostgreSQL, and scikit-learn