# Sentinel AI — Automated Security Incident Response System

> **INFO3235 Software Quality Assurance — Term Project**  
> Kwantlen Polytechnic University | April 2026  
> Student: Inderpreet Kaur

---

## What is Sentinel AI?

Sentinel AI is a real-time security middleware tool that monitors a PHP web application, detects malicious input using Machine Learning, and automatically blocks attackers — all without modifying a single line of the target application's original code.

Built to demonstrate **automated incident response** and **defect containment** from Software Quality Assurance coursework.

---

## Quick Start — Test It in 5 Minutes

This repo includes a ready-made vulnerable PHP target (`target.php`) so you can see Sentinel AI in action immediately. No extra setup needed beyond XAMPP and Python.

### What you need
- [XAMPP](https://www.apachefriends.org/) (Apache + MySQL)
- Python 3.8+
- A browser

### Step 1 — Clone the repo
```bash
git clone https://github.com/inderpreet-k/sentinel-ai.git
```

### Step 2 — Copy to XAMPP
Copy the entire repo folder into:
```
C:\xampp\htdocs\sentinel-ai\
```

### Step 3 — Set up the database
1. Start XAMPP — make sure Apache and MySQL are green
2. Open `http://localhost/phpmyadmin`
3. Click **New** → name it `sentinel_test` → click **Create**
4. Click the **SQL** tab → paste and run the contents of `sql/setup.sql`

### Step 4 — Install Python dependencies
```bash
pip install scikit-learn mysql-connector-python joblib pandas
```

### Step 5 — Update the database name in sentinel_brain.py
Open `sentinel_brain.py` and find:
```python
database="catering_ms"
```
Change it to:
```python
database="sentinel_test"
```

### Step 6 — Start the sentinel
Open a terminal in the repo folder:
```bash
python sentinel_brain.py
```
You should see:
```
--- Sentinel AI is now Active and Monitoring Traffic ---
--- Hybrid Mode: ML + Explicit Rules ---
```

### Step 7 — Open the test app
Go to: `http://localhost/sentinel-ai/target.php`

### Step 8 — Test it

**Safe input** (should work normally):
```
Surrey, BC
```

**Attack inputs** (should trigger block — try these one at a time):
```
' OR '1'='1
delete from bookings where id=1
<script>alert('XSS')</script>
system('cat /etc/passwd')
sElEcT * fRoM bookings
```

After submitting an attack, refresh the page — you will see the **Access Denied** screen.

**To reset after a block**, run this in phpMyAdmin:
```sql
DELETE FROM blacklist WHERE ip_address = '::1';
```
Then clear the log file (`security_audit.log`) and restart the sentinel.

---

## How It Works

```
User submits form
       │
       ▼
PHP logs payload ──► security_audit.log
                            │
                            ▼
                Python Sentinel reads log
                            │
                ┌───────────┴───────────┐
                │                       │
          Explicit Rules            ML Model
          (high confidence          (Random Forest
           signatures)              TF-IDF n-gram)
                │                       │
                └───────────┬───────────┘
                            │
                Attack? (confidence > 0.75)
                            │
                     YES ───┼─── NO
                      │              │
               INSERT INTO       [SAFE] logged
               blacklist table
                      │
               PHP checks blacklist
               on next page load
                      │
               ACCESS DENIED screen
```

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

---

## Tech Stack

- **Python 3.13** — Sentinel brain and training scripts
- **Scikit-Learn** — Random Forest Classifier (300 trees, balanced weights)
- **TF-IDF Vectorizer** — Character-level n-grams (1–4), 80,000 features
- **MySQL** — Blacklist persistence layer
- **Java JUnit 5** — 25 automated integration test cases
- **PHP / XAMPP** — Target application environment

---

## Project Structure

```
sentinel-ai/
├── target.php                  # Standalone vulnerable PHP test app
├── sentinel_brain.py           # Main monitoring and response engine
├── train_sentinel.py           # Model training script
├── training_data_encoded.csv   # Base64-encoded training dataset (24,161 rows)
├── sentinel_model.pkl          # Trained Random Forest model
├── vectorizer.pkl              # Fitted TF-IDF vectorizer
├── README.md
├── junit_tests/
│   └── SentinelTest.java       # JUnit 5 integration test suite (25 cases)
└── sql/
    ├── setup.sql               # Creates sentinel_test database and tables
    └── blacklist.sql           # Blacklist table only (for existing apps)
```

---

## Integrating Into Your Own PHP App

If you want to protect an existing PHP application instead of using `target.php`:

**1. Add the logging hook** to your main controller (after `session_start()`):
```php
$log_file = __DIR__ . '/../security_audit.log';
$log_entry = json_encode([
    'ip'        => $_SERVER['REMOTE_ADDR'],
    'timestamp' => date('Y-m-d H:i:s'),
    'action'    => filter_input(INPUT_GET, 'action'),
    'payload'   => $_POST
]) . PHP_EOL;
file_put_contents($log_file, $log_entry, FILE_APPEND);
```

**2. Add the access control check** to your database connection file:
```php
$ip = $_SERVER['REMOTE_ADDR'];
$check = $db->prepare("SELECT attack_type FROM blacklist WHERE ip_address = ?");
$check->execute([$ip]);
$blocked = $check->fetch();
if ($blocked) {
    die("<div style='background:red;color:white;padding:50px;text-align:center;'>
        <h1>ACCESS DENIED</h1>
        <p>Sentinel AI: " . htmlspecialchars($blocked['attack_type']) . "</p>
    </div>");
}
```

**3. Run `sql/blacklist.sql`** against your database.

**4. Update `sentinel_brain.py`** with your database name and start it.

---

## Test Results (JUnit 5 — 25 Cases)

| Category | Cases | Result |
|---|---|---|
| Known Attack Vectors (TC001–TC015) | 15 | 14 Pass, 1 Fail |
| Safe BC Locations (TC016–TC020) | 5 | 5 Pass |
| Natural Language Edge Cases (TC021–TC025) | 5 | 4 Pass, 1 Fail |
| **Total** | **25** | **23 Pass (92%)** |

**Known limitations:**
- `update users set role='admin'` — false negative at ML confidence 0.58 (below 0.75 threshold)
- `Select all vegetarian options please` — false positive at ML confidence 0.76

These reflect the real-world tradeoff between sensitivity and specificity in ML-based security systems.

---

## Academic Context

Developed for INFO3235 Software Quality Assurance at KPU demonstrating:
- **Defect Containment** — blocking attackers without patching the vulnerable code
- **Fault Tolerance** — system stays operational for legitimate users under attack
- **Automated Incident Response** — zero human intervention from detection to block
- **Dynamic Testing** — real-time runtime analysis of live traffic
- **Predictive Validation** — quantifiable detection metrics via JUnit

---

## License

MIT License — free to use, modify, and distribute with attribution.
