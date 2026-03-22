import time
import json
import joblib
import mysql.connector

# Load the ML Brain and Vectorizer
model = joblib.load('sentinel_model.pkl')
vectorizer = joblib.load('vectorizer.pkl')

log_path = "security_audit.log"
last_processed_line = 0

# ---------------------------------------------------------------
# EXPLICIT RULE LAYER
# Real security systems (Cloudflare, AWS WAF) combine ML with
# explicit rules. This catches edge cases the ML might miss.
# These are high-confidence, zero-ambiguity attack signatures.
# ---------------------------------------------------------------
EXPLICIT_ATTACK_RULES = [
    "truncate table", "truncate TABLE",
    "exec xp_cmdshell", "EXEC xp_cmdshell",
    "alert(document", "alert(window",
    "xp_cmdshell", "sp_executesql",
    "<?php", "<script", "<img src=x",
    "onerror=", "onload=",
    "/etc/passwd", "cat /etc/", "' OR '",
    "' or '",
    "1'='1",
    "admin'--",
    "1/**/or/**/",
    "/**/or/**/",
]

def is_explicit_attack(text):
    text_lower = text.lower()
    for rule in EXPLICIT_ATTACK_RULES:
        if rule.lower() in text_lower:
            return True, rule
    return False, None

def block_attacker(ip, reason):
    try:
        conn = mysql.connector.connect(
            host="localhost", user="root", password="", database="catering_ms"
        )
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO blacklist (ip_address, attack_type) VALUES (%s, %s)",
            (ip, reason)
        )
        conn.commit()
        cursor.close()
        conn.close()
        print(f"!!! [BLOCKED] IP: {ip} | Reason: {reason}")
    except Exception as e:
        print(f"DB Error: {e}")

print("--- Sentinel AI is now Active and Monitoring Traffic ---")
print("--- Hybrid Mode: ML + Explicit Rules ---")

while True:
    try:
        with open(log_path, "r") as f:
            lines = f.readlines()

        if len(lines) > last_processed_line:
            new_line = lines[-1]
            last_processed_line = len(lines)

            entry = json.loads(new_line)
            user_ip = entry.get("ip", "unknown")
            raw_payload = entry.get("payload", {})

            # Skip empty payloads (normal page loads)
            if not raw_payload or raw_payload == [] or raw_payload == {}:
                continue

            # Extract text from payload
            if isinstance(raw_payload, dict):
                full_text = " ".join([str(v) for v in raw_payload.values()])
            else:
                full_text = str(raw_payload)

            if len(full_text.strip()) < 3:
                continue

            # LAYER 1: Explicit rules (catches edge cases with certainty)
            is_attack, matched_rule = is_explicit_attack(full_text)
            if is_attack:
                block_attacker(user_ip, f"Explicit Rule Match: {matched_rule}")
                continue

            # LAYER 2: ML Model (catches complex/obfuscated attacks)
            vec = vectorizer.transform([full_text])
            prediction = model.predict(vec)[0]
            confidence = model.predict_proba(vec)[0]

            if prediction == 1 and max(confidence) >= 0.75:
                block_attacker(user_ip, f"ML Detection (confidence: {max(confidence):.2f})")
            elif prediction == 1:
                 print(f"[LOW CONFIDENCE - ALLOWED] {user_ip}: {full_text[:40]}... (confidence: {max(confidence):.2f})")
            else:
                print(f"[SAFE] {user_ip}: {full_text[:40]}...")

    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Monitor error: {e}")

    time.sleep(1)
