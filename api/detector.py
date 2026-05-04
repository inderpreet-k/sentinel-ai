import os
import joblib

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "sentinel_model.pkl")
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "..", "vectorizer.pkl")

# These load ONCE when the server starts — stays in memory for every request
model = None
vectorizer = None


def load_models():
    global model, vectorizer
    try:
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECTORIZER_PATH)
        print("[ML] Model and vectorizer loaded successfully.")
    except FileNotFoundError:
        print("[ML] WARNING: Model files not found. ML detection disabled.")
        print("[ML] Run train_sentinel.py to generate them.")


# ---------------------------------------------------------------
# Explicit rules — high confidence, zero ambiguity attack patterns
# Same as original sentinel_brain.py but now used inside the API
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
    "drop table", "DROP TABLE",
    "insert into", "INSERT INTO",
    "union select", "UNION SELECT",
    "sleep(", "SLEEP(",
    "benchmark(", "BENCHMARK(",
    "javascript:",
    "vbscript:",
    "onmouseover=",
    "onfocus=",
]


def check_explicit_rules(text: str) -> tuple[bool, str | None]:
    text_lower = text.lower()
    for rule in EXPLICIT_ATTACK_RULES:
        if rule.lower() in text_lower:
            return True, rule
    return False, None


def check_ml(text: str) -> tuple[int, float]:
    """
    Returns (prediction, confidence).
    prediction: 1 = attack, 0 = safe
    confidence: 0.0 to 1.0
    """
    if model is None or vectorizer is None:
        return 0, 0.0
    vec = vectorizer.transform([text])
    prediction = model.predict(vec)[0]
    confidence = float(max(model.predict_proba(vec)[0]))
    return int(prediction), confidence


def analyze(payload: dict | str) -> dict:
    """
    Main entry point. Pass in the raw form payload (dict or string).
    Returns a result dict with decision, reason, and confidence.
    """
    # Flatten dict payload into a single string
    if isinstance(payload, dict):
        full_text = " ".join([str(v) for v in payload.values()])
    else:
        full_text = str(payload)

    full_text = full_text.strip()

    # Empty payloads are always safe
    if len(full_text) < 3:
        return {
            "decision": "allow",
            "reason": "Empty payload",
            "confidence": 1.0
        }

    # Layer 1: Explicit rules
    is_attack, matched_rule = check_explicit_rules(full_text)
    if is_attack:
        return {
            "decision": "block",
            "reason": f"Explicit rule match: {matched_rule}",
            "confidence": 1.0
        }

    # Layer 2: ML model
    prediction, confidence = check_ml(full_text)
    if prediction == 1 and confidence >= 0.75:
        return {
            "decision": "block",
            "reason": f"ML detection",
            "confidence": confidence
        }
    elif prediction == 1:
        return {
            "decision": "allow",
            "reason": f"Low confidence ML flag — allowed",
            "confidence": confidence
        }

    return {
        "decision": "allow",
        "reason": "Clean",
        "confidence": confidence if confidence > 0 else 1.0
    }