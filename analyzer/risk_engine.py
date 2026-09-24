def calculate_risk(
    suspicious_strings=0,
    suspicious_imports=0,
    yara_matches=0,
    entropy=0.0,
    malicious_hash=False
):
    score = 0
    reasons = []

    # Known malicious hash
    if malicious_hash:
        score += 50
        reasons.append("Known malicious hash")

    # YARA detection
    if yara_matches > 0:
        score += 30
        reasons.append("YARA rule matched")

    # Suspicious strings
    string_score = min(suspicious_strings * 5, 15)

    if string_score > 0:
        score += string_score
        reasons.append(
            f"{suspicious_strings} suspicious string(s)"
        )

    # Suspicious PE imports
    import_score = min(suspicious_imports * 5, 15)

    if import_score > 0:
        score += import_score
        reasons.append(
            f"{suspicious_imports} suspicious API(s)"
        )

    # High entropy
    if entropy >= 7.2:
        score += 10
        reasons.append("High file entropy")

    score = min(score, 100)

    if score >= 75:
        verdict = "CRITICAL"
    elif score >= 50:
        verdict = "HIGH RISK"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }
