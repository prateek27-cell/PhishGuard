import re #Provides regular-expression tools for finding suspicious phrases.

#REGEX PATTERNS:

SUSPICIOUS_PATTERNS = {
    "urgency_or_threat": [
        r"\baccount.{0,30}suspended\b", 
        r"\bimmediate action required\b",
        r"\bact now\b",
        r"\burgent(?:ly)?\b",
        r"\bwithin 24 hours\b",
        r"\byour account will be closed\b",
    ],
    "sensitive_information_request": [
        r"\b(?:share|provide|confirm|verify|enter)\b.{0,40}\bpassword\b",
        r"\b(?:share|provide|enter|send)\b.{0,40}\botp\b",
        r"\b(?:credit card|bank account)\s+(?:details|information|number)\b",
        r"\bsocial security number\b",
    ],
    "payment_pressure": [
        r"\bunusual payment\b",
        r"\bpayment required immediately\b",
        r"\bpay now\b",
        r"\bpayment.{0,30}failed\b",
    ],
}

# Examines email text and returns the suspicious phrases it finds

def analyze_text(text):
    """Find suspicious language and return matching evidence."""

    findings = []

    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)

            for match in matches:
                findings.append({
                    "category": category,
                    "matched_text": match.group(),
                    "explanation": (
                        "This phrase may indicate a phishing warning sign."
                    ),
                })

    return findings

# Runs the example when this file is executed directly

if __name__ == "__main__":
    sample_text = """
    URGENT! Your account will be suspended.
    Verify your password within 24 hours.
    """

    results = analyze_text(sample_text)

    for finding in results:
        print(finding)
