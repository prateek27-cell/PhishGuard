#MAIN MOTIVE: combine the warning signs detected by our existing components and calculate a phishing risk score from 0 to 100
'''
Warning sign						Points

Threatening or urgent language				+10

Request for sensitive information			+20

Suspicious URL characteristics				+25

Sender and reply-address mismatch			+20

Reported email authentication failure			+15
'''

def calculate_risk(findings):
    """Calculate an explainable phishing risk score."""

    score = 0
    scored_categories = set()
    score_rules = {
        "urgency_or_threat": 10,
        "sensitive_information_request": 20,
        "suspicious_url": 25,
        "sender_reply_mismatch": 20,
        "authentication_failure": 15,
    }

    for finding in findings:
        category = finding.get("category")

        # Count each category only once.
        if category in score_rules and category not in scored_categories:
            score += score_rules[category]
            scored_categories.add(category)

    # Keep the score within the 0–100 range.
    score = min(score, 100)

    if score < 25:
        risk_level = "Lower risk"
    elif score < 50:
        risk_level = "Some suspicious indicators"
    elif score < 75:
        risk_level = "High risk"
    else:
        risk_level = "Very high risk"

    return {
        "risk_score": score,
        "risk_level": risk_level,
    }


if __name__ == "__main__":
    sample_findings = [
        {"category": "urgency_or_threat"},
        {"category": "sensitive_information_request"},
        {"category": "suspicious_url"},
    ]

    print(calculate_risk(sample_findings))
