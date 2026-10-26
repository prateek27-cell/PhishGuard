# MAIN MOTIVE: Connect all PHISHGUARD analyzers into one workflow.

from app.email_parser import parse_email
from app.text_analyzer import analyze_text
from app.url_analyzer import analyze_url
from app.header_analyzer import analyze_headers
from app.risk_scorer import calculate_risk
from app.report_generator import generate_report


def analyze_email(raw_email):
    """Analyze a raw email and return one combined report."""

    # 1. Extract email information.
    parsed_email = parse_email(raw_email)

    # 2. Analyze the email body for suspicious wording.
    text_findings = analyze_text(parsed_email["body"])

    # 3. Analyze each extracted URL without visiting it.
    url_results = [
        analyze_url(url.rstrip(".,);]"))
        for url in parsed_email["urls"]
    ]

    # Convert URL warnings into categories the risk scorer understands.
    risk_findings = list(text_findings)

    for result in url_results:
        if result["findings"]:
            risk_findings.append({
                "category": "suspicious_url",
                "matched_text": result["url"],
                "explanation": "; ".join(result["findings"]),
            })

    # 4. Analyze email headers.
    header_results = analyze_headers(raw_email)

    # Include header findings in risk scoring.
    risk_findings.extend(header_results["findings"])

    # 5. Calculate the overall risk.
    risk_results = calculate_risk(risk_findings)

    # 6. Generate the combined report.
    return generate_report(
        parsed_email,
        text_findings,
        url_results,
        header_results,
        risk_results,
    )


if __name__ == "__main__":
    sample_email = """From: security@example.com
Reply-To: attacker@example.net
Return-Path: <security@example.com>
Subject: URGENT: Verify your account

Your account will be suspended. Verify your password within 24 hours.
http://192.0.2.1/login
"""

    report = analyze_email(sample_email)

    import json
    print(json.dumps(report, indent=4))
