from app.email_parser import parse_email
from app.text_analyzer import analyze_text


def test_email_parser_and_text_analyzer():
    raw_email = """From: security@example.com
Reply-To: different@example.net
Subject: Urgent: Verify your account

URGENT! Your account will be suspended.
Verify your password within 24 hours.
https://example.com/verify
"""

    parsed = parse_email(raw_email)
    findings = analyze_text(parsed["body"])

    assert parsed["sender"] == "security@example.com"
    assert parsed["reply_to"] == "different@example.net"
    assert parsed["subject"] == "Urgent: Verify your account"
    assert "https://example.com/verify" in parsed["urls"]
    assert len(findings) >= 3

99999

# Tests for the URL analyzer.
from app.url_analyzer import extract_urls, analyze_url


def test_extract_urls():
    # Check that URLs are extracted from text.
    text = "Visit https://example.com and http://192.0.2.1/login"
    urls = extract_urls(text)

    assert len(urls) == 2
    assert "https://example.com" in urls
    assert "http://192.0.2.1/login" in urls


def test_analyze_url_flags_http_and_ip():
    # Check that HTTP and IP-address warnings are detected.
    result = analyze_url("http://192.0.2.1/login")

    assert "URL uses HTTP instead of HTTPS." in result["findings"]
    assert "URL uses an IP address as its hostname." in result["findings"]


def test_analyze_https_url():
    # Check that a basic HTTPS example has no findings.
    result = analyze_url("https://example.com/verify")

    assert result["hostname"] == "example.com"
    assert result["findings"] == []



from app.header_analyzer import analyze_headers


def test_header_analyzer_detects_reply_mismatch():
    raw_email = """From: security@example.com
Reply-To: attacker@example.net
Return-Path: <security@example.com>
Subject: Verify account

Please verify your account.
"""

    result = analyze_headers(raw_email)

    assert result["sender"] == "security@example.com"
    assert result["reply_to"] == "attacker@example.net"

    categories = [
        finding["category"]
        for finding in result["findings"]
    ]

    assert "sender_reply_mismatch" in categories


# Test the risk scorer
from app.risk_scorer import calculate_risk


def test_risk_scorer():
    findings = [
        {"category": "urgency_or_threat"},
        {"category": "sensitive_information_request"},
        {"category": "suspicious_url"},
    ]

    result = calculate_risk(findings)

    assert result["risk_score"] == 55
    assert result["risk_level"] == "High risk"



# Test the report generator
from app.report_generator import generate_report


def test_report_generator():
    parsed_email = {
        "sender": "security@example.com",
        "subject": "Urgent: Verify your account",
    }

    text_findings = [
        {
            "category": "urgency_or_threat",
            "matched_text": "URGENT",
            "explanation": "May indicate pressure to act quickly.",
        }
    ]

    url_findings = [
        {
            "url": "http://192.0.2.1/login",
            "findings": ["URL uses HTTP instead of HTTPS."],
        }
    ]

    header_results = {
        "findings": [
            {
                "category": "sender_reply_mismatch",
                "explanation": "From and Reply-To addresses differ.",
            }
        ]
    }

    risk_results = {
        "risk_score": 55,
        "risk_level": "High risk",
    }

    report = generate_report(
        parsed_email,
        text_findings,
        url_findings,
        header_results,
        risk_results,
    )

    assert report["email"]["sender"] == "security@example.com"
    assert report["email"]["subject"] == "Urgent: Verify your account"
    assert report["risk_score"] == 55
    assert report["risk_level"] == "High risk"
    assert len(report["text_findings"]) == 1
    assert len(report["url_findings"]) == 1
    assert len(report["header_findings"]) == 1
    assert len(report["recommendations"]) > 0



# MAIN MOTIVE: Test the complete PHISHGUARD analysis pipeline.
from app.analyzer_email import analyze_email


def test_complete_email_analysis_pipeline():
    raw_email = """From: security@example.com
Reply-To: attacker@example.net
Return-Path: <security@example.com>
Subject: URGENT: Verify your account

Your account will be suspended.
Verify your password within 24 hours.
http://192.0.2.1/login
"""

    report = analyze_email(raw_email)

    assert report["email"]["sender"] == "security@example.com"
    assert report["risk_score"] > 0
    assert report["risk_level"] == "Very high risk"
    assert len(report["text_findings"]) > 0
    assert len(report["url_findings"]) > 0
    assert len(report["header_findings"]) > 0
    assert len(report["recommendations"]) > 0
