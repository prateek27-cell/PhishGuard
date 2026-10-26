#MAIN MOTIVE: inspect email headers and flag every potential warning signs ESPECIALLY when the sender is from a different org and the replt to is showing another person

from email import message_from_string
from email.policy import default


def analyze_headers(raw_email):
    """Inspect email headers for potential phishing warning signs."""

    message = message_from_string(raw_email, policy=default)

    # Extract important email headers
    sender = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    return_path = message.get("Return-Path", "")

    # Collect email transmission details
    received_headers = message.get_all("Received", [])

    # Store suspicious indicators
    findings = []

    # Check whether the reply address differs from the sender
    if reply_to and sender:
        if reply_to.strip().lower() != sender.strip().lower():
            findings.append({
                "category": "sender_reply_mismatch",
                "explanation": (
                    "The Reply-To header differs from the From header. "
                    "Check whether this difference is expected."
                ),
                "from": sender,
                "reply_to": reply_to,
            })

    # Check whether a Return-Path header exists
    if not return_path:
        findings.append({
            "category": "missing_return_path",
            "explanation": (
                "The Return-Path header is missing. "
                "This alone does not prove the email is malicious."
            ),
        })

    # Check for available authentication results
    authentication_results = message.get_all(
        "Authentication-Results", []
    )

    return {
        "sender": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "received_headers": received_headers,
        "authentication_results": [
            str(result) for result in authentication_results
        ],
        "findings": findings,
    }


if __name__ == "__main__":
    sample_email = """From: security@example.com
Reply-To: different@example.net
Subject: Verify your account
Return-Path: <security@example.com>
Received: from mail.example.com
Authentication-Results: example.com; spf=pass; dkim=pass; dmarc=pass

Please verify your account.
"""

    result = analyze_headers(sample_email)

    for key, value in result.items():
        print(f"{key}: {value}")
