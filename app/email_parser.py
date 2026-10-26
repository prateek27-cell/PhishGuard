# MAIN MOTIVE: to extract useful info to identify the mail's sender so the rest of the app could analyze it further

from email import policy
from email.parser import Parser
from urllib.parse import urlparse
import re


def parse_email(raw_email):
    """Extract basic information from a raw email."""

    message = Parser(policy=policy.default).parsestr(raw_email)

    sender = message.get("From", "")
    reply_to = message.get("Reply-To", "")
    subject = message.get("Subject", "")

    body_parts = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                if part.get_content_disposition() != "attachment":
                    try:
                        body_parts.append(part.get_content())
                    except (LookupError, UnicodeError):
                        continue
    else:
        if message.get_content_type() == "text/plain":
            try:
                body_parts.append(message.get_content())
            except (LookupError, UnicodeError):
                pass

    body = "\n".join(body_parts)

    urls = re.findall(r"https?://[^\s<>\"']+", body)
    urls = [url.rstrip(".,);]") for url in urls]

    return {
        "sender": sender,
        "reply_to": reply_to,
        "subject": subject,
        "body": body,
        "urls": urls,
    }


if __name__ == "__main__":
    sample_email = """From: security@example.com
Reply-To: different@example.net
Subject: Urgent: Verify your account

Your account will be suspended. Verify immediately:
https://example.com/verify
"""

    result = parse_email(sample_email)

    for field, value in result.items():
        print(f"{field}: {value}")
