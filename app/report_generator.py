#MAIN MOTIVE: to combine the result of everything and give the user a finalized report with their risk score and a warning/flag

import json


def generate_report(parsed_email, text_findings, url_findings,
                    header_results, risk_results):
    """Combine analysis results into one report."""

    # Store the results in a single structured report.
    report = {
        "email": {
            "sender": parsed_email.get("sender", ""),
            "subject": parsed_email.get("subject", ""),
        },
        "risk_score": risk_results["risk_score"],
        "risk_level": risk_results["risk_level"],
        "text_findings": text_findings,
        "url_findings": url_findings,
        "header_findings": header_results.get("findings", []),
        "recommendations": [
            "Do not reply to suspicious emails.",
            "Do not share passwords or OTPs.",
            "Verify requests through an official channel.",
        ],
    }

    return report


if __name__ == "__main__":
    # Example results to demonstrate report generation.
    sample_email = {
        "sender": "security@example.com",
        "subject": "Urgent: Verify your account",
    }

    sample_text_findings = [
        {
            "category": "urgency_or_threat",
            "matched_text": "URGENT",
            "explanation": "May indicate pressure to act quickly.",
        }
    ]

    sample_url_findings = [
        {
            "url": "http://192.0.2.1/login",
            "findings": ["URL uses HTTP instead of HTTPS."],
        }
    ]

    sample_header_results = {
        "findings": [
            {
                "category": "sender_reply_mismatch",
                "explanation": "From and Reply-To addresses differ.",
            }
        ]
    }

    sample_risk_results = {
        "risk_score": 55,
        "risk_level": "High risk",
    }

    report = generate_report(
        sample_email,
        sample_text_findings,
        sample_url_findings,
        sample_header_results,
        sample_risk_results,
    )

    print(json.dumps(report, indent=4))
