# MAIN MOTIVE: Accept uploaded .eml files or pasted email text and analyze them.

from flask import Flask, render_template, request
from app.analyzer_email import analyze_email
from pathlib import Path

app = Flask(
    __name__,
    template_folder="../templates",
    static_folder="../static"
)

# Limit uploaded emails to 2 MB.
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    email_text = ""
    error = None

    if request.method == "POST":
        uploaded_file = request.files.get("email_file")
        pasted_text = request.form.get("email_text", "").strip()

        if uploaded_file and uploaded_file.filename:
            if Path(uploaded_file.filename).suffix.lower() != ".eml":
                error = "Please upload an email file with the .eml extension."
            else:
                try:
                    email_text = uploaded_file.read().decode("utf-8", errors="replace").strip()
                except Exception:
                    error = "Could not read the uploaded email file."

        elif pasted_text:
            email_text = pasted_text

        else:
            error = "Please upload an .eml file or paste an email before analyzing."

        if email_text and not error:
            try:
                report = analyze_email(email_text)
            except Exception:
                app.logger.exception("Email analysis failed.")
                error = "Analysis failed. Please check the email format and try again."

    return render_template(
        "index.html",
        report=report,
        email_text=email_text,
        error=error,
    )


if __name__ == "__main__":
    app.run(debug=True)
