# PHISHGUARD — Email Threat Analyzer

A beginner cybersecurity project to identify suspicious emails and detect potential phishing indicators.

# Hello, World!

This is **PHISHGUARD**, my first cybersecurity project, built using Kali Linux on Windows Subsystem for Linux (WSL).

I'm genuinely happy that I completed this project! It was my first step toward applying what I've been learning about cybersecurity to a practical application.

This project helped me explore email analysis, suspicious URL detection, email header inspection, and basic risk assessment.

I'm really thankful for all the learning resources, tutorials, and AI assistance that helped me bring this project to life.

---

## What Is PHISHGUARD?

PHISHGUARD is a web-based email analysis application designed to examine email content and identify indicators commonly associated with phishing attempts.

It analyzes an email and generates a report containing suspicious indicators and a risk assessment.

### ✨ Features

- **📧 Email Parsing:** Extracts the sender, reply-to address, subject, body, and URLs from an email.
- **🔍 Text Analysis:** Identifies suspicious language, including urgency, threats, and requests for sensitive information.
- **🌐 URL Analysis:** Checks URLs for potentially suspicious characteristics without opening or visiting them.
- **🧾 Email Header Analysis:** Checks header information for indicators such as mismatches between the sender and reply-to addresses.
- **⚠️ Risk Assessment:** Calculates a risk score based on detected indicators.
- **📊 Analysis Report:** Combines the findings into a readable report with recommendations.
- **🧪 Automated Testing:** Includes tests to verify important analysis components.

## Technologies Used

- **Python** — Core application logic and email analysis.
- **Flask** — Web application framework.
- **HTML** — Web interface structure.
- **CSS** — Interface styling.
- **pytest** — Automated testing.
- **Git & GitHub** — Version control and source-code hosting.
- **Kali Linux on WSL** — Development environment.
- **AI tools** — Assistance with backend logic, frontend development, debugging, and learning.

##  How It Works

1. The user submits email content for analysis.
2. PHISHGUARD extracts relevant email information.
3. The text analyzer identifies suspicious wording.
4. The URL analyzer examines URLs for potentially suspicious characteristics without visiting them.
5. The header analyzer checks for inconsistencies in email headers.
6. The risk scorer calculates a risk score based on the detected indicators.
7. The report generator combines the findings into a final report.

## Run Locally

- Prerequisites

- Python 3
- Git
- A terminal with access to the project directory

### 1. Clone the repository

```bash
git clone https://github.com/prateek27-cell/PhishGuard.git
cd PhishGuard
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

### 3. Activate the virtual environment

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Run the automated tests

```bash
python -m pytest -v
```

### 6. Start the web application

```bash
python -m app.web_app
```

Open the local address displayed in the terminal in your browser. If the application does not start, check the Flask application's entry point and its configuration.

## 📚 Learning Resources & Effort

This project was built through self-learning, experimentation, and AI-assisted development.

My approximate learning and preparation time included:

- **12+ hours:** YouTube videos covering cybersecurity concepts and components.
- **5 hours:** YouTube videos exploring phishing, its background, and how attackers use it.
- **2 hours:** Learning the essential tools and components required for the project, including installing and configuring tools in Kali Linux.

**Total: Approximately 19+ hours of focused learning and preparation.**

I also used AI to assist with backend and frontend development, understand implementation choices, and troubleshoot issues during the process.

## 🧠 What I Learned

Working on PHISHGUARD gave me practical exposure to:

- Python-based email processing.
- Identifying common phishing indicators.
- Analyzing URLs without visiting them.
- Inspecting email headers for inconsistencies.
- Building a web application using Flask.
- Writing and running automated tests with pytest.
- Using Git and GitHub to manage a project.
- Developing in Kali Linux through WSL.
- Using AI as a learning and development assistant.

## ⚠️ Limitations

PHISHGUARD is an educational project and should not be considered a complete enterprise-grade email security solution.

- Detected indicators do not automatically prove that an email is malicious.
- A low risk score does not guarantee that an email is safe.
- The current analysis uses implemented detection rules and should not be treated as a substitute for professional security tools.
- URL analysis examines URL characteristics without visiting the URLs.
- Email authentication results are not independently verified
