# LeakGuard 🔍

<p align="center">
  <strong>Open-source sensitive data discovery scanner for codebases, files, and git history.</strong><br/>
  Detect API keys, hardcoded credentials, private keys, and PII before they reach production.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue" alt="Python 3.9+"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License"/>
  <img src="https://img.shields.io/badge/output-SARIF%20%7C%20JSON%20%7C%20Table-orange" alt="Output formats"/>
  <img src="https://img.shields.io/badge/rules-40%2B-red" alt="40+ rules"/>
</p>

---

## 📖 Overview

Leaked secrets are one of the most common and costly security incidents in software development. API keys, database passwords, private certificates, and personal data regularly end up in codebases — committed accidentally, left in config files, or buried deep in git history where they are easily overlooked but remain exploitable indefinitely.

**LeakGuard** is a developer-first CLI tool that scans your entire codebase — including the full git commit history — for sensitive data using two complementary detection strategies:

- **Pattern matching** — 40+ built-in regex rules covering cloud providers, payment APIs, private keys, database URIs, PII, and more.
- **📊 Shannon entropy analysis** — detects high-randomness strings that are statistically likely to be secrets, even when they don't match a known pattern.

LeakGuard is designed to fit seamlessly into modern development workflows: it runs as a pre-commit hook to catch secrets before they are ever committed, as a CI/CD step to enforce policy on every pull request, and as a standalone CLI for auditing existing repositories. Findings are exportable in **SARIF format** for direct integration with the GitHub Security tab, or as **JSON** for downstream tooling and reporting.

---

## ✨ Features

| Feature | Description |
|---|---|
| **🧩 40+ detection rules** | Covers AWS, GCP, Azure, GitHub, Stripe, Slack, OpenAI, Anthropic, private keys, database URIs, JWT, PII, and more |
| **Entropy analysis** | Identifies high-entropy strings (base64, hex) that are likely secrets even without a known pattern |
| **🕰️ Git history scanning** | Walks every commit in the repository — finds secrets that were added and later deleted |
| **SARIF output** | Native integration with GitHub Code Scanning; findings appear in the Security tab |
| **🗂️ JSON output** | Machine-readable results for dashboards, ticketing systems, or custom pipelines |
| **`.scannerignore`** | gitignore-style file to whitelist paths, suppress false positives, and tune scan scope |
| **Baseline snapshots** | Snapshot existing findings so CI only alerts on *new* secrets introduced after a baseline |
| **⚠️ Severity levels** | Every rule carries a severity (`critical`, `high`, `medium`, `low`) for prioritised triage |
| **🪝 Pre-commit hook** | Blocks commits containing secrets before they ever leave a developer's machine |
| **Secret redaction** | Matched values are partially redacted in all output — LeakGuard never logs full secrets |
| **Fingerprinting** | Each finding has a stable SHA-256 fingerprint for deduplication and baseline comparison |

---

## ⚙️ Installation

### From PyPI

```bash
pip install leakguard
```

### From source

```bash
git clone https://github.com/your-username/leakguard.git
cd leakguard
pip install -e .
```

### 📋 Requirements

- Python 3.9 or higher
- Git (only required for `--git` history scanning)

---

## 🚀 Quick Start

```bash
# Scan the current directory
leakguard scan .

# Scan and include full git commit history
leakguard scan . --git

# Only report high and critical findings
leakguard scan . --min-severity high

# Export results as JSON
leakguard scan . --format json --output results.json

# Export results as SARIF (for GitHub Code Scanning)
leakguard scan . --format sarif --output results.sarif
```

LeakGuard exits with code `1` if any findings are detected, making it suitable for use as a CI gate.

---

## 🖥️ CLI Reference

### `leakguard scan`

Scan a file or directory for sensitive data.

```
leakguard scan [PATH] [OPTIONS]

Arguments:
  PATH                    File or directory to scan (default: current directory)

Options:
  --format, -f            Output format: table | json | sarif  (default: table)
  --output, -o PATH       Write results to a file instead of stdout
  --git / --no-git        Also scan the full git commit history (default: off)
  --min-severity TEXT     Minimum severity to report: low | medium | high | critical
  --ignore-file PATH      Path to a custom .scannerignore file
  --baseline PATH         Suppress findings that appear in a baseline JSON file
```

### `leakguard baseline`

Scan and save all current findings as a baseline. Future scans run with `--baseline` will only report findings that are *new* relative to the snapshot — useful for onboarding LeakGuard into an existing codebase without being overwhelmed by historical findings.

```bash
leakguard baseline .
leakguard scan . --baseline .leakguard-baseline.json
```

### `leakguard list-rules`

Print all built-in detection rules, their severity, and their pattern (truncated).

```bash
leakguard list-rules
```

---

## 🛡️ Detection Rules

LeakGuard ships with 40+ rules across the following categories:

| Category | Covered Secrets |
|---|---|
| **Cloud — AWS** | Access Key ID, Secret Access Key, Session Token |
| **Cloud — GCP** | API Key, OAuth Client Secret, Service Account JSON |
| **Cloud — Azure** | Storage Connection String |
| **Source Control** | GitHub PAT (classic), OAuth token, App token, Refresh token |
| **Payment** | Stripe secret key, Stripe restricted key |
| **Communication** | Slack bot token, user token, incoming webhook URL |
| **Cryptographic Keys** | RSA private key, EC private key, OpenSSH private key, PGP private key block |
| **Authentication Tokens** | JSON Web Token (JWT), generic Bearer token |
| **Database URIs** | PostgreSQL, MySQL, MongoDB, Redis (with embedded credentials) |
| **Hardcoded Credentials** | Generic `password =`, `secret =` assignments |
| **PII** | Email addresses, US SSNs, credit card numbers (Visa/MC/Amex/Discover), IBANs |
| **Developer Tools** | NPM access token, Docker Hub PAT |
| **AI / ML APIs** | OpenAI API key, Anthropic API key |
| **Email & SMS** | Twilio API key, SendGrid API key, Mailchimp API key |
| **High-entropy strings** | Base64 and hex tokens exceeding Shannon entropy thresholds |

Run `leakguard list-rules` for the complete list with full rule IDs and severities.

---

## ⚡ GitHub Actions Integration

LeakGuard integrates natively with GitHub's Code Scanning feature via SARIF output. Add the following workflow to your repository to automatically scan every push and pull request, with findings surfaced directly in the **Security → Code scanning** tab:

```yaml
# .github/workflows/leakguard.yml
name: LeakGuard Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # Full history for git scanning

      - name: Install LeakGuard
        run: pip install leakguard

      - name: Run LeakGuard
        run: leakguard scan . --format sarif --output results.sarif || true

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

> ℹ️ The `|| true` prevents the workflow from failing at the scan step — findings are reported as annotations in the Security tab rather than blocking the build. Remove it if you want LeakGuard to act as a hard gate.

---

## 🪝 Pre-commit Hook

Catching secrets before they are committed is the most effective line of defence. LeakGuard ships with a pre-commit hook that scans staged files automatically on every `git commit`.

### Manual installation

```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Using the pre-commit framework

If your project uses the [pre-commit](https://pre-commit.com) framework:

```bash
pip install pre-commit
pre-commit install
```

The included `.pre-commit-config.yaml` configures LeakGuard to run automatically. To bypass in exceptional cases (not recommended):

```bash
git commit --no-verify
```

---

## 🚫 Suppressing False Positives

Create a `.scannerignore` file in the root of your repository to exclude paths from scanning. The syntax is identical to `.gitignore`:

```gitignore
# Test fixtures that intentionally contain fake secrets
tests/fixtures/

# Example configuration files
docs/examples/

# A specific known false-positive file
config/example.env
```

💡 Pass a custom ignore file path with `--ignore-file` if needed.

---

## 🔬 How Detection Works

### 🔎 Pattern matching

Each rule in `scanner/patterns.py` defines a compiled regular expression targeting the known format of a specific secret type. For example, AWS Access Key IDs always begin with `AKIA` followed by 16 uppercase alphanumeric characters — a pattern that is highly specific and produces very few false positives.

### 📊 Shannon entropy analysis

Not all secrets follow a known format. Randomly generated tokens, encryption keys, and internal credentials may not match any rule. LeakGuard addresses this by computing the [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) of candidate strings extracted from each line. Strings above a configurable threshold (default: **4.5 bits/char** for base64, **3.0 bits/char** for hex) are flagged as probable secrets and reported with a `medium` severity.

### 🔒 Secret redaction

LeakGuard never outputs full secret values. All matched strings are partially redacted (first 4 characters + asterisks) in table, JSON, and SARIF output alike, making it safe to share scan results with teammates or store them in CI logs.

---

## Development

```bash
# Clone and install with development dependencies
git clone https://github.com/your-username/leakguard.git
cd leakguard
pip install -e ".[dev]"

# Run the full test suite
pytest

# Run tests with coverage report
pytest --cov=scanner --cov-report=term-missing

# Lint and format
ruff check .
black .

# Type checking
mypy scanner/ cli.py
```

### ➕ Adding a new detection rule

Open `scanner/patterns.py` and append a new `PatternRule` entry:

```python
PatternRule(
    rule_id="my-service-api-key",
    description="My Service API Key",
    regex=r"ms_[a-zA-Z0-9]{32}",
    severity="high",
    tags=["my-service", "api-key"],
),
```

Add a corresponding test in `tests/test_scanner.py` under `TestPatterns`, then run `pytest` to verify.

---

## 📁 Project Structure

```
leakguard/
├── cli.py                        # CLI entry point — scan, baseline, list-rules
├── scanner/
│   ├── patterns.py               # All regex detection rules
│   ├── entropy.py                # Shannon entropy analysis
│   ├── finding.py                # Finding dataclass with fingerprinting & redaction
│   ├── file_scanner.py           # File/directory traversal + .scannerignore support
│   ├── git_scanner.py            # Git commit history scanner
│   └── reporter.py               # Table, JSON, and SARIF output rendering
├── tests/
│   ├── test_scanner.py           # Full test suite (~30 tests)
│   └── fixtures/fake_secrets.py  # Fake credentials for testing
├── .github/workflows/ci.yml      # CI: tests + lint + self-scan with SARIF upload
├── hooks/pre-commit              # Git pre-commit hook script
├── .pre-commit-config.yaml       # pre-commit framework configuration
├── .scannerignore                # Default ignore rules
├── pyproject.toml                # Project metadata, dependencies, tool configuration
└── LICENSE                       # MIT License
```

---

## 🤝 Contributing

Contributions are welcome. If you have a new detection rule, a bug fix, or an improvement, please open an issue first to discuss the change, then submit a pull request. All new rules must include at least one test in `tests/test_scanner.py`.

---

## 📜 License

LeakGuard is released under the [MIT License](LICENSE). You are free to use, modify, and distribute it in both open-source and commercial projects.
