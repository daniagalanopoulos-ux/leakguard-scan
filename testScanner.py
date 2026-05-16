"""
Tests for LeakGuard scanner modules.
Sensitive-looking strings are split across concatenations so this file
itself does not trigger secret scanners.
"""

import textwrap
import tempfile
from pathlib import Path

import pytest

from scanner.entropy import shannon_entropy, find_high_entropy_strings, is_likely_secret
from scanner.file_scanner import FileScanner
from scanner.finding import Finding
from scanner.patterns import PATTERNS
from scanner.reporter import Reporter, OutputFormat
import json


# ── Helpers ───────────────────────────────────────────────────────────────────

# Strings are built at runtime via concatenation so static scanners
# cannot match them as secrets in this source file.
def _aws_key():
    return "AKIA" + "IOSFODNN7EXAMPLE"

def _github_pat():
    return "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"

def _stripe_key():
    return "sk_live_" + "abcdefghijklmnopqrstuvwx"

def _rsa_header():
    return "-----BEGIN RSA" + " PRIVATE KEY-----"

def _jwt():
    return (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )

def _sendgrid():
    return (
        "SG." + "abcdefghijklmnopqrstuv."
        + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS"
    )

def _slack_token():
    return "xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvw"

def _postgres_uri():
    return "postgres://" + "user:password@localhost:5432/mydb"

def _google_api_key():
    return "AIza" + "SyD-9tSrke72I6e0MVVQwdtpV9B2FqJz9Xk"


# ── Entropy Tests ─────────────────────────────────────────────────────────────

class TestEntropy:
    def test_empty_string_is_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_char_is_zero(self):
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_high_entropy_random_string(self):
        s = "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleQ=="
        assert shannon_entropy(s) > 4.0

    def test_low_entropy_repeated(self):
        assert shannon_entropy("aaabbbccc") < 2.0

    def test_find_high_entropy_strings_detects_secret(self):
        line = 'api_key = "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleVhYWFhYWA=="'
        results = find_high_entropy_strings(line)
        assert len(results) > 0

    def test_find_high_entropy_ignores_short_tokens(self):
        line = 'x = "abc123"'
        results = find_high_entropy_strings(line)
        assert len(results) == 0

    def test_is_likely_secret_true(self):
        assert is_likely_secret("dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleVhYWFhYWA==") is True

    def test_is_likely_secret_false_for_short(self):
        assert is_likely_secret("shortvalue") is False


# ── Pattern Tests ─────────────────────────────────────────────────────────────

class TestPatterns:
    def _match(self, rule_id: str, text: str) -> bool:
        import re
        rule = next((p for p in PATTERNS if p.rule_id == rule_id), None)
        assert rule is not None, f"Rule {rule_id} not found"
        return bool(re.search(rule.regex, text))

    def test_aws_access_key(self):
        assert self._match("aws-access-key-id", _aws_key())

    def test_github_pat(self):
        assert self._match("github-pat", _github_pat())

    def test_google_api_key(self):
        assert self._match("google-api-key", _google_api_key())

    def test_stripe_secret(self):
        assert self._match("stripe-secret-key", _stripe_key())

    def test_postgres_uri(self):
        assert self._match("postgres-uri", _postgres_uri())

    def test_rsa_private_key(self):
        assert self._match("rsa-private-key", _rsa_header())

    def test_jwt_token(self):
        assert self._match("jwt-token", _jwt())

    def test_email_pii(self):
        assert self._match("email-address", "user@example.com")

    def test_credit_card(self):
        assert self._match("credit-card-number", "4111111111111111")

    def test_ssn(self):
        assert self._match("us-ssn", "123-45-6789")

    def test_no_false_positive_aws(self):
        assert not self._match("aws-access-key-id", "NOTANAWSKEY12345678")

    def test_slack_bot_token(self):
        assert self._match("slack-bot-token", _slack_token())

    def test_sendgrid(self):
        assert self._match("sendgrid-api-key", _sendgrid())


# ── File Scanner Tests ────────────────────────────────────────────────────────

class TestFileScanner:
    def _make_temp_file(self, content: str, filename: str = "test_file.py") -> Path:
        tmp = tempfile.mkdtemp()
        p = Path(tmp) / filename
        p.write_text(content)
        return p

    def test_detects_aws_key_in_file(self):
        # Write the key into a temp file at runtime — not stored as a literal here
        content = f'aws_key = "{_aws_key()}"\n'
        filepath = self._make_temp_file(content)
        scanner = FileScanner()
        findings = scanner.scan(filepath)
        assert any(f.rule_id == "aws-access-key-id" for f in findings)

    def test_detects_postgres_uri(self):
        content = f'DB_URL = "{_postgres_uri()}"\n'
        filepath = self._make_temp_file(content)
        findings = FileScanner().scan(filepath)
        assert any(f.rule_id == "postgres-uri" for f in findings)

    def test_suspicious_filename_flagged(self):
        content = "ssh-rsa AAAAB3NzaC1yc2E..."
        filepath = self._make_temp_file(content, filename="id_rsa")
        findings = FileScanner().scan(filepath)
        assert any(f.rule_id == "suspicious-filename" for f in findings)

    def test_no_findings_in_clean_file(self):
        content = textwrap.dedent("""\
            def hello():
                return "Hello, world!"
        """)
        filepath = self._make_temp_file(content)
        findings = FileScanner().scan(filepath)
        assert len(findings) == 0

    def test_scannerignore_respected(self):
        tmp = Path(tempfile.mkdtemp())
        secret_file = tmp / "secrets.py"
        secret_file.write_text(f'key = "{_aws_key()}"\n')
        ignore_file = tmp / ".scannerignore"
        ignore_file.write_text("secrets.py\n")
        findings = FileScanner(ignore_file=ignore_file).scan(tmp)
        assert len(findings) == 0

    def test_multiple_findings_in_one_file(self):
        content = (
            f'aws_key = "{_aws_key()}"\n'
            f'db = "{_postgres_uri()}"\n'
            f'token = "{_github_pat()}"\n'
        )
        filepath = self._make_temp_file(content)
        findings = FileScanner().scan(filepath)
        assert len(findings) >= 3


# ── Finding Tests ─────────────────────────────────────────────────────────────

class TestFinding:
    def _make_finding(self, match=None):
        match = match or _aws_key()
        return Finding(
            rule_id="aws-access-key-id",
            description="AWS Access Key ID",
            severity="critical",
            filepath="/repo/config.py",
            line_number=42,
            line_content=f'key = "{match}"',
            match=match,
            tags=["aws"],
        )

    def test_fingerprint_is_stable(self):
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert f1.fingerprint == f2.fingerprint

    def test_redacted_match_hides_secret(self):
        f = self._make_finding(_aws_key())
        assert "AKIA" in f.redacted_match
        assert f.redacted_match.count("*") > 0

    def test_to_dict_contains_required_keys(self):
        f = self._make_finding()
        d = f.to_dict()
        for key in ["fingerprint", "rule_id", "severity", "filepath", "line_number", "match"]:
            assert key in d

    def test_redacted_line_replaces_match(self):
        key = _aws_key()
        f = self._make_finding(key)
        assert key not in f.redacted_line


# ── Reporter Tests ────────────────────────────────────────────────────────────

class TestReporter:
    def _make_finding(self, severity="high"):
        return Finding(
            rule_id="test-rule",
            description="Test finding",
            severity=severity,
            filepath="/repo/test.py",
            line_number=1,
            line_content='password = "s3cr3t"',
            match="s3cr3t",
            tags=["test"],
        )

    def test_json_output_is_valid(self):
        findings = [self._make_finding()]
        r = Reporter(findings=findings)
        output = r.render(OutputFormat.json)
        data = json.loads(output)
        assert data["total"] == 1
        assert len(data["findings"]) == 1

    def test_sarif_output_is_valid(self):
        findings = [self._make_finding()]
        r = Reporter(findings=findings)
        output = r.render(OutputFormat.sarif)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 1

    def test_empty_findings_json(self):
        r = Reporter(findings=[])
        output = r.render(OutputFormat.json)
        data = json.loads(output)
        assert data["total"] == 0
        