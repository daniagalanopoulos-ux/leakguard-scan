"""
Detection patterns for LeakGuard.
Each PatternRule defines one type of sensitive data to detect.
"""

from dataclasses import dataclass
from typing import List


@dataclass
class PatternRule:
    rule_id: str
    description: str
    regex: str
    severity: str          # low/medium/high/critical
    tags: List[str]


PATTERNS: List[PatternRule] = [

    # ── AWS ──────────────────────────────────────────────────────────────────
    PatternRule(
        rule_id="aws-access-key-id",
        description="AWS Access Key ID",
        regex=r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        severity="critical",
        tags=["aws", "cloud", "credentials"],
    ),
    PatternRule(
        rule_id="aws-secret-access-key",
        description="AWS Secret Access Key",
        regex=r"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key[\s]*[=:\"'\s]+([A-Za-z0-9/+=]{40})",
        severity="critical",
        tags=["aws", "cloud", "credentials"],
    ),
    PatternRule(
        rule_id="aws-session-token",
        description="AWS Session Token",
        regex=r"(?i)aws[_\-\s]*session[_\-\s]*token[\s]*[=:\"'\s]+([A-Za-z0-9/+=]{100,})",
        severity="critical",
        tags=["aws", "cloud", "credentials"],
    ),

    # ── GitHub ───────────────────────────────────────────────────────────────
    PatternRule(
        rule_id="github-pat",
        description="GitHub Personal Access Token (classic)",
        regex=r"ghp_[a-zA-Z0-9]{36}",
        severity="critical",
        tags=["github", "token"],
    ),
    PatternRule(
        rule_id="github-oauth-token",
        description="GitHub OAuth Token",
        regex=r"gho_[a-zA-Z0-9]{36}",
        severity="critical",
        tags=["github", "oauth"],
    ),
    PatternRule(
        rule_id="github-app-token",
        description="GitHub App Token",
        regex=r"(?:ghu|ghs)_[a-zA-Z0-9]{36}",
        severity="critical",
        tags=["github", "app"],
    ),
    PatternRule(
        rule_id="github-refresh-token",
        description="GitHub Refresh Token",
        regex=r"ghr_[a-zA-Z0-9]{76}",
        severity="critical",
        tags=["github", "token"],
    ),

    # ── Google ───────────────────────────────────────────────────────────────
    PatternRule(
        rule_id="google-api-key",
        description="Google API Key",
        regex=r"AIza[0-9A-Za-z\-_]{35}",
        severity="high",
        tags=["google", "api-key"],
    ),
    PatternRule(
        rule_id="google-oauth-client-secret",
        description="Google OAuth Client Secret",
        regex=r"(?i)client.?secret[\s]*[=:\"'\s]+([a-zA-Z0-9\-_]{24})",
        severity="high",
        tags=["google", "oauth"],
    ),
    PatternRule(
        rule_id="google-service-account",
        description="Google Service Account Key (JSON)",
        regex=r'"type"\s*:\s*"service_account"',
        severity="critical",
        tags=["google", "gcp", "service-account"],
    ),

    # ── Stripe ───────────────────────────────────────────────────────────────
    PatternRule(
        rule_id="stripe-secret-key",
        description="Stripe Secret Key",
        regex=r"sk_live_[0-9a-zA-Z]{24,}",
        severity="critical",
        tags=["stripe", "payments"],
    ),
    PatternRule(
        rule_id="stripe-restricted-key",
        description="Stripe Restricted Key",
        regex=r"rk_live_[0-9a-zA-Z]{24,}",
        severity="high",
        tags=["stripe", "payments"],
    ),

    # ── Slack ────────────────────────────────────────────────────────────────
    PatternRule(
        rule_id="slack-bot-token",
        description="Slack Bot Token",
        regex=r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{23,25}",
        severity="high",
        tags=["slack", "token"],
    ),
    PatternRule(
        rule_id="slack-user-token",
        description="Slack User Token",
        regex=r"xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{31,35}",
        severity="high",
        tags=["slack", "token"],
    ),
    PatternRule(
        rule_id="slack-webhook",
        description="Slack Webhook URL",
        regex=r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{23,25}",
        severity="high",
        tags=["slack", "webhook"],
    ),

    # ── Private Keys ─────────────────────────────────────────────────────────
    PatternRule(
        rule_id="rsa-private-key",
        description="RSA Private Key",
        regex=r"-----BEGIN RSA PRIVATE KEY-----",
        severity="critical",
        tags=["private-key", "rsa", "crypto"],
    ),
    PatternRule(
        rule_id="ec-private-key",
        description="EC Private Key",
        regex=r"-----BEGIN EC PRIVATE KEY-----",
        severity="critical",
        tags=["private-key", "ec", "crypto"],
    ),
    PatternRule(
        rule_id="openssh-private-key",
        description="OpenSSH Private Key",
        regex=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity="critical",
        tags=["private-key", "ssh"],
    ),
    PatternRule(
        rule_id="pgp-private-key",
        description="PGP Private Key Block",
        regex=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity="critical",
        tags=["private-key", "pgp"],
    ),

    # ── Tokens / JWT ─────────────────────────────────────────────────────────
    PatternRule(
        rule_id="jwt-token",
        description="JSON Web Token (JWT)",
        regex=r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        severity="medium",
        tags=["jwt", "token"],
    ),
    PatternRule(
        rule_id="generic-bearer-token",
        description="Generic Bearer Token in header",
        regex=r"(?i)authorization[\s]*[=:\"'\s]+bearer\s+([a-zA-Z0-9\-_.+/=]{20,})",
        severity="medium",
        tags=["bearer", "token"],
    ),

    # ── Database URIs ────────────────────────────────────────────────────────
    PatternRule(
        rule_id="postgres-uri",
        description="PostgreSQL connection string with credentials",
        regex=r"postgres(?:ql)?://[^:@\s]+:[^@\s]+@[^\s\"']+",
        severity="critical",
        tags=["database", "postgresql"],
    ),
    PatternRule(
        rule_id="mysql-uri",
        description="MySQL connection string with credentials",
        regex=r"mysql://[^:@\s]+:[^@\s]+@[^\s\"']+",
        severity="critical",
        tags=["database", "mysql"],
    ),
    PatternRule(
        rule_id="mongodb-uri",
        description="MongoDB URI with credentials",
        regex=r"mongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@[^\s\"']+",
        severity="critical",
        tags=["database", "mongodb"],
    ),
    PatternRule(
        rule_id="redis-uri",
        description="Redis URI with password",
        regex=r"redis://:[^@\s]+@[^\s\"']+",
        severity="high",
        tags=["database", "redis"],
    ),

    # ── Generic Passwords ────────────────────────────────────────────────────
    PatternRule(
        rule_id="generic-password-assignment",
        description="Hardcoded password assignment",
        regex=r"(?i)(?:password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{6,}[\"']",
        severity="high",
        tags=["password", "credentials"],
    ),
    PatternRule(
        rule_id="generic-secret-assignment",
        description="Hardcoded secret assignment",
        regex=r"(?i)(?:secret|api_secret|app_secret)\s*[=:]\s*[\"'][^\"']{8,}[\"']",
        severity="high",
        tags=["secret", "credentials"],
    ),

    # ── PII ──────────────────────────────────────────────────────────────────
    PatternRule(
        rule_id="email-address",
        description="Email address",
        regex=r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        severity="low",
        tags=["pii", "email"],
    ),
    PatternRule(
        rule_id="us-ssn",
        description="US Social Security Number",
        regex=r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        severity="critical",
        tags=["pii", "ssn"],
    ),
    PatternRule(
        rule_id="credit-card-number",
        description="Credit card number (Visa/MC/Amex/Discover)",
        regex=r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        severity="critical",
        tags=["pii", "payment", "credit-card"],
    ),
    PatternRule(
        rule_id="iban",
        description="IBAN bank account number",
        regex=r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b",
        severity="high",
        tags=["pii", "banking", "iban"],
    ),

    # ── Other Services ───────────────────────────────────────────────────────
    PatternRule(
        rule_id="twilio-api-key",
        description="Twilio API Key",
        regex=r"SK[a-f0-9]{32}",
        severity="high",
        tags=["twilio", "api-key"],
    ),
    PatternRule(
        rule_id="sendgrid-api-key",
        description="SendGrid API Key",
        regex=r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
        severity="high",
        tags=["sendgrid", "api-key"],
    ),
    PatternRule(
        rule_id="mailchimp-api-key",
        description="Mailchimp API Key",
        regex=r"[a-f0-9]{32}-us[0-9]{1,2}",
        severity="high",
        tags=["mailchimp", "api-key"],
    ),
    PatternRule(
        rule_id="npm-token",
        description="NPM Access Token",
        regex=r"npm_[a-zA-Z0-9]{36}",
        severity="high",
        tags=["npm", "token"],
    ),
    PatternRule(
        rule_id="docker-hub-token",
        description="Docker Hub Personal Access Token",
        regex=r"dckr_pat_[a-zA-Z0-9\-_]{27}",
        severity="high",
        tags=["docker", "token"],
    ),
    PatternRule(
        rule_id="anthropic-api-key",
        description="Anthropic API Key",
        regex=r"sk-ant-[a-zA-Z0-9\-_]{93}",
        severity="critical",
        tags=["anthropic", "api-key"],
    ),
    PatternRule(
        rule_id="openai-api-key",
        description="OpenAI API Key",
        regex=r"sk-(?:proj-)?[a-zA-Z0-9]{48,}",
        severity="critical",
        tags=["openai", "api-key"],
    ),
    PatternRule(
        rule_id="azure-connection-string",
        description="Azure Storage Connection String",
        regex=r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]{86,88}==",
        severity="critical",
        tags=["azure", "cloud", "storage"],
    ),
]