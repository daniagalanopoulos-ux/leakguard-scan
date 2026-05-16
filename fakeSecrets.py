# fixtures/fake_secrets.py
# This file contains PLACEHOLDER strings for unit testing only.
# These are NOT real credentials and will not work with any service.
# Patterns are intentionally broken/split to avoid triggering secret scanners.

# AWS placeholder — split string to avoid pattern matching
AWS_ACCESS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # pragma: allowlist secret

# GitHub placeholder — split string
GITHUB_TOKEN = "ghp_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456"  # pragma: allowlist secret

# Database placeholder — fake hostname and password
DATABASE_URL = "postgres://admin:FAKE_PASSWORD@db.example.com:5432/testdb"  # pragma: allowlist secret

# Private key header — split to avoid scanning
PRIVATE_KEY_HEADER = "-----BEGIN RSA" + " PRIVATE KEY-----"

# Stripe placeholder — uses test prefix, not live
STRIPE_SECRET = "sk_test_" + "FAKE_KEY_FOR_TESTING_ONLY"  # pragma: allowlist secret

# JWT placeholder — intentionally malformed, not a real token
JWT_EXAMPLE = "eyJ.FAKE.JWT_FOR_TESTING_ONLY"  # pragma: allowlist secret

# PII placeholders — all zeroed out
FAKE_EMAIL = "test.user@example.com"
FAKE_SSN = "000-00-0000"
FAKE_CREDIT_CARD = "0000-0000-0000-0000"
