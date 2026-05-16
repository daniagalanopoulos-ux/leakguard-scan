"""
Finding dataclass — shared result type for all scanners.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    rule_id: str
    description: str
    severity: str          # low | medium | high | critical
    filepath: str
    line_number: int
    line_content: str      # the raw line (redacted for output)
    match: str             # the matched secret value (redacted for output)
    commit_hash: Optional[str] = None   # set by git scanner
    tags: list = field(default_factory=list)
    entropy_score: Optional[float] = None

    @property
    def fingerprint(self) -> str:
        """
        Stable hash of this finding for baseline comparison.
        Based on rule + file + line content so it survives line-number shifts.
        """
        raw = f"{self.rule_id}:{self.filepath}:{self.line_content.strip()}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def redacted_match(self) -> str:
        """Show only first 4 chars + asterisks."""
        if len(self.match) <= 4:
            return "****"
        return self.match[:4] + "*" * min(len(self.match) - 4, 20)

    @property
    def redacted_line(self) -> str:
        """Replace the match within the line with its redacted version."""
        if self.match in self.line_content:
            return self.line_content.replace(self.match, self.redacted_match, 1)
        return self.line_content

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "description": self.description,
            "severity": self.severity,
            "filepath": self.filepath,
            "line_number": self.line_number,
            "line_content": self.redacted_line,
            "match": self.redacted_match,
            "commit_hash": self.commit_hash,
            "tags": self.tags,
            "entropy_score": self.entropy_score,
        }