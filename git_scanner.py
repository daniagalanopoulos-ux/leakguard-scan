"""
Git history scanner for LeakGuard.
Walks all commits in a git repository and scans diff content for secrets.
"""

import re
from pathlib import Path
from typing import List, Optional

from .patterns import PATTERNS
from .entropy import find_high_entropy_strings
from .finding import Finding


class GitScanner:
    def __init__(self, ignore_file: Optional[Path] = None):
        self.ignore_file = ignore_file

    def scan(self, repo_path) -> List[Finding]:
        """
        Walk all commits in the repo and scan added lines for secrets.
        Returns a flat list of Finding objects with commit_hash set.
        """
        try:
            import git as gitpython
        except ImportError:
            raise ImportError(
                "GitPython is required for git history scanning. "
                "Install it with: pip install gitpython"
            )

        repo_path = Path(repo_path)
        findings: List[Finding] = []

        try:
            repo = gitpython.Repo(repo_path, search_parent_directories=True)
        except gitpython.InvalidGitRepositoryError:
            return findings

        seen_fingerprints = set()

        for commit in repo.iter_commits():
            try:
                diff_text = self._get_commit_diff(repo, commit)
            except Exception:
                continue

            for line_number, line in enumerate(diff_text.splitlines(), start=1):
                # Only scan added lines (start with +), skip diff headers
                if not line.startswith("+") or line.startswith("+++"):
                    continue

                clean_line = line[1:]  # Remove leading +

                for rule in PATTERNS:
                    for match in re.finditer(rule.regex, clean_line):
                        finding = Finding(
                            rule_id=rule.rule_id,
                            description=rule.description,
                            severity=rule.severity,
                            filepath=self._extract_filepath(diff_text, line_number),
                            line_number=line_number,
                            line_content=clean_line.strip(),
                            match=match.group(0),
                            commit_hash=commit.hexsha[:8],
                            tags=rule.tags + ["git-history"],
                        )
                        if finding.fingerprint not in seen_fingerprints:
                            seen_fingerprints.add(finding.fingerprint)
                            findings.append(finding)

                # Entropy-based detection on git diff lines
                for token, score, charset_type in find_high_entropy_strings(clean_line):
                    already = any(
                        token in f.match and f.commit_hash == commit.hexsha[:8]
                        for f in findings
                    )
                    if not already:
                        finding = Finding(
                            rule_id="high-entropy-string",
                            description=f"High-entropy {charset_type} string in git history",
                            severity="medium",
                            filepath="(git history)",
                            line_number=line_number,
                            line_content=clean_line.strip(),
                            match=token,
                            commit_hash=commit.hexsha[:8],
                            tags=["entropy", charset_type, "git-history"],
                            entropy_score=round(score, 3),
                        )
                        if finding.fingerprint not in seen_fingerprints:
                            seen_fingerprints.add(finding.fingerprint)
                            findings.append(finding)

        return findings

    def _get_commit_diff(self, repo, commit) -> str:
        """Return the unified diff text for a commit."""
        if not commit.parents:
            # Initial commit — diff against empty tree
            diff = repo.git.show(commit.hexsha, "--unified=0", "--no-color")
        else:
            diff = repo.git.diff(
                commit.parents[0].hexsha,
                commit.hexsha,
                "--unified=0",
                "--no-color",
            )
        return diff

    def _extract_filepath(self, diff_text: str, near_line: int) -> str:
        """
        Best-effort extraction of the filename from the diff header
        closest to the given line number.
        """
        filepath = "(unknown)"
        lines = diff_text.splitlines()
        for i, line in enumerate(lines):
            if line.startswith("+++ b/"):
                filepath = line[6:]
            if i >= near_line:
                break
        return filepath