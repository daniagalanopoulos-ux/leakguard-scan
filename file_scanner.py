"""
File and directory scanner for LeakGuard.
Walks a path, respects .scannerignore, and applies all detection patterns.
"""

import re
from pathlib import Path
from typing import List, Optional, Set

import pathspec

from .patterns import PATTERNS, PatternRule
from .entropy import find_high_entropy_strings
from .finding import Finding

 
# Binary file extensions to skip entirely
BINARY_EXTENSIONS: Set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp4", ".mp3", ".wav", ".avi", ".mov", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".class",
    ".pdf", ".docx", ".xlsx", ".pptx",
    ".pyc", ".pyo", ".pyd",
    ".woff", ".woff2", ".ttf", ".eot",
}

# Files that are always suspicious by name alone
SUSPICIOUS_FILENAMES: Set[str] = {
    ".env", ".env.local", ".env.production", ".env.staging",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials", "credentials.json", "secret.json",
    "secrets.yaml", "secrets.yml",
    "*.pem", "*.key", "*.p12", "*.pfx",
}

# Directories to always skip
SKIP_DIRS: Set[str] = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", "coverage", ".idea", ".vscode",
}

# Max file size to scan (5 MB)
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024


class FileScanner:
    def __init__(self, ignore_file: Optional[Path] = None):
        self.ignore_spec: Optional[pathspec.PathSpec] = None

        if ignore_file and Path(ignore_file).exists():
            lines = Path(ignore_file).read_text().splitlines()
            self.ignore_spec = pathspec.PathSpec.from_lines("gitwildmatch", lines)

    def _is_ignored(self, path: Path, root: Path) -> bool:
        if self.ignore_spec is None:
            return False
        try:
            rel = path.relative_to(root)
            return self.ignore_spec.match_file(str(rel))
        except ValueError:
            return False

    def _should_skip_dir(self, dir_name: str) -> bool:
        return dir_name in SKIP_DIRS or dir_name.startswith(".")

    def _should_skip_file(self, filepath: Path) -> bool:
        if filepath.suffix.lower() in BINARY_EXTENSIONS:
            return True
        try:
            if filepath.stat().st_size > MAX_FILE_SIZE_BYTES:
                return True
        except OSError:
            return True
        return False

    def _flag_suspicious_name(self, filepath: Path) -> List[Finding]:
        """Flag files that are suspicious by name alone (e.g. id_rsa, .env)."""
        findings = []
        name = filepath.name
        for pattern in SUSPICIOUS_FILENAMES:
            if pattern.startswith("*"):
                if name.endswith(pattern[1:]):
                    findings.append(Finding(
                        rule_id="suspicious-filename",
                        description=f"Sensitive filename detected: {name}",
                        severity="high",
                        filepath=str(filepath),
                        line_number=0,
                        line_content="",
                        match=name,
                        tags=["filename"],
                    ))
            else:
                if name == pattern:
                    findings.append(Finding(
                        rule_id="suspicious-filename",
                        description=f"Sensitive filename detected: {name}",
                        severity="high",
                        filepath=str(filepath),
                        line_number=0,
                        line_content="",
                        match=name,
                        tags=["filename"],
                    ))
        return findings

    def _scan_file_content(self, filepath: Path) -> List[Finding]:
        findings = []

        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        for line_number, line in enumerate(content.splitlines(), start=1):
            # Pattern-based detection
            for rule in PATTERNS:
                for match in re.finditer(rule.regex, line):
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        description=rule.description,
                        severity=rule.severity,
                        filepath=str(filepath),
                        line_number=line_number,
                        line_content=line.strip(),
                        match=match.group(0),
                        tags=rule.tags,
                    ))

            # Entropy-based detection
            for token, score, charset_type in find_high_entropy_strings(line, line_number, str(filepath)):
                # Avoid duplicate with pattern match
                already_found = any(
                    f.filepath == str(filepath)
                    and f.line_number == line_number
                    and token in f.match
                    for f in findings
                )
                if not already_found:
                    findings.append(Finding(
                        rule_id="high-entropy-string",
                        description=f"High-entropy {charset_type} string (possible secret)",
                        severity="medium",
                        filepath=str(filepath),
                        line_number=line_number,
                        line_content=line.strip(),
                        match=token,
                        tags=["entropy", charset_type],
                        entropy_score=round(score, 3),
                    ))

        return findings

    def scan(self, path) -> List[Finding]:
        """
        Scan a file or directory recursively.
        Returns a flat list of Finding objects.
        """
        path = Path(path)
        root = path if path.is_dir() else path.parent
        all_findings: List[Finding] = []

        if path.is_file():
            files = [path]
        else:
            files = []
            for p in path.rglob("*"):
                if p.is_file():
                    files.append(p)

        for filepath in files:
            # Skip ignored dirs
            parts = filepath.relative_to(root).parts if root in filepath.parents or root == filepath.parent else filepath.parts
            if any(self._should_skip_dir(part) for part in parts[:-1]):
                continue

            # Skip ignored by .scannerignore
            if self._is_ignored(filepath, root):
                continue

            # Skip binary/large files
            if self._should_skip_file(filepath):
                continue

            # Check filename
            all_findings.extend(self._flag_suspicious_name(filepath))

            # Check content
            all_findings.extend(self._scan_file_content(filepath))

        return all_findings