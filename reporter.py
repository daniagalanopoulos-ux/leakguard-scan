"""
Reporter module for LeakGuard.
Supports table (rich), JSON, and SARIF output formats.
"""

import json
from enum import Enum
from typing import List

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .finding import Finding 
 

class OutputFormat(str, Enum):
    table = "table"
    json = "json"
    sarif = "sarif"


SEVERITY_COLORS = {
    "low": "white",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}

SEVERITY_ICONS = {
    "low": "ℹ",
    "medium": "⚠",
    "high": "✖",
    "critical": "☠",
}


class Reporter:
    def __init__(self, findings: List[Finding]):
        self.findings = findings

    def render(self, format: OutputFormat) -> str:
        if format == OutputFormat.json:
            return self._to_json()
        elif format == OutputFormat.sarif:
            return self._to_sarif()
        else:
            return ""  # Table is rendered directly via print_table()

    def print_table(self, console: Console):
        if not self.findings:
            return

        table = Table(
            title=f"LeakGuard Findings ({len(self.findings)} total)",
            border_style="cyan",
            show_lines=True,
        )
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Rule", style="cyan", width=28)
        table.add_column("File", width=35)
        table.add_column("Line", justify="right", width=6)
        table.add_column("Match (redacted)", width=28)
        table.add_column("Commit", width=10)

        # Sort: critical → high → medium → low
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(self.findings, key=lambda f: order.get(f.severity, 9))

        for f in sorted_findings:
            color = SEVERITY_COLORS.get(f.severity, "white")
            icon = SEVERITY_ICONS.get(f.severity, " ")
            sev_text = Text(f"{icon} {f.severity.upper()}", style=color)

            # Shorten long file paths
            fp = f.filepath
            if len(fp) > 35:
                fp = "…" + fp[-33:]

            table.add_row(
                sev_text,
                f.rule_id,
                fp,
                str(f.line_number) if f.line_number else "-",
                f.redacted_match,
                f.commit_hash or "-",
            )

        console.print(table)

    # ── JSON ─────────────────────────────────────────────────────────────────

    def _to_json(self) -> str:
        data = {
            "version": "1.0.0",
            "total": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        return json.dumps(data, indent=2)

    # ── SARIF ────────────────────────────────────────────────────────────────

    def _to_sarif(self) -> str:
        """
        Generate SARIF 2.1.0 output compatible with GitHub Code Scanning.
        https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
        """
        from .patterns import PATTERNS

        rules_map = {p.rule_id: p for p in PATTERNS}

        sarif_rules = []
        seen_rule_ids = set()
        for f in self.findings:
            if f.rule_id not in seen_rule_ids:
                seen_rule_ids.add(f.rule_id)
                rule = rules_map.get(f.rule_id)
                sarif_rules.append({
                    "id": f.rule_id,
                    "name": f.rule_id.replace("-", " ").title(),
                    "shortDescription": {
                        "text": rule.description if rule else f.description,
                    },
                    "defaultConfiguration": {
                        "level": self._sarif_level(f.severity),
                    },
                    "tags": rule.tags if rule else [],
                })

        results = []
        for f in self.findings:
            results.append({
                "ruleId": f.rule_id,
                "level": self._sarif_level(f.severity),
                "message": {
                    "text": f"{f.description} — {f.redacted_match}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.filepath,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(f.line_number, 1),
                            },
                        },
                    }
                ],
                "fingerprints": {
                    "leakguard/v1": f.fingerprint,
                },
                "properties": {
                    "commit": f.commit_hash,
                    "tags": f.tags,
                    "entropy": f.entropy_score,
                },
            })

        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "LeakGuard",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/your-username/leakguard",
                            "rules": sarif_rules,
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, indent=2)

    @staticmethod
    def _sarif_level(severity: str) -> str:
        return {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
        }.get(severity.lower(), "warning")