import json
from typing import List

from agentsecure.scanner.models import CHECKLIST, SEVERITIES, Finding, ScanReport


def render_report(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return render_json(report)
    if output_format == "markdown":
        return render_markdown(report)
    return render_text(report)


def render_text(report: ScanReport) -> str:
    lines: List[str] = [
        "AgentSecure AI Coding Agent Security Scanner",
        "",
        "Path: %s" % report.path,
        "Score: %s/100" % report.score,
        "Risk: %s" % report.risk_level,
        "",
    ]
    grouped = report.findings_by_severity()
    for severity in SEVERITIES:
        findings = grouped.get(severity, [])
        if not findings:
            continue
        lines.append("%s:" % severity)
        for finding in findings:
            lines.extend(_text_finding(finding))
        lines.append("")
    if not report.findings:
        lines.extend(["No findings.", ""])
    lines.append("Next steps:")
    for item in CHECKLIST:
        lines.append("[ ] %s" % item)
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(report: ScanReport) -> str:
    lines: List[str] = [
        "# AgentSecure AI Coding Agent Security Scanner",
        "",
        "- Path: `%s`" % report.path,
        "- Score: `%s/100`" % report.score,
        "- Risk: `%s`" % report.risk_level,
        "",
    ]
    grouped = report.findings_by_severity()
    for severity in SEVERITIES:
        findings = grouped.get(severity, [])
        if not findings:
            continue
        lines.append("## %s" % severity)
        lines.append("")
        for finding in findings:
            lines.extend(_markdown_finding(finding))
            lines.append("")
    if not report.findings:
        lines.extend(["No findings.", ""])
    lines.append("## Next steps")
    lines.append("")
    for item in CHECKLIST:
        lines.append("- [ ] %s" % item)
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


def _text_finding(finding: Finding) -> List[str]:
    lines = [
        "- %s" % finding.title,
        "  File: %s" % finding.path,
    ]
    if finding.line is not None:
        lines.append("  Line: %s" % finding.line)
    if finding.evidence:
        lines.append("  Evidence: %s" % finding.evidence)
    lines.extend(
        [
            "  Why it matters: %s" % finding.why,
            "  Recommendation: %s" % finding.recommendation,
        ]
    )
    return lines


def _markdown_finding(finding: Finding) -> List[str]:
    lines = [
        "- **%s**" % finding.title,
        "  - File: `%s`" % finding.path,
    ]
    if finding.line is not None:
        lines.append("  - Line: `%s`" % finding.line)
    if finding.evidence:
        lines.append("  - Evidence: `%s`" % finding.evidence)
    lines.extend(
        [
            "  - Why it matters: %s" % finding.why,
            "  - Recommendation: %s" % finding.recommendation,
        ]
    )
    return lines
