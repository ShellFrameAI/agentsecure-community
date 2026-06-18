from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")


@dataclass(frozen=True)
class Finding:
    title: str
    path: str
    severity: str
    why: str
    recommendation: str
    line: Optional[int] = None
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "title": self.title,
            "path": self.path,
            "severity": self.severity,
            "why": self.why,
            "recommendation": self.recommendation,
        }
        if self.line is not None:
            payload["line"] = self.line
        if self.evidence:
            payload["evidence"] = self.evidence
        return payload


@dataclass
class ScanReport:
    path: str
    findings: List[Finding] = field(default_factory=list)
    scanned_files: int = 0
    skipped_files: int = 0

    @property
    def score(self) -> int:
        weights = {
            "Critical": 30,
            "High": 15,
            "Medium": 7,
            "Low": 3,
            "Info": 1,
        }
        penalty = sum(weights.get(finding.severity, 0) for finding in self.findings)
        return max(0, 100 - penalty)

    @property
    def risk_level(self) -> str:
        score = self.score
        if score >= 80:
            return "Low"
        if score >= 60:
            return "Medium"
        if score >= 30:
            return "High"
        return "Critical"

    def findings_by_severity(self) -> Dict[str, List[Finding]]:
        grouped = {severity: [] for severity in SEVERITIES}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "score": self.score,
            "risk": self.risk_level,
            "scanned_files": self.scanned_files,
            "skipped_files": self.skipped_files,
            "findings": [finding.to_dict() for finding in self.findings],
            "checklist": CHECKLIST,
        }


CHECKLIST = [
    "Create agent-safe `.env`",
    "Move production credentials out of agent-visible files",
    "Restrict MCP filesystem access",
    "Add network allowlist",
    "Run the repo through AgentSecure",
]
