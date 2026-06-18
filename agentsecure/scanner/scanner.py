import os
from typing import Iterable, List, Optional, Set

from agentsecure.scanner.models import Finding, ScanReport
from agentsecure.scanner.rules import (
    AgentConfigPathRule,
    FileContext,
    McpConfigRule,
    NetworkProductionHintRule,
    PathContext,
    Rule,
    ScriptRiskRule,
    SecretPatternRule,
    SensitivePathRule,
    normalized_rel,
)


IGNORE_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    ".next",
    ".turbo",
    "target",
    "__pycache__",
}
MAX_FILE_BYTES = 1024 * 1024


class RepositoryScanner:
    def __init__(self, rules: Optional[Iterable[Rule]] = None) -> None:
        self.rules = list(rules) if rules is not None else default_rules()

    def scan(self, path: str = ".") -> ScanReport:
        root = os.path.abspath(path)
        display_path = path or "."
        report = ScanReport(path=display_path)
        seen_path_findings: Set[str] = set()
        for current_root, dirnames, filenames in os.walk(root):
            dirnames[:] = [dirname for dirname in dirnames if dirname not in IGNORE_DIRS]
            for dirname in list(dirnames):
                abs_path = os.path.join(current_root, dirname)
                rel_path = normalized_rel(os.path.relpath(abs_path, root))
                context = PathContext(root=root, rel_path=rel_path, abs_path=abs_path, is_dir=True)
                for finding in self._check_path(context):
                    key = self._dedupe_key(finding)
                    if key not in seen_path_findings:
                        seen_path_findings.add(key)
                        report.findings.append(finding)
            for filename in filenames:
                abs_path = os.path.join(current_root, filename)
                rel_path = normalized_rel(os.path.relpath(abs_path, root))
                path_context = PathContext(root=root, rel_path=rel_path, abs_path=abs_path, is_dir=False)
                for finding in self._check_path(path_context):
                    report.findings.append(finding)
                text = self._read_text(abs_path)
                if text is None:
                    report.skipped_files += 1
                    continue
                report.scanned_files += 1
                file_context = FileContext(root=root, rel_path=rel_path, abs_path=abs_path, text=text)
                for finding in self._check_file(file_context):
                    report.findings.append(finding)
        report.findings.sort(key=_finding_sort_key)
        return report

    def _check_path(self, context: PathContext) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            findings.extend(rule.check_path(context))
        return findings

    def _check_file(self, context: FileContext) -> List[Finding]:
        findings: List[Finding] = []
        for rule in self.rules:
            findings.extend(rule.check_file(context))
        return findings

    def _read_text(self, path: str) -> Optional[str]:
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                return None
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            return None
        if b"\x00" in data:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace")

    def _dedupe_key(self, finding: Finding) -> str:
        return "%s:%s:%s" % (finding.title, finding.path, finding.severity)


def default_rules() -> List[Rule]:
    return [
        SensitivePathRule(),
        AgentConfigPathRule(),
        SecretPatternRule(),
        McpConfigRule(),
        ScriptRiskRule(),
        NetworkProductionHintRule(),
    ]


def _finding_sort_key(finding: Finding):
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    return (severity_order.get(finding.severity, 99), finding.path, finding.line or 0, finding.title)
