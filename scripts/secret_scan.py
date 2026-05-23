#!/usr/bin/env python3
import argparse
import os
import re
import sys
from dataclasses import dataclass
from typing import Iterable, List


SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".agentsecure",
    "build",
    "dist",
    "*.egg-info",
}

ALLOWED_SECRET_VALUES = {
    "sk-demo-local-secret-do-not-use",
    "sk_test_dummy_value_do_not_use",
    "sk-real-local-secret",
    "sk-receipt-real-secret",
    "sk-real-openai-local-test",
    "sk-doctor-local-test",
    "sk-command-guard-real-secret",
    "sk-workspace-real-secret",
    "sk-integration-real-secret",
    "sk-configured-no-discover-secret",
    "sk-real",
}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    kind: str


SECRET_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----")),
    ("aws access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("openai-like key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    (
        "credential url",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
            r"[^:\s\"'<>]+:[^@\s\"'<>]+@[^.\s\"'<>]+(?:\.[^\s\"'<>]+)+",
            re.IGNORECASE,
        ),
    ),
)


def scan_path(root: str) -> List[Finding]:
    findings: List[Finding] = []
    for path in _iter_files(root):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except (OSError, UnicodeDecodeError):
            continue
        rel_path = os.path.relpath(path, root)
        for line_number, line in enumerate(lines, 1):
            for kind, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(line):
                    if _is_allowed_placeholder(kind, match.group(0), rel_path):
                        continue
                    findings.append(Finding(rel_path, line_number, kind))
    return findings


def _iter_files(root: str) -> Iterable[str]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [
            directory
            for directory in dirs
            if directory not in SKIP_DIRS and not directory.endswith(".egg-info")
        ]
        for filename in files:
            yield os.path.join(current, filename)


def _is_allowed_placeholder(kind: str, value: str, rel_path: str) -> bool:
    if value in ALLOWED_SECRET_VALUES:
        return True
    if kind == "github token" and rel_path == "tests/test_secret_scan.py":
        return True
    if kind == "credential url" and any(
        marker in value
        for marker in (
            "example.invalid",
            "production.example",
            "prod.example",
            "dev.example",
            ".host.domain",
            ".prod.host",
        )
    ):
        return True
    if rel_path.startswith(("tests/", "examples/")) and "do-not-use" in value:
        return True
    return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Scan for likely committed secrets.")
    parser.add_argument("path", nargs="?", default=".", help="Repository path to scan")
    args = parser.parse_args(argv)
    root = os.path.abspath(args.path)
    findings = scan_path(root)
    if not findings:
        print("Secret scan passed.")
        return 0
    print("Secret scan found likely sensitive values:")
    for finding in findings:
        print("%s:%s: %s" % (finding.path, finding.line, finding.kind))
    return 1


if __name__ == "__main__":
    sys.exit(main())
