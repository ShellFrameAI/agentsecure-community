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

ALLOW_MARKERS = (
    "demo",
    "dummy",
    "example",
    "fake",
    "fixture",
    "placeholder",
    "sample",
    "test",
    "do-not-use",
    "sk-real",
    "sk-cloud",
    "real-secret",
    "secret-value",
    "localhost",
    "127.0.0.1",
    ".host.domain",
    ".prod.host",
)


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
            if _is_allowed_placeholder(line):
                continue
            for kind, pattern in SECRET_PATTERNS:
                if pattern.search(line):
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


def _is_allowed_placeholder(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in ALLOW_MARKERS)


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
