#!/usr/bin/env python3
"""Static security audit for small Python web applications.

I wrote this scanner to review code that comes out of AI coding tools.
It looks for the failure modes that show up again and again in rushed,
generated applications: secrets written straight into the source, SQL
built by gluing strings together, debug mode left on, routes with no
authentication, no audit logging, and dependencies nobody pinned.

It uses only the Python standard library. It reads source files as text
and never executes the code it scans.

Some checks are exact pattern matches (a private key block is a private
key block). Others are heuristics, and I label them as heuristics in the
output: a route with no visible auth check nearby might still be
protected by middleware I cannot see. Treat the report as a starting
point for a human review, not a verdict.

Usage:
    python3 src/audit.py <target-dir> [--report report.md] [--json report.json]

Exit code is 1 when any critical or high severity finding is present,
0 otherwise.
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    severity: str
    category: str
    path: str
    line: int
    message: str
    remediation: str
    heuristic: bool = False

    def sort_key(self):
        return (SEVERITY_ORDER[self.severity], self.path, self.line)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
SECRET_ASSIGN_RE = re.compile(
    r"""(?ix)
    (?P<name>[A-Za-z0-9_\-]*(?:api[_-]?key|secret|passwd|password|token)[A-Za-z0-9_\-]*)
    \s*["']?\]?\s*=\s*
    (?P<q>["'])(?P<value>[^"']{4,})(?P=q)
    """
)
PLACEHOLDER_VALUES = {
    "changeme", "change-me", "example", "placeholder", "todo",
    "xxxx", "xxxxxxxx", "********", "password", "secret",
}

SQL_KEYWORD_RE = re.compile(r"(?i)\b(select|insert\s+into|update|delete\s+from)\b")
STRING_CONCAT_RE = re.compile(r"""["']\s*\+|\+\s*["']""")
EXEC_FSTRING_RE = re.compile(r"""\.execute\(\s*f["']""")
EXEC_CONCAT_RE = re.compile(r"""\.execute\(\s*["'][^"']*["']\s*\+""")
EXEC_PERCENT_RE = re.compile(r"""\.execute\([^)]*["']\s*%""")
QUERY_FSTRING_RE = re.compile(r"""(?i)\b(query|sql)\b\s*=\s*f["']""")

DEBUG_RE = re.compile(r"(?i)\bdebug\s*=\s*True\b")
CORS_HEADER_RE = re.compile(r"""Access-Control-Allow-Origin["']?\]?\s*[:=]\s*["']\*["']""")
CORS_ORIGINS_RE = re.compile(r"""origins\s*=\s*["']\*["']""")
CORS_BARE_RE = re.compile(r"\bCORS\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)")
HOST_BIND_RE = re.compile(r"""host\s*=\s*["']0\.0\.0\.0["']""")

ROUTE_RE = re.compile(r"@(app|router|bp|blueprint|api)\.(route|get|post|put|delete|patch)\s*\(")
AUTH_TOKENS = (
    "login_required", "require_auth", "requires_auth", "authenticate",
    "check_auth", "verify_token", "current_user", "session.get",
    "session[", "authorization",
)
PUBLIC_PATH_HINTS = ("login", "logout", "health", "static", "signup", "register", "public")

LOGGING_RE = re.compile(r"\blogging\b|\blogger\b|getLogger|\.log\(")

SKIP_DIRS = {"__pycache__", ".git", ".hg", "venv", ".venv", "node_modules"}


# ---------------------------------------------------------------------------
# Individual checks. Each takes a relative path and the file's lines.
# ---------------------------------------------------------------------------

def check_secrets(path, lines):
    findings = []
    for lineno, line in enumerate(lines, start=1):
        if PRIVATE_KEY_RE.search(line):
            findings.append(Finding(
                "critical", "hardcoded-secret", path, lineno,
                "A private key block is written directly in the source code.",
                "Remove the key from source, rotate it (it must be treated as "
                "compromised), and load keys from the environment or a secrets manager.",
            ))
        if AWS_KEY_RE.search(line):
            findings.append(Finding(
                "critical", "hardcoded-secret", path, lineno,
                "An AWS access key ID is written directly in the source code.",
                "Remove the key from source, rotate it, and use environment "
                "variables or an instance role instead.",
            ))
        if "environ" in line or "getenv" in line:
            continue  # value comes from the environment, not a literal
        match = SECRET_ASSIGN_RE.search(line)
        if match:
            value = match.group("value").strip()
            if value.lower() in PLACEHOLDER_VALUES or value.startswith("your-"):
                continue
            findings.append(Finding(
                "high", "hardcoded-secret", path, lineno,
                "A secret value is assigned as a literal in the source: "
                + match.group("name") + ". Anyone who can read the code, a "
                "backup, or a chat transcript the code was pasted into has the secret.",
                "Move the secret to an environment variable or a secrets "
                "manager, and rotate the exposed value.",
            ))
    return findings


def check_sql(path, lines):
    findings = []
    for lineno, line in enumerate(lines, start=1):
        hit = None
        if EXEC_FSTRING_RE.search(line) or EXEC_CONCAT_RE.search(line) or EXEC_PERCENT_RE.search(line):
            hit = "A SQL statement passed to execute() is built with string formatting or concatenation."
        elif QUERY_FSTRING_RE.search(line):
            hit = "A SQL query string is built with an f-string."
        elif SQL_KEYWORD_RE.search(line) and STRING_CONCAT_RE.search(line):
            hit = "A SQL statement is assembled by concatenating strings, so user input can change the query."
        if hit:
            findings.append(Finding(
                "high", "sql-injection", path, lineno, hit,
                "Use parameterized queries: pass the SQL with placeholders "
                "and the values as a separate parameter tuple, and let the "
                "database driver handle quoting.",
            ))
    return findings


def check_debug(path, lines):
    findings = []
    for lineno, line in enumerate(lines, start=1):
        if DEBUG_RE.search(line):
            findings.append(Finding(
                "high", "debug-mode", path, lineno,
                "Debug mode is enabled. Framework debug modes can expose an "
                "interactive debugger and stack traces to anyone who can reach the app.",
                "Turn debug off outside local development and drive it from "
                "an environment setting that defaults to off.",
            ))
    return findings


def check_cors(path, lines):
    findings = []
    for lineno, line in enumerate(lines, start=1):
        if CORS_HEADER_RE.search(line) or CORS_ORIGINS_RE.search(line):
            findings.append(Finding(
                "medium", "cors-wildcard", path, lineno,
                "CORS is configured to allow any origin (*). Any website a "
                "user visits can make cross-origin requests to this app.",
                "Restrict allowed origins to the specific sites that need access.",
            ))
        elif CORS_BARE_RE.search(line):
            findings.append(Finding(
                "medium", "cors-wildcard", path, lineno,
                "CORS is enabled with no origin restriction, which defaults "
                "to allowing cross-origin requests broadly.",
                "Pass an explicit list of allowed origins when enabling CORS.",
            ))
    return findings


def check_host_binding(path, lines):
    findings = []
    for lineno, line in enumerate(lines, start=1):
        if HOST_BIND_RE.search(line):
            findings.append(Finding(
                "low", "network-binding", path, lineno,
                "The development server binds to 0.0.0.0, which exposes it "
                "on every network interface, not just this machine. That is "
                "sometimes intended behind a firewall or in a container, "
                "and risky when it is not.",
                "Bind to 127.0.0.1 for local development, and put a real "
                "web server in front for anything shared.",
            ))
    return findings


def check_route_auth(path, lines):
    """Heuristic: a route whose handler shows no sign of an auth check."""
    findings = []
    route_indexes = [i for i, line in enumerate(lines) if ROUTE_RE.search(line)]
    for pos, start in enumerate(route_indexes):
        end = route_indexes[pos + 1] if pos + 1 < len(route_indexes) else len(lines)
        end = min(end, start + 40)
        decorator_line = lines[start]
        if any(hint in decorator_line for hint in PUBLIC_PATH_HINTS):
            continue  # login, health checks and similar are public on purpose
        window = "\n".join(lines[start:end]).lower()
        if not any(token in window for token in AUTH_TOKENS):
            findings.append(Finding(
                "medium", "missing-authentication", path, start + 1,
                "This route shows no authentication check in or near its "
                "handler. If middleware elsewhere does not protect it, "
                "anyone who can reach the app can use this route.",
                "Require authentication on the route itself (for example a "
                "login decorator) so the protection is visible where the "
                "route is defined, and verify by hand that the route "
                "rejects anonymous requests.",
                heuristic=True,
            ))
    return findings


FILE_CHECKS = (check_secrets, check_sql, check_debug, check_cors,
               check_host_binding, check_route_auth)


# ---------------------------------------------------------------------------
# Project level checks
# ---------------------------------------------------------------------------

def check_logging(root, py_files_lines):
    for _path, lines in py_files_lines:
        for line in lines:
            if LOGGING_RE.search(line):
                return []
    return [Finding(
        "medium", "no-audit-logging", "(project)", 0,
        "No logging calls appear anywhere in the project. With no audit "
        "trail there is no record of who viewed or changed data, which "
        "matters most for the systems that hold sensitive records.",
        "Add structured logging for sign-ins, record views, changes and "
        "deletions, and make sure the logs go somewhere they are reviewed.",
    )]


def check_requirements(root):
    req_path = os.path.join(root, "requirements.txt")
    if not os.path.isfile(req_path):
        return []
    findings = []
    with open(req_path, encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()
    for lineno, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[<>=!~\[]", line)[0].strip()
        if "==" not in line:
            findings.append(Finding(
                "low", "unpinned-dependency", "requirements.txt", lineno,
                "Dependency '" + name + "' is not pinned to an exact "
                "version. The next install can silently pull a different, "
                "possibly compromised or breaking, release.",
                "Pin every dependency to an exact version (name==x.y.z) "
                "and review changes when versions are bumped.",
            ))
    return findings


# ---------------------------------------------------------------------------
# Scanning driver
# ---------------------------------------------------------------------------

def iter_python_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in sorted(filenames):
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


def scan_directory(root):
    root = os.path.abspath(root)
    findings = []
    py_files_lines = []
    for full_path in iter_python_files(root):
        rel = os.path.relpath(full_path, root)
        with open(full_path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()
        py_files_lines.append((rel, lines))
        for check in FILE_CHECKS:
            findings.extend(check(rel, lines))
    findings.extend(check_logging(root, py_files_lines))
    findings.extend(check_requirements(root))
    findings.sort(key=lambda f: f.sort_key())
    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def format_location(finding):
    if finding.line:
        return finding.path + ":" + str(finding.line)
    return finding.path


def render_console(findings, target):
    out = []
    out.append("Audit target: " + target)
    out.append("Files scanned for a set of known failure patterns; see the "
               "limitations in the project README.")
    out.append("")
    if not findings:
        out.append("No findings. That means none of the patterns this "
                   "scanner knows about were found. It does not mean the "
                   "application is secure.")
        return "\n".join(out)
    for finding in findings:
        tag = " [heuristic]" if finding.heuristic else ""
        out.append("[" + finding.severity.upper() + "] " + finding.category + tag)
        out.append("  Where: " + format_location(finding))
        out.append("  What: " + finding.message)
        out.append("  Fix: " + finding.remediation)
        out.append("")
    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    parts = [sev + ": " + str(counts[sev]) for sev in
             ("critical", "high", "medium", "low") if sev in counts]
    out.append("Summary: " + str(len(findings)) + " findings (" + ", ".join(parts) + ")")
    return "\n".join(out)


def render_markdown(findings, target):
    out = []
    out.append("# Scan report")
    out.append("")
    out.append("Target: `" + target + "`")
    out.append("")
    if not findings:
        out.append("No findings. None of the patterns this scanner knows "
                   "about were found. That is not the same as the "
                   "application being secure.")
        return "\n".join(out) + "\n"
    out.append("| Severity | Category | Location | Finding |")
    out.append("| --- | --- | --- | --- |")
    for finding in findings:
        tag = " (heuristic)" if finding.heuristic else ""
        out.append("| " + finding.severity + " | " + finding.category + tag
                   + " | " + format_location(finding) + " | "
                   + finding.message + " |")
    out.append("")
    out.append("## Remediation notes")
    out.append("")
    seen = set()
    for finding in findings:
        key = (finding.category, finding.path, finding.line)
        if key in seen:
            continue
        seen.add(key)
        out.append("- **" + finding.category + "** at "
                   + format_location(finding) + ": " + finding.remediation)
    out.append("")
    return "\n".join(out)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Static security audit for small Python web apps.")
    parser.add_argument("target", help="Directory of source code to audit")
    parser.add_argument("--report", help="Also write a Markdown report to this path")
    parser.add_argument("--json", help="Also write a JSON report to this path")
    args = parser.parse_args(argv)

    if not os.path.isdir(args.target):
        print("Target is not a directory: " + args.target, file=sys.stderr)
        return 2

    findings = scan_directory(args.target)
    print(render_console(findings, args.target))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as handle:
            handle.write(render_markdown(findings, args.target))
    if args.json:
        payload = [finding.__dict__ for finding in findings]
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    if any(f.severity in ("critical", "high") for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
