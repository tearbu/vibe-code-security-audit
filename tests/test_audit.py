"""Tests for the audit scanner.

I test each check twice where it matters: once against code that
should be flagged and once against the fixed version of the same code,
so a check that flags everything (or nothing) fails the suite.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"),
)

import audit


def scan_source(source, extra_files=None):
    """Write source to a temp app.py, scan it, and return the findings."""
    tmp = tempfile.mkdtemp()
    with open(os.path.join(tmp, "app.py"), "w", encoding="utf-8") as handle:
        handle.write(source)
    for name, content in (extra_files or {}).items():
        with open(os.path.join(tmp, name), "w", encoding="utf-8") as handle:
            handle.write(content)
    return audit.scan_directory(tmp)


def categories(findings):
    return {finding.category for finding in findings}


class SecretTests(unittest.TestCase):
    def test_hardcoded_password_flagged(self):
        findings = scan_source('DB_PASSWORD = "hunter2-is-bad"\n')
        self.assertIn("hardcoded-secret", categories(findings))

    def test_private_key_flagged_as_critical(self):
        findings = scan_source('KEY = "-----BEGIN PRIVATE KEY-----"\n')
        secret = [f for f in findings if f.category == "hardcoded-secret"]
        self.assertTrue(any(f.severity == "critical" for f in secret))

    def test_secret_from_environment_not_flagged(self):
        source = 'import os\nSECRET_KEY = os.environ.get("APP_SECRET", "dev")\n'
        findings = scan_source(source)
        self.assertNotIn("hardcoded-secret", categories(findings))

    def test_placeholder_value_not_flagged(self):
        findings = scan_source('API_TOKEN = "changeme"\n')
        self.assertNotIn("hardcoded-secret", categories(findings))


class SqlTests(unittest.TestCase):
    def test_concatenated_query_flagged(self):
        source = (
            "def f(owner):\n"
            "    q = \"SELECT * FROM risks WHERE owner = '\" + owner + \"'\"\n"
            "    return db.execute(q)\n"
        )
        findings = scan_source(source)
        self.assertIn("sql-injection", categories(findings))

    def test_execute_concatenation_flagged(self):
        source = 'db.execute("DELETE FROM risks WHERE id = " + risk_id)\n'
        findings = scan_source(source)
        self.assertIn("sql-injection", categories(findings))

    def test_parameterized_query_not_flagged(self):
        source = (
            "def f(owner):\n"
            "    return db.execute(\"SELECT * FROM risks WHERE owner = ?\", (owner,))\n"
        )
        findings = scan_source(source)
        self.assertNotIn("sql-injection", categories(findings))


class DebugAndSettingsTests(unittest.TestCase):
    def test_debug_true_flagged(self):
        findings = scan_source("app.run(debug=True)\n")
        self.assertIn("debug-mode", categories(findings))

    def test_debug_false_not_flagged(self):
        findings = scan_source("app.run(debug=False)\n")
        self.assertNotIn("debug-mode", categories(findings))

    def test_cors_wildcard_header_flagged(self):
        source = 'resp.headers["Access-Control-Allow-Origin"] = "*"\n'
        findings = scan_source(source)
        self.assertIn("cors-wildcard", categories(findings))

    def test_specific_origin_not_flagged(self):
        source = 'resp.headers["Access-Control-Allow-Origin"] = "https://ok.example"\n'
        findings = scan_source(source)
        self.assertNotIn("cors-wildcard", categories(findings))

    def test_host_binding_flagged(self):
        findings = scan_source('app.run(host="0.0.0.0")\n')
        self.assertIn("network-binding", categories(findings))


class RouteAuthTests(unittest.TestCase):
    def test_route_without_auth_flagged_as_heuristic(self):
        source = (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/risks')\n"
            "def risks():\n"
            "    return 'all the risks'\n"
        )
        findings = scan_source(source)
        auth = [f for f in findings if f.category == "missing-authentication"]
        self.assertEqual(len(auth), 1)
        self.assertTrue(auth[0].heuristic)

    def test_route_with_login_decorator_not_flagged(self):
        source = (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/risks')\n"
            "@login_required\n"
            "def risks():\n"
            "    return 'all the risks'\n"
        )
        findings = scan_source(source)
        self.assertNotIn("missing-authentication", categories(findings))

    def test_login_route_not_flagged(self):
        source = (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/login')\n"
            "def login():\n"
            "    return 'login page'\n"
        )
        findings = scan_source(source)
        self.assertNotIn("missing-authentication", categories(findings))


class ProjectLevelTests(unittest.TestCase):
    def test_missing_logging_flagged(self):
        findings = scan_source("x = 1\n")
        self.assertIn("no-audit-logging", categories(findings))

    def test_logging_present_not_flagged(self):
        source = "import logging\nlogging.info('started')\n"
        findings = scan_source(source)
        self.assertNotIn("no-audit-logging", categories(findings))

    def test_unpinned_dependency_flagged(self):
        findings = scan_source(
            "x = 1\n", extra_files={"requirements.txt": "flask\n"}
        )
        self.assertIn("unpinned-dependency", categories(findings))

    def test_pinned_dependency_not_flagged(self):
        findings = scan_source(
            "x = 1\n", extra_files={"requirements.txt": "flask==3.0.3\n"}
        )
        self.assertNotIn("unpinned-dependency", categories(findings))


class SampleAppTests(unittest.TestCase):
    """The two sample apps are the proof the scanner works."""

    SAMPLES = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "samples"
    )

    def test_insecure_sample_lights_up(self):
        findings = audit.scan_directory(
            os.path.join(self.SAMPLES, "insecure-grc-register")
        )
        found = categories(findings)
        for expected in (
            "hardcoded-secret", "sql-injection", "debug-mode",
            "missing-authentication", "no-audit-logging",
            "unpinned-dependency", "cors-wildcard",
        ):
            self.assertIn(expected, found)

    def test_hardened_sample_is_clean(self):
        findings = audit.scan_directory(
            os.path.join(self.SAMPLES, "hardened-grc-register")
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
