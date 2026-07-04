from __future__ import annotations

import unittest
from pathlib import Path

from sigma_rule_helper.checks import check_rule
from sigma_rule_helper.loader import LoadedRule


class CheckRuleTests(unittest.TestCase):
    def test_valid_learning_rule_has_no_findings(self) -> None:
        rule = LoadedRule(
            path=Path("ok.yml"),
            data={
                "title": "Failed Logon",
                "id": "11111111-1111-4111-8111-111111111111",
                "status": "experimental",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
                "level": "medium",
            },
        )

        self.assertEqual(check_rule(rule), [])

    def test_incomplete_rule_reports_actionable_findings(self) -> None:
        rule = LoadedRule(
            path=Path("bad.yml"),
            data={
                "title": "Bad Rule",
                "status": "maybe",
                "logsource": [],
                "detection": {"condition": "selection"},
                "level": "noisy",
            },
        )

        codes = {finding.code for finding in check_rule(rule)}

        self.assertIn("missing-field", codes)
        self.assertIn("unknown-status", codes)
        self.assertIn("bad-logsource", codes)
        self.assertIn("no-selectors", codes)


if __name__ == "__main__":
    unittest.main()
