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
                "falsepositives": ["mistyped passwords"],
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

    def test_missing_falsepositives_reports_finding(self) -> None:
        rule = LoadedRule(
            path=Path("missing_falsepositives.yml"),
            data={
                "title": "Missing False Positives",
                "id": "66666666-6666-4666-8666-666666666666",
                "status": "test",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
                "level": "medium",
            },
        )

        findings = check_rule(rule)

        self.assertIn("missing-falsepositives", {finding.code for finding in findings})

    def test_empty_falsepositives_reports_finding(self) -> None:
        rule = LoadedRule(
            path=Path("empty_falsepositives.yml"),
            data={
                "title": "Empty False Positives",
                "id": "77777777-7777-4777-8777-777777777777",
                "status": "test",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
                "falsepositives": [],
                "level": "medium",
            },
        )

        findings = check_rule(rule)

        self.assertIn("missing-falsepositives", {finding.code for finding in findings})

    def test_invalid_id_format_reports_finding(self) -> None:
        rule = LoadedRule(
            path=Path("bad_id.yml"),
            data={
                "title": "Bad ID",
                "id": "not-a-uuid",
                "status": "stable",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
                "level": "medium",
            },
        )

        codes = {finding.code for finding in check_rule(rule)}

        self.assertIn("invalid-id-format", codes)

    def test_invalid_date_format_reports_finding(self) -> None:
        rule = LoadedRule(
            path=Path("bad_date.yml"),
            data={
                "title": "Bad Date",
                "id": "99999999-9999-4999-8999-999999999999",
                "status": "stable",
                "date": "2026-09-17",
                "modified": "2026/13/17",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {"selection": {"EventID": 4625}, "condition": "selection"},
                "falsepositives": ["lab testing"],
                "level": "medium",
            },
        )

        findings = check_rule(rule)

        self.assertEqual(
            ["invalid-date-format", "invalid-date-format"],
            [finding.code for finding in findings],
        )
        self.assertEqual(
            {"date should use YYYY/MM/DD format", "modified should use YYYY/MM/DD format"},
            {finding.message for finding in findings},
        )

    def test_condition_references_missing_selector(self) -> None:
        rule = LoadedRule(
            path=Path("missing_selector.yml"),
            data={
                "title": "Missing Selector",
                "id": "22222222-2222-4222-8222-222222222222",
                "status": "test",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {
                    "selection": {"EventID": 4625},
                    "condition": "selection and filter",
                },
                "level": "medium",
            },
        )

        findings = check_rule(rule)

        self.assertIn(
            "missing-condition-selector",
            {finding.code for finding in findings},
        )
        self.assertIn(
            "filter",
            {finding.message.rsplit(": ", maxsplit=1)[-1] for finding in findings},
        )

    def test_condition_wildcard_prefix_matches_selectors(self) -> None:
        rule = LoadedRule(
            path=Path("wildcard.yml"),
            data={
                "title": "Wildcard Condition",
                "id": "33333333-3333-4333-8333-333333333333",
                "status": "test",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {
                    "selection_process": {"Image|endswith": "\\cmd.exe"},
                    "selection_parent": {"ParentImage|endswith": "\\powershell.exe"},
                    "condition": "1 of selection_*",
                },
                "level": "medium",
            },
        )

        codes = {finding.code for finding in check_rule(rule)}

        self.assertNotIn("missing-condition-selector", codes)

    def test_broad_them_condition_reports_finding(self) -> None:
        rule = LoadedRule(
            path=Path("broad_condition.yml"),
            data={
                "title": "Broad Condition",
                "id": "88888888-8888-4888-8888-888888888888",
                "status": "test",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {
                    "selection_process": {"Image|endswith": "\\cmd.exe"},
                    "filter_admin": {"User": "admin"},
                    "condition": "1 of them",
                },
                "level": "medium",
            },
        )

        codes = {finding.code for finding in check_rule(rule)}

        self.assertIn("broad-condition", codes)

    def test_empty_selector_reports_finding(self) -> None:
        rule = LoadedRule(
            path=Path("empty_selector.yml"),
            data={
                "title": "Empty Selector",
                "id": "44444444-4444-4444-8444-444444444444",
                "status": "test",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {
                    "selection": {},
                    "condition": "selection",
                },
                "level": "medium",
            },
        )

        findings = check_rule(rule)

        self.assertIn("empty-selector", {finding.code for finding in findings})
        self.assertIn(
            "selection",
            {finding.message.rsplit(": ", maxsplit=1)[-1] for finding in findings},
        )

    def test_selector_with_scalar_body_reports_finding(self) -> None:
        rule = LoadedRule(
            path=Path("scalar_selector.yml"),
            data={
                "title": "Scalar Selector",
                "id": "55555555-5555-4555-8555-555555555555",
                "status": "test",
                "logsource": {"product": "windows", "service": "security"},
                "detection": {
                    "selection": 4625,
                    "condition": "selection",
                },
                "level": "medium",
            },
        )

        findings = check_rule(rule)

        self.assertIn("bad-selector", {finding.code for finding in findings})
        self.assertIn(
            "selection",
            {finding.message.rsplit(": ", maxsplit=1)[-1] for finding in findings},
        )


if __name__ == "__main__":
    unittest.main()
