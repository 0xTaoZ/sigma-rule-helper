from __future__ import annotations

import unittest
from pathlib import Path

from sigma_rule_helper.loader import LoadedRule
from sigma_rule_helper.summary import rule_attack_techniques, rule_logsource, summarize_counts


class SummaryTests(unittest.TestCase):
    def test_logsource_joins_known_parts(self) -> None:
        rule = LoadedRule(
            path=Path("rule.yml"),
            data={"logsource": {"product": "windows", "service": "security"}},
        )

        self.assertEqual(rule_logsource(rule), "windows/security")

    def test_count_summary_includes_levels_and_statuses(self) -> None:
        rules = [
            LoadedRule(Path("a.yml"), {"level": "medium", "status": "experimental"}),
            LoadedRule(Path("b.yml"), {"level": "high", "status": "stable"}),
        ]

        lines = summarize_counts(rules)

        self.assertIn("rules: 2", lines)
        self.assertIn("levels: high=1, medium=1", lines)
        self.assertIn("statuses: experimental=1, stable=1", lines)

    def test_attack_techniques_are_normalized(self) -> None:
        rule = LoadedRule(
            path=Path("rule.yml"),
            data={"tags": ["attack.credential_access", "Attack.T1110"]},
        )

        self.assertEqual(rule_attack_techniques(rule), ["attack.t1110"])


if __name__ == "__main__":
    unittest.main()
