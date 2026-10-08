from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sigma_rule_helper.cli import main


class CliTests(unittest.TestCase):
    def test_wildcard_sample_warns_in_text_and_json(self) -> None:
        for output_format in ("text", "json"):
            with self.subTest(output_format=output_format):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    exit_code = main([
                        "check", "--format", output_format, "samples/wildcard_only.yml"
                    ])
                self.assertEqual(exit_code, 1)
                if output_format == "json":
                    findings = json.loads(output.getvalue())[0]["findings"]
                    self.assertEqual(len(findings), 1)
                    self.assertEqual(findings[0]["code"], "wildcard-only-value")
                    self.assertEqual(findings[0]["severity"], "warning")
                else:
                    self.assertIn("warning: wildcard-only-value", output.getvalue())
                    self.assertIn("selection, field Image", output.getvalue())

    def test_summary_json_output_is_machine_readable(self) -> None:
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            exit_code = main(["summary", "--format", "json", "samples/windows_failed_logon.yml"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["rules"][0]["title"], "Windows Failed Logon Spike")
        self.assertEqual(payload["rules"][0]["level"], "medium")
        self.assertEqual(payload["rules"][0]["attack_techniques"], ["attack.t1110"])

    def test_check_reports_duplicate_rule_ids_across_files(self) -> None:
        rule = """\
title: Duplicate ID example
id: 11111111-1111-4111-8111-111111111111
status: test
logsource:
  product: linux
detection:
  selection:
    event: login
  condition: selection
falsepositives:
  - Lab traffic
level: low
"""
        output = io.StringIO()

        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory, "first.yml")
            second = Path(directory, "second.yml")
            first.write_text(rule, encoding="utf-8")
            second.write_text(
                rule.replace("Duplicate ID example", "Second rule"), encoding="utf-8"
            )

            with contextlib.redirect_stdout(output):
                exit_code = main(["check", str(first), str(second)])

        self.assertEqual(exit_code, 1)
        self.assertEqual(output.getvalue().count("duplicate-rule-id"), 2)
        self.assertIn("first.yml", output.getvalue())
        self.assertIn("second.yml", output.getvalue())


if __name__ == "__main__":
    unittest.main()
