from __future__ import annotations

import contextlib
import io
import json
import unittest

from sigma_rule_helper.cli import main


class CliTests(unittest.TestCase):
    def test_summary_json_output_is_machine_readable(self) -> None:
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            exit_code = main(["summary", "--format", "json", "samples/windows_failed_logon.yml"])

        self.assertEqual(exit_code, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["rules"][0]["title"], "Windows Failed Logon Spike")
        self.assertEqual(payload["rules"][0]["level"], "medium")
        self.assertEqual(payload["rules"][0]["attack_techniques"], ["attack.t1110"])


if __name__ == "__main__":
    unittest.main()
