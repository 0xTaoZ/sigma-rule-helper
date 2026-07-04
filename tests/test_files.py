from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sigma_rule_helper.files import iter_rule_files


class IterRuleFilesTests(unittest.TestCase):
    def test_finds_yaml_files_under_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "nested").mkdir()
            first = root / "a.yml"
            second = root / "nested" / "b.yaml"
            ignored = root / "notes.txt"
            first.write_text("title: a\n", encoding="utf-8")
            second.write_text("title: b\n", encoding="utf-8")
            ignored.write_text("not a rule\n", encoding="utf-8")

            self.assertEqual(iter_rule_files([str(root)]), [first, second])


if __name__ == "__main__":
    unittest.main()
