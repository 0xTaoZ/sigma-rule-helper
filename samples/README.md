# Sample rules

These rules are small teaching examples for the CLI.

- `windows_failed_logon.yml` is a valid-looking learning rule.
- `broken_rule.yml` is intentionally incomplete, including missing false-positive notes and malformed selectors, so the checker has something to report.
- `wildcard_only.yml` has an intentionally broad image match and produces one `wildcard-only-value` warning. Run `sigma-rule-helper check samples/wildcard_only.yml` to review it; warnings return exit status 1.
