# Rule review notes

This project uses a small checklist for reading Sigma rules. The checklist is intentionally basic, but it helps turn a YAML file into a structured review.

## First pass

Check that the rule has the core metadata:

- `title` explains the detection idea in plain language
- `id` is present and unique
- `status` is honest about maturity
- `level` matches expected impact
- `logsource` points to the product, service, or category

## Detection pass

Read the `detection` section like a small query:

- selectors describe the fields and values being matched
- `condition` ties selectors together
- obvious false positives are documented

## ATT&CK pass

ATT&CK tags are useful when they are specific. A tactic tag such as `attack.credential_access` is helpful, but a technique tag such as `attack.t1110` is more actionable during triage and reporting.

## Useful next checks

Future versions could check UUID format, date format, duplicate rule IDs, and whether the `condition` references selectors that actually exist.
