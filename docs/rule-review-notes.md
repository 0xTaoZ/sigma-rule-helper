# Rule review notes

This project uses a small checklist for reading Sigma rules. The checklist is intentionally basic, but it helps turn a YAML file into a structured review.

## First pass

Check that the rule has the core metadata:

- `title` explains the detection idea in plain language
- `id` is present, unique, and formatted as a valid UUID
- `status` is honest about maturity
- `level` matches expected impact
- `logsource` points to the product, service, or category

## Detection pass

Read the `detection` section like a small query:

- selectors describe the fields and values being matched
- selectors should not be empty placeholders
- selector bodies should be mappings or lists, not single scalar values
- `condition` ties selectors together
- each selector named in `condition` exists in the same `detection` block
- obvious false positives are documented
- `falsepositives` is present and not just an empty placeholder

## ATT&CK pass

ATT&CK tags are useful when they are specific. A tactic tag such as `attack.credential_access` is helpful, but a technique tag such as `attack.t1110` is more actionable during triage and reporting.

## Useful next checks

Future versions could check date format, duplicate rule IDs, or suspiciously broad wildcard conditions.
