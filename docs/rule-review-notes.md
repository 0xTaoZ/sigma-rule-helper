# Rule review notes

This project uses a small checklist for reading Sigma rules. The checklist is intentionally basic, but it helps turn a YAML file into a structured review.

## First pass

Check that the rule has the core metadata:

- `title` explains the detection idea in plain language
- `id` is present, unique, and formatted as a valid UUID
- `status` is honest about maturity
- `date` and `modified` use the Sigma `YYYY/MM/DD` style
- `level` matches expected impact
- `logsource` points to the product, service, or category

## Detection pass

Read the `detection` section like a small query:

- selectors describe the fields and values being matched
- selectors should not be empty placeholders
- selector bodies should be mappings or lists, not single scalar values
- wildcard-only values should be reviewed for intentional broad matching
- `condition` ties selectors together
- each selector named in `condition` exists in the same `detection` block
- obvious false positives are documented
- `falsepositives` is present and not just an empty placeholder

## ATT&CK pass

ATT&CK tags are useful when they are specific. A tactic tag such as `attack.credential_access` is helpful, but a technique tag such as `attack.t1110` is more actionable during triage and reporting.

## Wildcard value review

The checker warns when a nonempty string contains only `*` and `?`. It inspects
field values, field-value lists, keyword lists, and lists of selector mappings.
The warning names the selector and field (`keyword` for keyword lists).

This is a review hint, not proof that a rule is invalid. An asterisk can be an
intentional broad match; question marks still constrain string length. Values
with literal text, escaped wildcards, or whitespace are left alone. Field
modifiers are limited to `contains`, `startswith`, `endswith`, `all`, and `cased`;
other modifiers, including regular expressions and encodings, are skipped.
The checker does not estimate the selectivity of the complete condition.
