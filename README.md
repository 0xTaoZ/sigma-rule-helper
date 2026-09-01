# sigma-rule-helper

Small command line helper for reviewing Sigma detection rules in a lab or learning repo.

The first goal is practical and narrow: load one or more Sigma YAML files, report missing core fields, and print a compact summary that is easy to read during rule review.

This is not a replacement for the official Sigma tooling. It is a beginner-friendly project for learning how detection rules are structured and how simple validation tools are built.

## Planned workflow

```bash
sigma-rule-helper check rules/
sigma-rule-helper summary rules/
sigma-rule-helper summary --format json rules/
```

Try the sample rule set:

```bash
sigma-rule-helper check samples/
```

## What it checks

- required top-level fields such as `title`, `id`, `status`, `logsource`, `detection`, and `level`
- basic detection shape
- empty detection selectors
- selector bodies that are scalar values instead of mappings or lists
- condition references to missing selectors
- missing or empty `falsepositives` notes
- MITRE ATT&CK tags when present
- readable output for quick rule review

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
PYTHONPATH=src python -m unittest discover -s tests
```

## Project status

Early learning project. The CLI and checks are intentionally small so each behavior can be tested and understood.

## Current checks

The repository includes a small unittest suite and a GitHub Actions workflow that runs it on push and pull request events.

See `docs/rule-review-notes.md` for the small review checklist this tool is based on.
