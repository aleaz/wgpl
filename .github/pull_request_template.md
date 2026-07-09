## Summary

<!-- What does this PR change and why? -->

## Checklist

- [ ] `uv run ruff check src/ tests/` passes
- [ ] `uv run mypy src/ tests/` passes
- [ ] `uv run pytest` passes
- [ ] JSON/M2M output does not expose `private_key` or `preshared_key` (unless via `peer config`)
- [ ] Documentation and comments are in English
- [ ] No database files (`*.db`, `*.sqlite3`) or real keys included

## Test plan

<!-- How was this verified? -->
