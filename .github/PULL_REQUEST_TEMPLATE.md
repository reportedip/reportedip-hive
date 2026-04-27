<!--
Thanks for your PR! Please fill in the items below where they apply.
-->

## What does this PR change?

<!-- Short description. Bug fix? Feature? Refactor? -->

## Why?

<!-- What problem does this solve? Which bug, which use case? -->

## How was it tested?

- [ ] `composer test` (unit) green locally
- [ ] `composer lint` green locally
- [ ] `composer analyse` green locally (or baseline entry justified)
- [ ] Manually tested in the Docker stack
- [ ] New tests added (for new code)

## Checklist

- [ ] Code follows WordPress Coding Standards (`composer lint:fix` passes)
- [ ] Translatable strings use `__()`/`esc_html__()` with text domain `reportedip-hive`
- [ ] Inputs are sanitized, outputs escaped, nonces in place
- [ ] No hardcoded colors — design system tokens (`--rip-*`) only
- [ ] CHANGELOG.md updated (if user-visible)
- [ ] Documentation/help text updated (for UI changes)

## Linked issues

<!-- Closes #123 / Refs #456 -->
