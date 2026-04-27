# ReportedIP Hive

[![License: GPL v2](https://img.shields.io/badge/License-GPLv2%2B-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![PHP](https://img.shields.io/badge/PHP-8.1%2B-777BB4.svg)](https://www.php.net/)
[![WordPress](https://img.shields.io/badge/WordPress-5.0%2B-21759B.svg)](https://wordpress.org/)

**Community-powered WordPress security — IP threat intelligence, brute-force protection, and a complete 2FA suite. Be part of the hive.**

Thousands of WordPress sites form a swarm. When one is attacked, every other one learns about it instantly. Local five-layer defense, four 2FA methods at the core (TOTP, email, SMS, WebAuthn/Passkeys), GDPR-compliant data flow, made in Germany.

→ Product website: <https://reportedip.de>

---

## Installation

### Option 1: WP Admin (recommended)

1. Download the latest release ZIP: <https://github.com/reportedip/reportedip-hive/releases/latest>
2. WP Admin → *Plugins → Add New → Upload Plugin* → pick `reportedip-hive.zip`
3. Activate → run through the 6-step setup wizard

### Option 2: Composer (for developers)

```bash
composer require reportedip/reportedip-hive
```

---

## Updates

**Updates ship directly from the publisher via GitHub Releases — not via wordpress.org.**

How the update mechanism works:

1. We publish a Git tag `vX.Y.Z` on <https://github.com/reportedip/reportedip-hive>.
2. GitHub Actions automatically builds a production-ready ZIP (`reportedip-hive.zip`) and attaches it as a release asset.
3. The plugin ships the [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker), which polls the GitHub API every 12 hours.
4. The update notice appears in WP Admin like for any other plugin — one click installs it.

For instant updates without waiting 12 hours: WP Admin → *Dashboard → Updates → "Check again"*.

---

## Development

The plugin code in this repo is developed inside a separate local dev environment (Docker + WordPress + Mailpit + phpMyAdmin). That environment lives **outside** this repo and is not public, because it contains project-specific local paths.

### Local setup without the dev environment

```bash
git clone https://github.com/reportedip/reportedip-hive.git
cd reportedip-hive
composer install
composer test           # PHPUnit unit suite
composer lint           # PHPCS against WordPress Coding Standards
composer analyse        # PHPStan level 5
composer check-all      # all three together
```

### With the dev environment (maintainer setup)

The plugin repo is cloned as a `dev/` subdirectory inside a local workspace that holds `docker-compose.yml`, `Dockerfile`, and helper scripts. Maintainer details live in the internal workspace documentation.

### Testing & quality

| Command | Purpose |
|---|---|
| `composer test` | All PHPUnit suites |
| `composer test:unit` | Unit tests only (no WP bootstrap needed) |
| `composer test:integration` | Integration tests (requires the WP test suite — install via `wp-cli` or your preferred WordPress test suite installer) |
| `composer test:coverage` | HTML coverage in `coverage/` |
| `composer lint` / `lint:fix` | PHPCS WordPress standards |
| `composer analyse` | PHPStan level 5 |
| `composer make-pot` | Extract translatable strings |

### CI

GitHub Actions runs on every push and PR:
- PHP lint (`parallel-lint`)
- PHPCS (WordPress + PHPCompatibility)
- PHPStan level 5
- PHPUnit matrix against PHP 8.1, 8.2, 8.3
- WordPress integration tests against WP 6.5, latest, trunk
- Plugin Check (WP repo compliance)
- `composer audit` (security)

Workflow definitions: [`.github/workflows/`](./.github/workflows/).

---

## Release workflow

A new version is released like this:

1. **Bump the version** in `reportedip-hive.php`:
   - Plugin header `Version:` (line 6)
   - Constant `REPORTEDIP_HIVE_VERSION` (around line 46)
   - Both must match.
2. **Update `readme.txt`** stable tag.
3. **Add a `CHANGELOG.md`** entry with the date and changes.
4. Commit + push to `main`.
5. **Tag and push:**
   ```bash
   git tag v1.2.3
   git push --tags
   ```
6. The GitHub Action `release.yml` runs automatically:
   - `composer install --no-dev --optimize-autoloader`
   - ZIP build (same filters as the local `run.sh build`)
   - GitHub Release is created with the ZIP attached
7. Active installs pull the update within 12 hours; "Check again" pulls it immediately.

**Important:** the tag name **must** start with `v` and match the plugin version (`v1.2.3` ↔ `Version: 1.2.3`). Otherwise PUC version matching fails.

---

## License & copyright

- **License:** [GPLv2 or later](./LICENSE) — same as WordPress itself.
- **Copyright:** © 2025–2026 Patrick Schlesinger / ReportedIP. All rights reserved.
- The code is GPL-licensed (distribution + modification permitted under GPL terms). The trademarks **ReportedIP**, **ReportedIP Hive**, and the logo are not covered by the GPL and remain the property of ReportedIP.
- Third-party software: Plugin Update Checker (MIT, [YahnisElsts](https://github.com/YahnisElsts/plugin-update-checker)).

---

## Contributing

Bug reports, feature requests, and pull requests are welcome.

- Issues: <https://github.com/reportedip/reportedip-hive/issues>
- For security-related disclosures, **do not** report publicly — email <ps@cms-admins.de>.
- PRs target `main`; CI must be green.

**Language policy:** all code, comments, identifiers, commit messages, and user-facing strings are English.

---

## Support

- Website & documentation: <https://reportedip.de>
- Email: <ps@cms-admins.de>
