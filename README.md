# ReportedIP Hive

[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2%2B-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![PHP 8.1+](https://img.shields.io/badge/PHP-8.1%2B-777BB4.svg)](https://www.php.net/)
[![WordPress 5.0+](https://img.shields.io/badge/WordPress-5.0%2B-21759B.svg)](https://wordpress.org/)
[![Tests](https://img.shields.io/badge/PHPUnit-288%20tests-brightgreen.svg)](https://github.com/reportedip/reportedip-hive/actions)
[![Made in Germany](https://img.shields.io/badge/Made%20in-Germany-black.svg)](https://reportedip.de)

> **Community-powered WordPress security: 12 attack sensors, 4 progressive 2FA methods, herd-immunity threat sharing. GDPR-first. Made in Germany.**

Every protected site becomes a sensor. When one site is attacked, every other site can refuse the same attacker — before the password is even checked. One drop-in replaces brute-force protection, full 2FA suite and threat intelligence; no upsell tiers, no "Pro" gate.

→ Product: <https://reportedip.de> · Releases: [GitHub](https://github.com/reportedip/reportedip-hive/releases) · Docs: <https://reportedip.de/docs>

---

## Why pick it

- **One plugin instead of three.** Brute-force protection + complete 2FA suite + opt-in community threat intelligence. Single drop-in, GPL-2.0, public on GitHub.
- **Progressive blocks that don't burn legitimate users.** First-time tripping gets a 5-minute timeout; repeat offenders climb 5 m → 15 m → 30 m → 24 h → 48 h → 7 d. CGNAT visitors and fat-fingered admins recover in minutes; brute-forcers pay the full price.
- **Privacy-first by default.** GDPR-minimal logging, 30-day retention, anonymisation after 7 days, opt-in community sharing, all secrets encrypted at rest with libsodium. Lawful basis (Art. 6(1)(f) GDPR) documented in-product.
- **Cache-plugin-safe.** WP Rocket / W3TC / WP Super Cache / LiteSpeed cannot store the 403 page or serve cached HTML to blocked IPs on protected paths.
- **Code you can read.** PHPStan-clean, WPCS-clean, 288 unit tests with 439 assertions on every commit. No bundled minified bytes you can't audit.

## Feature overview

### 12 detection sensors (every one tunable)

| Sensor | Default threshold | Notes |
|---|---|---|
| Failed logins | 5 / 15 min | + 30-day rolling history |
| Password spray | 5 distinct usernames / 10 min | Hash-based for privacy |
| Comment spam | 5 / 60 min | |
| XMLRPC abuse | 10 / 60 min | `system.multicall` watched separately |
| App-password abuse | 5 / 15 min | REST/XMLRPC Basic-Auth bypass for 2FA |
| REST API rate-limit | 240 / 5 min global, 20 / 5 min on sensitive routes | Logged-in users skipped |
| User-enumeration defence | first probe blocks | `?author=`, `/wp-json/wp/v2/users`, oEmbed, login-error masking |
| 404 / scanner | 12 / 2 min, plus instant block on known-bad paths | `.env`, `wp-config.bak`, `/.git/` |
| Geographic anomaly | first occurrence triggers fresh 2FA | Optionally revokes trusted-device cookies |
| Password policy | min length, character classes, optional HIBP k-anonymity | |
| WooCommerce login | checkout + my-account forms tracked separately | |
| Cookie-banner consent endpoints | always-bypassed | Real Cookie Banner, Complianz, Borlabs, CookieYes baked in |

### Two-Factor Authentication — full suite, all included

- **TOTP** (RFC 6238) — Google Authenticator, Authy, 1Password, Microsoft Authenticator. Secrets encrypted at rest.
- **Passkey / WebAuthn / FIDO2** — Face ID, Touch ID, Windows Hello, YubiKey. In-house implementation, phishing-resistant, no Composer dependency.
- **Email OTP** — 6-digit, 10 min validity, rate-limited (3 sends / 15 min).
- **SMS OTP** — EU-only providers (Sipgate, MessageBird, seven.io) with explicit DPA confirmation.

Plus 10 single-use recovery codes, trusted-device tokens (default 30 days), multi-stage 2FA rate-limit (3/5/10/15 fails → 30 s/5 m/30 m/1 h delays, 15th fail graduates to a real progressive block), role-based enforcement with grace period, frontend onboarding wizard, branded login page option, IP allowlist for 2FA bypass.

### Progressive block escalation

Default ladder: **5 min → 15 min → 30 min → 24 h → 48 h → 7 d** (cap). After 30 days clean, the IP starts again at step 1. Fully editable as a comma-separated minute list under *Settings → Blocking*. Manual blocks (admin / CSV import) honour the chosen duration and never get overridden by the ladder.

### Cache compatibility

The 403 "Access Denied" response defines `DONOTCACHEPAGE`, `DONOTCACHEDB`, `DONOTCACHEOBJECT`, calls `nocache_headers()` and emits `Cache-Control: no-store, no-cache, must-revalidate` plus `Pragma: no-cache`. Cache plugins refuse to store the response. Authentication paths (`wp-login.php`, `wp-admin/`, `wp-json/`, XMLRPC) are excluded from caching by every reputable cache plugin out of the box, so blocks always fire on the paths attackers target.

Documented limitation: a blocked attacker visiting a *publicly cached* GET URL still gets the cached HTML. Their write attempts are blocked normally. For deny-on-cached-public-page, install a server-level firewall (Cloudflare WAF, Nginx `deny`, fail2ban).

### Two operating modes — pick what fits

| | Local Shield | Community Network |
|---|---|---|
| Account required | No | Free account at reportedip.de |
| External calls | None | Reputation lookups + anonymised reports |
| Pre-auth IP reputation check | – | ✓ |
| Coordinated-attack detection | – | ✓ |
| All 12 sensors | ✓ | ✓ |
| Full 2FA suite | ✓ | ✓ |
| Privacy | 100 % offline | Strictly opt-in, no usernames or comment content shared |

### Promote / community shortcodes

- **Auto-footer badge** with four position options (left / center / right / below content)
- **Shortcodes** — `[reportedip_badge]`, `[reportedip_stat type="..."]`, `[reportedip_banner]`, `[reportedip_shield]`
- **8 stat types** (`attacks_total`, `attacks_30d`, `reports_total`, `api_reports_30d`, `blocked_active`, `whitelist_active`, `logins_30d`, `spam_30d`) and **4 tone presets** (`protect`, `trust`, `community`, `contributor`)
- Web Component with Shadow DOM so themes cannot break the layout; `<a>` link stays in light DOM for SEO; UTM-tracked

### Admin UX

- **8-step setup wizard** (Welcome → Connect → Protection → 2FA → Privacy → Login → Promote → Done) with privacy-first defaults and a celebratory final step
- **Real-time dashboard** with 7- and 30-day Chart.js trend lines
- **Five list-table screens**: Blocked IPs, Whitelist, Security Logs, API Queue, plus the 2FA admin grid
- **CSV import** for blocked-IPs and whitelist; **CSV / JSON export** for logs and full settings backup
- **Trust badges** on every admin page

### Performance

- ETag-based reputation cache (24 h positive, 2 h negative)
- Per-request IP cache and 5-minute object-cache layer
- Login-skip on REST monitor (Block Editor never trips the rate-limit)
- Notification cooldown (1 h per IP+event), report cooldown (24 h per IP+category)

### Developer surface

- **REST API** namespace `reportedip-hive/v1` with `/2fa/challenge`, `/2fa/verify`, `/2fa/methods` for headless flows
- **WP-CLI** tree `wp reportedip 2fa` for user 2FA administration
- **PHP filters** — `reportedip_hive_rest_bypass_routes`, `reportedip_hive_rest_sensitive_routes`, `reportedip_hive_event_category_map`, `reportedip_2fa_sms_providers`, `reportedip_hive_mail_provider`, `reportedip_hive_mail_args`, `reportedip_hive_mail_template_path`
- **Constants** — `REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN` (emergency override from `wp-config.php`)
- **6 database tables** (auto-migrated, opt-in delete on uninstall)
- **Internationalisation-ready** (text domain `reportedip-hive`, English source + German translation included)

### What this plugin does NOT include

Honest scope so you can plan around it:

- No malware scanner / file-integrity monitor
- No web-application firewall (WAF) rules — IP-level blocking only
- No `advanced-cache.php` drop-in (server-level firewall is the right tool for cached-public-page denial)
- No Cloudflare API integration, no payment-fraud scoring

Pair it with a malware scanner if your stack needs that surface. Hive deliberately stays focused on identity, brute-force and threat intelligence.

---

## Installation

### Option 1: WP Admin (recommended)

1. Download the latest release ZIP: <https://github.com/reportedip/reportedip-hive/releases/latest>
2. WP Admin → *Plugins → Add New → Upload Plugin* → pick `reportedip-hive.zip`
3. Activate → run through the 8-step setup wizard

### Option 2: Composer (for developers)

```bash
composer require reportedip/reportedip-hive
```

### Updates

Updates ship directly from the publisher via [GitHub Releases](https://github.com/reportedip/reportedip-hive/releases) — not via wordpress.org.

How the update mechanism works:

1. We publish a Git tag `vX.Y.Z`.
2. GitHub Actions builds a production-ready ZIP and attaches it to the release.
3. The plugin ships [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker), which polls the GitHub API every 12 hours.
4. The update notice appears in WP Admin like for any other plugin — one click installs it.

For instant updates: WP Admin → *Plugins → Check for updates*.

---

## Requirements

- **PHP 8.1+**
- **WordPress 5.0–6.9** (tested up to 6.9)
- **MySQL 5.7+** or MariaDB equivalent
- **Optional:** WooCommerce (monitored if active, never required)
- **Optional:** SMS provider account (Sipgate / MessageBird / seven.io) for SMS 2FA

---

## Development

```bash
git clone https://github.com/reportedip/reportedip-hive.git
cd reportedip-hive
composer install
composer test           # PHPUnit unit suite (288 tests)
composer lint           # PHPCS against WordPress Coding Standards
composer analyse        # PHPStan level 5
composer check-all      # all three
```

### Testing & quality

| Command | Purpose |
|---|---|
| `composer test` | All PHPUnit suites |
| `composer test:unit` | Unit tests only (no WP bootstrap needed) |
| `composer test:integration` | Integration tests (requires the WP test suite) |
| `composer test:coverage` | HTML coverage in `coverage/` |
| `composer lint` / `lint:fix` | PHPCS WordPress standards |
| `composer analyse` | PHPStan level 5 |
| `composer make-pot` | Extract translatable strings |

### CI

GitHub Actions runs on every push and PR:

- PHP lint (`parallel-lint`)
- PHPCS (WordPress + PHPCompatibility)
- PHPStan level 5
- PHPUnit matrix against PHP 8.1, 8.2, 8.3, 8.4, 8.5
- WordPress integration tests
- Plugin Check (WP repo compliance)
- `composer audit` (security)

Workflow definitions: [`.github/workflows/`](./.github/workflows/).

### Release workflow

1. Bump version in three places (must match exactly):
   - `reportedip-hive.php` plugin header `Version:` (line 6)
   - `reportedip-hive.php` constant `REPORTEDIP_HIVE_VERSION` (line ~56)
   - `readme.txt` `Stable tag:` (line 8)
2. Add a `CHANGELOG.md` entry at the top.
3. Commit `chore(release): bump to X.Y.Z`.
4. `git tag -a vX.Y.Z -m "X.Y.Z"` then `git push origin main --follow-tags`.
5. `release.yml` builds the ZIP, validates the version markers against the tag, attaches it to the release, and pulls release notes from `CHANGELOG.md`.
6. Active installs pull the update within 12 hours; "Check for updates" pulls it immediately.

The tag name **must** start with `v` and match the plugin version (`v1.5.2` ↔ `Version: 1.5.2`). Otherwise PUC version matching fails.

---

## License & copyright

- **License:** [GPL-2.0-or-later](./LICENSE) — same as WordPress.
- **Copyright:** © 2025–2026 Patrick Schlesinger / ReportedIP.
- The code is GPL-licensed (distribution + modification permitted under GPL terms). The trademarks **ReportedIP**, **ReportedIP Hive**, and the logo are not covered by the GPL and remain the property of ReportedIP.
- Third-party software: [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker) (MIT), [Chart.js](https://www.chartjs.org/) (MIT). WebAuthn/FIDO2 is in-house, no external dependency.

---

## Contributing

Bug reports, feature requests, and pull requests are welcome.

- Issues: <https://github.com/reportedip/reportedip-hive/issues>
- Security disclosures (do **not** open a public issue): <ps@cms-admins.de>
- PRs target `main`; CI must be green.

**Language policy:** all code, comments, identifiers, commit messages, and user-facing strings are English.

---

## Support

- Website & documentation: <https://reportedip.de>
- Email: <ps@cms-admins.de>
- Status: see [GitHub Releases](https://github.com/reportedip/reportedip-hive/releases) for the current version and changelog
