# ReportedIP Hive

[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2%2B-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![PHP 8.1+](https://img.shields.io/badge/PHP-8.1%2B-777BB4.svg)](https://www.php.net/)
[![WordPress 5.9+](https://img.shields.io/badge/WordPress-5.9%2B-21759B.svg)](https://wordpress.org/)
[![Multisite](https://img.shields.io/badge/Multisite-network--aware-21759B.svg)](#multisite-support)
[![Tests](https://img.shields.io/badge/PHPUnit-unit%20%2B%20Multisite-brightgreen.svg)](https://github.com/reportedip/reportedip-hive/actions)
[![Made in Germany](https://img.shields.io/badge/Made%20in-Germany-black.svg)](https://reportedip.de)

> **Community-powered WordPress security: 16 attack sensors, a two-layer firewall, 4 progressive 2FA methods, herd-immunity threat sharing, fully Multisite-aware. GDPR-first. Made in Germany.**

Every protected site becomes a sensor. When one site is attacked, every other site can refuse the same attacker before the password is even checked. One drop-in replaces brute-force protection, a web application firewall, a multi-method 2FA suite and threat intelligence. The entire detection and identity core is free and GPL-2.0; the paid Professional / Business plans add managed mail/SMS relays, multi-site management and a handful of advanced modules on top. They never gate the core protection.

→ Product: <https://reportedip.de> · Releases: [GitHub](https://github.com/reportedip/reportedip-hive/releases) · Docs: <https://reportedip.de/docs>

---

## Why pick it

- **One plugin instead of four.** Brute-force protection, a two-layer WAF, a multi-method 2FA suite and opt-in community threat intelligence. Single drop-in, GPL-2.0, public on GitHub. The full protection core is free; paid plans only add relays, multi-site and advanced modules (see [Free vs. paid](#free-vs-paid)).
- **Blocks enforced before WordPress even loads.** The optional pre-WordPress guard (`auto_prepend_file`) refuses blocked IPs and firewall matches before a single WordPress file is included. Fail-open by design: any error lets the request through to the normal in-WordPress engine.
- **Progressive blocks that don't burn legitimate users.** First-time tripping gets a 5-minute timeout; repeat offenders climb 5 m → 15 m → 30 m → 24 h → 48 h → 7 d, and loud bursts skip rungs (10x the threshold skips two). CGNAT visitors and fat-fingered admins recover in minutes; brute-forcers pay the full price. The server's own addresses are exempt from auto-blocking, so cache preloaders and WP-Cron loopbacks can never lock the site out of itself.
- **Privacy-first by default.** GDPR-minimal logging, 30-day retention, anonymisation after 7 days, opt-in community sharing, all secrets encrypted at rest with libsodium. Lawful basis (Art. 6(1)(f) GDPR) documented in-product.
- **Multisite-native.** Network-only activation, single threat decision applies network-wide, Site Admins get a read-only UI with two narrow override fields. Cross-site brute-force aggregates into one central counter, so an attacker pivoting between sub-sites trips the threshold faster, not slower.
- **Fast and measured.** Option reads primed in one query, an 8 KB header answers the blocklist lookup, dashboard analytics aggregate in SQL. Benchmarked against a 500k-row event table; the numbers live in the changelog, not in marketing copy.
- **Code you can read.** PHPStan level 5 clean, WPCS clean, 1100+ PHPUnit tests (unit + Multisite) plus Playwright end-to-end suites on both topologies. No bundled minified bytes you can't audit.

## Feature overview

### 16 detection sensors (every one tunable)

| Sensor | Default threshold | Notes |
|---|---|---|
| Failed logins | 5 / 15 min | + 30-day rolling history |
| Password spray | 5 distinct usernames / 10 min | Hash-based for privacy |
| Comment spam | 5 / 60 min | |
| XMLRPC abuse | 10 / 60 min | `system.multicall` watched separately |
| App-password abuse | 5 / 15 min | REST/XMLRPC Basic-Auth bypass for 2FA |
| REST API rate-limit | 240 / 5 min global, 20 / 5 min on sensitive routes | Logged-in users skipped |
| User-enumeration defence | 5 / 5 min | `?author=`, `/wp-json/wp/v2/users`, oEmbed, login-error masking; author archives can stay public |
| 404 / scanner | 12 / 2 min, plus instant block on known-bad paths | `.env`, `wp-config.bak`, `/.git/` |
| Geographic anomaly | first occurrence triggers fresh 2FA | Optionally revokes trusted-device cookies |
| Password policy | min length, character classes, optional HIBP k-anonymity | |
| WooCommerce login | checkout + my-account forms tracked separately | Optional themed frontend 2FA on Professional plan |
| Cookie-banner consent endpoints | always bypassed | Real Cookie Banner, Complianz, Borlabs, CookieYes baked in |
| Web Application Firewall | Paranoia Level 1 baseline + backend exceptions | See [Two-layer firewall](#two-layer-firewall) |
| Verified bot detection | flag (default) or block | Official Google/Bing IP ranges first, FCrDNS fallback; genuine crawlers never blocked |
| Disposable-email blocking | monitor (default) | Registration (WP + WooCommerce); privacy relays pass through by default |
| Comment honeypot | on | Invisible decoy field, no CAPTCHA friction |

<a id="two-layer-firewall"></a>

### Two-layer firewall

Hive inspects requests in two places that stay behaviourally identical:

- **In-WordPress engine.** Runs on `init` priority 1 with SQLi/XSS/traversal/LFI/scanner rule patterns, a per-rule exception table (rule / group / path scope, one-click "Allow" from the log), report-only mode for audits and ReDoS-hardened matching. Paranoia Level 1 ships free and works offline; the deeper, Ed25519-signed PL 2/3 rulesets sync with a Professional plan.
- **Pre-WordPress guard ("Extended protection").** An optional `auto_prepend_file` drop-in generated from the exact same rules, exceptions and whitelist. It refuses blocked IPs and rule matches before WordPress loads, answers blocklist lookups from an 8 KB bitmap header instead of reading the whole file, aggregates its hits per (IP, rule) and feeds them back into the escalation ladder. The Firewall page's Server Setup tab produces the right directive for your stack (php.ini, `.user.ini`, hosting panel or nginx) and verifies live that the guard actually runs.

Both layers are fail-open: a broken rule, an unreadable file or an unwritable directory lets the request through rather than taking the site down. IP blocks are enforced even with the WAF disabled, because they come from the escalation ladder, not from rule inspection.

### Two-Factor Authentication (four methods)

Three methods work in **every plan**, including Free and the fully-offline Local Shield; SMS is the one method that rides the managed relay and therefore needs a Professional plan.

- **TOTP** (RFC 6238). Google Authenticator, Authy, 1Password, Microsoft Authenticator. Secrets encrypted at rest. *Free.*
- **Passkey / WebAuthn / FIDO2.** Face ID, Touch ID, Windows Hello and hardware security keys (YubiKey 5 series and other FIDO2 keys, USB-C or NFC phone tap). Ed25519 support, clone detection through signature counters, named key manager. In-house implementation, phishing-resistant, no Composer dependency. *One key per account free.*
- **Advanced Security Keys (Business plan).** Multiple keys per account (primary + backup), automatic model detection via attestation ("YubiKey 5 Series with NFC" shown in the key manager) and key-lifecycle email alerts.
- **Email OTP.** 6-digit, 10 min validity, rate-limited (3 sends / 15 min). *Free.*
- **SMS OTP (Professional plan).** Delivered through the managed reportedip.de relay, included with Professional and Business. No own SMS account or carrier contract required; phone numbers encrypted at rest. Free / Contributor sites use TOTP, Passkey or Email instead.

**Self-service on the profile page.** Every user manages their own 2FA from plain-language method cards: add or remove methods at any time, pick the default method the login challenge opens with, change the SMS number (the verified number is only replaced after the new one confirms a code), re-set-up the authenticator app, and manage security keys, recovery codes and trusted devices. The profile, the guided onboarding wizard and WP-CLI all share one activation path, so an added method never silently overwrites the chosen default or destroys existing recovery codes.

Also included in every plan: 10 single-use recovery codes, trusted-device tokens (default 30 days), a multi-stage 2FA rate-limit (3/5/10/15 fails → 30 s/5 m/30 m/1 h delays; the 15th IP-level fail graduates to a real progressive block), role-based enforcement with grace period, a branded login page option, an IP allowlist for 2FA bypass, and the **password-reset gate**: the "lost password" flow demands a second factor before a new password is accepted, with email excluded by design so a stolen mailbox cannot bypass 2FA.

**WooCommerce frontend 2FA (Professional plan and higher).** Customers signing in through `[woocommerce_my_account]`, the classic checkout, or the WooCommerce Cart / Checkout blocks see the second factor inside the active storefront theme instead of bouncing to wp-login.php. Customer / Subscriber roles get a themed onboarding wizard on a dedicated slug. Cart and checkout state survive the redirect roundtrip; the trusted-device cookie is shared with the wp-login flow. A tier downgrade soft-disables the module; existing customer secrets stay valid.

### Progressive block escalation

Default ladder: **5 min → 15 min → 30 min → 24 h → 48 h → 7 d** (cap). After 30 days clean, the IP starts again at step 1. Loud bursts are weighted: five times the threshold behind one block skips a rung, ten times skips two, twenty-five times skips three. Fully editable as a comma-separated minute list under *Settings → Blocking*. Manual blocks (admin / CSV import) honour the chosen duration and never get overridden by the ladder. The server's own addresses (loopback, interface address, everything the site hostname resolves to) are exempt from automatic blocking, extensible via the `reportedip_hive_own_server_ips` filter for multi-node setups.

### Cache compatibility

The 403 "Access Denied" response defines `DONOTCACHEPAGE`, `DONOTCACHEDB`, `DONOTCACHEOBJECT`, calls `nocache_headers()` and emits `Cache-Control: no-store, no-cache, must-revalidate` plus `Pragma: no-cache`. Cache plugins refuse to store the response. Authentication paths (`wp-login.php`, `wp-admin/`, `wp-json/`, XMLRPC) are excluded from caching by every reputable cache plugin out of the box, so blocks always fire on the paths attackers target.

Documented limitation: a blocked attacker visiting a *publicly cached* GET URL still gets the cached HTML unless the pre-WordPress guard is installed, which refuses the request before any cache plugin runs. Their write attempts are blocked normally either way.

### Two operating modes

The two **modes** decide whether the plugin talks to reportedip.de at all. They are independent of the **plan** (Free → Enterprise), which decides the relay quotas and the advanced modules. A Free site can run either mode; SMS 2FA and Hardening Mode additionally need a Professional plan because they ride the managed relay / coordinated-attack infrastructure.

| | Local Shield | Community Network |
|---|---|---|
| Account required | No | Free account at reportedip.de |
| External calls | None | Reputation lookups + anonymised reports |
| All 16 detection sensors + two-layer firewall | ✓ | ✓ |
| Core 2FA (TOTP, Passkey, Email, Recovery) | ✓ | ✓ |
| Progressive block escalation + password-reset gate | ✓ | ✓ |
| Pre-auth IP reputation check | – | ✓ |
| Reputation hits persist as local 24 h blocks | – | ✓ |
| Coordinated-attack detection | – | ✓ |
| SMS 2FA (managed relay) | – | Professional+ |
| Hardening Mode (auto-tighten thresholds on attack) | – | Professional+ |
| Privacy | 100 % offline | Strictly opt-in, no usernames or comment content shared |

<a id="free-vs-paid"></a>

### Free vs. paid

The plugin itself is **free, GPL-2.0 and fully functional** in both modes. Everything that detects an attack, blocks an IP, logs an event or verifies a second factor with TOTP / Passkey / Email / Recovery codes works on every plan, including the 100 %-offline Local Shield. No account, nothing held back.

What the paid **Professional** (3 domains) and **Business** (15 domains, multi-bookable) plans add on top:

- **Managed mail relay.** 2FA mails through clean SPF/DKIM/DMARC infrastructure, auto-fallback to `wp_mail()` on cap.
- **Managed SMS relay.** SMS OTP without your own carrier/Twilio contract.
- **WooCommerce frontend 2FA.** The second factor rendered inside the storefront theme on My Account / checkout / WC blocks.
- **Hardening Mode.** Automatically tighten failed-login and reputation thresholds network-wide for one hour when a coordinated attack is detected; also drivable via `wp reportedip hardening`.
- **Advanced security headers.** HSTS, Permissions-Policy, the CSP builder (report-only first) and the cross-origin isolation trio; the basic header trio stays free.
- **Priority Sync.** The deeper, Ed25519-signed WAF Paranoia-Level-2/3 rulesets plus the live bot-IP-range and disposable-domain feeds; the bundled baselines stay free and work offline.
- **Advanced Security Keys (Business).** Multiple WebAuthn keys per account, attestation-based model detection, key-lifecycle mails.
- **Audit event trail (Business).** Append-only user-lifecycle log (logins, password resets, profile updates, role changes including the acting user, new-IP alerts) with filters and CSV/JSON export.
- Higher API quotas, multi-site dashboard, priority blacklist sync, longer log retention, prepaid mail/SMS top-up bundles. Business adds white-label, the full WP-CLI surface, role-based login-time restrictions and a GDPR export tool.

Pricing and the full tier matrix live at <https://reportedip.de>.

### Remote management (MainWP)

Hive carries its own MainWP child bridge, so agencies can manage every Hive install from one [MainWP](https://mainwp.com/) dashboard without an extra child plugin: fleet-wide status sync (active blocks, failed logins, queue size, 2FA coverage as aggregate counts) and one-click API-key provisioning. Data-minimised by design: the sync returns counts only, never IP addresses, usernames or secrets. Requires the ReportedIP Hive extension on the MainWP dashboard side.

### Promote / community shortcodes

- **Auto-footer badge** with four position options (left / center / right / below content)
- **Shortcodes**: `[reportedip_badge]`, `[reportedip_stat type="..."]`, `[reportedip_banner]`, `[reportedip_shield]`
- **8 stat types** (`attacks_total`, `attacks_30d`, `reports_total`, `api_reports_30d`, `blocked_active`, `whitelist_active`, `logins_30d`, `spam_30d`) and **4 tone presets** (`protect`, `trust`, `community`, `contributor`)
- Web Component with Shadow DOM so themes cannot break the layout; `<a>` link stays in light DOM for SEO; UTM-tracked

### Admin UX

- **10-step setup wizard** (Welcome → Connect → Protection → Firewall → 2FA → Privacy → Notifications → Login → Promote → Done) with privacy-first defaults
- **Real-time dashboard** with detection & hardening score gauges (0–100, A+–F grade, per-item deep links) and 7- and 30-day Chart.js trend lines
- **Firewall area** with an overview mini-dashboard (per-module status, 7-day activity, recent firewall events), per-module tabs that each open with a plain-language intro, and a **Server Setup tab** that gathers every web-server snippet in one place: the WAF `auto_prepend_file` directive with live verification, the decoy rewrite rules and a server-level export of the configured security headers
- **Six list-table screens**: Blocked IPs, Whitelist, Security Logs, API Queue, the audit event trail (Business), plus the 2FA admin grid
- **CSV import** for blocked-IPs and whitelist; **CSV / JSON export** for logs and full settings backup
- Trust badges and a secured-by note on every admin page

### Performance

- All small plugin options primed into the request cache with a single query (36 → 11 plugin queries per anonymous request)
- Pre-WordPress blocklist answered from an 8 KB bitmap header instead of a full file read
- Request bodies read only when a body rule is active and a body exists
- Dashboard analytics cached and aggregated in SQL (TTFB 920 ms → 278 ms on a 500k-row event table)
- Retention cleanup in bounded chunks under a time budget; ETag-based reputation cache (24 h positive, 2 h negative); notification and report cooldowns

### Developer surface

- **REST API** namespace `reportedip-hive/v1` with `/2fa/challenge`, `/2fa/verify`, `/2fa/methods` for headless flows
- **WP-CLI** trees `wp reportedip 2fa` (status, enable, disable, reset, enforce, audit, cleanup) and `wp reportedip hardening`
- **PHP filters**: `reportedip_hive_rest_bypass_routes`, `reportedip_hive_rest_sensitive_routes`, `reportedip_hive_event_category_map`, `reportedip_hive_mail_provider`, `reportedip_hive_mail_args`, `reportedip_hive_mail_template_path`, `reportedip_hive_decoy_paths`, `reportedip_hive_bot_allowlist_patterns`, `reportedip_hive_own_server_ips`, `reportedip_hive_webauthn_rp_id`, `reportedip_hive_webauthn_allowed_origins`
- **Constants**: `REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN` (emergency override from `wp-config.php`)
- **9 database tables** (auto-migrated, opt-in delete on uninstall)
- **Internationalisation-ready** (text domain `reportedip-hive`, English source + complete German translation included)

### What this plugin does NOT include

Honest scope so you can plan around it:

- No malware scanner / file-integrity monitor
- No Cloudflare API integration, no payment-fraud scoring

Pair it with a malware scanner if your stack needs that surface. Hive deliberately stays focused on identity, brute-force, firewalling and threat intelligence.

---

## Installation

### Option 1: WP Admin (recommended)

1. Download the production ZIP. **Always pick `reportedip-hive.zip`**:
   - Direct link (always latest): <https://github.com/reportedip/reportedip-hive/releases/latest/download/reportedip-hive.zip>
   - Or open the [latest release page](https://github.com/reportedip/reportedip-hive/releases/latest) and grab `reportedip-hive.zip` from the *Assets* section.
2. WP Admin → *Plugins → Add New → Upload Plugin* → pick `reportedip-hive.zip`.
3. Activate → run through the 10-step setup wizard.

> **Do not use the auto-generated "Source code (zip)" link** or the *Code → Download ZIP* button on the repository page. Those archives have a top-level folder named `reportedip-hive-X.Y.Z` (with the version) instead of `reportedip-hive/`. WordPress installs the plugin under that versioned slug, which breaks in-place updates and creates a duplicate plugin folder on every release. Only the asset `reportedip-hive.zip` is built for installation.

### Option 2: Composer (for developers)

```bash
composer require reportedip/reportedip-hive
```

### Updates

Updates ship directly from the publisher via [GitHub Releases](https://github.com/reportedip/reportedip-hive/releases), not via wordpress.org.

How the update mechanism works:

1. We publish a Git tag `vX.Y.Z`.
2. GitHub Actions builds a production-ready ZIP and attaches it to the release.
3. The plugin ships [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker), which polls the GitHub API every 12 hours.
4. The update notice appears in WP Admin like for any other plugin; one click installs it.

For instant updates: WP Admin → *Plugins → Check for updates*.

---

## Requirements

- **PHP 8.1+**
- **WordPress 5.9–7.0** (tested up to 7.0)
- **MySQL 5.7+** or MariaDB equivalent
- **Optional:** WooCommerce (monitored if active, never required)
- **Optional:** Professional plan (or higher) for SMS 2FA, Hardening Mode and the deeper WAF rulesets

---

## Multisite support

Hive 2.0+ is fully network-aware. The plugin header sets `Network: true`, so on Multisite the only activation path is **Network Activate**; per-site activation is hidden by WordPress.

| Topic | Behaviour |
|---|---|
| Activation | Network-only (`Network: true` in plugin header). Single-site installs auto-migrate transparently. |
| Tables | All nine plugin tables live under `$wpdb->base_prefix`. `logs`, `api_queue`, `stats` and `audit_log` carry a `blog_id` column so the Network Admin can filter and Site Admins are auto-scoped. |
| Cross-site brute-force | Failed logins on Site A and Site B aggregate into the same central `attempts` row, so a streamed attack across sub-sites trips the threshold *faster*, and one `blocked` entry locks the IP out of every sub-site. |
| Site Admin UI | Read-only Status / Logs (auto-scoped via `blog_id`) plus a 2FA Site Settings page with exactly two writable overrides: per-site Frontend-2FA slug and additive 2FA enforcement roles. Site Admins cannot drop a role the Network requires. |
| Super Admins | Forced into 2FA setup unconditionally via `reportedip_hive_2fa_enforce_super_admins` (default on). |
| Trust cookie | Set with `SITECOOKIEPATH` so a single trust decision carries across the whole network. |
| REST throttle | Counters use `set_site_transient` so an attacker hitting multiple sub-sites cannot reset by switching host. |
| Cron | Scheduled only on `is_main_site()` with an `admin_init` self-heal; avoids N-fold execution on large networks. |

The codebase ships a dedicated PHPUnit-Multisite suite (`tests/Multisite/`, `phpunit-multisite.xml` with `WP_TESTS_MULTISITE=1`) plus Playwright projects for both topologies, gated by separate CI matrix jobs (`phpunit-multisite`, `e2e-multisite`).

---

## Development

```bash
git clone https://github.com/reportedip/reportedip-hive.git
cd reportedip-hive
composer install
composer test           # PHPUnit unit suite
composer lint           # PHPCS against WordPress Coding Standards
composer analyse        # PHPStan level 5
composer i18n           # refresh POT/PO and compile MO/JSON
composer check-all      # lint + analyse + i18n gate + tests
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
| `composer i18n:check` | Fail if POT is stale, German PO incomplete, or MO/JSON out of sync |

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
   - `reportedip-hive.php` plugin header `Version:`
   - `reportedip-hive.php` constant `REPORTEDIP_HIVE_VERSION`
   - `readme.txt` `Stable tag:`
2. Add a `CHANGELOG.md` entry at the top.
3. Commit `chore(release): bump to X.Y.Z`.
4. `git tag -a vX.Y.Z -m "X.Y.Z"` then `git push origin main --follow-tags`.
5. `release.yml` builds the ZIP, validates the version markers against the tag, attaches it to the release, and pulls release notes from `CHANGELOG.md`.
6. Active installs pull the update within 12 hours; "Check for updates" pulls it immediately.

The tag name **must** start with `v` and match the plugin version (`v2.1.32` ↔ `Version: 2.1.32`). Otherwise PUC version matching fails.

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
- Security disclosures (do **not** open a public issue): <abuse@reportedip.de>
- PRs target `main`; CI must be green.

**Language policy:** all code, comments, identifiers, commit messages, and user-facing strings are English.

---

## Support

- Website & documentation: <https://reportedip.de>
- Email: <1@reportedip.de>
- Status: see [GitHub Releases](https://github.com/reportedip/reportedip-hive/releases) for the current version and changelog
