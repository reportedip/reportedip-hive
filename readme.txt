=== ReportedIP Hive ===
Contributors: reportedip, patrickschlesinger
Donate link: https://reportedip.de
Tags: security, firewall, brute-force, two-factor, threat-intelligence
Requires at least: 5.0
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.5.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Update URI: https://github.com/reportedip/reportedip-hive

Community-powered WordPress security — IP threat intelligence, brute-force protection and a complete 2FA suite. Be part of the hive.

== Description ==

**Thousands of WordPress sites form a hive. When one gets attacked, all others learn instantly.**

**ReportedIP Hive** turns every protected site into a sensor. When a malicious IP attacks your site, the hive learns about it — and every other site can refuse that attacker before the first request lands. This is herd immunity for WordPress.

Built for privacy, engineered in Germany, and backed by the [ReportedIP.de](https://reportedip.de) threat-intelligence platform.

= Two ways to run =

**Local Shield (no account required)**

* Works completely offline — no data ever leaves your site
* Brute-force, comment-spam and XMLRPC protection
* Local IP blocklist and whitelist with CSV import
* Full 2FA suite with four methods (see below)
* Searchable, filterable, exportable security event logs

**Community Network (free account)**

* Real-time IP reputation lookups against the hive
* Anonymized threat reports shared back to protect everyone else
* Coordinated-attack detection across the network
* ETag-based response caching keeps API usage low
* Transparent quota and queue display in the dashboard

= How protection works =

* **Pre-authentication reputation check** — every login attempt is matched against the hive before the password is even verified (Community mode only)
* **Three independent thresholds** — failed logins, comment spam and XMLRPC requests are counted separately, each with its own time window and trigger value
* **Automatic blocks** — once a threshold is exceeded the IP is blocked locally, optionally with a configurable expiry; manual blocks and unblocks are always possible
* **Coordinated-attack detection** — a scheduled scan looks for multiple IPs hitting the same target in a short window and flags the campaign as a higher-severity event
* **Report-Only mode** — a true audit mode that logs every event without enforcing any block, ideal for tuning thresholds against live traffic before going active

= Two-Factor Authentication (4 methods, all included) =

* **TOTP** — RFC 6238 authenticator-app codes (Google Authenticator, Authy, 1Password, …); 6-digit, 30-second window, secret stored encrypted at rest
* **Email OTP** — 6-digit codes by email, rate-limited (max. 3 codes per 15 minutes), 5 verify attempts per code, 60-second resend cooldown
* **SMS** — via GDPR-compliant EU providers (Sipgate, MessageBird, seven.io); phone numbers and provider credentials encrypted at rest with libsodium (or OpenSSL fallback)
* **WebAuthn / FIDO2 / Passkeys** — Face ID, Touch ID, Windows Hello, YubiKey and other hardware security keys; in-house implementation, no external dependency

Plus:

* **10 single-use recovery codes** in `xxxx-xxxx` format, hashed at rest, with a low-codes warning at three remaining
* **Trusted devices** — opt-in cookie + DB-backed device tokens with configurable expiry, IP and device-name tracking, last-used timestamp
* **Multi-stage rate limiting** — 3/5/10/15 failed 2FA attempts trigger 30s/5min/30min/1h delays before further tries are accepted
* **Role-based enforcement** with optional grace period for new users
* **5-step onboarding wizard** that walks each user through method selection, setup, recovery codes and confirmation
* **New-device login notifications** by email, off by default, opt-in per site

= Admin dashboard =

* Real-time stats with 7 / 30-day trend charts (Chart.js)
* Five admin pages: Dashboard, Security, Settings, System Status, Community & Quota
* Security tabs: Logs, Blocked IPs, Whitelist, API Queue
* Settings tabs: Protection, 2FA, Privacy
* Six-step Setup Wizard with sensible privacy-first defaults
* CSV import for Blocked IPs and Whitelist; CSV / JSON export for Logs
* All four cron jobs are inspectable and manually triggerable from the dashboard

= Privacy & GDPR =

* **Made in Germany** — built with privacy as a design principle, not an afterthought
* **Minimal data collection** — no usernames, no comment content, no full user-agents in API reports; user-agents are truncated to 50 characters even locally
* **Configurable retention** — daily cleanup with default 30-day log retention, automatic anonymization of old entries
* **Opt-in sharing** — Local Shield works 100% offline; nothing leaves your site unless you switch to Community Network
* **GDPR documentation** — `GDPR-COMPLIANCE.md` and `GDPR-IMPROVEMENTS-SUMMARY.md` ship with the plugin

= For developers =

* WordPress Coding Standards compliant
* PHPStan Level 5 verified
* 170 PHPUnit tests, 181 assertions
* REST API namespace `reportedip-hive/v1` with three endpoints (`/2fa/challenge`, `/2fa/verify`, `/2fa/methods`) for headless 2FA flows
* WP-CLI command tree `wp reportedip 2fa` for user 2FA administration
* SMS-provider registry is pluggable — drop a new adapter into `includes/sms-providers/` to add a provider
* Internationalisation-ready: text domain `reportedip-hive`, English source with German translation included
* AES-256 encryption helper (libsodium with OpenSSL fallback) used for all secrets at rest

== Installation ==

= Manual =

1. Download the latest release ZIP from https://github.com/reportedip/reportedip-hive/releases/latest
2. Upload via *Plugins → Add New → Upload Plugin* and pick `reportedip-hive.zip`
3. Activate and follow the 6-step setup wizard

= Automatic Updates =

The plugin ships with a built-in update checker that polls the GitHub release feed every 12 hours. Updates appear in the standard *Plugins* list in your WordPress admin and install with a single click — exactly like a wordpress.org plugin, but served directly from the publisher.

ReportedIP Hive is **not** distributed through wordpress.org. All releases are signed and tagged on GitHub: https://github.com/reportedip/reportedip-hive/releases

= Configuration =

1. **Choose your mode** — *Local Shield* for standalone protection or *Community Network* for shared threat intelligence
2. **Community Network** — paste your free API key from [reportedip.de](https://reportedip.de)
3. **Pick a protection level** — adjust the three thresholds (failed logins, comment spam, XMLRPC) and the block duration to fit your traffic
4. **Enable 2FA** — choose which of the four methods to allow and which roles to enforce
5. **Set privacy preferences** — retention period, anonymization age and detail level

== Frequently Asked Questions ==

= Do I need a ReportedIP.de account? =

No. *Local Shield* works completely offline with no account and no external calls. You only need a free account for *Community Network*, which adds the shared threat intelligence and coordinated-attack detection.

= What makes this different from other security plugins? =

Three things:

1. **Four 2FA methods in the core**, not behind a paywall — TOTP, Email, SMS and WebAuthn / Passkeys are all included.
2. **Coordinated-attack detection** that looks at multiple IPs hitting the same target across a time window, not just per-IP rate limits.
3. **Privacy by default** — minimal data collection, automatic anonymization, opt-in community sharing, all secrets encrypted at rest.

= Is the plugin GDPR-compliant? =

Yes. GDPR compliance is a design principle here, not an afterthought: no usernames or comment content in any report, configurable retention, automatic anonymization, opt-in sharing, full GDPR documentation included.

= Will this slow down my site? =

No. ETag-based response caching cuts the bulk of API calls, queued reports are processed by cron in the background, and blocked-IP checks are cached per request to avoid N+1 database queries on hooks like XMLRPC's `system.multicall`.

= Can I test without blocking real users? =

Yes. Enable **Report-Only Mode** under *Settings → Protection*. Every event is logged exactly as it would have been blocked, but no IP is ever rejected. Ideal for tuning thresholds against live traffic.

= Does it work with other security plugins? =

Yes. ReportedIP Hive focuses on IP threat intelligence, brute-force protection and 2FA — it complements plugins that handle malware scanning or web-application firewalls.

= What happens if the API is unreachable? =

Nothing breaks. Local blocking rules and cached reputation continue to work; queued reports retry automatically when the API comes back. Up to three retries per report, then the report is marked failed and visible in the API Queue tab.

= Is multisite supported? =

Single-site only for v1.0.0. Multisite support is on the roadmap.

= I lost my 2FA device. How do I get back in? =

Use one of the ten recovery codes you printed during setup. Each is single-use. If you have shell access, `wp reportedip 2fa disable <user>` removes 2FA entirely for the affected account.

= How do I get support? =

* Website: [reportedip.de](https://reportedip.de)
* Documentation: [reportedip.de/docs](https://reportedip.de/docs)
* Bug reports: [GitHub Issues](https://github.com/reportedip/reportedip-hive/issues)
* Security disclosures: [ps@cms-admins.de](mailto:ps@cms-admins.de)

== Screenshots ==

1. **Security Dashboard** — Real-time overview of blocked IPs, failed logins, comment spam and XMLRPC abuse with 7- and 30-day trend charts.
2. **Blocked IPs Management** — Filterable, sortable list of blocked IPs with bulk actions, manual unblock and CSV export.
3. **Whitelist Management** — Trusted IPs with optional expiry, reason and CSV import.
4. **Security Event Logs** — Searchable logs with severity filtering, JSON / CSV export and bulk delete.
5. **Settings — Protection** — Three independent thresholds, block duration and Report-Only mode.
6. **Settings — 2FA** — Per-method enable/disable, role enforcement, recovery codes and trusted-device management.
7. **Setup Wizard** — Six-step guided configuration with privacy-first defaults.
8. **API Queue** — Pending and failed report queue with retry, quota status and queue health indicators.

== Changelog ==

The full structured changelog lives in [CHANGELOG.md](https://github.com/reportedip/reportedip-hive/blob/main/CHANGELOG.md). Highlights:

= 1.2.4 =

UX fix: the per-row "Retry" button on the API queue admin only reset the row to `pending` without actually sending — pending items appeared to do nothing on click. Retry now performs the API call synchronously and reports the actual outcome (sent / failed with the API error message). "Retry All Failed" likewise now drains the queue inline so the admin sees the result immediately instead of waiting for the next 15-min cron tick.

= 1.2.3 =

Hotfix: the cron queue processor still skipped on unlimited-tier accounts because `min( batch, remaining = -1 )` collapsed to `-1`. Same `-1`-as-unlimited issue as 1.2.1, second code path. Verified live before shipping.

= 1.2.2 =

Hotfix: the REST API rate-limit and the 404 burst-trigger could lock authenticated admins out of their own backend (the Block Editor alone fires 50+ REST calls per page-open). Both sensors now skip the threshold for logged-in users; pattern-hits on known scanner paths (`.env`, `.git/config`, `wp-config.php.bak`, …) stay armed for everyone. Default REST burst threshold raised from 60 to 240 in 5 min.

= 1.2.1 =

Hotfix: API report queue was stuck for accounts on tiers without a daily report limit (`remaining_reports = -1`). The quota gate now correctly treats `-1` as unlimited instead of zero. Locked down by a new test suite.

= 1.2.0 =

Major coverage expansion: seven new attack sensors close the WordPress surface that 1.x left exposed — Application Password Abuse (REST/XMLRPC Basic Auth bypass for 2FA), global REST API rate-limit, User Enumeration defence (`?author=`, `/wp-json/wp/v2/users`, oEmbed, login-error masking), 404 / Scanner pattern matching for known vulnerability paths, Password Spray cross-username detection, WooCommerce login hooks, Geographic Anomaly detection. Plus Hide Login (custom wp-login slug), Password Strength enforcement with optional HaveIBeenPwned k-anonymity check, and a centralised category-id mapping that surfaces these sensors in the service taxonomy. Database schema bumps to v3 (auto-migration).

= 1.1.0 =

Mail-Vereinheitlichung: alle vom Plugin versendeten E-Mails (2FA-Code, New-Device-Login, Admin-Security-Alert, 2FA-Reset) laufen jetzt durch eine zentrale Mailer-Klasse mit einheitlichem Brand-Template. Neuer pluggable Mail-Provider-Vertrag, Filter/Actions für Erweiterbarkeit, „Send test email"-Button im Admin. SMS-2FA-Bug behoben (Validity 5 → 10 Min korrekt).

= 1.0.1 =

Wartungs-Release: ~1.500 Zeilen toter Code entfernt, PHP 8.5-kompatibel (`openssl_random_pseudo_bytes` raus, WebAuthn CBOR-Hardening), UI-Fixes (Tabellen-Layout, Setup-Wizard-Redirect-Window). **Breaking:** `Requires PHP` von 7.4 auf 8.1 angehoben.

= 1.0.0 =

Initial public release as **ReportedIP Hive**.

* IP-based brute-force, comment-spam and XMLRPC protection with three configurable threshold channels
* Two operating modes: Local Shield (offline) and Community Network (shared threat intelligence)
* 2FA suite with TOTP, Email, SMS (Sipgate / MessageBird / seven.io) and WebAuthn / Passkeys; ten recovery codes; trusted-device tokens; multi-stage rate limiting
* Coordinated-attack detection across IP / time-window patterns
* ETag-based API response caching, configurable queue with retries and quota tracking
* Privacy-first: minimal data collection, automatic anonymization, no personal data in API reports, all secrets encrypted at rest
* Six-step setup wizard with sensible defaults
* Five admin pages, four security tabs, three settings tabs
* CSV import for blocked IPs and whitelist, CSV / JSON export for logs
* Four cron jobs: daily cleanup, hourly reputation sync, 15-minute queue processing, 6-hour quota refresh
* REST API namespace `reportedip-hive/v1` for headless 2FA flows
* WP-CLI command tree `wp reportedip 2fa`
* English source with German translation included
* WordPress Coding Standards compliant, PHPStan Level 5, 170 PHPUnit tests

== Upgrade Notice ==

= 1.0.0 =
Initial public release — no upgrade path. Install fresh.

== Privacy Policy ==

**Data stored locally**

* IP addresses of blocked or suspicious visitors
* Security event timestamps and event types (login failures, spam attempts, XMLRPC abuse, …)
* Optional, off by default: truncated user-agent strings (max. 50 characters) and request paths

**Data shared with the Community Network (only when enabled)**

* IP address and event type of reported threats
* Anonymized threat metadata for coordinated-attack analysis
* **Never sent:** usernames, comment content, full user-agents, any other personal data

**Retention**

* Configurable retention (default 30 days)
* Automatic anonymization (default after 7 days)
* Manual deletion available from the admin UI; full data wipe on uninstall is opt-in

Full privacy information: [reportedip.de/privacy](https://reportedip.de/privacy).

== External Services ==

This plugin connects to the following external service when *Community Network* mode is active:

**ReportedIP.de API**

* Service URL: `https://reportedip.de/wp-json/reportedip/v2/`
* Purpose: IP reputation lookups and anonymized threat sharing
* Data transmitted: IP addresses, event types, timestamps
* Terms: [reportedip.de/terms](https://reportedip.de/terms)
* Privacy: [reportedip.de/privacy](https://reportedip.de/privacy)

This connection is **optional** and only active in Community Network mode. Local Shield mode works entirely without external connections.

== Credits ==

* Developed by [ReportedIP](https://reportedip.de)
* Plugin Update Checker by [YahnisElsts](https://github.com/YahnisElsts/plugin-update-checker) (MIT)
* WebAuthn / FIDO2 implementation: in-house, no external dependency
* Icons: in-house SVG set

== Translations ==

* English (source)
* German (Deutsch) — included

Want to help translate into more languages? Open an issue on [GitHub](https://github.com/reportedip/reportedip-hive/issues) or contact [ps@cms-admins.de](mailto:ps@cms-admins.de).
