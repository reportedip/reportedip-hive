=== ReportedIP Hive ===
Contributors: reportedip, patrickschlesinger
Donate link: https://reportedip.de
Tags: security, firewall, brute-force, two-factor, threat-intelligence
Requires at least: 5.0
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.6.8
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Update URI: https://github.com/reportedip/reportedip-hive

Community-powered WordPress security: 12 attack sensors, 4 2FA methods, threat sharing. GDPR-first. Made in Germany.

== Description ==

**Every protected site becomes a sensor. When one site is attacked, every other site can refuse the same attacker — before the password is even checked.**

ReportedIP Hive is a complete security plugin for serious WordPress sites: 12 detection sensors, four 2FA methods in the core (TOTP, Passkey/WebAuthn, email, SMS), progressive block escalation, and an opt-in community-intelligence network. Engineered in Germany with privacy as the design principle, not a checkbox.

Two ways to run, no feature held hostage behind a paywall:

* **Local Shield** — works fully offline; nothing ever leaves your site.
* **Community Network** — free account at [reportedip.de](https://reportedip.de) lights up real-time IP reputation lookups and anonymised threat sharing.

= Why agencies and serious site owners pick it =

* **One plugin instead of three.** Brute-force protection, full 2FA suite and threat intelligence in a single drop-in. The plugin itself stays free and Open Source — paid plans only buy optional server-side comfort (managed mail/SMS relay, multi-site, higher API quotas), never the protection itself.
* **Progressive blocks that don't burn legitimate users.** A first-time tripping CGNAT visitor or a fat-fingered admin gets a 5-minute timeout — repeat offenders climb the ladder up to 7 days. Nobody pays a 24h block for a typo.
* **Privacy-first by default.** GDPR-minimal logging mode, 30-day retention, anonymisation after 7 days, opt-in community sharing, all secrets encrypted at rest with libsodium.
* **Cache-plugin-safe.** WP Rocket, W3 Total Cache, WP Super Cache, LiteSpeed and Cloudflare cannot store the 403 block page or serve cached HTML to blocked IPs on protected paths (login, admin, REST, XMLRPC).
* **Code you can read.** Public on GitHub, GPL-2.0-or-later, PHPStan-clean, WPCS-clean, 398 unit tests with 655 assertions on every commit.

= 12 detection sensors (every one tunable) =

* **Failed logins** — default 5 fails / 15 min
* **Password spray** — distinct usernames from same IP, default 5 / 10 min
* **Comment spam** — default 5 / 60 min
* **XMLRPC abuse** — default 10 / 60 min
* **Application-password abuse** — REST/XMLRPC Basic-Auth bypass for 2FA, default 5 / 15 min
* **REST API rate-limit** — global cap, default 240 / 5 min (sensitive routes 20 / 5 min)
* **User enumeration defence** — `?author=`, `/wp-json/wp/v2/users`, oEmbed, login-error masking
* **404 / scanner detection** — default 12 / 2 min, plus instant block on known-bad paths (`.env`, `wp-config.bak`, `/.git/`)
* **Geographic anomaly** — login from a country never seen for the user, optionally revokes trusted-device cookies
* **Password policy** — minimum length, character classes, optional Have-I-Been-Pwned k-anonymity check
* **WooCommerce login hooks** — checkout + my-account forms tracked separately
* **Cookie-banner consent endpoints whitelisted by default** — Real Cookie Banner, Complianz, Borlabs, CookieYes never get rate-limited

= Two-Factor Authentication (full suite, all included) =

* **TOTP** — RFC 6238, works with Google Authenticator, Authy, 1Password, Microsoft Authenticator. Secrets encrypted at rest.
* **Passkey / WebAuthn / FIDO2** — Face ID, Touch ID, Windows Hello, YubiKey. In-house implementation, no Composer dependency. Phishing-resistant.
* **Email OTP** — 6-digit code, 10-minute validity, rate-limited (3 sends / 15 min, 60 s cooldown), 5 verify attempts per code.
* **SMS OTP** — EU-only providers (Sipgate, MessageBird, seven.io) with explicit DPA confirmation. Phone numbers and provider credentials encrypted at rest.

Plus:

* **10 single-use recovery codes**, hashed at rest, low-codes warning at 3 remaining
* **Trusted devices** with configurable expiry (default 30 days), IP + device-name + last-used tracking, auto-revoked on geo anomaly
* **Password-reset gate** — the WordPress "lost password" flow demands a second factor before the new password is accepted. Email is excluded by design (it is the channel that delivered the reset link), so a stolen mailbox cannot bypass 2FA. Email-only accounts without recovery codes are hard-locked with an admin alert.
* **Multi-stage 2FA rate-limit** — 3/5/10/15 fails trigger 30 s/5 m/30 m/1 h delays; the 15th IP-level fail graduates the IP to a real progressive block (so the brute-forcer no longer just times out and tries again hourly)
* **Role-based enforcement** with grace period (default 7 days) and skip counter
* **Frontend onboarding** — branded 5-step setup wizard for users on the front-end (e.g. WooCommerce account)
* **WooCommerce frontend 2FA (Professional plan)** — second factor renders inside the active storefront theme on My Account, classic checkout and the WooCommerce blocks, with a themed onboarding page for Customer / Subscriber roles. Cart and checkout state survive the redirect roundtrip; the trusted-device cookie is shared with the wp-login flow so a checkout-side "Trust this device" silences the next backend login as well. Soft-disables on a tier downgrade — existing customer secrets stay valid, only new onboardings are blocked.
* **Branded login page** option, custom email subject + body, IP allowlist for 2FA bypass

= Progressive block escalation =

The default ladder: **5 min → 15 min → 30 min → 24 h → 48 h → 7 d** (cap). After 30 days without a new offence, the IP starts again at step 1. The ladder is fully editable as a comma-separated minute list under *Settings → Blocking*. A toggle keeps the legacy single-duration mode available for sites that prefer the old behaviour.

Manual blocks (admin clicks "Block this IP" or imports a CSV) honour the admin's chosen duration and are never overridden by the ladder.

= Cache compatibility =

ReportedIP Hive plays nicely with WP Rocket, W3 Total Cache, WP Super Cache, LiteSpeed Cache and CDNs.

* The 403 "Access Denied" response sets `DONOTCACHEPAGE`, `DONOTCACHEDB` and `DONOTCACHEOBJECT`, calls `nocache_headers()`, and emits explicit `Cache-Control: no-store` + `Pragma: no-cache`. No cache layer stores the 403 and hands it back to legitimate visitors.
* Login (`wp-login.php`), admin (`/wp-admin/`), REST (`/wp-json/`), XMLRPC, POST requests and logged-in users are excluded from page caching by every reputable cache plugin out of the box — exactly the paths attackers target. Blocks always take effect there.
* **Documented limitation:** a blocked attacker visiting a *publicly cached* GET URL still receives the cached HTML. Their write-path attempts (login, comment, REST, XMLRPC) are blocked normally. For deny-on-cached-public-page, install a server-level rule (Cloudflare WAF, Nginx `deny`, fail2ban).

= Promote / community shortcodes =

Show the world that your site is part of the hive — and earn community-network credibility:

* **Auto-footer badge** — one toggle, four positions (left / center / right / below content), zero shortcode placement needed
* **Shortcodes** — `[reportedip_badge]`, `[reportedip_stat type="..."]`, `[reportedip_banner]`, `[reportedip_shield]`. Drop into any post, page, widget or template
* **8 stat types** — `attacks_total`, `attacks_30d`, `reports_total`, `api_reports_30d`, `blocked_active`, `whitelist_active`, `logins_30d`, `spam_30d`
* **4 tone presets** — `protect`, `trust`, `community`, `contributor`
* **Web Component with Shadow DOM** — your theme cannot break the layout. The `<a>` link stays in the light DOM, so search engines pick it up.
* **UTM-tracked** — every click measurable in your analytics

= Privacy & GDPR =

* **Made in Germany.** Privacy is a design principle, not an afterthought.
* **Minimal data collection.** No usernames, no comment content, no full user-agents in any report; user-agents are truncated to 50 characters even locally.
* **Configurable retention.** Daily cleanup with a 30-day default; automatic anonymisation after 7 days.
* **Opt-in sharing.** Local Shield works 100 % offline. Nothing leaves your site unless you switch to Community Network.
* **Lawful basis: Art. 6(1)(f) GDPR** (legitimate interest — preventing unauthorised access). Documented in the wizard and admin UI.
* **Encryption at rest.** All secrets (TOTP seeds, SMS provider credentials, phone numbers) sealed with libsodium (or OpenSSL fallback).
* **Delete-on-uninstall** opt-in for total removal.

= Admin UX =

* **9-step setup wizard** with privacy-first defaults: Welcome → Connect → Protection → 2FA → Privacy → Notifications → Login → Promote → Done. Skippable (3 skips, 7-day grace).
* **Real-time dashboard** with 7- and 30-day Chart.js trend lines.
* **Five list-table screens**: Blocked IPs, Whitelist, Security Logs, API Queue, plus the 2FA admin grid.
* **CSV import** for blocked-IPs and whitelist; **CSV / JSON export** for logs and full settings backup.
* **Trust badges** on every admin page: "Security Focused", "GDPR Compliant", "Made in Germany".

= Performance =

* **Login-skip on REST monitor.** Authenticated users never trip the global REST rate-limit (the Block Editor alone fires 50+ calls per page-open).
* **Per-request IP cache.** Repeated checks within a single request hit memory, not the database.
* **ETag-based reputation cache.** 24 h positive-cache for safe IPs, 2 h negative-cache for known-bad IPs. Keeps API usage low.
* **Notification cooldown.** Same IP + same event type emails the admin at most once per hour by default.
* **Report cooldown.** Same IP + same category submitted to the community at most once per 24 h by default.

= Developer surface =

* **REST API** namespace `reportedip-hive/v1` with three 2FA endpoints (`/2fa/challenge`, `/2fa/verify`, `/2fa/methods`) for headless flows.
* **WP-CLI** command tree `wp reportedip 2fa` for user 2FA administration.
* **PHP filters** to extend the engine without forking:
  * `reportedip_hive_rest_bypass_routes` — whitelist additional REST namespaces
  * `reportedip_hive_rest_sensitive_routes` — flag additional REST routes for the lower threshold
  * `reportedip_hive_event_category_map` — map your custom event types to community-API categories
  * `reportedip_2fa_sms_providers` — register additional SMS providers
  * `reportedip_hive_mail_provider`, `reportedip_hive_mail_args`, `reportedip_hive_mail_template_path` — replace the mailer
* **Constants** for emergency overrides:
  * `REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN` — temporarily disable hide-login from `wp-config.php`
* **6 database tables** (auto-migrated; opt-in delete on uninstall): logs, blocked, whitelist, attempts, api_queue, stats, plus trusted_devices for 2FA.
* **Internationalisation-ready.** Text domain `reportedip-hive`, English source with German translation included.
* **Test suite.** 398 PHPUnit tests, 655 assertions; PHPStan level 5; WPCS-compliant.

= What this plugin does NOT include =

Honest scope so you can plan around it:

* No malware scanner / file-integrity monitor
* No web-application firewall (WAF) rules — IP-level blocking only
* No `advanced-cache.php` drop-in (use a server-level firewall for blocking on cached public pages)
* No Cloudflare API integration
* No payment-fraud scoring

Pair it with a malware scanner if you need that surface — Hive deliberately stays focused on identity, brute force and threat intelligence.

== Plans (optional, comfort only) ==

The plugin itself is **free, GPL-2.0 and complete** in every operating mode — every sensor, every 2FA method, every alert, every dashboard, the password-reset gate. Nothing is held back behind a paywall.

Paid plans only buy the **server-side comfort** at reportedip.de — useful for sites that don't want to maintain their own SMTP / SMS / multi-site stack:

= Free / Contributor (0 €) =

* Full plugin functionality, including all sensors and the 2FA suite
* 1 domain per licence, 1,000 IP-reputation checks/day, 50 reports/day
* Local-mode `wp_mail()` for 2FA emails, bring-your-own SMS provider (Sipgate / MessageBird / seven.io with explicit DPA)
* 30-day log retention, community support
* **Contributor tier** is identical to Free but earns curated-feed access for sites that operate a public honeypot

= Professional (14.90 €/month, 149 €/year — covers up to 3 domains) =

* 25,000 reputation checks/day, 1,000 reports/day
* **Managed mail relay** — 500 transactional 2FA mails/month routed through reportedip.de's clean SPF/DKIM/DMARC infrastructure (auto-fallback to `wp_mail()` on cap)
* **Managed SMS relay** — 25 EU-only OTP SMS/month with no third-party Twilio account required
* Multi-site dashboard, priority sync (daily blacklist download), 90-day log retention, e-mail support (48 h SLA)
* Prepaid top-up bundles (SMS and mail) available for heavy months

= Business (39 €/month, 389 €/year — up to 15 domains) =

* 100,000 checks/day, 5,000 reports/day
* **2,500 mail/month + 75 SMS/month included**
* White-label (logo, copy, mail templates), WooCommerce-specific 2FA hooks, full WP-CLI surface, role-based login-time restrictions
* 1-year log retention, weekly security PDF report, GDPR data-export tool, priority support (12 h SLA)

= Enterprise (custom, from ~99 €/month) =

* Unlimited checks and reports, custom mail/SMS quotas, custom domain limit
* Custom AVV / DPA terms, dedicated onboarding, phone support (4 h response)

**Bundles (PRO+ only, refundable until first use):** 50/200/500-SMS bundles (14.90 / 49.90 / 99.90 €), 1k/5k/25k-mail bundles (4.90 / 14.90 / 49.90 €). All prices VAT-inclusive (Stripe `tax_behavior = inclusive`).

What stays Free regardless of plan: every sensor, all four 2FA methods, the password-reset gate, the recovery-code system, every dashboard, every export, the entire plugin source. The plugin works fully offline in Local Shield mode — no plan, no account, nothing leaves your site.

== How Hive actually works ==

A short architectural map for evaluators:

= Two operating modes =

* **Local Shield** — fully offline. Every sensor decision is local; no outbound HTTP. The 2FA-mail-relay and reputation-check endpoints are never touched.
* **Community Network** — Local Shield plus opt-in IP-reputation lookups against `reportedip.de/wp-json/reportedip/v2/check` and queued threat reports against `/report`. Lookups are cached (24 h positive, 2 h negative); reports are batched by cron.

= Request lifecycle =

1. **`init` priority 1.** The very first thing Hive does on every front-end request is check the IP against the local block table. Blocked IPs receive a 403 with `DONOTCACHEPAGE` + `Cache-Control: no-store` headers and exit before any other plugin's `init` handler runs.
2. **`wp_authenticate_user` priority 10.** Reputation check (Community-mode only) and IP-block check before the password is verified — failed-but-cheap, blocked attackers never trigger a `wp_login_failed` action.
3. **`authenticate` priority 99.** After WordPress core verifies the password, the 2FA orchestrator decides whether a second factor is required, sends an OTP if needed, and intercepts with a session-bound nonce + `wp-login.php?action=reportedip_2fa` redirect.
4. **`validate_password_reset` priority 5 + `password_reset` priority 5.** Since 1.6.5: a non-email second factor is required before any new password is persisted via the WordPress "lost password" flow. Email is excluded from the eligible methods because it is the channel that delivered the reset link itself.

= Storage =

* **7 dedicated tables** under the `wp_reportedip_hive_` prefix: `logs`, `blocked`, `whitelist`, `attempts`, `api_queue`, `stats`, `trusted_devices`.
* **Schema v4**, auto-migrated on plugin update; opt-in delete on uninstall.
* All secrets at rest (TOTP seeds, SMS provider credentials, phone numbers) sealed with libsodium (OpenSSL fallback). Plain user-meta storage is never used for credentials.

= Throttle ladder =

A single failure-counter ladder is shared by every brute-force-style sensor (failed logins, 2FA wrong codes, password-reset wrong codes, application-password failures). 3 fails → 30 s, 5 → 5 min, 10 → 30 min, 15 → 1 h. After the 15th failure the IP is graduated to a real `blocked`-table entry via the canonical `handle_threshold_exceeded()` pipeline, which fires the progressive escalation ladder (5 m → 15 m → 30 m → 24 h → 48 h → 7 d) and, in Community mode, queues an anonymised report.

= Performance budget =

* **`init` priority-1 IP check**: ~1 indexed SELECT, request-level memoised — under 1 ms for blocked IPs, ~0.2 ms for clean ones.
* **REST API monitor**: skips authenticated users entirely so the Block Editor (50+ REST calls per page-open) never trips the rate-limiter.
* **Reputation cache**: ETag-based, 24 h positive / 2 h negative. Daily API usage stays low even on busy sites.
* **Reports**: queued, sent in batches of 20 by a 15-minute cron with a 5-minute transient lock against concurrent runs.

= Settings persistence =

Every option lives under the `reportedip_hive_` prefix in `wp_options` (tracked by an explicit snapshot test that fails CI on a silent rename). User-level data uses the `reportedip_hive_2fa_*` user-meta family. Admin actions write structured audit lines to the `logs` table.

== Installation ==

= Manual (recommended) =

1. Download the latest release ZIP from [github.com/reportedip/reportedip-hive/releases/latest](https://github.com/reportedip/reportedip-hive/releases/latest).
2. WP Admin → *Plugins → Add New → Upload Plugin* → pick `reportedip-hive.zip`.
3. Activate and follow the 9-step setup wizard.

= Composer (for developers) =

`composer require reportedip/reportedip-hive`

= Updates =

The plugin ships a built-in update checker that polls the GitHub release feed every 12 hours. Updates appear in the standard *Plugins* list and install with a single click — exactly like a wordpress.org plugin, but served directly from the publisher.

ReportedIP Hive is **not** distributed through wordpress.org. All releases are signed and tagged on GitHub: [github.com/reportedip/reportedip-hive/releases](https://github.com/reportedip/reportedip-hive/releases). For instant updates, hit *Plugins → Check for updates*.

= Configuration =

1. **Pick a mode** — *Local Shield* (offline) or *Community Network* (paste your free API key from [reportedip.de](https://reportedip.de)).
2. **Tune protection** — adjust thresholds and pick a block-duration strategy (progressive ladder vs. fixed length).
3. **Enable 2FA** — pick methods and roles to enforce, set the grace period and max-skip counter.
4. **Set privacy preferences** — retention, anonymisation, detail level. The "GDPR Minimal" preset is one click.
5. **Optionally hide wp-login.php** behind a custom slug.
6. **Optionally show the community badge** in your footer or via shortcode.

== Frequently Asked Questions ==

= Do I need a ReportedIP.de account? =

No. *Local Shield* works completely offline with no account and no external calls. A free account unlocks *Community Network*, which adds shared threat intelligence and coordinated-attack detection.

= How is this different from Wordfence / Sucuri / iThemes Security? =

* **Four 2FA methods in the core**, not behind a paywall — TOTP, Email, SMS and Passkey/WebAuthn.
* **Progressive block escalation** that adapts to repeat offenders without punishing first-time tripping legitimate users.
* **Cache-plugin-safe by default** — Wordfence in particular has had repeated cache-coupling issues.
* **Privacy by default** — minimal data collection, automatic anonymisation, opt-in community sharing, all secrets encrypted at rest.
* **GPL-2.0, public on GitHub** — read every line, fork it, audit it.

We don't compete with malware scanners. Run one alongside Hive if your stack needs it.

= Is the plugin GDPR-compliant? =

Yes. Lawful basis is documented (Art. 6(1)(f) GDPR), processing is minimised, retention is configurable (default 30 days), anonymisation runs daily after 7 days, and Community Network is strictly opt-in. No usernames, comment content or full user-agents leave your site.

= Will this slow down my site? =

No. ETag-based reputation caching, per-request IP cache, queued reports processed by cron in the background, and a `init` priority 1 hook make blocked-IP rejection a few microseconds. The REST monitor skips authenticated users so the Block Editor never trips the rate-limit.

= Does it conflict with my page-cache plugin? =

No. The 403 block-page sets `DONOTCACHEPAGE` and the no-store header set respected by WP Rocket, W3TC, WP Super Cache and LiteSpeed. Authentication paths (`wp-login.php`, `wp-admin/`, `wp-json/`, XMLRPC) are excluded from caching by all of these plugins by default — your blocks fire there normally.

= Can I test thresholds without blocking real users? =

Yes. Enable **Report-Only mode** under *Settings → Blocking*. Every event is logged exactly as it would have been blocked, but no IP is ever rejected. Ideal for tuning thresholds against live traffic before flipping enforcement on.

= I'm getting 403s on Real Cookie Banner / Complianz / Borlabs. Is it Hive? =

In 1.5.0 we baked the four most common cookie-consent REST namespaces into the default REST-monitor bypass list. Update to 1.5.0+ and the issue is gone. For a custom consent stack, add your namespace via the `reportedip_hive_rest_bypass_routes` filter.

= What happens if the API is unreachable? =

Nothing breaks. Local blocking and the cached reputation continue working; queued reports retry automatically (up to 3 attempts, then surfaced in the API Queue tab as failed). Local Shield is unaffected.

= I lost my 2FA device. How do I get back in? =

Use one of the ten recovery codes you saved at setup. Each is single-use. With shell access, `wp reportedip 2fa reset <user>` removes 2FA entirely for the affected account.

= Is multisite supported? =

Single-site for now. Multisite support is on the roadmap.

= How do I get support? =

* Documentation: [reportedip.de/docs](https://reportedip.de/docs)
* Bug reports: [GitHub Issues](https://github.com/reportedip/reportedip-hive/issues)
* Security disclosures (do **not** open a public issue): [ps@cms-admins.de](mailto:ps@cms-admins.de)

== Cache compatibility ==

ReportedIP Hive plays nicely with the major page-cache plugins (WP Rocket, W3 Total Cache, WP Super Cache, LiteSpeed Cache) and CDNs.

* **Blocked-page responses are never cached.** Defines `DONOTCACHEPAGE`, `DONOTCACHEDB`, `DONOTCACHEOBJECT`, calls `nocache_headers()` and emits `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` plus `Pragma: no-cache`.
* **Sensor-protected paths are never cached** by reputable cache plugins anyway: `wp-login.php`, `/wp-admin/`, `/wp-json/`, XMLRPC, POSTs and logged-in users — exactly where attackers operate.
* **Documented limitation:** a blocked attacker visiting a *publicly cached* GET URL receives the cached HTML. Their write-path attempts are still blocked. For deny-on-cached-public-page, install a server-level firewall (Cloudflare WAF rule, Nginx `deny`, fail2ban).

== Screenshots ==

1. **Security Dashboard** — Real-time overview of blocked IPs, attacks, sign-ins and spam with 7- and 30-day trend charts.
2. **Blocked IPs** — Filterable, sortable list with bulk actions, manual unblock, "move to whitelist" and CSV export.
3. **Whitelist** — Trusted IPs with optional expiry, reason, and CSV import.
4. **Security Event Logs** — Searchable, severity-filterable, JSON / CSV export, bulk delete + bulk block + bulk whitelist actions.
5. **Settings → Blocking** — How-blocking-decides info card, auto-block toggle, progressive ladder editor with reset window, report-only mode toggle, blocked-page contact link.
6. **Settings → Two-Factor** — Method enable/disable, role enforcement, grace period, IP allowlist, recovery-code management, trusted-device list.
7. **Setup Wizard** — 9-step guided configuration with privacy-first defaults and a celebration on the final step.
8. **API Queue** — Pending and failed report queue with retry, quota status, queue-health indicators.
9. **Promote** — Auto-footer badge configurator and shortcode showcase with live previews.

== Changelog ==

The full structured changelog lives in [CHANGELOG.md](https://github.com/reportedip/reportedip-hive/blob/main/CHANGELOG.md). Highlights:

= 1.6.6 =

**Password-reset gate hardening (E2E coverage).** Three real bugs in the 1.6.5 implementation that were caught while driving the full reset flow against a Docker stack and would have shipped silently otherwise:

* The reset-key resolver only looked at the URL — the WordPress reset cookie (`wp-resetpass-COOKIEHASH`, set during step 2 of the reset flow) and `$_POST['rp_key']` were ignored. The `validate_password_reset` hook fired but bailed out without effect on every standard reset, so the gate was end-to-end bypassable. Resolver now reads URL → POST → cookie.
* Email-only lockout used `$errors->add()`, but `User_Enumeration::normalize_login_errors()` rewrites every non-2FA login error to "Invalid credentials." for username-probing defence — affected users never saw the real reason. The gate now renders a dedicated 403 page via `wp_die()`, which no `login_errors` filter can rewrite.
* `User_Enumeration::normalize_login_errors()` whitelist extended: `?action=reportedip_2fa_reset` pages and any error text containing "reset blocked" or "two-factor" on the `rp` / `resetpass` actions now pass through unmasked.

**Strongly recommended for everyone running 1.6.5** — without this update the reset gate is wired but inactive on the standard reset flow.

= 1.6.5 =

**Password-reset 2FA gate.** The WordPress "lost password" flow now demands a non-email second factor (Authenticator app, SMS, passkey, or recovery code) before a new password is accepted. Email is excluded from the eligible methods by design — it is the channel that delivered the reset link itself, so accepting an email OTP as the second factor would collapse to single-factor security if the mailbox is compromised. Hooks `validate_password_reset` (priority 5, gates the form render) and `password_reset` (priority 5, last-mile guard before `wp_set_password`). Failures share the IP-block ladder with login-flow failures via the canonical `2fa_brute_force` event. Accounts whose only enrolled second factor is email and which hold no recovery codes are hard-locked from the reset flow with an admin-mail alert; unblock manually via `wp user reset-password <id> --skip-email`. Two new options under *Settings → Two-Factor → Password reset gate*: `reportedip_hive_2fa_require_on_password_reset` (master toggle, default on) and `reportedip_hive_2fa_password_reset_block_email_only` (default on). The list of methods rejected as second factor in this flow is filterable via `reportedip_hive_2fa_password_reset_excluded_methods` and defaults to `["email"]`. Aligns with NIST SP 800-63B §6.1.2.3 and OWASP ASVS V6.3.

= 1.7.0 =

Mail bundle balance now visible alongside SMS in the relay-quota panel. The Hive dashboard now reads the prepaid bundle saldo for both Mail and SMS from `/relay-quota` and renders a "+ X credits in your bundle balance" hint under each usage card. A negative bundle balance (after a Stripe refund) surfaces a red warning that explains why sending stays blocked even though the inclusive monthly cap may not be reached yet. Snapshot schema gains per-type `bundle_balance` plus the top-level `mail_bundle_balance` mirror; the existing `sms_bundle_balance` field is now actually populated by the service. Cron quota refresh logs both bundle balances for easier diagnostics. Setup wizard tier teasers mention prepaid Mail bundles next to the existing SMS bundle copy.

= 1.6.3 =

Managed mail and SMS relay — Professional / Business / Enterprise plans now route 2FA mails and OTP-SMS through reportedip.de instead of needing their own SMTP / Twilio / Sipgate contract. Mail relay falls back transparently to local `wp_mail()` on cap (HTTP 402) or backoff (HTTP 429) so 2FA flows never break. SMS relay surfaces typed `WP_Error`s so the 2FA UI can encourage another method instead of silently switching. New `ReportedIP_Hive_Phone_Validator` enforces an EU-only country-code whitelist (29 countries, filterable). Progressive SMS backoff ladder (0s → 2m → 5m → 15m → 30m → 60m) mirrors the service-side rate-limiter. Setup wizard slimmed from 8 to 7 steps. Scan-detector path matcher refactored to a single pass.

= 1.6.1 =

Post-upgrade 2FA setup banner appears on every Hive admin page when a customer's plan crosses from Free / Contributor into Professional / Business / Enterprise, with a three-step checklist (provider chosen, AVV confirmed, SMS method enabled). Login-time 2FA reminder for end users — counts logins without a configured method and renders a soft banner across wp-admin; after the configurable threshold (default 5) administrators, editors and shop managers are forced into the existing onboarding wizard, while customers, subscribers and other non-privileged roles only ever see the soft banner so a missing phone never locks anyone out of WooCommerce. AVV / DPA checkbox on the 2FA tab now adapts to the active SMS provider — selecting `reportedip_relay` flips the label to "I have accepted the ReportedIP AVV (signed with my plan subscription)" and auto-checks. New `Login reminder` settings section to toggle the reminder, set the hard-block threshold (1–10), and pick which roles get hard-blocked at threshold.

= 1.6.0 =

Tier-aware UI foundation across admin pages — every page now renders a tier badge next to the operation-mode badge (Free / Contributor / Professional / Business / Enterprise), and PRO+ tiers gain a managed-relay quota panel on the security dashboard with mail and SMS counters, progress bars and reset hints. Setup wizard's first step reuses the same Local-vs-Community comparison cards as the Settings page. SMS-provider selector marks "ReportedIP SMS Relay" as PRO+ when the current tier is too low, with a deep link to the pricing page. New `Mode_Manager::feature_status()`, `get_tier_info()` and `get_relay_quota_snapshot()` are the canonical contracts every future tier-gated control hooks into. New `reportedip_hive_tier_changed` action fires when the upstream `userRole` flips between tiers.

= 1.5.3 =

API queue reliability hotfix. A worker that crashed mid-HTTP (PHP fatal, OOM, timeout) used to leave its queue row stuck in `processing` forever — invisible to every later cron run, never cleaned up, and the cooldown check then silently suppressed all further reports for that IP for 24 h. The queue cron now recovers stuck rows on every run, protects in-flight rows via a new `submitted_at` timestamp, runs each row in its own try/catch so one failure can't abort the batch, and serialises concurrent invocations with a transient lock. Schema bumps to v4 (auto-migrated). Strongly recommended for every Community-mode site.

= 1.5.2 =

Cache plugins (WP Rocket / W3TC / WP Super Cache / LiteSpeed) no longer cache the 403 "Access Denied" page back to legitimate visitors — the response now defines `DONOTCACHEPAGE` + sends `Cache-Control: no-store` and `Pragma: no-cache`. Front-end IP-block hook moved to `init` priority 1. The 2FA per-IP throttle now graduates a brute-forcer to a real progressive block at the 15th wrong code via the canonical `handle_threshold_exceeded()` pipeline — community-mode reporting and admin notification fire correctly. New `2fa_brute_force` event slug registered in both category and stat mappings.

= 1.5.1 =

Settings UI clarity. The Blocking tab and the wizard's Protection step now spell out the three-level decision chain (Report-only > Auto-blocking > Duration strategy). The duration strategy is a labelled subsection with a required marker that visually disables when Auto-blocking is off, so users cannot configure a duration that will never apply.

= 1.5.0 =

Progressive block escalation. New `ReportedIP_Hive_Block_Escalation` class with a configurable per-IP ladder (default 5 m → 15 m → 30 m → 24 h → 48 h → 7 d) and a 30-day reset window. Cookie-consent endpoints (Real Cookie Banner, Complianz, Borlabs, CookieYes) baked into the default REST-monitor bypass list — a regression for high-traffic sites where the consent POST counted toward the global rate-limit. 404 default 8/1 min → 12/2 min, comment-spam 3/60 min → 5/60 min (existing installs untouched).

= 1.4.0 =

Wizard UX overhaul. Step 3 protection toggles split into three themed cards (Authentication / Content & API / Behaviour). Step 4 pre-ticks methods and roles from saved options; SMS card surfaces a "Provider setup required" tag when picked. Step 6 hide-login spacing replaced with a `.rip-input-group` BEM. Step 7 Promote alignment radios with live preview. Step 8 Setup-complete celebration (halo pulse, summary fade-up, checkmark bounce) all gated behind `prefers-reduced-motion`. Step 3 fixed a regression where five advanced sensors were silently dropped on save. New `ReportedIP_Hive_Defaults` class centralises wizard defaults.

= 1.3.0 =

Promote tab + frontend banner shortcodes. Four new public shortcodes (`[reportedip_badge]`, `[reportedip_stat]`, `[reportedip_banner]`, `[reportedip_shield]`) render community-trust banners on any post, page, widget or template, each linking back to reportedip.de with UTM tracking. Auto-footer badge with variant + alignment selector. Eight stat types, four tone presets. Banners render as `<rip-hive-banner>` Web Component with Shadow DOM so themes cannot break their styling.

= 1.2.x =

Hotfix series: REST API rate-limit + 404 burst-trigger no longer lock authenticated admins out of the Block Editor; API queue retry button performs the call inline with the actual outcome; quota gate correctly treats `-1` as "unlimited" instead of zero.

= 1.2.0 =

Major sensor expansion: Application-Password Abuse, REST API rate-limit, User Enumeration defence, 404 / Scanner pattern matching, Password Spray, WooCommerce login, Geographic Anomaly, plus Hide-Login (custom wp-login slug) and Password Strength enforcement with optional Have-I-Been-Pwned k-anonymity check. Database schema bumps to v3 with auto-migration.

= 1.1.0 =

Mail unification: every plugin email runs through a central mailer with branded template; pluggable mail-provider contract; "Send test email" button.

= 1.0.x =

Initial public release as ReportedIP Hive. Three threshold channels, two operating modes (Local Shield / Community Network), four 2FA methods, ten recovery codes, six-step setup wizard, REST API namespace `reportedip-hive/v1`, WP-CLI tree.

== Upgrade Notice ==

= 1.6.6 =
Critical hardening for the 1.6.5 password-reset gate. The reset-key resolver missed the WordPress reset cookie, so the gate was wired but inactive on the standard reset flow — making 1.6.5 effectively unprotected. Strongly recommended for every site running 1.6.5. No breaking change.

= 1.6.5 =
Closes a long-standing 2FA bypass: the WordPress "lost password" flow used to let anyone with mailbox access through email-2FA, because the reset link and the email OTP arrived on the same channel. Hive now requires a non-email second factor (Authenticator, SMS, passkey, recovery code) before a new password is accepted. Strongly recommended for every site using email 2FA. No breaking change: users without 2FA configured are unaffected.

= 1.6.3 =
Managed Mail/SMS relay for Professional+. 2FA mail falls back to local `wp_mail()` on cap; SMS surfaces typed errors to the user. EU-only phone validator. Free / Contributor sites are unaffected. Recommended for everyone — no breaking change.

= 1.6.1 =
Post-upgrade welcome banner with a 3-step 2FA-setup checklist, plus a login-time reminder for users without 2FA (hard-block after 5 reminders for administrator/editor/shop_manager only). Recommended.

= 1.6.0 =
Tier-aware UI foundation: every admin page now renders the active tier and (on PRO+) a managed-relay quota card on the security dashboard. Recommended.

= 1.5.3 =
API queue reliability hotfix. Recovers rows stuck in `processing` after a crashed worker, protects in-flight rows, isolates per-row failures, and serialises concurrent cron runs. Schema bumps to v4 (auto-migrated). Strongly recommended for every Community-mode site.

= 1.5.2 =
Cache-plugin-safe 403 page + 2FA brute-force graduation to progressive escalation. Strongly recommended if you run any page-cache plugin or have public-facing 2FA endpoints.

= 1.5.0 =
Progressive block escalation + cookie-banner consent endpoints whitelisted. Update to fix Real Cookie Banner / Complianz visitor-block loops.

= 1.4.0 =
Wizard saving regression for advanced sensors. Update if you re-ran the wizard on 1.3.x — your advanced sensor toggles may have been silently saved as off.

= 1.2.0 =
Major sensor expansion + auto-migration to schema v3. No manual steps required.

= 1.0.0 =
Initial release.

== Privacy Policy ==

**Data stored locally**

* IP addresses of blocked or suspicious visitors
* Security event timestamps and event types (login failures, spam attempts, XMLRPC abuse, …)
* Optional, off by default: truncated user-agent strings (max. 50 characters) and request paths
* Encrypted at rest: 2FA TOTP seeds, SMS provider credentials, user phone numbers (libsodium with OpenSSL fallback)

**Data shared with the Community Network (only when enabled)**

* IP address and event type of reported threats
* Anonymised threat metadata for coordinated-attack analysis
* **Never sent:** usernames, comment content, full user-agents, any other personal data

**Lawful basis** (EU GDPR)

* Art. 6(1)(f) GDPR — legitimate interest in preventing unauthorised access and detecting attacks against the controller's site.

**Retention**

* Configurable retention (default 30 days)
* Automatic anonymisation (default after 7 days)
* Manual deletion available from the admin UI; full data wipe on uninstall is opt-in

Full privacy information: [reportedip.de/privacy](https://reportedip.de/privacy).

== External Services ==

This plugin connects to external services only when explicitly configured. *Local Shield* mode works completely offline — none of the endpoints below are contacted unless the corresponding feature is enabled.

= ReportedIP Community Network API =

* Service URL: `https://reportedip.de/wp-json/reportedip/v2/` (endpoints `verify-key`, `check`, `report`, `whitelist`, `categories`)
* Purpose: IP reputation lookups, anonymised threat reporting, whitelist sync, threat-category catalogue
* Default: off — only active in Community Network mode AND with a configured API key
* Data transmitted: IP addresses, optional event categories and timestamps, the API key, the site domain
* Terms: [reportedip.de/terms](https://reportedip.de/terms)
* Privacy / DPA: [reportedip.de/privacy](https://reportedip.de/privacy)

= ReportedIP Managed Mail Relay =

* Service URL: `https://reportedip.de/wp-json/reportedip/v2/relay-mail`
* Purpose: route 2FA verification mails through the reportedip.de transactional mail infrastructure (clean SPF / DKIM / DMARC)
* Default: off — only available for Professional, Business and Enterprise plans, only when the user enabled the email 2FA factor; on any error (cap reached HTTP 402, recipient backoff HTTP 429, network error) the plugin falls back to the local `wp_mail()` transport so the 2FA flow never breaks
* Data transmitted: recipient email, subject, HTML and plain-text body, headers, optional Reply-To, the site domain
* Privacy / DPA: [reportedip.de/legal/avv](https://reportedip.de/legal/avv)

= ReportedIP Managed SMS Relay =

* Service URL: `https://reportedip.de/wp-json/reportedip/v2/relay-sms` (and `relay-quota` for monthly usage display)
* Purpose: deliver 2FA OTP messages without requiring the site operator to maintain their own SMS-provider contract
* Default: off — only available for Professional, Business and Enterprise plans, only when a user actively enrolled SMS as a 2FA factor and the site selected `ReportedIP SMS Relay` as the active provider; phone numbers are validated as EU-only (29-country whitelist) before any send
* Data transmitted: recipient phone number (E.164), the verification code, expiry minutes, language code, the site domain
* Privacy / DPA: [reportedip.de/legal/avv](https://reportedip.de/legal/avv)

= GitHub Releases API (Plugin Update Checker) =

* Service URL: `https://api.github.com/repos/reportedip/reportedip-hive/releases` (via the [plugin-update-checker](https://github.com/YahnisElsts/plugin-update-checker) library)
* Purpose: notifies the WordPress plugin updater about new tagged releases (release ZIP is downloaded from GitHub when the admin clicks "Update")
* Default: on — runs once every 12 hours via the `wp_update_plugins` cron, the same cadence WordPress core uses for its own update checks
* Data transmitted: only plugin metadata (current version, slug); no site identifiers, no user data
* Terms: [GitHub Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service)
* Privacy: [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)

= HaveIBeenPwned (HIBP) Range API =

* Service URL: `https://api.pwnedpasswords.com/range/{first-5-sha1-hex-chars}`
* Purpose: optional k-anonymity password-strength check at user password change — flags credentials known from public breach corpora
* Default: off — opt-in via the option `reportedip_hive_password_check_hibp`, only triggers for users in the configured enforce-roles
* Data transmitted: only the first 5 hex characters of the SHA-1 hash of the proposed password (the password itself is never sent and cannot be reconstructed)
* Privacy: [haveibeenpwned.com/Privacy](https://haveibeenpwned.com/Privacy)
* Soft-fail behaviour: a network error never blocks a password change

= Third-party SMS providers (only when configured by the site operator) =

When the site operator selects a non-relay SMS provider, the plugin contacts that provider directly with the recipient's E.164 phone number, the OTP message body and the configured sender ID:

* **Sipgate (Germany)** — `https://api.sipgate.com/v2/sessions/sms` — Terms: [sipgate.de/agb](https://www.sipgate.de/agb) — DPA: [sipgate.de/agb#auftragsverarbeitung](https://www.sipgate.de/agb#auftragsverarbeitung)
* **MessageBird / Bird (Netherlands)** — `https://rest.messagebird.com/messages` — Terms: [messagebird.com/legal/terms](https://messagebird.com/legal/terms) — DPA: [messagebird.com/legal/dpa](https://messagebird.com/legal/dpa)
* **seven.io (Germany)** — `https://gateway.seven.io/api/sms` — Terms: [seven.io/agb](https://www.seven.io/agb) — DPA: included in [seven.io/agb](https://www.seven.io/agb)

No SMS traffic occurs unless a user actively enrols an SMS factor and a site operator has both configured a provider AND ticked the corresponding DPA confirmation in 2FA settings — that confirmation is a hard gate.

= No CDN, no third-party assets =

All JavaScript, CSS, fonts and images shipped with the plugin are loaded from the plugin directory itself. The plugin does not embed Google Fonts, Google Analytics, jQuery from a CDN or any other remote asset.

== Related projects ==

ReportedIP Hive is one piece of an Open-Source ecosystem around community-driven WordPress security. All projects are GPL or compatible licences and live on GitHub:

* **Hive** (this plugin) — [github.com/reportedip/reportedip-hive](https://github.com/reportedip/reportedip-hive). Community-powered WordPress security: IP threat intelligence, brute-force protection and the complete 2FA suite. Be part of the hive.
* **Honeypot Server** — [github.com/reportedip/honeypot-server](https://github.com/reportedip/honeypot-server). PHP honeypot that emulates WordPress, Drupal and Joomla to detect malicious traffic. 36 threat analyzers, automatic reporting to the reportedip.de API, admin dashboard, AI content generation, bot detection. Zero Composer dependencies, SQLite, Docker-ready. Run one yourself to feed the network and earn the Contributor tier.
* **Blacklist** — [github.com/reportedip/reportedip-blacklist](https://github.com/reportedip/reportedip-blacklist). Community-driven IP threat-intelligence feed with curated and dynamic blacklists, updated daily. Free to consume, no account required.

Project home, documentation and the optional managed-relay service: [reportedip.de](https://reportedip.de).

== Credits ==

* Developed by [ReportedIP](https://reportedip.de)
* Plugin Update Checker by [YahnisElsts](https://github.com/YahnisElsts/plugin-update-checker) (MIT)
* WebAuthn / FIDO2 implementation: in-house, no external dependency
* Charts: [Chart.js](https://www.chartjs.org/) (MIT)
* Icons: in-house SVG set

== Translations ==

* English (source)
* German (Deutsch) — included

Want to help translate into more languages? Open an issue on [GitHub](https://github.com/reportedip/reportedip-hive/issues) or contact [ps@cms-admins.de](mailto:ps@cms-admins.de).

== Disclaimer ==

ReportedIP Hive is provided **"as is"** and **"as available"** under the terms of the GNU General Public License version 2 or later (GPL-2.0-or-later). The licence in full: [gnu.org/licenses/gpl-2.0.html](https://www.gnu.org/licenses/gpl-2.0.html).

= No warranty =

There is **no warranty** for the program, to the extent permitted by applicable law. Except when otherwise stated in writing, the copyright holder and other parties provide the program "as is" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose. The entire risk as to the quality and performance of the program is with you. Should the program prove defective, you assume the cost of all necessary servicing, repair or correction.

This includes — explicitly and without limitation — no warranty of:

* uninterrupted or error-free operation;
* fitness for any specific security objective;
* prevention of any specific class of attack;
* compatibility with any specific WordPress version, theme, plugin or hosting environment;
* completeness or accuracy of the threat-intelligence data shared via the optional Community Network;
* timely or reliable delivery of email or SMS one-time passwords through any mail or SMS provider, whether self-configured or routed through the optional managed relays;
* compliance with any specific legal, regulatory or contractual obligation that applies to the operator of the protected site.

= No liability =

In no event will the copyright holder, or any other party who modifies and/or conveys the program as permitted under the GPL, be liable to you for damages, including any general, special, incidental or consequential damages arising out of the use or inability to use the program (including but not limited to loss of data, data being rendered inaccurate, losses sustained by you or third parties, lost revenue, business interruption, lockout from your own administrative interface, or a failure of the program to operate with any other programs).

Operating ReportedIP Hive is solely the responsibility of the site operator. The operator is responsible for:

* maintaining backups of WordPress, the database and the plugin configuration before installation, upgrades and configuration changes;
* understanding the consequences of enabling 2FA enforcement, hide-login, password-reset gating and IP blocking — in particular the documented edge case where an account with only email-2FA and no recovery codes is intentionally locked out of the password-reset flow until an administrator intervenes;
* maintaining recovery procedures (recovery codes, alternative second factors, WP-CLI access, server-level access) so that a misconfiguration or an upstream service outage does not cause permanent loss of access to the site;
* obtaining and maintaining any data-processing agreements, terms of service or end-user disclosures required by applicable law for the SMS, email or threat-intelligence services they choose to use.

= Security disclosures =

If you believe you have discovered a security issue in ReportedIP Hive, **please do not open a public GitHub issue**. Send the details to [ps@cms-admins.de](mailto:ps@cms-admins.de). We will acknowledge receipt within five business days.

= Recommended posture =

Treat ReportedIP Hive as one layer in a defence-in-depth setup. Pair it with:

* offsite, versioned backups (database + uploads + plugin configuration);
* a malware scanner of your choice — Hive deliberately does not include one;
* a server-level firewall (Cloudflare WAF, Nginx `deny`, fail2ban) for blocking on cached public pages, which the plugin cannot reach by design;
* a reasonable patch cadence — install updates as they are released, run `./run.sh check-all` (or your CI equivalent) before upgrading on production-critical sites.

By installing or activating this plugin you confirm that you have read and accepted the terms above and the GPL-2.0-or-later licence under which the plugin is distributed.
