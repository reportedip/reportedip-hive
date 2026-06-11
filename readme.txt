=== ReportedIP Hive ===
Contributors: reportedip, patrickschlesinger
Donate link: https://reportedip.de
Tags: security, firewall, brute-force, two-factor, multisite
Requires at least: 5.0
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 2.1.6
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Update URI: https://github.com/reportedip/reportedip-hive

Community-powered WordPress security: 12 attack sensors, 4 2FA methods, threat sharing, fully Multisite-aware. GDPR-first. Made in Germany.

== Description ==

**Every protected site becomes a sensor. When one site is attacked, every other site can refuse the same attacker — before the password is even checked.**

ReportedIP Hive is a complete security plugin for serious WordPress sites: 16 detection sensors, four 2FA methods (TOTP, Passkey/WebAuthn and email in every plan; SMS on Professional via the managed relay), progressive block escalation, and an opt-in community-intelligence network. Engineered in Germany with privacy as the design principle, not a checkbox.

The entire detection and identity core is **free, GPL-2.0 and complete** — every sensor, the core 2FA methods, progressive blocking, the password-reset gate, every dashboard and export. Paid plans add managed relays, multi-site management and a few advanced modules on top (see *Plans* below); they never gate the core protection.

Two ways to run:

* **Local Shield** — works fully offline; nothing ever leaves your site.
* **Community Network** — free account at [reportedip.de](https://reportedip.de) lights up real-time IP reputation lookups and anonymised threat sharing.

= Why agencies and serious site owners pick it =

* **One plugin instead of three.** Brute-force protection, a four-method 2FA suite and threat intelligence in a single drop-in. The full protection core stays free and Open Source — paid plans add the managed mail/SMS relays, multi-site management, higher API quotas and a few advanced modules (WooCommerce frontend 2FA, Hardening Mode, white-label), never the core protection itself.
* **Progressive blocks that don't burn legitimate users.** A first-time tripping CGNAT visitor or a fat-fingered admin gets a 5-minute timeout — repeat offenders climb the ladder up to 7 days. Nobody pays a 24h block for a typo.
* **Privacy-first by default.** GDPR-minimal logging mode, 30-day retention, anonymisation after 7 days, opt-in community sharing, all secrets encrypted at rest with libsodium.
* **Hardening Mode on coordinated attacks (PRO).** When the plugin spots ≥ 3 IPs / ≥ 20 failed logins in the same minute it tightens the failed-login and reputation thresholds network-wide for one hour. Distributed brute-force from botnets stops mid-flight instead of slipping under the per-IP threshold. Realtime trigger in the login pipeline plus an hourly cron sweep as fallback. Visible state via the admin bar, configurable from a dedicated Settings tab, controllable via WP-CLI.
* **Cache-plugin-safe.** WP Rocket, W3 Total Cache, WP Super Cache, LiteSpeed and Cloudflare cannot store the 403 block page or serve cached HTML to blocked IPs on protected paths (login, admin, REST, XMLRPC).
* **Security headers out of the box.** The basic hardening trio (X-Content-Type-Options, X-Frame-Options, Referrer-Policy) is free; HSTS, Permissions-Policy, a report-only-first Content-Security-Policy and the cross-origin isolation trio come with Professional. Headers already sent by your server or another plugin are detected and left untouched.
* **Code you can read.** Public on GitHub, GPL-2.0-or-later, PHPStan level 5 clean, WPCS-clean (zero warnings), a comprehensive PHPUnit suite (unit + Multisite) running on every commit.

= 16 detection sensors (every one tunable) =

* **Failed logins** — default 5 fails / 15 min
* **Password spray** — distinct usernames from same IP, default 5 / 10 min
* **Comment spam** — default 5 / 60 min
* **XMLRPC abuse** — default 10 / 60 min
* **Application-password abuse** — REST/XMLRPC Basic-Auth bypass for 2FA, default 5 / 15 min
* **REST API rate-limit** — global cap, default 240 / 5 min (sensitive routes 20 / 5 min)
* **User enumeration defence** — `?author=`, `/wp-json/wp/v2/users`, oEmbed, login-error masking
* **404 / scanner detection** — default 12 / 2 min, plus instant block on known-bad paths (`.env`, `wp-config.bak`, `/.git/`)
* **Web Application Firewall** — request-inspecting engine (SQLi, XSS, path traversal, command injection, LFI wrappers, scanner tooling). The engine and the OWASP-Top-10 Paranoia-Level-1 baseline are free on every plan; Professional adds the deeper, frequently-updated, Ed25519-signed Level 2/3 ruleset. ReDoS-hardened and fail-open, with an optional pre-WordPress drop-in (Apache / PHP-FPM auto-config, nginx snippet) for blocking before WordPress loads
* **Verified bot detection** — confirms Googlebot, Bingbot and other crawlers via their official IP ranges (DNS-free) and forward-confirmed reverse DNS. Spoofers are flagged (default) or blocked; genuine crawlers are never blocked. Free on every plan
* **Disposable-email blocking** — inspects the address at registration (WordPress + WooCommerce) against the throwaway-mail list (off / monitor / block). Privacy relays (Apple Hide My Email, Firefox Relay, …) pass through by default. Free; the live list rides Priority Sync
* **Comment honeypot** — invisible, screen-reader-excluded decoy field; spam bots that fill it are rejected with no CAPTCHA friction
* **Geographic anomaly** — login from a country never seen for the user, optionally revokes trusted-device cookies
* **Password policy** — minimum length, character classes, optional Have-I-Been-Pwned k-anonymity check
* **WooCommerce login hooks** — checkout + my-account forms tracked separately
* **Cookie-banner consent endpoints whitelisted by default** — Real Cookie Banner, Complianz, Borlabs, CookieYes never get rate-limited

= Two-Factor Authentication (four methods) =

Three of the four methods work in **every plan**, including Free and the fully-offline Local Shield. SMS is the one method that rides the managed relay, so it needs a Professional plan.

* **TOTP** — RFC 6238, works with Google Authenticator, Authy, 1Password, Microsoft Authenticator. Secrets encrypted at rest. *Free.*
* **Passkey / WebAuthn / FIDO2** — Face ID, Touch ID, Windows Hello, YubiKey. In-house implementation, no Composer dependency. Phishing-resistant. *Free.*
* **Email OTP** — 6-digit code, 10-minute validity, rate-limited (3 sends / 15 min, 60 s cooldown), 5 verify attempts per code. *Free.*
* **SMS OTP (Professional)** — delivered through the managed reportedip.de relay, included with Professional and Business plans. No own SMS account or carrier contract required. Phone numbers encrypted at rest. Free / Contributor sites use TOTP, Passkey or Email instead.

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
* **Encryption at rest.** All secrets (TOTP seeds, phone numbers) sealed with libsodium (or OpenSSL fallback).
* **Delete-on-uninstall** opt-in for total removal.
* **Privacy-policy generator.** A ready-to-paste passage for your own privacy policy (German or English, tailored to the modules you use) is at [reportedip.de/dashboard/dsgvo](https://reportedip.de/dashboard/dsgvo); the plugin also registers a suggested text in the WordPress Privacy Policy Guide (Tools -> Privacy).

= Admin UX =

* **10-step setup wizard** with privacy-first defaults: Welcome → Connect → Protection → Firewall → 2FA → Privacy → Notifications → Login → Promote → Done. Skippable (3 skips, 7-day grace).
* **Real-time dashboard** with detection & hardening score gauges (0–100 plus an A+–F grade, per-item deep links) and 7- and 30-day Chart.js trend lines.
* **Six list-table screens**: Blocked IPs, Whitelist, Security Logs, API Queue, the audit event trail (Business), plus the 2FA admin grid.
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
  * `reportedip_hive_mail_provider`, `reportedip_hive_mail_args`, `reportedip_hive_mail_template_path` — replace the mailer
* **Constants** for emergency overrides:
  * `REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN` — temporarily disable hide-login from `wp-config.php`
* **8 database tables** (auto-migrated; opt-in delete on uninstall): logs, blocked, whitelist, attempts, api_queue, stats, trusted_devices and audit_log.
* **Internationalisation-ready.** Text domain `reportedip-hive`, English source with German translation included.
* **Test suite.** A comprehensive PHPUnit suite (unit + Multisite) runs on every commit; PHPStan level 5 (No errors); WPCS-compliant with zero warnings.

= What this plugin does NOT include =

Honest scope so you can plan around it:

* No malware scanner / file-integrity monitor
* No Cloudflare API integration
* No payment-fraud scoring

Pair it with a malware scanner if you need that surface — Hive deliberately stays focused on identity, brute force and threat intelligence.

== Plans (optional, comfort only) ==

The full **detection and identity core is free, GPL-2.0 and complete** in every operating mode — all 16 sensors, the core 2FA methods (TOTP, Passkey, Email, Recovery codes), progressive block escalation, the password-reset gate, every alert, every dashboard and export. None of that is ever gated.

Paid plans add the **managed relays, multi-site management and a handful of advanced modules** at reportedip.de — useful for sites that don't want to maintain their own SMTP / SMS / multi-site stack, run a WooCommerce storefront, or need network-wide auto-hardening:

= Free / Contributor (0 €) =

* Full core functionality — all 16 sensors, progressive blocking, the password-reset gate, every dashboard and export
* 1 domain per licence, 1,000 IP-reputation checks/day, 50 reports/day
* Local-mode `wp_mail()` for 2FA emails; TOTP, Passkey and Email 2FA included (SMS 2FA, WooCommerce frontend 2FA and Hardening Mode require Professional)
* 30-day log retention, community support
* **Contributor tier** is identical to Free but earns curated-feed access for sites that operate a public honeypot

= Professional (14.90 €/month, 149 €/year — covers up to 3 domains) =

* 25,000 reputation checks/day, 1,000 reports/day
* **Managed mail relay** — 500 transactional 2FA mails/month routed through reportedip.de's clean SPF/DKIM/DMARC infrastructure (auto-fallback to `wp_mail()` on cap)
* **Managed SMS relay** — 25 worldwide OTP SMS/month with no third-party Twilio account required
* **WooCommerce frontend 2FA** — the second factor rendered inside the storefront theme on My Account, classic checkout and the WC blocks
* **Hardening Mode** — auto-tighten failed-login and reputation thresholds network-wide for one hour on a detected coordinated attack
* **Advanced security headers** — HSTS, Permissions-Policy, the Content-Security-Policy builder and the cross-origin isolation trio (the basic header trio stays free)
* **Priority Sync** — the deeper, frequently-updated, Ed25519-signed WAF Paranoia-Level-2/3 rulesets plus the live bot-IP-range and disposable-domain feeds
* Multi-site dashboard, priority sync (daily blacklist download), 90-day log retention, e-mail support (48 h SLA)
* Prepaid top-up bundles (SMS and mail) available for heavy months

= Business (39 €/month, 389 €/year — up to 15 domains per licence) =

* 100,000 checks/day, 5,000 reports/day
* **2,500 mail/month + 75 SMS/month included**
* Everything in Professional, plus white-label (logo, copy, mail templates), the WooCommerce complete integration, full WP-CLI surface and role-based login-time restrictions
* **Audit event trail** — append-only user-lifecycle log (logins, password resets, profile updates, role changes including the acting user, new-IP alerts) with filters and CSV/JSON export
* 1-year log retention, weekly security PDF report, GDPR data-export tool, priority support (12 h SLA)
* **Multi-bookable:** book Business x2–x20 to scale domains, API quota and 2FA mail/SMS with the licence count — a volume discount applies automatically

= Enterprise (custom, from ~663 €/month) =

* Unlimited checks and reports, custom mail/SMS quotas, custom domain limit
* Custom AVV / DPA terms, dedicated onboarding, phone support (4 h response)

**Bundles (PRO+ only, refundable until first use):** 50/200/500-SMS bundles (14.90 / 49.90 / 99.90 €), 1k/5k/25k-mail bundles (4.90 / 14.90 / 49.90 €). All prices VAT-inclusive (Stripe `tax_behavior = inclusive`).

What stays Free regardless of plan: all 16 detection sensors, the WAF engine with its baseline ruleset, verified-bot detection, disposable-email blocking, the comment honeypot, the basic security headers, the TOTP / Passkey / Email 2FA methods, the password-reset gate, the recovery-code system, progressive block escalation, every dashboard, every export, the entire plugin source. A short, explicit list of what does need a paid plan: SMS 2FA (managed relay), WooCommerce frontend 2FA, Hardening Mode, advanced security headers (HSTS / CSP / cross-origin isolation), Priority Sync (the deeper WAF rulesets and live feeds), the audit event trail (Business), the managed mail relay quota, higher API quotas, multi-site management, white-label and the GDPR export tool. The plugin works fully offline in Local Shield mode — no plan, no account, nothing leaves your site.

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

* **8 dedicated tables** under the `wp_reportedip_hive_` prefix: `logs`, `blocked`, `whitelist`, `attempts`, `api_queue`, `stats`, `trusted_devices`, `audit_log`.
* **Schema v9**, auto-migrated step-by-step on plugin update; opt-in delete on uninstall.
* All secrets at rest (TOTP seeds, phone numbers) sealed with libsodium (OpenSSL fallback). Plain user-meta storage is never used for credentials.

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

1. Download the production ZIP — **always pick the `reportedip-hive.zip` asset**:
   * Direct link (always latest): [github.com/reportedip/reportedip-hive/releases/latest/download/reportedip-hive.zip](https://github.com/reportedip/reportedip-hive/releases/latest/download/reportedip-hive.zip)
   * Or open the [latest release page](https://github.com/reportedip/reportedip-hive/releases/latest) and grab `reportedip-hive.zip` from the *Assets* section.
2. WP Admin → *Plugins → Add New → Upload Plugin* → pick `reportedip-hive.zip`.
3. Activate and follow the 10-step setup wizard.

**Do not** use the auto-generated "Source code (zip)" link, nor the *Code → Download ZIP* button on the repository page. Those archives have a top-level folder named `reportedip-hive-X.Y.Z` (with the version) instead of `reportedip-hive/`. WordPress would install the plugin under that versioned slug, breaking in-place updates and producing a duplicate plugin folder on every release. Only the asset `reportedip-hive.zip` is built for installation.

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

* **Three free 2FA methods** — TOTP, Email and Passkey/WebAuthn work on every plan, including the free tier (SMS is the one method that needs a Professional plan, because it rides our managed relay).
* **Progressive block escalation** that adapts to repeat offenders without punishing first-time tripping legitimate users.
* **Cache-plugin-safe by default** — Wordfence in particular has had repeated cache-coupling issues.
* **Privacy by default** — minimal data collection, automatic anonymisation, opt-in community sharing, all secrets encrypted at rest.
* **GPL-2.0, public on GitHub** — read every line, fork it, audit it.

We don't compete with malware scanners. Run one alongside Hive if your stack needs it.

= Is the plugin GDPR-compliant? =

Yes. Lawful basis is documented (Art. 6(1)(f) GDPR), processing is minimised, retention is configurable (default 30 days), anonymisation runs daily after 7 days, and Community Network is strictly opt-in. No usernames, comment content or full user-agents leave your site. A ready-to-paste privacy passage for your own site (German or English) is available at [reportedip.de/dashboard/dsgvo](https://reportedip.de/dashboard/dsgvo), and the plugin registers a suggested text under Tools -> Privacy.

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

Yes — fully, since 2.0.0. On Multisite the plugin is **network-only** (`Network: true`), so per-site activation is hidden by WordPress and the security configuration stays uniform across the network. A single threat decision applies network-wide: cross-site brute-force attempts aggregate into one central counter, and one block locks the IP out of every sub-site. Network Admins get the full settings and an all-sites Logs view; Site Admins on a sub-site get a read-only Status / Logs UI plus two writable per-site overrides (Frontend-2FA slug and additive 2FA-enforcement roles). Cron runs only on the main site. A dedicated PHPUnit-Multisite suite and Playwright projects gate every release against both topologies.

= How do I get support? =

* Documentation: [reportedip.de/docs](https://reportedip.de/docs)
* Bug reports: [GitHub Issues](https://github.com/reportedip/reportedip-hive/issues)
* Security disclosures (do **not** open a public issue): [abuse@reportedip.de](mailto:abuse@reportedip.de)

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
7. **Setup Wizard** — 10-step guided configuration with privacy-first defaults and a celebration on the final step.
8. **API Queue** — Pending and failed report queue with retry, quota status, queue-health indicators.
9. **Promote** — Auto-footer badge configurator and shortcode showcase with live previews.

== Changelog ==

The full structured changelog lives in [CHANGELOG.md](https://github.com/reportedip/reportedip-hive/blob/main/CHANGELOG.md). Highlights:

= 2.1.6 =

Fixed: genuine search crawlers are no longer mislabelled "fake bot". The verified-bot classifier wrongly treated an out-of-range IP as a spoofer and a failed reverse-DNS lookup as proof of forgery, so a real Bing crawler from a /24 missing from the seed (52.167.144.0/24) or any crawler on a host with a flaky resolver was flagged. Classification is now three-state — IP-range match verifies, a foreign-domain PTR is fake, and a missing range or unresolved DNS stays "unknown" and is never flagged; out-of-range IPs fall back to forward-confirmed reverse DNS. New: the MainWP sync reports the WAF drop-in status so a dashboard can flag sites whose extended protection is enabled but not yet running.

= 2.1.5 =

Fixed: a fatal "bit shift by negative number" error in the CIDR matcher when a v4 address was tested against a v6 range (a v6 whitelist entry or bot IP-range feed) — it now rejects mismatched families and out-of-range masks cleanly. Fixed: genuine search crawlers (Googlebot and friends) are no longer auto-blocked as user enumeration when they index author archives — the sensor now exempts verified-crawler user-agents from the IP-block ladder while still serving the 404 that hides the username, so this is SEO-safe. Fixed: loopback and private addresses (127.0.0.1, ::1, RFC1918, link-local) can no longer be mistaken for the client IP via the trusted proxy header, and the API report queue now drops the "unknown" sentinel and all private/reserved ranges before queueing — no more wasted report retries for internal requests.

= 2.1.4 =

Firewall admin UX overhaul: the Overview tab is now a mini-dashboard (per-module status, 7-day activity counters, recent firewall event stream), every tab opens with a short plain-language intro, and a new Server Setup tab gathers every web-server snippet in one place — the WAF auto_prepend_file directive (with a new php.ini / hosting-panel option next to the nginx snippet), the decoy rewrite rules and a server-level export of the configured security headers. Extended Protection setup is now verifiable: the status reports whether the guard actually executed for the current request. The Bot Verification tab shows the verified crawler list and 7-day spoofer counts; the Rule Sync tab brands synced rulesets as delivered by the reportedip.de Rule API. New: specific WAF block reason codes for SSRF, Log4Shell, PHP object injection, NoSQL, XXE, web-shell, CRLF and template injection. Fixed: the basic security headers can be saved again on free plans.

= 2.1.3 =

Fixed: verified-bot detection no longer flags genuine crawlers that connect over IPv6 (the forward-confirmation now resolves AAAA records as well), and facebookexternalhit is verified against Meta's published IP ranges instead of reverse DNS, which Meta does not provide reliably.

= 2.1.2 =

New: a complete firewall layer. A request-inspecting Web Application Firewall (engine + OWASP-Top-10 Paranoia-Level-1 baseline free on every plan, Level 2/3 with Professional, ReDoS-hardened and fail-open) fed by server-delivered, versioned, Ed25519-signed rulesets with a bundled offline baseline; an optional pre-WordPress drop-in that blocks before WordPress loads (Apache/PHP-FPM auto-config, nginx snippet, rebaked immediately on rule sync and whitelist changes, trusted-proxy-header aware); verified-bot detection (official IP ranges, then forward-confirmed reverse DNS — genuine crawlers are never blocked); disposable-email blocking with privacy-relay pass-through; an invisible comment honeypot; a Firewall admin area with per-tab controls and a Rule Sync status view. Also new: detection & hardening score gauges on the dashboard (A+–F grade), security response headers (basic trio free, advanced with Professional, conflict detection), the Business audit event trail (user-lifecycle events including role changes with the acting user, CSV/JSON export, GDPR integration), a firewall step in the setup wizard, and settings export/import coverage for the firewall, headers and audit configuration. Schema v9 adds the audit_log table.

= 2.1.0 =

New: MainWP integration — the plugin is now remote-manageable from a MainWP dashboard (aggregate security metrics sync and API-key provisioning) with no extra child plugin, authenticated through the MainWP Child channel. New: blocked pages now show a correlatable reference code (also sent as the `X-RIP-Ref` header) so a wrongly blocked visitor can quote one short string an admin can match in the logs — no personal data is exposed. The blocked page was rebuilt on the design system (sharp-edged card, inline SVG, no emoji) and fully translated. Fixed: the 2FA allowed-methods and enforced-roles sanitisers ran for every option write (setup wizard, import, WP-CLI), not just the settings form, so a direct write could collapse the methods to TOTP only or wipe the enforced roles; both now detect the form shape and preserve direct writes.

= 2.0.29 =

Security: Hardening Mode now also catches distributed botnets that rotate IPs over several minutes, not just bursts that hit within a single minute. A second detector aggregates distinct IPs and failed logins across a configurable rolling window (default 10 minutes) and tightens the failed-login and reputation thresholds network-wide once the pattern crosses 5 IPs / 20 attempts; the original same-minute burst rule stays in place. The detection window, minimum distinct IPs and minimum total attempts are configurable on the Hardening Mode settings tab. Fixed a multisite bug where coordinated-attack detection and the plugin reset queried a per-site table instead of the network-wide one, leaving detection inert on sub-sites.

= 2.0.28 =

Fewer false positives: the bot allowlist now also exempts WordPress core loopback, uptime monitors (UptimeRobot, Pingdom, Site24x7, StatusCake, BetterStack) and a wider set of search / social crawlers from the 404 and REST burst triggers, and the `Pinterest` / `Slackbot` tokens were broadened to match the real user-agent strings. The scan detector no longer counts missing `css`, `js`, `.map` or `.webmanifest` files toward the scanner threshold. Honeypot-path detection stays active for every user-agent. Business tier copy across the settings card, setup wizard and mode descriptor now states the multi-bookable model (15 domains per licence, bookable x2–x20 with a volume discount). Documentation pass: the free-vs-paid positioning was corrected (the protection core is free; SMS 2FA, WooCommerce frontend 2FA and Hardening Mode need a Professional plan), the multisite FAQ now reflects the network-only support shipped in 2.0.0, and several stale facts (schema version, removed SMS-provider filter, table count, wizard step count, Enterprise price floor) were fixed.

= 2.0.27 =

Multisite Network Admin compatibility: hardcoded `admin_url` references were replaced with context-aware URL resolution, so administrators stay in the Network Admin context when managing network-activated settings, onboarding, 2FA settings or resets. Login-error masking is now keyed on error codes inside the global `$errors` object instead of matching error strings, so 2FA onboarding, password resets and IP/reputation blocks surface their real reason across all languages (German included) while genuine credential errors stay masked. The missing-API-key notice on the Community page was rebuilt on the design-system BEM classes and SVG layout.

= 2.0.25 =

Changed: SMS 2FA is now a Professional feature delivered exclusively through the managed reportedip.de relay. The self-hosted SMS provider option and its three third-party adapters were removed, along with the provider selector, the encrypted provider-credentials store and the per-provider AVV confirmation — the relay AVV is part of the plan subscription. Removed: the `reportedip_2fa_sms_providers` extension filter. Breaking: sites on Free / Contributor (or any tier not running the relay) can no longer send 2FA SMS; affected users fall back to TOTP, Email or a passkey. A schema migration (v8) clears the now-orphaned provider options on upgrade. Also in this release: GDPR / privacy integration — a suggested privacy-policy passage in the WordPress Privacy Policy Guide (Tools -> Privacy), a personal-data exporter/eraser for a user's own login attempts and trusted devices, and a configuration-aware privacy-text generator (German / English) at reportedip.de/dashboard/dsgvo. Fixed dead /privacy, /terms and /legal/avv documentation links. Contact addresses updated: security disclosures go to abuse@reportedip.de, general enquiries to 1@reportedip.de.

= 2.0.22 =

Fixed: with several 2FA methods configured, switching from Email to the SMS tab and submitting a wrong or expired code snapped the page back to Email and discarded the typed code. The challenge now keeps the chosen method across a re-render, so users stay on their tab, see the error and can re-enter. Applies to both wp-login.php and the WooCommerce frontend flow.

= 2.0.21 =

New: Hide-Login probe sensor — when Hide Login is active, repeated direct hits on the old wp-login.php from one IP are blocked on the escalation ladder (and reported to the community), while a single accidental visit stays harmless. Tunable threshold and timeframe on the Login tab. Changed: the 2FA challenge method picker now stacks vertically with full labels on narrow themed login cards instead of truncating to "A…/E…/S…".

= 2.0.20 =

Fixed: tier-change emails ("[Site] <Plan> plan is active") were re-sent on every API refresh of a paid key. The previous tier was read from a 5-minute transient that collapsed to "free" once it lapsed, so each refresh looked like a fresh upgrade. The change baseline is now a durable option, so the mail fires only on a genuine tier change.

Changed: the 2FA login screen no longer auto-sends the email or SMS one-time code. Both delivery methods now start with a "Send code" button, so the user picks a method first — no unsolicited mail/SMS, and no rate limit or relay quota spent on a method the user did not choose. Authenticator app, passkey and recovery codes are unaffected.

Fixed: the setup wizard silently dropped enforced-2FA roles whose slug was not all-lowercase (e.g. membership-plugin roles like "um_Premium-Member"); every selected role is now kept.

Fixed: admin notices rendered unstyled on non-plugin admin pages and the primary button text lost its contrast; a self-contained stylesheet now styles every notice on every admin screen.

Changed: all backend admin notices share one consistent renderer, and the 2FA onboarding wizard was streamlined to show less at each step.

New: the guided 2FA wizard is now reachable directly — both the "2FA recommended" reminder banner and the profile 2FA section link straight into it.

= 2.0.19 =

Fix: a fatal error (PHP 8 TypeError) crashed the 2FA settings tab and the 2FA setup-wizard step when the enforce-roles / allowed-methods options were stored as arrays — reads are now format-tolerant. New: complete German translation (formal address, "Sie"), shipped as de_DE — the plugin now displays in German automatically on German-language sites. Source strings stay English, so other locales are unaffected. A translation-freshness gate was added to the build and CI so the German strings stay in sync with the source on every change.

= 2.0.17 =

Fix: the 2FA-enforcement lockout (onboarding skip quota exhausted) was shown as the generic "Invalid credentials." login error, misleading locked-out admins into resetting a password that was actually fine. The real reason now reaches the login screen, so admins know to use a recovery code, run wp reportedip 2fa reset, or ask an administrator to reset 2FA. The block fires only after the password has already validated, so surfacing it leaks nothing about user existence; genuine credential errors stay masked.

= 2.0.16 =

Promo-frequency rework: a new central `Promo_Manager` caps Pro upgrade hints at ~4 per admin per year and adds a "hide all upgrade hints" kill-switch in Settings → Notifications. The 2FA reminder banner gets a 14-day cooldown (was 30 minutes) and a permanent per-user opt-out. Operational visibility added: a dismissible cap-status notice appears whenever the managed mail/SMS relay hits its monthly cap, and a new quota notifier mails admins once when usage crosses 80 % and once when the cap is reached (per channel, per billing period). Welcome / goodbye mails on plan changes. Local protection, sensors and 2FA suite are untouched.

= 2.0.15 =

Hotfix for multi-recipient admin notifications. `Security_Monitor::send_admin_alert()` builds the recipient field as `implode(', ', $recipients)` — the standard WP_Mail convention. The Hive Relay endpoint (`POST /relay-mail`) on reportedip.de, however, validates a single address per request via `sanitize_email` + `is_email` and HTTP-422s anything that looks like a list — silently dropping every alert when more than one admin is configured. The mailer now splits comma-lists itself, fan-outs one outbound request per recipient, and logs each delivery separately. The local `wp_mail` fallback keeps working unchanged.

= 2.0.14 =

Decoy bait-path list expanded from 16 to 40 entries — adds the full `wp-config.php.*` variant family (`.bak`, `.old`, `.save`, `.orig`, `.swp`, `.txt`, `~`), more `.env*` Backups (`.production.bak`, `.local.bak`), Joomla `configuration.php.bak`, common SQL dumps (`dump.sql`, `database.sql`, `backup.sql`, `db.sql`), `.htpasswd` / `.htaccess.bak`, AWS credentials (`.aws/credentials`, `.aws/config`), SSH keys (`.ssh/id_rsa`, `.ssh/authorized_keys`), private-key files (`id_rsa`, `private.key`, `server.key`). The `.htaccess` rewrite block and both nginx snippets are regenerated from the same list. `is_decoy_path()` learns nested paths (`.aws/credentials`) with the same one-optional-subdir prefix rule the server snippets use, so PHP detection stays consistent with the Apache/nginx rewrite. New nginx exact-match snippet variant added for ISPConfig and managed stacks where the host template emits `location ~ /\.  { deny all; }` before the site's custom directives — exact-match locations have higher nginx priority and survive that ordering.

= 2.0.13 =

Hotfix: every locally auto-blocked offender was silently excluded from the community report. `Database::is_recently_processed()` counted the very block that triggered the report — once the IP landed in `wp_reportedip_hive_blocked`, the helper returned `recently_blocked=true` for the next 24 hours and `queue_api_report()` dropped the row before it ever reached the API. The check is removed: only successful past reports (`api_queue.status=completed`) gate the cooldown now, which is the dedup behaviour the helper is supposed to enforce. Combined with the 2.0.12 Decoy fix, `decoy_pathblock_hit`, `user_enumeration`, `failed_login`, `scan_404` and every other sensor now actually reach the Hive API after an auto-block.

= 2.0.12 =

Hotfix for the 2.0.11 Decoy Path Block: the sensor logged each hit locally but did not actually push it onto the community-report queue. `Logger::log_security_event()` only writes to the local `logs` table — queueing for the Hive API has to go through `Security_Monitor::report_security_event()` explicitly. The decoy hook now calls both, and the event-to-category mapping in `Security_Monitor::$default_category_mapping` has a new entry `decoy_pathblock_hit => [21, 15]` (admin-scanning + reputation). Sites running 2.0.11 will start populating the API queue immediately after the upgrade; older `decoy_pathblock_hit` rows in `logs` cannot be retro-reported (the API queue dedup window would suppress them anyway).

= 2.0.11 =

Decoy Path Block architecture correction. The sensor no longer adds the source IP to the local block table — a single false-positive (legitimate backup plugin, admin testing on the live site, an old crawler probing stale URLs) would otherwise have locked the site out of its own traffic for 24 hours. Each hit is still logged at severity `high` and forwarded to the community-reputation queue, and the visitor still receives a 403 for that one request. Companion change: the plugin now auto-manages an Apache rewrite block inside `.htaccess` (between `# BEGIN ReportedIP Hive Decoy` / `# END ReportedIP Hive Decoy` markers, placed before WordPress's own block). The rewrite routes hits to `index.php` instead of issuing `[F,L]` — that preserves the detection, while still protecting the site against any real bait file that might sit on disk (`.env.backup` left behind by Composer, etc.). nginx users get an equivalent `rewrite ^ /index.php last;` snippet in the Settings tab. The block-duration option `reportedip_hive_decoy_block_hours` is removed; migration v7 cleans up legacy entries from the 2.0.9-era `blocked` table.

= 2.0.10 =

Two fixes to the 2.0.9 Decoy Path Block. Report-only mode is now respected end-to-end: the 403 + `exit` are skipped when the mode is active, so audits keep getting the `decoy_pathblock_hit` log entry without any user-visible block. The path matcher now also recognises bait filenames behind a subdirectory prefix (e.g. `/site-a/.env.backup` on a Multisite subdir install) — the canonical match keeps working unchanged; the basename fallback only triggers when the full path does not already match. New unit-test case covers the Multisite subdir scenario.

= 2.0.9 =

Decoy Path Block — new free-tier sensor that bans the source IP on the very first request to a known bait path (`.env.backup`, `wp-config.old.php`, `db-dump-master.sql.php`, `admin-shell-console.php`, `debug-logs-temp.php` and more). Distinct from the existing scan-detector: legitimate visitors never request these paths, so the first hit IS the attack indicator — no N-of-Y window, no waiting. No physical decoy files are dropped on disk; detection lives entirely in the request pipeline. The Settings tab additionally exposes ready-to-paste `.htaccess` and nginx snippets so admins can move the block to the server level (pre-PHP) for extra hardening; the plugin never writes to server configs itself. Extend the bait list via the `reportedip_hive_decoy_paths` filter. New options `reportedip_hive_decoy_pathblock_enabled` (default on) and `reportedip_hive_decoy_block_hours` (1–168, default 24). New event type `decoy_pathblock_hit` (severity `high`); the 2.0.8 Hardening-Mode log decoration applies automatically when an attack hits during an active hardening window.

= 2.0.8 =

Hardening Mode (Professional plan and higher). When the coordinated-attack sensor spots ≥ 3 IPs / ≥ 20 failed logins in the same minute the plugin scharfschaltet a network-wide hardening window: failed-login threshold tightens from 5 / 15 min to 2 / 5 min, reputation block threshold from 75 % to 60 %. Default duration 60 minutes, configurable 5–360. Realtime trigger now hooks directly into `wp_login_failed` (60-second debounce) so reaction time drops from up to an hour to under a minute; the hourly cron sweep stays as a safety net. New dedicated Settings tab "Hardening Mode" with master toggle, sub-fields are visually disabled while the master is off; tab is gated on the Professional tier with an explicit upsell card on Free / Contributor. Active hardening surfaces as a red node in the WordPress admin bar (countdown + manage link) and visually marks every log row captured during the window with a "Hardening" badge. New events `hardening_mode_activated` (severity high) and `hardening_mode_deactivated` (severity low) record activations and the actor (admin / cli / expired). WP-CLI: `wp reportedip hardening status|activate|deactivate`.

= 2.0.7 =

Hourly API rate-limit is now split into three independent buckets — reputation lookups, report submissions and meta/quota sync — so a bot-driven reputation scan can no longer freeze the report queue or starve quota sync. Caps scale with the active tier (Free 150/h reputation, Professional 3 000/h, Business 12 000/h, Enterprise unlimited) and follow the daily quota in the PRICING-PLAN with a 3× spike factor. The "Max API calls per hour" setting accepts `0` as "auto (tier-bound)" and is reset to `0` on every install via migration v6. When the community layer is rate-limited, an inline banner makes the fallback explicit — local firewall (sensors, blocks, logs, queue) stays fully active, only outgoing community calls pause until the hourly counter resets. New `Mode_Manager::default_api_rate_limits_for_tier()`, `get_api_rate_limit_snapshot()` and `is_community_layer_degraded()` helpers are the canonical contracts for tier-gated rate-limit behaviour.

= 2.0.6 =

Setup wizard now opens on a fresh activation again — the activation hook wrote a `set_site_transient()`, the redirect guard consumed it with `get_transient()`, so the read never matched the write on single-site or multisite. Both halves now use `_site_transient_`. Admin-email burst protection: the existing per-(IP × event_type) 60-minute cooldown stays, plus a new global per-event_type cap (default 15 min, option `reportedip_hive_notify_event_cap_minutes`). Distributed brute-force from many IPs no longer floods the operator's inbox — additional alerts of the same type are folded into a "Burst suppression: N additional alerts (M distinct IPs) since …" digest line on the next outgoing mail. Suppressed alerts continue to land in the logs as `notification_event_cap_suppressed`.

= 2.0.5 =

Search engine and AI crawler User-Agents (Googlebot, Bingbot, DuckDuckBot, Applebot, YandexBot, GPTBot, ChatGPT-User, ClaudeBot, PerplexityBot, Amazonbot, CCBot, MetaExternalAgent, …) are now excluded from the 404 burst trigger and the REST burst trigger so legit crawls over stale URLs cannot push the bot into the progressive block ladder. Honeypot-path detection (`.env`, `wp-config.php.bak`, `.git/config`, `/phpmyadmin/`, …) stays active for **all** visitors — a "Googlebot" request to `/.env` IS the attack indicator and still triggers immediately. New `ReportedIP_Hive_Bot_Allowlist` class (extensible via `reportedip_hive_bot_allowlist_patterns` filter), master toggle `reportedip_hive_bot_allowlist_enabled` (default on) in Settings → Protection → 404 / Scanner detection.

= 2.0.4 =

SMS-2FA delivery is no longer gated by a client-side EU country-code whitelist. The plugin validates E.164 format and forwards every number to the managed relay, which returns HTTP 422 `country_not_supported` for the few destinations it does not serve — surfaced to the 2FA UI as a typed error so users can pick TOTP, Email or a passkey instead. UI, wizard and docs copy reworded from "EU-only" to "worldwide via managed relay". `Phone_Validator::is_eu()` / `::get_country_code()` kept as no-op shims for any out-of-tree caller; the `DEFAULT_EU_CODES` constant, `get_whitelist()` helper and the `reportedip_hive_eu_phone_country_codes` option/filter are removed.

= 2.0.1 =

**Password-reset 2FA challenge: visible errors, automatic dispatch, shared verifier.** Three real bugs on the reset-flow challenge page (`wp-login.php?action=reportedip_2fa_reset`) and one drift-prevention refactor:

* **Wrong code now shows an error.** The challenge used to render verification failures only via `login_header()`. Plugins that filter `wp_login_errors` would strip the message, and the WP-default `#login_error` block sat outside the card. Errors now render inline as a `rip-alert--danger` banner inside the `.rip-2fa-challenge` card and survive any `wp_login_errors` filter.
* **Initial SMS / email is dispatched on first land.** The send used to run only when `?method=sms` was already in the URL — which never happened on the first redirect. Users with SMS-only 2FA saw an empty form. Initial dispatch now happens in `on_validate_reset()` before the redirect, mirroring the login flow.
* **Send-failures surface to the user.** `WP_Error` returned by `Two_Factor_SMS::send_code()` / `Two_Factor_Email::send_code()` is no longer discarded — it lands in the inline error banner with the provider's reason string and is logged under the new `2fa_reset_send_failed` event.
* **Server-side resend.** `?resend_sms=1` / `?resend_email=1` URL parameters trigger a fresh OTP without losing the challenge session. The template renders a "Resend the SMS / email code" link with the provider-side cooldown.
* **Method-health assessment.** `assess_methods_health()` checks each eligible method for usability before render: TOTP secret presence + decryptability, SMS provider readiness + stored phone number, WebAuthn provider class. Methods that fail are removed from the picker. When **none** of the methods is usable the gate hard-stops with a new `2fa_reset_no_usable_method` event, an admin-mail listing what is broken, and a dedicated "contact your administrator" page — instead of dropping the user into an "Invalid code" loop.
* **Shared verifier.** The per-method verification switch (TOTP / SMS / Email / WebAuthn / Recovery) is extracted into `ReportedIP_Hive_Two_Factor_Verifier::verify_method()`. Both the login and reset surfaces delegate to it so a fix to one cannot silently miss the other. Verified: PHPCS clean, PHPStan level 5 *No errors*, 453/453 single-site PHPUnit.

= 2.0.0 =

**WordPress Multisite support — breaking change.** ReportedIP Hive is now fully network-aware. The plugin can only be network-activated on Multisite (`Network: true`); per-site activation is hidden by WordPress. All seven plugin tables move to `$wpdb->base_prefix` so a single threat decision applies network-wide: cross-site brute-force attempts aggregate into one central `attempts` row, and one `blocked` entry locks the IP out of every sub-site. Site Admins on a sub-site see a read-only Status / Logs UI plus a single 2FA Site Settings page with two writable overrides (Frontend-2FA slug per-site, plus additive 2FA enforcement roles — site admins cannot drop a role the network requires). Super Admins are forced into 2FA setup unconditionally via a new `reportedip_hive_2fa_enforce_super_admins` toggle (default on), and the trust cookie now widens to `SITECOOKIEPATH` so a single trust decision carries across the whole network. Cron is scheduled only on the main site (`is_main_site()`-guarded). New `Schema`, `Migration_Manager` and `Option_Routing` service classes mediate every Multisite-relevant access; 353 plugin option calls were rewired through the routing layer in one sweep. Versioned migration system with atomic site-option lock auto-upgrades single-site v1.x → v5 transparently on the first admin visit (only `ALTER TABLE … ADD COLUMN blog_id` with default 1 — no data movement). Existing Multisite installs that ran Hive on individual sites without `Network: true` get a one-time option-promotion pass into sitemeta. Existing trusted_devices rows have `expires_at` capped at NOW()+24h so users get a smooth re-trust window after the cookie path widens. PHPUnit Multisite suite (`tests/Multisite/` + `phpunit-multisite.xml`) and Playwright E2E projects (`tests/e2e/`, single-site + multisite) plus dedicated CI matrix jobs gate every change against both topologies.

**Post-beta-1 hardening.** The Network Admin Settings page now uses a custom `network_admin_edit_*` save handler — Multisite was silently dropping every Settings-API form submission into the main site's wp_options instead of sitemeta, so the API key, 2FA Hard-block roles, WooCommerce frontend toggles and many other options bounced back to their previous value on every save. Shipped with `Option_Routing` rewires for the call sites that the beta-1 sweep missed (Mode_Manager, Two_Factor_Frontend, Two_Factor_Recommend, Two_Factor_SMS, Two_Factor_Reset_Gate, Two_Factor_WC_Notice, Tier_Upgrade, API_Client, Cache, Setup_Wizard, activation hook). Site-2FA UI redesigned in `rip-settings-section` style with a full Network-state read-out and clear "enforced by network" markers on the additional-roles checklist. Per-blog resolve cache isolation (`switch_to_blog()` no longer leaks resolved overrides). Default Frontend-2FA challenge slug pinned at `reportedip-hive-2fa` (was briefly `2fa-login` in beta-1) so existing installs keep their public URL. Tooling: PHPStan bumped to 2.1, `szepeviktor/phpstan-wordpress` to 2.0, twelve newly-flagged errors fixed at the source. Verified: PHPCS clean, PHPStan 2.1 *No errors*, 435/435 single-site PHPUnit, 19/19 multisite PHPUnit, 105/105 option-roundtrip on both Docker stacks.

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

Managed mail and SMS relay — Professional / Business / Enterprise plans now route 2FA mails and OTP-SMS through reportedip.de instead of needing their own SMTP / SMS contract. Mail relay falls back transparently to local `wp_mail()` on cap (HTTP 402) or backoff (HTTP 429) so 2FA flows never break. SMS relay surfaces typed `WP_Error`s so the 2FA UI can encourage another method instead of silently switching. New `ReportedIP_Hive_Phone_Validator` validates E.164 format on the client; routing decisions live on the server. Progressive SMS backoff ladder (0s → 2m → 5m → 15m → 30m → 60m) mirrors the service-side rate-limiter. Setup wizard slimmed from 8 to 7 steps. Scan-detector path matcher refactored to a single pass.

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

= 2.0.28 =
Fewer false-positive blocks of legitimate crawlers and asset 404s, Business multi-bookable tier copy, and a documentation pass correcting the free-vs-paid positioning. No breaking changes.

= 2.0.27 =
Multisite Network Admin URL fixes and language-independent login-error masking (German included). No breaking changes.

= 2.0.25 =
SMS 2FA is now a Professional feature via the managed reportedip.de relay; the self-hosted SMS providers are removed. Sites that sent SMS via a self-configured provider or on a non-paid plan lose it — users fall back to TOTP, Email or a passkey. A v8 migration removes the old options.

= 2.0.24 =
Adds GDPR tooling: a WordPress Privacy Policy Guide entry, a personal-data exporter/eraser for login attempts and trusted devices, and a privacy-text generator. Fixes dead legal links in the documentation. No breaking changes.

= 2.0.19 =
German translation (de_DE, formal) added — the admin UI now displays in German on German-language sites. Also fixes a fatal error on the 2FA settings tab. No breaking changes.

== Privacy Policy ==

**Data stored locally**

* IP addresses of blocked or suspicious visitors
* Security event timestamps and event types (login failures, spam attempts, XMLRPC abuse, …)
* Optional, off by default: truncated user-agent strings (max. 50 characters) and request paths
* Encrypted at rest: 2FA TOTP seeds and user phone numbers (libsodium with OpenSSL fallback)

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

Full privacy information: [reportedip.de/datenschutzerklaerung/](https://reportedip.de/datenschutzerklaerung/). A ready-to-paste privacy passage for your own site — German or English, tailored to the modules you use — is available at [reportedip.de/dashboard/dsgvo](https://reportedip.de/dashboard/dsgvo).

== External Services ==

This plugin connects to external services only when explicitly configured. *Local Shield* mode works completely offline — none of the endpoints below are contacted unless the corresponding feature is enabled.

= ReportedIP Community Network API =

* Service URL: `https://reportedip.de/wp-json/reportedip/v2/` (endpoints `verify-key`, `check`, `report`, `whitelist`, `categories`)
* Purpose: IP reputation lookups, anonymised threat reporting, whitelist sync, threat-category catalogue
* Default: off — only active in Community Network mode AND with a configured API key
* Data transmitted: IP addresses, optional event categories and timestamps, the API key, the site domain
* Terms: [reportedip.de/nutzungsbedingungen/](https://reportedip.de/nutzungsbedingungen/)
* Privacy / DPA: [reportedip.de/datenschutzerklaerung/](https://reportedip.de/datenschutzerklaerung/)

= ReportedIP Managed Mail Relay =

* Service URL: `https://reportedip.de/wp-json/reportedip/v2/relay-mail`
* Purpose: route 2FA verification mails through the reportedip.de transactional mail infrastructure (clean SPF / DKIM / DMARC)
* Default: off — only available for Professional, Business and Enterprise plans, only when the user enabled the email 2FA factor; on any error (cap reached HTTP 402, recipient backoff HTTP 429, network error) the plugin falls back to the local `wp_mail()` transport so the 2FA flow never breaks
* Data transmitted: recipient email, subject, HTML and plain-text body, headers, optional Reply-To, the site domain
* Privacy / DPA: [reportedip.de/legal/avv/](https://reportedip.de/legal/avv/)

= ReportedIP Managed SMS Relay =

* Service URL: `https://reportedip.de/wp-json/reportedip/v2/relay-sms` (and `relay-quota` for monthly usage display)
* Purpose: deliver 2FA OTP messages without requiring the site operator to maintain their own SMS-provider contract
* Default: off — only available for Professional, Business and Enterprise plans, only when a user actively enrolled SMS as a 2FA factor; routing is worldwide except for a small number of high-cost destinations that are unsupported by the managed relay (HTTP 422 with code `country_not_supported` is returned to the plugin in that case)
* Data transmitted: recipient phone number (E.164), the verification code, expiry minutes, language code, the site domain
* Privacy / DPA: [reportedip.de/legal/avv/](https://reportedip.de/legal/avv/)

= ReportedIP Rule Sync =

* Service URL: `https://reportedip.de/wp-json/reportedip/v2/rules/{ruleset}` (one call per ruleset: `waf`, `bot_signatures`, `disposable_domains`, `scan_paths`)
* Purpose: fetch signed firewall rule updates; the bundled baseline rulesets stay active without any connection, and Professional plans receive the deeper, frequently-updated rulesets through this channel
* Default: off — only active in Community Network mode AND with a configured API key AND the Rule Sync toggle enabled; runs every six hours via cron, and conditional `If-None-Match` requests return HTTP 304 when nothing changed
* Data transmitted: the API key, the current ETag and the site domain; each downloaded ruleset carries an Ed25519 signature that the plugin verifies against a bundled public key before applying it
* Terms: [reportedip.de/nutzungsbedingungen/](https://reportedip.de/nutzungsbedingungen/)
* Privacy / DPA: [reportedip.de/datenschutzerklaerung/](https://reportedip.de/datenschutzerklaerung/)

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
* Default: on — the password policy and its HIBP range check are both enabled by default; the check runs server-side at password change for users covered by the policy. Disable via the option `reportedip_hive_password_check_hibp`. (No visitor IP is sent — the WordPress server queries HIBP with only the 5-char hash prefix.)
* Data transmitted: only the first 5 hex characters of the SHA-1 hash of the proposed password (the password itself is never sent and cannot be reconstructed)
* Privacy: [haveibeenpwned.com/Privacy](https://haveibeenpwned.com/Privacy)
* Soft-fail behaviour: a network error never blocks a password change

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

Want to help translate into more languages? Open an issue on [GitHub](https://github.com/reportedip/reportedip-hive/issues) or contact [1@reportedip.de](mailto:1@reportedip.de).

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
* timely or reliable delivery of email or SMS one-time passwords through the local mail transport or the optional managed mail/SMS relay;
* compliance with any specific legal, regulatory or contractual obligation that applies to the operator of the protected site.

= No liability =

In no event will the copyright holder, or any other party who modifies and/or conveys the program as permitted under the GPL, be liable to you for damages, including any general, special, incidental or consequential damages arising out of the use or inability to use the program (including but not limited to loss of data, data being rendered inaccurate, losses sustained by you or third parties, lost revenue, business interruption, lockout from your own administrative interface, or a failure of the program to operate with any other programs).

Operating ReportedIP Hive is solely the responsibility of the site operator. The operator is responsible for:

* maintaining backups of WordPress, the database and the plugin configuration before installation, upgrades and configuration changes;
* understanding the consequences of enabling 2FA enforcement, hide-login, password-reset gating and IP blocking — in particular the documented edge case where an account with only email-2FA and no recovery codes is intentionally locked out of the password-reset flow until an administrator intervenes;
* maintaining recovery procedures (recovery codes, alternative second factors, WP-CLI access, server-level access) so that a misconfiguration or an upstream service outage does not cause permanent loss of access to the site;
* obtaining and maintaining any data-processing agreements, terms of service or end-user disclosures required by applicable law for the SMS, email or threat-intelligence services they choose to use.

To help with that end-user disclosure, a configuration-aware privacy-policy generator (German / English) is provided at [reportedip.de/dashboard/dsgvo](https://reportedip.de/dashboard/dsgvo), and a suggested passage is registered in the WordPress Privacy Policy Guide (Tools -> Privacy). Both are **templates only**, provided without warranty, and do **not** constitute legal advice or replace your own review — the no-warranty and no-liability terms above apply to them in full.

= Security disclosures =

If you believe you have discovered a security issue in ReportedIP Hive, **please do not open a public GitHub issue**. Send the details to [abuse@reportedip.de](mailto:abuse@reportedip.de). We will acknowledge receipt within five business days.

= Recommended posture =

Treat ReportedIP Hive as one layer in a defence-in-depth setup. Pair it with:

* offsite, versioned backups (database + uploads + plugin configuration);
* a malware scanner of your choice — Hive deliberately does not include one;
* a server-level firewall (Cloudflare WAF, Nginx `deny`, fail2ban) for blocking on cached public pages, which the plugin cannot reach by design;
* a reasonable patch cadence — install updates as they are released, run `./run.sh check-all` (or your CI equivalent) before upgrading on production-critical sites.

By installing or activating this plugin you confirm that you have read and accepted the terms above and the GPL-2.0-or-later licence under which the plugin is distributed.
