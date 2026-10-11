=== ReportedIP Hive ===
Contributors: reportedip, patrickschlesinger
Donate link: https://reportedip.com
Tags: security, firewall, brute-force, two-factor, multisite
Requires at least: 5.9
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 2.1.73
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Update URI: https://github.com/reportedip/reportedip-hive

Community-powered WordPress security: 16 attack sensors, 4 2FA methods, threat sharing, fully Multisite-aware. GDPR-first. Made in Germany.

== Description ==

**Every protected site becomes a sensor. When one site is attacked, every other site can refuse the same attacker, before the password is even checked.**

ReportedIP Hive is a complete security plugin for serious WordPress sites: 16 detection sensors, four 2FA methods (TOTP, Passkey/WebAuthn and email in every plan; SMS on Professional via the managed relay), progressive block escalation, and an opt-in community-intelligence network. Engineered in Germany with privacy as the design principle, not a checkbox.

The entire detection and identity core is **free, GPL-2.0 and complete**, every sensor, the core 2FA methods, progressive blocking, the password-reset gate, every dashboard and export. Paid plans add managed relays, multi-site management and a few advanced modules on top (see *Plans* below); they never gate the core protection.

Two ways to run:

* **Local Shield**, works fully offline; nothing ever leaves your site.
* **Community Network**, free account at [reportedip.com](https://reportedip.com) lights up real-time IP reputation lookups and anonymised threat sharing.

== Features at a glance ==

The full reference with every default, hook and command lives in the [README on GitHub](https://github.com/reportedip/reportedip-hive#readme) and in the [plugin documentation](https://reportedip.com/docs/wordpress-plugin/).

* **16 detection sensors, every one tunable.** Failed logins (5 in 15 min), password spray, comment spam, XML-RPC and application-password abuse, a REST rate limit, user-enumeration defence, 404 and scanner detection with instant blocks on bait paths, geographic login anomalies, a password policy with an optional Have-I-Been-Pwned check and the WooCommerce login forms.
* **Web Application Firewall in two layers.** A request-inspecting engine inside WordPress plus an optional pre-WordPress guard (Extended Protection) that applies the same rules, exceptions, whitelist and IP blocks before WordPress loads. Signed rulesets, Paranoia Level 1 free.
* **Verified bot detection.** Googlebot, Bingbot and the other large crawlers are confirmed through their official address ranges or forward-confirmed reverse DNS; a spoofed user-agent buys nothing, a genuine crawler is never blocked.
* **Two-factor authentication.** TOTP, passkeys and security keys (WebAuthn, YubiKey), e-mail codes and recovery codes in every plan; SMS through the managed relay on Professional. Trusted devices, an enrolment wizard, enforcement per role and a password-reset gate that a stolen mailbox cannot bypass.
* **Form protection.** A cache-safe execution proof on the comment, sign-up and password-reset forms and on Contact Form 7, the community threat check on the same forms, disposable mail addresses refused, a scored comment spam filter and an API for your own forms. Adapters for WPForms, Gravity Forms, Forminator, Formidable, Elementor Forms and Ultimate Member on Business.
* **Registration defence.** Prohibited usernames, e-mail allow and block rules, a sign-up rate limit and disposable-mail detection on every sign-up surface.
* **Progressive blocks.** 5 minutes for a first offence, climbing to 7 days for repeat offenders, so a typo never costs a day.
* **Access lockdown.** REST for signed-in users or chosen roles, XML-RPC, feeds, wp-admin for guests, PHP in uploads and version fingerprints, each a switch.
* **Hide Login, security headers, Hardening Mode, Tor exit-node blocking** (the last two on Professional).
* **Privacy first.** GDPR-minimal logging, retention and anonymisation windows, secrets encrypted at rest, community sharing opt-in.
* **Operations.** A system readiness register, a security score, an audit trail (Business), MainWP and fleet management, WP-CLI for IPs, blocks, 2FA and status, full Multisite support.

What it does not include: a malware scanner or file-integrity monitor, a Cloudflare API integration and payment-fraud scoring.

== Plans (optional, comfort only) ==

The detection and identity core is free, GPL-2.0 and complete in every mode: all sensors, the WAF engine with its baseline ruleset, verified-bot detection, TOTP, passkey and e-mail 2FA, the password-reset gate, progressive blocking, the form protection on the WordPress forms and Contact Form 7, every dashboard and export. Local Shield works fully offline without any account.

* **Free / Contributor (0 €):** 1 domain, 1,000 reputation checks and 50 reports a day, ten entries per registration list, 30-day log retention. Contributor adds Priority Sync with the Paranoia Level 2 ruleset, refreshed weekly.
* **Professional (14.90 €/month, 149 €/year, up to 3 domains):** 25,000 checks and 1,000 reports a day, managed mail relay (500 mails a month) and SMS relay (25 a month), WooCommerce storefront 2FA, Hardening Mode, advanced security headers, adaptive 2FA triggers, unlimited registration rules, the computation check on forms, daily Priority Sync with Paranoia Level 3.
* **Business (39 €/month, 389 €/year, up to 15 domains):** 100,000 checks and 5,000 reports a day, 2,500 mails and 75 SMS a month, white-label, the audit trail, the form adapters for WPForms, Gravity Forms, Forminator, Formidable, Elementor Forms and Ultimate Member, advanced security keys, account blocking and the session manager, cloud fleet management.
* **Enterprise (custom):** unlimited checks and reports, custom quotas and terms.

Details, bundles and how domains are counted: [reportedip.com](https://reportedip.com).

== Installation ==

= Manual (recommended) =

1. Download the production ZIP, **always pick the `reportedip-hive.zip` asset**:
   * Direct link (always latest): [github.com/reportedip/reportedip-hive/releases/latest/download/reportedip-hive.zip](https://github.com/reportedip/reportedip-hive/releases/latest/download/reportedip-hive.zip)
   * Or open the [latest release page](https://github.com/reportedip/reportedip-hive/releases/latest) and grab `reportedip-hive.zip` from the *Assets* section.
2. WP Admin → *Plugins → Add New → Upload Plugin* → pick `reportedip-hive.zip`.
3. Activate and switch protection on in the quickstart.

**Do not** use the auto-generated "Source code (zip)" link, nor the *Code → Download ZIP* button on the repository page. Those archives have a top-level folder named `reportedip-hive-X.Y.Z` (with the version) instead of `reportedip-hive/`. WordPress would install the plugin under that versioned slug, breaking in-place updates and producing a duplicate plugin folder on every release. Only the asset `reportedip-hive.zip` is built for installation.

= Composer (for developers) =

`composer require reportedip/reportedip-hive`

= Updates =

The plugin ships a built-in update checker that polls the GitHub release feed every 12 hours. Updates appear in the standard *Plugins* list and install with a single click, exactly like a wordpress.org plugin, but served directly from the publisher.

ReportedIP Hive is **not** distributed through wordpress.org. All releases are signed and tagged on GitHub: [github.com/reportedip/reportedip-hive/releases](https://github.com/reportedip/reportedip-hive/releases). For instant updates, hit *Plugins → Check for updates*.

= Configuration =

1. **Pick a mode**, *Local Shield* (offline) or *Community Network* (paste your free API key from [reportedip.com](https://reportedip.com)).
2. **Tune protection**, adjust thresholds and pick a block-duration strategy (progressive ladder vs. fixed length).
3. **Enable 2FA**, pick methods and roles to enforce, set the grace period and max-skip counter.
4. **Set privacy preferences**, retention, anonymisation, detail level. The "GDPR Minimal" preset is one click.
5. **Optionally hide wp-login.php** behind a custom slug.
6. **Optionally show the community badge** in your footer or via shortcode.

== Frequently Asked Questions ==

= Do I need a ReportedIP.de account? =

No. *Local Shield* works completely offline with no account and no external calls. A free account unlocks *Community Network*, which adds shared threat intelligence and coordinated-attack detection.

= Which security keys are supported? =

Every FIDO2/WebAuthn authenticator: hardware keys such as the YubiKey 5 series (USB-A, USB-C, Lightning, including NFC models tapped against a phone) and the Security Key by Yubico line, plus platform passkeys like Face ID, Touch ID and Windows Hello. One key per account is free and can be named, renamed and removed in the profile key manager. The Business plan adds Advanced Security Keys: several keys per account (keep one as a backup), automatic model detection and key-lifecycle email alerts. Older U2F-only keys (CTAP1) are not officially supported.

= Can I manage settings across many sites at once? =

Yes. Hive carries its own MainWP child bridge, so you can manage every install from one MainWP dashboard with no extra child plugin. On the Business plan you can do the same from the reportedip.com fleet dashboard: define one security policy, override single fields per site, push with one click, and see immediately when a site drifts from the policy. The reportedip.com transport is strictly opt-in per site (a toggle on the General settings tab, off by default) and every push is cryptographically signed, bound to your site and account, and replay-protected. Both dashboards manage the same 63 settings through the same validation pipeline. See the Cloud Fleet Management guide in the plugin's docs folder.

= How is this different from Wordfence / Sucuri / iThemes Security? =

* **Three free 2FA methods**, TOTP, Email and Passkey/WebAuthn work on every plan, including the free tier (SMS is the one method that needs a Professional plan, because it rides our managed relay).
* **Progressive block escalation** that adapts to repeat offenders without punishing first-time tripping legitimate users.
* **Cache-plugin-safe by default**, Wordfence in particular has had repeated cache-coupling issues.
* **Privacy by default**, minimal data collection, automatic anonymisation, opt-in community sharing, all secrets encrypted at rest.
* **GPL-2.0, public on GitHub**, read every line, fork it, audit it.

We don't compete with malware scanners. Run one alongside Hive if your stack needs it.

= Is the plugin GDPR-compliant? =

Yes. Lawful basis is documented (Art. 6(1)(f) GDPR), processing is minimised, retention is configurable (default 30 days), anonymisation runs daily after 7 days, and Community Network is strictly opt-in. No usernames, comment content or full user-agents of your visitors leave your site; in Community mode each API request identifies the installation itself with its site address and plugin/WordPress version (wp.org-style, used for licence and support purposes). A ready-to-paste privacy passage for your own site (German or English) is available at [reportedip.com/dashboard/dsgvo](https://reportedip.com/dashboard/dsgvo), and the plugin registers a suggested text under Tools -> Privacy.

= Will this slow down my site? =

No. ETag-based reputation caching, per-request IP cache, queued reports processed by cron in the background, and a `init` priority 1 hook make blocked-IP rejection a few microseconds. The REST monitor skips authenticated users so the Block Editor never trips the rate-limit.

= Does it conflict with my page-cache plugin? =

No. The 403 block-page sets `DONOTCACHEPAGE` and the no-store header set respected by WP Rocket, W3TC, WP Super Cache and LiteSpeed. Authentication paths (`wp-login.php`, `wp-admin/`, `wp-json/`, XMLRPC) are excluded from caching by all of these plugins by default, your blocks fire there normally.

= What happens when my daily lookup allowance runs out? =

Nothing is refused. Every failure mode of the community lookup, an exhausted allowance, a rate limit, a timeout, an unreachable network or a missing key, reads as "no opinion", and the submission is judged by the local signals alone, exactly as it was before the check existed. The same holds on the sign-in page. A community verdict is extra evidence; losing it costs a site that evidence, never its ability to accept comments, sign-ups or password resets.

= What happens to visitors who browse without JavaScript? =

They can still comment. The form execution proof treats a missing proof as a strong scoring signal, not as a refusal, so the comment is filed as spam for review rather than thrown away, and an address is never blocked over that reason alone. Sign-up and password reset do ask for JavaScript and say so in the error message, because those two surfaces have no review folder to fall back on. If that trade-off does not suit your audience there are three ways out, in increasing order of bluntness: leave the two login forms out with the second switch under Protection → Form Protection, turn on report-only mode to log everything and refuse nothing, or switch the layer off entirely, either on the same card or with `REPORTEDIP_HIVE_DISABLE_FORM_PROOF` in `wp-config.php`.

= Can I test thresholds without blocking real users? =

Yes. Enable **Report-Only mode** under *Protection → Blocking & Escalation*. Every event is logged exactly as it would have been blocked, but no IP is ever rejected. Ideal for tuning thresholds against live traffic before flipping enforcement on.

= I'm getting 403s on Real Cookie Banner / Complianz / Borlabs. Is it Hive? =

In 1.5.0 we baked the four most common cookie-consent REST namespaces into the default REST-monitor bypass list. Update to 1.5.0+ and the issue is gone. For a custom consent stack, add your namespace via the `reportedip_hive_rest_bypass_routes` filter.

= What happens if the API is unreachable? =

Nothing breaks. Local blocking and the cached reputation continue working; queued reports retry automatically (up to 3 attempts, then surfaced in the API Queue tab as failed). Local Shield is unaffected.

= I lost my 2FA device. How do I get back in? =

Use one of the ten recovery codes you saved at setup. Each is single-use. With shell access, `wp reportedip 2fa reset <user>` removes 2FA entirely for the affected account.

= A legitimate visitor got blocked. How do I release the IP from the shell? =

Run `wp reportedip unblock <ip> --reset-attempts`. The flag matters: without it the attempt counters survive the unblock, and a still-exceeded threshold re-blocks the address on the very next request. If the address should never be blocked again, whitelist it instead, `wp reportedip whitelist add <ip> --reason="customer"` lifts the block and wins over every protection layer. For connections with rotating addresses (common with IPv6), whitelist the prefix as a CIDR range (e.g. `2001:db8::/56`) rather than the single address.

= Is multisite supported? =

Yes, fully, since 2.0.0. On Multisite the plugin is **network-only** (`Network: true`), so per-site activation is hidden by WordPress and the security configuration stays uniform across the network. A single threat decision applies network-wide: cross-site brute-force attempts aggregate into one central counter, and one block locks the IP out of every sub-site. Network Admins get the full settings, an all-sites Logs view and the audit trail with a site filter; Site Admins on a sub-site get a read-only Status / Logs UI, the audit trail of their own site (Business) plus two writable per-site overrides (Frontend-2FA slug and additive 2FA-enforcement roles). Cron runs only on the main site. A dedicated PHPUnit-Multisite suite and Playwright projects gate every release against both topologies.

= How do I get support? =

* Documentation: [reportedip.com/docs](https://reportedip.com/docs)
* Bug reports: [GitHub Issues](https://github.com/reportedip/reportedip-hive/issues)
* Security disclosures (do **not** open a public issue): [abuse@reportedip.com](mailto:abuse@reportedip.com)

= How does Hive work under the hood? =

A short architectural map for evaluators:

**Two operating modes.**

* **Local Shield**, fully offline. Every sensor decision is local; no outbound HTTP. The 2FA-mail-relay and reputation-check endpoints are never touched.
* **Community Network**, Local Shield plus opt-in IP-reputation lookups against `reportedip.com/wp-json/reportedip/v2/check` and queued threat reports against `/report`. Lookups are cached (24 h positive, 2 h negative); reports are batched by cron. Every Community-mode request identifies the installation wp.org-style (site address plus plugin and WordPress version in the User-Agent and an `X-Rip-Site` header) so the service can count the domains per licence.

**Request lifecycle.**

1. **`init` priority 1.** The very first thing Hive does on every front-end request is check the IP against the local block table. Blocked IPs receive a 403 with `DONOTCACHEPAGE` + `Cache-Control: no-store` headers and exit before any other plugin's `init` handler runs.
2. **`wp_authenticate_user` priority 10.** Reputation check (Community-mode only) and IP-block check before the password is verified, failed-but-cheap, blocked attackers never trigger a `wp_login_failed` action.
3. **`authenticate` priority 99.** After WordPress core verifies the password, the 2FA orchestrator decides whether a second factor is required, sends an OTP if needed, and intercepts with a session-bound nonce + `wp-login.php?action=reportedip_2fa` redirect.
4. **`validate_password_reset` priority 5 + `password_reset` priority 5.** Since 1.6.5: a non-email second factor is required before any new password is persisted via the WordPress "lost password" flow. Email is excluded from the eligible methods because it is the channel that delivered the reset link itself.

**Storage.**

* **9 dedicated tables** under the `wp_reportedip_hive_` prefix: `logs`, `blocked`, `whitelist`, `attempts`, `api_queue`, `stats`, `trusted_devices`, `audit_log` and `waf_exceptions`.
* **Schema v16**, auto-migrated step-by-step on plugin update; opt-in delete on uninstall.
* All secrets at rest (TOTP seeds, phone numbers) sealed with libsodium (OpenSSL fallback). Plain user-meta storage is never used for credentials.

**Throttle ladder.**

A single failure-counter ladder is shared by every brute-force-style sensor (failed logins, 2FA wrong codes, password-reset wrong codes, application-password failures). 3 fails → 30 s, 5 → 5 min, 10 → 30 min, 15 → 1 h. After the 15th failure the IP is graduated to a real `blocked`-table entry via the canonical `handle_threshold_exceeded()` pipeline, which fires the progressive escalation ladder (5 m → 15 m → 30 m → 24 h → 48 h → 7 d) and, in Community mode, queues an anonymised report.

**Performance budget.**

* **`init` priority-1 IP check**: ~1 indexed SELECT, request-level memoised, under 1 ms for blocked IPs, ~0.2 ms for clean ones.
* **REST API monitor**: skips authenticated users entirely so the Block Editor (50+ REST calls per page-open) never trips the rate-limiter.
* **Reputation cache**: ETag-based, 24 h positive / 2 h negative. Daily API usage stays low even on busy sites.
* **Reports**: queued, sent in batches of 20 by a 15-minute cron with a 5-minute transient lock against concurrent runs.

**Settings persistence.**

Every option lives under the `reportedip_hive_` prefix in `wp_options` (tracked by an explicit snapshot test that fails CI on a silent rename). User-level data uses the `reportedip_hive_2fa_*` user-meta family. Admin actions write structured audit lines to the `logs` table.

= Disclaimer and warranty =

ReportedIP Hive is provided **"as is"** and **"as available"** under the terms of the GNU General Public License version 2 or later (GPL-2.0-or-later). The licence in full: [gnu.org/licenses/gpl-2.0.html](https://www.gnu.org/licenses/gpl-2.0.html).

**No warranty.**

There is **no warranty** for the program, to the extent permitted by applicable law. Except when otherwise stated in writing, the copyright holder and other parties provide the program "as is" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose. The entire risk as to the quality and performance of the program is with you. Should the program prove defective, you assume the cost of all necessary servicing, repair or correction.

This includes, explicitly and without limitation, no warranty of:

* uninterrupted or error-free operation;
* fitness for any specific security objective;
* prevention of any specific class of attack;
* compatibility with any specific WordPress version, theme, plugin or hosting environment;
* completeness or accuracy of the threat-intelligence data shared via the optional Community Network;
* timely or reliable delivery of email or SMS one-time passwords through the local mail transport or the optional managed mail/SMS relay;
* compliance with any specific legal, regulatory or contractual obligation that applies to the operator of the protected site.

**No liability.**

In no event will the copyright holder, or any other party who modifies and/or conveys the program as permitted under the GPL, be liable to you for damages, including any general, special, incidental or consequential damages arising out of the use or inability to use the program (including but not limited to loss of data, data being rendered inaccurate, losses sustained by you or third parties, lost revenue, business interruption, lockout from your own administrative interface, or a failure of the program to operate with any other programs).

Operating ReportedIP Hive is solely the responsibility of the site operator. The operator is responsible for:

* maintaining backups of WordPress, the database and the plugin configuration before installation, upgrades and configuration changes;
* understanding the consequences of enabling 2FA enforcement, hide-login, password-reset gating and IP blocking, in particular the documented edge case where an account with only email-2FA and no recovery codes is intentionally locked out of the password-reset flow until an administrator intervenes;
* maintaining recovery procedures (recovery codes, alternative second factors, WP-CLI access, server-level access) so that a misconfiguration or an upstream service outage does not cause permanent loss of access to the site;
* obtaining and maintaining any data-processing agreements, terms of service or end-user disclosures required by applicable law for the SMS, email or threat-intelligence services they choose to use.

To help with that end-user disclosure, a configuration-aware privacy-policy generator (German / English) is provided at [reportedip.com/dashboard/dsgvo](https://reportedip.com/dashboard/dsgvo), and a suggested passage is registered in the WordPress Privacy Policy Guide (Tools -> Privacy). Both are **templates only**, provided without warranty, and do **not** constitute legal advice or replace your own review, the no-warranty and no-liability terms above apply to them in full.

**Security disclosures.**

If you believe you have discovered a security issue in ReportedIP Hive, **please do not open a public GitHub issue**. Send the details to [abuse@reportedip.com](mailto:abuse@reportedip.com). We will acknowledge receipt within five business days.

**Recommended posture.**

Treat ReportedIP Hive as one layer in a defence-in-depth setup. Pair it with:

* offsite, versioned backups (database + uploads + plugin configuration);
* a malware scanner of your choice, Hive deliberately does not include one;
* a server-level firewall (Cloudflare WAF, Nginx `deny`, fail2ban) for blocking on cached public pages, which the plugin cannot reach by design;
* a reasonable patch cadence, install updates as they are released, run `./run.sh check-all` (or your CI equivalent) before upgrading on production-critical sites.

By installing or activating this plugin you confirm that you have read and accepted the terms above and the GPL-2.0-or-later licence under which the plugin is distributed.

== Cache compatibility ==

ReportedIP Hive plays nicely with the major page-cache plugins (WP Rocket, W3 Total Cache, WP Super Cache, LiteSpeed Cache) and CDNs.

* **Blocked-page responses are never cached.** Defines `DONOTCACHEPAGE`, `DONOTCACHEDB`, `DONOTCACHEOBJECT`, calls `nocache_headers()` and emits `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` plus `Pragma: no-cache`.
* **Sensor-protected paths are never cached** by reputable cache plugins anyway: `wp-login.php`, `/wp-admin/`, `/wp-json/`, XMLRPC, POSTs and logged-in users, exactly where attackers operate.
* **Documented limitation:** a blocked attacker visiting a *publicly cached* GET URL receives the cached HTML. Their write-path attempts are still blocked. For deny-on-cached-public-page, install a server-level firewall (Cloudflare WAF rule, Nginx `deny`, fail2ban).

== Screenshots ==

1. **Security Dashboard**, Real-time overview of blocked IPs, attacks, sign-ins and spam with 7- and 30-day trend charts.
2. **Blocked IPs**, Filterable, sortable list with bulk actions, manual unblock, "move to whitelist" and CSV export.
3. **Whitelist**, Trusted IPs with optional expiry, reason, and CSV import.
4. **Activity**, event log with a labelled filter bar (search, event type, severity, date range), JSON / CSV export, bulk delete + bulk block + bulk whitelist actions; IP lookup and audit trail on the same page.
5. **Protection → Blocking & Escalation**, auto-block toggle, progressive ladder editor with reset window, report-only mode toggle, blocked-page contact link.
6. **Protection → Two-Factor Authentication**, method enable/disable, role enforcement, grace period, IP allowlist; recovery codes and trusted devices live on the profile.
7. **Quickstart**, one page, two decisions, a plan-aware recommendation applied through the settings registry.
8. **API Queue**, Pending and failed report queue with retry, quota status, queue-health indicators.
9. **Community &rarr; Badges**, one-click footer badge with live preview and the banner builder with templates.

== Changelog ==

The full structured changelog lives in [CHANGELOG.md](https://github.com/reportedip/reportedip-hive/blob/main/CHANGELOG.md). Highlights:

= 2.1.73 =
New: a support bundle on System Status, as one JSON file with settings, health, queue, the events of a chosen period and the active blocks, also through WP-CLI and MainWP. Fixed: a Gravity Forms submission the form itself turned down no longer spends the form check; blocked addresses no longer write firewall rows; automatic blocks are lifted when the network vouches for the address; Local Shield no longer asks for the relay quota; CSV exports quote correctly; dates follow the site language.

= 2.1.72 =
New: disposable mail addresses are refused on comments and on every protected contact form, with a setting of its own (block by default). Fixed: a form left open longer than ten minutes was refused as expired; a verified crawler (OAI-SearchBot) was blocked and reported for a bait path; reports the network refuses as whitelisted stayed in the queue; bulk actions did nothing after a filter; "Delete All Failed" skipped rows with retries left. Extended Protection is one card with one status and one button, and the dashboard links to the reportedip.com security header check.

= 2.1.71 =
Fixed: on a Multisite with its own domain per site, an admin with Hide Login or the wp-admin guest block on could only reach the site they signed in on. Admin links to another domain of the network now lead through that domain's login first.

= 2.1.70 =
Fixed: installations count on wordpress.org again. The update checker had been removing the plugin from the update-check request WordPress sends to api.wordpress.org, so no site running this plugin was ever counted there. Updates keep coming from GitHub only.
Fixed: every admin-post form works in the Network Admin (WordPress ships no network admin-post.php).
Changed: the settings fingerprint reported to MainWP and the fleet covers only values that differ from their defaults, so a plugin update no longer marks the whole fleet as drifted; the remote schema lists the choices of every checkbox group.

= 2.1.69 =
Changed: the Protection page is five tabs (Core protection, Forms, Firewall & Bots, Advanced, Operations) over the fifteen areas. A switch is one row with a plain sentence and its state, a switch outside the plan shows the plan and a link instead of a greyed-out toggle, and the expert settings of every area fold away behind "Show technical details". One "Save changes" and one "Restore defaults" per tab, a "Check protection" button next to the status banner, and every link into the page still lands on its area.
Security: a user agent wrapped in quotes counts as a certain bot on every protected form; a plugin update no longer reopens the plain form marker for a day.
Fixed: switching Hide Login on together with its slug no longer fails silently (values are written before switches on every channel); saving the Protection page in the Network Admin lands back in the Network Admin instead of a "not allowed" page; the Adaptive Step-Up area no longer reports "0 triggers" with roles stored; the three step-up intervals are locked with the policies they belong to.
Changed: the German translation addresses the operator formally throughout.

= 2.1.68 =
Security: the bundled offline ruleset now blocks error-based SQL injection (EXTRACTVALUE, UPDATEXML) and second-order SQL injection through the trackback body, so a site in Local Shield mode or without Rule Sync is covered as well.
New: Priority Sync starts with the Contributor plan. Contributor receives the Paranoia-Level-2 WAF ruleset and the bot IP-range feeds, refreshed weekly; Level 3 and the daily refresh stay with Professional.
Privacy: the audit trail stores the browser identification only while "Log user agents" is on, the same switch the security log follows. It is off by default; entries already recorded stay as they are.
Fix: the expert-mode tooltip no longer names a fixed number of settings, the API endpoint help text names reportedip.com, and the readme counts the twenty readiness detectors.

Older releases: see the full [CHANGELOG.md](https://github.com/reportedip/reportedip-hive/blob/main/CHANGELOG.md).

== Upgrade Notice ==

= 2.1.41 =
Adds opt-in Tor exit-node blocking (Professional), trusted-proxy source ranges against header spoofing, a WordPress dashboard security widget, richer IP lookups with a WP-CLI command, new developer hooks and race-safe attempt counters (schema v15). No breaking changes.

= 2.0.28 =
Fewer false-positive blocks of legitimate crawlers and asset 404s, Business multi-bookable tier copy, and a documentation pass correcting the free-vs-paid positioning. No breaking changes.

= 2.0.27 =
Multisite Network Admin URL fixes and language-independent login-error masking (German included). No breaking changes.

= 2.0.25 =
SMS 2FA is now a Professional feature via the managed reportedip.com relay; the self-hosted SMS providers are removed. Sites that sent SMS via a self-configured provider or on a non-paid plan lose it, users fall back to TOTP, Email or a passkey. A v8 migration removes the old options.

= 2.0.24 =
Adds GDPR tooling: a WordPress Privacy Policy Guide entry, a personal-data exporter/eraser for login attempts and trusted devices, and a privacy-text generator. Fixes dead legal links in the documentation. No breaking changes.

= 2.0.19 =
German translation (de_DE, formal) added, the admin UI now displays in German on German-language sites. Also fixes a fatal error on the 2FA settings tab. No breaking changes.

== Privacy Policy ==

**Data stored locally**

* IP addresses of blocked or suspicious visitors
* Security event timestamps and event types (login failures, spam attempts, XMLRPC abuse, ...)
* Optional, off by default: truncated user-agent strings (max. 50 characters) and request paths
* Encrypted at rest: 2FA TOTP seeds and user phone numbers (libsodium with OpenSSL fallback)

**Data shared with the Community Network (only when enabled)**

* IP address and event type of reported threats
* Anonymised threat metadata for coordinated-attack analysis
* **Never sent:** usernames, comment content, full user-agents, any other personal data

**Lawful basis** (EU GDPR)

* Art. 6(1)(f) GDPR, legitimate interest in preventing unauthorised access and detecting attacks against the controller's site.

**Retention**

* Configurable retention (default 30 days)
* Automatic anonymisation (default after 7 days)
* Manual deletion available from the admin UI; full data wipe on uninstall is opt-in

Full privacy information: [reportedip.com/datenschutzerklaerung/](https://reportedip.com/datenschutzerklaerung/). A ready-to-paste privacy passage for your own site, German or English, tailored to the modules you use, is available at [reportedip.com/dashboard/dsgvo](https://reportedip.com/dashboard/dsgvo).

== External Services ==

This plugin connects to external services only when explicitly configured. *Local Shield* mode works completely offline, none of the endpoints below are contacted unless the corresponding feature is enabled.

= ReportedIP Community Network API =

* Service URL: `https://reportedip.com/wp-json/reportedip/v2/` (endpoints `verify-key`, `check`, `report`, `whitelist`, `categories`)
* Purpose: IP reputation lookups, anonymised threat reporting, whitelist sync, threat-category catalogue
* Default: off, only active in Community Network mode AND with a configured API key
* Data transmitted: IP addresses, optional event categories and timestamps, the API key, the site domain and the plugin/WordPress version (wp.org-style User-Agent plus an `X-Rip-Site` header, used for licence domain counting and support)
* Terms: [reportedip.com/nutzungsbedingungen/](https://reportedip.com/nutzungsbedingungen/)
* Privacy / DPA: [reportedip.com/datenschutzerklaerung/](https://reportedip.com/datenschutzerklaerung/)

= ReportedIP Managed Mail Relay =

* Service URL: `https://reportedip.com/wp-json/reportedip/v2/relay-mail`
* Purpose: route 2FA verification mails through the reportedip.com transactional mail infrastructure (clean SPF / DKIM / DMARC)
* Default: off, only available for Professional, Business and Enterprise plans, only when the user enabled the email 2FA factor; on any error (cap reached HTTP 402, recipient backoff HTTP 429, network error) the plugin falls back to the local `wp_mail()` transport so the 2FA flow never breaks
* Data transmitted: recipient email, subject, HTML and plain-text body, headers, optional Reply-To, the site domain
* Privacy / DPA: [reportedip.com/legal/avv/](https://reportedip.com/legal/avv/)

= ReportedIP Managed SMS Relay =

* Service URL: `https://reportedip.com/wp-json/reportedip/v2/relay-sms` (and `relay-quota` for monthly usage display)
* Purpose: deliver 2FA OTP messages without requiring the site operator to maintain their own SMS-provider contract
* Default: off, only available for Professional, Business and Enterprise plans, only when a user actively enrolled SMS as a 2FA factor; routing is worldwide except for a small number of high-cost destinations that are unsupported by the managed relay (HTTP 422 with code `country_not_supported` is returned to the plugin in that case)
* Data transmitted: recipient phone number (E.164), the verification code, expiry minutes, language code, the site domain
* Privacy / DPA: [reportedip.com/legal/avv/](https://reportedip.com/legal/avv/)

= ReportedIP Rule Sync =

* Service URL: `https://reportedip.com/wp-json/reportedip/v2/rules/{ruleset}` (one call per ruleset: `waf`, `bot_signatures`, `disposable_domains`, `scan_paths`, `tor_exits`)
* Purpose: fetch signed firewall rule updates; the bundled baseline rulesets stay active without any connection, and Professional plans receive the deeper, frequently-updated rulesets through this channel
* Default: off, only active in Community Network mode AND with a configured API key AND the Rule Sync toggle enabled; runs every six hours via cron, and conditional `If-None-Match` requests return HTTP 304 when nothing changed
* Data transmitted: the API key, the current ETag, the site domain and the plugin/WordPress version; each downloaded ruleset carries an Ed25519 signature that the plugin verifies against a bundled public key before applying it
* Terms: [reportedip.com/nutzungsbedingungen/](https://reportedip.com/nutzungsbedingungen/)
* Privacy / DPA: [reportedip.com/datenschutzerklaerung/](https://reportedip.com/datenschutzerklaerung/)

= ReportedIP Release-Notes Feed ("What's new" banner) =

* Service URL: `https://reportedip.com/wp-json/reportedip/v2/hive/whats-new`
* Purpose: fetch the release highlights shown once per version in the dismissible "What's new" banner on plugin admin pages
* Default: on, one keyless GET per installed version (with backoff on failure), admin pages only
* Data transmitted: no API key; the request identifies the installation wp.org-style (site address plus plugin and WordPress version in the User-Agent)
* Terms: [reportedip.com/nutzungsbedingungen/](https://reportedip.com/nutzungsbedingungen/)
* Privacy / DPA: [reportedip.com/datenschutzerklaerung/](https://reportedip.com/datenschutzerklaerung/)

= GitHub Releases API (Plugin Update Checker) =

* Service URL: `https://api.github.com/repos/reportedip/reportedip-hive/releases` (via the [plugin-update-checker](https://github.com/YahnisElsts/plugin-update-checker) library)
* Purpose: notifies the WordPress plugin updater about new tagged releases (release ZIP is downloaded from GitHub when the admin clicks "Update")
* Default: on, runs once every 12 hours via the `wp_update_plugins` cron, the same cadence WordPress core uses for its own update checks
* Data transmitted: only plugin metadata (current version, slug); no site identifiers, no user data
* Terms: [GitHub Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service)
* Privacy: [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)

= HaveIBeenPwned (HIBP) Range API =

* Service URL: `https://api.pwnedpasswords.com/range/{first-5-sha1-hex-chars}`
* Purpose: optional k-anonymity password-strength check at user password change, flags credentials known from public breach corpora
* Default: on, the password policy and its HIBP range check are both enabled by default; the check runs server-side at password change for users covered by the policy. Disable via the option `reportedip_hive_password_check_hibp`. (No visitor IP is sent, the WordPress server queries HIBP with only the 5-char hash prefix.)
* Data transmitted: only the first 5 hex characters of the SHA-1 hash of the proposed password (the password itself is never sent and cannot be reconstructed)
* Privacy: [haveibeenpwned.com/Privacy](https://haveibeenpwned.com/Privacy)
* Soft-fail behaviour: a network error never blocks a password change

= No CDN, no third-party assets =

All JavaScript, CSS, fonts and images shipped with the plugin are loaded from the plugin directory itself. The plugin does not embed Google Fonts, Google Analytics, jQuery from a CDN or any other remote asset.

== Related projects ==

ReportedIP Hive is one piece of an Open-Source ecosystem around community-driven WordPress security. All projects are GPL or compatible licences and live on GitHub:

* **Hive** (this plugin), [github.com/reportedip/reportedip-hive](https://github.com/reportedip/reportedip-hive). Community-powered WordPress security: IP threat intelligence, brute-force protection and the complete 2FA suite. Be part of the hive.
* **Honeypot Server**, [github.com/reportedip/honeypot-server](https://github.com/reportedip/honeypot-server). PHP honeypot that emulates WordPress, Drupal and Joomla to detect malicious traffic. 36 threat analyzers, automatic reporting to the reportedip.com API, admin dashboard, AI content generation, bot detection. Zero Composer dependencies, SQLite, Docker-ready. Run one yourself to feed the network and earn the Contributor tier.
* **Blacklist**, [github.com/reportedip/reportedip-blacklist](https://github.com/reportedip/reportedip-blacklist). Community-driven IP threat-intelligence feed, updated daily. Free to consume, no account required.

Project home, documentation and the optional managed-relay service: [reportedip.com](https://reportedip.com).

== Credits ==

* Developed by [ReportedIP](https://reportedip.com)
* Plugin Update Checker by [YahnisElsts](https://github.com/YahnisElsts/plugin-update-checker) (MIT)
* WebAuthn / FIDO2 implementation: in-house, no external dependency
* Charts: [Chart.js](https://www.chartjs.org/) (MIT)
* Icons: in-house SVG set

== Translations ==

* English (source)
* German (Deutsch), included

Want to help translate into more languages? Open an issue on [GitHub](https://github.com/reportedip/reportedip-hive/issues) or contact [1@reportedip.com](mailto:1@reportedip.com).
