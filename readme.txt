=== ReportedIP Hive ===
Contributors: reportedip, patrickschlesinger
Donate link: https://reportedip.com
Tags: security, firewall, brute-force, two-factor, multisite
Requires at least: 5.9
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 2.1.65
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

= Why agencies and serious site owners pick it =

* **One plugin instead of three.** Brute-force protection, a four-method 2FA suite and threat intelligence in a single drop-in. The full protection core stays free and Open Source, paid plans add the managed mail/SMS relays, multi-site management, higher API quotas and a few advanced modules (WooCommerce frontend 2FA, Hardening Mode, white-label), never the core protection itself.
* **Progressive blocks that don't burn legitimate users.** A first-time tripping CGNAT visitor or a fat-fingered admin gets a 5-minute timeout, repeat offenders climb the ladder up to 7 days. Nobody pays a 24h block for a typo.
* **Privacy-first by default.** GDPR-minimal logging mode, 30-day retention, anonymisation after 7 days, opt-in community sharing, all secrets encrypted at rest with libsodium.
* **Hardening Mode on coordinated attacks (PRO).** When several IPs hit the login in the same minute, or enough distinct IPs add up across a rolling window (default 10 minutes, 10 IPs, 50 attempts), the plugin tightens the failed-login and reputation thresholds network-wide for one hour, on wp-login, the WooCommerce storefront login and application passwords alike. Distributed brute-force from botnets stops mid-flight instead of slipping under the per-IP threshold. Realtime trigger in the login pipeline plus an hourly cron sweep as fallback. Visible state via the admin bar, configurable on the Protection page under Attack Response, controllable via WP-CLI.
* **Tor exit-node blocking (PRO).** An opt-in toggle rejects connections from known Tor exit nodes, backed by a signed exit-node list refreshed twice daily. Blocks are temporary and never reported to the community, operating an exit node is not abuse evidence.
* **Cache-plugin-safe.** WP Rocket, W3 Total Cache, WP Super Cache, LiteSpeed and Cloudflare cannot store the 403 block page or serve cached HTML to blocked IPs on protected paths (login, admin, REST, XMLRPC).
* **Access lockdown switches.** Turn off the parts of WordPress the site does not use: the REST API for signed-in users only or restricted to selected roles and namespaces, XML-RPC including pingbacks, feeds, the admin area for signed-out visitors, PHP execution in the uploads folder and the version fingerprints in the page source. Every switch is off by default, free on every plan and reversible from the same screen.
* **System readiness register.** Eighteen detectors watch what usually fails quietly: an unwritable pre-WordPress guard queue, stalled or disabled cron, a trusted proxy header without proxy ranges, an outdated database schema, a degraded community layer, exhausted relay quotas, failing mail delivery, a missing encryption extension and a growing report queue. Six of them are advisory rather than faults and only surface once the quickstart is done: Hide Login switched off, storefront 2FA included in the plan but unused, the footer badge off, the pre-WordPress guard possible but not running, Local Shield instead of the community network, and the signed-in administrator without a second factor of their own. Open issues show up on the System Status page with severity, first-seen time and a jump to the responsible setting, and `wp reportedip status` reports them as well. Free on every plan.
* **Security headers out of the box.** The basic hardening trio (X-Content-Type-Options, X-Frame-Options, Referrer-Policy) is free; HSTS, Permissions-Policy, a report-only-first Content-Security-Policy and the cross-origin isolation trio come with Professional. Headers already sent by your server or another plugin are detected and left untouched.
* **Code you can read.** Public on GitHub, GPL-2.0-or-later, PHPStan level 5 clean, WPCS-clean (zero warnings), a comprehensive PHPUnit suite (unit + Multisite) running on every commit.

= 16 detection sensors (every one tunable) =

* **Failed logins**, default 5 fails / 15 min
* **Password spray**, distinct usernames from same IP, default 5 / 10 min
* **Comment spam**, default 5 / 60 min
* **XMLRPC abuse**, default 10 / 60 min
* **Application-password abuse**, REST/XMLRPC Basic-Auth bypass for 2FA, default 5 / 15 min
* **REST API rate-limit**, global cap, default 240 / 5 min (sensitive routes 20 / 5 min)
* **User enumeration defence**, `?author=`, `/wp-json/wp/v2/users`, oEmbed, login-error masking, default 5 / 5 min. Author archive pages can be kept public for sites that link to them
* **404 / scanner detection**, default 12 / 2 min, plus instant block on known-bad paths (`.env`, `wp-config.bak`, `/.git/`)
* **Web Application Firewall**, request-inspecting engine (SQLi, XSS, path traversal, command injection, LFI wrappers, scanner tooling). The engine and the OWASP-Top-10 Paranoia-Level-1 baseline are free on every plan; Professional adds the deeper, frequently-updated, Ed25519-signed Level 2/3 ruleset. ReDoS-hardened and fail-open, with an optional pre-WordPress drop-in (Apache / PHP-FPM auto-config, nginx snippet) for blocking before WordPress loads
* **Verified bot detection**, confirms Googlebot, Bingbot and other crawlers via their official IP ranges (DNS-free) and forward-confirmed reverse DNS. Spoofers are flagged (default) or blocked; genuine crawlers are never blocked. Free on every plan
* **Registration defence**, one rule set for every sign-up surface (WordPress, WooCommerce, Multisite sign-ups, programmatic user creation): throwaway-mail domains (off / monitor / block, privacy relays such as Apple Hide My Email and Firefox Relay pass by default), prohibited usernames on top of a baseline of ten role names, e-mail allow or block rules, a per-IP registration rate limit (default 3 / 60 min) and an opt-in immediate block for sign-in attempts against usernames that do not exist. Ten plain entries per list are free; Professional lifts the cap, accepts `/regex/` patterns and adds registration restricted to allowlisted IP ranges. The live throwaway-mail list rides Priority Sync
* **Form execution proof**, the comment, sign-up and password-reset forms check that the submission came from a browser that really rendered them, and four form plugins are covered on the paid plans. No CAPTCHA, no puzzle and no extra step for a visitor. Full detail in *Form protection* below
* **Community threat check on forms**, when a comment, sign-up or password reset is submitted, the visitor address is checked against the community network at the same protection level the sign-in page enforces. Someone the site would refuse a login to cannot post a comment instead. The visitor is told why, and the address is closed for 24 hours exactly as a refused sign-in closes it. On by default, needs Community Network mode, and honours every exemption the sign-in path honours. If the daily allowance runs out, the network is unreachable or the answer never arrives, nothing is refused anywhere: the local scoring carries on exactly as before. Losing the community opinion may cost a site that evidence, never its ability to accept input
* **Geographic anomaly**, login from a country never seen for the user, optionally revokes trusted-device cookies
* **Password policy**, minimum length, character classes, optional Have-I-Been-Pwned k-anonymity check
* **WooCommerce login hooks**, checkout + my-account forms tracked separately

Not a sensor, but part of the same screen: the consent endpoints of Real Cookie Banner, Complianz, Borlabs and CookieYes are exempt from the rate limit out of the box, because on a compliant site they look like a burst on every single page view.

= Two-Factor Authentication (four methods) =

Three of the four methods work in **every plan**, including Free and the fully-offline Local Shield. SMS is the one method that rides the managed relay, so it needs a Professional plan.

* **TOTP**, RFC 6238, works with Google Authenticator, Authy, 1Password, Microsoft Authenticator. Secrets encrypted at rest. *Free.*
* **Passkey / WebAuthn / FIDO2**, Face ID, Touch ID, Windows Hello and hardware security keys (YubiKey 5 series and other FIDO2 keys, USB-C or NFC phone tap). Ed25519 support, clone detection, named key manager. In-house implementation, no Composer dependency. Phishing-resistant. *One key per account free.*
* **Advanced Security Keys (Business)**, multiple keys per account (primary + backup), automatic model detection via attestation and key-lifecycle email alerts.
* **Email OTP**, 6-digit code, 10-minute validity, rate-limited (3 sends / 15 min, 60 s cooldown), 5 verify attempts per code. *Free.*
* **SMS OTP (Professional)**, delivered through the managed reportedip.com relay, included with Professional and Business plans. No own SMS account or carrier contract required. Phone numbers encrypted at rest. Free / Contributor sites use TOTP, Passkey or Email instead.

Plus:

* **Self-service method management on the profile page**, plain-language method cards let every user add or remove methods at any time, pick the default method the login challenge opens with, change the SMS number (the verified number is only replaced after the new one confirms a code) and re-set-up the authenticator app
* **10 single-use recovery codes**, hashed at rest, low-codes warning at 3 remaining
* **Trusted devices** with configurable expiry (default 30 days), IP + device-name + last-used tracking, auto-revoked on geo anomaly
* **Password-reset gate**, the WordPress "lost password" flow demands a second factor before the new password is accepted. Email is excluded by design (it is the channel that delivered the reset link), so a stolen mailbox cannot bypass 2FA. Email-only accounts without recovery codes are hard-locked with an admin alert.
* **Multi-stage 2FA rate-limit**, 3/5/10/15 fails trigger 30 s/5 m/30 m/1 h delays; the 15th IP-level fail graduates the IP to a real progressive block (so the brute-forcer no longer just times out and tries again hourly)
* **Role-based enforcement** with grace period (default 7 days) and skip counter
* **Adaptive step-up triggers (Professional)**, seven per-role rules that ask for the second factor again: new country, new IP address, new network, new device, every N days, every N sign-ins, more than N concurrent sessions. The step-up applies even when a trusted-device cookie is present; the 2FA IP allowlist and the `reportedip_2fa_bypass` filter still bypass it. Users without a configured method are never locked out, and the administrator role can only be armed once an administrator has passed one challenge on the site
* **Frontend onboarding**, branded 5-step setup wizard for users on the front-end (e.g. WooCommerce account)
* **WooCommerce frontend 2FA (Professional plan)**, second factor renders inside the active storefront theme on My Account, classic checkout and the WooCommerce blocks, with a themed onboarding page for Customer / Subscriber roles. Cart and checkout state survive the redirect roundtrip; the trusted-device cookie is shared with the wp-login flow so a checkout-side "Trust this device" silences the next backend login as well. Soft-disables on a tier downgrade, existing customer secrets stay valid, only new onboardings are blocked.
* **Branded login page** option, custom email subject + body, IP allowlist for 2FA bypass

= Form protection =

Hive checks that a submission came from a browser that really rendered the form. A visitor notices nothing of it, there is no image to decipher and no extra step to take. What the check cannot do is tell a person from a botnet driving a real browser. It tells a browser from a script.

**Free on every plan:**

* **Comment form**
* **Registration**, the WordPress, WooCommerce and Multisite sign-up forms
* **Lost password**, the WordPress password-reset form
* **Your own forms**, through the open interface `ReportedIP_Hive_Form_Proof::field()`, `check()` and `passes()`, so a hand-built form can drop its captcha

**On every plan:**

* **Contact Form 7**

**From Business:**

* **Gravity Forms**, including forms sent in the background and forms with several pages
* **WPForms** and WPForms Lite, including forms sent in the background. A refused submission is shown to the sender above the form
* **Forminator**, whether the form sits in the page or is loaded afterwards. A refused submission is shown to the sender at the form, never dropped into a spam folder
* **Ultimate Member**, its sign-in, sign-up and password forms. A sign-up also runs through the registration rules, so a throwaway address or a reserved name is refused before the account exists
* **Formidable Forms**
* **Formidable Forms PRO**
* **Elementor Forms**, which needs Elementor PRO, because the form widget exists only there

**Tested against** Contact Form 7 in the version published on wordpress.org, Gravity Forms 3.1, Formidable Forms and Formidable Forms PRO 6.35, Elementor and Elementor PRO 3.34, Ultimate Member 2.13, WPForms Lite 2.0, Forminator 1.57.

**How it works.** Every protected form carries an invisible, screen-reader-excluded anchor field. A bot that fills every input it finds fills that one too. A small script adds a second field whose name is random per installation, so a script posting straight at the endpoint without ever loading the form cannot carry it. The verdict is four-way, `proved`, `failed`, `tripped` or `absent`, and "absent" stays lenient until the site has seen itself render the field, so a theme with hand-written comment markup is never treated like a bot. Nothing request-specific reaches the HTML, so page caches stay valid.

**What a verdict costs.** On the comment form a filled anchor scores 7 and a missing proof scores 4 against a spam threshold of 7, so a reader browsing without JavaScript loses a moderation step rather than the comment, and that reason on its own never counts towards a block. Sign-up, password reset and the form plugins refuse a failed proof outright and say why. On the form plugins a filled anchor counts towards the per-address block ladder the same way it does on a comment, while a client that simply never ran the script never does. The one exception is the Ultimate Member password form: a page served from a cache filled before the switch went on never refuses there, because that form is what somebody reaches for once they are already locked out.

**Computation check (Professional).** With it on, the browser fetches a small task from your own site and works it out in the background. The task is signed with your site's salt, expires after ten minutes, is accepted once, and gets harder the faster one network asks for tasks; the starting value is derived from the task itself, so a client can choose neither it nor the difficulty. That closes the shortcut the plain marker leaves open, reading the field name out of the page and posting it back, and it closes the follow-up as well: a script that fetches one task cannot reuse it, and a script that fetches hundreds pays for every one. The page itself carries nothing but the address of the endpoint, identical for every visitor, so a full-page cache, LiteSpeed, WP Rocket or a CDN in front of the site keeps serving it unchanged; the task comes from a POST that no cache stores. Without HTTPS the task carries no arithmetic, because the browser hash API only exists in a secure context, but it keeps its signature, its expiry and its single use. After a plugin update the plain marker passes again for a day and the page cache is purged, so readers of a page cached by the previous version are never refused.

**One switch per plugin.** On a plan that does not cover an adapter the switch stays visible and locked, with the plan it needs written next to it. For 24 hours after a switch goes on, a submission that never carried the proof is still accepted, and switching it on clears the common page caches, so a page cached without the field cannot lock anybody out. `reportedip_hive_form_adapters_grace` buys more room on a site whose cache outlives a day.

**Self-test.** Tools → Diagnostics. The card first lists what is switched on, and why an adapter is inactive when it is, then runs three passes with the browser you are sitting in front of: like a visitor, like the same visitor twice, and like a bot. No real form is submitted, no mail goes out and no entry is stored. An invisible protection is otherwise hard to tell apart from no protection at all, and this card answers that question.

**Fill time.** The script measures how long the form was on screen and sends the seconds along. The starting point comes from the browser and never from the markup, because a value baked into the HTML is already wrong when a page cache serves it. The number is not signed, so a determined attacker writes into it whatever suits them. It is therefore enforced on the comment filter alone, where it weighs 2 of the 7 points a comment needs to count as spam and can never convict on its own. Every other surface measures it and writes it to the log. The threshold is three seconds and `reportedip_hive_form_proof_fast_seconds` changes it.

Everything above sits on the Protection page under Form Protection, next to the master switch, a second switch that leaves sign-up and password reset out, and report-only mode, which logs every refusal and refuses nothing. `REPORTEDIP_HIVE_DISABLE_FORM_PROOF` in `wp-config.php` switches the whole layer off.

= Honeypots and decoys =

Two traps sit outside the forms. Neither needs a CAPTCHA, a puzzle or an extra step; each one is a place a genuine visitor never goes and an automated tool cannot resist.

**Decoy paths.** 45 built-in bait URLs that exist on no real site: `/.env.backup`, `/wp-config.old.php`, `/db-dump-master.sql.php`, `/admin-shell-console.php` and the like. A single request answers with one 403 and queues a high-severity report to the community network. It does not block the address locally, on purpose: a backup plugin that writes `wp-config.old.php`, or an administrator testing a bait URL, must never lock a site out of its own traffic. On Apache the plugin keeps a marker block in `.htaccess` so a real file at a bait path is still routed through WordPress instead of being served; nginx gets a snippet to paste. Extend the list with the `reportedip_hive_decoy_paths` filter. Free, on by default.

**Scanner honeypot paths.** The 404 detector counts misses per address (default 12 in 2 minutes), but a hit on a known scanner target fires at once, threshold 1: `/.env`, `/.git/config`, `/.aws/credentials`, `/.ssh/id_rsa`, `/backup.sql` and a bundled baseline of ten, plus prefixes such as `/cgi-bin/` and known-vulnerable plugin folders. Professional receives the live list of roughly a hundred targets through Priority Sync. Verified crawlers are exempt from the rate trigger but never from a honeypot hit, because a Googlebot that asks for `/.env` is not Googlebot. Extend with `reportedip_hive_scan_paths` and `reportedip_hive_scan_prefixes`.

Both traps report what they caught to the log with the reason, and both honour the whitelist, the site's own server addresses and report-only mode, which logs the hit and refuses nothing.

Not to be confused with the **Honeypot Operator** plan: that is a reportedip.com account tier for people running a dedicated honeypot server that feeds the network, unrelated to the traps above. See the honeypot-server integration docs on reportedip.com.


= Progressive block escalation =

The default ladder: **5 min → 15 min → 30 min → 24 h → 48 h → 7 d** (cap). After 30 days without a new offence, the IP starts again at step 1. The ladder is fully editable as a comma-separated minute list under *Protection → Blocking & Escalation*. A toggle keeps the legacy single-duration mode available for sites that prefer the old behaviour.

Manual blocks (admin clicks "Block this IP" or imports a CSV) honour the admin's chosen duration and are never overridden by the ladder.

= Cache compatibility =

ReportedIP Hive plays nicely with WP Rocket, W3 Total Cache, WP Super Cache, LiteSpeed Cache and CDNs.

* The 403 "Access Denied" response sets `DONOTCACHEPAGE`, `DONOTCACHEDB` and `DONOTCACHEOBJECT`, calls `nocache_headers()`, and emits explicit `Cache-Control: no-store` + `Pragma: no-cache`. No cache layer stores the 403 and hands it back to legitimate visitors.
* Login (`wp-login.php`), admin (`/wp-admin/`), REST (`/wp-json/`), XMLRPC, POST requests and logged-in users are excluded from page caching by every reputable cache plugin out of the box, exactly the paths attackers target. Blocks always take effect there.
* The form execution proof emits nothing request-specific: the decoy carries no value, the proof field name is a per-site constant and the script is a static file. A page cached under any of these layers stays valid indefinitely, and no page is marked uncacheable for it.
* **Documented limitation:** a blocked attacker visiting a *publicly cached* GET URL still receives the cached HTML. Their write-path attempts (login, comment, REST, XMLRPC) are blocked normally. For deny-on-cached-public-page, install a server-level rule (Cloudflare WAF, Nginx `deny`, fail2ban).

= Badges and community shortcodes =

Show the world that your site is part of the hive, and earn community-network credibility:

* **Badges tab on the Community page**, the one-click footer badge with its live preview on top, the banner builder below; templates set variant, number and wording in one click, colours and text overrides sit behind a disclosure
* **Auto-footer badge**, one toggle, four positions (left / center / right / below content), zero shortcode placement needed
* **Shortcodes**, `[reportedip_badge]`, `[reportedip_stat type="..."]`, `[reportedip_banner]`, `[reportedip_shield]`. Drop into any post, page, widget or template
* **8 stat types**, `attacks_total`, `attacks_30d`, `reports_total`, `api_reports_30d`, `blocked_active`, `whitelist_active`, `logins_30d`, `spam_30d`
* **4 tone presets**, `protect`, `trust`, `community`, `contributor`
* **Web Component with Shadow DOM**, your theme cannot break the layout. The `<a>` link stays in the light DOM, so search engines pick it up.
* **UTM-tracked**, every click measurable in your analytics

= Privacy & GDPR =

* **Made in Germany.** Privacy is a design principle, not an afterthought.
* **Minimal data collection.** No usernames, no comment content, no full user-agents in any report; user-agents are truncated to 50 characters even locally.
* **Configurable retention.** Daily cleanup with a 30-day default; automatic anonymisation after 7 days.
* **Opt-in sharing.** Local Shield works 100 % offline. Nothing leaves your site unless you switch to Community Network.
* **Transparent installation identity.** In Community mode each API request identifies the installation itself, site address plus plugin and WordPress version, wp.org-style, for licence domain counting and support. This is data about your installation, never about your visitors.
* **Lawful basis: Art. 6(1)(f) GDPR** (legitimate interest, preventing unauthorised access). Documented in the quickstart and admin UI.
* **Encryption at rest.** All secrets (TOTP seeds, phone numbers) sealed with libsodium (or OpenSSL fallback).
* **Delete-on-uninstall** opt-in for total removal: tables, options and every piece of user meta the plugin wrote.
* **Export and erasure requests are wired up.** A personal-data export returns the account's own login attempts, its trusted devices, an account block with its texts, the address and expiry of every open session and the sign-in history behind the adaptive 2FA triggers. An erasure clears the texts and the history but keeps an active account block and reports that as retained, because an erasure request must not become a way to lift a security block.
* **Privacy-policy generator.** A ready-to-paste passage for your own privacy policy (German or English, tailored to the modules you use) is at [reportedip.com/dashboard/dsgvo](https://reportedip.com/dashboard/dsgvo); the plugin also registers a suggested text in the WordPress Privacy Policy Guide (Tools -> Privacy).

= Admin UX =

* **One-page quickstart** with a tier-aware recommendation: pick Community Network or Local Shield, paste the key, switch protection on. Everything else is preconfigured for your plan and adjustable later.
* **Real-time dashboard** with detection & hardening score gauges (0–100 plus an A+-F grade, per-item deep links) and 7- and 30-day Chart.js trend lines.
* **Security widget on the WordPress dashboard**, attacks blocked (30 days), blocks today, active IP blocks, protection layers and the detection score on wp-admin's front page, with deep links into the plugin; on Multisite the widget appears on the network dashboard.
* **Seven list-table screens**: Blocked IPs, Whitelist, Security Logs, API Queue, the audit event trail (Business), the session manager under Users -> Sessions (Business), plus the 2FA admin grid.
* **System Status page** listing every open readiness issue with its severity, when it first appeared, a jump to the responsible setting and a link to the documentation.
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
* **WP-CLI** command trees for 2FA, hardening, IP lookup and full IP management (see the WP-CLI section below).
* **PHP filters** to extend the engine without forking:
  * `reportedip_hive_rest_bypass_routes`, whitelist additional REST namespaces
  * `reportedip_hive_rest_sensitive_routes`, flag additional REST routes for the lower threshold
  * `reportedip_hive_event_category_map`, map your custom event types to community-API categories
  * `reportedip_hive_mail_provider`, `reportedip_hive_mail_args`, `reportedip_hive_mail_template_path`, replace the mailer
  * `reportedip_hive_form_proof_adapters`, choose which form surfaces carry the execution proof (`comment`, `register`, `lostpassword`), and admit your own
  * `reportedip_hive_form_proof_bits`, difficulty of the computation check in leading zero bits (14 for a quiet network, one more per doubling of its requests up to 22, plus two while the hardening mode runs; the second argument is the context `challenge`)
  * `reportedip_hive_form_challenge_ttl`, seconds a fetched task stays valid (600 by default, at most 1800)
  * `reportedip_hive_reputation_form_surfaces`, choose which form surfaces are checked against the community network
* **Form API** for your own or a third-party form, so it can drop its captcha: admit the surface through `reportedip_hive_form_proof_adapters`, print the anchor with `ReportedIP_Hive_Form_Proof::field( 'my_form' )` on the render hook, and gate the submission with `ReportedIP_Hive_Form_Proof::passes( 'my_form' )` on the validation hook. `ReportedIP_Hive_Form_Proof::check( 'my_form' )` returns the raw four-way verdict instead.
* **Constants** for emergency overrides:
  * `REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN`, temporarily disable hide-login from `wp-config.php`
  * `REPORTEDIP_HIVE_DISABLE_FORM_PROOF`, switch off the whole form-proof layer from `wp-config.php`, for the case where a visitor cannot submit and you need the site working before you debug
* **9 database tables** (auto-migrated; opt-in delete on uninstall): logs, blocked, whitelist, attempts, api_queue, stats, trusted_devices, audit_log and waf_exceptions.
* **Internationalisation-ready.** Text domain `reportedip-hive`, English source with German translation included.
* **Test suite.** A comprehensive PHPUnit suite (unit + Multisite) runs on every commit; PHPStan level 5 (No errors); WPCS-compliant with zero warnings.

= WP-CLI =

Every day-to-day management task is available from the shell. List-style commands accept `--format=<table|json|csv|yaml>`; `<ip>` accepts a single IPv4/IPv6 address or a CIDR range throughout.

IP management:

* `wp reportedip whitelist add <ip> [--reason=<text>] [--expires=<datetime>]`, whitelist an address (lifts an active block automatically)
* `wp reportedip whitelist remove <ip>` / `wp reportedip whitelist list`
* `wp reportedip block <ip> [--reason=<text>] [--hours=<n>]`, manual block
* `wp reportedip unblock <ip> [--reset-attempts]`, release a blocked address; the flag also clears the attempt counters so a still-exceeded threshold cannot re-block it on the next request
* `wp reportedip blocked list`, active blocks
* `wp reportedip attempts reset <ip> [--type=<type>]`, clear per-IP counters
* `wp reportedip lookup <ip>`, local status plus community reputation

Status and administration:

* `wp reportedip status`, version, mode, tier, counters, queue health, protection toggles and the open readiness issues at a glance
* `wp reportedip 2fa <status|enable|disable|reset|enforce|audit|cleanup>`, user 2FA administration
* `wp reportedip hardening <status|activate|deactivate>`, hardening mode

User accounts (Business):

* `wp reportedip user block <user> [--message=<text>] [--note=<text>]`, block an account; `<user>` is an id, login or e-mail address. The message is what the person sees at sign-in, the note stays internal
* `wp reportedip user unblock <user>`, lift the block; never needs a paid plan, so an expired licence can never leave an account locked out
* `wp reportedip user list`, every blocked account with the time, the administrator and the message

= What this plugin does NOT include =

Honest scope so you can plan around it:

* No malware scanner / file-integrity monitor
* No Cloudflare API integration
* No payment-fraud scoring

Pair it with a malware scanner if you need that surface, Hive deliberately stays focused on identity, brute force and threat intelligence.

== Plans (optional, comfort only) ==

The full **detection and identity core is free, GPL-2.0 and complete** in every operating mode, all 16 sensors, the core 2FA methods (TOTP, Passkey, Email, Recovery codes), progressive block escalation, the password-reset gate, every alert, every dashboard and export. None of that is ever gated.

Paid plans add the **managed relays, multi-site management and a handful of advanced modules** at reportedip.com, useful for sites that don't want to maintain their own SMTP / SMS / multi-site stack, run a WooCommerce storefront, or need network-wide auto-hardening:

= Free / Contributor (0 €) =

* Full core functionality, all 16 sensors, progressive blocking, the password-reset gate, every dashboard and export
* Registration rules (ten entries per list), the access lockdown switches and the system readiness register
* Form protection on the comment, sign-up and password-reset forms and on your own forms through the form API, with the self-test on the Tools page and the measured fill time
* 1 domain per licence, 1,000 IP-reputation checks/day, 50 reports/day
* Local-mode `wp_mail()` for 2FA emails; TOTP, Passkey and Email 2FA included (SMS 2FA, WooCommerce frontend 2FA and Hardening Mode require Professional)
* 30-day log retention, community support
* **Contributor tier** is identical to Free but earns threat-feed access for sites that operate a public honeypot

= Professional (14.90 €/month, 149 €/year, covers up to 3 domains) =

* 25,000 reputation checks/day, 1,000 reports/day
* **Managed mail relay**, 500 transactional 2FA mails/month routed through reportedip.com's clean SPF/DKIM/DMARC infrastructure (auto-fallback to `wp_mail()` on cap)
* **Managed SMS relay**, 25 worldwide OTP SMS/month with no third-party Twilio account required
* **WooCommerce frontend 2FA**, the second factor rendered inside the storefront theme on My Account, classic checkout and the WC blocks
* **Hardening Mode**, auto-tighten failed-login and reputation thresholds network-wide for one hour on a detected coordinated attack
* **Advanced security headers**, HSTS, Permissions-Policy, the Content-Security-Policy builder and the cross-origin isolation trio (the basic header trio stays free)
* **Adaptive 2FA triggers**, per-role step-up rules on a new device, IP address, network or country, every N days or sign-ins, or above a concurrent-session limit
* **Unlimited registration rules**, no ten-entry cap on the username and e-mail lists, `/regex/` patterns and registration restricted to allowlisted IP ranges
* **The computation check on every protected form** (see *Form protection* above)
* **Priority Sync**, the deeper, frequently-updated, Ed25519-signed WAF Paranoia-Level-2/3 rulesets plus the live bot-IP-range and disposable-domain feeds
* Multi-site dashboard, priority sync (daily blacklist download), 90-day log retention, e-mail support (48 h SLA)
* Prepaid top-up bundles (SMS and mail) available for heavy months

= Business (39 €/month, 389 €/year, up to 15 domains per licence) =

* 100,000 checks/day, 5,000 reports/day
* **2,500 mail/month + 75 SMS/month included**
* Everything in Professional, plus white-label (logo, copy, mail templates), the WooCommerce complete integration, full WP-CLI surface and role-based login-time restrictions
* **Audit event trail**, append-only record of who changed what: settings with old and new value, plugins, themes and core, pages and posts, menus and widgets, edited files and user accounts, each with the acting user and the affected object; eight trigger groups as switches, filters and CSV/JSON export
* **Form protection on WPForms, Gravity Forms, Forminator, Formidable Forms, Formidable Forms PRO, Elementor Forms and Ultimate Member**, one switch per plugin
* **Advanced Security Keys**, multiple WebAuthn keys per account (primary + backup YubiKey), automatic model detection via attestation, key-lifecycle email alerts
* **User account control and sessions**, block an account (it keeps its content but cannot sign in, authenticate an application password or complete a password reset), drop all of its sessions and trusted devices, and review or terminate active sessions from Users → Sessions
* 1-year log retention, weekly security PDF report, GDPR data-export tool, priority support (12 h SLA)
* **Multi-bookable:** book Business x2, x20 to scale domains, API quota and 2FA mail/SMS with the licence count, a volume discount applies automatically

= Enterprise (custom, from ~663 €/month) =

* Unlimited checks and reports, custom mail/SMS quotas, custom domain limit
* Custom AVV / DPA terms, dedicated onboarding, phone support (4 h response)

**Bundles (PRO+ only, refundable until first use):** 50/200/500-SMS bundles (14.90 / 49.90 / 99.90 €), 1k/5k/25k-mail bundles (4.90 / 14.90 / 49.90 €). All prices VAT-inclusive (Stripe `tax_behavior = inclusive`).

**How domains are counted:** each Hive installation announces its site address with every API request, and every distinct domain occupies one slot of the plan. A WordPress Multisite network counts as a single domain. Your reportedip.com dashboard shows the used/included domains per licence, lets you release slots of retired or moved sites (up to 3 self-service releases per 30 days), and domains that stop reporting for 60 days free their slot automatically. Currently informational only, nothing is blocked when a plan is over its allowance.

What stays Free regardless of plan: all 16 detection sensors, the WAF engine with its baseline ruleset, verified-bot detection, the registration rule set with ten entries per list, the form protection on the comment, sign-up and password-reset forms together with the form API for your own forms and the Contact Form 7 adapter, its self-test on the Tools page and the measured fill time, the community threat check on forms, the access lockdown switches, the system readiness register, the basic security headers, the TOTP / Passkey / Email 2FA methods, the password-reset gate, the recovery-code system, progressive block escalation, every dashboard, every export, the entire plugin source. A short, explicit list of what does need a paid plan: SMS 2FA (managed relay), WooCommerce frontend 2FA, Hardening Mode, advanced security headers (HSTS / CSP / cross-origin isolation), Priority Sync (the deeper WAF rulesets and live feeds), the audit event trail (Business), advanced security keys, multiple WebAuthn keys, model detection, key alerts (Business), adaptive 2FA triggers (Professional), unlimited registration rules with regular expressions and allowlist-only registration (Professional), the computation check on forms (Professional), the form protection on WPForms, Gravity Forms, Forminator, Formidable Forms, Formidable Forms PRO, Elementor Forms and Ultimate Member (Business), blocking user accounts and the session manager (Business), the managed mail relay quota, higher API quotas, multi-site management, white-label and the GDPR export tool. The plugin works fully offline in Local Shield mode, no plan, no account, nothing leaves your site.

== How Hive actually works ==

A short architectural map for evaluators:

= Two operating modes =

* **Local Shield**, fully offline. Every sensor decision is local; no outbound HTTP. The 2FA-mail-relay and reputation-check endpoints are never touched.
* **Community Network**, Local Shield plus opt-in IP-reputation lookups against `reportedip.com/wp-json/reportedip/v2/check` and queued threat reports against `/report`. Lookups are cached (24 h positive, 2 h negative); reports are batched by cron. Every Community-mode request identifies the installation wp.org-style (site address plus plugin and WordPress version in the User-Agent and an `X-Rip-Site` header) so the service can count the domains per licence.

= Request lifecycle =

1. **`init` priority 1.** The very first thing Hive does on every front-end request is check the IP against the local block table. Blocked IPs receive a 403 with `DONOTCACHEPAGE` + `Cache-Control: no-store` headers and exit before any other plugin's `init` handler runs.
2. **`wp_authenticate_user` priority 10.** Reputation check (Community-mode only) and IP-block check before the password is verified, failed-but-cheap, blocked attackers never trigger a `wp_login_failed` action.
3. **`authenticate` priority 99.** After WordPress core verifies the password, the 2FA orchestrator decides whether a second factor is required, sends an OTP if needed, and intercepts with a session-bound nonce + `wp-login.php?action=reportedip_2fa` redirect.
4. **`validate_password_reset` priority 5 + `password_reset` priority 5.** Since 1.6.5: a non-email second factor is required before any new password is persisted via the WordPress "lost password" flow. Email is excluded from the eligible methods because it is the channel that delivered the reset link itself.

= Storage =

* **9 dedicated tables** under the `wp_reportedip_hive_` prefix: `logs`, `blocked`, `whitelist`, `attempts`, `api_queue`, `stats`, `trusted_devices`, `audit_log` and `waf_exceptions`.
* **Schema v16**, auto-migrated step-by-step on plugin update; opt-in delete on uninstall.
* All secrets at rest (TOTP seeds, phone numbers) sealed with libsodium (OpenSSL fallback). Plain user-meta storage is never used for credentials.

= Throttle ladder =

A single failure-counter ladder is shared by every brute-force-style sensor (failed logins, 2FA wrong codes, password-reset wrong codes, application-password failures). 3 fails → 30 s, 5 → 5 min, 10 → 30 min, 15 → 1 h. After the 15th failure the IP is graduated to a real `blocked`-table entry via the canonical `handle_threshold_exceeded()` pipeline, which fires the progressive escalation ladder (5 m → 15 m → 30 m → 24 h → 48 h → 7 d) and, in Community mode, queues an anonymised report.

= Performance budget =

* **`init` priority-1 IP check**: ~1 indexed SELECT, request-level memoised, under 1 ms for blocked IPs, ~0.2 ms for clean ones.
* **REST API monitor**: skips authenticated users entirely so the Block Editor (50+ REST calls per page-open) never trips the rate-limiter.
* **Reputation cache**: ETag-based, 24 h positive / 2 h negative. Daily API usage stays low even on busy sites.
* **Reports**: queued, sent in batches of 20 by a 15-minute cron with a 5-minute transient lock against concurrent runs.

= Settings persistence =

Every option lives under the `reportedip_hive_` prefix in `wp_options` (tracked by an explicit snapshot test that fails CI on a silent rename). User-level data uses the `reportedip_hive_2fa_*` user-meta family. Admin actions write structured audit lines to the `logs` table.

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

= 2.1.65 =

New: form protection on WPForms and WPForms Lite (Business), on the page-load path and the background path alike. A refusal is the form's own error above the form, no entry is written and no mail is sent.

Fixed: a refused Elementor submission still sent the form mail. Elementor stops a submission only when the handler holds a field error, so a refusal given as a message alone let every submit action run first and reported the failure afterwards. The refusal is now a field error as well.

Fixed: sign-ups through Ultimate Member could be refused although a person filled the form in. Ultimate Member submits with a jQuery trigger, which fires no submit event, so the proof script never saw those submissions. It sees them now.

Fixed: the card that offers Extended Protection never appeared on sites running PHP-FPM, nginx or LiteSpeed, because the dashboard asked whether the server reads .htaccess while the one-click setup writes .user.ini there.

= 2.1.64 =

Security: a script that reads the hidden field names out of the page can no longer pass the form protection. The computation check now hands the browser a task from this site's own endpoint, signed, good once, expiring in ten minutes and harder the faster one network asks. The page stays fully cacheable. Verified across all eight surfaces (comment, sign-up, password reset, Contact Form 7, Formidable, Elementor, Ultimate Member, Gravity Forms): the field-name bot is refused, a real browser gets through.

Changed: no visitor loses a message to the check. A task the server cannot mint is handed out with zero difficulty, a browser that submits before its task arrives is held for a moment and then sent on, a plugin update restarts the day of grace, and without HTTPS the task keeps its signature and single use. The proof script keeps out of Cloudflare Rocket Loader and WP Rocket combining.

= 2.1.63 =

Security: the firewall's directory-traversal rule now matches every encoding on the wire, including the double-encoded form behind the WordPress 7.1.2 template fix, in both firewall layers.

New: form protection on Gravity Forms (Business), including forms sent in the background and forms with several pages. A refused submission is a validation error the sender sees above the form; nothing lands in a spam folder unread.

Changed: Contact Form 7 protection is included in every plan, Ultimate Member moves to Business next to Gravity Forms, Formidable Forms and Elementor Forms. A switched-on adapter above the plan keeps its stored value and can still be switched off.

Fixed: a form rendered again after a failed validation can pass the computation check; a community-reputation refusal above a third-party form names the form, not the password reset; certain comment spam blocks the address on the spot and the counter stands at three rejected comments a day; three German strings on the Protection page no longer show garbled umlauts.

= 2.1.62 =

New: the audit trail records what a support case needs. Eight trigger groups instead of eight account hooks: sign-ins, user accounts, pages and posts, plugins, themes and core, site settings with the old and the new value, menus and widgets, the built-in file editor and, on a network, sites and super admins. Every row names the acting user, how the request came in and the affected object. The groups are switches on the Protection page, retention defaults to 90 days and the sweep runs in chunks like the security log.

New: the audit tab reads like a record, with the user and address, the event and its group, the object and a sentence with old and new value, a filter by event or group, user, address, object and date, and exports that carry the active filter. Below Business the tab shows what it would answer and five sample rows.

New: on a network every site administrator has an Audit Trail page under the site menu with that site's rows, and the Network Admin narrows the network view to one site or to the network rows.

New: the event-type filter of the event log can be searched and selects whole groups; every event type the plugin writes is in one registry with its label, group and threat family.

Fixed: form spam was missing from the activity filter and from both dashboard charts, and three chart entries pointed at slugs nobody writes.

= 2.1.61 =

New: the Ultimate Member sign-in, sign-up and password forms are protected. The switch comes with Professional and the quickstart turns it on.

New: a sign-up through Ultimate Member runs the registration rules. The plugin writes the account itself instead of going through the WordPress sign-up, so a throwaway address or a reserved name used to be caught only by the last safety net, moments before the row was written and with nothing but WordPress's own "empty data" wording. The refusal now names the field it is about and the account never reaches the database.

Changed: a denial on the Multisite sign-up form that came from the community check or from a missing execution proof handed the visitor the form back with no reason on it. Both now carry their message across.

= 2.1.60 =

Changed: the community check on forms moved into the simple view, it switches a protection on and off. The action taken on a comment that scores as spam took its place among the expert settings, it picks between three ways of handling one and the default suits nearly every site.

= 2.1.59 =

Changed: the Protection page looks like it can be opened. Every area carries an arrow that turns when it opens, and the state on the right is a coloured pill: green for on, red for off, neutral for everything that is neither. The colour is decided where the state is built, not guessed from its wording.

Changed: the key check in the quickstart says clearly that it worked. The answer is a proper notice now, bold and in the success colour, and the error case reads just as clearly.

Fix: the information symbol was drawn wrong, and so were eleven others across the admin pages, the profile and the key manager. The dot of the "i" is a line of almost no length, which a browser draws as nothing unless the stroke has round caps, so the symbols looked like an upside down exclamation mark.

Fix: the hint next to the expert switch is a real layer instead of the browser's own tooltip, which waits a second, disappears on its own and never shows up on a phone. It is reachable with the keyboard and announced to a screen reader.

Changed: the form protection has its own area on the Protection page. Nine form checks used to sit inside "Registration & Spam" next to eleven rules about who may create an account, so anybody looking for the form protection had to know where to look. "Form Protection" now holds the comment decoy, the execution proof, the computation check, the three form plugins, the community check on forms and the comment spam action, and "Registration Rules" keeps what its name says.

Changed: every setting says which plan it belongs to. The plan marker used to appear only on a setting the plan does not cover, so somebody on Business saw nothing on the features they were paying for. A locked setting keeps the coloured marker naming the plan it needs; an included one carries a quiet grey note naming the plan it comes with.

Changed: the quickstart names the form plugins it found on the site, and stays silent when none of the three is installed.

Fix: the audit trail switch carried no plan marker although the trail is a Business feature and gated as one. Somebody on a lower plan could switch it on and never learn that nothing was being recorded.

Fix: a dashboard card no longer offers to cover "Formidable Forms forms". Two of the three form plugins carry the word in their own name.

= 2.1.58 =

Security: the form execution proof now covers three form plugins. Contact Form 7 comes with Professional, Formidable Forms together with Formidable Forms PRO and Elementor Forms with Business, each with its own switch. A submission that never carried the proof is still accepted for 24 hours after a switch goes on, so a page from an older cache locks nobody out. On these three forms a filled decoy now counts towards the block ladder the way it always has on a comment; a browser without JavaScript never does.

New: a form-protection self-test on the Tools page, tab Diagnostics. It lists what is switched on and then runs three passes with the browser of the operator, like a visitor, like the same visitor twice and like a bot. No real form is submitted, no mail goes out and no entry is stored.

New: the proof field carries how long the form was on screen. The starting point comes from the browser, never from the markup, so a page cache cannot falsify it. The value is not signed and is therefore enforced on the comment filter alone, where it weighs 2 of the 7 points; everywhere else it is only measured and logged.

Fixed: two forms on one page, and every step of a multi-step form, get their own proof answer. The script wrote a single answer into every form, and the server accepts an answer only once, so the second submission read as a repeat.

Security: the comment spam filter reads eight more signals. Measured against 27,796 real comments of a site collecting them since 2014, the old content rules caught 9.1 per cent of the spam and everything else rested on the form execution proof, which a botnet running a real browser walks past. The filter now also reads the user-agent header, link markup pasted back from a rendered page, digits and foreign script in the author name, the language of the text against the language of the site, a praise opening next to a link, how often a link target was submitted before, and whether the same text has arrived already. On the same comments the hit rate rises to 95.2 per cent and the false positives fall from 32 to none.

Changed: a missing execution proof no longer files a comment as spam on its own. The threshold rose from 4 to 7 and the proof still weighs 4, so it needs a second reason; until now a reader browsing without JavaScript was filed as a spammer for that alone. A filled decoy field and a domain in the author name still convict by themselves.

Fixed: one submitted comment counts once towards the per-address block ladder. A filled decoy was counted twice, so an address reached a threshold of five after three comments.

= 2.1.57 =

Changed: the Activity page opens on the event log and every tab starts with a sentence that says what the list is for; the filters moved into a labelled filter bar that survives paging and bulk actions. The Community page has three tabs: Settings, Community and Badges, the badges tab shows the footer badge with its live preview and a banner builder with templates. The dashboard carries one status line ("Protection active since <date> on the <plan> recommendation") instead of the API strip, and the protection areas are collapsed cards with the points each one would add to the score. The 2FA Status page filters its user list by status, method and role. Leftovers of the retired Settings and Firewall pages are gone.

Fixed: a rejected Community Access Key no longer counts as a failed API sample for three hours; the report-queue readiness issues stay silent in Local Shield; the Protection page shows stored role and method lists as checked; a settings export from a site on its defaults no longer writes null and switches protections off on import; the settings import on the System Status page works again; the test-mail button on the Tools page works again; seven score links opened the wrong Protection card; the audit log CSV is Business-only like the audit trail; the footer-badge preview on the Community page comes alive on every tab.

= 2.1.56 =

Changed: the Settings and Firewall pages are gone; one Protection page replaces them. Every area of the settings registry is a collapsible card with a short status and a search box; simple depth shows the sixteen day-to-day settings, expert depth shows every field. A Tools page (expert mode, always reachable by URL) carries the Extended Protection drop-in, rule sync, WAF exceptions, hardening status, import/export and the test mail. Old settings and firewall addresses redirect to their new home.

Changed: the dashboard answers "done, and now?" with a status banner, next-step cards from six new advisory readiness checks (with one-click actions), a row per protection area and at most one upsell card per visit. News from reportedip.com render as a card grid.

Changed: expert mode is a switch in the page header with an info icon; it is stored per person. The plan locks of the former tabs are back on the Protection page, and saving a card never resets a locked field.

Fixed: the quickstart key check showed a stale domain count after the key was replaced.

= 2.1.55 =

Fix: the quickstart's expert route landed in the 2FA onboarding instead of the settings when the 2FA switch was on or "switch protection on" had been pressed before. The expert route now clears the pending onboarding; enforcement stays as chosen and the onboarding returns on the next sign-in.

= 2.1.54 =

Changed: the setup wizard is gone; a one-page quickstart replaces it. It asks for the operation mode and the Community Access Key, reads the plan from the key check and switches on a plan-aware recommendation through the settings registry. Three switches stay visible (2FA for administrators, the footer badge, alert mails); everything else is preconfigured. The old wizard address redirects to the quickstart.

Changed: the Security Dashboard lost its clutter. API statistics and the licensed-domains card moved to the Community page, the quick-action tiles are gone, the activity list shows the five latest events, and the three latest reportedip.com news items appear at the bottom in the admin's language (Community Network only).

Changed: a plan upgrade switches on what the new plan recommends for every setting the admin has not changed, and the post-upgrade banner lists what changed.

Changed: every stored setting follows one standard; eight options that lived outside the settings registry now have a default, a registry entry and a form.

Removed: three unused options, the unreachable relay mail Reply-To option, and the legacy threshold sanitizers.

= 2.1.53 =

New: community threat check on forms. A comment, sign-up or password reset is now checked against the community network at the same protection level the sign-in page enforces, so someone the site would refuse a login to cannot post a comment instead. The visitor is told why, and the address is closed for 24 hours as a refused sign-in closes it. On by default, switchable, dormant without Community Network mode.

New: form execution proof. Comment, sign-up and password-reset forms carry a hidden anchor field, and a small script adds a second field whose name is random per installation. A submission carrying neither never rendered the form, which is exactly what a script posting straight at the address looks like. Nothing request-specific is emitted, so page caches are unaffected. For comments the result is a score signal, so a reader without JavaScript is filed for review rather than refused; sign-up and password reset do refuse and say why. Free on every plan.

Security: the comment filter now skips whitelisted and already-blocked addresses, like every other sensor.

Changed: the comment decoy moved to a hook that also fires for logged-in visitors, and a filled decoy is scored instead of answered with its own 403.

= 2.1.52 =

Security: a comment waiting for approval is no longer treated as spam. The comment sensor read the approval state WordPress had already decided on and counted "held for moderation" as a spam verdict, so on a site where every comment needs manual approval, ordinary readers were logged as spammers, counted towards the block ladder and reported to the community network.

New: comment spam filter. Every incoming comment is scored on link count, link density, the number of distinct domains, throwaway mail domains, giveaway top-level domains, a domain in the author name and a body that carries no message behind a link. Several signals have to agree before a comment counts. The default action files it as spam for review; rejecting it outright is opt-in. Free on every plan.

Changed: a comment that trips the honeypot now counts towards the per-address comment counter, so a bot walking into the trap repeatedly reaches the block threshold.

= 2.1.51 =

New: registration defence. The registration sensor grew from a throwaway-mail check into a rule set with prohibited usernames, e-mail allow or block rules, a per-IP registration rate limit and an opt-in block for sign-in attempts against usernames that do not exist. Ten plain entries per list are free; Professional lifts the cap, accepts regular expressions and adds registration restricted to allowlisted IP ranges.

New: access lockdown switches. A new section on the Firewall page turns off the REST API for signed-out visitors or for everyone outside chosen roles and namespaces, XML-RPC and pingbacks, feeds, the admin area for signed-out visitors, PHP execution in the uploads folder and the version fingerprints in the page source. Free on every plan.

New: system readiness register. Twelve detectors report an unwritable guard queue, stalled or disabled cron, a trusted proxy header without proxy ranges, an outdated database schema, a degraded community layer, exhausted relay quotas, failing mail delivery, a missing encryption extension and a growing report queue on the System Status page and in `wp reportedip status`.

New: block user accounts and manage sessions (Business). A blocked account keeps its content but cannot sign in, authenticate an application password or complete a password reset, and loses every session and trusted device. The new Users → Sessions page lists and terminates active sessions.

New: adaptive two-factor triggers per role (Professional). Seven step-up rules ask for the second factor again on a new country, IP address, network or device, every N days or sign-ins, or above a concurrent-session limit, even when a trusted-device cookie is present. The 2FA IP allowlist still bypasses.

Changed: every setting is one setting everywhere. Seventy options lived outside the settings registry, so MainWP and the cloud fleet could not manage them and the JSON export left them out: the security headers, the trusted-proxy pair, the application-password and REST limits, the geo-anomaly window, the WooCommerce login monitor, the hide-login probe, the password policy, the caching and report-queue settings, the audit trail and the eight hardening options. All of them are registry options now, all 169 carry a one-sentence description that the settings page, MainWP and the fleet render alike, fourteen of them gained a form in wp-admin for the first time, and the sections were re-cut along what the options actually do. No option key changed, so stored fleet policies and site overrides are untouched; both dashboards need one schema reload to show the new grouping.

Security: an imported settings file can no longer write anything unchecked. The import used to send known keys through the sanitiser and everything else straight to the option store. That raw path is gone. It mattered most for the trusted client-IP header, where an arbitrary value is the precondition for spoofing every sensor, the whitelist and the block list at once.

Changed: the settings cards on the Firewall page write through the settings registry, so plan limits apply to them as well; honeypot sites now count as Contributor; the user sitemap disappears while user-enumeration blocking is on (default on); `wp_login` fires after a passed two-factor challenge and after a REST verify; the hardening score was re-balanced; the trusted-proxy warning became a standing readiness issue; the setup wizard offers the new lockdown switches and two of the adaptive triggers; the audit trail's IP anonymisation and new-address alert do something now.

Changed: a privacy request covers the new account data. The export carries an account block with its texts, the address and expiry of every open session and the sign-in history behind the adaptive triggers; an erasure clears the texts and the history but keeps the block itself and reports it as retained.

Fixed: Hide Login blocked logged-out `admin-post.php` requests; on Multisite a sub-site administrator could write network settings through the admin AJAX handlers; the Rule Sync tab showed no label for the Tor exit-node list; the Logs page offered an XMLRPC filter that never matched a row; the decoy `.htaccess` block is now removed completely when switched off; uninstalling with "delete all data" left the account-block record behind in user meta.

Security: hardening mode now reaches every login surface. While a coordinated attack tightened the failed-login threshold network-wide, the WooCommerce login monitor (My Account and classic checkout) and the application-password monitor kept using the relaxed values, so an attack on the storefront forms slipped through untouched. Both are now clamped like wp-login. The gap dates back to 2.0.8; sites without WooCommerce and without application passwords were never affected.

Changed: the eight hardening options are part of the remote settings standard, so MainWP and the cloud fleet can manage them. The master toggle stays local because its "no stored value" state is what enables hardening automatically on Professional and higher.

Fixed: the distributed-detection help texts named 5 and 20 as defaults while the code used 10 and 50.

= 2.1.50 =

Security: the community reputation block threshold now has a hard floor of 25 %, sub-floor values blocked far more legitimate visitors than attackers. The floor applies everywhere (settings UI, import, cloud and MainWP writes, hardening mode) and a one-time migration lifts already-stored lower values; the wizard's "High" protection preset softens from 50 % to 60 %. Sites can raise the floor further via the reportedip_hive_reputation_threshold_floor filter.

New: full IP management on WP-CLI, wp reportedip whitelist add/remove/list, block, unblock --reset-attempts, blocked list and attempts reset, plus a wp reportedip status overview. All accept CIDR ranges; see the WP-CLI section above.

= 2.1.49 =

Security: the cloud fleet management endpoint now returns a single generic authentication error whether the feature is disabled or the request signature is invalid, so an unauthenticated caller can no longer tell from the response whether a site has opted in. Hardening follow-up to the 2.1.48 cloud transport; no configuration change required.

= 2.1.48 =

New: cloud fleet management transport (Business plan). reportedip.com can read the settings schema and apply security policies through Ed25519-signed REST requests, verified against a bundled public key, bound to this site and your Community Access Key, replay-protected and strictly opt-in via a new toggle on the General settings tab (off by default). While enabled, API requests announce a settings fingerprint so the fleet dashboard detects drift passively.

Fixed: the "Reset API statistics" button on the security dashboard works again, and the admin pages no longer scroll sideways on phones.

= 2.1.47 =

New: canonical settings registry. The plugin's core settings now share one declarative source for value kinds, ranges, allowed values, tier gates and side effects, the settings page, the setup wizard and the settings import all sanitize through it, so every writer behaves identically, including writers outside wp-admin.

New: remote settings management protocol (schema v1). Management dashboards can read the settings schema, read current values and apply a validated batch with a per-key result; every sync reports a settings fingerprint for drift detection. Documented in docs/remote-settings-protocol.md; the MainWP extension uses it today and the reportedip.com management API can adopt the same contract later.

Changed: rewrite-rule flushes for Hide Login and frontend 2FA now run for every writer via option watchers, so a remote or CLI write can no longer leave stale rewrite rules behind.

= 2.1.46 =

Fixed: remote-management dashboards (MainWP, ManageWP and similar) could neither see nor install plugin updates since 2.1.32, because the update checker was skipped on the front-end requests those tools sync over. It now runs in every request context again.

Changed: WordPress auto-updates are always on for this plugin, so security fixes install without a per-plugin opt-in. Pin the version with add_filter( 'reportedip_hive_auto_update', '__return_false' ) if you must.

Fixed: with extended protection enabled, activating the plugin ended in a fatal error and left it deactivated. Activation rebakes the pre-WordPress guard, and that step reads the trusted-proxy ranges without the class that parses them being loaded. Sites that had deactivated the plugin could not turn it back on.

= 2.1.45 =

New: every request to reportedip.com now identifies the installation with the site address and the plugin and WordPress version, the same way core announces itself to wordpress.org. The Security Dashboard shows how many domains the Community Access Key is used on versus the plan allowance. Third-party services never receive the site identity.

= 2.1.44 =

Security: results of a full-codebase audit. Blocked addresses could still reach admin-ajax.php, and requests there were inspected by neither firewall layer. A single firewall exception could mask every rule ordered behind it. A malformed prefix such as 10.0.0.0/-1 made the pre-WordPress guard match every address. Percent-encoded probes (/wp-login%2Ephp, /%2Eenv) slipped past the hidden login, the scan detector and the decoy paths. A submitted 2FA method was never checked against the factors the user actually has, TOTP codes could be replayed within their window, and the unauthenticated 2FA REST routes accepted cross-origin logins.

Fixed: blocks and unblocks took up to five minutes to apply on sites with a persistent object cache; lifting a CIDR block or an expiring whitelist entry left the guard enforcing the old state. Replacing an authenticator destroyed the working secret before the new one was confirmed. Two queue workers could send the same report twice. Queue searches beginning with s, d or f returned nothing. Clearing the reputation cache did nothing under Redis or Memcached. Comment spam behind a proxy was attributed to the edge address.

= 2.1.43 =

Changed: corrected the contact domain in two historical changelog entries (reportedip.de to reportedip.com). No code change.

= 2.1.42 =

Fixed: failed XML-RPC app-password logins no longer count twice, the application-password sensor claims the wire attempt and the generic failed-login listener stands down for the duplicate row and attempt count; coordinated-attack detection now counts app_password_failed rows alongside failed_login so nothing goes invisible.

Changed: the event-type filter on the Activity tab gained an App Password Failed option.

= 2.1.41 =

New: Tor exit-node blocking (Professional), an opt-in toggle under Settings → Blocking rejects connections from known Tor exit nodes. The exit-node list arrives as a signed tor_exits ruleset refreshed twice daily; blocks are temporary (24 hours by default, filterable) and are never reported to the community, operating an exit node is not abuse evidence.

New: trusted-proxy source ranges, the trusted IP header is only honored when the connecting peer is one of the proxy addresses declared under Settings → General (IP/CIDR list), so a direct connection can no longer spoof a whitelisted address or shed a block. An empty list keeps the previous behavior.

New: security widget on the WordPress dashboard, attacks blocked in the last 30 days, blocks today, active IP blocks, protection layers and the detection score, with deep links into the plugin. On Multisite the widget appears on the network dashboard.

New: "What's new" banner, after an update, plugin pages show a one-time dismissible summary of the release highlights.

New: never-block veto for community-verified infrastructure (search-engine crawlers, major CDNs, monitoring fleets), local blocks are spared and logged as infrastructure_spared; reports still go out.

New: developer hooks, reportedip_hive_threshold_exceeded fires on every confirmed detection, reportedip_hive_report_queued fires once per queued community report, and the block page gained reportedip_hive_access_denied plus a strings filter for white-label overrides.

New: every IP in the admin tables carries copy, internal-lookup and a link to its public reportedip.com profile; the lookup tab shows ISP, ASN, usage type, Tor and infrastructure flags with Block/Whitelist quick actions; also available as wp reportedip lookup (table/json/csv/yaml output).

New: add-my-IP helper on the whitelist form (IPv6 prefills the /64 network), a confirmation before blocking your own current IP, a date-range filter on the event log and a duration choice for the block-from-log action.

Fixed: attempt counters are race-safe, a single atomic upsert per IP and attempt type (schema v15), so parallel failed-login bursts can no longer lose counts.

Fixed: API rate-limit back-off is scoped per endpoint and the report path honors Retry-After; the reputation cache respects verbosity and is invalidated by your own reports; CIDR ranges are accepted in the manual block form; the blocked-page contact URL resolves network-wide on Multisite.

Fixed: WooCommerce-only settings (login monitor, storefront-2FA card in the wizard) grey out with an explanatory note when WooCommerce is not installed. Thanks to Benjamin for reporting.

Fixed: 2FA emails stay readable in GMX Webmail and Outlook for Android, header and button carry a solid color fallback for clients that strip CSS gradients, and the footer text meets contrast requirements.

Changed: an API status strip on the Security Dashboard summarizes connection, quota (with reset countdown) and rate-limit state from cached data, and the daily quota display stays fresh between cron runs.

Changed: accessibility pass, forced-colors and reduced-motion support, focus rings that survive Windows High Contrast, 40px touch targets on coarse pointers and a polite live region for AJAX notifications; roughly 90 admin-JS strings became translatable.

= 2.1.40 =

Security: claiming to be a search engine no longer protects an attacker. Hive spares genuine crawlers from its automatic blocking so a Googlebot crawl over stale URLs can never lock the bot out of the site. That protection was granted on the strength of the user-agent alone whenever the crawler could not be checked, and almost none of the crawlers in the list can be checked without the rule set naming them. Anyone sending "GPTBot", "Amazonbot" or "FacebookBot" was therefore exempt from the block ladder and from community reporting. On one production site that meant 47 skipped blocks in three days, each for a request probing for exposed configuration files or private keys from a data-centre address that belonged to none of the companies named. From now on the exemption requires a rule that can actually verify the crawler, by reverse DNS or by an official address list. A name-server outage still gives a checkable crawler the benefit of the doubt.

Security: an attack request now cancels the exemption outright. Requests for bait paths that nothing links to, and firewall hits for traversal, command and code injection, web shells or probes for credential files, are treated as attacks whoever the visitor claims to be. They block, they are reported, and the revoked exemption is recorded in the log. Search-term and editor-content patterns keep the previous three-strike ladder on purpose, so a customer searching your shop is never locked out over a product code. Those same attack patterns now block on the first hit instead of the third, and two crawler exemptions that were broader than documented were narrowed: the REST user list and the REST enumeration route are no longer covered.

Also: the bundled crawler list gained Baiduspider, LinkedInBot and Amazonbot, and the ReportedIP service now delivers official address lists for Google's specialist crawlers, Apple, DuckDuckGo, OpenAI, Perplexity, Ahrefs and the common uptime monitors, so those crawlers keep their exemption.

= 2.1.39 =

Security: the bundled rule files never made it into the release package. The build copied the plugin's code folders but not the one holding the four baseline rule sets, so an installed copy found no rules on disk and the firewall passed every request through. Bot signatures and the disposable-address list were empty for the same reason. Sites that pull rules from the ReportedIP service were unaffected, since a downloaded set replaces the bundled one, which is why this stayed invisible for so long. Both builds now include the rule files and refuse to package a release without them. Updating puts the free firewall into service for the first time on unconnected installs.

Security: the firewall learned to see injected markup, not just injected code. Both existing cross-site-scripting signatures look for a script tag or an event handler, so a payload made purely of HTML passed untouched. That is the shape of the login-screen chain published in August 2026 (CVE-2026-64638). Four new rules close it on every plan: a login field containing an angle bracket is rejected outright, because WordPress strips those from usernames; a second rule catches the smuggled element itself and so covers the whole class of sanitiser disagreements rather than this one advisory; two more cover the escalation through the REST JSONP callback. Twelve attack variants blocked, no false positives across thirty-four ordinary requests. They run in the pre-WordPress guard too. This is an extra layer, not a replacement for the WordPress fix.

= 2.1.31 =

Changed: a burst now buys ladder rungs. The escalation ladder counted block events rather than offences, so an attacker who tripped the threshold once and kept firing got the same five minutes as one who stopped, every later offence hit an already-blocked IP. A bot with 60 violations in ten seconds is now weighted directly: five times the threshold skips one ladder rung, ten times skips two, twenty-five times skips three.

Changed: repeat offences against the same rule are imported as one event with an offence count and a sample of the targets tried, instead of one row per request. Twenty near-identical rows used to bury every other finding on the Firewall page and skew the 30-day statistic. Enforcement is unchanged, every offence still counts toward the block ladder.

Fix: the hit queue can no longer be imported twice. Rotating the file is atomic, importing it was not, so the queue cron and an admin page view could double both the log and the offence counter. The drain now takes a mutual-exclusion lock.

Fix: the server can no longer block itself. Cache-preload crawlers (WP Rocket and friends), WP-Cron loopbacks and REST self-requests connect back through the site's public URL, so their address is the server's own public IP, and the burst sensors treated it like any attacker: auto-blocked for days, enforced before WordPress loads, and reported to the community against the site's own reputation. The automatic pipeline now stands down for the server's own addresses (loopback, the request's interface address, everything the site hostname resolves to), an upgrade migration lifts self-blocks that are already active, and averted decisions stay visible in the log.

= 2.1.30 =

New: extended protection now enforces IP blocks before WordPress loads. The guard knew the firewall rules and the whitelist but not the block list, so a banned IP still reached WordPress on every request. Active blocks are mirrored into a protected side file the guard reads first, a new block applies within the same request, a lifted one stops applying immediately, whitelisted IPs still win, and blocks hold even when rule inspection is off.

New: extended protection (the pre-WordPress guard) now records what it blocks. It runs before WordPress loads and could previously neither log nor escalate, and because it evaluates the same rules as the in-WordPress engine it also intercepted every hit that engine would have logged, so a site running it reported zero WAF hits no matter how much it blocked, repeat offenders were never escalated to an IP block, and nothing reached the community. Hits are now queued to a protected file under uploads/ and imported on the next admin request or queue cron, stamped with the time the request actually happened. The Firewall page reports whether the queue is writable.

Fix: the setup wizard opens again after activation on busy sites. The one-shot activation marker was consumed by any request passing through admin_init, including admin-ajax.php, on a WooCommerce store the Action Scheduler or Heartbeat regularly won that race and the wizard silently never appeared. Background requests now leave the marker alone.

Fix: the Firewall page counts detected scans again. Counter and log filter looked for an event type the detector never writes; both now read the type that is actually stored.

Fix: failed-login, comment-spam, XML-RPC and successful-login entries show the correct time. Those four stamped their timestamp detail with the site-local clock while everything else stores UTC, so the detail read a full timezone offset ahead of its own row.

Fix: coordinated-attack logs no longer show "1. January 1970" as their time window. The distributed detector labels its window with a bucket index rather than a date, and the log table pushed that through a datetime formatter. The label now resolves back into the timespan it measured, and unparseable values are printed verbatim instead of as the Unix epoch.

Fix: "Hardening expires at" renders as a date in the site timezone instead of a raw Unix timestamp, and "Anonymized at" is converted from UTC like every other logged datetime.

Fix: the "API health degraded" warning no longer repeats every hour for an outage that already ended. The health window holds the last 50 calls, which on a low-traffic site spans more than a day, so a finished fault kept the rate below the threshold. The warning now also requires a failed call within the last three hours.

Everything before 2.1.30, back to 1.0.0, is kept in full in [CHANGELOG.md](https://github.com/reportedip/reportedip-hive/blob/main/CHANGELOG.md).

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

== Disclaimer ==

ReportedIP Hive is provided **"as is"** and **"as available"** under the terms of the GNU General Public License version 2 or later (GPL-2.0-or-later). The licence in full: [gnu.org/licenses/gpl-2.0.html](https://www.gnu.org/licenses/gpl-2.0.html).

= No warranty =

There is **no warranty** for the program, to the extent permitted by applicable law. Except when otherwise stated in writing, the copyright holder and other parties provide the program "as is" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose. The entire risk as to the quality and performance of the program is with you. Should the program prove defective, you assume the cost of all necessary servicing, repair or correction.

This includes, explicitly and without limitation, no warranty of:

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
* understanding the consequences of enabling 2FA enforcement, hide-login, password-reset gating and IP blocking, in particular the documented edge case where an account with only email-2FA and no recovery codes is intentionally locked out of the password-reset flow until an administrator intervenes;
* maintaining recovery procedures (recovery codes, alternative second factors, WP-CLI access, server-level access) so that a misconfiguration or an upstream service outage does not cause permanent loss of access to the site;
* obtaining and maintaining any data-processing agreements, terms of service or end-user disclosures required by applicable law for the SMS, email or threat-intelligence services they choose to use.

To help with that end-user disclosure, a configuration-aware privacy-policy generator (German / English) is provided at [reportedip.com/dashboard/dsgvo](https://reportedip.com/dashboard/dsgvo), and a suggested passage is registered in the WordPress Privacy Policy Guide (Tools -> Privacy). Both are **templates only**, provided without warranty, and do **not** constitute legal advice or replace your own review, the no-warranty and no-liability terms above apply to them in full.

= Security disclosures =

If you believe you have discovered a security issue in ReportedIP Hive, **please do not open a public GitHub issue**. Send the details to [abuse@reportedip.com](mailto:abuse@reportedip.com). We will acknowledge receipt within five business days.

= Recommended posture =

Treat ReportedIP Hive as one layer in a defence-in-depth setup. Pair it with:

* offsite, versioned backups (database + uploads + plugin configuration);
* a malware scanner of your choice, Hive deliberately does not include one;
* a server-level firewall (Cloudflare WAF, Nginx `deny`, fail2ban) for blocking on cached public pages, which the plugin cannot reach by design;
* a reasonable patch cadence, install updates as they are released, run `./run.sh check-all` (or your CI equivalent) before upgrading on production-critical sites.

By installing or activating this plugin you confirm that you have read and accepted the terms above and the GPL-2.0-or-later licence under which the plugin is distributed.
