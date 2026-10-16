=== ReportedIP Hive: Firewall, Brute Force Protection, 2FA and Anti-Spam ===
Contributors: reportedip
Tags: security, firewall, brute-force, 2fa, anti-spam
Requires at least: 5.9
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 3.0.1
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Firewall, limit login attempts, 2FA with passkeys and anti-spam for comments and forms without CAPTCHA. Optional IP blocklist. GDPR-first.

== Description ==

ReportedIP Hive is a free WordPress security plugin with a web application firewall (WAF), brute force protection, two-factor authentication (2FA) and anti-spam protection for comments, registrations and contact forms. It is built for site owners, agencies and WooCommerce shops that want login security and spam protection in one plugin, without a CAPTCHA and without sending data anywhere by default.

The plugin blocks attacking IP addresses on your own server. It needs no account. Sixteen sensors watch the sign-in form, XML-RPC, the REST API, the comment, registration and password-reset forms and every request. An optional community IP blocklist shares and checks attacking addresses with other sites.

Everything described here up to the add-on section is free and complete: no trial, no locked switch, no time limit.

= Web application firewall (WAF) =

* **Request inspection** with a bundled ruleset against SQL injection, cross-site scripting (XSS), path traversal, command injection and vulnerability scanners.
* **Pre-WordPress firewall.** An optional layer (`auto_prepend_file`) applies the same rules, exceptions, whitelist and IP blocks before WordPress loads. A blocked request costs almost nothing.
* **404 and scanner detection.** Requests for bait paths such as `.env`, `.git/config` or `wp-config.php.bak` block the address at once.
* **Verified bot detection.** Googlebot, Bingbot and other large crawlers are confirmed through their published address ranges or reverse DNS. A fake Googlebot is treated like any other visitor.
* **REST API rate limit**, firewall exceptions per rule, path or IP, and a report-only mode for testing.
* **IP blocking and whitelist** for single addresses and CIDR ranges, with incident reference codes on the block page.

= Login security and brute force protection =

* **Limit login attempts.** Failed sign-ins are counted per IP address. The default blocks an address after 5 failures in 15 minutes.
* **Progressive IP blocking.** Six steps from 5 minutes to 7 days. The ladder resets after 30 quiet days, so a typo never costs a day.
* **Password spraying detection.** Many usernames tried from one address are caught separately.
* **Application password protection.** Failed Basic Auth sign-ins count like failed logins, so the REST API is no way around the limit.
* **Hide Login.** Move wp-login.php to a custom login URL.
* **User enumeration protection.** Author archives, the users REST route, the user sitemap and login error messages no longer reveal usernames.
* **Login anomaly detection.** A sign-in from a new country is logged and asks for the second factor again.
* **WooCommerce login protection.** My Account sign-in and registration are counted like wp-login.php.
* **Password policy** with minimum length, character classes and an optional breach check (off by default).

= Two-factor authentication (2FA) =

* **Authenticator apps (TOTP)** such as Google Authenticator, Microsoft Authenticator, Authy or 1Password.
* **Passkeys and hardware security keys (WebAuthn, FIDO2),** for example a YubiKey, Face ID, Touch ID or Windows Hello. One key per account.
* **E-mail codes.**
* **Recovery codes,** ten single-use codes per user.
* **2FA enforcement per user role,** an enrolment wizard, trusted devices for 30 days and a password-reset gate that a stolen mailbox cannot bypass.
* **WP-CLI commands** to enable, reset and audit 2FA per user.

= Anti-spam and form protection without CAPTCHA =

ReportedIP Hive replaces a CAPTCHA with checks the visitor never sees. No puzzle, no checkbox, no Google reCAPTCHA or other third-party script.

* **Invisible execution proof.** A hidden decoy field and a short script prove that a real browser filled in the form. A bot that fills the decoy is blocked on the first try and, in the Community Network, reported. The check carries nothing request-specific, so cached pages keep working.
* **Comment spam filter.** Scores links in the text and the website field, link density, the number of domains, disposable addresses, throwaway top-level domains, a domain in the author name, foreign script and text without content. Spam goes to the spam folder or is rejected.
* **Comment honeypot.**
* **Registration spam protection** for WordPress, WooCommerce and multisite sign-ups: prohibited usernames, e-mail allow and block rules, a sign-up rate limit and an optional block for sign-ins with unknown usernames. Ten entries per list.
* **Disposable e-mail blocking** on registrations and forms.
* **Password reset spam protection.** The lost-password form carries the same proof.
* **Contact Form 7 spam protection** with the same invisible check.
* **IP reputation on forms.** In the Community Network, comment, registration and password-reset submissions from known attacking addresses are refused.

= Hardening and attack surface =

* XML-RPC and pingbacks off with one switch.
* REST API for signed-in users or chosen roles only.
* Feeds, wp-admin for guests, PHP execution in the uploads folder and software version fingerprints, each a switch.
* Security headers: X-Content-Type-Options, X-Frame-Options and Referrer-Policy.
* Protection score and a readiness check that lists what still needs attention.

= Activity log and operations =

* Security activity log with filters by event type, severity and date, CSV and JSON export.
* E-mail alerts for blocks and critical events.
* Settings import and export.
* WP-CLI: `wp reportedip block`, `unblock`, `whitelist`, `lookup`, `status` and `2fa`.
* Works behind Cloudflare and other reverse proxies with a trusted proxy list.
* Compatible with WP Rocket, W3 Total Cache, WP Super Cache and LiteSpeed Cache.

= WordPress multisite and MainWP =

* Network-activated, one set of tables, IP blocks and whitelist shared by every site.
* Site admins see the activity of their own site; protection is managed by the network admin.
* MainWP dashboards read status counts and push settings through the MainWP Child plugin, with no extra child plugin.

= Community threat intelligence (optional) =

* **Local Shield** is the default. The plugin makes no outbound request.
* **Community Network** is opt-in. With a free Community Access Key from [reportedip.com](https://reportedip.com/?rc=hive-wporg) the plugin checks the IP reputation of attacking addresses during sign-in and on forms, shares the addresses it blocks with the community IP blocklist and receives signed firewall, bot and disposable-domain rulesets.

= Privacy and GDPR =

* Minimal logging, retention of 30 days by default, addresses anonymised after 7 days.
* Usernames, passwords and form content never leave the site.
* A suggested text for your privacy policy is added under Settings, Privacy.
* Made in Germany.

= What it does not do =

ReportedIP Hive does not scan files for malware and does not monitor file integrity. Run a malware scanner next to it if your site needs one.

= ReportedIP Hive Pro add-on =

ReportedIP Hive Pro is a separate add-on for paid plans. It is not hosted on wordpress.org and adds new features on top of this plugin; nothing in the free plugin is held back for it.

Professional plan:

* **Managed 2FA mail relay** (500 mails per month) and **SMS two-factor authentication** through an EU SMS gateway (25 SMS per month).
* **WooCommerce two-factor authentication** on My Account, the classic checkout and the WooCommerce Blocks login, inside the shop theme.
* **Adaptive 2FA policies per role:** ask again on a new device, IP address, network or country, every N days or sign-ins, or above a session limit.
* **Hardening mode** that tightens thresholds for one hour during a coordinated attack.
* **Advanced security headers:** Content Security Policy (CSP) builder, HSTS with preload, Permissions-Policy and Cross-Origin headers.
* **Computation proof on forms,** a proof of work the browser solves in the background, as a CAPTCHA alternative that a script cannot copy.
* **Tor exit node blocking.**
* **Unlimited registration rules** with regular expressions and sign-ups restricted to allowlisted IP addresses.
* **Group ban lists:** one block list and whitelist shared by all sites of a group.

Business plan, in addition:

* **Spam protection for further form plugins:** WPForms, Gravity Forms, Elementor Forms, Formidable Forms, Forminator and Ultimate Member.
* **Audit trail (activity log for changes):** who changed which setting, plugin, theme, page, menu, file or user account, with old and new values and export.
* **User account blocking and session management:** block accounts, end sessions and review active sessions.
* **Multiple security keys per account** with model detection.
* **Cloud fleet management** of many sites from the reportedip.com dashboard.
* Higher mail and SMS quotas (2,500 mails and 75 SMS per month).

Paid plans also receive fresher and deeper rulesets through the Community Network. Plans and prices: [reportedip.com pricing](https://reportedip.com/pricing/?rc=hive-wporg).

Documentation: [ReportedIP Hive guide](https://reportedip.com/docs/integrations/wordpress-hive/?rc=hive-wporg).

== Installation ==

1. Install the plugin from the WordPress plugin directory and activate it. On a multisite network, install it in the Network Admin and click Network Activate.
2. The quickstart opens after activation, on a multisite network in the Network Admin. It lets you pick Local Shield or the Community Network and applies the recommended settings with one click. You find it again under ReportedIP Hive, System Status, Open quickstart.
3. Enrol your own second factor on your profile page.

The plugin writes its two optional .htaccess blocks (bait-path responses and PHP execution in uploads) when the quickstart completes, never at activation. On nginx it shows a snippet to paste instead.

== Frequently Asked Questions ==

= What is ReportedIP Hive? =

ReportedIP Hive is a WordPress security plugin that combines a firewall, brute force protection with limited login attempts, two-factor authentication with passkeys and anti-spam protection for comments and forms. It runs on your own server and works without an account.

= Is ReportedIP Hive free, and do I need an account? =

Yes, the plugin is free under the GPL and works without any account. A free account at reportedip.com adds the community IP reputation check and synced firewall rulesets.

= Does ReportedIP Hive replace a CAPTCHA or reCAPTCHA? =

For most sites, yes. The invisible execution proof stops scripted submissions on comments, registrations, password resets and Contact Form 7 without a puzzle for your visitors and without loading a third-party service.

= How does it stop comment spam? =

Three layers: the invisible execution proof refuses bots that do not run a browser, the honeypot catches bots that fill every field, and the comment spam filter scores links, domains, disposable addresses and text without content. Spam goes to the spam folder or is rejected.

= Is it GDPR compliant? =

The plugin is built for GDPR compliance: logging is minimal, retention is configurable (30 days by default), addresses are anonymised after 7 days and the Community Network is opt-in. In Local Shield mode no data leaves the site.

= Which data leaves my site in the Community Network? =

Only the attacking IP address, the event category, the time, your site name and address, the attempt count and the plugin version. Usernames, passwords and form content never leave the site.

= Does it work with WooCommerce? =

Yes. The WooCommerce sign-in and registration forms get the same login attempt limits, registration rules and disposable e-mail blocking. Two-factor authentication on the storefront is part of the Pro add-on.

= Does it support passkeys and YubiKeys? =

Yes. Any FIDO2 or WebAuthn authenticator works as a second factor, including YubiKey hardware keys and platform passkeys such as Face ID, Touch ID and Windows Hello.

= Will it slow down my site? =

On an anonymous page view the plugin runs five database queries of its own. A request from a blocked address is refused by the pre-WordPress firewall in about 1.5 ms. Both figures come from a test site with 500,000 log entries and 5,000 blocked addresses. Community reports are sent in the background by WP-Cron.

= How is it different from Wordfence? =

Wordfence includes a malware scanner and file integrity checks; ReportedIP Hive does not. ReportedIP Hive focuses on the firewall, login security, two-factor authentication and form spam protection without CAPTCHA, sends no data in its default mode and offers an optional community IP blocklist. Many sites run a scanner next to it.

= Can I use it together with another security plugin? =

Yes, but switch off overlapping features. Two plugins that both limit login attempts or both ask for a second factor will lock users out twice, so keep one of each.

= How is it different from a cloud firewall? =

A cloud firewall filters traffic before it reaches your server, while ReportedIP Hive runs inside WordPress and sees what a cloud firewall cannot: failed sign-ins, usernames tried, form submissions and user roles. Both work well together; set the proxy header so the plugin sees the real visitor address.

= Does it work behind Cloudflare or a reverse proxy? =

Yes. Choose the header that carries the visitor address (CF-Connecting-IP, X-Forwarded-For, X-Real-IP, Client-IP, True-Client-IP or X-Cluster-Client-IP) and list the trusted proxy ranges.

= Does it work on WordPress multisite? =

Yes. The plugin is activated network-wide and keeps one set of tables for the whole network. Blocks and the whitelist apply to every site, and each site admin sees the activity of their own site.

= What is in the Pro add-on? =

The add-on adds SMS 2FA and a managed mail relay, WooCommerce storefront 2FA, adaptive 2FA policies, hardening mode, advanced security headers, a computation proof on forms, Tor blocking, group ban lists, protection for further form plugins, an audit trail, account blocking and fleet management. The list per plan is in the description above.

= I still run version 1.3 of this plugin. What happens on the update? =

Version 3.0.0 arrives like any other update from the plugin directory. Your whitelist, blocks, counters and settings are carried over, including ranges, permanent whitelist entries and the True-Client-IP or X-Cluster-Client-IP proxy header. On a multisite network where the plugin ran site by site, the data of every site moves into the network tables. Open the quickstart afterwards to pick Local Shield or the Community Network.

= What if I lock myself out? =

Use a recovery code, or run `wp reportedip 2fa reset <user_id>` and `wp reportedip unblock <ip>` with WP-CLI. Adding your own address to the whitelist prevents blocks in the first place.

== Screenshots ==

1. Security dashboard with the protection score, blocks and the activity stream.
2. Protection page: every sensor and threshold on five tabs.
3. Activity log with filters.
4. Two-factor enrolment wizard.
5. Sign-in challenge with authenticator, passkey and e-mail options.
6. Tools page with the pre-WordPress firewall and the server rules.
7. Community page: Local Shield or Community Network.
8. System status and readiness check.
9. Site view on a multisite network: local activity, protection managed centrally by the network admin.

== Changelog ==

= 3.0.1 =
* Network activation on Multisite opens the quickstart in the Network Admin.
* A plan upgrade applies the recommended settings of the new plan also without the Pro add-on.
* The password policy and breach check also cover the WooCommerce and Ultimate Member account and registration forms; padding lines of the breach service no longer count as a hit.
* "Apply the password policy to every role" now covers every user, also next to the roles that must use two-factor; the score item is called "Password policy".
* The quickstart applies the same settings as version 2.1.74, and a form plugin installed later is protected on the next admin visit.
* The pre-WordPress firewall is rewritten after every update, and the settings hash stays stable after the update from 2.1.74.
* The firewall queue import can no longer run twice at the same time.
* German, Austrian and Swiss German translations are complete, in both the informal and the formal form.
* Every link to reportedip.com carries its campaign tag.

= 3.0.0 =
* The plugin now comes from the WordPress plugin directory. The former GitHub update checker is gone.
* Paid features moved to the separate ReportedIP Hive Pro add-on.
* The breach check for new passwords is off until you switch it on.
* .htaccess blocks are written after an operator action (quickstart, saving the switch, import, WP-CLI), never at activation. A site updating from 2.x with a completed quickstart keeps its blocks.
* Local Shield sends no request to reportedip.com, even with a key stored. The news feed loads only in Community Network mode.
* The footer badge stays off until you tick it in the quickstart; the dashboard no longer suggests it.
* Notices can be closed and return after an hour or a day; a critical queue or readiness problem stays until it is fixed.
* Update path from version 1.3.9: permanent and range whitelist entries, attempt counters and the proxy header are kept.
* Networks that ran version 1.3.9 per site keep the blocks, whitelist entries, counters and pending reports of every site.
* Database schema 25.

== Upgrade Notice ==

= 3.0.1 =
Fixes the quickstart defaults, the network activation on Multisite and the firewall rewrite after an update.

= 3.0.0 =
Updates now come from wordpress.org. Sites with a paid plan install the Pro add-on from their reportedip.com account. Sites on version 1.3.9 keep their whitelist, blocks and settings.

== Privacy Policy ==

The plugin stores the addresses of failed sign-ins, blocked requests and security events in its own database tables for the retention period you configure (30 days by default), together with the event type and, when detailed logging is on, the user agent. Addresses are anonymised after seven days by default. A ready-made text for your privacy policy is added under Settings, Privacy. Processing is based on Art. 6(1)(f) GDPR (protection of the site).

Verified bot detection resolves the host name of visitors that claim to be a search engine crawler through your server's DNS resolver, which means the visitor address is sent to that resolver. Results are cached for up to 24 hours.

== External Services ==

**reportedip.com.** In Local Shield (the default) the plugin contacts no external service, even with a key stored; only a click on "Check" in the quickstart or on "Test Connection" sends one key check. With the Community Network switched on and a Community Access Key entered, the plugin talks to `https://reportedip.com/wp-json/reportedip/v2/`. It checks the key every six hours, looks up attacking addresses during sign-ins and on forms, reports addresses it blocked (address, event category, attempt count, site name), sends addresses you whitelist as feedback, and downloads signed firewall, bot and disposable-domain rulesets every six hours. With "Sync alert recipients" on, it also sends the alert recipient addresses. Every request carries the key, the site address and the plugin and WordPress version. The dashboard shows the reportedip.com news feed (`https://reportedip.com/feed/?post_type=news`), cached for twelve hours. If the Pro add-on is installed, it checks reportedip.com for its own updates with your key. Terms of use: https://reportedip.com/nutzungsbedingungen/. Privacy policy: https://reportedip.com/datenschutzerklaerung/.

**api.pwnedpasswords.com.** Only with the breach check switched on: when a user sets a new password (also on the WooCommerce and Ultimate Member account and registration forms), the first five characters of its SHA-1 hash are sent to `https://api.pwnedpasswords.com/range/`; the password never leaves the site. Service by Have I Been Pwned, privacy: https://haveibeenpwned.com/Privacy.

== Credits ==

* Chart.js 4.4.1 (MIT) renders the dashboard charts. Source: https://github.com/chartjs/Chart.js
* qrcode-generator 1.4.4 (MIT) draws the TOTP QR code. Source: https://github.com/kazuhikoarase/qrcode-generator

Both libraries ship inside the plugin, nothing is loaded from a CDN.
