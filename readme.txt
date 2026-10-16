=== ReportedIP Hive: Firewall, Login Security, Brute Force Protection and 2FA ===
Contributors: reportedip
Tags: security, firewall, brute-force, 2fa, spam-protection
Requires at least: 5.9
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 3.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Firewall, brute force protection, 2FA with passkeys and spam protection for forms. Optional community IP blocklist. GDPR-first, made in Germany.

== Description ==

ReportedIP Hive is a WordPress security plugin that combines a web application firewall (WAF), login security with limited login attempts, two-factor authentication with passkeys, and spam protection for comments, registrations and contact forms. It blocks malicious IPs on your own server, works without an account, and can optionally share and check attacking addresses through a community IP blocklist.

Sixteen sensors watch the sign-in form, XML-RPC, the REST API, the comment, registration and password-reset forms and the request itself. Four two-factor methods keep accounts safe when a password leaks.

Everything in this plugin is free and complete: no trial, no locked switch, no account requirement. The Community Network and the separate Pro add-on are optional.

= Login security and brute force protection =

* **Limit login attempts.** Failed sign-ins are counted per IP address. The default locks an address after 5 failures in 15 minutes.
* **Password spraying detection.** Many usernames tried from one address are caught separately.
* **Progressive IP blocking.** Six steps from 5 minutes to 7 days. The ladder resets after 30 quiet days, so a typo never costs a day.
* **Hide Login.** Move wp-login.php to a custom login URL.
* **User enumeration protection.** Author archives, the users REST route, the user sitemap and login error messages no longer reveal usernames.
* **XML-RPC and pingback protection,** with a switch to turn XML-RPC off.
* **Login anomaly detection.** A sign-in from a new country asks for the second factor again.
* **WooCommerce login protection.** The My Account sign-in and registration forms are counted like wp-login.php.
* **Password policy** with an optional breach check (off by default).

= Two-factor authentication (2FA) =

* **Authenticator apps (TOTP)** such as Google Authenticator, Authy or 1Password.
* **Passkeys and hardware security keys (WebAuthn, FIDO2),** for example a YubiKey, Face ID, Touch ID or Windows Hello. One key per account.
* **E-mail codes.**
* **Recovery codes,** ten single-use codes per user.
* Trusted devices, an enrolment wizard, 2FA enforcement per user role and a password-reset gate that a stolen mailbox cannot bypass.

= Web application firewall =

* **Request inspection** with a bundled baseline ruleset against SQL injection, XSS, path traversal and scanner traffic.
* **Pre-WordPress guard.** An optional firewall layer that applies the same rules, exceptions, whitelist and IP blocks before WordPress loads.
* **404 and scanner detection.** Requests for bait paths such as .env or .git/config block the address at once.
* **Verified bot detection.** Googlebot, Bingbot and other large crawlers are confirmed through their published address ranges or reverse DNS. A fake Googlebot gains nothing.
* **Firewall exceptions** and a report-only mode for testing.

= Spam protection for forms and comments =

* **Invisible form check instead of a CAPTCHA.** A cache-safe execution proof on the comment, registration and password-reset forms. Visitors see no puzzle, and no third-party CAPTCHA service is loaded.
* **Contact Form 7 spam protection** through the same check.
* **Comment spam filter** that scores links, link density, disposable addresses and other signals.
* **Comment honeypot.**
* **Disposable e-mail blocking** on registrations and forms.
* **Registration rules:** prohibited usernames, e-mail allow and block rules and a sign-up rate limit.

= Access lockdown =

* REST API for signed-in users or chosen roles.
* Feeds, wp-admin for guests, PHP execution in uploads and software version fingerprints, each a switch.
* Basic security headers.

= Operations =

* Activity log, protection score, CSV and JSON exports, settings import and export.
* WP-CLI commands for blocks, the whitelist, 2FA and status.
* WordPress multisite: network-activated, one set of tables, per-site logs.
* Works behind Cloudflare and other reverse proxies with a trusted proxy list.

= Two ways to run it =

* **Local Shield** is the default. The plugin makes no outbound request.
* **Community Network** is optional. With a free Community Access Key from [reportedip.com](https://reportedip.com/?rc=hive-wporg) the plugin checks the IP reputation of attacking addresses during sign-in and on forms, shares the addresses it blocks with the community blocklist, and receives updated firewall rulesets. Every request is listed under External Services below.

= What it does not do =

ReportedIP Hive does not scan files for malware and does not monitor file integrity. Run a scanner next to it if your site needs one.

= ReportedIP Hive Pro =

A separate add-on, ReportedIP Hive Pro, extends this plugin with a managed EU relay for 2FA mails and SMS codes, two-factor authentication on the WooCommerce storefront, adaptive per-role 2FA policies, a hardening mode during attack waves, advanced security headers, a computation check on forms, form protection for further form plugins, Tor exit node blocking, an audit trail, user account control and fleet management. It is not hosted on wordpress.org and is described on the [product page](https://reportedip.com/products/wordpress-plugin/?rc=hive-wporg).

Documentation: [ReportedIP Hive guide](https://reportedip.com/docs/integrations/wordpress-hive/?rc=hive-wporg).

== Installation ==

1. Install the plugin from the WordPress plugin directory and activate it. On a multisite network, activate it network-wide.
2. Open ReportedIP Hive in the admin menu. The quickstart lets you pick Local Shield or the Community Network and applies the recommended settings with one click.
3. Enrol your own second factor on your profile page.

The plugin writes its two optional .htaccess blocks (bait-path responses and PHP execution in uploads) when the quickstart completes, never at activation. On nginx it shows a snippet to paste instead.

== Frequently Asked Questions ==

= Is ReportedIP Hive free, and do I need an account? =

Yes, the plugin is free under the GPL and works without any account. A free account at reportedip.com adds the community IP reputation check and the synced firewall rulesets.

= Will it slow down my site? =

No. A blocked address is refused at the very start of the request, before themes and most plugins load, and community reports are sent in the background by WP-Cron.

= Can I use it together with another security plugin? =

Yes, but switch off overlapping features. Two plugins that both limit login attempts or both ask for a second factor will lock users out twice, so keep one of each.

= How is it different from a cloud firewall? =

A cloud firewall filters traffic before it reaches your server, while ReportedIP Hive runs inside WordPress and sees what a cloud firewall cannot: failed sign-ins, usernames tried, form submissions and user roles. Both work well together; set the proxy header so the plugin sees the real visitor address.

= Does it work with WooCommerce? =

Yes. The WooCommerce sign-in and registration forms are protected by the same login attempt limits, the registration rules and disposable e-mail blocking.

= Is it GDPR compliant? =

The plugin is built for GDPR compliance: logging is minimal, retention is configurable (30 days by default), addresses are anonymised after 7 days and the Community Network is opt-in. A suggested text for your privacy policy is added under Settings, Privacy.

= Which data leaves my site in the Community Network? =

Only the attacking IP address, the event category, the time, your site name and address, the attempt count and the plugin version. Usernames, passwords and form content never leave the site.

= Does it work behind Cloudflare or a reverse proxy? =

Yes. Choose the header that carries the visitor address (CF-Connecting-IP, X-Forwarded-For, X-Real-IP, Client-IP, True-Client-IP or X-Cluster-Client-IP) and list the trusted proxy ranges.

= Does it work with caching plugins? =

Yes. The block page sends no-cache headers that WP Rocket, W3 Total Cache, WP Super Cache and LiteSpeed Cache respect, and the form check contains nothing request-specific, so cached pages keep working.

= Does it support passkeys and YubiKeys? =

Yes. Any FIDO2 or WebAuthn authenticator works as a second factor, including YubiKey hardware keys and platform passkeys such as Face ID, Touch ID and Windows Hello.

= Do I still need a CAPTCHA? =

Usually not. The invisible form check stops scripted submissions on comments, registrations, password resets and Contact Form 7 without a puzzle for your visitors.

= I use ReportedIP Hive Light. What happens on the update? =

ReportedIP Hive replaces ReportedIP Hive Light under the same name in the plugin directory, so the update arrives like any other. Your whitelist, blocks, counters and settings are carried over, including ranges, permanent whitelist entries and the True-Client-IP or X-Cluster-Client-IP proxy header. On a multisite network where Light ran site by site, the data of every site moves into the network tables. Open the quickstart afterwards to pick Local Shield or the Community Network.

= What if I lock myself out? =

Use a recovery code, or run `wp reportedip 2fa reset <user_id>` and `wp reportedip unblock <ip>` with WP-CLI. Adding your own address to the whitelist prevents blocks in the first place.

== Screenshots ==

1. Security dashboard with the protection score, blocks and the activity stream.
2. Protection page: every sensor and threshold on five tabs.
3. Activity log with filters.
4. Two-factor enrolment wizard.
5. Sign-in challenge with authenticator, passkey and e-mail options.
6. Firewall rules and the pre-WordPress guard on the Tools page.
7. Community page with the connection card.
8. System status and readiness check.
9. Site view on a multisite network: local activity, protection managed centrally by the network admin.

== Changelog ==

= 3.0.0 =
* The plugin now comes from the WordPress plugin directory. The former GitHub update checker is gone.
* Paid features moved to the separate ReportedIP Hive Pro add-on.
* The breach check for new passwords is off until you switch it on.
* .htaccess blocks are written after an operator action (quickstart, saving the switch, import, WP-CLI), never at activation. A site updating from 2.x with a completed quickstart keeps its blocks.
* Local Shield sends no request to reportedip.com, even with a key stored. The news feed loads only in Community Network mode.
* The footer badge stays off until you tick it in the quickstart; the dashboard no longer suggests it.
* Notices can be closed and return after an hour or a day; a critical queue or readiness problem stays until it is fixed.
* Update path from ReportedIP Hive Light 1.3.9: permanent and range whitelist entries, attempt counters and the proxy header are kept.
* Networks that ran ReportedIP Hive Light per site keep the blocks, whitelist entries, counters and pending reports of every site.
* Database schema 25.

== Upgrade Notice ==

= 3.0.0 =
Updates now come from wordpress.org. Sites with a paid plan install the Pro add-on from their reportedip.com account. Sites on ReportedIP Hive Light 1.3.9 keep their whitelist, blocks and settings.

== Privacy Policy ==

The plugin stores the addresses of failed sign-ins, blocked requests and security events in its own database tables for the retention period you configure (30 days by default), together with the event type and, when detailed logging is on, the user agent. Addresses are anonymised after seven days by default. A ready-made text for your privacy policy is added under Settings, Privacy. Processing is based on Art. 6(1)(f) GDPR (protection of the site).

Verified bot detection resolves the host name of visitors that claim to be a search engine crawler through your server's DNS resolver, which means the visitor address is sent to that resolver. Results are cached for up to 24 hours.

== External Services ==

In Local Shield (the default) the plugin contacts no external service on its own, even with a key stored. Only a click on "Check" in the quickstart or on "Test Connection" sends one `verify-key` request.

**reportedip.com (Community Network on, only with a Community Access Key you enter)**

Endpoint base: `https://reportedip.com/wp-json/reportedip/v2/`. Every request carries the key, the site address (`X-Rip-Site`) and a user agent with the plugin and WordPress version.

* `verify-key`: validates the key when you check it and, while the Community Network is on, every six hours; receives the plan and quotas of your account.
* `check`: looks up an attacking address during sign-in attempts and on the comment, registration and password-reset forms; sends the address.
* `report`: shares an address the plugin blocked; sends the address, the event category and a one-line description with the site name, site address and attempt count. Queued and sent in batches.
* `whitelist`: sends an address marked as legitimate, as positive feedback.
* `categories`: receives the report category list.
* `notification-config`: only with the switch "Sync alert recipients" on; sends the alert recipient addresses of this site to your account.
* `rules/<ruleset>`: receives signed firewall, bot, bait-path and disposable-domain rulesets every six hours. Signatures are verified before use; the bundled baseline is used when the service is unreachable.
* `https://reportedip.com/feed/?post_type=news` (or the localised feed for German, Spanish and French): the dashboard shows the latest reportedip.com news, cached for twelve hours.

Terms of use: https://reportedip.com/nutzungsbedingungen/ and privacy policy: https://reportedip.com/datenschutzerklaerung/.

**api.pwnedpasswords.com (only with the breach check switched on)**

When a user sets a new password, the first five characters of its SHA-1 hash are sent to `https://api.pwnedpasswords.com/range/`; the password itself never leaves the site. Service by Have I Been Pwned: https://haveibeenpwned.com/Privacy.

== Credits ==

* Chart.js 4.4.1 (MIT) renders the dashboard charts. Source: https://github.com/chartjs/Chart.js
* qrcode-generator 1.4.4 (MIT) draws the TOTP QR code. Source: https://github.com/kazuhikoarase/qrcode-generator

Both libraries ship inside the plugin, nothing is loaded from a CDN.
