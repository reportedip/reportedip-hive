# ReportedIP Hive

[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2%2B-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![PHP 8.1+](https://img.shields.io/badge/PHP-8.1%2B-777BB4.svg)](https://www.php.net/)
[![WordPress 5.9+](https://img.shields.io/badge/WordPress-5.9%2B-21759B.svg)](https://wordpress.org/)
[![Multisite](https://img.shields.io/badge/Multisite-network--aware-21759B.svg)](#multisite-support)
[![Tests](https://img.shields.io/badge/PHPUnit-unit%20%2B%20Multisite-brightgreen.svg)](https://github.com/reportedip/reportedip-hive/actions)
[![Made in Germany](https://img.shields.io/badge/Made%20in-Germany-black.svg)](https://reportedip.com)

> **Community-powered WordPress security: 16 attack sensors, a two-layer firewall, 4 progressive 2FA methods, herd-immunity threat sharing, fully Multisite-aware. GDPR-first. Made in Germany.**

Every protected site becomes a sensor. When one site is attacked, every other site can refuse the same attacker before the password is even checked. One drop-in replaces brute-force protection, a web application firewall, a multi-method 2FA suite and threat intelligence. The entire detection and identity core is free and GPL-2.0; the paid Professional / Business plans add managed mail/SMS relays, multi-site management and a handful of advanced modules on top. They never gate the core protection.

→ Product: <https://reportedip.com> · Releases: [GitHub](https://github.com/reportedip/reportedip-hive/releases) · Docs: <https://reportedip.com/docs>

---

## Why pick it

- **One plugin instead of four.** Brute-force protection, a two-layer WAF, a multi-method 2FA suite and opt-in community threat intelligence. Single drop-in, GPL-2.0, public on GitHub. The full protection core is free; paid plans only add relays, multi-site and advanced modules (see [Free vs. paid](#free-vs-paid)).
- **Blocks enforced before WordPress even loads.** The optional pre-WordPress guard (`auto_prepend_file`) refuses blocked IPs and firewall matches before a single WordPress file is included. Fail-open by design: any error lets the request through to the normal in-WordPress engine.
- **Progressive blocks that don't burn legitimate users.** First-time tripping gets a 5-minute timeout; repeat offenders climb 5 m → 15 m → 30 m → 24 h → 48 h → 7 d, and loud bursts skip rungs (10x the threshold skips two). CGNAT visitors and fat-fingered admins recover in minutes; brute-forcers pay the full price. The server's own addresses are exempt from auto-blocking, so cache preloaders and WP-Cron loopbacks can never lock the site out of itself.
- **Turn off what you do not use.** Free lockdown switches close the REST API, XML-RPC and pingbacks, feeds, the admin area for signed-out visitors, PHP execution in the uploads folder and the version fingerprints, and a readiness register names the parts of the setup that are failing quietly before they cost you an incident.
- **Privacy-first by default.** GDPR-minimal logging, 30-day retention, anonymisation after 7 days, opt-in community sharing, all secrets encrypted at rest with libsodium. Lawful basis (Art. 6(1)(f) GDPR) documented in-product.
- **Multisite-native.** Network-only activation, single threat decision applies network-wide, Site Admins get a read-only UI with their site's audit trail and two narrow override fields. Cross-site brute-force aggregates into one central counter, so an attacker pivoting between sub-sites trips the threshold faster, not slower.
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
| Web Application Firewall | Paranoia Level 1 baseline + backend exceptions | See [Two-layer firewall](#two-layer-firewall) |
| Verified bot detection | flag (default) or block | Official Google/Bing IP ranges first, FCrDNS fallback; genuine crawlers never blocked |
| Registration defence | username baseline on (10 role names), rate limit on (3 / 60 min), disposable mail: monitor, custom lists empty | Throwaway-mail domains, prohibited usernames, e-mail allow/block rules, per-IP rate limit (3 / 60 min), opt-in unknown-username block; WP + WooCommerce + Multisite sign-ups. Ten entries per list free, unlimited plus regex on Professional |
| Form execution proof | on | Checks that a comment, sign-up or password reset came from a browser that rendered the form. See [Form protection](#form-protection) |
| Form plugin adapters | off | The same check on Contact Form 7 (every plan) and on WPForms, Gravity Forms, Formidable Forms, Formidable Forms PRO, Elementor Forms and Ultimate Member (Business). See [Form protection](#form-protection) |
| Community threat check on forms | on, needs Community Network mode | Comment, sign-up and password reset checked at the same protection level as the sign-in page; fail-open when the allowance runs out |

Not a sensor, but part of the same screen: the consent endpoints of Real Cookie Banner, Complianz, Borlabs and CookieYes are exempt from the rate limit out of the box, because on a compliant site they look like a burst on every single page view.

<a id="two-layer-firewall"></a>

### Two-layer firewall

Hive inspects requests in two places that stay behaviourally identical:

- **In-WordPress engine.** Runs on `init` priority 1 with SQLi/XSS/traversal/LFI/scanner rule patterns, a per-rule exception table (rule / group / path scope, one-click "Allow" from the log), report-only mode for audits and ReDoS-hardened matching. Paranoia Level 1 ships free and works offline; the deeper, Ed25519-signed PL 2/3 rulesets sync with a Professional plan.
- **Pre-WordPress guard ("Extended protection").** An optional `auto_prepend_file` drop-in generated from the exact same rules, exceptions and whitelist. It refuses blocked IPs and rule matches before WordPress loads, answers blocklist lookups from an 8 KB bitmap header instead of reading the whole file, aggregates its hits per (IP, rule) and feeds them back into the escalation ladder. The Tools page's Server tab produces the right directive for your stack (php.ini, `.user.ini`, hosting panel or nginx) and verifies live that the guard actually runs.

Both layers are fail-open: a broken rule, an unreadable file or an unwritable directory lets the request through rather than taking the site down. IP blocks are enforced even with the WAF disabled, because they come from the escalation ladder, not from rule inspection.

Client-IP resolution is spoof-proof at both layers: when a trusted IP header is configured (Cloudflare, nginx, a load balancer), it is only honored for requests that connect from the trusted-proxy addresses (IP/CIDR list) declared under *Protection → Detection & Thresholds*, anyone hitting the origin directly cannot smuggle a whitelisted address into the header or shed a block. An empty list keeps the previous accept-from-anywhere behavior.

### Two-Factor Authentication (four methods)

Three methods work in **every plan**, including Free and the fully-offline Local Shield; SMS is the one method that rides the managed relay and therefore needs a Professional plan.

- **TOTP** (RFC 6238). Google Authenticator, Authy, 1Password, Microsoft Authenticator. Secrets encrypted at rest. *Free.*
- **Passkey / WebAuthn / FIDO2.** Face ID, Touch ID, Windows Hello and hardware security keys (YubiKey 5 series and other FIDO2 keys, USB-C or NFC phone tap). Ed25519 support, clone detection through signature counters, named key manager. In-house implementation, phishing-resistant, no Composer dependency. *One key per account free.*
- **Advanced Security Keys (Business plan).** Multiple keys per account (primary + backup), automatic model detection via attestation ("YubiKey 5 Series with NFC" shown in the key manager) and key-lifecycle email alerts.
- **Email OTP.** 6-digit, 10 min validity, rate-limited (3 sends / 15 min). *Free.*
- **SMS OTP (Professional plan).** Delivered through the managed reportedip.com relay, included with Professional and Business. No own SMS account or carrier contract required; phone numbers encrypted at rest. Free / Contributor sites use TOTP, Passkey or Email instead.

**Self-service on the profile page.** Every user manages their own 2FA from plain-language method cards: add or remove methods at any time, pick the default method the login challenge opens with, change the SMS number (the verified number is only replaced after the new one confirms a code), re-set-up the authenticator app, and manage security keys, recovery codes and trusted devices. The profile, the guided onboarding wizard and WP-CLI all share one activation path, so an added method never silently overwrites the chosen default or destroys existing recovery codes.

Also included in every plan: 10 single-use recovery codes, trusted-device tokens (default 30 days), a multi-stage 2FA rate-limit (3/5/10/15 fails → 30 s/5 m/30 m/1 h delays; the 15th IP-level fail graduates to a real progressive block), role-based enforcement with grace period, a branded login page option, an IP allowlist for 2FA bypass, and the **password-reset gate**: the "lost password" flow demands a second factor before a new password is accepted, with email excluded by design so a stolen mailbox cannot bypass 2FA.

**WooCommerce frontend 2FA (Professional plan and higher).** Customers signing in through `[woocommerce_my_account]`, the classic checkout, or the WooCommerce Cart / Checkout blocks see the second factor inside the active storefront theme instead of bouncing to wp-login.php. Customer / Subscriber roles get a themed onboarding wizard on a dedicated slug. Cart and checkout state survive the redirect roundtrip; the trusted-device cookie is shared with the wp-login flow. A tier downgrade soft-disables the module; existing customer secrets stay valid.

<a id="form-protection"></a>

### Form protection

Hive checks that a submission came from a browser that really rendered the form. A visitor notices nothing of it, there is no image to decipher and no extra step to take. What the check cannot do is tell a person from a botnet driving a real browser. It tells a browser from a script.

| Form | Plan |
|---|---|
| Comment form | Free |
| Registration (WordPress, WooCommerce, Multisite sign-ups) | Free |
| Lost password | Free |
| Your own forms, through `Form_Proof::field()` / `check()` / `passes()` | Free |
| Contact Form 7 | Free |
| Ultimate Member, its sign-in, sign-up and password forms | Business |
| Gravity Forms, including forms sent in the background and multi-page forms | Business |
| WPForms and WPForms Lite, including forms sent in the background | Business |
| Formidable Forms | Business |
| Formidable Forms PRO | Business |
| Elementor Forms (needs Elementor PRO, the form widget exists only there) | Business |

Tested against Contact Form 7 in the version published on wordpress.org, Gravity Forms 3.1, Formidable Forms and Formidable Forms PRO 6.35, Elementor and Elementor PRO 3.34, Ultimate Member 2.13, WPForms Lite 2.0.

A refused submission is always told so. Contact Form 7 shows its own "not sent" notice, every other form plugin shows the reason above the form, and no message is ever filed away quietly: the sender either gets through or learns that they did not.

**How it works.** Every protected form carries an invisible, screen-reader-excluded anchor field, and a bot that fills every input it finds fills that one too. A small script adds a second field whose name is random per installation, so a script posting straight at the endpoint without ever loading the form cannot carry it. The verdict is four-way, `proved`, `failed`, `tripped` or `absent`, and "absent" stays lenient until the site has seen itself render the field, so a theme with hand-written comment markup is never treated like a bot. Nothing request-specific reaches the HTML, so page caches stay valid.

**What a verdict costs.** On the comment form a filled anchor scores 7 and a missing proof scores 4 against a spam threshold of 7, so a reader browsing without JavaScript loses a moderation step rather than the comment, and that reason on its own never counts towards a block. Sign-up, password reset and the form plugins refuse a failed proof outright and say why. On the form plugins a filled anchor counts towards the per-address block ladder the way it does on a comment, while a client that simply never ran the script never does. The Ultimate Member password form is the one place where a missing anchor never refuses, because that form is what somebody reaches for once they are already locked out.

**Computation check (Professional).** With it on, the browser fetches a small task from your own site and works it out in the background. The task is signed with your site's salt, expires after ten minutes, is accepted once, and gets harder the faster one network asks for tasks; the starting value is derived from the task itself, so a client can choose neither it nor the difficulty. That closes the shortcut the plain marker leaves open, reading the field name out of the page and posting it back, and it closes the follow-up as well: a script that fetches one task cannot reuse it, and a script that fetches hundreds pays for every one. The page itself carries nothing but the address of the endpoint, identical for every visitor, so a full-page cache, LiteSpeed, WP Rocket or a CDN in front of the site keeps serving it unchanged; the task comes from a POST that no cache stores. Without HTTPS the task carries no arithmetic, because the browser hash API only exists in a secure context, but it keeps its signature, its expiry and its single use. After a plugin update the plain marker passes again for a day and the page cache is purged, so readers of a page cached by the previous version are never refused. Difficulty via `reportedip_hive_form_proof_bits` (14 bits for a quiet network, one more per doubling of its requests up to 22, plus two while the hardening mode runs).

**Ultimate Member.** The plugin writes the account itself instead of going through the WordPress sign-up, so `registration_errors` never fires on it. Its sign-up therefore runs the registration rules from the plugin's own validation hook: the same rate limit, prohibited usernames, e-mail rules and disposable-domain check the WordPress form gets, refused before the account exists and with the reason on the field it is about.

**One switch per plugin.** On a plan that does not cover an adapter the switch stays visible and locked, with the plan it needs written next to it. For 24 hours after a switch goes on a submission that never carried the proof is still accepted, and switching it on clears the common page caches, so a page cached without the field cannot lock anybody out. `reportedip_hive_form_adapters_grace` buys more room on a site whose cache outlives a day. On a form this plugin does not own, both field names carry a leading underscore, which keeps them out of the notification mail and out of a stored entry.

**Self-test.** Tools → Diagnostics. The card first lists what is switched on, and why an adapter is inactive when it is, then runs three passes with the browser you are sitting in front of: like a visitor, like the same visitor twice, and like a bot. No real form is submitted, no mail goes out and no entry is stored. An invisible protection is otherwise hard to tell apart from no protection at all, and this card answers that question.

**Fill time.** The script measures how long the form was on screen and sends the seconds along. The starting point comes from the browser and never from the markup, because a value baked into the HTML is already wrong when a page cache serves it. The number is not signed, so a determined attacker writes into it whatever suits them. It is therefore enforced on the comment filter alone, where it weighs 2 of the 7 points a comment needs to count as spam and can never convict on its own. Every other surface measures it and writes it to the log. The threshold is three seconds, changed with `reportedip_hive_form_proof_fast_seconds`.

Everything above sits on the Protection page under Form Protection, next to the master switch, a second switch that leaves sign-up and password reset out, and report-only mode, which logs every refusal and refuses nothing. `REPORTEDIP_HIVE_DISABLE_FORM_PROOF` in `wp-config.php` switches the whole layer off, and `reportedip_hive_form_proof_adapters` decides which surfaces take part.

<a id="honeypots-and-decoys"></a>

### Honeypots and decoys

Two traps sit outside the forms. Neither needs a CAPTCHA, a puzzle or an extra step; each one is a place a genuine visitor never goes and an automated tool cannot resist.

| Trap | What it catches | Consequence | Plan |
|---|---|---|---|
| **Decoy paths** | Anyone requesting one of 45 bait URLs that exist on no real site (`/.env.backup`, `/wp-config.old.php`, `/db-dump-master.sql.php`) | One 403 plus a high-severity community report. Deliberately no local block, so a backup plugin or a curious admin cannot lock the site out | Free |
| **Scanner honeypot paths** | A request for a known scanner target (`/.env`, `/.git/config`, `/.aws/credentials`, `/.ssh/id_rsa`) | The 404 detector fires at once instead of after 12 misses; the address enters the block ladder and is reported | Baseline free, live list of ~100 targets on Professional |

Details worth knowing:

- Verified crawlers are exempt from the 404 rate trigger but never from a honeypot hit: a Googlebot that asks for `/.env` is not Googlebot.
- On Apache the decoy-path trap keeps a marker block in `.htaccess` so a real file at a bait path is routed through WordPress instead of being served; nginx gets a snippet to paste.
- Both traps honour the whitelist, the site's own server addresses and report-only mode, and log what they caught with the reason.
- Filters: `reportedip_hive_decoy_paths`, `reportedip_hive_scan_paths`, `reportedip_hive_scan_prefixes`.

Not to be confused with the **Honeypot Operator** plan, which is a reportedip.com account tier for people running a dedicated honeypot server that feeds the network, unrelated to the traps above.


### Progressive block escalation

Default ladder: **5 min → 15 min → 30 min → 24 h → 48 h → 7 d** (cap). After 30 days clean, the IP starts again at step 1. Loud bursts are weighted: five times the threshold behind one block skips a rung, ten times skips two, twenty-five times skips three. Fully editable as a comma-separated minute list under *Protection → Blocking & Escalation*. Manual blocks (admin / CSV import) honour the chosen duration and never get overridden by the ladder. The server's own addresses (loopback, interface address, everything the site hostname resolves to) are exempt from automatic blocking, extensible via the `reportedip_hive_own_server_ips` filter for multi-node setups.

### Cache compatibility

The 403 "Access Denied" response defines `DONOTCACHEPAGE`, `DONOTCACHEDB`, `DONOTCACHEOBJECT`, calls `nocache_headers()` and emits `Cache-Control: no-store, no-cache, must-revalidate` plus `Pragma: no-cache`. Cache plugins refuse to store the response. Authentication paths (`wp-login.php`, `wp-admin/`, `wp-json/`, XMLRPC) are excluded from caching by every reputable cache plugin out of the box, so blocks always fire on the paths attackers target.

Documented limitation: a blocked attacker visiting a *publicly cached* GET URL still gets the cached HTML unless the pre-WordPress guard is installed, which refuses the request before any cache plugin runs. Their write attempts are blocked normally either way.

### Two operating modes

The two **modes** decide whether the plugin talks to reportedip.com at all. They are independent of the **plan** (Free → Enterprise), which decides the relay quotas and the advanced modules. A Free site can run either mode; SMS 2FA and Hardening Mode additionally need a Professional plan because they ride the managed relay / coordinated-attack infrastructure.

| | Local Shield | Community Network |
|---|---|---|
| Account required | No | Free account at reportedip.com |
| External calls | None | Reputation lookups + anonymised reports (each request carries the site address and plugin/WordPress version, wp.org-style) |
| All 16 detection sensors + two-layer firewall | yes | yes |
| Core 2FA (TOTP, Passkey, Email, Recovery) | yes | yes |
| Progressive block escalation + password-reset gate | yes | yes |
| Pre-auth IP reputation check |, | yes |
| Reputation hits persist as local 24 h blocks |, | yes |
| Coordinated-attack detection |, | yes |
| SMS 2FA (managed relay) |, | Professional+ |
| Hardening Mode (auto-tighten thresholds on attack) |, | Professional+ |
| Tor exit-node blocking (signed exit-node list) |, | Professional+ |
| Access lockdown switches + system readiness register | yes | yes |
| Adaptive 2FA step-up triggers per role |, | Professional+ |
| User account blocking + session manager |, | Business+ |
| Privacy | 100 % offline | Strictly opt-in, no usernames or comment content shared |

<a id="free-vs-paid"></a>

### Free vs. paid

The plugin itself is **free, GPL-2.0 and fully functional** in both modes. Everything that detects an attack, blocks an IP, logs an event or verifies a second factor with TOTP / Passkey / Email / Recovery codes works on every plan, including the 100 %-offline Local Shield. So does the form protection on the comment, sign-up and password-reset forms, its self-test and the form API for your own forms. No account, nothing held back.

What the paid **Professional** (3 domains) and **Business** (15 domains, multi-bookable) plans add on top:

- **Managed mail relay.** 2FA mails through clean SPF/DKIM/DMARC infrastructure, auto-fallback to `wp_mail()` on cap.
- **Managed SMS relay.** SMS OTP without your own carrier/Twilio contract.
- **WooCommerce frontend 2FA.** The second factor rendered inside the storefront theme on My Account / checkout / WC blocks.
- **Hardening Mode.** Automatically tighten failed-login and reputation thresholds network-wide for one hour when a coordinated attack is detected; also drivable via `wp reportedip hardening`.
- **Advanced security headers.** HSTS, Permissions-Policy, the CSP builder (report-only first) and the cross-origin isolation trio; the basic header trio stays free.
- **Priority Sync.** The deeper, Ed25519-signed WAF Paranoia-Level-2/3 rulesets plus the live bot-IP-range and disposable-domain feeds; the bundled baselines stay free and work offline.
- **Tor exit-node blocking.** Opt-in rejection of connections from known Tor exit nodes, backed by a signed `tor_exits` ruleset refreshed twice daily. Blocks are temporary (24 h default, filterable) and never reported to the community, operating an exit node is not abuse evidence.
- **Adaptive 2FA triggers.** Per-role step-up rules on a new country, IP address, network or device, every N days or sign-ins, or above a concurrent-session limit; they apply even when the trusted-device cookie is present, while the 2FA IP allowlist still bypasses.
- **Unlimited registration rules.** No ten-entry cap on the username and e-mail lists, `/regex/` patterns and registration restricted to allowlisted IP ranges.
- **Form protection on third-party form plugins.** Contact Form 7 on every plan, WPForms, Gravity Forms, Formidable Forms, Formidable Forms PRO, Elementor Forms and Ultimate Member with Business, plus the computation check on every protected form. See [Form protection](#form-protection).
- **Advanced Security Keys (Business).** Multiple WebAuthn keys per account, attestation-based model detection, key-lifecycle mails.
- **User account control and sessions (Business).** Block an account so it cannot sign in, use an application password or reset its password, drop all of its sessions and trusted devices, and review or terminate active sessions from Users → Sessions.
- **Audit event trail (Business).** Append-only record of who changed what: settings with the old and the new value, plugins, themes and core, pages and posts, menus and widgets, files saved in the built-in editor, user accounts and, on a network, sites; each row names the acting user, the request agent and the affected object. Eight trigger groups are switches, retention is configurable, the tab filters by group, user, address, object and date and exports the filtered rows as CSV or JSON.
- Higher API quotas, multi-site dashboard, priority blacklist sync, longer log retention, prepaid mail/SMS top-up bundles. Business adds white-label, the full WP-CLI surface, role-based login-time restrictions and a GDPR export tool.

Pricing and the full tier matrix live at <https://reportedip.com>.

### Remote management (MainWP and reportedip.com)

Hive carries its own MainWP child bridge, so agencies can manage every Hive install from one [MainWP](https://mainwp.com/) dashboard without an extra child plugin: fleet-wide status sync (active blocks, failed logins, queue size, 2FA coverage as aggregate counts), one-click API-key provisioning and centrally managed settings policies (schema-driven, with per-key validation, tier awareness and drift detection via a settings fingerprint, see `docs/remote-settings-protocol.md`). Data-minimised by design: the sync returns counts only, never IP addresses, usernames or secrets. Requires the ReportedIP Hive extension on the MainWP dashboard side.

The same settings protocol powers the cloud fleet dashboard on reportedip.com (Business plan): enable the "Cloud fleet management" toggle on the Community page and the site accepts Ed25519-signed policy pushes from the reportedip.com fleet service, verified against a bundled public key, bound to this site and to your Community Access Key, replay-protected and off by default. Both transports go through the same validation pipeline, so a policy behaves identically no matter which dashboard applied it.

**What you can manage:** every setting in the plugin's settings registry, grouped into fifteen sections (detection, blocking, firewall and bots, registration rules, form protection, attack response, hide login, security headers, access lockdown, two-factor authentication, adaptive step-up, password policy, privacy and logs, notifications, performance). The only stored options that stay local are the connection identity (`operation_mode`, `api_key`, `api_endpoint`), the remote-management opt-in itself, the uninstall data switch, the hardening master toggle (its "no value" state is what enables hardening automatically on Professional) and the Extended Protection switch (it needs a server directive next to it). Coverage is identical on both dashboards because both render from the same site-exported schema; a new managed option appears in both after a schema reload.

**How drift works:** each site reports a settings fingerprint (computed on the site, never recomputed by the dashboard) so a setting changed directly on a site shows up as *drifted* until you push again. "Push drifted only" targets exactly the drifted and pending sites, never sites you have not set up yet.

Full feature, security and operations guide: [`docs/cloud-fleet-management.md`](docs/cloud-fleet-management.md). Wire format and versioning rules: [`docs/remote-settings-protocol.md`](docs/remote-settings-protocol.md).

### Badges and community shortcodes

- **Badges tab on the Community page**: the one-click footer badge with its live preview on top, the banner builder below; templates set variant, number and wording in one click
- **Auto-footer badge** with four position options (left / center / right / below content)
- **Shortcodes**: `[reportedip_badge]`, `[reportedip_stat type="..."]`, `[reportedip_banner]`, `[reportedip_shield]`
- **8 stat types** (`attacks_total`, `attacks_30d`, `reports_total`, `api_reports_30d`, `blocked_active`, `whitelist_active`, `logins_30d`, `spam_30d`) and **4 tone presets** (`protect`, `trust`, `community`, `contributor`)
- Web Component with Shadow DOM so themes cannot break the layout; `<a>` link stays in light DOM for SEO; UTM-tracked

### Admin UX

- **One-page quickstart** (mode, key, switch on) with a plan-aware recommendation
- **Real-time dashboard** with detection & hardening score gauges (0–100, A+-F grade, per-item deep links) and 7- and 30-day Chart.js trend lines
- **Security widget on the WordPress dashboard**, attacks blocked (30 days), blocks today, active IP blocks, protection layers and the detection score on wp-admin's front page, with deep links; renders on the network dashboard on Multisite
- **One Protection page** rendered from the settings registry: fifteen collapsible cards (one per area) with a short status each, a search box that opens the matching card and marks the label, and a simple/expert depth switch. Simple shows the sixteen settings that matter day to day; expert shows every field. Each card saves on its own through the same apply service MainWP and the cloud fleet use, so plan limits and validation are identical on every path
- **Next steps on the dashboard**: a status banner with the plan the recommendation was applied for and the number of adjusted settings, advisory cards with an inline action (badge, storefront 2FA and Hide Login switch on from the card; the rest link where they belong), a row per protection area, and at most one plan card per visit. Expert mode is a switch in the page header
- **Tools page** (expert mode) with four tabs: Server (Extended Protection drop-in, `.htaccess`/nginx/php.ini snippets, decoy rules, header export), Rules (rule sync, WAF exceptions, hardening status), Data (import/export, reset) and Diagnostics (test mail). Old Settings and Firewall URLs redirect to the new home
- **Activity page** opening on the event log, with IP lookup, audit trail (Business), blocked and whitelist tabs and the report queue; every tab starts with one sentence that says what the list is for, and the filters live in a labelled GET filter bar (search, event type, severity, date range) that survives paging, sorting and bulk actions
- **Community page** with three tabs: Settings (operation mode, Community Access Key, client-IP header, fleet management, connection test), Community (contribution, quota, domains, plan overview) and Badges
- **Seven list-table screens**: Blocked IPs, Whitelist, the event log, API Queue, the audit event trail (Business), the session manager under Users → Sessions (Business), plus the 2FA admin grid, the 2FA Status list filterable by status, method and role
- **System Status page** listing every open readiness issue with severity, first-seen time, a jump to the responsible setting and a documentation link; non-critical issues can be dismissed for seven days
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
- **WP-CLI** command trees for 2FA, hardening, IP lookup and full IP management, see [WP-CLI](#wp-cli) below
- **PHP filters**: `reportedip_hive_rest_bypass_routes`, `reportedip_hive_rest_sensitive_routes`, `reportedip_hive_event_category_map`, `reportedip_hive_mail_provider`, `reportedip_hive_mail_args`, `reportedip_hive_mail_template_path`, `reportedip_hive_decoy_paths`, `reportedip_hive_bot_allowlist_patterns`, `reportedip_hive_own_server_ips`, `reportedip_hive_webauthn_rp_id`, `reportedip_hive_webauthn_allowed_origins`, `reportedip_hive_auto_update`
- **Constants**: `REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN` (emergency override from `wp-config.php`)
- **9 database tables** (auto-migrated, opt-in delete on uninstall)
- **Internationalisation-ready** (text domain `reportedip-hive`, English source + complete German translation included)

### WP-CLI

Every day-to-day management task is available from the shell. All list-style commands accept `--format=<table|json|csv|yaml>`.

**IP management**

```
wp reportedip whitelist add <ip> [--reason=<text>] [--expires=<datetime>]
wp reportedip whitelist remove <ip>
wp reportedip whitelist list [--format=<format>]
wp reportedip block <ip> [--reason=<text>] [--hours=<n>]
wp reportedip unblock <ip> [--reset-attempts]
wp reportedip blocked list [--format=<format>]
wp reportedip attempts reset <ip> [--type=<type>]
wp reportedip lookup <ip> [--format=<format>]
```

`<ip>` accepts a single IPv4/IPv6 address or a CIDR range throughout. Whitelisting lifts an active block automatically and wins over every protection layer, including the pre-WordPress guard. When releasing a locked-out visitor, prefer `wp reportedip unblock <ip> --reset-attempts`, without the flag, a still-exceeded threshold re-blocks the address on the very next request. `--expires` on the whitelist is the site's local time; every other datetime is UTC.

```bash
# Release a locked-out customer and clear their counters
wp reportedip unblock 203.0.113.9 --reset-attempts

# Whitelist a rotating IPv6 prefix instead of a single address
wp reportedip whitelist add 2001:db8::/56 --reason="customer office"

# Manual block for a week, machine-readable overview afterwards
wp reportedip block 203.0.113.0/24 --reason="scanner" --hours=168
wp reportedip blocked list --format=json
```

**Status overview**

```
wp reportedip status [--format=<format>]
```

Prints version, operation mode, tier, report-only state, block/whitelist counters, report-queue health and the main protection toggles (hide-login, firewall, extended protection guard, enforced 2FA roles) as a field/value table.

**Two-factor administration**

```
wp reportedip 2fa status [--user=<id>]
wp reportedip 2fa enable <user_id> --method=<totp|email|sms|webauthn> [--secret=<base32>] [--force]
wp reportedip 2fa disable <user_id> [--method=<method>]
wp reportedip 2fa reset <user_id>
wp reportedip 2fa enforce --role=<role> [--remove]
wp reportedip 2fa audit [--user=<id>] [--since=<date>]
wp reportedip 2fa cleanup
```

**Hardening mode**

```
wp reportedip hardening <status|activate|deactivate>
```

**User accounts (Business)**

```
wp reportedip user block <user> [--message=<text>] [--note=<text>]
wp reportedip user unblock <user>
wp reportedip user list [--format=<format>]
```

`<user>` is an id, login or e-mail address. `--message` is what the person sees at sign-in, `--note` stays internal. A blocked account keeps its content but cannot sign in, authenticate an application password or complete a password reset, and loses every session and trusted device at once. `unblock` is deliberately never plan-gated, so an expired licence can never leave an account locked out.

### Developer hooks

Stable public hooks for webhook, SIEM and white-label integrations.

#### Actions

`reportedip_hive_threshold_exceeded( $ip, $event_type, $details )`, fires once per confirmed sensor detection, regardless of the auto-block and community-reporting settings, so integrations see every detection.

```php
add_action( 'reportedip_hive_threshold_exceeded', function ( $ip, $event_type, $details ) {
    wp_remote_post( 'https://siem.example.com/ingest', array( 'body' => wp_json_encode( compact( 'ip', 'event_type', 'details' ) ) ) );
}, 10, 3 );
```

`reportedip_hive_ip_blocked( $ip, $reason, $blocked_until )`, fires when an IP is blocked; `$blocked_until` is a UTC MySQL datetime, or `null` for a permanent block.

```php
add_action( 'reportedip_hive_ip_blocked', function ( $ip, $reason, $blocked_until ) {
    error_log( sprintf( 'Hive blocked %s (%s) until %s', $ip, $reason, $blocked_until ?? 'forever' ) );
}, 10, 3 );
```

`reportedip_hive_ip_unblocked( $ip )`, fires when a block is lifted.

```php
add_action( 'reportedip_hive_ip_unblocked', function ( $ip ) {
    error_log( 'Hive unblocked ' . $ip );
} );
```

`reportedip_hive_report_queued( $ip, $category_ids, $report_type )`, fires once per report that actually enters the API queue (after the cooldown and dedup checks); `$category_ids` is a comma-separated ID list, `$report_type` is `negative` or `positive`.

```php
add_action( 'reportedip_hive_report_queued', function ( $ip, $category_ids, $report_type ) {
    error_log( sprintf( 'Queued %s report for %s (categories %s)', $report_type, $ip, $category_ids ) );
}, 10, 3 );
```

`reportedip_hive_access_denied( $ip, $context )`, fires once per denied request, just before the 403 block page renders. Refusals by the pre-WordPress guard terminate earlier and do not reach this hook.

```php
add_action( 'reportedip_hive_access_denied', function ( $ip, $context ) {
    error_log( sprintf( 'Denied %s (%s)', $ip, $context ) );
}, 10, 2 );
```

`reportedip_hive_2fa_verified( $user_id, $method, $context )`, fires after a passed second-factor challenge, on wp-login, on the WooCommerce frontend and on the REST verify endpoint. Core's own `wp_login` fires in the same place, so a listener on either sees challenged sign-ins as well as unchallenged ones.

```php
add_action( 'reportedip_hive_2fa_verified', function ( $user_id, $method, $context ) {
    error_log( sprintf( 'User %d passed %s (%s)', $user_id, $method, $context ) );
}, 10, 3 );
```

#### Filters

`reportedip_hive_reputation_block_hours`, duration in hours (default 24) of the temporary local block written on a community-reputation hit.

```php
add_filter( 'reportedip_hive_reputation_block_hours', function () {
    return 48;
} );
```

`reportedip_hive_tor_block_hours`, duration in hours (default 24) of the temporary block written for a Tor exit node.

```php
add_filter( 'reportedip_hive_tor_block_hours', function () {
    return 6;
} );
```

`reportedip_hive_blocked_page_strings( $strings, $context )`, white-label the visitor-facing 403 page. Keys: `doc_title`, `title`, `message`, `reason`; missing keys keep their defaults.

```php
add_filter( 'reportedip_hive_blocked_page_strings', function ( $strings, $context ) {
    $strings['message'] = 'Access from your network is currently restricted.';
    return $strings;
}, 10, 2 );
```

`reportedip_hive_external_url( $url, $context )`, override outbound reportedip.com URLs (IP profile links, release feed, upgrade links).

```php
add_filter( 'reportedip_hive_external_url', function ( $url, $context ) {
    return 'ip_detail_base' === $context ? 'https://intel.example.com/ip/' : $url;
}, 10, 2 );
```

`reportedip_hive_rest_bypass_routes( $routes )`, extend the REST-route prefixes that bypass the burst monitor (cookie-banner integrations).

```php
add_filter( 'reportedip_hive_rest_bypass_routes', function ( $routes ) {
    $routes[] = '/my-consent-plugin/v1';
    return $routes;
} );
```

`reportedip_hive_scan_paths( $paths )`, extend the honeypot path list for the scan detector.

```php
add_filter( 'reportedip_hive_scan_paths', function ( $paths ) {
    $paths[] = '/.aws/credentials';
    return $paths;
} );
```

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
3. Activate → switch protection on in the quickstart.

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

WordPress auto-updates are always on for this plugin: a security plugin that lags behind its own fixes protects nobody, so releases install automatically without the per-plugin opt-in (the Plugins screen shows "Auto-updates enabled"). Sites that must pin the version can restore manual control:

```php
add_filter( 'reportedip_hive_auto_update', '__return_false' );
```

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
| Site Admin UI | Read-only Status / Logs (auto-scoped via `blog_id`), the audit trail of that site (Business, filters and export, network rows stay with the Network Admin) plus a 2FA Site Settings page with exactly two writable overrides: per-site Frontend-2FA slug and additive 2FA enforcement roles. Site Admins cannot drop a role the Network requires. |
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

- **License:** [GPL-2.0-or-later](./LICENSE), same as WordPress.
- **Copyright:** © 2025–2026 Patrick Schlesinger / ReportedIP.
- The code is GPL-licensed (distribution + modification permitted under GPL terms). The trademarks **ReportedIP**, **ReportedIP Hive**, and the logo are not covered by the GPL and remain the property of ReportedIP.
- Third-party software: [Plugin Update Checker](https://github.com/YahnisElsts/plugin-update-checker) (MIT), [Chart.js](https://www.chartjs.org/) (MIT). WebAuthn/FIDO2 is in-house, no external dependency.

---

## Contributing

Bug reports, feature requests, and pull requests are welcome.

- Issues: <https://github.com/reportedip/reportedip-hive/issues>
- Security disclosures (do **not** open a public issue): <abuse@reportedip.com>
- PRs target `main`; CI must be green.

**Language policy:** all code, comments, identifiers, commit messages, and user-facing strings are English.

---

## Support

- Website & documentation: <https://reportedip.com>
- Email: <1@reportedip.com>
- Status: see [GitHub Releases](https://github.com/reportedip/reportedip-hive/releases) for the current version and changelog
