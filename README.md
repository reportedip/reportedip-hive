# ReportedIP Hive

**Firewall, brute force protection, 2FA with passkeys and spam protection for forms. Optional community IP blocklist. GDPR-first, made in Germany.**

[![WordPress plugin version](https://img.shields.io/wordpress/plugin/v/reportedip-hive.svg)](https://wordpress.org/plugins/reportedip-hive/)
[![Active installations](https://img.shields.io/wordpress/plugin/installs/reportedip-hive.svg)](https://wordpress.org/plugins/reportedip-hive/)
[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2%2B-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![PHP 8.1+](https://img.shields.io/badge/PHP-8.1%2B-777BB4.svg)](https://www.php.net/)

ReportedIP Hive is a WordPress security plugin that combines a web application firewall (WAF), login security with limited login attempts, two-factor authentication with passkeys, and spam protection for comments, registrations and contact forms. It blocks malicious IPs on your own server, works without an account, and can optionally share and check attacking addresses through a community IP blocklist.

Sixteen sensors watch the sign-in form, XML-RPC, the REST API, the comment, registration and password-reset forms and the request itself. Four two-factor methods keep accounts safe when a password leaks. Everything in this plugin is free and complete: no trial, no locked switch, no account requirement. The Community Network and the separate Pro add-on are optional.

Install: [wordpress.org/plugins/reportedip-hive](https://wordpress.org/plugins/reportedip-hive/) · Product: [reportedip.com](https://reportedip.com/products/wordpress-plugin/?rc=hive-github) · Documentation: [ReportedIP Hive guide](https://reportedip.com/docs/integrations/wordpress-hive/?rc=hive-github)

---

## Login security and brute force protection

| Sensor | Default | Notes |
|---|---|---|
| Limit login attempts | 5 failures in 15 minutes per IP | the core counter behind every sign-in path |
| Password spraying detection | many usernames from one address | caught separately from plain failures |
| Progressive IP blocking | 6 steps: 5 min, 15 min, 30 min, 24 h, 48 h, 7 days | the ladder resets after 30 quiet days |
| Hide Login | off | moves wp-login.php to a custom login URL |
| User enumeration protection | on | author archives, `/wp-json/wp/v2/users`, the user sitemap and login error messages stop revealing usernames |
| XML-RPC and pingback protection | counted, with a switch to turn XML-RPC off | |
| Application password abuse | counted per IP | closes the Basic-Auth path around 2FA |
| REST API rate limit | 240 requests in 5 minutes | cookie-banner consent routes are skipped |
| Login anomaly detection | on | a sign-in from a new country asks for the second factor again |
| WooCommerce login protection | on when WooCommerce is active | My Account sign-in and registration counted like wp-login.php |
| Password policy | 12 characters minimum | optional breach check against Have I Been Pwned (k-anonymity, off by default) |

The server's own addresses are never auto-blocked, so cache preloaders and WP-Cron loopbacks cannot lock the site out of itself.

## Two-factor authentication (2FA)

- **Authenticator apps (TOTP)** such as Google Authenticator, Authy or 1Password.
- **Passkeys and hardware security keys (WebAuthn, FIDO2)**, for example a YubiKey, Face ID, Touch ID or Windows Hello. One key per account.
- **E-mail codes.**
- **Recovery codes**, ten single-use codes per user.
- Trusted devices, an enrolment wizard, 2FA enforcement per user role, a password-reset gate that a stolen mailbox cannot bypass, and a REST namespace for headless sign-in flows.

## Web application firewall

Hive inspects requests in two places that stay behaviourally identical:

- **In-WordPress engine.** Runs on `init` priority 1 with a bundled baseline ruleset against SQL injection, XSS, path traversal and scanner traffic, a per-rule exception table (rule, group or path scope) and a report-only mode for testing. Works offline.
- **Pre-WordPress guard.** An optional `auto_prepend_file` drop-in generated from the same rules, exceptions, whitelist and IP blocks. It refuses blocked IPs and rule matches before WordPress loads and feeds its hits back into the block ladder. The Tools page produces the directive for your stack (php.ini, `.user.ini`, hosting panel or nginx) and checks that the guard actually runs.

Both layers are fail-open: a broken rule or an unwritable directory lets the request through rather than taking the site down. IP blocks are enforced even with the WAF switched off.

- **404 and scanner detection.** Bursts of 404s and requests for bait paths such as `.env` or `.git/config` block the address.
- **Verified bot detection.** Googlebot, Bingbot and other large crawlers are confirmed through their published address ranges or reverse DNS. A fake Googlebot gains nothing.
- **Cloudflare and reverse proxies.** A trusted IP header (CF-Connecting-IP, X-Forwarded-For, X-Real-IP, Client-IP, True-Client-IP, X-Cluster-Client-IP) is honoured only for requests from the trusted proxy list, so nobody can smuggle an allowed address into the header.

## Spam protection for forms and comments

- **Invisible form check instead of a CAPTCHA.** A cache-safe execution proof on the comment, registration and password-reset forms. Visitors see no puzzle, and no third-party CAPTCHA service is loaded.
- **Contact Form 7 spam protection** through the same check.
- **Comment spam filter** that scores links, link density, disposable addresses and other signals.
- **Comment honeypot.**
- **Disposable e-mail blocking** on registrations and forms.
- **Registration rules:** prohibited usernames, e-mail allow and block rules and a sign-up rate limit.

## Access lockdown

Each a switch: the REST API for signed-in users or chosen roles, XML-RPC and pingbacks, feeds, wp-admin for guests, PHP execution in uploads and software version fingerprints. Basic security headers come on top.

## Community IP blocklist

- **Local Shield** is the default. The plugin makes no outbound request, even with a key stored; every decision is taken from the data on your own server.
- **Community Network** is optional. With a free Community Access Key from [reportedip.com](https://reportedip.com/register/?rc=hive-github) the plugin checks the IP reputation of attacking addresses during sign-in and on forms, shares the addresses it blocks with the community blocklist, and receives signed firewall rulesets every six hours.

Only the attacking IP address, the event category, the time, the site name and address, the attempt count and the plugin version leave the site. Usernames, passwords and form content never do. Every request is listed under External Services in [`readme.txt`](./readme.txt).

## GDPR and privacy

Minimal logging, 30 days retention by default, anonymisation after 7 days, the Community Network is opt-in. A suggested text for the privacy policy is added under Settings, Privacy; the lawful basis is Art. 6(1)(f) GDPR.

## Performance and caching

A blocked address is refused at the start of the request, before themes and most plugins load. Community reports leave in the background through WP-Cron. The block page sends no-cache headers that WP Rocket, W3 Total Cache, WP Super Cache and LiteSpeed Cache respect, and the form check contains nothing request-specific, so cached pages keep working.

## What it does not do

ReportedIP Hive does not scan files for malware and does not monitor file integrity. Run a scanner next to it if your site needs one.

## ReportedIP Hive Pro

A separate add-on, ReportedIP Hive Pro, extends this plugin with a managed EU relay for 2FA mails and SMS codes, two-factor authentication on the WooCommerce storefront, adaptive per-role 2FA policies, a hardening mode during attack waves, advanced security headers, a computation check on forms, form protection for further form plugins, Tor exit node blocking, an audit trail, user account control and fleet management. It is not part of this repository and is described on the [product page](https://reportedip.com/products/wordpress-plugin/?rc=hive-github).

---

## Installation

Install ReportedIP Hive from the WordPress plugin directory: [wordpress.org/plugins/reportedip-hive](https://wordpress.org/plugins/reportedip-hive/). On a multisite network, activate it network-wide. The quickstart under ReportedIP Hive lets you pick Local Shield or the Community Network and applies the recommended settings with one click. Updates arrive through the plugin directory.

The two optional `.htaccess` blocks (bait-path responses and PHP execution in uploads) are written only after an operator action: the quickstart, saving either switch, a settings import or WP-CLI. Activation writes nothing. A site updating from 2.x with a completed quickstart keeps its blocks.

A site on version 1.3.9 of this plugin receives 3.0.0 as a normal update. Its whitelist (including ranges and permanent entries), blocks, attempt counters, proxy header and settings are carried over.

## Requirements

- PHP 8.1 or newer
- WordPress 5.9 or newer (tested up to 7.1)
- MySQL 5.7+ or MariaDB
- Optional: WooCommerce (monitored when active, never required)

## Multisite support

| Topic | Behaviour |
|---|---|
| Activation | Network-only (`Network: true` in the plugin header). |
| Tables | All plugin tables live under `$wpdb->base_prefix`; logs, queue and stats carry a `blog_id`, so the Network Admin can filter and site admins see their own site. |
| Cross-site brute force | Failed sign-ins on every sub-site count into one row, and one block covers the whole network. |
| Site admin UI | Read-only status and logs plus two per-site 2FA overrides. A site cannot drop a role the network requires. |
| Cron | Scheduled on the main site only, with a self-heal on `admin_init`. |

---

## Developer surface

- **REST API** namespace `reportedip-hive/v1`: `POST /2fa/challenge`, `POST /2fa/verify`, `GET /2fa/methods`.
- **PHP filters:** `reportedip_hive_rest_bypass_routes`, `reportedip_hive_rest_sensitive_routes`, `reportedip_hive_event_category_map`, `reportedip_hive_mail_provider`, `reportedip_hive_decoy_paths`, `reportedip_hive_bot_allowlist_patterns`, `reportedip_hive_own_server_ips`, `reportedip_hive_webauthn_rp_id`, `reportedip_hive_webauthn_allowed_origins`.
- **Constant:** `REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN` (emergency override from `wp-config.php`).
- **Translations:** text domain `reportedip-hive`, English source with a complete German translation.

### WP-CLI

All list-style commands accept `--format=<table|json|csv|yaml>`.

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

**Status and support**

```
wp reportedip status [--format=<format>]
wp reportedip support-bundle [--days=<1-30>] [--events=<n>] [--full-ips] [--output=<file>]
```

**Two-factor administration**

```
wp reportedip 2fa status [<user_id>]
wp reportedip 2fa enable <user_id> --method=<totp|email|webauthn> [--secret=<base32>] [--force]
wp reportedip 2fa disable <user_id> [--method=<method>]
wp reportedip 2fa reset <user_id>
wp reportedip 2fa enforce --role=<role> [--remove]
wp reportedip 2fa audit [<user_id>] [--since=<date>]
wp reportedip 2fa cleanup
```

### Developer hooks

Stable public hooks for webhook and SIEM integrations.

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

`reportedip_hive_2fa_verified( $user_id, $method, $context )`, fires after a passed second-factor challenge, on wp-login and on the REST verify endpoint. Core's own `wp_login` fires in the same place, so a listener on either sees challenged sign-ins as well as unchallenged ones.

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

`reportedip_hive_external_url( $url, $context )`, override outbound reportedip.com URLs (IP profile links, the news feed).

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

---

## Development

```bash
composer install
composer test           # PHPUnit
composer test:multisite # PHPUnit multisite suite
composer lint           # PHPCS against the WordPress Coding Standards
composer analyse        # PHPStan level 5
composer i18n           # refresh POT and PO, compile MO and JSON
composer check-all      # lint, analyse, i18n check and tests
```

## License

- [GPL-2.0-or-later](./LICENSE), same as WordPress. Copyright 2025-2026 Patrick Schlesinger / ReportedIP.
- The names ReportedIP and ReportedIP Hive and the logo are not covered by the GPL.
- Bundled third-party code: [Chart.js](https://github.com/chartjs/Chart.js) 4.4.1 (MIT) for the dashboard charts and [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4 (MIT) for the TOTP QR code. Nothing is loaded from a CDN.

## Contributing and support

This repository mirrors the free plugin from a private repository. Report issues here; pull requests are welcome and get merged there.

- Issues: <https://github.com/reportedip/reportedip-hive/issues>
- Security disclosures (please do not open a public issue): <abuse@reportedip.com>
- Website and documentation: [reportedip.com](https://reportedip.com/?rc=hive-github)
