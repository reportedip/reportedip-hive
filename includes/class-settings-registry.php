<?php
/**
 * Canonical settings registry, the single declarative source for option
 * kinds, ranges, tier gates and side effects, shared by the Settings API,
 * the setup wizard, settings import/export and every remote transport
 * (MainWP today, the reportedip.com management API later).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.47
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Declarative per-option specification and the sanitizers built on it.
 *
 * Every spec entry is `array{section:string, kind:string, min?:int, max?:int,
 * allowed?:string[], tier?:string, tier_gate?:callable, remote:bool,
 * sanitize?:callable, side_effects?:string[], json_filter?:callable,
 * json_fallback?:string[], label:string, description?:string}`. Defaults are
 * deliberately NOT duplicated here, they live in
 * {@see ReportedIP_Hive_Defaults::SAFE_OPTIONS} and are read at runtime; a unit
 * test enforces that every registry key has a default.
 *
 * `description` is the one sentence that explains the option to whoever is
 * looking at it. It belongs here rather than in the markup because three
 * surfaces render the same option: the settings page, the MainWP form and the
 * cloud fleet. A text kept in the page markup reaches exactly one of them, so
 * dashboards used to show bare labels for every field.
 *
 * The class is loaded unconditionally (never behind `is_admin()`), so its
 * sanitizers exist in every request context, wp-admin, MainWP child calls,
 * WP-CLI and cron alike.
 *
 * @since 2.1.47
 */
final class ReportedIP_Hive_Settings_Registry {

	/**
	 * Protocol schema version. Bump on key removal or kind change; pure
	 * additions do not require a bump (consumers must tolerate unknown keys).
	 */
	const SCHEMA_VERSION = 1;

	/**
	 * Ordered section definitions for schema export and form rendering.
	 *
	 * @return array<string, array{label:string, description:string}>
	 */
	public static function sections() {
		return array(
			'detection'        => array(
				'label'       => __( 'Detection & Thresholds', 'reportedip-hive' ),
				'description' => __( 'The sensors that watch for an attack and the counts at which each one reacts. Also holds the proxy settings, because every sensor depends on resolving the visitor address correctly.', 'reportedip-hive' ),
			),
			'blocking'         => array(
				'label'       => __( 'Blocking & Escalation', 'reportedip-hive' ),
				'description' => __( 'Automatic blocking, durations and the escalation ladder.', 'reportedip-hive' ),
			),
			'waf'              => array(
				'label'       => __( 'Firewall & Bots', 'reportedip-hive' ),
				'description' => __( 'The request-inspecting firewall, its rule feed and the check that a crawler is really the crawler it claims to be.', 'reportedip-hive' ),
			),
			'registration'     => array(
				'label'       => __( 'Registration Rules', 'reportedip-hive' ),
				'description' => __( 'Who may create an account, under which name and with which mail address. Throwaway mail domains and the rate limit for sign-ups belong here too.', 'reportedip-hive' ),
			),
			'forms'            => array(
				'label'       => __( 'Form Protection', 'reportedip-hive' ),
				'description' => __( 'The checks that sit on the comment form, the sign-up form, the password-reset form and the forms of Contact Form 7, Formidable Forms and Elementor. A visitor sees none of it, and nobody has to read a distorted image.', 'reportedip-hive' ),
			),
			'hardening_mode'   => array(
				'label'       => __( 'Attack Response', 'reportedip-hive' ),
				'description' => __( 'What changes while a coordinated attack is running. These thresholds replace the normal ones for the duration and are meant to be stricter than anything you would run permanently.', 'reportedip-hive' ),
			),
			'hide_login'       => array(
				'label'       => __( 'Hide Login', 'reportedip-hive' ),
				'description' => __( 'Custom login URL and probe monitoring.', 'reportedip-hive' ),
			),
			'headers'          => array(
				'label'       => __( 'Security Headers', 'reportedip-hive' ),
				'description' => __( 'Response headers that tell the browser to refuse risky behaviour: MIME sniffing, framing by foreign sites, referrer leaks and downgrades to HTTP. The basic three are free; HSTS, Content-Security-Policy, Permissions-Policy and the Cross-Origin trio are part of advanced hardening.', 'reportedip-hive' ),
			),
			'lockdown'         => array(
				'label'       => __( 'Access Lockdown', 'reportedip-hive' ),
				'description' => __( 'Attack-surface switches: REST API access, XML-RPC, feeds, wp-admin for visitors, PHP execution in uploads and software fingerprints.', 'reportedip-hive' ),
			),
			'account_security' => array(
				'label'       => __( 'Two-Factor Authentication', 'reportedip-hive' ),
				'description' => __( 'Which methods exist, who has to use one, and how long a device stays trusted. The storefront variant for WooCommerce lives here too.', 'reportedip-hive' ),
			),
			'twofa_policies'   => array(
				'label'       => __( 'Adaptive Step-Up', 'reportedip-hive' ),
				'description' => __( 'When a user who already passed the second factor is asked for it again. Each trigger is set per role, and a user without a configured method is never locked out by one.', 'reportedip-hive' ),
			),
			'account_password' => array(
				'label'       => __( 'Password Policy', 'reportedip-hive' ),
				'description' => __( 'What a password has to look like before WordPress accepts it.', 'reportedip-hive' ),
			),
			'privacy_logs'     => array(
				'label'       => __( 'Privacy & Logs', 'reportedip-hive' ),
				'description' => __( 'Logging depth, retention and the audit trail.', 'reportedip-hive' ),
			),
			'notifications'    => array(
				'label'       => __( 'Notifications', 'reportedip-hive' ),
				'description' => __( 'Admin notification recipients and sender identity.', 'reportedip-hive' ),
			),
			'performance'      => array(
				'label'       => __( 'Performance & Footprint', 'reportedip-hive' ),
				'description' => __( 'Lookup caching, the report queue and the public protection badge. These change how much work the site does per request, not how it decides what to block.', 'reportedip-hive' ),
			),
		);
	}

	/**
	 * The full option specification map.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function spec() {
		return array(
			'reportedip_hive_trusted_ip_header'            => array(
				'section'     => 'detection',
				'kind'        => 'enum',
				'allowed'     => array( '', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP' ),
				'sanitize'    => array( 'ReportedIP_Hive_Proxy_Trust', 'sanitize_header' ),
				'remote'      => true,
				'label'       => __( 'Client IP header', 'reportedip-hive' ),
				'description' => __( 'Header to read the visitor address from when the site sits behind a proxy or CDN. Leave empty unless you run one, because a wrong header lets anyone claim any address.', 'reportedip-hive' ),
			),
			'reportedip_hive_trusted_proxy_ranges'         => array(
				'section'     => 'detection',
				'kind'        => 'textarea',
				'sanitize'    => array( 'ReportedIP_Hive_Proxy_Trust', 'sanitize_ranges' ),
				'remote'      => true,
				'label'       => __( 'Trusted proxy ranges', 'reportedip-hive' ),
				'description' => __( 'Addresses or CIDR ranges of your proxies, one per line. The header above is only believed when the request really comes from one of them. An empty list trusts every peer, which is the old behaviour.', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_failed_logins'        => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Monitor failed logins', 'reportedip-hive' ),
				'description' => __( 'Count failed sign-in attempts per address and act once the threshold is passed.', 'reportedip-hive' ),
			),
			'reportedip_hive_failed_login_threshold'       => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'Failed login threshold', 'reportedip-hive' ),
				'description' => __( 'How many failed sign-ins one address may produce inside the window below.', 'reportedip-hive' ),
			),
			'reportedip_hive_failed_login_timeframe'       => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'Failed login window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window the failed sign-ins are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_comments'             => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Monitor comment spam', 'reportedip-hive' ),
				'description' => __( 'Count comments that the spam filter rejects and act on addresses that keep trying.', 'reportedip-hive' ),
			),
			'reportedip_hive_comment_spam_threshold'       => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 50,
				'remote'      => true,
				'label'       => __( 'Comment spam threshold', 'reportedip-hive' ),
				'description' => __( 'How many rejected comments one address may produce inside the window below.', 'reportedip-hive' ),
			),
			'reportedip_hive_comment_spam_timeframe'       => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'Comment spam window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window rejected comments are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_xmlrpc'               => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Monitor XML-RPC abuse', 'reportedip-hive' ),
				'description' => __( 'Watch xmlrpc.php, which is a favourite entry point for password guessing because it accepts many attempts per request.', 'reportedip-hive' ),
			),
			'reportedip_hive_xmlrpc_threshold'             => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'XML-RPC threshold', 'reportedip-hive' ),
				'description' => __( 'How many XML-RPC calls one address may make inside the window below.', 'reportedip-hive' ),
			),
			'reportedip_hive_xmlrpc_timeframe'             => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'XML-RPC window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window XML-RPC calls are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_disable_xmlrpc_multicall'     => array(
				'section'     => 'lockdown',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Disable XML-RPC multicall', 'reportedip-hive' ),
				'description' => __( 'Remove the multicall method, which lets an attacker pack hundreds of password guesses into a single request. The rest of XML-RPC keeps working. To switch off XML-RPC completely, use the Access Lockdown switch instead.', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_rest_api'             => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Monitor REST API bursts', 'reportedip-hive' ),
				'description' => __( 'Watch the REST API for bursts of requests from one address.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_user_enumeration'       => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Block user enumeration', 'reportedip-hive' ),
				'description' => __( 'Stop the routes that hand out a list of your usernames, such as author archives, the users REST route and oEmbed lookups. Knowing the names is half of a password attack.', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_404_scans'            => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Monitor 404 scans', 'reportedip-hive' ),
				'description' => __( 'Count requests for pages that do not exist. A scanner produces far more of them than a visitor.', 'reportedip-hive' ),
			),
			'reportedip_hive_scan_404_threshold'           => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( '404 scan threshold', 'reportedip-hive' ),
				'description' => __( 'How many missing pages one address may request inside the window below.', 'reportedip-hive' ),
			),
			'reportedip_hive_scan_404_timeframe'           => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( '404 scan window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window missing-page requests are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_app_passwords'        => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Monitor application passwords', 'reportedip-hive' ),
				'description' => __( 'Watch application passwords, which authenticate without ever passing the second factor.', 'reportedip-hive' ),
			),
			'reportedip_hive_app_password_threshold'       => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'Application password threshold', 'reportedip-hive' ),
				'description' => __( 'How many failed application-password attempts one address may produce inside the window below.', 'reportedip-hive' ),
			),
			'reportedip_hive_app_password_timeframe'       => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'Application password window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window failed application-password attempts are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_app_password_require_2fa'     => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Application passwords require an account with 2FA', 'reportedip-hive' ),
				'description' => __( 'Only let accounts that have a second factor create application passwords. Without this, an application password is a way around your 2FA policy.', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_threshold'               => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 10000,
				'remote'      => true,
				'label'       => __( 'REST burst threshold', 'reportedip-hive' ),
				'description' => __( 'How many REST requests one address may make inside the window below.', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_timeframe'               => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'REST burst window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window REST requests are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_sensitive_threshold'     => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 10000,
				'remote'      => true,
				'label'       => __( 'Sensitive REST route threshold', 'reportedip-hive' ),
				'description' => __( 'A tighter limit for routes that expose user or setting data.', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_sensitive_timeframe'     => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'Sensitive REST route window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window requests to sensitive routes are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_user_enum_threshold'          => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'User enumeration threshold', 'reportedip-hive' ),
				'description' => __( 'How many enumeration attempts one address may make inside the window below.', 'reportedip-hive' ),
			),
			'reportedip_hive_user_enum_timeframe'          => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'User enumeration window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window enumeration attempts are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_allow_author_archives'        => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Keep author archives reachable', 'reportedip-hive' ),
				'description' => __( 'Keep /author/name pages reachable even while enumeration blocking is on. Turn this on only if your theme really uses them, because those pages hand out login names.', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_geo_anomaly'          => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Monitor country and network changes on login', 'reportedip-hive' ),
				'description' => __( 'Notice when an account signs in from a country or network it has never used.', 'reportedip-hive' ),
			),
			'reportedip_hive_geo_window_days'              => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 365,
				'remote'      => true,
				'label'       => __( 'Login history window (days)', 'reportedip-hive' ),
				'description' => __( 'How far back the per-account location history reaches.', 'reportedip-hive' ),
			),
			'reportedip_hive_geo_revoke_trusted_devices'   => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Drop trusted devices on a country change', 'reportedip-hive' ),
				'description' => __( 'Drop the account\'s trusted devices when it signs in from a new country, so the second factor is asked for again.', 'reportedip-hive' ),
			),
			'reportedip_hive_geo_report_to_api'            => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Share country anomalies with the community', 'reportedip-hive' ),
				'description' => __( 'Share country anomalies with the community database. Off by default because a travelling colleague is not an attacker.', 'reportedip-hive' ),
			),
			'reportedip_hive_password_spray_threshold'     => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'Password spray threshold', 'reportedip-hive' ),
				'description' => __( 'How many different accounts one address may try inside the window below. Spraying tries one common password against many names instead of many passwords against one.', 'reportedip-hive' ),
			),
			'reportedip_hive_password_spray_timeframe'     => array(
				'section'     => 'detection',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'Password spray window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window distinct account names are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_woocommerce'          => array(
				'section'     => 'detection',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Monitor WooCommerce login forms', 'reportedip-hive' ),
				'description' => __( 'Also watch the WooCommerce sign-in forms on My Account and at checkout. Without this, a storefront attack is invisible to the login sensor.', 'reportedip-hive' ),
			),
			'reportedip_hive_bot_allowlist_enabled'        => array(
				'section'     => 'waf',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Exempt verified crawlers from auto-blocking', 'reportedip-hive' ),
				'description' => __( 'Never auto-block a crawler whose identity was confirmed by reverse DNS. This protects your search ranking, and a crawler that cannot be confirmed is not exempt.', 'reportedip-hive' ),
			),

			'reportedip_hive_hardening_realtime_detection' => array(
				'ui_lock'     => 'hardening_mode',
				'section'     => 'hardening_mode',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Hardening realtime detection', 'reportedip-hive' ),
				'description' => __( 'Notice a coordinated attack while it happens instead of after the fact, and tighten the thresholds below for its duration.', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_duration_minutes'   => array(
				'ui_lock'     => 'hardening_mode',
				'section'     => 'hardening_mode',
				'kind'        => 'int',
				'min'         => 5,
				'max'         => 360,
				'remote'      => true,
				'label'       => __( 'Hardening duration (minutes)', 'reportedip-hive' ),
				'description' => __( 'How long the tightened thresholds stay in force after an attack is detected.', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_login_threshold'    => array(
				'ui_lock'     => 'hardening_mode',
				'section'     => 'hardening_mode',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 10,
				'remote'      => true,
				'label'       => __( 'Failed-login threshold during hardening', 'reportedip-hive' ),
				'description' => __( 'The failed-login threshold that replaces the normal one while hardening is active.', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_login_timeframe'    => array(
				'ui_lock'     => 'hardening_mode',
				'section'     => 'hardening_mode',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 60,
				'remote'      => true,
				'label'       => __( 'Failed-login window during hardening (minutes)', 'reportedip-hive' ),
				'description' => __( 'The failed-login window that replaces the normal one while hardening is active.', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_block_threshold'    => array(
				'ui_lock'     => 'hardening_mode',
				'section'     => 'hardening_mode',
				'kind'        => 'int',
				'min'         => ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'Reputation block threshold during hardening (%)', 'reportedip-hive' ),
				'description' => __( 'The community confidence value from which an address is blocked while hardening is active. Lower than normal, so more is caught and more false positives are accepted.', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_detect_window_minutes' => array(
				'ui_lock'     => 'hardening_mode',
				'section'     => 'hardening_mode',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 120,
				'remote'      => true,
				'label'       => __( 'Distributed-attack detection window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window used to decide whether separate attempts belong to one coordinated attack.', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_detect_min_ips'     => array(
				'ui_lock'     => 'hardening_mode',
				'section'     => 'hardening_mode',
				'kind'        => 'int',
				'min'         => 2,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'Minimum distinct IPs for a distributed attack', 'reportedip-hive' ),
				'description' => __( 'How many different addresses must take part before the attempts count as coordinated.', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_detect_min_attempts' => array(
				'ui_lock'     => 'hardening_mode',
				'section'     => 'hardening_mode',
				'kind'        => 'int',
				'min'         => 3,
				'max'         => 1000,
				'remote'      => true,
				'label'       => __( 'Minimum total attempts for a distributed attack', 'reportedip-hive' ),
				'description' => __( 'How many attempts those addresses must add up to before the attempts count as coordinated.', 'reportedip-hive' ),
			),

			'reportedip_hive_auto_block'                   => array(
				'simple'      => true,
				'section'     => 'blocking',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Automatic blocking', 'reportedip-hive' ),
				'description' => __( 'Actually refuse an address once a sensor threshold is passed. Off, the sensors only record.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_duration'               => array(
				'section'     => 'blocking',
				'kind'        => 'int',
				'min'         => 0,
				'max'         => 8760,
				'remote'      => true,
				'label'       => __( 'Block duration (hours)', 'reportedip-hive' ),
				'description' => __( 'How long a first block lasts before the address is allowed back.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_threshold'              => array(
				'section'     => 'blocking',
				'kind'        => 'int',
				'min'         => ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'Community block threshold (%)', 'reportedip-hive' ),
				'description' => __( 'The community confidence value from which an address is refused. Lower catches more and produces more false positives; the floor is there because below it most of what is caught is ordinary visitors.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_escalation_enabled'     => array(
				'section'     => 'blocking',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Escalation ladder', 'reportedip-hive' ),
				'description' => __( 'Make each repeat offence last longer than the one before it.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_ladder_minutes'         => array(
				'section'     => 'blocking',
				'kind'        => 'csv_int_list',
				'min'         => 1,
				'max'         => 525600,
				'remote'      => true,
				'label'       => __( 'Escalation ladder steps (minutes)', 'reportedip-hive' ),
				'description' => __( 'The rungs of the ladder in minutes, shortest first. An address that keeps coming back moves up one rung per offence.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_ladder_reset_days'      => array(
				'section'     => 'blocking',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 365,
				'remote'      => true,
				'label'       => __( 'Ladder reset window (days)', 'reportedip-hive' ),
				'description' => __( 'How long an address must behave before it drops back to the first rung.', 'reportedip-hive' ),
			),
			'reportedip_hive_report_only_mode'             => array(
				'simple'      => true,
				'section'     => 'blocking',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Report-only mode', 'reportedip-hive' ),
				'description' => __( 'Record every decision without acting on any of it. Use this to see what the settings would do before letting them do it.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_tor'                    => array(
				'section'     => 'blocking',
				'kind'        => 'bool',
				'tier'        => 'tor_blocking',
				'remote'      => true,
				'label'       => __( 'Block Tor exit nodes', 'reportedip-hive' ),
				'description' => __( 'Refuse addresses on the signed Tor exit-node list. Anonymity is not an attack in itself, so this is off unless your site has a reason.', 'reportedip-hive' ),
			),
			'reportedip_hive_blocked_page_contact_url'     => array(
				'section'     => 'blocking',
				'kind'        => 'url',
				'remote'      => true,
				'label'       => __( 'Contact URL on the block page', 'reportedip-hive' ),
				'description' => __( 'Where a wrongly blocked visitor can reach you. Without it the block page is a dead end for a customer.', 'reportedip-hive' ),
			),

			'reportedip_hive_waf_enabled'                  => array(
				'simple'      => true,
				'section'     => 'waf',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Firewall enabled', 'reportedip-hive' ),
				'description' => __( 'Inspect every front-end request against attack signatures before it reaches your site.', 'reportedip-hive' ),
			),
			'reportedip_hive_waf_report_only'              => array(
				'section'     => 'waf',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Firewall report-only', 'reportedip-hive' ),
				'description' => __( 'Record what the firewall would have blocked without blocking anything. The right way to try a new rule set on a live site.', 'reportedip-hive' ),
			),
			'reportedip_hive_waf_paranoia'                 => array(
				'partial'     => true,
				'section'     => 'waf',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 3,
				'tier'        => 'rule_sync_priority',
				'tier_gate'   => array( __CLASS__, 'paranoia_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Firewall paranoia level', 'reportedip-hive' ),
				'description' => __( 'How aggressively the rules are read. Level 1 is the false-positive-poor baseline; higher levels catch obfuscated attacks and need a report-only run first.', 'reportedip-hive' ),
			),
			'reportedip_hive_waf_block_threshold'          => array(
				'section'     => 'waf',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'Firewall block threshold (hits)', 'reportedip-hive' ),
				'description' => __( 'How many rule hits one request may collect before it is refused.', 'reportedip-hive' ),
			),
			'reportedip_hive_waf_dropin_skip_authenticated' => array(
				'section'     => 'waf',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Skip body inspection for signed-in users (Extended Protection)', 'reportedip-hive' ),
				'description' => __( 'The pre-WordPress guard cannot see roles, only the sign-in cookie. With this on it leaves the request body of signed-in users alone, so an editor saving a post with a script tag in it is not refused before WordPress loads. URL and user-agent rules still run.', 'reportedip-hive' ),
			),
			'reportedip_hive_rule_sync_enabled'            => array(
				'section'     => 'waf',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Rule synchronisation', 'reportedip-hive' ),
				'description' => __( 'Fetch fresh signatures from the community server. Turned off, the bundled baseline keeps working but stops learning.', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_bot_verification'     => array(
				'section'     => 'waf',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Bot verification', 'reportedip-hive' ),
				'description' => __( 'Check whether a request that claims to be a known crawler really comes from it. Attackers use the Googlebot name to slip past rate limits.', 'reportedip-hive' ),
			),
			'reportedip_hive_bot_action'                   => array(
				'simple'      => true,
				'section'     => 'waf',
				'kind'        => 'enum',
				'allowed'     => array( 'flag', 'off', 'block' ),
				'remote'      => true,
				'label'       => __( 'Action on failed bot verification', 'reportedip-hive' ),
				'description' => __( 'What happens to a request whose crawler identity does not hold up.', 'reportedip-hive' ),
			),
			'reportedip_hive_disposable_email_action'      => array(
				'simple'      => true,
				'section'     => 'registration',
				'kind'        => 'enum',
				'allowed'     => array( 'monitor', 'off', 'block' ),
				'remote'      => true,
				'label'       => __( 'Action on disposable email domains', 'reportedip-hive' ),
				'description' => __( 'What happens when a registration uses a throwaway mail domain.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_email_relays'           => array(
				'section'     => 'registration',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Block privacy relay addresses', 'reportedip-hive' ),
				'description' => __( 'Also reject forwarding services such as Apple and Firefox Relay. These are used by ordinary customers too, so weigh this against your sign-up numbers.', 'reportedip-hive' ),
			),
			'reportedip_hive_prohibited_usernames'         => array(
				'partial'     => true,
				'section'     => 'registration',
				'kind'        => 'textarea',
				'tier'        => 'registration_rules_unlimited',
				'tier_gate'   => array( 'ReportedIP_Hive_Registration_Guard', 'list_needs_tier' ),
				'sanitize'    => array( 'ReportedIP_Hive_Registration_Guard', 'sanitize_username_list' ),
				'remote'      => true,
				'label'       => __( 'Prohibited usernames', 'reportedip-hive' ),
				'description' => __( 'Names that may not be registered, one per line. An entry matches literally, as a wildcard when it contains an asterisk, or as a regular expression when written between slashes.', 'reportedip-hive' ),
			),
			'reportedip_hive_prohibited_usernames_baseline' => array(
				'section'     => 'registration',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Built-in prohibited usernames', 'reportedip-hive' ),
				'description' => __( 'Also reject the built-in list of role names such as admin, administrator and root. It does not count towards the free entry allowance.', 'reportedip-hive' ),
			),
			'reportedip_hive_email_rule_mode'              => array(
				'section'     => 'registration',
				'kind'        => 'enum',
				'allowed'     => array( 'off', 'block', 'allow' ),
				'remote'      => true,
				'label'       => __( 'E-mail rule mode', 'reportedip-hive' ),
				'description' => __( 'Whether the list below rejects matching addresses, accepts only matching addresses, or is ignored.', 'reportedip-hive' ),
			),
			'reportedip_hive_email_rules'                  => array(
				'partial'     => true,
				'section'     => 'registration',
				'kind'        => 'textarea',
				'tier'        => 'registration_rules_unlimited',
				'tier_gate'   => array( 'ReportedIP_Hive_Registration_Guard', 'list_needs_tier' ),
				'sanitize'    => array( 'ReportedIP_Hive_Registration_Guard', 'sanitize_email_rule_list' ),
				'remote'      => true,
				'label'       => __( 'E-mail rules', 'reportedip-hive' ),
				'description' => __( 'Address patterns, one per line. A bare host name is read as every address at that host.', 'reportedip-hive' ),
			),
			'reportedip_hive_registration_limit_enabled'   => array(
				'section'     => 'registration',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Registration rate limit', 'reportedip-hive' ),
				'description' => __( 'Limit how many accounts one address may create in a row.', 'reportedip-hive' ),
			),
			'reportedip_hive_registration_limit_count'     => array(
				'section'     => 'registration',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'Registrations per window', 'reportedip-hive' ),
				'description' => __( 'How many sign-ups one address may complete inside the window below.', 'reportedip-hive' ),
			),
			'reportedip_hive_registration_limit_timeframe' => array(
				'section'     => 'registration',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 60,
				'remote'      => true,
				'label'       => __( 'Registration window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window sign-ups are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_registration_allowlist'       => array(
				'section'     => 'registration',
				'kind'        => 'textarea',
				'tier'        => 'registration_rules_unlimited',
				'sanitize'    => array( 'ReportedIP_Hive_Registration_Guard', 'sanitize_ip_list' ),
				'remote'      => true,
				'label'       => __( 'Registration allowlist (IP/CIDR)', 'reportedip-hive' ),
				'description' => __( 'When filled, accounts can only be created from these addresses or ranges. Leave empty to accept sign-ups from anywhere.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_unknown_username_login' => array(
				'section'     => 'registration',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Block logins with unknown usernames', 'reportedip-hive' ),
				'description' => __( 'Treat a sign-in attempt for a name that does not exist as an attack straight away. Effective against name guessing, but it also catches a colleague who mistypes their login.', 'reportedip-hive' ),
			),
			'reportedip_hive_comment_honeypot_enabled'     => array(
				'simple'      => true,
				'section'     => 'forms',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Comment honeypot', 'reportedip-hive' ),
				'description' => __( 'Add a field to the comment form that a person never fills in and a bot always does.', 'reportedip-hive' ),
			),
			'reportedip_hive_form_proof_enabled'           => array(
				'simple'       => true,
				'section'      => 'forms',
				'kind'         => 'bool',
				'remote'       => true,
				'side_effects' => array( 'purge_pages_for_form_proof' ),
				'label'        => __( 'Form execution proof', 'reportedip-hive' ),
				'description'  => __( 'Check whether a comment, sign-up or password reset came from a browser that actually rendered the form, instead of from a script posting straight at the address.', 'reportedip-hive' ),
			),
			'reportedip_hive_form_proof_login_forms'       => array(
				'section'     => 'forms',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Apply the proof to sign-up and password reset', 'reportedip-hive' ),
				'description' => __( 'A comment that fails the check is filed for review, a sign-up or password reset that fails is refused. Switch this off to keep the comment protection while leaving both login forms untouched.', 'reportedip-hive' ),
			),
			'reportedip_hive_form_proof_pow'               => array(
				'section'      => 'forms',
				'kind'         => 'bool',
				'remote'       => true,
				'tier'         => 'form_proof_pow',
				'side_effects' => array( 'stamp_form_proof_pow' ),
				'label'        => __( 'Computation check on forms', 'reportedip-hive' ),
				'description'  => __( 'Give the form a small sum to work out in the background and check the answer on submit. A script that only copies the hidden field out of the page can no longer pass for a visitor, and nobody has to read a distorted image. Needs HTTPS.', 'reportedip-hive' ),
			),
			'reportedip_hive_form_proof_cf7'               => array(
				'simple_form'  => 'cf7',
				'section'      => 'forms',
				'kind'         => 'bool',
				'remote'       => true,
				'tier'         => 'form_adapters',
				'side_effects' => array( 'stamp_form_adapters_since' ),
				'label'        => __( 'Protect Contact Form 7 forms', 'reportedip-hive' ),
				'description'  => __( 'Put the same check on every Contact Form 7 form: the entry has to come from a browser that rendered the page. Visitors notice nothing, and there is no image to decipher.', 'reportedip-hive' ),
			),
			'reportedip_hive_form_proof_formidable'        => array(
				'simple_form'  => 'formidable',
				'section'      => 'forms',
				'kind'         => 'bool',
				'remote'       => true,
				'tier'         => 'form_adapters_advanced',
				'side_effects' => array( 'stamp_form_adapters_since' ),
				'label'        => __( 'Protect Formidable Forms', 'reportedip-hive' ),
				'description'  => __( 'The same check on Formidable Forms and Formidable Forms PRO, including multi-step forms. Visitors notice nothing.', 'reportedip-hive' ),
			),
			'reportedip_hive_form_proof_elementor'         => array(
				'simple_form'  => 'elementor',
				'section'      => 'forms',
				'kind'         => 'bool',
				'remote'       => true,
				'tier'         => 'form_adapters_advanced',
				'side_effects' => array( 'stamp_form_adapters_since' ),
				'label'        => __( 'Protect Elementor forms', 'reportedip-hive' ),
				'description'  => __( 'The same check on Elementor Pro forms, which are sent in the background. Visitors notice nothing.', 'reportedip-hive' ),
			),
			'reportedip_hive_reputation_on_forms'          => array(
				'section'     => 'forms',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Community threat check on forms', 'reportedip-hive' ),
				'description' => __( 'Ask the community network about the visitor address when a comment, sign-up or password reset is submitted, using the same protection level the sign-in page enforces. Needs Community Network mode.', 'reportedip-hive' ),
			),
			'reportedip_hive_comment_spam_action'          => array(
				'simple'      => true,
				'section'     => 'forms',
				'kind'        => 'enum',
				'allowed'     => array( 'spam', 'off', 'block' ),
				'remote'      => true,
				'label'       => __( 'Action on a comment scored as spam', 'reportedip-hive' ),
				'description' => __( 'Whether a comment that trips several spam signals is filed as spam, rejected outright, or left to WordPress.', 'reportedip-hive' ),
			),
			'reportedip_hive_decoy_pathblock_enabled'      => array(
				'section'     => 'waf',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Decoy path blocking', 'reportedip-hive' ),
				'description' => __( 'Serve bait paths that only a scanner would ask for, and report whoever takes the bait to the community.', 'reportedip-hive' ),
			),

			'reportedip_hive_hide_login_enabled'           => array(
				'simple'       => true,
				'section'      => 'hide_login',
				'kind'         => 'bool',
				'remote'       => true,
				'side_effects' => array( 'flush_rewrite' ),
				'label'        => __( 'Hide login enabled', 'reportedip-hive' ),
				'description'  => __( 'Move the sign-in page away from wp-login.php, so the address that every bot tries first leads nowhere.', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_login_slug'              => array(
				'simple'       => true,
				'section'      => 'hide_login',
				'kind'         => 'slug',
				'sanitize'     => array( 'ReportedIP_Hive_Hide_Login', 'validate_slug_value' ),
				'remote'       => true,
				'side_effects' => array( 'flush_rewrite' ),
				'label'        => __( 'Login slug', 'reportedip-hive' ),
				'description'  => __( 'The path your sign-in page lives at. Note it somewhere before saving, because the old address stops working immediately.', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_login_response_mode'     => array(
				'section'     => 'hide_login',
				'kind'        => 'enum',
				'allowed'     => array( 'block_page', '404' ),
				'remote'      => true,
				'label'       => __( 'Response on the default login URL', 'reportedip-hive' ),
				'description' => __( 'What a visitor to the old sign-in address sees. A plain 404 gives away less than a block page.', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_hide_login_probe'     => array(
				'section'     => 'hide_login',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Monitor login probe attempts', 'reportedip-hive' ),
				'description' => __( 'Count who keeps knocking at the old sign-in address. Nobody does that by accident.', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_login_probe_threshold'   => array(
				'section'     => 'hide_login',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'Login probe threshold', 'reportedip-hive' ),
				'description' => __( 'How many probes at the old address one visitor may make inside the window below.', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_login_probe_timeframe'   => array(
				'section'     => 'hide_login',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'Login probe window (minutes)', 'reportedip-hive' ),
				'description' => __( 'The window probes are counted in.', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_login_token_in_urls'     => array(
				'section'     => 'hide_login',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Append the login token to generated URLs', 'reportedip-hive' ),
				'description' => __( 'Append the login token to links WordPress generates. Convenient for password-reset mails, but it also puts the hidden path into anything that logs a URL.', 'reportedip-hive' ),
			),

			'reportedip_hive_rest_access_mode'             => array(
				'section'     => 'lockdown',
				'kind'        => 'enum',
				'allowed'     => array( 'open', 'logged_in', 'restricted' ),
				'remote'      => true,
				'label'       => __( 'REST API access', 'reportedip-hive' ),
				'description' => __( 'Who may use the REST API. Many plugins and the block editor depend on it, so try a restriction before you rely on it.', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_allowed_namespaces'      => array(
				'section'     => 'lockdown',
				'kind'        => 'textarea',
				'remote'      => true,
				'label'       => __( 'REST namespaces always allowed', 'reportedip-hive' ),
				'description' => __( 'Namespaces that stay reachable whatever the mode above says, one per line. This is where a cookie banner or a shop plugin goes.', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_allowed_roles'           => array(
				'choices_fixed' => array( 'administrator' ),
				'choices'       => 'roles',
				'section'       => 'lockdown',
				'kind'          => 'json_list',
				'json_filter'   => array( 'ReportedIP_Hive_Two_Factor', 'filter_valid_roles' ),
				'json_fallback' => array( 'administrator' ),
				'remote'        => true,
				'label'         => __( 'Roles allowed to use the REST API', 'reportedip-hive' ),
				'description'   => __( 'The roles that may use the REST API while access is restricted to roles.', 'reportedip-hive' ),
			),
			'reportedip_hive_disable_xmlrpc'               => array(
				'section'     => 'lockdown',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Disable XML-RPC', 'reportedip-hive' ),
				'description' => __( 'Switch off xmlrpc.php and pingbacks completely. Most sites never use it; the Jetpack app and some publishing tools do. If you need XML-RPC, leave this off and use the multicall switch below instead.', 'reportedip-hive' ),
			),
			'reportedip_hive_disable_feeds'                => array(
				'section'     => 'lockdown',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Disable RSS and Atom feeds', 'reportedip-hive' ),
				'description' => __( 'Return a 404 for RSS and Atom feeds. Turn this on only if nothing subscribes to your site.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_admin_guests'           => array(
				'section'     => 'lockdown',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Close wp-admin for visitors', 'reportedip-hive' ),
				'description' => __( 'Send signed-out visitors away from wp-admin instead of showing them the sign-in form.', 'reportedip-hive' ),
			),
			'reportedip_hive_block_uploads_php'            => array(
				'section'     => 'lockdown',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Block PHP execution in uploads', 'reportedip-hive' ),
				'description' => __( 'Refuse to run PHP inside the uploads folder, so a file that got in through an upload form cannot be executed. Written into the uploads .htaccess on Apache; other servers get a snippet to paste.', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_software_info'           => array(
				'section'     => 'lockdown',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Hide software fingerprints', 'reportedip-hive' ),
				'description' => __( 'Remove the version numbers WordPress prints into your pages. It does not fix anything, it just stops handing a scanner the list of what to try.', 'reportedip-hive' ),
			),
			'reportedip_hive_headers_enabled'              => array(
				'section'     => 'headers',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Send security headers', 'reportedip-hive' ),
				'description' => __( 'Send hardening response headers on every front-end request. A header your server already sets is left alone.', 'reportedip-hive' ),
			),
			'reportedip_hive_header_xcto'                  => array(
				'section'     => 'headers',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'X-Content-Type-Options', 'reportedip-hive' ),
				'description' => __( 'Stop the browser from guessing a file type against what you declared, which is how an uploaded image gets treated as a script.', 'reportedip-hive' ),
			),
			'reportedip_hive_header_xfo'                   => array(
				'section'     => 'headers',
				'kind'        => 'enum',
				'allowed'     => array( 'SAMEORIGIN', 'DENY', 'off' ),
				'sanitize'    => array( 'ReportedIP_Hive_Security_Headers', 'sanitize_xfo' ),
				'remote'      => true,
				'label'       => __( 'X-Frame-Options', 'reportedip-hive' ),
				'description' => __( 'Who may put your pages inside a frame. Same-origin is right for almost every site; deny breaks legitimate embeds.', 'reportedip-hive' ),
			),
			'reportedip_hive_header_referrer'              => array(
				'section'     => 'headers',
				'kind'        => 'enum',
				'allowed'     => array( 'no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade' ),
				'remote'      => true,
				'label'       => __( 'Referrer-Policy', 'reportedip-hive' ),
				'description' => __( 'How much of the current address is passed on when a visitor follows a link away from your site.', 'reportedip-hive' ),
			),
			'reportedip_hive_hsts_enabled'                 => array(
				'section'     => 'headers',
				'kind'        => 'bool',
				'tier'        => 'security_headers_advanced',
				'remote'      => true,
				'label'       => __( 'HTTP Strict Transport Security', 'reportedip-hive' ),
				'description' => __( 'Tell the browser to reach this site over HTTPS only, from now on. Never turn this on before HTTPS works everywhere, because it cannot be taken back quickly.', 'reportedip-hive' ),
			),
			'reportedip_hive_hsts_max_age'                 => array(
				'ui_lock'     => 'security_headers_advanced',
				'section'     => 'headers',
				'kind'        => 'int',
				'min'         => 0,
				'max'         => 63072000,
				'remote'      => true,
				'label'       => __( 'HSTS max-age (seconds)', 'reportedip-hive' ),
				'description' => __( 'How long the browser remembers the HTTPS-only instruction. Start short while you are testing.', 'reportedip-hive' ),
			),
			'reportedip_hive_hsts_subdomains'              => array(
				'ui_lock'     => 'security_headers_advanced',
				'section'     => 'headers',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'HSTS includeSubDomains', 'reportedip-hive' ),
				'description' => __( 'Apply the HTTPS-only instruction to every subdomain as well. Check that all of them really have a certificate first.', 'reportedip-hive' ),
			),
			'reportedip_hive_hsts_preload'                 => array(
				'ui_lock'     => 'security_headers_advanced',
				'section'     => 'headers',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'HSTS preload', 'reportedip-hive' ),
				'description' => __( 'Ask to be added to the browsers\' built-in HTTPS-only list. Getting off that list takes months, so only set it when the setup is final.', 'reportedip-hive' ),
			),
			'reportedip_hive_permissions_policy'           => array(
				'section'     => 'headers',
				'kind'        => 'text',
				'tier'        => 'security_headers_advanced',
				'tier_gate'   => array( __CLASS__, 'header_text_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Permissions-Policy', 'reportedip-hive' ),
				'description' => __( 'Which browser features your pages are allowed to use. The default switches off camera, microphone, location and payment, which almost no site needs.', 'reportedip-hive' ),
			),
			'reportedip_hive_csp_mode'                     => array(
				'section'     => 'headers',
				'kind'        => 'enum',
				'allowed'     => array( 'off', 'report_only', 'enforce' ),
				'tier'        => 'security_headers_advanced',
				'tier_gate'   => array( __CLASS__, 'header_off_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Content-Security-Policy mode', 'reportedip-hive' ),
				'description' => __( 'Whether the content policy is enforced or only reported. Always run it in report-only first; an enforced policy that is too strict makes a page look broken.', 'reportedip-hive' ),
			),
			'reportedip_hive_csp_policy'                   => array(
				'ui_lock'     => 'security_headers_advanced',
				'section'     => 'headers',
				'kind'        => 'textarea',
				'remote'      => true,
				'label'       => __( 'Content-Security-Policy', 'reportedip-hive' ),
				'description' => __( 'The policy itself. It decides which scripts, styles and frames may load, and it is the one header that will break your theme if it is wrong.', 'reportedip-hive' ),
			),
			'reportedip_hive_csp_report_uri'               => array(
				'ui_lock'     => 'security_headers_advanced',
				'section'     => 'headers',
				'kind'        => 'url',
				'remote'      => true,
				'label'       => __( 'CSP report URI', 'reportedip-hive' ),
				'description' => __( 'Where the browser sends policy violations while you are tuning the policy.', 'reportedip-hive' ),
			),
			'reportedip_hive_coop'                         => array(
				'section'     => 'headers',
				'kind'        => 'enum',
				'allowed'     => array( 'off', 'same-origin' ),
				'tier'        => 'security_headers_advanced',
				'tier_gate'   => array( __CLASS__, 'header_off_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Cross-Origin-Opener-Policy', 'reportedip-hive' ),
				'description' => __( 'Separate your pages from windows they opened, so a foreign page cannot reach back into yours.', 'reportedip-hive' ),
			),
			'reportedip_hive_corp'                         => array(
				'section'     => 'headers',
				'kind'        => 'enum',
				'allowed'     => array( 'off', 'same-origin' ),
				'tier'        => 'security_headers_advanced',
				'tier_gate'   => array( __CLASS__, 'header_off_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Cross-Origin-Resource-Policy', 'reportedip-hive' ),
				'description' => __( 'Who may embed your resources such as images and scripts.', 'reportedip-hive' ),
			),
			'reportedip_hive_coep'                         => array(
				'section'     => 'headers',
				'kind'        => 'enum',
				'allowed'     => array( 'off', 'require-corp' ),
				'tier'        => 'security_headers_advanced',
				'tier_gate'   => array( __CLASS__, 'header_off_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Cross-Origin-Embedder-Policy', 'reportedip-hive' ),
				'description' => __( 'Require every embedded resource to opt in. Needed for some browser features, and it breaks third-party embeds that have not opted in.', 'reportedip-hive' ),
			),

			'reportedip_hive_2fa_enabled_global'           => array(
				'simple'      => true,
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Two-factor authentication enabled', 'reportedip-hive' ),
				'description' => __( 'Master switch for the second factor. Off, nobody is asked for one, whatever the roles below say.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_allowed_methods'          => array(
				'choices'       => 'methods',
				'section'       => 'account_security',
				'kind'          => 'json_list',
				'json_filter'   => array( 'ReportedIP_Hive_Two_Factor', 'filter_valid_methods' ),
				'json_fallback' => array( 'totp', 'email' ),
				'remote'        => true,
				'label'         => __( 'Allowed 2FA methods', 'reportedip-hive' ),
				'description'   => __( 'The methods users may set up. Leave at least one that works without a phone, or a lost device locks the account out.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_email_subject'            => array(
				'section'     => 'account_security',
				'kind'        => 'text',
				'remote'      => true,
				'label'       => __( 'Subject of the e-mail code', 'reportedip-hive' ),
				'description' => __( 'Subject line of the mail that carries the sign-in code. Leave empty for the default; {site_name} is replaced with the site title.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_enforce_roles'            => array(
				'choices'     => 'roles',
				'simple'      => true,
				'section'     => 'account_security',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor', 'filter_valid_roles' ),
				'remote'      => true,
				'label'       => __( 'Roles required to use 2FA', 'reportedip-hive' ),
				'description' => __( 'Roles that must use a second factor. Everyone else may, and is asked to.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_enforce_grace_days'       => array(
				'section'     => 'account_security',
				'kind'        => 'int',
				'min'         => 0,
				'max'         => 60,
				'remote'      => true,
				'label'       => __( '2FA grace period (days)', 'reportedip-hive' ),
				'description' => __( 'How long a required user may keep signing in before setting the second factor up.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_max_skips'                => array(
				'section'     => 'account_security',
				'kind'        => 'int',
				'min'         => 0,
				'max'         => 20,
				'remote'      => true,
				'label'       => __( 'Maximum onboarding skips', 'reportedip-hive' ),
				'description' => __( 'How often a required user may postpone the setup during the grace period.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_enforce_action'           => array(
				'section'     => 'account_security',
				'kind'        => 'enum',
				'allowed'     => array( 'enroll', 'lockout' ),
				'remote'      => true,
				'label'       => __( 'Action when grace period is exhausted', 'reportedip-hive' ),
				'description' => __( 'What happens to a required user who never set the second factor up.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_trusted_devices'          => array(
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Trusted devices', 'reportedip-hive' ),
				'description' => __( 'Let users mark a device so they are not asked for the code on every sign-in.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_enforce_super_admins'     => array(
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Enforce 2FA for super admins', 'reportedip-hive' ),
				'description' => __( 'Also require the second factor from network super admins. They are the most valuable account on a multisite, and the easiest to forget.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_extended_remember'        => array(
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Extend the trusted-device window on "remember me"', 'reportedip-hive' ),
				'description' => __( 'Give the trusted-device cookie a longer life when the user ticked "remember me". More convenient, and a stolen laptop stays signed in longer.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_ip_allowlist'             => array(
				'section'     => 'account_security',
				'kind'        => 'textarea',
				'sanitize'    => array( 'ReportedIP_Hive_Proxy_Trust', 'sanitize_ranges' ),
				'remote'      => true,
				'label'       => __( 'IP addresses exempt from the second factor', 'reportedip-hive' ),
				'description' => __( 'Addresses or ranges that skip the second factor, one per line. This is a way past your own 2FA policy, so keep it to networks you control.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_branded_login'            => array(
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Brand the login challenge', 'reportedip-hive' ),
				'description' => __( 'Show your site name and logo on the challenge page instead of the plain WordPress one.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_notify_new_device'        => array(
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Mail the user when a new device signs in', 'reportedip-hive' ),
				'description' => __( 'Mail the user when their account is used from a device it has not seen before.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_reminder_enabled'         => array(
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Remind users without a second factor', 'reportedip-hive' ),
				'description' => __( 'Show a banner after sign-in to users who have not set up a second factor yet. Roles listed below are locked out once they ignore it too often.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_reminder_hard_threshold'  => array(
				'section'     => 'account_security',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 10,
				'remote'      => true,
				'label'       => __( 'Sign-ins before the reminder locks out', 'reportedip-hive' ),
				'description' => __( 'How many sign-ins without a second factor a user in one of the roles below gets before the reminder turns into a hard stop.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_reminder_hard_roles'      => array(
				'choices'     => 'roles',
				'section'     => 'account_security',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor', 'filter_valid_roles' ),
				'remote'      => true,
				'label'       => __( 'Roles the reminder locks out', 'reportedip-hive' ),
				'description' => __( 'Roles that cannot keep signing in without a second factor once the count above is reached. An empty list falls back to administrators, editors and shop managers.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_xmlrpc_app_password_only' => array(
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'XML-RPC accepts application passwords only', 'reportedip-hive' ),
				'description' => __( 'Refuse account passwords over XML-RPC and accept application passwords only, so XML-RPC stops being a way around the second factor.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_password_reset_block_email_only' => array(
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Block a password reset when e-mail is the only second factor', 'reportedip-hive' ),
				'description' => __( 'Refuse a password reset for users whose only second factor is e-mail. Otherwise a stolen mailbox is enough for both steps.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_frontend_enabled'         => array(
				'simple'       => true,
				'section'      => 'account_security',
				'kind'         => 'bool',
				'tier'         => 'frontend_2fa',
				'remote'       => true,
				'side_effects' => array( 'flush_rewrite', 'flush_2fa_frontend_memo' ),
				'label'        => __( 'Themed second factor on the storefront', 'reportedip-hive' ),
				'description'  => __( 'Ask for the second factor inside your theme on My Account and at checkout, instead of sending customers to wp-login.php.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_frontend_onboarding'      => array(
				'ui_lock'     => 'frontend_2fa',
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Send storefront users to themed onboarding', 'reportedip-hive' ),
				'description' => __( 'Also run the setup inside the theme, so a customer never leaves the storefront.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_frontend_slug'            => array(
				'ui_lock'      => 'frontend_2fa',
				'section'      => 'account_security',
				'kind'         => 'text',
				'sanitize'     => array( 'ReportedIP_Hive_Two_Factor_Frontend', 'sanitize_challenge_slug' ),
				'remote'       => true,
				'side_effects' => array( 'flush_rewrite', 'flush_2fa_frontend_memo' ),
				'label'        => __( 'Storefront challenge URL', 'reportedip-hive' ),
				'description'  => __( 'The path the themed challenge page lives at.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_frontend_setup_slug'      => array(
				'ui_lock'      => 'frontend_2fa',
				'section'      => 'account_security',
				'kind'         => 'text',
				'sanitize'     => array( 'ReportedIP_Hive_Two_Factor_Frontend', 'sanitize_setup_slug' ),
				'remote'       => true,
				'side_effects' => array( 'flush_rewrite', 'flush_2fa_frontend_memo' ),
				'label'        => __( 'Storefront setup URL', 'reportedip-hive' ),
				'description'  => __( 'The path the themed setup page lives at.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_frontend_customer_optional' => array(
				'ui_lock'     => 'frontend_2fa',
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Customers may opt out of the second factor', 'reportedip-hive' ),
				'description' => __( 'Let customers decide for themselves, while staff accounts stay bound by the roles above.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_trusted_device_days'      => array(
				'section'     => 'account_security',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 365,
				'remote'      => true,
				'label'       => __( 'Trusted device lifetime (days)', 'reportedip-hive' ),
				'description' => __( 'How long a trusted device stays trusted before the code is asked for again.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_new_country'       => array(
				'choices'     => 'roles',
				'section'     => 'twofa_policies',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up on a new country', 'reportedip-hive' ),
				'description' => __( 'Roles that are asked for the second factor again when the sign-in comes from a country the account has not used.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_new_ip'            => array(
				'choices'     => 'roles',
				'section'     => 'twofa_policies',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up on a new IP address', 'reportedip-hive' ),
				'description' => __( 'Roles that are asked again when the exact address is new to the account. Fires often on ordinary dynamic connections.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_new_subnet'        => array(
				'choices'     => 'roles',
				'section'     => 'twofa_policies',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up on a new network', 'reportedip-hive' ),
				'description' => __( 'Roles that are asked again when the address block is new, which ignores a normal dynamic-IP change.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_new_device'        => array(
				'choices'     => 'roles',
				'section'     => 'twofa_policies',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up on a new browser or device', 'reportedip-hive' ),
				'description' => __( 'Roles that are asked again when the browser has not signed this account in before.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_every_n_days'      => array(
				'choices'     => 'roles',
				'section'     => 'twofa_policies',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up every few days', 'reportedip-hive' ),
				'description' => __( 'Roles that are asked again once the last verification is older than the interval below.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_every_n_logins'    => array(
				'choices'     => 'roles',
				'section'     => 'twofa_policies',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up every few sign-ins', 'reportedip-hive' ),
				'description' => __( 'Roles that are asked again after the number of sign-ins below.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_sessions_above_n'  => array(
				'choices'     => 'roles',
				'section'     => 'twofa_policies',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up above a session count', 'reportedip-hive' ),
				'description' => __( 'Roles that are asked again while the account already has more open sessions than the number below.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_days'              => array(
				'section'     => 'twofa_policies',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 365,
				'remote'      => true,
				'label'       => __( 'Step-up interval (days)', 'reportedip-hive' ),
				'description' => __( 'The interval for the every-few-days trigger. The clock starts at the first sign-in after you switch it on, so nobody is challenged all at once.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_logins'            => array(
				'section'     => 'twofa_policies',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100,
				'remote'      => true,
				'label'       => __( 'Step-up interval (sign-ins)', 'reportedip-hive' ),
				'description' => __( 'The number of sign-ins for the every-few-sign-ins trigger.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_sessions'          => array(
				'section'     => 'twofa_policies',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 20,
				'remote'      => true,
				'label'       => __( 'Open-session threshold', 'reportedip-hive' ),
				'description' => __( 'How many open sessions an account may have before the trigger applies.', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_require_on_password_reset' => array(
				'section'     => 'account_security',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Require 2FA on password reset', 'reportedip-hive' ),
				'description' => __( 'Ask for the second factor during a password reset, so a hijacked mailbox is not enough on its own.', 'reportedip-hive' ),
			),
			'reportedip_hive_password_policy_enabled'      => array(
				'section'     => 'account_password',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Password policy', 'reportedip-hive' ),
				'description' => __( 'Check new passwords against the rules below before accepting them.', 'reportedip-hive' ),
			),
			'reportedip_hive_password_min_length'          => array(
				'section'     => 'account_password',
				'kind'        => 'int',
				'min'         => 8,
				'max'         => 64,
				'remote'      => true,
				'label'       => __( 'Minimum password length', 'reportedip-hive' ),
				'description' => __( 'The shortest password that is accepted. Length helps more than any other single rule.', 'reportedip-hive' ),
			),
			'reportedip_hive_password_min_classes'         => array(
				'section'     => 'account_password',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 4,
				'remote'      => true,
				'label'       => __( 'Required character classes', 'reportedip-hive' ),
				'description' => __( 'How many of upper case, lower case, digits and symbols a password must mix.', 'reportedip-hive' ),
			),
			'reportedip_hive_password_policy_all_users'    => array(
				'section'     => 'account_password',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Apply the password policy to every role', 'reportedip-hive' ),
				'description' => __( 'Apply the rules to every role rather than to the ones that can change the site.', 'reportedip-hive' ),
			),
			'reportedip_hive_password_check_hibp'          => array(
				'section'     => 'account_password',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Check passwords against known breaches', 'reportedip-hive' ),
				'description' => __( 'Reject passwords that appear in known breach lists. Only the first five characters of a hash leave the site, never the password.', 'reportedip-hive' ),
			),

			'reportedip_hive_log_level'                    => array(
				'section'     => 'privacy_logs',
				'kind'        => 'enum',
				'allowed'     => array( 'debug', 'info', 'warning', 'error', 'critical' ),
				'remote'      => true,
				'label'       => __( 'Log level', 'reportedip-hive' ),
				'description' => __( 'How much detail lands in the security log.', 'reportedip-hive' ),
			),
			'reportedip_hive_minimal_logging'              => array(
				'simple'      => true,
				'section'     => 'privacy_logs',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Minimal logging', 'reportedip-hive' ),
				'description' => __( 'Record only what is needed to make a decision, and leave out everything that would identify a person.', 'reportedip-hive' ),
			),
			'reportedip_hive_log_user_agents'              => array(
				'section'     => 'privacy_logs',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Log user agents', 'reportedip-hive' ),
				'description' => __( 'Record the browser identification with each event. Useful for telling a bot from a customer, and it is personal data.', 'reportedip-hive' ),
			),
			'reportedip_hive_data_retention_days'          => array(
				'simple'      => true,
				'section'     => 'privacy_logs',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 365,
				'remote'      => true,
				'label'       => __( 'Data retention (days)', 'reportedip-hive' ),
				'description' => __( 'How long security events are kept before they are deleted.', 'reportedip-hive' ),
			),
			'reportedip_hive_auto_anonymize_days'          => array(
				'section'     => 'privacy_logs',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 365,
				'remote'      => true,
				'label'       => __( 'Auto-anonymize after (days)', 'reportedip-hive' ),
				'description' => __( 'How long before addresses in old events are shortened. Keeps the statistics while dropping the identifying part.', 'reportedip-hive' ),
			),
			'reportedip_hive_audit_enabled'                => array(
				'section'     => 'privacy_logs',
				'kind'        => 'bool',
				'tier'        => 'audit_log',
				'remote'      => true,
				'label'       => __( 'Audit trail', 'reportedip-hive' ),
				'description' => __( 'Keep a separate, append-only record of what happened to accounts: sign-ins, resets, role changes and who made them.', 'reportedip-hive' ),
			),
			'reportedip_hive_audit_retention_days'         => array(
				'section'     => 'privacy_logs',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 365,
				'remote'      => true,
				'label'       => __( 'Audit retention (days)', 'reportedip-hive' ),
				'description' => __( 'How long audit entries are kept. Compliance requirements usually set this, not convenience.', 'reportedip-hive' ),
			),
			'reportedip_hive_audit_anonymize_ip'           => array(
				'section'     => 'privacy_logs',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Anonymize IPs in the audit trail', 'reportedip-hive' ),
				'description' => __( 'Store only the network part of the address in the audit trail, so the record survives a data-protection review.', 'reportedip-hive' ),
			),
			'reportedip_hive_audit_new_ip_alert'           => array(
				'section'     => 'privacy_logs',
				'kind'        => 'bool',
				'tier'        => 'audit_log',
				'remote'      => true,
				'label'       => __( 'Mail an alert on a sign-in from a new address', 'reportedip-hive' ),
				'description' => __( 'Mail the notification recipients when an account signs in from an address it has never used. Rate-limited per account so a dynamic connection does not flood the inbox.', 'reportedip-hive' ),
			),
			'reportedip_hive_detailed_logging'             => array(
				'section'     => 'privacy_logs',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Record request details with each event', 'reportedip-hive' ),
				'description' => __( 'Record the request context with each event. Helps when reconstructing an incident, and makes the log bigger.', 'reportedip-hive' ),
			),
			'reportedip_hive_log_referer_domains'          => array(
				'section'     => 'privacy_logs',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Record the referring domain', 'reportedip-hive' ),
				'description' => __( 'Record which site a visitor came from.', 'reportedip-hive' ),
			),
			'reportedip_hive_enable_caching'               => array(
				'section'     => 'performance',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Cache community lookups', 'reportedip-hive' ),
				'description' => __( 'Remember community answers instead of asking again for the same address. This is what keeps the check off your response time.', 'reportedip-hive' ),
			),
			'reportedip_hive_cache_duration'               => array(
				'section'     => 'performance',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 168,
				'remote'      => true,
				'label'       => __( 'Cache lifetime (hours)', 'reportedip-hive' ),
				'description' => __( 'How long a community answer is reused.', 'reportedip-hive' ),
			),
			'reportedip_hive_negative_cache_duration'      => array(
				'section'     => 'performance',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 168,
				'remote'      => true,
				'label'       => __( 'Clean-result cache lifetime (hours)', 'reportedip-hive' ),
				'description' => __( 'How long a clean result is reused. Shorter than the above, because an address can turn bad quickly.', 'reportedip-hive' ),
			),
			'reportedip_hive_max_api_calls_per_hour'       => array(
				'section'     => 'performance',
				'kind'        => 'int',
				'min'         => 0,
				'max'         => 100000,
				'remote'      => true,
				'label'       => __( 'Community lookups per hour (0 = no local limit)', 'reportedip-hive' ),
				'description' => __( 'A local ceiling on community lookups per hour. Zero means only your plan quota applies.', 'reportedip-hive' ),
			),
			'reportedip_hive_report_cooldown_hours'        => array(
				'section'     => 'performance',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 720,
				'remote'      => true,
				'label'       => __( 'Report cooldown per address (hours)', 'reportedip-hive' ),
				'description' => __( 'How long to wait before reporting the same address again, so one persistent attacker does not eat the daily report budget.', 'reportedip-hive' ),
			),
			'reportedip_hive_queue_max_age_days'           => array(
				'section'     => 'performance',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 90,
				'remote'      => true,
				'label'       => __( 'Discard queued reports after (days)', 'reportedip-hive' ),
				'description' => __( 'How long a report may sit in the queue before it is dropped as stale.', 'reportedip-hive' ),
			),
			'reportedip_hive_queue_warning_threshold'      => array(
				'section'     => 'performance',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100000,
				'remote'      => true,
				'label'       => __( 'Queue warning threshold', 'reportedip-hive' ),
				'description' => __( 'The queue length at which the status page starts warning.', 'reportedip-hive' ),
			),
			'reportedip_hive_queue_critical_threshold'     => array(
				'section'     => 'performance',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 100000,
				'remote'      => true,
				'label'       => __( 'Queue critical threshold', 'reportedip-hive' ),
				'description' => __( 'The queue length at which the status page calls it critical.', 'reportedip-hive' ),
			),
			'reportedip_hive_processing_timeout_minutes'   => array(
				'section'     => 'performance',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'Recover stuck queue rows after (minutes)', 'reportedip-hive' ),
				'description' => __( 'How long a report may stay in processing before it is assumed the worker crashed and the row is picked up again.', 'reportedip-hive' ),
			),
			'reportedip_hive_auto_footer_enabled'          => array(
				'simple'      => true,
				'section'     => 'performance',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Show the protection badge in the site footer', 'reportedip-hive' ),
				'description' => __( 'Show a small protection badge in your site footer.', 'reportedip-hive' ),
			),
			'reportedip_hive_auto_footer_variant'          => array(
				'simple'      => true,
				'section'     => 'performance',
				'kind'        => 'enum',
				'allowed'     => array( 'badge', 'shield' ),
				'remote'      => true,
				'label'       => __( 'Footer badge style', 'reportedip-hive' ),
				'description' => __( 'Which badge is shown.', 'reportedip-hive' ),
			),
			'reportedip_hive_auto_footer_align'            => array(
				'section'     => 'performance',
				'kind'        => 'enum',
				'allowed'     => array( 'left', 'center', 'right', 'below' ),
				'remote'      => true,
				'label'       => __( 'Footer badge placement', 'reportedip-hive' ),
				'description' => __( 'Where the badge sits in the footer.', 'reportedip-hive' ),
			),
			'reportedip_hive_notify_sync_to_api'           => array(
				'section'     => 'notifications',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Send notification preferences to the community server', 'reportedip-hive' ),
				'description' => __( 'Let the community server know your notification preferences, so it can reach you about your account.', 'reportedip-hive' ),
			),
			'reportedip_hive_notify_event_cap_minutes'     => array(
				'section'     => 'notifications',
				'kind'        => 'int',
				'min'         => 1,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'Per-event notification cap (minutes)', 'reportedip-hive' ),
				'description' => __( 'How long to wait before mailing about the same kind of event again.', 'reportedip-hive' ),
			),

			'reportedip_hive_notify_admin'                 => array(
				'simple'      => true,
				'section'     => 'notifications',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Admin notifications', 'reportedip-hive' ),
				'description' => __( 'Mail the recipients below when something needs a person to look at it.', 'reportedip-hive' ),
			),
			'reportedip_hive_notify_recipients'            => array(
				'simple'      => true,
				'section'     => 'notifications',
				'kind'        => 'email_list',
				'remote'      => true,
				'label'       => __( 'Notification recipients', 'reportedip-hive' ),
				'description' => __( 'Who receives those mails. Several addresses can be separated by commas.', 'reportedip-hive' ),
			),
			'reportedip_hive_notify_from_name'             => array(
				'section'     => 'notifications',
				'kind'        => 'text',
				'remote'      => true,
				'label'       => __( 'Sender name', 'reportedip-hive' ),
				'description' => __( 'The sender name on mails this plugin sends.', 'reportedip-hive' ),
			),
			'reportedip_hive_notify_from_email'            => array(
				'section'     => 'notifications',
				'kind'        => 'email',
				'remote'      => true,
				'label'       => __( 'Sender address', 'reportedip-hive' ),
				'description' => __( 'The sender address. Use one at your own domain, otherwise the mails land in spam.', 'reportedip-hive' ),
			),
			'reportedip_hive_notification_cooldown_minutes' => array(
				'section'     => 'notifications',
				'kind'        => 'int',
				'min'         => 0,
				'max'         => 1440,
				'remote'      => true,
				'label'       => __( 'Notification cooldown (minutes)', 'reportedip-hive' ),
				'description' => __( 'How long the same address and event type stays quiet after a mail went out.', 'reportedip-hive' ),
			),
			'reportedip_hive_promo_enabled'                => array(
				'section'     => 'notifications',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Show upgrade hints in the admin', 'reportedip-hive' ),
				'description' => __( 'Off hides every plan promotion in wp-admin: dashboard cards, inline hints and the WooCommerce banner. Security notices are not affected.', 'reportedip-hive' ),
			),
			'reportedip_hive_quota_notif_enabled'          => array(
				'section'     => 'notifications',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Mail when the relay quota reaches 80 % or 100 %', 'reportedip-hive' ),
				'description' => __( 'One mail per channel and stage per month, sent to the alert recipients.', 'reportedip-hive' ),
			),
			'reportedip_hive_tier_change_mail_enabled'     => array(
				'section'     => 'notifications',
				'kind'        => 'bool',
				'remote'      => true,
				'label'       => __( 'Mail when the plan changes', 'reportedip-hive' ),
				'description' => __( 'One factual mail per upgrade or downgrade with what becomes available or pauses.', 'reportedip-hive' ),
			),
		);
	}

	/**
	 * Spec entries exposed to remote transports.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public static function remote_spec() {
		return array_filter(
			self::spec(),
			static function ( array $entry ) {
				return ! empty( $entry['remote'] );
			}
		);
	}

	/**
	 * Whether the paranoia tier gate applies for a given target value.
	 * level 1 is free, levels 2 and 3 require the Professional ruleset.
	 *
	 * @param mixed $value Sanitized target value.
	 * @return bool
	 */
	public static function paranoia_needs_tier( $value ) {
		return (int) $value >= 2;
	}

	/**
	 * Whether a policy role list activates the adaptive-2FA tier gate. An
	 * empty list is inert and stays writable on every plan, so a site that
	 * lost the plan can still clear its matrix.
	 *
	 * @param mixed $value Sanitized target value (JSON string or array).
	 * @return bool
	 */
	public static function policy_list_needs_tier( $value ) {
		$list = is_array( $value ) ? $value : json_decode( (string) $value, true );

		return is_array( $list ) && ! empty( $list );
	}

	/**
	 * Whether a header setting whose "inactive" state is the literal string
	 * `off` activates the advanced-hardening gate.
	 *
	 * Switching such a header back off must stay possible after a plan ends,
	 * so only a value other than `off` is gated.
	 *
	 * @param mixed $value Sanitized target value.
	 * @return bool
	 * @since  2.1.51
	 */
	public static function header_off_needs_tier( $value ) {
		return 'off' !== (string) $value;
	}

	/**
	 * Whether a free-text header policy activates the advanced-hardening gate.
	 *
	 * An empty policy emits nothing, so clearing one is always allowed.
	 *
	 * @param mixed $value Sanitized target value.
	 * @return bool
	 * @since  2.1.51
	 */
	public static function header_text_needs_tier( $value ) {
		return '' !== trim( (string) $value );
	}

	/**
	 * Sanitize one value against its spec. Applies the tier gate, then the
	 * spec's sanitize override or the generic kind sanitizer.
	 *
	 * @param string $key   Option key.
	 * @param mixed  $value Raw value.
	 * @return mixed|WP_Error Sanitized value or a WP_Error with code
	 *                        `unknown_key`, `tier_locked` or `invalid`.
	 */
	public static function sanitize( $key, $value ) {
		$spec = self::spec();
		if ( ! isset( $spec[ $key ] ) ) {
			return new WP_Error( 'unknown_key', __( 'This option is not part of the settings registry.', 'reportedip-hive' ) );
		}
		$entry = $spec[ $key ];

		if ( isset( $entry['sanitize'] ) && is_callable( $entry['sanitize'] ) ) {
			$result = call_user_func( $entry['sanitize'], $value );
			if ( is_wp_error( $result ) ) {
				return new WP_Error( 'invalid', $result->get_error_message() );
			}
		} else {
			$result = self::sanitize_kind( (string) $entry['kind'], $value, $entry );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}

		$gate_error = self::check_tier_gate( $entry, $result );
		if ( is_wp_error( $gate_error ) ) {
			return $gate_error;
		}

		return $result;
	}

	/**
	 * Generic kind sanitizer, reusable by the wizard schema.
	 *
	 * @param string               $kind  Kind token.
	 * @param mixed                $value Raw value.
	 * @param array<string, mixed> $spec  Spec entry providing min/max/allowed.
	 * @return mixed|WP_Error
	 */
	public static function sanitize_kind( $kind, $value, array $spec = array() ) {
		switch ( $kind ) {
			case 'bool':
				return rest_sanitize_boolean( $value ) ? 1 : 0;

			case 'int':
				$min = isset( $spec['min'] ) ? (int) $spec['min'] : 0;
				$max = isset( $spec['max'] ) ? (int) $spec['max'] : PHP_INT_MAX;
				return max( $min, min( $max, absint( $value ) ) );

			case 'enum':
				$candidate = sanitize_key( (string) ( is_scalar( $value ) ? $value : '' ) );
				$allowed   = isset( $spec['allowed'] ) ? (array) $spec['allowed'] : array();
				if ( ! in_array( $candidate, $allowed, true ) ) {
					return new WP_Error(
						'invalid',
						sprintf(
							/* translators: %s: comma-separated list of allowed values */
							__( 'Value must be one of: %s', 'reportedip-hive' ),
							implode( ', ', $allowed )
						)
					);
				}
				return $candidate;

			case 'text':
				return sanitize_text_field( (string) ( is_scalar( $value ) ? $value : '' ) );

			case 'slug':
				return sanitize_title( (string) ( is_scalar( $value ) ? $value : '' ) );

			case 'textarea':
				return sanitize_textarea_field( (string) ( is_scalar( $value ) ? $value : '' ) );

			case 'email':
				$clean = sanitize_email( (string) ( is_scalar( $value ) ? $value : '' ) );
				return ( '' !== $clean && is_email( $clean ) ) ? $clean : '';

			case 'email_list':
				return self::sanitize_email_list( (string) ( is_scalar( $value ) ? $value : '' ) );

			case 'url':
				$raw = (string) ( is_scalar( $value ) ? $value : '' );
				return '' === trim( $raw ) ? '' : esc_url_raw( trim( $raw ) );

			case 'csv_int_list':
				return self::sanitize_csv_int_list( $value, $spec );

			case 'json_list':
				return self::sanitize_json_list( $value, $spec );

			default:
				return new WP_Error( 'invalid', __( 'Unknown value kind.', 'reportedip-hive' ) );
		}
	}

	/**
	 * Batch cross-field validation. Rules see the merged view of incoming
	 * values over current values so a rule holds regardless of which keys a
	 * batch carries.
	 *
	 * @param array<string, mixed> $values  Sanitized incoming values.
	 * @param array<string, mixed> $current Current stored values.
	 * @return array<string, WP_Error> Per-key errors (empty when valid).
	 */
	public static function validate_batch( array $values, array $current ) {
		$errors = array();
		$merged = array_merge( $current, $values );

		$hide_enabled = ! empty( $merged['reportedip_hive_hide_login_enabled'] );
		$hide_slug    = isset( $merged['reportedip_hive_hide_login_slug'] ) ? (string) $merged['reportedip_hive_hide_login_slug'] : '';
		if ( $hide_enabled && '' === $hide_slug && array_key_exists( 'reportedip_hive_hide_login_enabled', $values ) ) {
			$errors['reportedip_hive_hide_login_enabled'] = new WP_Error(
				'invalid',
				__( 'Hide Login cannot be enabled without a login slug, set a slug first.', 'reportedip-hive' )
			);
		}

		return $errors;
	}

	/**
	 * Current stored values for registry keys, falling back to the canonical
	 * defaults for unset options.
	 *
	 * @param string[]|null $keys Keys to read; null = all remote keys.
	 * @return array<string, mixed>
	 */
	public static function current_values( $keys = null ) {
		if ( null === $keys ) {
			$keys = array_keys( self::remote_spec() );
		}
		$defaults = ReportedIP_Hive_Defaults::all_option_defaults();
		$values   = array();
		foreach ( $keys as $key ) {
			$default        = array_key_exists( $key, $defaults ) ? $defaults[ $key ] : '';
			$values[ $key ] = ReportedIP_Hive_Option_Routing::get( $key, $default );
		}
		return $values;
	}

	/**
	 * Normalize a stored value for comparison and hashing so representation
	 * differences ('1' vs 1 vs true) never register as change or drift.
	 *
	 * @param string $key   Option key.
	 * @param mixed  $value Stored value.
	 * @return mixed
	 */
	public static function normalize_value( $key, $value ) {
		$spec = self::spec();
		$kind = isset( $spec[ $key ] ) ? (string) $spec[ $key ]['kind'] : 'text';

		switch ( $kind ) {
			case 'bool':
				return rest_sanitize_boolean( $value );
			case 'int':
				return (int) $value;
			default:
				return (string) ( is_scalar( $value ) ? $value : wp_json_encode( $value ) );
		}
	}

	/**
	 * Stable fingerprint over all remote-managed values. Computed exclusively
	 * on the child, dashboards compare reported hashes, never recompute.
	 *
	 * @return string `sha256:<hex>`.
	 */
	public static function settings_hash() {
		$values     = self::current_values();
		$normalized = array();
		foreach ( $values as $key => $value ) {
			$normalized[ $key ] = self::normalize_value( $key, $value );
		}
		ksort( $normalized );
		return 'sha256:' . hash(
			'sha256',
			(string) wp_json_encode(
				array(
					's' => self::SCHEMA_VERSION,
					'v' => $normalized,
				)
			)
		);
	}

	/**
	 * Values envelope for management dashboards, the canonical response
	 * body of the `settings_get` operation, shared by every transport so
	 * MainWP and the cloud API stay provably identical.
	 *
	 * @return array{schema_version:int, values:array<string, mixed>, hash:string, is_main_site:bool, network_wide:bool}
	 * @since  2.1.48
	 */
	public static function values_envelope() {
		return array(
			'schema_version' => self::SCHEMA_VERSION,
			'values'         => self::current_values(),
			'hash'           => self::settings_hash(),
			'is_main_site'   => is_main_site(),
			'network_wide'   => is_multisite(),
		);
	}

	/**
	 * Versioned schema envelope for management dashboards. Labels are
	 * translated into the site locale at export time.
	 *
	 * @return array<string, mixed>
	 */
	public static function export_schema() {
		$defaults = ReportedIP_Hive_Defaults::all_option_defaults();
		$sections = array();
		$fields   = array();

		foreach ( self::sections() as $slug => $section ) {
			$sections[ $slug ] = array(
				'id'          => $slug,
				'label'       => $section['label'],
				'description' => $section['description'],
				'keys'        => array(),
			);
		}

		foreach ( self::remote_spec() as $key => $entry ) {
			$section = (string) $entry['section'];
			if ( isset( $sections[ $section ] ) ) {
				$sections[ $section ]['keys'][] = $key;
			}

			$field = array(
				'kind'    => (string) $entry['kind'],
				'label'   => isset( $entry['label'] ) ? (string) $entry['label'] : $key,
				'default' => array_key_exists( $key, $defaults ) ? $defaults[ $key ] : '',
				'tier'    => isset( $entry['tier'] ) ? (string) $entry['tier'] : null,
			);
			if ( isset( $entry['description'] ) && '' !== (string) $entry['description'] ) {
				$field['description'] = (string) $entry['description'];
			}
			if ( isset( $entry['min'] ) ) {
				$field['min'] = (int) $entry['min'];
			}
			if ( isset( $entry['max'] ) ) {
				$field['max'] = (int) $entry['max'];
			}
			if ( isset( $entry['allowed'] ) ) {
				$field['allowed'] = array_values( (array) $entry['allowed'] );
			}
			if ( isset( $entry['ui_lock'] ) ) {
				$field['ui_lock'] = (string) $entry['ui_lock'];
			}
			$fields[ $key ] = $field;
		}

		return array(
			'schema_version' => self::SCHEMA_VERSION,
			'plugin_version' => defined( 'REPORTEDIP_HIVE_VERSION' ) ? REPORTEDIP_HIVE_VERSION : '',
			'sections'       => array_values( $sections ),
			'fields'         => $fields,
		);
	}

	/**
	 * Factory for a Settings-API sanitize callback backed by the registry.
	 * On rejection it surfaces a settings error (when available) and returns
	 * the previously stored value so nothing invalid is ever persisted.
	 *
	 * @param string $key Option key.
	 * @return callable
	 */
	public static function settings_api_callback( $key ) {
		return static function ( $value ) use ( $key ) {
			$result = self::sanitize( $key, $value );

			if ( ! is_wp_error( $result ) ) {
				$batch_errors = self::validate_batch( array( $key => $result ), self::current_values( array_keys( self::spec() ) ) );
				if ( isset( $batch_errors[ $key ] ) ) {
					$result = $batch_errors[ $key ];
				}
			}

			if ( is_wp_error( $result ) ) {
				if ( function_exists( 'add_settings_error' ) ) {
					add_settings_error( $key, $key . '_rejected', $result->get_error_message() );
				}
				$current = self::current_values( array( $key ) );
				return $current[ $key ];
			}

			return $result;
		};
	}

	/**
	 * Apply the spec's tier gate to a sanitized target value.
	 *
	 * @param array<string, mixed> $entry Spec entry.
	 * @param mixed                $value Sanitized value.
	 * @return true|WP_Error True when allowed, WP_Error `tier_locked` otherwise.
	 */
	private static function check_tier_gate( array $entry, $value ) {
		if ( empty( $entry['tier'] ) || ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return true;
		}

		$applies = isset( $entry['tier_gate'] ) && is_callable( $entry['tier_gate'] )
			? (bool) call_user_func( $entry['tier_gate'], $value )
			: (bool) $value;
		if ( ! $applies ) {
			return true;
		}

		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( (string) $entry['tier'] );
		if ( ! empty( $status['available'] ) ) {
			return true;
		}

		$min_tier = isset( $status['min_tier'] ) ? (string) $status['min_tier'] : '';
		return new WP_Error(
			'tier_locked',
			'' !== $min_tier
				? sprintf(
					/* translators: %s: minimum plan name required for the feature */
					__( 'This setting requires the %s plan.', 'reportedip-hive' ),
					$min_tier
				)
				: __( 'This setting requires a higher plan.', 'reportedip-hive' )
		);
	}

	/**
	 * Normalise a free-form recipient list into a canonical, deduplicated
	 * `a@x, b@y` string. Mirrors the historic Settings-API behaviour.
	 *
	 * @param string $value Raw list (comma/semicolon/whitespace separated).
	 * @return string
	 */
	private static function sanitize_email_list( $value ) {
		$candidates = array_filter( array_map( 'trim', (array) preg_split( '/[\s,;]+/', $value ) ) );
		$valid      = array();
		foreach ( $candidates as $candidate ) {
			$clean = sanitize_email( $candidate );
			if ( '' !== $clean && is_email( $clean ) ) {
				$valid[] = $clean;
			}
		}
		return implode( ', ', array_values( array_unique( $valid ) ) );
	}

	/**
	 * Sanitize a comma-separated integer list (the escalation ladder). Falls
	 * back to the canonical default ladder when nothing usable remains.
	 *
	 * @param mixed                $value Raw value.
	 * @param array<string, mixed> $spec  Spec entry providing min/max per item.
	 * @return string
	 */
	private static function sanitize_csv_int_list( $value, array $spec ) {
		$min   = isset( $spec['min'] ) ? (int) $spec['min'] : 1;
		$max   = isset( $spec['max'] ) ? (int) $spec['max'] : PHP_INT_MAX;
		$raw   = (string) ( is_scalar( $value ) ? $value : '' );
		$parts = array_filter(
			array_map( 'trim', explode( ',', $raw ) ),
			static function ( $part ) {
				return '' !== $part;
			}
		);

		$list = array();
		foreach ( $parts as $part ) {
			$list[] = max( $min, min( $max, (int) $part ) );
		}

		if ( empty( $list ) && class_exists( 'ReportedIP_Hive_Block_Escalation' ) ) {
			$list = ReportedIP_Hive_Block_Escalation::DEFAULT_LADDER_MINUTES;
		}

		return implode( ',', $list );
	}

	/**
	 * Sanitize a JSON string-list option. Accepts an array or a JSON-encoded
	 * string, filters entries through the spec's `json_filter` and re-encodes
	 * canonically so stored representations (and hashes) stay stable.
	 *
	 * @param mixed                $value Raw value.
	 * @param array<string, mixed> $spec  Spec entry providing json_filter/json_fallback.
	 * @return string|WP_Error Canonical JSON array string.
	 */
	private static function sanitize_json_list( $value, array $spec ) {
		if ( is_array( $value ) ) {
			$items = $value;
		} else {
			$decoded = json_decode( (string) ( is_scalar( $value ) ? $value : '' ), true );
			if ( ! is_array( $decoded ) ) {
				return new WP_Error( 'invalid', __( 'Value must be a JSON array of strings.', 'reportedip-hive' ) );
			}
			$items = $decoded;
		}

		$items = array_map(
			static function ( $item ) {
				return sanitize_key( (string) ( is_scalar( $item ) ? $item : '' ) );
			},
			$items
		);
		$items = array_values( array_unique( array_filter( $items ) ) );

		if ( isset( $spec['json_filter'] ) && is_callable( $spec['json_filter'] ) ) {
			$items = array_values( (array) call_user_func( $spec['json_filter'], $items ) );
		}

		if ( empty( $items ) && ! empty( $spec['json_fallback'] ) ) {
			$items = array_values( (array) $spec['json_fallback'] );
		}

		return (string) wp_json_encode( $items );
	}
}
