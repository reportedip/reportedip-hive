<?php
/**
 * Canonical settings registry — the single declarative source for option
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
 * json_fallback?:string[]}`. Defaults are deliberately NOT duplicated here —
 * they live in {@see ReportedIP_Hive_Defaults::SAFE_OPTIONS} and are read at
 * runtime; a unit test enforces that every registry key has a default.
 *
 * The class is loaded unconditionally (never behind `is_admin()`), so its
 * sanitizers exist in every request context — wp-admin, MainWP child calls,
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
				'description' => __( 'Attack sensors and their trigger thresholds.', 'reportedip-hive' ),
			),
			'blocking'         => array(
				'label'       => __( 'Blocking & Escalation', 'reportedip-hive' ),
				'description' => __( 'Automatic blocking, durations and the escalation ladder.', 'reportedip-hive' ),
			),
			'waf'              => array(
				'label'       => __( 'Firewall & Bots', 'reportedip-hive' ),
				'description' => __( 'Web application firewall, bot verification and honeypots.', 'reportedip-hive' ),
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
				'label'       => __( 'Account Security', 'reportedip-hive' ),
				'description' => __( 'Two-factor authentication and password policy.', 'reportedip-hive' ),
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
				'section'  => 'detection',
				'kind'     => 'enum',
				'allowed'  => array( '', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP' ),
				'sanitize' => array( 'ReportedIP_Hive_Proxy_Trust', 'sanitize_header' ),
				'remote'   => true,
				'label'    => __( 'Client IP header', 'reportedip-hive' ),
			),
			'reportedip_hive_trusted_proxy_ranges'         => array(
				'section'  => 'detection',
				'kind'     => 'textarea',
				'sanitize' => array( 'ReportedIP_Hive_Proxy_Trust', 'sanitize_ranges' ),
				'remote'   => true,
				'label'    => __( 'Trusted proxy ranges', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_failed_logins'        => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Monitor failed logins', 'reportedip-hive' ),
			),
			'reportedip_hive_failed_login_threshold'       => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'Failed login threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_failed_login_timeframe'       => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'Failed login window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_comments'             => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Monitor comment spam', 'reportedip-hive' ),
			),
			'reportedip_hive_comment_spam_threshold'       => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 50,
				'remote'  => true,
				'label'   => __( 'Comment spam threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_comment_spam_timeframe'       => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'Comment spam window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_xmlrpc'               => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Monitor XML-RPC abuse', 'reportedip-hive' ),
			),
			'reportedip_hive_xmlrpc_threshold'             => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'XML-RPC threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_xmlrpc_timeframe'             => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'XML-RPC window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_disable_xmlrpc_multicall'     => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Disable XML-RPC multicall', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_rest_api'             => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Monitor REST API bursts', 'reportedip-hive' ),
			),
			'reportedip_hive_block_user_enumeration'       => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Block user enumeration', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_404_scans'            => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Monitor 404 scans', 'reportedip-hive' ),
			),
			'reportedip_hive_scan_404_threshold'           => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( '404 scan threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_scan_404_timeframe'           => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( '404 scan window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_app_passwords'        => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Monitor application passwords', 'reportedip-hive' ),
			),
			'reportedip_hive_app_password_threshold'       => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'Application password threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_app_password_timeframe'       => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'Application password window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_app_password_require_2fa'     => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Application passwords require an account with 2FA', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_threshold'               => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 10000,
				'remote'  => true,
				'label'   => __( 'REST burst threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_timeframe'               => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'REST burst window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_sensitive_threshold'     => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 10000,
				'remote'  => true,
				'label'   => __( 'Sensitive REST route threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_sensitive_timeframe'     => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'Sensitive REST route window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_user_enum_threshold'          => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'User enumeration threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_user_enum_timeframe'          => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'User enumeration window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_allow_author_archives'        => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Keep author archives reachable', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_geo_anomaly'          => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Monitor country and network changes on login', 'reportedip-hive' ),
			),
			'reportedip_hive_geo_window_days'              => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 365,
				'remote'  => true,
				'label'   => __( 'Login history window (days)', 'reportedip-hive' ),
			),
			'reportedip_hive_geo_revoke_trusted_devices'   => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Drop trusted devices on a country change', 'reportedip-hive' ),
			),
			'reportedip_hive_geo_report_to_api'            => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Share country anomalies with the community', 'reportedip-hive' ),
			),
			'reportedip_hive_password_spray_threshold'     => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'Password spray threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_password_spray_timeframe'     => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'Password spray window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_woocommerce'          => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Monitor WooCommerce login forms', 'reportedip-hive' ),
			),
			'reportedip_hive_bot_allowlist_enabled'        => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Exempt verified crawlers from auto-blocking', 'reportedip-hive' ),
			),

			'reportedip_hive_hardening_realtime_detection' => array(
				'section' => 'detection',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Hardening realtime detection', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_duration_minutes'   => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 5,
				'max'     => 360,
				'remote'  => true,
				'label'   => __( 'Hardening duration (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_login_threshold'    => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 10,
				'remote'  => true,
				'label'   => __( 'Failed-login threshold during hardening', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_login_timeframe'    => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 60,
				'remote'  => true,
				'label'   => __( 'Failed-login window during hardening (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_block_threshold'    => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'Reputation block threshold during hardening (%)', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_detect_window_minutes' => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 120,
				'remote'  => true,
				'label'   => __( 'Distributed-attack detection window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_detect_min_ips'     => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 2,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'Minimum distinct IPs for a distributed attack', 'reportedip-hive' ),
			),
			'reportedip_hive_hardening_detect_min_attempts' => array(
				'section' => 'detection',
				'kind'    => 'int',
				'min'     => 3,
				'max'     => 1000,
				'remote'  => true,
				'label'   => __( 'Minimum total attempts for a distributed attack', 'reportedip-hive' ),
			),

			'reportedip_hive_auto_block'                   => array(
				'section' => 'blocking',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Automatic blocking', 'reportedip-hive' ),
			),
			'reportedip_hive_block_duration'               => array(
				'section' => 'blocking',
				'kind'    => 'int',
				'min'     => 0,
				'max'     => 8760,
				'remote'  => true,
				'label'   => __( 'Block duration (hours)', 'reportedip-hive' ),
			),
			'reportedip_hive_block_threshold'              => array(
				'section' => 'blocking',
				'kind'    => 'int',
				'min'     => ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'Community block threshold (%)', 'reportedip-hive' ),
			),
			'reportedip_hive_block_escalation_enabled'     => array(
				'section' => 'blocking',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Escalation ladder', 'reportedip-hive' ),
			),
			'reportedip_hive_block_ladder_minutes'         => array(
				'section' => 'blocking',
				'kind'    => 'csv_int_list',
				'min'     => 1,
				'max'     => 525600,
				'remote'  => true,
				'label'   => __( 'Escalation ladder steps (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_block_ladder_reset_days'      => array(
				'section' => 'blocking',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 365,
				'remote'  => true,
				'label'   => __( 'Ladder reset window (days)', 'reportedip-hive' ),
			),
			'reportedip_hive_report_only_mode'             => array(
				'section' => 'blocking',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Report-only mode', 'reportedip-hive' ),
			),
			'reportedip_hive_block_tor'                    => array(
				'section' => 'blocking',
				'kind'    => 'bool',
				'tier'    => 'tor_blocking',
				'remote'  => true,
				'label'   => __( 'Block Tor exit nodes', 'reportedip-hive' ),
			),
			'reportedip_hive_blocked_page_contact_url'     => array(
				'section' => 'blocking',
				'kind'    => 'url',
				'remote'  => true,
				'label'   => __( 'Contact URL on the block page', 'reportedip-hive' ),
			),

			'reportedip_hive_waf_enabled'                  => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Firewall enabled', 'reportedip-hive' ),
			),
			'reportedip_hive_waf_report_only'              => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Firewall report-only', 'reportedip-hive' ),
			),
			'reportedip_hive_waf_paranoia'                 => array(
				'section'   => 'waf',
				'kind'      => 'int',
				'min'       => 1,
				'max'       => 3,
				'tier'      => 'rule_sync_priority',
				'tier_gate' => array( __CLASS__, 'paranoia_needs_tier' ),
				'remote'    => true,
				'label'     => __( 'Firewall paranoia level', 'reportedip-hive' ),
			),
			'reportedip_hive_waf_block_threshold'          => array(
				'section' => 'waf',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'Firewall block threshold (hits)', 'reportedip-hive' ),
			),
			'reportedip_hive_rule_sync_enabled'            => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Rule synchronisation', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_bot_verification'     => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Bot verification', 'reportedip-hive' ),
			),
			'reportedip_hive_bot_action'                   => array(
				'section' => 'waf',
				'kind'    => 'enum',
				'allowed' => array( 'flag', 'off', 'block' ),
				'remote'  => true,
				'label'   => __( 'Action on failed bot verification', 'reportedip-hive' ),
			),
			'reportedip_hive_disposable_email_action'      => array(
				'section' => 'waf',
				'kind'    => 'enum',
				'allowed' => array( 'monitor', 'off', 'block' ),
				'remote'  => true,
				'label'   => __( 'Action on disposable email domains', 'reportedip-hive' ),
			),
			'reportedip_hive_block_email_relays'           => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Block privacy relay addresses', 'reportedip-hive' ),
			),
			'reportedip_hive_prohibited_usernames'         => array(
				'section'   => 'waf',
				'kind'      => 'textarea',
				'tier'      => 'registration_rules_unlimited',
				'tier_gate' => array( 'ReportedIP_Hive_Registration_Guard', 'list_needs_tier' ),
				'sanitize'  => array( 'ReportedIP_Hive_Registration_Guard', 'sanitize_username_list' ),
				'remote'    => true,
				'label'     => __( 'Prohibited usernames', 'reportedip-hive' ),
			),
			'reportedip_hive_prohibited_usernames_baseline' => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Built-in prohibited usernames', 'reportedip-hive' ),
			),
			'reportedip_hive_email_rule_mode'              => array(
				'section' => 'waf',
				'kind'    => 'enum',
				'allowed' => array( 'off', 'block', 'allow' ),
				'remote'  => true,
				'label'   => __( 'E-mail rule mode', 'reportedip-hive' ),
			),
			'reportedip_hive_email_rules'                  => array(
				'section'   => 'waf',
				'kind'      => 'textarea',
				'tier'      => 'registration_rules_unlimited',
				'tier_gate' => array( 'ReportedIP_Hive_Registration_Guard', 'list_needs_tier' ),
				'sanitize'  => array( 'ReportedIP_Hive_Registration_Guard', 'sanitize_email_rule_list' ),
				'remote'    => true,
				'label'     => __( 'E-mail rules', 'reportedip-hive' ),
			),
			'reportedip_hive_registration_limit_enabled'   => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Registration rate limit', 'reportedip-hive' ),
			),
			'reportedip_hive_registration_limit_count'     => array(
				'section' => 'waf',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'Registrations per window', 'reportedip-hive' ),
			),
			'reportedip_hive_registration_limit_timeframe' => array(
				'section' => 'waf',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 60,
				'remote'  => true,
				'label'   => __( 'Registration window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_registration_allowlist'       => array(
				'section'  => 'waf',
				'kind'     => 'textarea',
				'tier'     => 'registration_rules_unlimited',
				'sanitize' => array( 'ReportedIP_Hive_Registration_Guard', 'sanitize_ip_list' ),
				'remote'   => true,
				'label'    => __( 'Registration allowlist (IP/CIDR)', 'reportedip-hive' ),
			),
			'reportedip_hive_block_unknown_username_login' => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Block logins with unknown usernames', 'reportedip-hive' ),
			),
			'reportedip_hive_comment_honeypot_enabled'     => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Comment honeypot', 'reportedip-hive' ),
			),
			'reportedip_hive_decoy_pathblock_enabled'      => array(
				'section' => 'waf',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Decoy path blocking', 'reportedip-hive' ),
			),

			'reportedip_hive_hide_login_enabled'           => array(
				'section'      => 'hide_login',
				'kind'         => 'bool',
				'remote'       => true,
				'side_effects' => array( 'flush_rewrite' ),
				'label'        => __( 'Hide login enabled', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_login_slug'              => array(
				'section'      => 'hide_login',
				'kind'         => 'slug',
				'sanitize'     => array( 'ReportedIP_Hive_Hide_Login', 'validate_slug_value' ),
				'remote'       => true,
				'side_effects' => array( 'flush_rewrite' ),
				'label'        => __( 'Login slug', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_login_response_mode'     => array(
				'section' => 'hide_login',
				'kind'    => 'enum',
				'allowed' => array( 'block_page', '404' ),
				'remote'  => true,
				'label'   => __( 'Response on the default login URL', 'reportedip-hive' ),
			),
			'reportedip_hive_monitor_hide_login_probe'     => array(
				'section' => 'hide_login',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Monitor login probe attempts', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_login_probe_threshold'   => array(
				'section' => 'hide_login',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'Login probe threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_login_probe_timeframe'   => array(
				'section' => 'hide_login',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'Login probe window (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_login_token_in_urls'     => array(
				'section' => 'hide_login',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Append the login token to generated URLs', 'reportedip-hive' ),
			),

			'reportedip_hive_rest_access_mode'             => array(
				'section' => 'lockdown',
				'kind'    => 'enum',
				'allowed' => array( 'open', 'logged_in', 'restricted' ),
				'remote'  => true,
				'label'   => __( 'REST API access', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_allowed_namespaces'      => array(
				'section' => 'lockdown',
				'kind'    => 'textarea',
				'remote'  => true,
				'label'   => __( 'REST namespaces always allowed', 'reportedip-hive' ),
			),
			'reportedip_hive_rest_allowed_roles'           => array(
				'section'       => 'lockdown',
				'kind'          => 'json_list',
				'json_filter'   => array( 'ReportedIP_Hive_Two_Factor', 'filter_valid_roles' ),
				'json_fallback' => array( 'administrator' ),
				'remote'        => true,
				'label'         => __( 'Roles allowed to use the REST API', 'reportedip-hive' ),
			),
			'reportedip_hive_disable_xmlrpc'               => array(
				'section' => 'lockdown',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Disable XML-RPC', 'reportedip-hive' ),
			),
			'reportedip_hive_disable_feeds'                => array(
				'section' => 'lockdown',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Disable RSS and Atom feeds', 'reportedip-hive' ),
			),
			'reportedip_hive_block_admin_guests'           => array(
				'section' => 'lockdown',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Close wp-admin for visitors', 'reportedip-hive' ),
			),
			'reportedip_hive_block_uploads_php'            => array(
				'section' => 'lockdown',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Block PHP execution in uploads', 'reportedip-hive' ),
			),
			'reportedip_hive_hide_software_info'           => array(
				'section' => 'lockdown',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Hide software fingerprints', 'reportedip-hive' ),
			),
			'reportedip_hive_headers_enabled'              => array(
				'section' => 'headers',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Send security headers', 'reportedip-hive' ),
			),
			'reportedip_hive_header_xcto'                  => array(
				'section' => 'headers',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'X-Content-Type-Options', 'reportedip-hive' ),
			),
			'reportedip_hive_header_xfo'                   => array(
				'section'  => 'headers',
				'kind'     => 'enum',
				'allowed'  => array( 'SAMEORIGIN', 'DENY', 'off' ),
				'sanitize' => array( 'ReportedIP_Hive_Security_Headers', 'sanitize_xfo' ),
				'remote'   => true,
				'label'    => __( 'X-Frame-Options', 'reportedip-hive' ),
			),
			'reportedip_hive_header_referrer'              => array(
				'section' => 'headers',
				'kind'    => 'enum',
				'allowed' => array( 'no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade' ),
				'remote'  => true,
				'label'   => __( 'Referrer-Policy', 'reportedip-hive' ),
			),
			'reportedip_hive_hsts_enabled'                 => array(
				'section' => 'headers',
				'kind'    => 'bool',
				'tier'    => 'security_headers_advanced',
				'remote'  => true,
				'label'   => __( 'HTTP Strict Transport Security', 'reportedip-hive' ),
			),
			'reportedip_hive_hsts_max_age'                 => array(
				'section' => 'headers',
				'kind'    => 'int',
				'min'     => 0,
				'max'     => 63072000,
				'remote'  => true,
				'label'   => __( 'HSTS max-age (seconds)', 'reportedip-hive' ),
			),
			'reportedip_hive_hsts_subdomains'              => array(
				'section' => 'headers',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'HSTS includeSubDomains', 'reportedip-hive' ),
			),
			'reportedip_hive_hsts_preload'                 => array(
				'section' => 'headers',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'HSTS preload', 'reportedip-hive' ),
			),
			'reportedip_hive_permissions_policy'           => array(
				'section'   => 'headers',
				'kind'      => 'text',
				'tier'      => 'security_headers_advanced',
				'tier_gate' => array( __CLASS__, 'header_text_needs_tier' ),
				'remote'    => true,
				'label'     => __( 'Permissions-Policy', 'reportedip-hive' ),
			),
			'reportedip_hive_csp_mode'                     => array(
				'section'   => 'headers',
				'kind'      => 'enum',
				'allowed'   => array( 'off', 'report_only', 'enforce' ),
				'tier'      => 'security_headers_advanced',
				'tier_gate' => array( __CLASS__, 'header_off_needs_tier' ),
				'remote'    => true,
				'label'     => __( 'Content-Security-Policy mode', 'reportedip-hive' ),
			),
			'reportedip_hive_csp_policy'                   => array(
				'section' => 'headers',
				'kind'    => 'textarea',
				'remote'  => true,
				'label'   => __( 'Content-Security-Policy', 'reportedip-hive' ),
			),
			'reportedip_hive_csp_report_uri'               => array(
				'section' => 'headers',
				'kind'    => 'url',
				'remote'  => true,
				'label'   => __( 'CSP report URI', 'reportedip-hive' ),
			),
			'reportedip_hive_coop'                         => array(
				'section'   => 'headers',
				'kind'      => 'enum',
				'allowed'   => array( 'off', 'same-origin' ),
				'tier'      => 'security_headers_advanced',
				'tier_gate' => array( __CLASS__, 'header_off_needs_tier' ),
				'remote'    => true,
				'label'     => __( 'Cross-Origin-Opener-Policy', 'reportedip-hive' ),
			),
			'reportedip_hive_corp'                         => array(
				'section'   => 'headers',
				'kind'      => 'enum',
				'allowed'   => array( 'off', 'same-origin' ),
				'tier'      => 'security_headers_advanced',
				'tier_gate' => array( __CLASS__, 'header_off_needs_tier' ),
				'remote'    => true,
				'label'     => __( 'Cross-Origin-Resource-Policy', 'reportedip-hive' ),
			),
			'reportedip_hive_coep'                         => array(
				'section'   => 'headers',
				'kind'      => 'enum',
				'allowed'   => array( 'off', 'require-corp' ),
				'tier'      => 'security_headers_advanced',
				'tier_gate' => array( __CLASS__, 'header_off_needs_tier' ),
				'remote'    => true,
				'label'     => __( 'Cross-Origin-Embedder-Policy', 'reportedip-hive' ),
			),

			'reportedip_hive_2fa_enabled_global'           => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Two-factor authentication enabled', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_allowed_methods'          => array(
				'section'       => 'account_security',
				'kind'          => 'json_list',
				'json_filter'   => array( 'ReportedIP_Hive_Two_Factor', 'filter_valid_methods' ),
				'json_fallback' => array( 'totp', 'email' ),
				'remote'        => true,
				'label'         => __( 'Allowed 2FA methods', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_enforce_roles'            => array(
				'section'     => 'account_security',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor', 'filter_valid_roles' ),
				'remote'      => true,
				'label'       => __( 'Roles required to use 2FA', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_enforce_grace_days'       => array(
				'section' => 'account_security',
				'kind'    => 'int',
				'min'     => 0,
				'max'     => 60,
				'remote'  => true,
				'label'   => __( '2FA grace period (days)', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_max_skips'                => array(
				'section' => 'account_security',
				'kind'    => 'int',
				'min'     => 0,
				'max'     => 20,
				'remote'  => true,
				'label'   => __( 'Maximum onboarding skips', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_enforce_action'           => array(
				'section' => 'account_security',
				'kind'    => 'enum',
				'allowed' => array( 'enroll', 'lockout' ),
				'remote'  => true,
				'label'   => __( 'Action when grace period is exhausted', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_trusted_devices'          => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Trusted devices', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_enforce_super_admins'     => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Enforce 2FA for super admins', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_extended_remember'        => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Extend the trusted-device window on "remember me"', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_ip_allowlist'             => array(
				'section'  => 'account_security',
				'kind'     => 'textarea',
				'sanitize' => array( 'ReportedIP_Hive_Proxy_Trust', 'sanitize_ranges' ),
				'remote'   => true,
				'label'    => __( 'IP addresses exempt from the second factor', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_branded_login'            => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Brand the login challenge', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_notify_new_device'        => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Mail the user when a new device signs in', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_xmlrpc_app_password_only' => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'XML-RPC accepts application passwords only', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_password_reset_block_email_only' => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Block a password reset when e-mail is the only second factor', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_frontend_enabled'         => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'tier'    => 'frontend_2fa',
				'remote'  => true,
				'label'   => __( 'Themed second factor on the storefront', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_frontend_onboarding'      => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Send storefront users to themed onboarding', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_frontend_slug'            => array(
				'section'  => 'account_security',
				'kind'     => 'text',
				'sanitize' => array( 'ReportedIP_Hive_Two_Factor_Frontend', 'sanitize_challenge_slug' ),
				'remote'   => true,
				'label'    => __( 'Storefront challenge URL', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_frontend_setup_slug'      => array(
				'section'  => 'account_security',
				'kind'     => 'text',
				'sanitize' => array( 'ReportedIP_Hive_Two_Factor_Frontend', 'sanitize_setup_slug' ),
				'remote'   => true,
				'label'    => __( 'Storefront setup URL', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_frontend_customer_optional' => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Customers may opt out of the second factor', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_trusted_device_days'      => array(
				'section' => 'account_security',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 365,
				'remote'  => true,
				'label'   => __( 'Trusted device lifetime (days)', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_new_country'       => array(
				'section'     => 'account_security',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up on a new country', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_new_ip'            => array(
				'section'     => 'account_security',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up on a new IP address', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_new_subnet'        => array(
				'section'     => 'account_security',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up on a new network', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_new_device'        => array(
				'section'     => 'account_security',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up on a new browser or device', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_every_n_days'      => array(
				'section'     => 'account_security',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up every few days', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_every_n_logins'    => array(
				'section'     => 'account_security',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up every few sign-ins', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_sessions_above_n'  => array(
				'section'     => 'account_security',
				'kind'        => 'json_list',
				'json_filter' => array( 'ReportedIP_Hive_Two_Factor_Policies', 'filter_policy_roles' ),
				'tier'        => '2fa_policies',
				'tier_gate'   => array( 'ReportedIP_Hive_Settings_Registry', 'policy_list_needs_tier' ),
				'remote'      => true,
				'label'       => __( 'Step-up above a session count', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_days'              => array(
				'section' => 'account_security',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 365,
				'remote'  => true,
				'label'   => __( 'Step-up interval (days)', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_logins'            => array(
				'section' => 'account_security',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100,
				'remote'  => true,
				'label'   => __( 'Step-up interval (sign-ins)', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_policy_sessions'          => array(
				'section' => 'account_security',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 20,
				'remote'  => true,
				'label'   => __( 'Open-session threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_2fa_require_on_password_reset' => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Require 2FA on password reset', 'reportedip-hive' ),
			),
			'reportedip_hive_password_policy_enabled'      => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Password policy', 'reportedip-hive' ),
			),
			'reportedip_hive_password_min_length'          => array(
				'section' => 'account_security',
				'kind'    => 'int',
				'min'     => 8,
				'max'     => 64,
				'remote'  => true,
				'label'   => __( 'Minimum password length', 'reportedip-hive' ),
			),
			'reportedip_hive_password_min_classes'        => array(
				'section' => 'account_security',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 4,
				'remote'  => true,
				'label'   => __( 'Required character classes', 'reportedip-hive' ),
			),
			'reportedip_hive_password_policy_all_users'   => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Apply the password policy to every role', 'reportedip-hive' ),
			),
			'reportedip_hive_password_check_hibp'          => array(
				'section' => 'account_security',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Check passwords against known breaches', 'reportedip-hive' ),
			),

			'reportedip_hive_log_level'                    => array(
				'section' => 'privacy_logs',
				'kind'    => 'enum',
				'allowed' => array( 'debug', 'info', 'warning', 'error', 'critical' ),
				'remote'  => true,
				'label'   => __( 'Log level', 'reportedip-hive' ),
			),
			'reportedip_hive_minimal_logging'              => array(
				'section' => 'privacy_logs',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Minimal logging', 'reportedip-hive' ),
			),
			'reportedip_hive_log_user_agents'              => array(
				'section' => 'privacy_logs',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Log user agents', 'reportedip-hive' ),
			),
			'reportedip_hive_data_retention_days'          => array(
				'section' => 'privacy_logs',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 365,
				'remote'  => true,
				'label'   => __( 'Data retention (days)', 'reportedip-hive' ),
			),
			'reportedip_hive_auto_anonymize_days'          => array(
				'section' => 'privacy_logs',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 365,
				'remote'  => true,
				'label'   => __( 'Auto-anonymize after (days)', 'reportedip-hive' ),
			),
			'reportedip_hive_audit_enabled'                => array(
				'section' => 'privacy_logs',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Audit trail', 'reportedip-hive' ),
			),
			'reportedip_hive_audit_retention_days'         => array(
				'section' => 'privacy_logs',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 365,
				'remote'  => true,
				'label'   => __( 'Audit retention (days)', 'reportedip-hive' ),
			),
			'reportedip_hive_audit_anonymize_ip'           => array(
				'section' => 'privacy_logs',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Anonymize IPs in the audit trail', 'reportedip-hive' ),
			),
			'reportedip_hive_detailed_logging'            => array(
				'section' => 'privacy_logs',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Record request details with each event', 'reportedip-hive' ),
			),
			'reportedip_hive_log_referer_domains'         => array(
				'section' => 'privacy_logs',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Record the referring domain', 'reportedip-hive' ),
			),
			'reportedip_hive_enable_caching'              => array(
				'section' => 'performance',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Cache community lookups', 'reportedip-hive' ),
			),
			'reportedip_hive_cache_duration'              => array(
				'section' => 'performance',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 168,
				'remote'  => true,
				'label'   => __( 'Cache lifetime (hours)', 'reportedip-hive' ),
			),
			'reportedip_hive_negative_cache_duration'     => array(
				'section' => 'performance',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 168,
				'remote'  => true,
				'label'   => __( 'Clean-result cache lifetime (hours)', 'reportedip-hive' ),
			),
			'reportedip_hive_max_api_calls_per_hour'      => array(
				'section' => 'performance',
				'kind'    => 'int',
				'min'     => 0,
				'max'     => 100000,
				'remote'  => true,
				'label'   => __( 'Community lookups per hour (0 = no local limit)', 'reportedip-hive' ),
			),
			'reportedip_hive_report_cooldown_hours'       => array(
				'section' => 'performance',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 720,
				'remote'  => true,
				'label'   => __( 'Report cooldown per address (hours)', 'reportedip-hive' ),
			),
			'reportedip_hive_queue_max_age_days'          => array(
				'section' => 'performance',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 90,
				'remote'  => true,
				'label'   => __( 'Discard queued reports after (days)', 'reportedip-hive' ),
			),
			'reportedip_hive_queue_warning_threshold'     => array(
				'section' => 'performance',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100000,
				'remote'  => true,
				'label'   => __( 'Queue warning threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_queue_critical_threshold'    => array(
				'section' => 'performance',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 100000,
				'remote'  => true,
				'label'   => __( 'Queue critical threshold', 'reportedip-hive' ),
			),
			'reportedip_hive_processing_timeout_minutes'  => array(
				'section' => 'performance',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'Recover stuck queue rows after (minutes)', 'reportedip-hive' ),
			),
			'reportedip_hive_auto_footer_enabled'         => array(
				'section' => 'performance',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Show the protection badge in the site footer', 'reportedip-hive' ),
			),
			'reportedip_hive_auto_footer_variant'         => array(
				'section' => 'performance',
				'kind'    => 'enum',
				'allowed' => array( 'badge', 'shield' ),
				'remote'  => true,
				'label'   => __( 'Footer badge style', 'reportedip-hive' ),
			),
			'reportedip_hive_auto_footer_align'           => array(
				'section' => 'performance',
				'kind'    => 'enum',
				'allowed' => array( 'left', 'center', 'right', 'below' ),
				'remote'  => true,
				'label'   => __( 'Footer badge placement', 'reportedip-hive' ),
			),
			'reportedip_hive_notify_sync_to_api'          => array(
				'section' => 'notifications',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Send notification preferences to the community server', 'reportedip-hive' ),
			),
			'reportedip_hive_notify_event_cap_minutes'    => array(
				'section' => 'notifications',
				'kind'    => 'int',
				'min'     => 1,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'Per-event notification cap (minutes)', 'reportedip-hive' ),
			),

			'reportedip_hive_notify_admin'                 => array(
				'section' => 'notifications',
				'kind'    => 'bool',
				'remote'  => true,
				'label'   => __( 'Admin notifications', 'reportedip-hive' ),
			),
			'reportedip_hive_notify_recipients'            => array(
				'section' => 'notifications',
				'kind'    => 'email_list',
				'remote'  => true,
				'label'   => __( 'Notification recipients', 'reportedip-hive' ),
			),
			'reportedip_hive_notify_from_name'             => array(
				'section' => 'notifications',
				'kind'    => 'text',
				'remote'  => true,
				'label'   => __( 'Sender name', 'reportedip-hive' ),
			),
			'reportedip_hive_notify_from_email'            => array(
				'section' => 'notifications',
				'kind'    => 'email',
				'remote'  => true,
				'label'   => __( 'Sender address', 'reportedip-hive' ),
			),
			'reportedip_hive_notification_cooldown_minutes' => array(
				'section' => 'notifications',
				'kind'    => 'int',
				'min'     => 0,
				'max'     => 1440,
				'remote'  => true,
				'label'   => __( 'Notification cooldown (minutes)', 'reportedip-hive' ),
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
	 * Whether the paranoia tier gate applies for a given target value —
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
				__( 'Hide Login cannot be enabled without a login slug — set a slug first.', 'reportedip-hive' )
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
	 * on the child — dashboards compare reported hashes, never recompute.
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
	 * Values envelope for management dashboards — the canonical response
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
			if ( isset( $entry['min'] ) ) {
				$field['min'] = (int) $entry['min'];
			}
			if ( isset( $entry['max'] ) ) {
				$field['max'] = (int) $entry['max'];
			}
			if ( isset( $entry['allowed'] ) ) {
				$field['allowed'] = array_values( (array) $entry['allowed'] );
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
