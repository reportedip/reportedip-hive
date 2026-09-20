<?php
/**
 * Security event taxonomy, the single registry of every logged event type.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.13
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registry of every `event_type` the plugin writes.
 *
 * One row per event slug feeds four consumers: the threat family used by the
 * dashboard charts, the display label used by the logs table, the option group
 * of the activity filter and the badge colour. Before 2.1.62 those four lived
 * in four hand-kept lists that drifted apart, which is how form spam ended up
 * unfilterable and geo anomalies vanished from every chart.
 *
 * Row keys:
 *
 * - `label`  Display text. Mandatory.
 * - `group`  Option group of the activity filter. Mandatory.
 * - `family` Threat family for the charts. Absent means operational, those rows
 *            are offered in the filter but deliberately kept out of the threat
 *            charts so bookkeeping does not inflate attack numbers.
 * - `writes` `direct` (default, the bare slug is logged), `threshold` (only the
 *            generated `_threshold_exceeded` variant is logged) or `both`.
 *
 * An event type that is not registered at all classifies as `other` and shows
 * up in the charts as such, so a new sensor stays visible even when someone
 * forgets this file.
 *
 * @since 2.1.13
 */
class ReportedIP_Hive_Event_Taxonomy {

	/**
	 * Ordered family keys for stable display ordering.
	 *
	 * @var array<int, string>
	 */
	private const ORDER = array( 'login', 'firewall', 'scanner', 'bot', 'recon', 'spam', 'anomaly', 'other' );

	/**
	 * Ordered filter group keys.
	 *
	 * @var array<int, string>
	 */
	private const GROUP_ORDER = array(
		'login',
		'registration',
		'forms',
		'firewall',
		'bots',
		'recon',
		'reputation',
		'twofa',
		'hardening',
		'reportonly',
		'ops_blocks',
		'ops_api',
		'ops_system',
	);

	/**
	 * Memoised registry.
	 *
	 * @var array<string, array<string, string>>|null
	 */
	private static $registry = null;

	/**
	 * The registry.
	 *
	 * @return array<string, array<string, string>> Event slug to row.
	 * @since  2.1.62
	 */
	public static function registry() {
		if ( null !== self::$registry ) {
			return self::$registry;
		}

		self::$registry = array(

			'failed_login'                      => array(
				'label'  => __( 'Failed Login', 'reportedip-hive' ),
				'group'  => 'login',
				'family' => 'login',
				'writes' => 'both',
			),
			'password_spray'                    => array(
				'label'  => __( 'Password Spray', 'reportedip-hive' ),
				'group'  => 'login',
				'family' => 'login',
				'writes' => 'threshold',
			),
			'wc_login_failed'                   => array(
				'label'  => __( 'WooCommerce Login Failed', 'reportedip-hive' ),
				'group'  => 'login',
				'family' => 'login',
				'writes' => 'threshold',
			),
			'app_password_failed'               => array(
				'label'  => __( 'App Password Failed', 'reportedip-hive' ),
				'group'  => 'login',
				'family' => 'login',
			),
			'app_password_abuse'                => array(
				'label'  => __( 'App Password Abuse', 'reportedip-hive' ),
				'group'  => 'login',
				'family' => 'login',
				'writes' => 'threshold',
			),
			'blocked_user_denied'               => array(
				'label'  => __( 'Blocked Account Sign-in', 'reportedip-hive' ),
				'group'  => 'login',
				'family' => 'login',
			),
			'app_password_success'              => array(
				'label' => __( 'App Password Sign-in', 'reportedip-hive' ),
				'group' => 'login',
			),
			'successful_login'                  => array(
				'label' => __( 'Successful Login', 'reportedip-hive' ),
				'group' => 'login',
			),

			'disposable_email'                  => array(
				'label'  => __( 'Disposable Email', 'reportedip-hive' ),
				'group'  => 'registration',
				'family' => 'spam',
			),
			'prohibited_username'               => array(
				'label'  => __( 'Prohibited Username', 'reportedip-hive' ),
				'group'  => 'registration',
				'family' => 'spam',
			),
			'registration_denied'               => array(
				'label'  => __( 'Registration Denied', 'reportedip-hive' ),
				'group'  => 'registration',
				'family' => 'spam',
			),
			'registration_limit'                => array(
				'label'  => __( 'Registration Rate Limit', 'reportedip-hive' ),
				'group'  => 'registration',
				'family' => 'spam',
			),
			'unknown_username_probe'            => array(
				'label'  => __( 'Unknown Username Probe', 'reportedip-hive' ),
				'group'  => 'registration',
				'family' => 'login',
				'writes' => 'threshold',
			),

			'form_proof_failed'                 => array(
				'label'  => __( 'Form Proof Failed', 'reportedip-hive' ),
				'group'  => 'forms',
				'family' => 'spam',
			),
			'form_spam'                         => array(
				'label'  => __( 'Form Spam', 'reportedip-hive' ),
				'group'  => 'forms',
				'family' => 'spam',
				'writes' => 'threshold',
			),
			'comment_spam'                      => array(
				'label'  => __( 'Comment Spam', 'reportedip-hive' ),
				'group'  => 'forms',
				'family' => 'spam',
				'writes' => 'both',
			),
			'comment_honeypot'                  => array(
				'label'  => __( 'Comment Honeypot', 'reportedip-hive' ),
				'group'  => 'forms',
				'family' => 'spam',
			),

			'waf_block'                         => array(
				'label'  => __( 'WAF Block', 'reportedip-hive' ),
				'group'  => 'firewall',
				'family' => 'firewall',
				'writes' => 'both',
			),
			'waf_would_block'                   => array(
				'label'  => __( 'WAF Match (report-only)', 'reportedip-hive' ),
				'group'  => 'firewall',
				'family' => 'firewall',
			),
			'scan_404'                          => array(
				'label'  => __( 'Scan Detected', 'reportedip-hive' ),
				'group'  => 'firewall',
				'family' => 'scanner',
				'writes' => 'threshold',
			),
			'decoy_pathblock_hit'               => array(
				'label'  => __( 'Decoy Path Hit', 'reportedip-hive' ),
				'group'  => 'firewall',
				'family' => 'scanner',
			),
			'rule_sync_signature_fail'          => array(
				'label' => __( 'Ruleset Signature Failure', 'reportedip-hive' ),
				'group' => 'firewall',
			),

			'fake_bot'                          => array(
				'label'  => __( 'Spoofed Crawler (flagged)', 'reportedip-hive' ),
				'group'  => 'bots',
				'family' => 'bot',
			),
			'fake_bot_blocked'                  => array(
				'label'  => __( 'Spoofed Crawler (blocked)', 'reportedip-hive' ),
				'group'  => 'bots',
				'family' => 'bot',
			),
			'bot_exemption_denied'              => array(
				'label'  => __( 'Bot Exemption Denied', 'reportedip-hive' ),
				'group'  => 'bots',
				'family' => 'bot',
			),
			'verified_bot_block_averted'        => array(
				'label' => __( 'Verified Crawler Spared', 'reportedip-hive' ),
				'group' => 'bots',
			),

			'user_enumeration'                  => array(
				'label'  => __( 'User Enumeration', 'reportedip-hive' ),
				'group'  => 'recon',
				'family' => 'recon',
				'writes' => 'threshold',
			),
			'rest_abuse'                        => array(
				'label'  => __( 'REST API Abuse', 'reportedip-hive' ),
				'group'  => 'recon',
				'family' => 'recon',
				'writes' => 'threshold',
			),
			'rest_denied'                       => array(
				'label'  => __( 'REST API Denied', 'reportedip-hive' ),
				'group'  => 'recon',
				'family' => 'recon',
			),
			'xmlrpc_denied'                     => array(
				'label'  => __( 'XML-RPC Denied', 'reportedip-hive' ),
				'group'  => 'recon',
				'family' => 'recon',
			),
			'feed_denied'                       => array(
				'label'  => __( 'Feed Denied', 'reportedip-hive' ),
				'group'  => 'recon',
				'family' => 'recon',
			),
			'admin_guest_denied'                => array(
				'label'  => __( 'Admin Area Denied (signed out)', 'reportedip-hive' ),
				'group'  => 'recon',
				'family' => 'recon',
			),
			'xmlrpc_abuse'                      => array(
				'label'  => __( 'XML-RPC Abuse', 'reportedip-hive' ),
				'group'  => 'recon',
				'family' => 'spam',
				'writes' => 'threshold',
			),
			'hide_login_probe'                  => array(
				'label'  => __( 'Hidden Login Probe', 'reportedip-hive' ),
				'group'  => 'recon',
				'family' => 'recon',
				'writes' => 'threshold',
			),
			'hide_login_block'                  => array(
				'label'  => __( 'Hidden Login Denied', 'reportedip-hive' ),
				'group'  => 'recon',
				'family' => 'recon',
			),
			'xmlrpc_call'                       => array(
				'label' => __( 'XML-RPC Call', 'reportedip-hive' ),
				'group' => 'recon',
			),

			'blocked_by_reputation'             => array(
				'label'  => __( 'Blocked by Community Reputation', 'reportedip-hive' ),
				'group'  => 'reputation',
				'family' => 'anomaly',
			),
			'blocked_by_tor_exit'               => array(
				'label'  => __( 'Blocked Tor Exit Node', 'reportedip-hive' ),
				'group'  => 'reputation',
				'family' => 'anomaly',
			),
			'reputation_infrastructure_spared'  => array(
				'label'  => __( 'Infrastructure Spared (forms)', 'reportedip-hive' ),
				'group'  => 'reputation',
				'family' => 'anomaly',
			),
			'infrastructure_spared'             => array(
				'label'  => __( 'Infrastructure Spared', 'reportedip-hive' ),
				'group'  => 'reputation',
				'family' => 'anomaly',
			),

			'2fa_brute_force'                   => array(
				'label'  => __( 'Two-Factor Brute Force', 'reportedip-hive' ),
				'group'  => 'twofa',
				'family' => 'login',
				'writes' => 'threshold',
			),
			'2fa_stepup_required'               => array(
				'label' => __( 'Step-Up Challenge Required', 'reportedip-hive' ),
				'group' => 'twofa',
			),
			'2fa_stepup_skipped_no_method'      => array(
				'label' => __( 'Step-Up Skipped (no method)', 'reportedip-hive' ),
				'group' => 'twofa',
			),
			'2fa_webauthn_counter_regression'   => array(
				'label'  => __( 'Security Key Counter Regression', 'reportedip-hive' ),
				'group'  => 'twofa',
				'family' => 'anomaly',
			),
			'2fa_reset_bypass_attempt'          => array(
				'label'  => __( 'Password Reset Gate Bypass Attempt', 'reportedip-hive' ),
				'group'  => 'twofa',
				'family' => 'anomaly',
			),
			'2fa_reset_challenge_failed'        => array(
				'label'  => __( 'Password Reset Challenge Failed', 'reportedip-hive' ),
				'group'  => 'twofa',
				'family' => 'login',
			),
			'2fa_reset_challenge_sent'          => array(
				'label' => __( 'Password Reset Challenge Sent', 'reportedip-hive' ),
				'group' => 'twofa',
			),
			'2fa_reset_challenge_passed'        => array(
				'label' => __( 'Password Reset Challenge Passed', 'reportedip-hive' ),
				'group' => 'twofa',
			),
			'2fa_reset_email_only_blocked'      => array(
				'label' => __( 'Password Reset Blocked (email only)', 'reportedip-hive' ),
				'group' => 'twofa',
			),
			'2fa_reset_no_eligible_method'      => array(
				'label' => __( 'Password Reset without Eligible Method', 'reportedip-hive' ),
				'group' => 'twofa',
			),
			'2fa_reset_no_usable_method'        => array(
				'label' => __( 'Password Reset without Usable Method', 'reportedip-hive' ),
				'group' => 'twofa',
			),
			'2fa_reset_send_failed'             => array(
				'label' => __( 'Password Reset Challenge Send Failed', 'reportedip-hive' ),
				'group' => 'twofa',
			),
			'2fa_reset_verify_internal_error'   => array(
				'label' => __( 'Password Reset Verification Error', 'reportedip-hive' ),
				'group' => 'twofa',
			),

			'geo_anomaly_detected'              => array(
				'label'  => __( 'Geo Anomaly', 'reportedip-hive' ),
				'group'  => 'hardening',
				'family' => 'anomaly',
			),
			'coordinated_attack_detected'       => array(
				'label'  => __( 'Coordinated Attack Detected', 'reportedip-hive' ),
				'group'  => 'hardening',
				'family' => 'anomaly',
			),
			'hardening_mode_activated'          => array(
				'label'  => __( 'Hardening Mode Activated', 'reportedip-hive' ),
				'group'  => 'hardening',
				'family' => 'anomaly',
			),
			'hardening_mode_extended'           => array(
				'label'  => __( 'Hardening Mode Extended', 'reportedip-hive' ),
				'group'  => 'hardening',
				'family' => 'anomaly',
			),
			'hardening_mode_deactivated'        => array(
				'label' => __( 'Hardening Mode Deactivated', 'reportedip-hive' ),
				'group' => 'hardening',
			),
			'own_server_ip_block_averted'       => array(
				'label' => __( 'Own Server IP Spared', 'reportedip-hive' ),
				'group' => 'hardening',
			),

			'would_block_access'                => array(
				'label' => __( 'Would Block Access', 'reportedip-hive' ),
				'group' => 'reportonly',
			),
			'would_block_ip'                    => array(
				'label' => __( 'Would Block IP', 'reportedip-hive' ),
				'group' => 'reportonly',
			),
			'would_block_by_reputation'         => array(
				'label' => __( 'Would Block by Reputation', 'reportedip-hive' ),
				'group' => 'reportonly',
			),
			'would_block_by_tor_exit'           => array(
				'label' => __( 'Would Block Tor Exit Node', 'reportedip-hive' ),
				'group' => 'reportonly',
			),
			'would_send_notification'           => array(
				'label' => __( 'Would Send Notification', 'reportedip-hive' ),
				'group' => 'reportonly',
			),

			'ip_blocked'                        => array(
				'label' => __( 'IP Blocked', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'ip_unblocked'                      => array(
				'label' => __( 'IP Unblocked', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'ip_whitelisted'                    => array(
				'label' => __( 'IP Whitelisted', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'ip_removed_from_whitelist'         => array(
				'label' => __( 'IP Removed from Whitelist', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'whitelist_imported'                => array(
				'label' => __( 'Whitelist Imported', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'csv_import_blocked'                => array(
				'label' => __( 'CSV Import (blocked IPs)', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'csv_import_whitelist'              => array(
				'label' => __( 'CSV Import (whitelist)', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'attempting_auto_block'             => array(
				'label' => __( 'Auto Block Attempted', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'auto_block_failed'                 => array(
				'label' => __( 'Auto Block Failed', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'block_skipped_already_blocked'     => array(
				'label' => __( 'Block Skipped (already blocked)', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'block_skipped_whitelist'           => array(
				'label' => __( 'Block Skipped (whitelisted)', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),
			'local_event_detected'              => array(
				'label' => __( 'Local Event Detected', 'reportedip-hive' ),
				'group' => 'ops_blocks',
			),

			'api_call_failed'                   => array(
				'label' => __( 'API Call Failed', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_domain_limit'                  => array(
				'label' => __( 'API Domain Limit', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_error'                         => array(
				'label' => __( 'API Error', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_health_degraded'               => array(
				'label' => __( 'API Health Degraded', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_invalid_response'              => array(
				'label' => __( 'API Invalid Response', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_quota_refreshed'               => array(
				'label' => __( 'API Quota Refreshed', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_rate_limit_hit'                => array(
				'label' => __( 'API Rate Limit Hit', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_rate_limited'                  => array(
				'label' => __( 'API Rate Limited', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_report_queued'                 => array(
				'label' => __( 'Report Queued', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_report_skipped'                => array(
				'label' => __( 'Report Skipped', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_report_retry'                  => array(
				'label' => __( 'Report Retried', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_report_deleted'                => array(
				'label' => __( 'Report Deleted', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_reports_bulk_retry'            => array(
				'label' => __( 'Reports Retried (bulk)', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'api_success'                       => array(
				'label' => __( 'API Success', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'queue_processing_skipped'          => array(
				'label' => __( 'Queue Processing Skipped', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'categories_cached'                 => array(
				'label' => __( 'Report Categories Cached', 'reportedip-hive' ),
				'group' => 'ops_api',
			),
			'cloud_management_auth_fail'        => array(
				'label' => __( 'Cloud Management Auth Failed', 'reportedip-hive' ),
				'group' => 'ops_api',
			),

			'mode_changed'                      => array(
				'label' => __( 'Operation Mode Changed', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'settings_admin_apply'              => array(
				'label' => __( 'Settings Saved (admin)', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'settings_remote_apply'             => array(
				'label' => __( 'Settings Saved (remote)', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'settings_imported'                 => array(
				'label' => __( 'Settings Imported', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'quickstart_value_rejected'         => array(
				'label' => __( 'Quickstart Value Rejected', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'mail_relay_error'                  => array(
				'label' => __( 'Mail Relay Error', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'mail_relay_fallback'               => array(
				'label' => __( 'Mail Relay Fallback', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'notification_rate_limited'         => array(
				'label' => __( 'Notification Rate Limited', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'notification_event_cap_suppressed' => array(
				'label' => __( 'Notification Suppressed (cap)', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'cache_hit'                         => array(
				'label' => __( 'Cache Hit', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'cache_set'                         => array(
				'label' => __( 'Cache Set', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'cache_cleared'                     => array(
				'label' => __( 'Cache Cleared', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'cache_cleanup'                     => array(
				'label' => __( 'Cache Cleanup', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'cache_flush_all'                   => array(
				'label' => __( 'Cache Flushed', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'info'                              => array(
				'label' => __( 'Info Message', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'warning'                           => array(
				'label' => __( 'Warning Message', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'error'                             => array(
				'label' => __( 'Error Message', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'critical'                          => array(
				'label' => __( 'Critical Message', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'debug'                             => array(
				'label' => __( 'Debug Message', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'auto_block_test_initiated'         => array(
				'label' => __( 'Auto Block Test', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'failed_login_simulation_started'   => array(
				'label' => __( 'Login Simulation Started', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'simulated_failed_login'            => array(
				'label' => __( 'Simulated Failed Login', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'debug_test_low'                    => array(
				'label' => __( 'Logging Test (low)', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'debug_test_medium'                 => array(
				'label' => __( 'Logging Test (medium)', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'debug_test_high'                   => array(
				'label' => __( 'Logging Test (high)', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
			'debug_test_critical'               => array(
				'label' => __( 'Logging Test (critical)', 'reportedip-hive' ),
				'group' => 'ops_system',
			),
		);

		return self::$registry;
	}

	/**
	 * Ordered list of threat families with translated labels.
	 *
	 * @return array<string, string> Map of family key to display label.
	 * @since  2.1.13
	 */
	public static function labels() {
		$labels = array(
			'login'    => __( 'Login & Credential', 'reportedip-hive' ),
			'firewall' => __( 'Firewall (WAF)', 'reportedip-hive' ),
			'scanner'  => __( 'Scanners & Probes', 'reportedip-hive' ),
			'bot'      => __( 'Fake Bots', 'reportedip-hive' ),
			'recon'    => __( 'Recon & Enumeration', 'reportedip-hive' ),
			'spam'     => __( 'Spam & Flooding', 'reportedip-hive' ),
			'anomaly'  => __( 'Anomalies', 'reportedip-hive' ),
			'other'    => __( 'Other', 'reportedip-hive' ),
		);

		$ordered = array();
		foreach ( self::ORDER as $key ) {
			$ordered[ $key ] = $labels[ $key ];
		}
		return $ordered;
	}

	/**
	 * Ordered filter group keys with translated labels.
	 *
	 * @return array<string, string> Map of group key to display label.
	 * @since  2.1.62
	 */
	public static function group_labels() {
		$labels = array(
			'login'        => __( 'Login & Accounts', 'reportedip-hive' ),
			'registration' => __( 'Registration', 'reportedip-hive' ),
			'forms'        => __( 'Forms & Comments', 'reportedip-hive' ),
			'firewall'     => __( 'Firewall', 'reportedip-hive' ),
			'bots'         => __( 'Bots', 'reportedip-hive' ),
			'recon'        => __( 'Recon & Enumeration', 'reportedip-hive' ),
			'reputation'   => __( 'Community Reputation', 'reportedip-hive' ),
			'twofa'        => __( 'Two-Factor', 'reportedip-hive' ),
			'hardening'    => __( 'Anomalies & Hardening', 'reportedip-hive' ),
			'reportonly'   => __( 'Report-only Mode', 'reportedip-hive' ),
			'ops_blocks'   => __( 'Operations: Blocks & Whitelist', 'reportedip-hive' ),
			'ops_api'      => __( 'Operations: API & Queue', 'reportedip-hive' ),
			'ops_system'   => __( 'Operations: System', 'reportedip-hive' ),
		);

		$ordered = array();
		foreach ( self::GROUP_ORDER as $key ) {
			$ordered[ $key ] = $labels[ $key ];
		}
		return $ordered;
	}

	/**
	 * All event types that belong to a threat family.
	 *
	 * Returns every registered threat type plus its generated
	 * `_threshold_exceeded` variant, suitable for an SQL `IN()` filter that
	 * selects only attack rows (variants that never occur are harmless in the
	 * clause). Operational rows are excluded.
	 *
	 * @return string[] Distinct threat event-type strings.
	 * @since  2.1.13
	 */
	public static function threat_event_types() {
		$types = array();
		foreach ( self::registry() as $base => $row ) {
			if ( empty( $row['family'] ) ) {
				continue;
			}
			$types[] = $base;
			$types[] = $base . '_threshold_exceeded';
		}
		return array_values( array_unique( $types ) );
	}

	/**
	 * Map a raw event type to its threat family.
	 *
	 * Strips the generated `_threshold_exceeded` suffix before the lookup so
	 * both the base event and its threshold variant resolve to one family.
	 *
	 * @param string $event_type Raw event type from the logs table.
	 * @return string|null Family key, `other` for an unregistered type, or null
	 *                     for a registered operational event.
	 * @since  2.1.13
	 */
	public static function classify( $event_type ) {
		$registry = self::registry();
		$base     = self::base_type( $event_type );

		if ( ! isset( $registry[ $base ] ) ) {
			return 'other';
		}

		return isset( $registry[ $base ]['family'] ) ? $registry[ $base ]['family'] : null;
	}

	/**
	 * Display label for one event type.
	 *
	 * @param string $event_type Raw event type from the logs table.
	 * @return string Translated label, humanised slug for unregistered types.
	 * @since  2.1.62
	 */
	public static function label( $event_type ) {
		$type     = (string) $event_type;
		$base     = self::base_type( $type );
		$registry = self::registry();

		$label = isset( $registry[ $base ] )
			? $registry[ $base ]['label']
			: ucwords( str_replace( '_', ' ', $base ) );

		if ( $base !== $type ) {
			return self::threshold_label( $label );
		}

		return $label;
	}

	/**
	 * Whether an event type carries a registry row.
	 *
	 * @param string $event_type Raw event type.
	 * @return bool True when registered.
	 * @since  2.1.62
	 */
	public static function is_registered( $event_type ) {
		return isset( self::registry()[ self::base_type( $event_type ) ] );
	}

	/**
	 * Grouped option list for the activity filter.
	 *
	 * A row that writes both the bare slug and the threshold variant yields two
	 * options, because they are separate values in the column and one option
	 * could only ever match one of them.
	 *
	 * @return array<string, array<string, string>> Group key to slug/label map.
	 * @since  2.1.62
	 */
	public static function filter_options() {
		$groups = array();
		foreach ( array_keys( self::group_labels() ) as $key ) {
			$groups[ $key ] = array();
		}

		foreach ( self::registry() as $slug => $row ) {
			$group  = $row['group'];
			$writes = isset( $row['writes'] ) ? $row['writes'] : 'direct';

			if ( 'threshold' !== $writes ) {
				$groups[ $group ][ $slug ] = $row['label'];
			}

			if ( 'direct' !== $writes ) {
				$groups[ $group ][ $slug . '_threshold_exceeded' ] = self::threshold_label( $row['label'] );
			}
		}

		return array_filter( $groups );
	}

	/**
	 * Strip the generated threshold suffix.
	 *
	 * @param string $event_type Raw event type.
	 * @return string Base type.
	 * @since  2.1.62
	 */
	private static function base_type( $event_type ) {
		$type   = (string) $event_type;
		$suffix = '_threshold_exceeded';

		if ( substr( $type, -strlen( $suffix ) ) === $suffix ) {
			return substr( $type, 0, -strlen( $suffix ) );
		}

		return $type;
	}

	/**
	 * Decorate a base label as its threshold variant.
	 *
	 * @param string $label Base label.
	 * @return string Decorated label.
	 * @since  2.1.62
	 */
	private static function threshold_label( $label ) {
		/* translators: %s: event type label. */
		return sprintf( __( '%s (threshold reached)', 'reportedip-hive' ), $label );
	}
}
