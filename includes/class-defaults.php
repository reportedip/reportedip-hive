<?php
/**
 * Centralised plugin defaults — single source of truth for the wizard JS,
 * the wizard PHP form fallbacks and the post-wizard safe-default seed.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.4.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin-wide defaults registry.
 *
 * Two value sets are exposed:
 *
 *  - `wizard()` returns the small set of wizard-form fallbacks (grace days,
 *    retention, mode, protection level, auto-footer alignment). Consumed by
 *    the wizard JS via wp_localize_script and by PHP rendering of the
 *    wizard steps.
 *  - `safe_options()` returns the larger map of WordPress option keys used
 *    by the post-wizard `add_option()` seed in the setup wizard.
 *
 * @since 1.4.0
 */
final class ReportedIP_Hive_Defaults {

	/**
	 * Wizard-form fallbacks. Keep keys ASCII-stable and JSON-friendly —
	 * they are sent to the browser via wp_localize_script.
	 *
	 * @var array<string, scalar>
	 */
	private const WIZARD = array(
		'grace_days'        => 7,
		'max_skips'         => 3,
		'retention_days'    => 30,
		'anonymize_days'    => 7,
		'mode'              => 'local',
		'protection_level'  => 'medium',
		'auto_footer_align' => 'center',
	);

	/**
	 * WordPress option keys seeded after the wizard completes. Values are
	 * passed verbatim to `add_option()`, so booleans stay bool and ints stay
	 * int — do not coerce to strings here.
	 *
	 * @var array<string, scalar>
	 */
	private const SAFE_OPTIONS = array(
		'reportedip_hive_api_endpoint'                  => 'https://reportedip.de/wp-json/reportedip/v2/',
		'reportedip_hive_trusted_ip_header'             => '',
		'reportedip_hive_blocked_page_contact_url'      => '',
		'reportedip_hive_max_api_calls_per_hour'        => 100,
		'reportedip_hive_report_cooldown_hours'         => 24,
		'reportedip_hive_notification_cooldown_minutes' => 60,
		'reportedip_hive_comment_spam_threshold'        => 5,
		'reportedip_hive_comment_spam_timeframe'        => 60,
		'reportedip_hive_scan_404_threshold'            => 12,
		'reportedip_hive_scan_404_timeframe'            => 2,
		'reportedip_hive_xmlrpc_threshold'              => 10,
		'reportedip_hive_xmlrpc_timeframe'              => 60,
		'reportedip_hive_disable_xmlrpc_multicall'      => true,
		'reportedip_hive_log_level'                     => 'info',
		'reportedip_hive_detailed_logging'              => false,
		'reportedip_hive_enable_caching'                => true,
		'reportedip_hive_cache_duration'                => 24,
		'reportedip_hive_negative_cache_duration'       => 2,
		'reportedip_hive_queue_max_age_days'            => 7,
		'reportedip_hive_queue_warning_threshold'       => 50,
		'reportedip_hive_queue_critical_threshold'      => 200,
		'reportedip_hive_2fa_trusted_device_days'       => 30,
		'reportedip_hive_2fa_branded_login'             => false,
		'reportedip_hive_2fa_extended_remember'         => false,
		'reportedip_hive_2fa_ip_allowlist'              => '',
		'reportedip_hive_block_escalation_enabled'      => true,
		'reportedip_hive_block_ladder_minutes'          => '5,15,30,1440,2880,10080',
		'reportedip_hive_block_ladder_reset_days'       => 30,
	);

	/**
	 * Look up a single wizard-form default.
	 *
	 * Throws on an unknown key — defaults must be registered explicitly to
	 * avoid the "scattered default values" anti-pattern this class exists to
	 * solve.
	 *
	 * @param string $key Wizard default key.
	 * @return scalar
	 * @throws \InvalidArgumentException When the key is unknown.
	 * @since  1.4.0
	 */
	public static function get( string $key ) {
		if ( ! array_key_exists( $key, self::WIZARD ) ) {
			throw new \InvalidArgumentException(
				sprintf( 'Unknown wizard default: %s', esc_html( $key ) )
			);
		}
		return self::WIZARD[ $key ];
	}

	/**
	 * Return all wizard-form defaults — used by `wp_localize_script` so the
	 * JS can read them without bundling a duplicated copy.
	 *
	 * @return array<string, scalar>
	 * @since  1.4.0
	 */
	public static function wizard(): array {
		return self::WIZARD;
	}

	/**
	 * Return the post-wizard safe-options seed map.
	 *
	 * @return array<string, scalar>
	 * @since  1.4.0
	 */
	public static function safe_options(): array {
		return self::SAFE_OPTIONS;
	}
}
