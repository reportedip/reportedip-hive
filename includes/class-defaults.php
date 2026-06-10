<?php
/**
 * Centralised plugin defaults — single source of truth for the wizard JS,
 * the wizard PHP form fallbacks and the post-wizard safe-default seed.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.4.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Plugin-wide defaults registry — the single source of truth for every
 * `reportedip_hive_*` option default.
 *
 * Three accessors are exposed:
 *
 *  - `wizard()` returns the small set of wizard-form fallbacks (grace days,
 *    retention, mode, protection level, auto-footer alignment). Consumed by
 *    the wizard JS via wp_localize_script and by PHP rendering of the
 *    wizard steps.
 *  - `all_option_defaults()` (alias `safe_options()`) returns the canonical
 *    option-key => default map. This is the one place option defaults live;
 *    activation seeding, the wizard-skip seed, the settings-reset re-seed and
 *    `ReportedIP_Hive::get_default_options()` all read from it.
 *  - `seed_missing()` writes every default that is not yet present through
 *    `ReportedIP_Hive_Option_Routing`, so network-wide keys land in sitemeta
 *    on Multisite instead of a single blog's options table.
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
	 * Canonical option-key => default map. The single source of truth for
	 * every `reportedip_hive_*` default: activation seeding, the wizard-skip
	 * seed, the settings-reset re-seed and `ReportedIP_Hive::get_default_options()`
	 * all read from here. Values are typed (bool stays bool, int stays int) and
	 * persisted verbatim through `ReportedIP_Hive_Option_Routing::set()`.
	 *
	 * The three per-site override keys are deliberately absent — they are
	 * blog-scoped and resolved on demand by `ReportedIP_Hive_Option_Routing`.
	 *
	 * @var array<string, scalar>
	 */
	private const SAFE_OPTIONS = array(
		'reportedip_hive_operation_mode'                 => 'local',
		'reportedip_hive_api_key'                        => '',
		'reportedip_hive_api_endpoint'                   => 'https://reportedip.de/wp-json/reportedip/v2/',
		'reportedip_hive_trusted_ip_header'              => '',
		'reportedip_hive_max_api_calls_per_hour'         => 0,
		'reportedip_hive_report_cooldown_hours'          => 24,
		'reportedip_hive_report_only_mode'               => false,

		'reportedip_hive_rule_sync_enabled'              => true,
		'reportedip_hive_rule_sync_last_run'             => 0,
		'reportedip_hive_ruleset_waf'                    => '',
		'reportedip_hive_ruleset_bot_signatures'         => '',
		'reportedip_hive_ruleset_disposable_domains'     => '',
		'reportedip_hive_ruleset_ua_blocklist'           => '',
		'reportedip_hive_ruleset_scan_paths'             => '',

		'reportedip_hive_waf_enabled'                    => true,
		'reportedip_hive_waf_report_only'                => false,
		'reportedip_hive_waf_paranoia'                   => 1,
		'reportedip_hive_waf_block_threshold'            => 3,
		'reportedip_hive_waf_dropin_enabled'             => false,
		'reportedip_hive_waf_dropin_path'                => '',
		'reportedip_hive_waf_dropin_server'              => '',

		'reportedip_hive_monitor_failed_logins'          => true,
		'reportedip_hive_failed_login_threshold'         => 5,
		'reportedip_hive_failed_login_timeframe'         => 15,
		'reportedip_hive_password_spray_threshold'       => 5,
		'reportedip_hive_password_spray_timeframe'       => 10,

		'reportedip_hive_monitor_comments'               => true,
		'reportedip_hive_comment_spam_threshold'         => 5,
		'reportedip_hive_comment_spam_timeframe'         => 60,
		'reportedip_hive_monitor_xmlrpc'                 => true,
		'reportedip_hive_xmlrpc_threshold'               => 10,
		'reportedip_hive_xmlrpc_timeframe'               => 60,
		'reportedip_hive_disable_xmlrpc_multicall'       => true,

		'reportedip_hive_monitor_app_passwords'          => true,
		'reportedip_hive_app_password_threshold'         => 5,
		'reportedip_hive_app_password_timeframe'         => 15,
		'reportedip_hive_app_password_require_2fa'       => true,

		'reportedip_hive_monitor_rest_api'               => true,
		'reportedip_hive_rest_threshold'                 => 240,
		'reportedip_hive_rest_timeframe'                 => 5,
		'reportedip_hive_rest_sensitive_threshold'       => 20,
		'reportedip_hive_rest_sensitive_timeframe'       => 5,

		'reportedip_hive_block_user_enumeration'         => true,
		'reportedip_hive_user_enum_threshold'            => 5,
		'reportedip_hive_user_enum_timeframe'            => 5,

		'reportedip_hive_monitor_404_scans'              => true,
		'reportedip_hive_scan_404_threshold'             => 12,
		'reportedip_hive_scan_404_timeframe'             => 2,

		'reportedip_hive_monitor_geo_anomaly'            => true,
		'reportedip_hive_geo_window_days'                => 90,
		'reportedip_hive_geo_revoke_trusted_devices'     => true,
		'reportedip_hive_geo_report_to_api'              => false,

		'reportedip_hive_monitor_woocommerce'            => true,
		'reportedip_hive_decoy_pathblock_enabled'        => true,
		'reportedip_hive_bot_allowlist_enabled'          => true,

		'reportedip_hive_auto_block'                     => true,
		'reportedip_hive_block_duration'                 => 24,
		'reportedip_hive_block_threshold'                => 75,
		'reportedip_hive_block_escalation_enabled'       => true,
		'reportedip_hive_block_ladder_minutes'           => '5,15,30,1440,2880,10080',
		'reportedip_hive_block_ladder_reset_days'        => 30,
		'reportedip_hive_blocked_page_contact_url'       => '',

		'reportedip_hive_hardening_duration_minutes'     => 60,
		'reportedip_hive_hardening_login_threshold'      => 2,
		'reportedip_hive_hardening_login_timeframe'      => 5,
		'reportedip_hive_hardening_block_threshold'      => 60,
		'reportedip_hive_hardening_realtime_detection'   => true,

		'reportedip_hive_hide_login_enabled'             => false,
		'reportedip_hive_hide_login_slug'                => '',
		'reportedip_hive_hide_login_response_mode'       => 'block_page',
		'reportedip_hive_hide_login_token_in_urls'       => false,
		'reportedip_hive_monitor_hide_login_probe'       => true,
		'reportedip_hive_hide_login_probe_threshold'     => 5,
		'reportedip_hive_hide_login_probe_timeframe'     => 10,

		'reportedip_hive_password_policy_enabled'        => true,
		'reportedip_hive_password_min_length'            => 12,
		'reportedip_hive_password_min_classes'           => 3,
		'reportedip_hive_password_check_hibp'            => true,
		'reportedip_hive_password_policy_all_users'      => false,

		'reportedip_hive_2fa_enabled_global'             => false,
		'reportedip_hive_2fa_allowed_methods'            => '["totp","email"]',
		'reportedip_hive_2fa_enforce_roles'              => '["administrator"]',
		'reportedip_hive_2fa_enforce_super_admins'       => true,
		'reportedip_hive_2fa_enforce_grace_days'         => 7,
		'reportedip_hive_2fa_max_skips'                  => 3,
		'reportedip_hive_2fa_trusted_devices'            => true,
		'reportedip_hive_2fa_trusted_device_days'        => 30,
		'reportedip_hive_2fa_extended_remember'          => false,
		'reportedip_hive_2fa_ip_allowlist'               => '',
		'reportedip_hive_2fa_branded_login'              => false,
		'reportedip_hive_2fa_notify_new_device'          => true,
		'reportedip_hive_2fa_xmlrpc_app_password_only'   => false,

		'reportedip_hive_2fa_email_subject'              => '',
		'reportedip_hive_2fa_email_subject_code'         => '',
		'reportedip_hive_2fa_email_body_code'            => '',

		'reportedip_hive_2fa_require_on_password_reset'  => true,
		'reportedip_hive_2fa_password_reset_excluded_methods' => '["email"]',
		'reportedip_hive_2fa_password_reset_block_email_only' => true,

		'reportedip_hive_2fa_frontend_enabled'           => false,
		'reportedip_hive_2fa_frontend_onboarding'        => true,
		'reportedip_hive_2fa_frontend_slug'              => 'reportedip-hive-2fa',
		'reportedip_hive_2fa_frontend_setup_slug'        => 'reportedip-hive-2fa-setup',
		'reportedip_hive_2fa_frontend_customer_optional' => true,
		'reportedip_hive_2fa_frontend_soft_disabled'     => 0,
		'reportedip_hive_wc2fa_promo_enabled'            => true,

		'reportedip_hive_notify_admin'                   => true,
		'reportedip_hive_notify_recipients'              => '',
		'reportedip_hive_notify_from_name'               => '',
		'reportedip_hive_notify_from_email'              => '',
		'reportedip_hive_notify_sync_to_api'             => false,
		'reportedip_hive_notification_cooldown_minutes'  => 60,
		'reportedip_hive_notify_event_cap_minutes'       => 15,

		'reportedip_hive_log_level'                      => 'info',
		'reportedip_hive_detailed_logging'               => false,
		'reportedip_hive_log_user_agents'                => false,
		'reportedip_hive_log_referer_domains'            => false,
		'reportedip_hive_minimal_logging'                => true,
		'reportedip_hive_data_retention_days'            => 30,
		'reportedip_hive_auto_anonymize_days'            => 7,
		'reportedip_hive_delete_data_on_uninstall'       => false,

		'reportedip_hive_enable_caching'                 => true,
		'reportedip_hive_cache_duration'                 => 24,
		'reportedip_hive_negative_cache_duration'        => 2,
		'reportedip_hive_queue_max_age_days'             => 7,
		'reportedip_hive_queue_warning_threshold'        => 50,
		'reportedip_hive_queue_critical_threshold'       => 200,
		'reportedip_hive_processing_timeout_minutes'     => 10,

		'reportedip_hive_auto_footer_enabled'            => false,
		'reportedip_hive_auto_footer_variant'            => 'badge',
		'reportedip_hive_auto_footer_align'              => 'center',
	);

	/**
	 * Wizard Step-3 detection-toggle keys (without the option prefix).
	 *
	 * The default ON/OFF value lives in `SAFE_OPTIONS` — the wizard reads it
	 * back through `wizard_protection_defaults()` so the two never drift.
	 *
	 * @var array<int, string>
	 */
	private const WIZARD_PROTECTION_KEYS = array(
		'monitor_failed_logins',
		'monitor_comments',
		'monitor_xmlrpc',
		'monitor_app_passwords',
		'monitor_rest_api',
		'block_user_enumeration',
		'monitor_404_scans',
		'monitor_geo_anomaly',
		'auto_block',
		'block_escalation_enabled',
		'report_only_mode',
	);

	/**
	 * Resolve the active notification recipient list.
	 *
	 * Reads the comma-separated `reportedip_hive_notify_recipients` option and
	 * filters every entry through `is_email()`. Falls back to the WordPress
	 * `admin_email` when the option is empty or fully invalid so existing call
	 * sites keep working.
	 *
	 * @return string[] Validated recipient addresses, never empty.
	 * @since  1.5.3
	 */
	public static function notify_recipients(): array {
		$raw   = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_recipients', '' );
		$parts = array_filter( array_map( 'trim', explode( ',', $raw ) ) );
		$valid = array();
		foreach ( $parts as $candidate ) {
			$clean = sanitize_email( $candidate );
			if ( '' !== $clean && is_email( $clean ) ) {
				$valid[] = $clean;
			}
		}
		if ( empty( $valid ) ) {
			$fallback = (string) get_option( 'admin_email', '' );
			if ( '' !== $fallback && is_email( $fallback ) ) {
				$valid[] = $fallback;
			}
		}
		return array_values( array_unique( $valid ) );
	}

	/**
	 * Brand default for the From-Name when no custom value is configured.
	 *
	 * Used as a last-resort fallback only — the regular default is the site's
	 * own bloginfo('name'), which makes the From line read like the user's
	 * site (e.g. "alre.de" instead of a generic "ReportedIP").
	 */
	public const NOTIFY_FROM_NAME_DEFAULT = 'ReportedIP';

	/**
	 * Computed default for the From-Name field — what the placeholder /
	 * settings UI should suggest when the user hasn't overridden the option.
	 *
	 * Uses the site's bloginfo('name') so plugin mails read like they came
	 * from the user's own site (e.g. "alre.de"). Falls back to the brand
	 * default ("ReportedIP") only when the site has no name set.
	 *
	 * @return string
	 */
	public static function notify_from_name_default(): string {
		$site_name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$site_name = trim( $site_name );
		return '' !== $site_name ? $site_name : self::NOTIFY_FROM_NAME_DEFAULT;
	}

	/**
	 * Resolve the active From: header components for outgoing mails.
	 *
	 * Reads `reportedip_hive_notify_from_name` and
	 * `reportedip_hive_notify_from_email`. Defaults are picked to make the
	 * mail look like it originated from the user's own site:
	 *   - name  → `get_bloginfo('name')` (e.g. "alre.de"), falls back to the
	 *             brand default if the site has no bloginfo name.
	 *   - email → WordPress `admin_email`. Note: when the relay is active,
	 *             the service overrides the envelope-from to noreply@reportedip.de
	 *             for SPF/DKIM alignment and only adopts the display name from
	 *             this header.
	 *
	 * @return array{name:string,email:string}
	 * @since  1.5.3
	 */
	public static function notify_from(): array {
		$name = trim( (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_from_name', '' ) );
		if ( '' === $name ) {
			$name = self::notify_from_name_default();
		}

		$email = sanitize_email( (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_from_email', '' ) );
		if ( '' === $email || ! is_email( $email ) ) {
			$email = (string) get_option( 'admin_email', '' );
		}

		return array(
			'name'  => $name,
			'email' => $email,
		);
	}

	/**
	 * Look up a single wizard-form default.
	 *
	 * Throws on an unknown key — defaults must be registered explicitly to
	 * avoid the "scattered default values" anti-pattern this class exists to
	 * solve.
	 *
	 * @param string $key Wizard default key.
	 * @return int|string
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
	 * Return the canonical option-key => default map.
	 *
	 * @return array<string, scalar>
	 * @since  2.0.2
	 */
	public static function all_option_defaults(): array {
		return self::SAFE_OPTIONS;
	}

	/**
	 * Back-compat alias for {@see all_option_defaults()}.
	 *
	 * @return array<string, scalar>
	 * @since  1.4.0
	 */
	public static function safe_options(): array {
		return self::SAFE_OPTIONS;
	}

	/**
	 * Seed every default that is not yet present, routed through
	 * `ReportedIP_Hive_Option_Routing` so network-wide keys land in sitemeta on
	 * Multisite instead of a single blog's options table. Existing values are
	 * never overwritten — this is the shared seeder for activation, the
	 * wizard-skip path and the settings-reset re-seed.
	 *
	 * @return void
	 * @since  2.0.2
	 */
	public static function seed_missing(): void {
		$sentinel = '__rip_hive_default_unset__';
		foreach ( self::SAFE_OPTIONS as $option_key => $default_value ) {
			if ( $sentinel !== ReportedIP_Hive_Option_Routing::get( $option_key, $sentinel ) ) {
				continue;
			}
			if ( is_bool( $default_value ) ) {
				$default_value = $default_value ? 1 : 0;
			}
			ReportedIP_Hive_Option_Routing::set( $option_key, $default_value );
		}
	}

	/**
	 * Wizard Step-3 fallback profile, derived from `SAFE_OPTIONS` so detection
	 * defaults stay in lockstep regardless of which surface a user reaches
	 * first (wizard, settings, fresh install).
	 *
	 * @return array<string, bool>
	 * @since  1.6.0
	 */
	public static function wizard_protection_defaults(): array {
		$defaults = array();
		foreach ( self::WIZARD_PROTECTION_KEYS as $key ) {
			$defaults[ $key ] = (bool) self::SAFE_OPTIONS[ 'reportedip_hive_' . $key ];
		}
		return $defaults;
	}
}
