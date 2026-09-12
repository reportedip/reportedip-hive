<?php
/**
 * Setup-wizard field schema — the single source of truth that maps every
 * wizard form field to its option key, type and sanitiser.
 *
 * The wizard JS collects each step's inputs generically and POSTs them to the
 * `reportedip_wizard_save_step` AJAX endpoint, which hands the step number and
 * payload to {@see save_step()}. Because render, collection and persistence
 * all flow through this one map, a field can never again be "rendered but
 * never saved" (the 1.x sessionStorage bug where the 2FA step silently
 * dropped every value).
 *
 * Step 8 (Hide Login) is intentionally NOT persisted here: its slug needs a
 * live uniqueness/blacklist validation + a rewrite flush, so the wizard owns
 * that one in `save_hide_login_step()`. Its fields still appear in
 * {@see fields()} for the drift test and inventory.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Declarative per-step field map + the typed save routine for the setup wizard.
 *
 * @since 2.0.2
 */
final class ReportedIP_Hive_Wizard_Schema {

	/**
	 * Steps that carry persisted form fields (Welcome/Connect/Done excluded).
	 *
	 * @var int[]
	 */
	const FIELD_STEPS = array( 3, 4, 5, 6, 7, 8, 9 );

	/**
	 * Steps whose fields {@see save_step()} persists generically. Step 8 is
	 * handled by the wizard itself (slug validation + rewrite flush).
	 *
	 * @var int[]
	 */
	const SAVE_STEPS = array( 3, 4, 5, 6, 7, 9 );

	/**
	 * Whether a step number carries persisted form fields.
	 *
	 * @param int $step Wizard step index.
	 * @return bool
	 */
	public static function is_field_step( $step ) {
		return in_array( (int) $step, self::FIELD_STEPS, true );
	}

	/**
	 * Field descriptors for a step.
	 *
	 * Each descriptor is `array{name:string, kind:string, option?:string, ...}`
	 * where `name` is the HTML/POST key, `kind` selects the sanitiser and
	 * `option` is the target option (absent for special multi-write kinds).
	 *
	 * @param int $step Wizard step index.
	 * @return array<int, array<string, mixed>>
	 */
	public static function fields( $step ) {
		switch ( (int) $step ) {
			case 3:
				return array_merge(
					array(
						array(
							'name' => 'protection_level',
							'kind' => 'preset',
						),
					),
					self::bool_fields(
						array(
							'monitor_failed_logins',
							'monitor_app_passwords',
							'block_user_enumeration',
							'monitor_comments',
							'monitor_xmlrpc',
							'monitor_rest_api',
							'monitor_404_scans',
							'monitor_geo_anomaly',
							'auto_block',
							'block_escalation_enabled',
							'report_only_mode',
						)
					)
				);
			case 4:
				return array(
					array(
						'name'   => 'waf_enabled',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_waf_enabled',
					),
					array(
						'name'   => 'waf_report_only',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_waf_report_only',
					),
					array(
						'name'   => 'bot_action',
						'kind'   => 'enum',
						'option' => 'reportedip_hive_bot_action',
					),
					array(
						'name'   => 'disposable_email_action',
						'kind'   => 'enum',
						'option' => 'reportedip_hive_disposable_email_action',
					),
					array(
						'name'   => 'comment_honeypot_enabled',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_comment_honeypot_enabled',
					),
					array(
						'name'   => 'registration_limit_enabled',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_registration_limit_enabled',
					),
					array(
						'name'   => 'disable_xmlrpc',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_disable_xmlrpc',
					),
					array(
						'name'   => 'disable_feeds',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_disable_feeds',
					),
					array(
						'name'   => 'hide_software_info',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_hide_software_info',
					),
				);
			case 5:
				return array(
					array(
						'name'   => '2fa_enabled_global',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_2fa_enabled_global',
					),
					array(
						'name'   => '2fa_methods',
						'kind'   => 'methods',
						'option' => 'reportedip_hive_2fa_allowed_methods',
					),
					array(
						'name'   => '2fa_enforce_role',
						'kind'   => 'roles',
						'option' => 'reportedip_hive_2fa_enforce_roles',
					),
					array(
						'name'   => '2fa_enforce_grace_days',
						'kind'   => 'int',
						'option' => 'reportedip_hive_2fa_enforce_grace_days',
					),
					array(
						'name'   => '2fa_max_skips',
						'kind'   => 'int',
						'option' => 'reportedip_hive_2fa_max_skips',
					),
					array(
						'name'   => '2fa_trusted_devices',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_2fa_trusted_devices',
					),
					array(
						'name'   => '2fa_frontend_onboarding',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_2fa_frontend_onboarding',
					),
					array(
						'name'   => '2fa_notify_new_device',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_2fa_notify_new_device',
					),
					array(
						'name'   => '2fa_xmlrpc_app_password_only',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_2fa_xmlrpc_app_password_only',
					),
					array(
						'name'   => '2fa_policy_new_country',
						'kind'   => 'json_list',
						'option' => 'reportedip_hive_2fa_policy_new_country',
					),
					array(
						'name'   => '2fa_policy_new_device',
						'kind'   => 'json_list',
						'option' => 'reportedip_hive_2fa_policy_new_device',
					),
					array(
						'name'   => '2fa_frontend_enabled',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_2fa_frontend_enabled',
					),
				);
			case 6:
				return array(
					array(
						'name'   => 'minimal_logging',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_minimal_logging',
					),
					array(
						'name'   => 'data_retention_days',
						'kind'   => 'int',
						'option' => 'reportedip_hive_data_retention_days',
					),
					array(
						'name'   => 'auto_anonymize_days',
						'kind'   => 'int',
						'option' => 'reportedip_hive_auto_anonymize_days',
					),
					array(
						'name'   => 'log_user_agents',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_log_user_agents',
					),
					array(
						'name'   => 'log_referer_domains',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_log_referer_domains',
					),
					array(
						'name'   => 'delete_data_on_uninstall',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_delete_data_on_uninstall',
					),
				);
			case 7:
				return array(
					array(
						'name'   => 'notify_admin',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_notify_admin',
					),
					array(
						'name'   => 'recipients',
						'kind'   => 'email_list',
						'option' => 'reportedip_hive_notify_recipients',
					),
					array(
						'name'   => 'from_name',
						'kind'   => 'text',
						'option' => 'reportedip_hive_notify_from_name',
					),
					array(
						'name'   => 'from_email',
						'kind'   => 'email',
						'option' => 'reportedip_hive_notify_from_email',
					),
					array(
						'name'   => 'sync_to_api',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_notify_sync_to_api',
					),
				);
			case 8:
				return array(
					array(
						'name'   => 'hide_login_enabled',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_hide_login_enabled',
					),
					array(
						'name'   => 'hide_login_slug',
						'kind'   => 'slug',
						'option' => 'reportedip_hive_hide_login_slug',
					),
					array(
						'name'   => 'hide_login_response_mode',
						'kind'   => 'enum',
						'option' => 'reportedip_hive_hide_login_response_mode',
					),
				);
			case 9:
				return array(
					array(
						'name'   => 'promote_enabled',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_auto_footer_enabled',
					),
					array(
						'name'   => 'promote_variant',
						'kind'   => 'enum',
						'option' => 'reportedip_hive_auto_footer_variant',
					),
					array(
						'name'   => 'promote_align',
						'kind'   => 'enum',
						'option' => 'reportedip_hive_auto_footer_align',
					),
				);
			default:
				return array();
		}
	}

	/**
	 * Protection-level presets shared by the wizard. Each level sets four base
	 * thresholds in one move.
	 *
	 * @return array<string, array<string, int>>
	 */
	public static function protection_presets() {
		return array(
			'low'      => array(
				'failed_login_threshold' => 10,
				'failed_login_timeframe' => 30,
				'block_duration'         => 1,
				'block_threshold'        => 90,
			),
			'medium'   => array(
				'failed_login_threshold' => 5,
				'failed_login_timeframe' => 15,
				'block_duration'         => 24,
				'block_threshold'        => 75,
			),
			'high'     => array(
				'failed_login_threshold' => 3,
				'failed_login_timeframe' => 15,
				'block_duration'         => 48,
				'block_threshold'        => 60,
			),
			'paranoid' => array(
				'failed_login_threshold' => 2,
				'failed_login_timeframe' => 10,
				'block_duration'         => 168,
				'block_threshold'        => 25,
			),
		);
	}

	/**
	 * Persist every field of a step from its POST payload.
	 *
	 * Only the fields declared for the step are touched, so a step the user
	 * never reached keeps its seeded defaults — there is no global `isset()`
	 * sweep that silently rewrites everything to hard-coded fallbacks.
	 *
	 * @param int                  $step Wizard step index (must be in SAVE_STEPS).
	 * @param array<string, mixed> $post Raw `$_POST` payload (already nonce-checked by the caller).
	 * @return void
	 */
	public static function save_step( $step, array $post ) {
		$step = (int) $step;
		if ( ! in_array( $step, self::SAVE_STEPS, true ) ) {
			return;
		}
		foreach ( self::fields( $step ) as $field ) {
			self::persist_field( $field, $post );
		}
	}

	/**
	 * Build a list of boolean field descriptors from bare option suffixes.
	 *
	 * @param string[] $names Field names (also the option suffix after the prefix).
	 * @return array<int, array<string, string>>
	 */
	private static function bool_fields( array $names ) {
		$out = array();
		foreach ( $names as $name ) {
			$out[] = array(
				'name'   => $name,
				'kind'   => 'bool',
				'option' => 'reportedip_hive_' . $name,
			);
		}
		return $out;
	}

	/**
	 * Sanitise and persist a single field descriptor.
	 *
	 * Generic kinds run through {@see ReportedIP_Hive_Settings_Registry::sanitize()},
	 * so the registry's ranges, allowed values, custom sanitizers and tier
	 * gates apply to the wizard exactly as they do to the settings page and
	 * the remote transports. The one wizard field outside the registry
	 * (`delete_data_on_uninstall`, deliberately never remote) uses the plain
	 * kind sanitizer. A rejected enum or bool falls back to its default;
	 * anything else is left untouched.
	 *
	 * @param array<string, mixed> $field Descriptor from {@see fields()}.
	 * @param array<string, mixed> $post  Raw POST payload.
	 * @return void
	 */
	private static function persist_field( array $field, array $post ) {
		$name   = (string) $field['name'];
		$option = isset( $field['option'] ) ? (string) $field['option'] : '';

		switch ( $field['kind'] ) {
			case 'bool':
				$raw = ! empty( $post[ $name ] );
				break;

			case 'int':
			case 'enum':
			case 'text':
			case 'email':
			case 'email_list':
				$raw = isset( $post[ $name ] ) && is_scalar( $post[ $name ] ) ? wp_unslash( (string) $post[ $name ] ) : '';
				break;

			case 'methods':
				ReportedIP_Hive_Option_Routing::set( $option, wp_json_encode( self::sanitize_methods( $post ) ) );
				return;

			case 'roles':
				ReportedIP_Hive_Option_Routing::set( $option, wp_json_encode( self::sanitize_roles( $post ) ) );
				return;

			case 'json_list':
				$raw = isset( $post[ $name ] ) && is_array( $post[ $name ] ) ? wp_unslash( $post[ $name ] ) : array();
				break;

			case 'preset':
				self::apply_protection_preset( isset( $post[ $name ] ) ? (string) $post[ $name ] : 'medium' );
				return;

			default:
				return;
		}

		$spec  = ReportedIP_Hive_Settings_Registry::spec();
		$value = isset( $spec[ $option ] )
			? ReportedIP_Hive_Settings_Registry::sanitize( $option, $raw )
			: ReportedIP_Hive_Settings_Registry::sanitize_kind( (string) $field['kind'], $raw, $field );
		if ( is_wp_error( $value ) ) {
			$defaults = ReportedIP_Hive_Defaults::all_option_defaults();
			if ( ! in_array( $field['kind'], array( 'enum', 'bool' ), true ) || ! array_key_exists( $option, $defaults ) ) {
				return;
			}
			$value = $defaults[ $option ];
		}
		ReportedIP_Hive_Option_Routing::set( $option, $value );
	}

	/**
	 * Intersect the posted comma-separated methods with the valid set, falling
	 * back to TOTP + Email when nothing usable remains. The valid-method
	 * allow-list is owned by {@see ReportedIP_Hive_Two_Factor::filter_valid_methods()}.
	 *
	 * @param array<string, mixed> $post POST payload.
	 * @return string[]
	 */
	private static function sanitize_methods( array $post ) {
		$raw     = isset( $post['2fa_methods'] ) ? sanitize_text_field( wp_unslash( (string) $post['2fa_methods'] ) ) : 'totp,email';
		$methods = ReportedIP_Hive_Two_Factor::filter_valid_methods( array_map( 'trim', explode( ',', $raw ) ) );
		if ( empty( $methods ) ) {
			$methods = array( 'totp', 'email' );
		}
		return $methods;
	}

	/**
	 * Intersect posted enforce-roles with the real role list (via
	 * {@see ReportedIP_Hive_Two_Factor::filter_valid_roles()}). When 2FA is on
	 * but no role was picked, fall back to administrator so enforcement is
	 * never silently empty.
	 *
	 * @param array<string, mixed> $post POST payload.
	 * @return string[]
	 */
	private static function sanitize_roles( array $post ) {
		$posted   = isset( $post['2fa_enforce_role'] ) && is_array( $post['2fa_enforce_role'] )
			? array_map( 'sanitize_text_field', wp_unslash( $post['2fa_enforce_role'] ) )
			: array();
		$enforced = ReportedIP_Hive_Two_Factor::filter_valid_roles( $posted );
		if ( ! empty( $post['2fa_enabled_global'] ) && empty( $enforced ) ) {
			$enforced = array( 'administrator' );
		}
		return $enforced;
	}

	/**
	 * Expand a protection-level preset into the four base threshold options.
	 *
	 * @param string $level Posted level slug.
	 * @return void
	 */
	private static function apply_protection_preset( $level ) {
		$presets = self::protection_presets();
		$level   = isset( $presets[ $level ] ) ? $level : 'medium';
		$preset  = $presets[ $level ];

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_failed_login_threshold', $preset['failed_login_threshold'] );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_failed_login_timeframe', $preset['failed_login_timeframe'] );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_block_duration', $preset['block_duration'] );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_block_threshold', $preset['block_threshold'] );
	}
}
