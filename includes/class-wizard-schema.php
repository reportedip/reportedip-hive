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
 * Step 7 (Hide Login) is intentionally NOT persisted here: its slug needs a
 * live uniqueness/blacklist validation + a rewrite flush, so the wizard owns
 * that one in `save_hide_login_step()`. Its fields still appear in
 * {@see fields()} for the drift test and inventory.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
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
	const FIELD_STEPS = array( 3, 4, 5, 6, 7, 8 );

	/**
	 * Steps whose fields {@see save_step()} persists generically. Step 7 is
	 * handled by the wizard itself (slug validation + rewrite flush).
	 *
	 * @var int[]
	 */
	const SAVE_STEPS = array( 3, 4, 5, 6, 8 );

	/**
	 * The 2FA methods a site may offer.
	 *
	 * @var string[]
	 */
	const VALID_METHODS = array( 'totp', 'email', 'webauthn', 'sms' );

	/**
	 * Option key for the WooCommerce Frontend-2FA master toggle.
	 */
	const OPT_FRONTEND_ENABLED = 'reportedip_hive_2fa_frontend_enabled';

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
						'min'    => 0,
						'max'    => 60,
					),
					array(
						'name'   => '2fa_max_skips',
						'kind'   => 'int',
						'option' => 'reportedip_hive_2fa_max_skips',
						'min'    => 0,
						'max'    => 20,
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
						'name'   => '2fa_frontend_enabled',
						'kind'   => 'frontend_2fa',
						'option' => self::OPT_FRONTEND_ENABLED,
					),
				);
			case 5:
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
						'min'    => 7,
						'max'    => 365,
					),
					array(
						'name'   => 'auto_anonymize_days',
						'kind'   => 'int',
						'option' => 'reportedip_hive_auto_anonymize_days',
						'min'    => 1,
						'max'    => 90,
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
			case 6:
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
			case 7:
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
						'name'    => 'hide_login_response_mode',
						'kind'    => 'enum',
						'option'  => 'reportedip_hive_hide_login_response_mode',
						'allowed' => array( 'block_page', '404' ),
					),
				);
			case 8:
				return array(
					array(
						'name'   => 'promote_enabled',
						'kind'   => 'bool',
						'option' => 'reportedip_hive_auto_footer_enabled',
					),
					array(
						'name'   => 'promote_variant',
						'kind'   => 'footer_variant',
						'option' => 'reportedip_hive_auto_footer_variant',
					),
					array(
						'name'   => 'promote_align',
						'kind'   => 'footer_align',
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
				'block_threshold'        => 50,
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
	 * @param array<string, mixed> $field Descriptor from {@see fields()}.
	 * @param array<string, mixed> $post  Raw POST payload.
	 * @return void
	 */
	private static function persist_field( array $field, array $post ) {
		$name   = (string) $field['name'];
		$option = isset( $field['option'] ) ? (string) $field['option'] : '';

		switch ( $field['kind'] ) {
			case 'bool':
				ReportedIP_Hive_Option_Routing::set( $option, ! empty( $post[ $name ] ) );
				break;

			case 'int':
				$value = isset( $post[ $name ] ) ? absint( $post[ $name ] ) : (int) $field['min'];
				$value = max( (int) $field['min'], min( (int) $field['max'], $value ) );
				ReportedIP_Hive_Option_Routing::set( $option, $value );
				break;

			case 'enum':
				$value   = isset( $post[ $name ] ) ? sanitize_key( wp_unslash( (string) $post[ $name ] ) ) : '';
				$allowed = (array) $field['allowed'];
				if ( ! in_array( $value, $allowed, true ) ) {
					$value = (string) $allowed[0];
				}
				ReportedIP_Hive_Option_Routing::set( $option, $value );
				break;

			case 'text':
				$value = isset( $post[ $name ] ) ? sanitize_text_field( wp_unslash( (string) $post[ $name ] ) ) : '';
				ReportedIP_Hive_Option_Routing::set( $option, $value );
				break;

			case 'email':
				$value = isset( $post[ $name ] ) ? sanitize_email( wp_unslash( (string) $post[ $name ] ) ) : '';
				if ( '' !== $value && ! is_email( $value ) ) {
					$value = '';
				}
				ReportedIP_Hive_Option_Routing::set( $option, $value );
				break;

			case 'email_list':
				ReportedIP_Hive_Option_Routing::set( $option, self::sanitize_email_list( isset( $post[ $name ] ) ? (string) $post[ $name ] : '' ) );
				break;

			case 'methods':
				ReportedIP_Hive_Option_Routing::set( $option, wp_json_encode( self::sanitize_methods( $post ) ) );
				break;

			case 'roles':
				ReportedIP_Hive_Option_Routing::set( $option, wp_json_encode( self::sanitize_roles( $post ) ) );
				break;

			case 'preset':
				self::apply_protection_preset( isset( $post[ $name ] ) ? (string) $post[ $name ] : 'medium' );
				break;

			case 'footer_variant':
				$raw   = isset( $post[ $name ] ) ? sanitize_key( wp_unslash( (string) $post[ $name ] ) ) : 'badge';
				$value = class_exists( 'ReportedIP_Hive_Frontend_Shortcodes' )
					? ReportedIP_Hive_Frontend_Shortcodes::sanitize_footer_variant( $raw )
					: ( 'shield' === $raw ? 'shield' : 'badge' );
				ReportedIP_Hive_Option_Routing::set( $option, $value );
				break;

			case 'footer_align':
				$raw   = isset( $post[ $name ] ) ? sanitize_key( wp_unslash( (string) $post[ $name ] ) ) : 'center';
				$value = in_array( $raw, array( 'left', 'center', 'right', 'below' ), true ) ? $raw : 'center';
				ReportedIP_Hive_Option_Routing::set( $option, $value );
				break;

			case 'frontend_2fa':
				self::persist_frontend_2fa( $option, ! empty( $post[ $name ] ) );
				break;
		}
	}

	/**
	 * Intersect the posted comma-separated methods with the valid set, falling
	 * back to TOTP + Email when nothing usable remains.
	 *
	 * @param array<string, mixed> $post POST payload.
	 * @return string[]
	 */
	private static function sanitize_methods( array $post ) {
		$raw     = isset( $post['2fa_methods'] ) ? sanitize_text_field( wp_unslash( (string) $post['2fa_methods'] ) ) : 'totp,email';
		$methods = array_values( array_intersect( array_map( 'trim', explode( ',', $raw ) ), self::VALID_METHODS ) );
		if ( empty( $methods ) ) {
			$methods = array( 'totp', 'email' );
		}
		return $methods;
	}

	/**
	 * Intersect posted enforce-roles with the real role list. When 2FA is on
	 * but no role was picked, fall back to administrator so enforcement is
	 * never silently empty.
	 *
	 * @param array<string, mixed> $post POST payload.
	 * @return string[]
	 */
	private static function sanitize_roles( array $post ) {
		$valid    = function_exists( 'wp_roles' ) ? array_keys( wp_roles()->get_names() ) : array();
		$posted   = isset( $post['2fa_enforce_role'] ) && is_array( $post['2fa_enforce_role'] )
			? array_map( 'sanitize_text_field', wp_unslash( $post['2fa_enforce_role'] ) )
			: array();
		$enforced = array_values( array_intersect( $posted, $valid ) );
		if ( ! empty( $post['2fa_enabled_global'] ) && empty( $enforced ) ) {
			$enforced = array( 'administrator' );
		}
		return $enforced;
	}

	/**
	 * Parse a free-form recipient list (commas, spaces or newlines) into a
	 * validated, de-duplicated, comma-separated string.
	 *
	 * @param string $raw Raw textarea value.
	 * @return string
	 */
	private static function sanitize_email_list( $raw ) {
		$raw        = sanitize_textarea_field( wp_unslash( (string) $raw ) );
		$candidates = array_filter( array_map( 'trim', preg_split( '/[\s,;]+/', $raw ) ) );
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

	/**
	 * Persist the WooCommerce Frontend-2FA toggle, refusing to enable it below
	 * the Professional tier, and flush rewrite rules when the state flips.
	 *
	 * @param string $option  Target option key.
	 * @param bool   $desired Whether the admin asked for it to be on.
	 * @return void
	 */
	private static function persist_frontend_2fa( $option, $desired ) {
		if ( $desired && class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'frontend_2fa' );
			if ( empty( $status['available'] ) ) {
				$desired = false;
			}
		}

		$was_on = (bool) ReportedIP_Hive_Option_Routing::get( $option, false );
		ReportedIP_Hive_Option_Routing::set( $option, $desired ? '1' : '' );

		if ( $was_on !== $desired ) {
			if ( class_exists( 'ReportedIP_Hive_Two_Factor_Frontend' ) ) {
				ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
			}
			if ( function_exists( 'flush_rewrite_rules' ) ) {
				flush_rewrite_rules( false );
			}
		}
	}
}
