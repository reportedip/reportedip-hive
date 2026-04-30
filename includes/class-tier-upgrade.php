<?php
/**
 * Tier-upgrade helper: soft-activates managed-relay defaults and tracks the
 * one-time setup banner shown after a Free/Contributor → PRO+ promotion.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.7.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Listens on `reportedip_hive_tier_changed`. When the customer crosses from a
 * free tier into a paid plan, prefills the SMS provider with the managed
 * relay (only if no provider was set yet), ensures the email method is in the
 * site-wide allow-list, and stores a notice payload that the admin banner
 * renders until the customer either finishes the setup or dismisses it.
 *
 * Public API is fully static — no singleton state required.
 *
 * @since 1.7.0
 */
class ReportedIP_Hive_Tier_Upgrade {

	/**
	 * Option key for the "you've upgraded — finish 2FA setup" notice payload.
	 *
	 * Payload shape: `array{from:string,to:string,set_at:int}`.
	 */
	const NOTICE_OPT = 'reportedip_hive_tier_upgrade_notice';

	/**
	 * Option key set when the admin clicks "Dismiss" on the banner.
	 * Also cleared after the checklist is fully done so a future upgrade
	 * can show a fresh banner.
	 */
	const NOTICE_DISMISSED = 'reportedip_hive_tier_upgrade_dismissed';

	/**
	 * Provider id used for the managed reportedip.de SMS gateway.
	 */
	const PROVIDER_RELAY = 'reportedip_relay';

	/**
	 * Tier slugs that are considered "free" for upgrade detection purposes.
	 *
	 * @var string[]
	 */
	const FREE_TIERS = array( 'free', 'contributor' );

	/**
	 * Tier slugs that count as "paid" — crossing into one of these from a
	 * free tier triggers the welcome banner.
	 *
	 * @var string[]
	 */
	const PAID_TIERS = array( 'professional', 'business', 'enterprise' );

	/**
	 * Wire the WordPress hooks. Idempotent — safe to call multiple times.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'reportedip_hive_tier_changed', array( __CLASS__, 'on_tier_changed' ), 20, 2 );
		add_action( 'admin_post_reportedip_hive_dismiss_tier_notice', array( __CLASS__, 'handle_dismiss' ) );
	}

	/**
	 * Hook callback: react to a tier transition.
	 *
	 * @param string $prev Previous tier slug (free / contributor / professional / …).
	 * @param string $new  New tier slug.
	 * @return void
	 */
	public static function on_tier_changed( $prev, $new ) {
		if ( ! self::is_upgrade_to_pro( (string) $prev, (string) $new ) ) {
			return;
		}

		if ( '' === (string) get_option( 'reportedip_hive_2fa_sms_provider', '' ) ) {
			update_option( 'reportedip_hive_2fa_sms_provider', self::PROVIDER_RELAY );
		}

		self::ensure_email_in_allowed_methods();

		update_option(
			self::NOTICE_OPT,
			array(
				'from'   => (string) $prev,
				'to'     => (string) $new,
				'set_at' => time(),
			)
		);

		delete_option( self::NOTICE_DISMISSED );
	}

	/**
	 * Whether the transition is a Free/Contributor → PRO/Business/Enterprise upgrade.
	 *
	 * Pure function — also used by the unit tests.
	 *
	 * @param string $prev Previous tier slug.
	 * @param string $new  New tier slug.
	 * @return bool
	 */
	public static function is_upgrade_to_pro( $prev, $new ) {
		return in_array( $prev, self::FREE_TIERS, true )
			&& in_array( $new, self::PAID_TIERS, true );
	}

	/**
	 * Should the welcome banner render right now?
	 *
	 * Returns true when:
	 *  - a notice payload exists,
	 *  - the customer has not dismissed it,
	 *  - and at least one checklist item is still open.
	 *
	 * @return bool
	 */
	public static function should_show_notice() {
		if ( ! self::get_notice() ) {
			return false;
		}
		if ( (bool) get_option( self::NOTICE_DISMISSED, false ) ) {
			return false;
		}

		foreach ( self::get_setup_checklist() as $item ) {
			if ( empty( $item['done'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Read the notice payload (or null when none).
	 *
	 * @return array{from:string,to:string,set_at:int}|null
	 */
	public static function get_notice() {
		$raw = get_option( self::NOTICE_OPT, null );
		return is_array( $raw ) ? $raw : null;
	}

	/**
	 * Three-step setup checklist for the post-upgrade banner.
	 *
	 * Each entry is `array{key:string,label:string,done:bool}` so the
	 * renderer can mark ✓/⬜ without re-implementing the conditions.
	 *
	 * @return array<int,array{key:string,label:string,done:bool}>
	 */
	public static function get_setup_checklist() {
		$provider = (string) get_option( 'reportedip_hive_2fa_sms_provider', '' );
		$avv      = false;
		if ( class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
			$avv = (bool) get_option( ReportedIP_Hive_Two_Factor_SMS::OPT_AVV_CONFIRMED, false );
		} else {
			$avv = (bool) get_option( 'reportedip_hive_2fa_sms_avv_confirmed', false );
		}
		$method_active = self::is_method_in_allowed_list( 'sms' );

		return array(
			array(
				'key'   => 'provider',
				'label' => __( 'Managed SMS provider selected', 'reportedip-hive' ),
				'done'  => ( self::PROVIDER_RELAY === $provider ),
			),
			array(
				'key'   => 'avv',
				'label' => __( 'ReportedIP AVV confirmed on the 2FA settings tab', 'reportedip-hive' ),
				'done'  => $avv,
			),
			array(
				'key'   => 'method',
				'label' => __( 'SMS code enabled as a 2FA method', 'reportedip-hive' ),
				'done'  => $method_active,
			),
		);
	}

	/**
	 * POST-handler for the "Dismiss" button.
	 *
	 * @return void
	 */
	public static function handle_dismiss() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Permission denied.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'reportedip_hive_dismiss_tier_notice' );

		update_option( self::NOTICE_DISMISSED, true );
		delete_option( self::NOTICE_OPT );

		$redirect = wp_get_referer();
		if ( ! $redirect ) {
			$redirect = admin_url( 'admin.php?page=reportedip-hive' );
		}
		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * Ensure the email method is part of the site-wide allow-list option.
	 * No-op if it is already in there.
	 *
	 * @return void
	 */
	private static function ensure_email_in_allowed_methods() {
		$raw     = get_option( 'reportedip_hive_2fa_allowed_methods', '["totp","email"]' );
		$decoded = json_decode( (string) $raw, true );
		if ( ! is_array( $decoded ) ) {
			$decoded = array( 'totp', 'email' );
		}
		if ( in_array( 'email', $decoded, true ) ) {
			return;
		}
		$decoded[] = 'email';
		update_option( 'reportedip_hive_2fa_allowed_methods', wp_json_encode( array_values( $decoded ) ) );
	}

	/**
	 * Whether a 2FA method id appears in the site-wide allow-list.
	 *
	 * @param string $method_id 'totp' | 'email' | 'sms' | 'webauthn'.
	 * @return bool
	 */
	private static function is_method_in_allowed_list( $method_id ) {
		$raw     = get_option( 'reportedip_hive_2fa_allowed_methods', '["totp","email"]' );
		$decoded = json_decode( (string) $raw, true );
		if ( ! is_array( $decoded ) ) {
			return false;
		}
		return in_array( $method_id, $decoded, true );
	}
}
