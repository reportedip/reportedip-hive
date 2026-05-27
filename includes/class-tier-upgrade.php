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
	 * @param string $next New tier slug.
	 * @return void
	 */
	public static function on_tier_changed( $prev, $next ) {
		$prev = (string) $prev;
		$next = (string) $next;

		if ( self::is_upgrade_to_pro( $prev, $next ) ) {
			self::handle_upgrade_to_pro( $prev, $next );
			return;
		}
		if ( self::is_downgrade_from_pro( $prev, $next ) ) {
			self::handle_downgrade_from_pro( $prev, $next );
		}
	}

	/**
	 * Upgrade path: pre-fill the managed relay defaults, store the post-upgrade
	 * setup-banner payload, reset every administrator's promo state (so the
	 * upgrade banner is not blocked by a stale global cap) and send a factual
	 * welcome mail to the admin recipient list.
	 *
	 * @param string $prev
	 * @param string $next
	 * @return void
	 * @since  2.0.16
	 */
	private static function handle_upgrade_to_pro( $prev, $next ) {
		if ( '' === (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_sms_provider', '' ) ) {
			ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_2fa_sms_provider', self::PROVIDER_RELAY );
		}

		self::ensure_email_in_allowed_methods();

		ReportedIP_Hive_Option_Routing::set(
			self::NOTICE_OPT,
			array(
				'from'   => $prev,
				'to'     => $next,
				'set_at' => time(),
			)
		);

		ReportedIP_Hive_Option_Routing::delete( self::NOTICE_DISMISSED );

		self::reset_promo_state_for_admins();
		self::send_tier_change_mail( $prev, $next, true );
	}

	/**
	 * Downgrade path: clear the stale post-upgrade banner state, soft-disable
	 * the WooCommerce Frontend-2FA toggle (the option is preserved so a future
	 * re-upgrade is seamless — the gate in {@see ReportedIP_Hive_Two_Factor_Frontend}
	 * blocks the UI anyway via `feature_status('frontend_2fa')`), and send a
	 * factual goodbye mail.
	 *
	 * Local protection (12 sensors, full 2FA suite, blocked-IP enforcement) is
	 * deliberately not touched — the Marketing-Story §7 promise holds.
	 *
	 * @param string $prev
	 * @param string $next
	 * @return void
	 * @since  2.0.16
	 */
	private static function handle_downgrade_from_pro( $prev, $next ) {
		ReportedIP_Hive_Option_Routing::delete( self::NOTICE_OPT );
		ReportedIP_Hive_Option_Routing::delete( self::NOTICE_DISMISSED );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_2fa_frontend_enabled', 0 );

		self::send_tier_change_mail( $prev, $next, false );
	}

	/**
	 * Whether the transition is a Free/Contributor → PRO/Business/Enterprise upgrade.
	 *
	 * Pure function — also used by the unit tests.
	 *
	 * @param string $prev Previous tier slug.
	 * @param string $next New tier slug.
	 * @return bool
	 */
	public static function is_upgrade_to_pro( $prev, $next ) {
		return in_array( $prev, self::FREE_TIERS, true )
			&& in_array( $next, self::PAID_TIERS, true );
	}

	/**
	 * Whether the transition is a PRO/Business/Enterprise → Free/Contributor downgrade.
	 *
	 * @param string $prev Previous tier slug.
	 * @param string $next New tier slug.
	 * @return bool
	 * @since  2.0.16
	 */
	public static function is_downgrade_from_pro( $prev, $next ) {
		return in_array( $prev, self::PAID_TIERS, true )
			&& in_array( $next, self::FREE_TIERS, true );
	}

	/**
	 * Reset {@see ReportedIP_Hive_Promo_Manager} state for every administrator
	 * — bounded to 200 admins so a large network never trips a timeout. The
	 * permanent opt-out map is preserved (explicit user choice).
	 *
	 * @return void
	 */
	private static function reset_promo_state_for_admins() {
		if ( ! class_exists( 'ReportedIP_Hive_Promo_Manager' ) ) {
			return;
		}
		$admin_ids = get_users(
			array(
				'role'   => 'administrator',
				'fields' => 'ID',
				'number' => 200,
			)
		);
		foreach ( (array) $admin_ids as $user_id ) {
			ReportedIP_Hive_Promo_Manager::reset_for_user( (int) $user_id );
		}
	}

	/**
	 * Send the factual tier-change mail (welcome on upgrade, goodbye on
	 * downgrade). Suppressible via the `reportedip_hive_tier_change_mail_enabled`
	 * option from Settings → Notifications.
	 *
	 * @param string $prev
	 * @param string $next
	 * @param bool   $is_upgrade
	 * @return void
	 */
	private static function send_tier_change_mail( $prev, $next, $is_upgrade ) {
		if ( ! (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_tier_change_mail_enabled', true ) ) {
			return;
		}
		if ( ! class_exists( 'ReportedIP_Hive_Mailer' ) || ! class_exists( 'ReportedIP_Hive_Defaults' ) ) {
			return;
		}
		$recipients = ReportedIP_Hive_Defaults::notify_recipients();
		if ( empty( $recipients ) ) {
			return;
		}

		$site_name  = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$tier_label = ucfirst( $is_upgrade ? $next : $prev );

		if ( $is_upgrade ) {
			$subject = sprintf(
				/* translators: 1: site name, 2: new tier label */
				__( '[%1$s] %2$s plan is active', 'reportedip-hive' ),
				$site_name,
				$tier_label
			);
			$intro = sprintf(
				/* translators: %s = tier label */
				__( 'Your %s plan is now active. The managed mail and SMS relay is included; the SMS provider has been prefilled for you.', 'reportedip-hive' ),
				$tier_label
			);
			$body = __( 'Open the Hive dashboard to finish the small remaining setup steps (AVV confirmation, enable SMS as a 2FA method).', 'reportedip-hive' );
		} else {
			$subject = sprintf(
				/* translators: %s = site name */
				__( '[%s] Plan switched back to Free', 'reportedip-hive' ),
				$site_name
			);
			$intro = __( 'Your subscription was switched back to the Free tier.', 'reportedip-hive' );
			$body  = __( 'What stays active: all 12 sensors, the full 2FA suite and your local IP/block list. What pauses: managed mail/SMS relay over reportedip.de and cloud backup. You can re-activate any time from the customer portal — your data and settings remain in place.', 'reportedip-hive' );
		}

		$portal_url = defined( 'REPORTEDIP_HIVE_UPGRADE_URL' )
			? REPORTEDIP_HIVE_UPGRADE_URL
			: 'https://reportedip.de/dashboard/';

		ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => implode( ', ', $recipients ),
				'subject'         => $subject,
				'intro'           => $intro,
				'main_block_html' => '<p>' . esc_html( $body ) . '</p>',
				'main_block_text' => $body,
				'cta'             => array(
					'label' => $is_upgrade
						? __( 'Open Hive dashboard', 'reportedip-hive' )
						: __( 'Open customer portal', 'reportedip-hive' ),
					'url'   => $is_upgrade ? admin_url( 'admin.php?page=reportedip-hive' ) : $portal_url,
				),
				'context'         => array(
					'kind' => $is_upgrade ? 'tier_welcome' : 'tier_goodbye',
					'from' => $prev,
					'to'   => $next,
				),
			)
		);
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
		if ( (bool) ReportedIP_Hive_Option_Routing::get( self::NOTICE_DISMISSED, false ) ) {
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
		$raw = ReportedIP_Hive_Option_Routing::get( self::NOTICE_OPT, null );
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
		$provider = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_sms_provider', '' );
		$avv      = false;
		if ( class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
			$avv = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Two_Factor_SMS::OPT_AVV_CONFIRMED, false );
		} else {
			$avv = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_sms_avv_confirmed', false );
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

		ReportedIP_Hive_Option_Routing::set( self::NOTICE_DISMISSED, true );
		ReportedIP_Hive_Option_Routing::delete( self::NOTICE_OPT );

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
		$raw     = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_allowed_methods', '["totp","email"]' );
		$decoded = json_decode( (string) $raw, true );
		if ( ! is_array( $decoded ) ) {
			$decoded = array( 'totp', 'email' );
		}
		if ( in_array( 'email', $decoded, true ) ) {
			return;
		}
		$decoded[] = 'email';
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_2fa_allowed_methods', wp_json_encode( array_values( $decoded ) ) );
	}

	/**
	 * Whether a 2FA method id appears in the site-wide allow-list.
	 *
	 * @param string $method_id 'totp' | 'email' | 'sms' | 'webauthn'.
	 * @return bool
	 */
	private static function is_method_in_allowed_list( $method_id ) {
		$raw     = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_allowed_methods', '["totp","email"]' );
		$decoded = json_decode( (string) $raw, true );
		if ( ! is_array( $decoded ) ) {
			return false;
		}
		return in_array( $method_id, $decoded, true );
	}
}
