<?php
/**
 * Promo banner that nudges Free / Contributor admins of WooCommerce stores
 * to consider the Frontend-2FA feature included with the Professional tier.
 *
 * Frequency, killswitch and dismiss persistence are delegated to
 * {@see ReportedIP_Hive_Promo_Manager} so this banner stays in lockstep with
 * every other Pro-promo surface (max one promo touch per ~90 days per admin
 * across all surfaces; 60-day cooldown after a dismiss).
 *
 * The render itself only fires when {@see ReportedIP_Hive_Mode_Manager}'s
 * `feature_status('frontend_2fa')` returns `reason=tier`. As soon as the
 * operator upgrades, the gate flips to `available` and the banner stays
 * silent without manual cleanup.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.7.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Static-only class. Dismiss / cap state lives in {@see ReportedIP_Hive_Promo_Manager}.
 *
 * @since 1.7.0
 */
class ReportedIP_Hive_Two_Factor_WC_Notice {

	/**
	 * Wire the WordPress hooks. Idempotent.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'admin_notices', array( __CLASS__, 'maybe_render' ), 20 );
		add_action( 'admin_post_reportedip_hive_wc2fa_promo_dismiss', array( __CLASS__, 'handle_dismiss' ) );
	}

	/**
	 * Whether the banner should show on the current request.
	 *
	 * @param int $user_id User id to evaluate. 0 = current user.
	 * @return bool
	 * @since  1.7.0
	 */
	public static function should_show( $user_id = 0 ) {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return false;
		}
		$user_id = (int) $user_id;
		if ( 0 === $user_id ) {
			$user_id = (int) get_current_user_id();
		}
		if ( $user_id <= 0 || ! user_can( $user_id, 'manage_options' ) ) {
			return false;
		}
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) || ! class_exists( 'ReportedIP_Hive_Promo_Manager' ) ) {
			return false;
		}

		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'frontend_2fa' );
		if ( ! empty( $status['available'] ) ) {
			return false;
		}
		if ( 'tier' !== ( $status['reason'] ?? '' ) ) {
			return false;
		}

		if ( ! ReportedIP_Hive_Promo_Manager::can_show( ReportedIP_Hive_Promo_Manager::KEY_WC_FRONTEND_2FA, $user_id ) ) {
			return false;
		}
		return self::is_eligible_screen();
	}

	/**
	 * Limit the banner to admin screens admins genuinely visit with intent
	 * (Hive admin pages, the dashboard, the plugins list).
	 *
	 * @return bool
	 */
	private static function is_eligible_screen() {
		if ( ! function_exists( 'get_current_screen' ) ) {
			return true;
		}
		$screen = get_current_screen();
		if ( ! $screen ) {
			return true;
		}
		$id = (string) $screen->id;
		if ( 'dashboard' === $id ) {
			return true;
		}
		if ( false !== strpos( $id, 'reportedip-hive' ) ) {
			return true;
		}
		if ( 'plugins' === $id ) {
			return true;
		}
		return false;
	}

	/**
	 * `admin_notices` callback.
	 *
	 * @return void
	 */
	public static function maybe_render() {
		$user_id = (int) get_current_user_id();
		if ( ! self::should_show( $user_id ) ) {
			return;
		}

		$dismiss_action = wp_nonce_url(
			admin_url( 'admin-post.php?action=reportedip_hive_wc2fa_promo_dismiss' ),
			'reportedip_hive_wc2fa_promo_dismiss'
		);
		$pricing_url    = defined( 'REPORTEDIP_HIVE_UPGRADE_URL' )
			? REPORTEDIP_HIVE_UPGRADE_URL
			: 'https://reportedip.de/pricing/';

		ReportedIP_Hive_Admin_Notice::render(
			array(
				'variant'           => 'info',
				'extra_classes'     => 'rip-wc2fa-promo',
				'title'             => __( 'Protect your WooCommerce customers with 2FA', 'reportedip-hive' ),
				'body'              => __( 'Hive Professional extends the second factor to My Account and Checkout — the only WordPress security plugin that keeps customers inside the storefront theme during sign-in. Solid Security and the WordPress Two-Factor plugin only cover the wp-admin login.', 'reportedip-hive' ),
				'primary_action'    => array(
					'label'  => __( 'Compare plans', 'reportedip-hive' ),
					'url'    => $pricing_url,
					'target' => '_blank',
					'rel'    => 'noopener',
				),
				'secondary_actions' => array(
					array(
						'type'  => 'link',
						'label' => __( 'Remind me later', 'reportedip-hive' ),
						'url'   => $dismiss_action,
					),
				),
			)
		);

		ReportedIP_Hive_Promo_Manager::mark_shown(
			ReportedIP_Hive_Promo_Manager::KEY_WC_FRONTEND_2FA,
			$user_id
		);
	}

	/**
	 * `admin_post` handler — record the dismiss in the central Promo_Manager
	 * (which also bumps the global cap), redirect back.
	 *
	 * @return void
	 */
	public static function handle_dismiss() {
		check_admin_referer( 'reportedip_hive_wc2fa_promo_dismiss' );

		if ( class_exists( 'ReportedIP_Hive_Promo_Manager' ) ) {
			ReportedIP_Hive_Promo_Manager::mark_dismissed(
				ReportedIP_Hive_Promo_Manager::KEY_WC_FRONTEND_2FA
			);
		}

		$redirect = wp_get_referer();
		if ( ! $redirect ) {
			$redirect = admin_url();
		}
		wp_safe_redirect( $redirect );
		exit;
	}
}
