<?php
/**
 * WooCommerce Login Monitor.
 *
 * The plugin's `wp_login_failed` listener already covers WC because WooCommerce
 * authenticates through the standard `wp_authenticate` filter. WooCommerce
 * fires *additional* dedicated hooks though, and they fire even on the AJAX
 * checkout login form where `wp_login_failed` does not — so we wire them too,
 * tag the events as `wc_login_failed`, and let the security monitor treat them
 * as a separate attempt-type bucket.
 *
 * No-op when WooCommerce is not active. Cheap to instantiate either way.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_WooCommerce_Monitor {

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_WooCommerce_Monitor|null
	 */
	private static $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Hook on plugins_loaded — WC may not be loaded yet at the time this
	 * class is instantiated, so we attach via the action with no class_exists
	 * guard. WC's hooks simply never fire if the plugin is inactive.
	 */
	private function __construct() {
		add_action( 'woocommerce_login_failed', array( $this, 'on_login_failed' ), 10, 2 );
		add_action( 'woocommerce_checkout_login_form_failed_login', array( $this, 'on_login_failed' ), 10, 1 );
	}

	/**
	 * Track a WC-specific failed login. The username argument is optional
	 * because WC fires the hook from multiple places with different
	 * signatures (the my-account form passes `$username`, the checkout
	 * variant does not).
	 *
	 * @param string|WP_Error $username_or_error Username string OR a WC WP_Error.
	 * @param string|null     $username          Optional second argument.
	 */
	public function on_login_failed( $username_or_error, $username = null ): void {
		if ( ! get_option( 'reportedip_hive_monitor_woocommerce', true ) ) {
			return;
		}
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}

		$user_attempt = '';
		if ( is_string( $username_or_error ) ) {
			$user_attempt = $username_or_error;
		} elseif ( is_string( $username ) ) {
			$user_attempt = $username;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( '' === $ip || 'unknown' === $ip ) {
			return;
		}

		$ip_manager = class_exists( 'ReportedIP_Hive_IP_Manager' )
			? ReportedIP_Hive_IP_Manager::get_instance()
			: null;
		if ( $ip_manager && method_exists( $ip_manager, 'is_whitelisted' ) && $ip_manager->is_whitelisted( $ip ) ) {
			return;
		}

		$client  = ReportedIP_Hive::get_instance();
		$monitor = $client->get_security_monitor();
		if ( ! ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) ) {
			return;
		}

		$threshold = (int) get_option( 'reportedip_hive_failed_login_threshold', 5 );
		$timeframe = (int) get_option( 'reportedip_hive_failed_login_timeframe', 15 );

		$monitor->track_generic_attempt(
			$ip,
			'wc_login',
			'wc_login_failed',
			$threshold,
			$timeframe,
			array( 'username_provided' => '' !== $user_attempt )
		);
	}
}
