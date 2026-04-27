<?php
/**
 * Application Password Monitor.
 *
 * Closes a 2FA-bypass gap: WordPress application passwords authenticate over
 * Basic Auth on REST and XMLRPC, skipping the wp-login.php interstitial that
 * normally enforces 2FA. This class:
 *  - rate-limits failed application-password authentications per IP and feeds
 *    them into the security monitor as `app_password_abuse`,
 *  - blocks the creation of new application passwords for users whose role is
 *    listed in `reportedip_hive_2fa_enforce_roles` until they have completed
 *    2FA enrolment, and
 *  - logs every successful application-password authentication (low severity)
 *    so the timeline shows when API-keyed access happened.
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

class ReportedIP_Hive_App_Password_Monitor {

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_App_Password_Monitor|null
	 */
	private static $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Hooks. `application_password_failed_authentication` and
	 * `application_password_did_authenticate` are core WP actions that fire on
	 * every Basic-Auth REST/XMLRPC request that uses an application password.
	 */
	private function __construct() {
		add_action( 'application_password_failed_authentication', array( $this, 'on_failed_authentication' ) );
		add_action( 'application_password_did_authenticate', array( $this, 'on_successful_authentication' ), 10, 2 );
		add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'block_creation_for_unenrolled' ), 10, 2 );
	}

	/**
	 * Track failed app-password authentications. Fires on every wrong
	 * username/password combination over Basic Auth.
	 *
	 * @param WP_Error $error WP_Error returned by core; carries the username
	 *                        attempted via `data.username` if WP populated it.
	 */
	public function on_failed_authentication( $error ): void {
		if ( ! get_option( 'reportedip_hive_monitor_app_passwords', true ) ) {
			return;
		}

		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
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

		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->log_security_event(
			'app_password_failed',
			$ip,
			array(
				'has_error'  => $error instanceof WP_Error,
				'error_code' => $error instanceof WP_Error ? $error->get_error_code() : null,
			),
			'medium'
		);

		$threshold = (int) get_option( 'reportedip_hive_app_password_threshold', 5 );
		$timeframe = (int) get_option( 'reportedip_hive_app_password_timeframe', 15 );

		$client  = ReportedIP_Hive::get_instance();
		$monitor = $client->get_security_monitor();
		if ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) {
			$monitor->track_generic_attempt( $ip, 'app_password', 'app_password_abuse', $threshold, $timeframe );
		}
	}

	/**
	 * Log every successful application-password authentication. Useful for
	 * compliance / audit trails — there is otherwise no record of when an API
	 * key actually authenticated.
	 *
	 * @param WP_User $user The authenticated user.
	 * @param array   $item The application-password row (item) from user meta.
	 */
	public function on_successful_authentication( $user, $item = array() ): void {
		if ( ! get_option( 'reportedip_hive_monitor_app_passwords', true ) ) {
			return;
		}
		if ( ! ( $user instanceof WP_User ) ) {
			return;
		}
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}

		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->log_security_event(
			'app_password_success',
			ReportedIP_Hive::get_client_ip(),
			array(
				'user_id'  => $user->ID,
				'app_name' => is_array( $item ) && isset( $item['name'] ) ? sanitize_text_field( (string) $item['name'] ) : '',
			),
			'low'
		);
	}

	/**
	 * Block app-password creation for users whose role is in the 2FA-enforce
	 * list until they have finished 2FA enrolment. App passwords without 2FA
	 * defeat the enforcement policy — same threat model as iThemes Pro.
	 *
	 * @param bool    $available Core's existing decision.
	 * @param WP_User $user      User the check runs against.
	 * @return bool              False to disable creation.
	 */
	public function block_creation_for_unenrolled( $available, $user ) {
		if ( ! $available ) {
			return $available;
		}
		if ( ! ( $user instanceof WP_User ) ) {
			return $available;
		}
		if ( ! get_option( 'reportedip_hive_app_password_require_2fa', true ) ) {
			return $available;
		}
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
			return $available;
		}

		if ( ReportedIP_Hive_Two_Factor::is_enforced_for_user( $user )
			&& ! ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID )
			&& ! ReportedIP_Hive_Two_Factor::is_in_grace_period( $user->ID )
		) {
			return false;
		}

		return $available;
	}
}
