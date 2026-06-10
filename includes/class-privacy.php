<?php
/**
 * GDPR / privacy integration for ReportedIP Hive.
 *
 * Two responsibilities:
 *
 *  1. Registers a suggested privacy-policy passage in the WordPress privacy
 *     assistant (Tools -> Privacy / Privacy Policy Guide) so the site operator
 *     can copy/paste it, with a link to the full, configuration-aware generator
 *     at reportedip.de/dashboard/dsgvo.
 *  2. Registers a personal-data exporter and eraser for the security data Hive
 *     stores about a logged-in user — their own login attempts (matched by
 *     username) and trusted devices (matched by user id). The 2FA secrets are
 *     handled separately by ReportedIP_Hive_Two_Factor_Admin.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.24
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Privacy / GDPR integration.
 *
 * @since 2.0.24
 */
class ReportedIP_Hive_Privacy {

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Privacy|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Privacy
	 * @since  2.0.24
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire the WordPress privacy hooks.
	 *
	 * @since 2.0.24
	 */
	private function __construct() {
		add_action( 'admin_init', array( $this, 'register_policy_content' ) );
		add_filter( 'wp_privacy_personal_data_exporters', array( $this, 'register_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( $this, 'register_eraser' ) );
	}

	/**
	 * Suggest a privacy-policy passage in the WordPress Privacy Policy Guide.
	 *
	 * @since 2.0.24
	 */
	public function register_policy_content() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}

		$content =
			'<p>' . __( 'This site uses the ReportedIP Hive security plugin. On security-relevant events (failed logins, password spraying, comment spam, XML-RPC and REST-API abuse, application-password abuse, user enumeration, 404/scanner hits, decoy-path hits, geographic login anomalies and WooCommerce logins) it processes the IP address of the request, the username used in failed logins, and the time and type of the event in order to detect attacks and block offending IP addresses.', 'reportedip-hive' ) . '</p>'
			. '<p>' . __( 'This data is stored locally on this site, deleted automatically after the configured retention period (30 days by default) and anonymised after 7 days by default. The legal basis is the operator\'s legitimate interest in the security and uninterrupted operation of the site (Art. 6(1)(f) GDPR, Recital 49). User agents are not stored unless detailed logging is explicitly enabled.', 'reportedip-hive' ) . '</p>'
			. '<p>' . __( 'If "Community Network" mode is enabled (off by default), the IP address of login/access attempts and detected attacks is also transmitted to ReportedIP (reportedip.de) for community threat intelligence. No visitor usernames, comment content, full user agents or other personal data of regular visitors are transmitted.', 'reportedip-hive' ) . '</p>'
			. '<p>' . sprintf(
				/* translators: 1: privacy generator URL, 2: ReportedIP privacy policy URL */
				__( 'A ready-to-paste privacy passage tailored to your configuration (German or English) is available at %1$s. See also the ReportedIP privacy policy at %2$s. This is suggested text only and not legal advice — adapt it to your site and have it reviewed.', 'reportedip-hive' ),
				'<a href="https://reportedip.de/dashboard/dsgvo">https://reportedip.de/dashboard/dsgvo</a>',
				'<a href="https://reportedip.de/datenschutzerklaerung/">https://reportedip.de/datenschutzerklaerung/</a>'
			) . '</p>';

		wp_add_privacy_policy_content( 'ReportedIP Hive', wp_kses_post( $content ) );
	}

	/**
	 * Register the security-data exporter.
	 *
	 * @param array $exporters Existing exporters.
	 * @return array
	 * @since  2.0.24
	 */
	public function register_exporter( $exporters ) {
		$exporters['reportedip-hive-security'] = array(
			'exporter_friendly_name' => __( 'ReportedIP Hive security data', 'reportedip-hive' ),
			'callback'               => array( $this, 'export_personal_data' ),
		);
		return $exporters;
	}

	/**
	 * Register the security-data eraser.
	 *
	 * @param array $erasers Existing erasers.
	 * @return array
	 * @since  2.0.24
	 */
	public function register_eraser( $erasers ) {
		$erasers['reportedip-hive-security'] = array(
			'eraser_friendly_name' => __( 'ReportedIP Hive security data', 'reportedip-hive' ),
			'callback'             => array( $this, 'erase_personal_data' ),
		);
		return $erasers;
	}

	/**
	 * Export a user's own login attempts and trusted devices.
	 *
	 * @param string $email_address User email.
	 * @param int    $page          Page number (unused; single-page export).
	 * @return array{data:array,done:bool}
	 * @since  2.0.24
	 */
	public function export_personal_data( $email_address, $page = 1 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$user = get_user_by( 'email', $email_address );
		if ( ! $user ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}

		global $wpdb;
		$items = array();

		$attempts_table = $wpdb->base_prefix . 'reportedip_hive_attempts';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$attempts = $wpdb->get_results( $wpdb->prepare( "SELECT id, ip_address, attempt_type, attempt_count, first_attempt, last_attempt FROM {$attempts_table} WHERE username = %s", $user->user_login ) );
		foreach ( (array) $attempts as $row ) {
			$items[] = array(
				'group_id'    => 'reportedip-hive-attempts',
				'group_label' => __( 'ReportedIP Hive — login attempts', 'reportedip-hive' ),
				'item_id'     => 'rip-hive-attempt-' . (int) $row->id,
				'data'        => array(
					array(
						'name'  => __( 'IP address', 'reportedip-hive' ),
						'value' => $row->ip_address,
					),
					array(
						'name'  => __( 'Type', 'reportedip-hive' ),
						'value' => $row->attempt_type,
					),
					array(
						'name'  => __( 'Attempts', 'reportedip-hive' ),
						'value' => $row->attempt_count,
					),
					array(
						'name'  => __( 'First attempt', 'reportedip-hive' ),
						'value' => $row->first_attempt,
					),
					array(
						'name'  => __( 'Last attempt', 'reportedip-hive' ),
						'value' => $row->last_attempt,
					),
				),
			);
		}

		$devices_table = $wpdb->base_prefix . 'reportedip_hive_trusted_devices';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$devices = $wpdb->get_results( $wpdb->prepare( "SELECT id, device_name, ip_address, created_at, expires_at, last_used_at FROM {$devices_table} WHERE user_id = %d", $user->ID ) );
		foreach ( (array) $devices as $row ) {
			$items[] = array(
				'group_id'    => 'reportedip-hive-trusted-devices',
				'group_label' => __( 'ReportedIP Hive — trusted devices', 'reportedip-hive' ),
				'item_id'     => 'rip-hive-device-' . (int) $row->id,
				'data'        => array(
					array(
						'name'  => __( 'Device name', 'reportedip-hive' ),
						'value' => $row->device_name,
					),
					array(
						'name'  => __( 'IP address', 'reportedip-hive' ),
						'value' => $row->ip_address,
					),
					array(
						'name'  => __( 'Added', 'reportedip-hive' ),
						'value' => $row->created_at,
					),
					array(
						'name'  => __( 'Expires', 'reportedip-hive' ),
						'value' => $row->expires_at,
					),
					array(
						'name'  => __( 'Last used', 'reportedip-hive' ),
						'value' => $row->last_used_at,
					),
				),
			);
		}

		$audit_table = $wpdb->base_prefix . 'reportedip_hive_audit_log';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$audit = $wpdb->get_results( $wpdb->prepare( "SELECT id, created_at, ip, event_type, event_action, event_data FROM {$audit_table} WHERE user_id = %d", $user->ID ) );
		foreach ( (array) $audit as $row ) {
			$items[] = array(
				'group_id'    => 'reportedip-hive-audit',
				'group_label' => __( 'ReportedIP Hive — audit trail', 'reportedip-hive' ),
				'item_id'     => 'rip-hive-audit-' . (int) $row->id,
				'data'        => array(
					array(
						'name'  => __( 'Time', 'reportedip-hive' ),
						'value' => $row->created_at,
					),
					array(
						'name'  => __( 'Event', 'reportedip-hive' ),
						'value' => $row->event_type,
					),
					array(
						'name'  => __( 'Action', 'reportedip-hive' ),
						'value' => $row->event_action,
					),
					array(
						'name'  => __( 'IP address', 'reportedip-hive' ),
						'value' => $row->ip,
					),
					array(
						'name'  => __( 'Details', 'reportedip-hive' ),
						'value' => $row->event_data,
					),
				),
			);
		}

		return array(
			'data' => $items,
			'done' => true,
		);
	}

	/**
	 * Erase a user's own login attempts and trusted devices.
	 *
	 * @param string $email_address User email.
	 * @param int    $page          Page number (unused; single-page erase).
	 * @return array{items_removed:int,items_retained:int,messages:array,done:bool}
	 * @since  2.0.24
	 */
	public function erase_personal_data( $email_address, $page = 1 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$user = get_user_by( 'email', $email_address );
		if ( ! $user ) {
			return array(
				'items_removed'  => 0,
				'items_retained' => 0,
				'messages'       => array(),
				'done'           => true,
			);
		}

		global $wpdb;
		$removed = 0;

		$attempts_table = $wpdb->base_prefix . 'reportedip_hive_attempts';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$removed += (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$attempts_table} WHERE username = %s", $user->user_login ) );

		$devices_table = $wpdb->base_prefix . 'reportedip_hive_trusted_devices';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$removed += (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$devices_table} WHERE user_id = %d", $user->ID ) );

		$audit_table = $wpdb->base_prefix . 'reportedip_hive_audit_log';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$removed += (int) $wpdb->query( $wpdb->prepare( "UPDATE {$audit_table} SET username = '', ip = '', user_id = NULL, event_data = NULL WHERE user_id = %d", $user->ID ) );

		delete_user_meta( $user->ID, '_reportedip_hive_known_ips' );

		return array(
			'items_removed'  => $removed,
			'items_retained' => 0,
			'messages'       => array(),
			'done'           => true,
		);
	}
}
