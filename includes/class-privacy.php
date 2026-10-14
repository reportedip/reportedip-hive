<?php
/**
 * GDPR / privacy integration for ReportedIP Hive.
 *
 * Two responsibilities:
 *
 *  1. Registers a suggested privacy-policy passage in the WordPress privacy
 *     assistant (Tools -> Privacy / Privacy Policy Guide) so the site operator
 *     can copy/paste it, with a link to the full, configuration-aware generator
 *     at reportedip.com/dashboard/dsgvo.
 *  2. Registers a personal-data exporter and eraser for the security data Hive
 *     stores about a logged-in user, their own login attempts (matched by
 *     username) and trusted devices (matched by user id). The 2FA secrets are
 *     handled separately by ReportedIP_Hive_Two_Factor_Admin. The account
 *     block record and the proxy-aware per-session IP are exported here too;
 *     core's own session export carries only `REMOTE_ADDR`.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
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
			. '<p>' . __( 'If "Community Network" mode is enabled (off by default), the IP address of login/access attempts and detected attacks is also transmitted to ReportedIP (reportedip.com) for community threat intelligence. Each such request identifies the installation itself with the site address and the plugin/WordPress version (for licensing and support). No visitor usernames, comment content, full user agents or other personal data of regular visitors are transmitted.', 'reportedip-hive' ) . '</p>'
			. '<p>' . sprintf(
				/* translators: 1: privacy generator URL, 2: ReportedIP privacy policy URL */
				__( 'A ready-to-paste privacy passage tailored to your configuration (German or English) is available at %1$s. See also the ReportedIP privacy policy at %2$s. This is suggested text only and not legal advice, adapt it to your site and have it reviewed.', 'reportedip-hive' ),
				'<a href="https://reportedip.com/dashboard/dsgvo">https://reportedip.com/dashboard/dsgvo</a>',
				'<a href="https://reportedip.com/datenschutzerklaerung/">https://reportedip.com/datenschutzerklaerung/</a>'
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from base_prefix, every value bound through prepare().
		$attempts = $wpdb->get_results( $wpdb->prepare( "SELECT id, ip_address, attempt_type, attempt_count, first_attempt, last_attempt FROM {$attempts_table} WHERE username = %s", $user->user_login ) );
		foreach ( (array) $attempts as $row ) {
			$items[] = array(
				'group_id'    => 'reportedip-hive-attempts',
				'group_label' => __( 'ReportedIP Hive: login attempts', 'reportedip-hive' ),
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from base_prefix, every value bound through prepare().
		$devices = $wpdb->get_results( $wpdb->prepare( "SELECT id, device_name, ip_address, created_at, expires_at, last_used_at FROM {$devices_table} WHERE user_id = %d", $user->ID ) );
		foreach ( (array) $devices as $row ) {
			$items[] = array(
				'group_id'    => 'reportedip-hive-trusted-devices',
				'group_label' => __( 'ReportedIP Hive: trusted devices', 'reportedip-hive' ),
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

		$items = array_merge( $items, ReportedIP_Hive_Legacy_Data::export_items( $user ) );

		$block = ReportedIP_Hive_Account_Block::get( $user->ID );
		if ( null !== $block ) {
			$items[] = array(
				'group_id'    => 'reportedip-hive-account-block',
				'group_label' => __( 'ReportedIP Hive: account block', 'reportedip-hive' ),
				'item_id'     => 'rip-hive-account-block',
				'data'        => array(
					array(
						'name'  => __( 'Blocked since', 'reportedip-hive' ),
						'value' => $block['blocked_at'],
					),
					array(
						'name'  => __( 'Message shown at sign-in', 'reportedip-hive' ),
						'value' => $block['message'],
					),
					array(
						'name'  => __( 'Administrator note', 'reportedip-hive' ),
						'value' => $block['note'],
					),
				),
			);
		}

		foreach ( ReportedIP_Hive_User_Sessions::for_user( $user->ID ) as $verifier => $session ) {
			$items[] = array(
				'group_id'    => 'reportedip-hive-sessions',
				'group_label' => __( 'ReportedIP Hive: session addresses', 'reportedip-hive' ),
				'item_id'     => 'rip-hive-session-' . substr( (string) $verifier, 0, 12 ),
				'data'        => array(
					array(
						'name'  => __( 'IP address', 'reportedip-hive' ),
						'value' => ReportedIP_Hive_User_Sessions::display_ip( $session ),
					),
					array(
						'name'  => __( 'Expires', 'reportedip-hive' ),
						'value' => isset( $session['expiration'] ) ? gmdate( 'Y-m-d H:i:s', (int) $session['expiration'] ) : '',
					),
				),
			);
		}

		$login_context = self::stored_login_context( $user->ID );
		if ( $login_context['last']['ts'] > 0 || ! empty( $login_context['nets'] ) ) {
			$items[] = array(
				'group_id'    => 'reportedip-hive-login-context',
				'group_label' => __( 'ReportedIP Hive: sign-in history', 'reportedip-hive' ),
				'item_id'     => 'rip-hive-login-context',
				'data'        => array(
					array(
						'name'  => __( 'Last sign-in', 'reportedip-hive' ),
						'value' => $login_context['last']['ts'] > 0
							? ReportedIP_Hive::format_local_datetime( gmdate( 'Y-m-d H:i:s', (int) $login_context['last']['ts'] ) )
							: '',
					),
					array(
						'name'  => __( 'Last sign-in IP address', 'reportedip-hive' ),
						'value' => $login_context['last']['ip'],
					),
					array(
						'name'  => __( 'Last sign-in device', 'reportedip-hive' ),
						'value' => $login_context['last']['ua_short'],
					),
					array(
						'name'  => __( 'Last sign-in country', 'reportedip-hive' ),
						'value' => $login_context['last']['country'],
					),
					array(
						'name'  => __( 'Last second-factor verification', 'reportedip-hive' ),
						'value' => $login_context['verified_at'] > 0
							? ReportedIP_Hive::format_local_datetime( gmdate( 'Y-m-d H:i:s', (int) $login_context['verified_at'] ) )
							: '',
					),
					array(
						'name'  => __( 'Sign-ins since that verification', 'reportedip-hive' ),
						'value' => (int) $login_context['logins_since_verify'],
					),
					array(
						'name'  => __( 'Known networks', 'reportedip-hive' ),
						'value' => implode( ', ', $login_context['nets'] ),
					),
					array(
						'name'  => __( 'Known devices', 'reportedip-hive' ),
						'value' => implode( ', ', $login_context['uas'] ),
					),
					array(
						'name'  => __( 'Known countries', 'reportedip-hive' ),
						'value' => implode( ', ', $login_context['countries'] ),
					),
				),
			);
		}

		/**
		 * Extend the personal data export of one user with the items of an
		 * add-on, each in the shape of a WordPress exporter item
		 * (`group_id`, `group_label`, `item_id`, `data`).
		 *
		 * @param array<int,array<string,mixed>> $items Export items.
		 * @param WP_User                        $user  User under request.
		 * @since 3.0.0
		 */
		$items = apply_filters( 'reportedip_hive_privacy_export_items', $items, $user );

		return array(
			'data' => is_array( $items ) ? array_values( $items ) : array(),
			'done' => true,
		);
	}

	/**
	 * The stored sign-in history of one user, padded to its full shape.
	 *
	 * Read straight from the user meta, so the export also covers the
	 * history an add-on recorded while it was active.
	 *
	 * @param int $user_id User id.
	 * @return array{last:array{ip:string,ua_short:string,country:string,ts:int},verified_at:int,logins_since_verify:int,nets:string[],uas:string[],countries:string[]}
	 * @since  3.0.0
	 */
	private static function stored_login_context( $user_id ) {
		$raw     = get_user_meta( (int) $user_id, ReportedIP_Hive_Two_Factor::META_LOGIN_CONTEXT, true );
		$decoded = is_string( $raw ) ? json_decode( $raw, true ) : $raw;
		$decoded = is_array( $decoded ) ? $decoded : array();
		$last    = isset( $decoded['last'] ) && is_array( $decoded['last'] ) ? $decoded['last'] : array();
		$list    = static function ( $key ) use ( $decoded ) {
			return isset( $decoded[ $key ] ) && is_array( $decoded[ $key ] ) ? array_map( 'strval', array_values( $decoded[ $key ] ) ) : array();
		};

		return array(
			'last'                => array(
				'ip'       => (string) ( $last['ip'] ?? '' ),
				'ua_short' => (string) ( $last['ua_short'] ?? '' ),
				'country'  => (string) ( $last['country'] ?? '' ),
				'ts'       => (int) ( $last['ts'] ?? 0 ),
			),
			'verified_at'         => (int) ( $decoded['verified_at'] ?? 0 ),
			'logins_since_verify' => (int) ( $decoded['logins_since_verify'] ?? 0 ),
			'nets'                => $list( 'nets' ),
			'uas'                 => $list( 'uas' ),
			'countries'           => $list( 'countries' ),
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name from base_prefix, every value bound through prepare().
		$removed += (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$attempts_table} WHERE username = %s", $user->user_login ) );

		$removed += ReportedIP_Hive_Two_Factor::revoke_all_trusted_devices( $user->ID );

		$removed += ReportedIP_Hive_Legacy_Data::erase( $user );

		delete_user_meta( $user->ID, '_reportedip_hive_known_ips' );
		delete_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_LOGIN_CONTEXT );

		$retained = 0;
		$messages = array();
		if ( ReportedIP_Hive_Account_Block::is_blocked( $user->ID ) ) {
			ReportedIP_Hive_Account_Block::update_texts( $user->ID, '', '' );
			$retained   = 1;
			$messages[] = __( 'The account block itself was retained for security; its free-text fields were cleared.', 'reportedip-hive' );
		}

		/**
		 * Erase the data an add-on keeps about one user and add its counts.
		 * The listener returns the array with `removed` and `retained`
		 * raised by what it erased or kept, and its sentences appended to
		 * `messages`.
		 *
		 * @param array{removed:int,retained:int,messages:string[]} $result Counts and messages so far.
		 * @param WP_User                                           $user   User under request.
		 * @since 3.0.0
		 */
		$result = apply_filters(
			'reportedip_hive_privacy_erase',
			array(
				'removed'  => $removed,
				'retained' => $retained,
				'messages' => $messages,
			),
			$user
		);
		$result = is_array( $result ) ? $result : array();

		return array(
			'items_removed'  => (int) ( $result['removed'] ?? $removed ),
			'items_retained' => (int) ( $result['retained'] ?? $retained ),
			'messages'       => array_values( (array) ( $result['messages'] ?? $messages ) ),
			'done'           => true,
		);
	}
}
