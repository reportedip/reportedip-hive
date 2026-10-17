<?php
/**
 * Instant alerts for signals that something got through.
 *
 * Blocked attacks are a warning at most and go into the daily summary
 * (ReportedIP_Hive_Digest). This class covers the other kind: a new
 * administrator, an administrator signing in from a new place, protection
 * that failed. Those reach the admin at once, with "Alert" in the subject.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     3.0.3
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Sends instant breach alerts and watches the role changes that create admins.
 *
 * @since 3.0.3
 */
class ReportedIP_Hive_Alerts {

	/**
	 * Option: instant alerts on or off.
	 */
	const OPT_ENABLED = 'reportedip_hive_notify_alerts';

	/**
	 * Seconds one alert key stays quiet after a mail. A role change fires
	 * several core hooks for the same user; the admin gets one mail.
	 */
	const DEDUPE_SECONDS = 600;

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Alerts|null
	 */
	private static $instance = null;

	/**
	 * Return the singleton and register the hooks once.
	 *
	 * @return ReportedIP_Hive_Alerts
	 * @since  3.0.3
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Register the role hooks.
	 */
	private function __construct() {
		add_action( 'set_user_role', array( $this, 'on_set_role' ), 10, 3 );
		add_action( 'add_user_role', array( $this, 'on_add_role' ), 10, 2 );
		add_action( 'user_register', array( $this, 'on_user_register' ), 20 );
		add_action( 'granted_super_admin', array( $this, 'on_super_admin' ) );
	}

	/**
	 * A user got a new main role.
	 *
	 * @param int      $user_id   User ID.
	 * @param string   $role      New role.
	 * @param string[] $old_roles Roles before the change.
	 * @return void
	 * @since  3.0.3
	 */
	public function on_set_role( $user_id, $role, $old_roles = array() ) {
		if ( self::is_admin_promotion( (string) $role, (array) $old_roles ) ) {
			$this->admin_granted( (int) $user_id );
		}
	}

	/**
	 * A user got an additional role.
	 *
	 * @param int    $user_id User ID.
	 * @param string $role    Added role.
	 * @return void
	 * @since  3.0.3
	 */
	public function on_add_role( $user_id, $role ) {
		if ( self::is_admin_promotion( (string) $role, array() ) ) {
			$this->admin_granted( (int) $user_id );
		}
	}

	/**
	 * A new account was created with administrator rights.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 * @since  3.0.3
	 */
	public function on_user_register( $user_id ) {
		if ( user_can( (int) $user_id, 'manage_options' ) ) {
			$this->admin_granted( (int) $user_id );
		}
	}

	/**
	 * A user became super admin of the network.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 * @since  3.0.3
	 */
	public function on_super_admin( $user_id ) {
		$user = get_userdata( (int) $user_id );
		self::send(
			'admin_granted_' . (int) $user_id,
			__( 'New super admin', 'reportedip-hive' ),
			self::user_rows( $user )
		);
	}

	/**
	 * Whether a role change turns a user into an administrator.
	 *
	 * @param string   $role      Role the user gets.
	 * @param string[] $old_roles Roles the user had.
	 * @return bool
	 * @since  3.0.3
	 */
	public static function is_admin_promotion( $role, array $old_roles ) {
		return 'administrator' === $role && ! in_array( 'administrator', $old_roles, true );
	}

	/**
	 * Mail for a new or promoted administrator.
	 *
	 * @param int $user_id User ID.
	 * @return void
	 */
	private function admin_granted( $user_id ) {
		$user = get_userdata( $user_id );
		self::send(
			'admin_granted_' . $user_id,
			__( 'New administrator account', 'reportedip-hive' ),
			self::user_rows( $user )
		);
	}

	/**
	 * Table rows that describe a user and who made the change.
	 *
	 * @param WP_User|false $user Affected user.
	 * @return array<int,array{0:string,1:string}>
	 */
	private static function user_rows( $user ) {
		$actor = wp_get_current_user();
		$rows  = array(
			array( __( 'Account', 'reportedip-hive' ), $user ? $user->user_login . ' (' . $user->user_email . ')' : '?' ),
			array( __( 'Changed by', 'reportedip-hive' ), ( $actor && $actor->exists() ) ? $actor->user_login : __( 'system or unknown', 'reportedip-hive' ) ),
		);
		if ( class_exists( 'ReportedIP_Hive' ) ) {
			$rows[] = array( __( 'IP address', 'reportedip-hive' ), (string) ReportedIP_Hive::get_client_ip() );
		}
		return $rows;
	}

	/**
	 * Send one instant alert to the notification recipients.
	 *
	 * Public so the Pro add-on can raise its own breach signals (audit rows
	 * with a danger badge) through the same switch, dedupe and wording.
	 *
	 * @param string                              $key   Dedupe key; the same key mails once per DEDUPE_SECONDS.
	 * @param string                              $title Short title for the subject.
	 * @param array<int,array{0:string,1:string}> $rows  Label/value rows for the mail body.
	 * @return bool True when a mail was handed to the mailer.
	 * @since  3.0.3
	 */
	public static function send( $key, $title, array $rows ) {
		if ( ! self::enabled() ) {
			return false;
		}

		$transient = 'rip_alert_' . md5( (string) $key );
		if ( get_site_transient( $transient ) ) {
			return false;
		}

		$recipients = ReportedIP_Hive_Defaults::notify_recipients();
		if ( empty( $recipients ) ) {
			return false;
		}

		set_site_transient( $transient, 1, self::DEDUPE_SECONDS );

		$site_name = wp_specialchars_decode( (string) ( get_bloginfo( 'name' ) ?: 'WordPress Site' ), ENT_QUOTES );
		$rows[]    = array( __( 'Time', 'reportedip-hive' ), (string) current_time( 'Y-m-d H:i:s' ) );
		$blocks    = self::rows_block( $rows );

		return (bool) ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => implode( ', ', $recipients ),
				/* translators: 1: site name, 2: alert title */
				'subject'         => sprintf( __( '[%1$s] Alert: %2$s', 'reportedip-hive' ), $site_name, $title ),
				'intro_text'      => __( 'Something changed on your site that only a person with access can do. If you did not expect it, check the account and change its password.', 'reportedip-hive' ),
				'main_block_html' => $blocks['html'],
				'main_block_text' => $blocks['text'],
				'disclaimer'      => __( 'You get these alerts at once. Switch them off under ReportedIP Hive > Protection > Operations > Notifications.', 'reportedip-hive' ),
				'context'         => array(
					'type' => 'admin_security_alert_breach',
					'key'  => (string) $key,
				),
			)
		);
	}

	/**
	 * Whether instant alerts may go out at all.
	 *
	 * @return bool
	 * @since  3.0.3
	 */
	public static function enabled() {
		return (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_admin', true )
			&& (bool) ReportedIP_Hive_Option_Routing::get( self::OPT_ENABLED, true );
	}

	/**
	 * Render label/value rows as the mail table plus its plain-text twin.
	 *
	 * @param array<int,array{0:string,1:string}> $rows Rows.
	 * @return array{html:string,text:string}
	 * @since  3.0.3
	 */
	public static function rows_block( array $rows ) {
		$html = '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F9FAFB;margin:0 0 24px;">';
		$text = '';
		foreach ( $rows as $row ) {
			$html .= '<tr>';
			$html .= '<td style="padding:10px 16px;font-size:12px;color:#6B7280;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;width:40%;">' . esc_html( $row[0] ) . '</td>';
			$html .= '<td style="padding:10px 16px;font-size:13px;color:#111827;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all;">' . esc_html( $row[1] ) . '</td>';
			$html .= '</tr>';
			$text .= $row[0] . ': ' . $row[1] . "\n";
		}
		$html .= '</table>';

		return array(
			'html' => $html,
			'text' => $text,
		);
	}
}
