<?php
/**
 * Two-Factor Login Notifications
 *
 * Sends the user an email when their account is accessed from a previously
 * unseen device (fingerprint = hash of User-Agent + IP /24 block). Does not
 * block the login — only notifies, so the user can react to surprises.
 *
 * Stored fingerprints live in a bounded-size per-user meta array (keeps the
 * most recent N devices only) to avoid unbounded meta growth.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.4.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Two_Factor_Notifications
 */
class ReportedIP_Hive_Two_Factor_Notifications {

	/**
	 * How many known-device fingerprints to retain per user.
	 */
	const MAX_DEVICES = 50;

	/**
	 * Constructor — register the wp_login hook.
	 */
	public function __construct() {
		add_action( 'wp_login', array( $this, 'on_login' ), 50, 2 );
	}

	/**
	 * wp_login callback — send a notification if the device fingerprint is new.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User object.
	 */
	public function on_login( $user_login, $user ) {
		unset( $user_login );

		if ( ! get_option( 'reportedip_hive_2fa_notify_new_device', true ) ) {
			return;
		}
		if ( ! ( $user instanceof \WP_User ) || ! $user->ID ) {
			return;
		}

		$fingerprint = self::fingerprint();
		if ( empty( $fingerprint ) ) {
			return;
		}

		$known = self::get_known_devices( $user->ID );

		if ( isset( $known[ $fingerprint ] ) ) {
			$last_seen = (int) ( $known[ $fingerprint ]['last_seen'] ?? 0 );
			if ( ( time() - $last_seen ) > HOUR_IN_SECONDS ) {
				$known[ $fingerprint ]['last_seen'] = time();
				self::save_known_devices( $user->ID, $known );
			}
			return;
		}

		$known[ $fingerprint ] = array(
			'first_seen' => time(),
			'last_seen'  => time(),
			'ip'         => ReportedIP_Hive::get_client_ip(),
			'ua_short'   => self::short_ua(),
		);
		if ( count( $known ) > self::MAX_DEVICES ) {
			uasort(
				$known,
				function ( $a, $b ) {
					return ( $b['last_seen'] ?? 0 ) <=> ( $a['last_seen'] ?? 0 );
				}
			);
			$known = array_slice( $known, 0, self::MAX_DEVICES, true );
		}
		self::save_known_devices( $user->ID, $known );

		if ( count( $known ) <= 1 ) {
			return;
		}

		$this->send_email( $user );
	}

	/**
	 * Compute a stable per-device fingerprint.
	 *
	 * Uses User-Agent + the /24 (IPv4) or /64 (IPv6) network block so that
	 * minor IP changes within the same ISP don't count as a new device.
	 *
	 * @return string Hash, or empty string when components are unavailable.
	 */
	public static function fingerprint() {
		$ua  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		$ip  = ReportedIP_Hive::get_client_ip();
		$net = self::ip_to_network( $ip );
		if ( '' === $ua || '' === $net ) {
			return '';
		}
		return hash( 'sha256', $ua . '|' . $net . '|' . wp_salt( 'auth' ) );
	}

	/**
	 * Reduce an IP to its network block for fingerprinting.
	 *
	 * @param string $ip IP address.
	 * @return string Network identifier or '' if invalid.
	 */
	private static function ip_to_network( $ip ) {
		if ( empty( $ip ) ) {
			return '';
		}
		if ( false !== strpos( $ip, '.' ) ) {
			$parts = explode( '.', $ip );
			if ( 4 !== count( $parts ) ) {
				return '';
			}
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
		}
		if ( false !== strpos( $ip, ':' ) ) {
			$expanded = inet_pton( $ip );
			if ( false === $expanded ) {
				return '';
			}
			$hex = bin2hex( $expanded );
			return substr( $hex, 0, 16 ) . '::/64';
		}
		return '';
	}

	/**
	 * Truncate the User-Agent string for display.
	 *
	 * @return string
	 */
	private static function short_ua() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		return substr( $ua, 0, 120 );
	}

	/**
	 * Load the known-devices map for a user.
	 *
	 * @param int $user_id User ID.
	 * @return array<string,array>
	 */
	public static function get_known_devices( $user_id ) {
		$raw = get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_KNOWN_DEVICES, true );
		if ( empty( $raw ) ) {
			return array();
		}
		$decoded = json_decode( $raw, true );
		return is_array( $decoded ) ? $decoded : array();
	}

	/**
	 * Persist the known-devices map for a user.
	 *
	 * @param int   $user_id User ID.
	 * @param array $map     Device map.
	 */
	private static function save_known_devices( $user_id, $map ) {
		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_KNOWN_DEVICES, wp_json_encode( $map ) );
	}

	/**
	 * Send the new-device notification email via the central mailer.
	 *
	 * @param WP_User $user Target user.
	 */
	private function send_email( $user ) {
		$site_name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$ip        = ReportedIP_Hive::get_client_ip();
		$ua        = self::short_ua();
		$when      = wp_date( 'd.m.Y H:i', time() );

		$subject = sprintf(
			/* translators: 1: site name */
			__( '[%1$s] Sign-in from a new device', 'reportedip-hive' ),
			$site_name
		);

		$intro = sprintf(
			/* translators: %s: site name */
			__( 'Just letting you know — your account at %s was just accessed from a device that hasn\'t signed in here before. If that was you, no further action is needed.', 'reportedip-hive' ),
			esc_html( $site_name )
		);

		$rows = array(
			array( __( 'Time', 'reportedip-hive' ), $when ),
			array( __( 'IP address', 'reportedip-hive' ), $ip ),
			array( __( 'Device / Browser', 'reportedip-hive' ), $ua ),
		);

		$main_html = '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F9FAFB;border-radius:8px;margin:0 0 24px;">';
		foreach ( $rows as $row ) {
			$main_html .= '<tr>';
			$main_html .= '<td style="padding:10px 16px;font-size:12px;color:#6B7280;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;width:40%;">' . esc_html( $row[0] ) . '</td>';
			$main_html .= '<td style="padding:10px 16px;font-size:13px;color:#111827;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all;">' . esc_html( $row[1] ) . '</td>';
			$main_html .= '</tr>';
		}
		$main_html .= '</table>';

		$main_text = sprintf( '%s: %s', __( 'Time', 'reportedip-hive' ), $when ) . "\n"
			. sprintf( '%s: %s', __( 'IP address', 'reportedip-hive' ), $ip ) . "\n"
			. sprintf( '%s: %s', __( 'Device / Browser', 'reportedip-hive' ), $ua );

		ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => $user->user_email,
				'subject'         => $subject,
				'greeting'        => sprintf(
					/* translators: %s: user display name */
					__( 'Hello %s,', 'reportedip-hive' ),
					$user->display_name
				),
				'intro_text'      => $intro,
				'main_block_html' => $main_html,
				'main_block_text' => $main_text,
				'cta'             => array(
					'label' => __( 'Review your security settings', 'reportedip-hive' ),
					'url'   => admin_url( 'profile.php' ),
				),
				'security_notice' => array(
					'ip'        => $ip,
					'timestamp' => $when,
				),
				'disclaimer'      => __( 'You are receiving this from the ReportedIP Hive security monitor. You can adjust new-device alerts in the plugin settings at any time.', 'reportedip-hive' ),
				'context'         => array(
					'type'    => 'new_device_login',
					'user_id' => $user->ID,
				),
			)
		);

		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->info(
			'New-device login notification sent',
			$ip,
			array(
				'user_id' => $user->ID,
			)
		);
	}

	/**
	 * Clear all known devices for a user (used during 2FA reset).
	 *
	 * @param int $user_id User ID.
	 */
	public static function clear( $user_id ) {
		delete_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_KNOWN_DEVICES );
	}
}
