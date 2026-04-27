<?php
/**
 * Two-Factor Email OTP Class for ReportedIP Hive.
 *
 * Generates, stores, and validates email-based one-time passwords.
 * Codes are stored as hashed values in WordPress transients.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.3.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Two_Factor_Email
 *
 * Handles email-based 2FA with rate limiting, hashed storage, and brute-force protection.
 */
class ReportedIP_Hive_Two_Factor_Email {

	/**
	 * Code length in digits.
	 *
	 * @var int
	 */
	const CODE_LENGTH = 6;

	/**
	 * Code validity in seconds (10 minutes).
	 *
	 * @var int
	 */
	const CODE_EXPIRY = 600;

	/**
	 * Maximum codes per rate limit window.
	 *
	 * @var int
	 */
	const RATE_LIMIT_MAX = 3;

	/**
	 * Rate limit window in seconds (15 minutes).
	 *
	 * @var int
	 */
	const RATE_LIMIT_WINDOW = 900;

	/**
	 * Maximum verification attempts per code.
	 *
	 * @var int
	 */
	const MAX_VERIFY_ATTEMPTS = 5;

	/**
	 * Minimum seconds between resend requests.
	 *
	 * @var int
	 */
	const RESEND_COOLDOWN = 60;

	/**
	 * Generate a secure 6-digit OTP code.
	 *
	 * @return string 6-digit code.
	 */
	public static function generate_code() {
		return (string) random_int(
			(int) pow( 10, self::CODE_LENGTH - 1 ),
			(int) pow( 10, self::CODE_LENGTH ) - 1
		);
	}

	/**
	 * Generate, store, and send an email OTP code to a user.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return true|\WP_Error True on success, WP_Error on failure.
	 */
	public static function send_code( $user_id ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return new \WP_Error( 'invalid_user', __( 'Invalid user.', 'reportedip-hive' ) );
		}

		$wait = self::get_resend_wait_seconds( $user_id );
		if ( $wait > 0 ) {
			return new \WP_Error(
				'rate_limited',
				sprintf(
					/* translators: %d: seconds to wait */
					__( 'Please wait %d seconds before requesting a new code.', 'reportedip-hive' ),
					$wait
				)
			);
		}

		$code      = self::generate_code();
		$code_hash = wp_hash_password( $code );

		$transient_data = array(
			'code_hash'  => $code_hash,
			'created_at' => time(),
			'attempts'   => 0,
		);
		set_transient( self::get_transient_key( $user_id ), $transient_data, self::CODE_EXPIRY );

		self::increment_rate_limit( $user_id );

		$site_name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$subject   = (string) get_option( 'reportedip_hive_2fa_email_subject', '' );
		if ( '' === $subject ) {
			/* translators: %s: site name */
			$subject = sprintf( __( '[%s] Your verification code', 'reportedip-hive' ), $site_name );
		} else {
			$subject = str_replace( '{site_name}', $site_name, $subject );
		}

		$expiry_minutes = (int) ( self::CODE_EXPIRY / 60 );
		$ip_address     = ReportedIP_Hive::get_client_ip();
		$timestamp      = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );

		$sent = ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => $user->user_email,
				'subject'         => $subject,
				'greeting'        => sprintf(
					/* translators: %s: user display name */
					__( 'Hello %s,', 'reportedip-hive' ),
					$user->display_name
				),
				'intro_text'      => __( 'Use the code below to finish signing in to your account. The code is good for one sign-in only.', 'reportedip-hive' ),
				'main_block_html' => self::render_code_box( $code, $expiry_minutes ),
				'main_block_text' => sprintf(
					/* translators: 1: verification code, 2: minutes valid */
					__( 'Your verification code: %1$s (valid for %2$d minutes)', 'reportedip-hive' ),
					$code,
					$expiry_minutes
				),
				'security_notice' => array(
					'ip'        => $ip_address,
					'timestamp' => $timestamp,
				),
				'disclaimer'      => __( 'Never share this code with anyone. Our team will never ask you for it.', 'reportedip-hive' ),
				'context'         => array(
					'type'    => '2fa_code',
					'user_id' => $user->ID,
				),
			)
		);

		if ( ! $sent ) {
			delete_transient( self::get_transient_key( $user_id ) );
			return new \WP_Error( 'email_failed', __( 'Could not send email.', 'reportedip-hive' ) );
		}

		return true;
	}

	/**
	 * Verify an email OTP code.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $code    6-digit code to verify.
	 * @return bool True if valid, false otherwise.
	 */
	public static function verify_code( $user_id, $code ) {
		if ( ! is_string( $code ) || ! preg_match( '/^\d{' . self::CODE_LENGTH . '}$/', $code ) ) {
			return false;
		}

		$transient_key  = self::get_transient_key( $user_id );
		$transient_data = get_transient( $transient_key );

		if ( false === $transient_data || ! is_array( $transient_data ) ) {
			return false;
		}

		if ( isset( $transient_data['attempts'] ) && $transient_data['attempts'] >= self::MAX_VERIFY_ATTEMPTS ) {
			delete_transient( $transient_key );
			return false;
		}

		$transient_data['attempts'] = ( $transient_data['attempts'] ?? 0 ) + 1;
		$remaining_ttl              = self::CODE_EXPIRY - ( time() - $transient_data['created_at'] );
		if ( $remaining_ttl > 0 ) {
			set_transient( $transient_key, $transient_data, $remaining_ttl );
		}

		if ( wp_check_password( $code, $transient_data['code_hash'] ) ) {
			delete_transient( $transient_key );
			return true;
		}

		return false;
	}

	/**
	 * Check if a new code can be sent (rate limit check).
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool True if sending is allowed.
	 */
	public static function can_send_code( $user_id ) {
		$rate_data = get_transient( self::get_rate_limit_key( $user_id ) );
		if ( false === $rate_data || ! is_array( $rate_data ) ) {
			return true;
		}

		if ( isset( $rate_data['last_sent'] ) ) {
			$elapsed = time() - $rate_data['last_sent'];
			if ( $elapsed < self::RESEND_COOLDOWN ) {
				return false;
			}
		}

		$count = $rate_data['count'] ?? 0;
		return $count < self::RATE_LIMIT_MAX;
	}

	/**
	 * Get seconds until a new code can be sent.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return int Seconds to wait (0 if sending is allowed).
	 */
	public static function get_resend_wait_seconds( $user_id ) {
		$rate_data = get_transient( self::get_rate_limit_key( $user_id ) );
		if ( false === $rate_data || ! is_array( $rate_data ) ) {
			return 0;
		}

		if ( isset( $rate_data['last_sent'] ) ) {
			$elapsed = time() - $rate_data['last_sent'];
			if ( $elapsed < self::RESEND_COOLDOWN ) {
				return self::RESEND_COOLDOWN - $elapsed;
			}
		}

		$count = $rate_data['count'] ?? 0;
		if ( $count >= self::RATE_LIMIT_MAX ) {
			$window_start = $rate_data['window_start'] ?? time();
			$window_end   = $window_start + self::RATE_LIMIT_WINDOW;
			$remaining    = $window_end - time();
			return max( 0, $remaining );
		}

		return 0;
	}

	/**
	 * Increment the rate limit counter for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	private static function increment_rate_limit( $user_id ) {
		$rate_key  = self::get_rate_limit_key( $user_id );
		$rate_data = get_transient( $rate_key );

		if ( false === $rate_data || ! is_array( $rate_data ) ) {
			$rate_data = array(
				'count'        => 0,
				'window_start' => time(),
				'last_sent'    => 0,
			);
		}

		++$rate_data['count'];
		$rate_data['last_sent'] = time();

		$window_remaining = self::RATE_LIMIT_WINDOW - ( time() - $rate_data['window_start'] );
		set_transient( $rate_key, $rate_data, max( $window_remaining, self::RESEND_COOLDOWN ) );
	}

	/**
	 * Get the transient key for storing an email OTP code.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string Transient key.
	 */
	private static function get_transient_key( $user_id ) {
		return 'reportedip_2fa_email_' . (int) $user_id;
	}

	/**
	 * Get the transient key for rate limiting.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return string Transient key.
	 */
	private static function get_rate_limit_key( $user_id ) {
		return 'reportedip_2fa_email_rate_' . (int) $user_id;
	}

	/**
	 * Render the code-box HTML fragment used as the main block in the OTP mail.
	 *
	 * @param string $code           6-digit verification code.
	 * @param int    $expiry_minutes Code validity in minutes.
	 * @return string HTML fragment with the styled code digits and validity hint.
	 */
	private static function render_code_box( $code, $expiry_minutes ) {
		$digit_style = "display:inline-block;width:40px;height:48px;line-height:48px;text-align:center;font-size:24px;font-weight:700;font-family:'SF Mono',SFMono-Regular,Consolas,monospace;background:#F3F4F6;border:1px solid #E5E7EB;border-radius:6px;margin:0 3px;color:#111827;";

		$code_html = '';
		foreach ( str_split( (string) $code ) as $digit ) {
			$code_html .= '<span style="' . esc_attr( $digit_style ) . '">' . esc_html( $digit ) . '</span>';
		}

		ob_start();
		?>
<div style="text-align:center;padding:24px 0;margin:0 0 24px;background:#F9FAFB;border-radius:8px;">
	<p style="margin:0 0 12px;font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#6B7280;font-weight:600;">
		<?php esc_html_e( 'Your verification code', 'reportedip-hive' ); ?>
	</p>
	<div style="margin:0;">
		<?php echo $code_html; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- digit spans are escaped above. ?>
	</div>
	<p style="margin:12px 0 0;font-size:12px;color:#9CA3AF;">
		<?php
		printf(
			/* translators: %d: minutes */
			esc_html__( 'Valid for %d minutes', 'reportedip-hive' ),
			(int) $expiry_minutes
		);
		?>
	</p>
</div>
		<?php
		return (string) ob_get_clean();
	}
}
