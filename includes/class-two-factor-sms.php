<?php
/**
 * SMS-OTP orchestration via the managed reportedip.de relay (Professional+).
 *
 * Important design constraints:
 *   - SMS is a Professional-tier feature delivered exclusively through the
 *     managed reportedip.de relay. There is no self-hosted provider option —
 *     {@see is_ready()} returns true only while the relay is available.
 *   - The relay AVV with reportedip.de is part of the plan subscription, so no
 *     per-provider DPA confirmation is required on the site.
 *   - Phone numbers are stored encrypted (libsodium / OpenSSL fallback) via
 *     ReportedIP_Hive_Two_Factor_Crypto so a DB dump alone is insufficient.
 *   - SMS bodies are rendered server-side; only the code, expiry and locale
 *     leave the site — no site name, user name, IP, device hints or URLs.
 *   - Audit log entries mask the number to +<country-code> ****<last 2>.
 *   - Rate-limits (3 sends / 15 min, 60 s cooldown) mirror the email flow.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.4.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Provider contract implemented by the managed reportedip.de relay adapter.
 */
interface ReportedIP_Hive_SMS_Provider {

	/** @return string Short identifier stored in the provider-selector setting. */
	public static function id();

	/** @return string Human-readable name shown in admin UI. */
	public static function display_name();

	/** @return string Country/region of the provider for transparency. */
	public static function region();

	/** @return string Link to the provider's AVV/DPA page. */
	public static function avv_url();

	/** @return array<string,array> Schema of required config fields (name => [label, type, required]). */
	public static function config_fields();

	/**
	 * Dispatch the SMS.
	 *
	 * @param string $phone   E.164-formatted phone number (e.g. +49151…).
	 * @param string $message Plain-text SMS body.
	 * @param array  $config  Provider-specific config values.
	 * @return true|WP_Error True on accepted send, WP_Error on failure.
	 */
	public static function send( $phone, $message, $config );
}

/**
 * Orchestrator — called by the 2FA challenge and by the onboarding AJAX flow.
 *
 * Interface + orchestrator ship in the same file because the interface is the
 * contract for the relay adapter registered below; splitting them hurts
 * readability more than it helps.
 */
// phpcs:ignore Generic.Files.OneObjectStructurePerFile.MultipleFound
class ReportedIP_Hive_Two_Factor_SMS {

	const TRANSIENT_CODE_PREFIX = 'reportedip_2fa_sms_';
	const TRANSIENT_RATE_PREFIX = 'reportedip_2fa_sms_rate_';
	const CODE_TTL              = 600;
	const RATE_WINDOW           = 900;
	const MAX_SENDS_PER_WINDOW  = 6;
	const COOLDOWN_SECONDS      = 60;
	const MAX_ATTEMPTS          = 5;
	const CODE_LENGTH           = 6;

	/**
	 * Progressive backoff ladder (seconds) per recipient/user within RATE_WINDOW.
	 * Index 0 = 1st send, index N = (N+1)-th send.
	 * Mirrors the server-side {@see ReportedIP_Constants::RELAY_BACKOFF_LADDER}:
	 * gentle early rungs (0s/30s/60s) cover legitimate resends, escalation only
	 * bites a burst. Keep this array in lock-step with the relay ladder.
	 *
	 * @var int[]
	 */
	const BACKOFF_LADDER = array( 0, 30, 60, 120, 300, 900 );

	/**
	 * Provider id of the managed reportedip.de SMS relay — the only provider.
	 */
	const PROVIDER_RELAY = 'reportedip_relay';

	/**
	 * Provider registry — the managed reportedip.de relay is the only adapter.
	 *
	 * @return array<string, class-string<ReportedIP_Hive_SMS_Provider>>
	 */
	public static function providers() {
		return array(
			self::PROVIDER_RELAY => 'ReportedIP_Hive_SMS_Provider_Relay',
		);
	}

	/**
	 * Is the plugin in a state where it may dispatch SMS messages?
	 *
	 * Hard gate — SMS is a Professional-tier feature delivered through the
	 * managed reportedip.de relay; returns true only while the relay is
	 * available for the current tier and mode.
	 *
	 * @return bool
	 */
	public static function is_ready() {
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}
		return ReportedIP_Hive_Mode_Manager::get_instance()->is_relay_available( 'sms' );
	}

	/**
	 * Normalise and E.164-check a phone number input.
	 *
	 * @param string $input
	 * @return string|WP_Error E.164 number (+…) or WP_Error.
	 */
	public static function normalise_phone( $input ) {
		$raw = preg_replace( '/[^\d+]/', '', (string) $input );
		if ( null === $raw || '' === $raw ) {
			return new WP_Error( 'reportedip_sms_phone_empty', __( 'Please enter a phone number.', 'reportedip-hive' ) );
		}
		if ( '+' !== substr( $raw, 0, 1 ) ) {
			return new WP_Error( 'reportedip_sms_phone_format', __( 'Phone number must start with the international format (e.g. +49...).', 'reportedip-hive' ) );
		}
		$digits = substr( $raw, 1 );
		if ( strlen( $digits ) < 6 || strlen( $digits ) > 15 ) {
			return new WP_Error( 'reportedip_sms_phone_length', __( 'Phone number has an invalid length.', 'reportedip-hive' ) );
		}

		if ( class_exists( 'ReportedIP_Hive_Phone_Validator' ) ) {
			if ( ! ReportedIP_Hive_Phone_Validator::is_valid_e164( $raw ) ) {
				return new WP_Error( 'reportedip_sms_phone_format', __( 'Phone number is not in valid international format.', 'reportedip-hive' ) );
			}
		}

		return $raw;
	}

	/**
	 * Return the encrypted user phone number (decrypted).
	 *
	 * @param int $user_id
	 * @return string|'' Empty string when none stored.
	 */
	public static function get_user_phone( $user_id ) {
		$encrypted = get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_SMS_NUMBER, true );
		if ( empty( $encrypted ) ) {
			return '';
		}
		$decrypted = ReportedIP_Hive_Two_Factor_Crypto::decrypt( $encrypted );
		return false === $decrypted ? '' : $decrypted;
	}

	/**
	 * Store the user phone number encrypted.
	 *
	 * @param int    $user_id
	 * @param string $phone   E.164 number.
	 * @return bool
	 */
	public static function set_user_phone( $user_id, $phone ) {
		$encrypted = ReportedIP_Hive_Two_Factor_Crypto::encrypt( $phone );
		if ( false === $encrypted ) {
			return false;
		}
		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_SMS_NUMBER, $encrypted );
		return true;
	}

	/**
	 * Mask a phone number for logs / UI (e.g. "+49 ****21").
	 *
	 * @param string $phone E.164 number.
	 * @return string
	 */
	public static function mask_phone( $phone ) {
		$phone = (string) $phone;
		if ( '' === $phone || '+' !== substr( $phone, 0, 1 ) ) {
			return '***';
		}
		$matches = array();
		if ( preg_match( '/^(\+\d{1,3})(\d+)(\d{2})$/', $phone, $matches ) ) {
			return $matches[1] . ' ****' . $matches[3];
		}
		return substr( $phone, 0, 2 ) . '****';
	}

	/**
	 * Dispatch a one-time code to the given user's registered phone number.
	 *
	 * @param int $user_id
	 * @return true|WP_Error
	 */
	public static function send_code( $user_id ) {
		if ( ! self::is_ready() ) {
			return new WP_Error(
				'reportedip_sms_not_ready',
				__( 'SMS sending is not configured. Please contact an administrator.', 'reportedip-hive' )
			);
		}

		$phone = self::get_user_phone( $user_id );
		if ( '' === $phone ) {
			return new WP_Error(
				'reportedip_sms_no_number',
				__( 'No phone number is stored for this user.', 'reportedip-hive' )
			);
		}

		$rate_check = self::can_send_code( $user_id );
		if ( is_wp_error( $rate_check ) ) {
			return $rate_check;
		}

		$code           = wp_rand( 100000, 999999 );
		$code_hash      = wp_hash_password( (string) $code );
		$expiry_minutes = (int) ( self::CODE_TTL / 60 );

		/*
		 * The managed reportedip.de relay is the only dispatch path. We transmit
		 * ONLY the code + expiry as template vars — the Service renders the final
		 * SMS body server-side. The verification code never enters a freshly
		 * composed string on the customer site, only the API payload.
		 */
		$result = ReportedIP_Hive_SMS_Provider_Relay::send_code(
			$phone,
			(string) $code,
			$expiry_minutes,
			substr( (string) get_locale(), 0, 2 )
		);

		if ( is_wp_error( $result ) ) {
			$logger = ReportedIP_Hive_Logger::get_instance();
			$logger->warning(
				'2FA SMS dispatch failed',
				ReportedIP_Hive::get_client_ip(),
				array(
					'user_id'      => $user_id,
					'provider'     => self::PROVIDER_RELAY,
					'masked_phone' => self::mask_phone( $phone ),
					'error_code'   => $result->get_error_code(),
				)
			);
			return $result;
		}

		/*
		 * Provider accepted the send — only NOW do we persist the code hash
		 * and advance the local backoff ladder. A pre-dispatch write left
		 * stale code hashes in the transient when the relay short-circuited
		 * (e.g. client-side cooldown returning a synthetic 429) and let the
		 * local ladder drift out of sync with the server-side ladder.
		 */
		set_transient(
			self::TRANSIENT_CODE_PREFIX . $user_id,
			array(
				'code_hash'  => $code_hash,
				'created_at' => time(),
				'attempts'   => 0,
			),
			self::CODE_TTL
		);

		self::record_send( $user_id );

		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->info(
			'2FA SMS code dispatched',
			ReportedIP_Hive::get_client_ip(),
			array(
				'user_id'      => $user_id,
				'provider'     => self::PROVIDER_RELAY,
				'masked_phone' => self::mask_phone( $phone ),
			)
		);

		return true;
	}

	/**
	 * Verify a submitted code against the current transient.
	 *
	 * @param int    $user_id
	 * @param string $code
	 * @return bool
	 */
	public static function verify_code( $user_id, $code ) {
		$key  = self::TRANSIENT_CODE_PREFIX . $user_id;
		$data = get_transient( $key );

		if ( ! is_array( $data ) || empty( $data['code_hash'] ) ) {
			return false;
		}

		$attempts = (int) ( $data['attempts'] ?? 0 );
		if ( $attempts >= self::MAX_ATTEMPTS ) {
			delete_transient( $key );
			return false;
		}

		if ( ! wp_check_password( (string) $code, $data['code_hash'] ) ) {
			$data['attempts'] = $attempts + 1;
			set_transient( $key, $data, self::CODE_TTL );
			return false;
		}

		delete_transient( $key );
		return true;
	}

	/**
	 * Seconds remaining before the user may request a new code.
	 *
	 * @param int $user_id
	 * @return int
	 */
	public static function get_resend_wait_seconds( $user_id ) {
		$rate = get_transient( self::TRANSIENT_RATE_PREFIX . $user_id );
		if ( ! is_array( $rate ) ) {
			return 0;
		}
		$next = (int) ( $rate['next_allowed_at'] ?? 0 );
		return max( 0, $next - time() );
	}

	/**
	 * Look up the backoff delay (seconds) for an attempt count (1-based).
	 *
	 * @param int $attempt Attempt number (1 = first send in window).
	 * @return int
	 */
	private static function delay_for_attempt( $attempt ) {
		$ladder = self::BACKOFF_LADDER;
		$index  = max( 0, min( count( $ladder ) - 1, $attempt - 1 ) );
		return (int) $ladder[ $index ];
	}

	/**
	 * Rate-limit check using the progressive backoff ladder.
	 *
	 * The window resets after RATE_WINDOW seconds of inactivity. Beyond
	 * MAX_SENDS_PER_WINDOW sends the request is rejected outright.
	 *
	 * @param int $user_id
	 * @return true|WP_Error
	 */
	private static function can_send_code( $user_id ) {
		$key  = self::TRANSIENT_RATE_PREFIX . $user_id;
		$data = get_transient( $key );
		$now  = time();

		if ( ! is_array( $data ) ) {
			return true;
		}

		$window_start = (int) ( $data['window_start'] ?? $now );
		if ( $now - $window_start > self::RATE_WINDOW ) {
			// Window expired — caller will start a fresh count via record_send().
			return true;
		}

		$count = (int) ( $data['count'] ?? 0 );
		if ( $count >= self::MAX_SENDS_PER_WINDOW ) {
			return new WP_Error(
				'reportedip_sms_rate',
				__( 'Too many SMS sends in a short time. Please try again later.', 'reportedip-hive' )
			);
		}

		$next = (int) ( $data['next_allowed_at'] ?? 0 );
		if ( $now < $next ) {
			$wait = $next - $now;
			return new WP_Error(
				'reportedip_sms_cooldown',
				sprintf(
					/* translators: %d: seconds to wait */
					__( 'Please wait %d seconds before requesting a new code.', 'reportedip-hive' ),
					$wait
				)
			);
		}

		return true;
	}

	/**
	 * Record a successful send in the rate-limit window using the backoff ladder.
	 *
	 * @param int $user_id
	 */
	private static function record_send( $user_id ) {
		$key  = self::TRANSIENT_RATE_PREFIX . $user_id;
		$data = get_transient( $key );
		$now  = time();

		if ( ! is_array( $data ) || ( $now - (int) ( $data['window_start'] ?? 0 ) ) > self::RATE_WINDOW ) {
			$data = array(
				'count'        => 0,
				'window_start' => $now,
			);
		}
		$data['count']           = (int) ( $data['count'] ?? 0 ) + 1;
		$data['last_sent']       = $now;
		$data['next_allowed_at'] = $now + self::delay_for_attempt( (int) $data['count'] + 1 );

		set_transient( $key, $data, self::RATE_WINDOW );
	}

	/**
	 * Load the relay provider adapter class.
	 */
	public static function load_providers() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/sms-providers/class-sms-provider-relay.php';
	}
}
