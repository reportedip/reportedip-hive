<?php
/**
 * SMS-OTP orchestration (DSGVO-conformant EU-provider adapters only).
 *
 * Important design constraints:
 *   - NO default provider is shipped — the admin MUST configure an own account.
 *   - The admin MUST confirm an AVV/DPA with the chosen provider before the
 *     plugin will dispatch any SMS (hard gate in send_code()).
 *   - Phone numbers are stored encrypted (libsodium / OpenSSL fallback) via
 *     ReportedIP_Hive_Two_Factor_Crypto so a DB dump alone is insufficient.
 *   - SMS bodies contain only the code and a minimal German notice — no site
 *     name, no user name, no IP, no device hints, no URLs.
 *   - Audit log entries mask the number to +<country-code> ****<last 2>.
 *   - Rate-limits (3 sends / 15 min, 60 s cooldown) mirror the email flow.
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
 * Provider contract. Every EU-provider adapter implements this.
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
 * contract for the provider adapters registered below; splitting them hurts
 * readability more than it helps.
 */
// phpcs:ignore Generic.Files.OneObjectStructurePerFile.MultipleFound
class ReportedIP_Hive_Two_Factor_SMS {

	const TRANSIENT_CODE_PREFIX = 'reportedip_2fa_sms_';
	const TRANSIENT_RATE_PREFIX = 'reportedip_2fa_sms_rate_';
	const CODE_TTL              = 600;
	const RATE_WINDOW           = 900;
	const MAX_SENDS_PER_WINDOW  = 3;
	const COOLDOWN_SECONDS      = 60;
	const MAX_ATTEMPTS          = 5;
	const CODE_LENGTH           = 6;

	/**
	 * Option names (global admin settings).
	 */
	const OPT_PROVIDER      = 'reportedip_hive_2fa_sms_provider';
	const OPT_AVV_CONFIRMED = 'reportedip_hive_2fa_sms_avv_confirmed';
	const OPT_FROM          = 'reportedip_hive_2fa_sms_from';
	const OPT_PROVIDER_CONF = 'reportedip_hive_2fa_sms_provider_config';

	/**
	 * Provider registry — add new adapters here.
	 *
	 * @return array<string, class-string<ReportedIP_Hive_SMS_Provider>>
	 */
	public static function providers() {
		$registry = array(
			'sevenio'     => 'ReportedIP_Hive_SMS_Provider_Sevenio',
			'sipgate'     => 'ReportedIP_Hive_SMS_Provider_Sipgate',
			'messagebird' => 'ReportedIP_Hive_SMS_Provider_MessageBird',
		);

		/**
		 * Allow third parties to register additional EU-compliant providers.
		 * Providers registered via this filter MUST implement the
		 * ReportedIP_Hive_SMS_Provider interface.
		 */
		return (array) apply_filters( 'reportedip_2fa_sms_providers', $registry );
	}

	/**
	 * Return the currently selected provider class name, or '' if not configured.
	 *
	 * @return string
	 */
	public static function get_active_provider_class() {
		$selected = (string) get_option( self::OPT_PROVIDER, '' );
		$registry = self::providers();
		if ( '' === $selected || empty( $registry[ $selected ] ) ) {
			return '';
		}
		$class = $registry[ $selected ];
		return class_exists( $class ) ? $class : '';
	}

	/**
	 * Is the plugin in a state where it may dispatch SMS messages?
	 *
	 * Hard gate — returns false unless provider is chosen, configured AND AVV
	 * was explicitly confirmed by the admin.
	 *
	 * @return bool
	 */
	public static function is_ready() {
		if ( ! self::get_active_provider_class() ) {
			return false;
		}
		if ( ! (bool) get_option( self::OPT_AVV_CONFIRMED, false ) ) {
			return false;
		}
		$config = self::get_provider_config();
		return ! empty( $config );
	}

	/**
	 * Load and decrypt the active provider's config array.
	 *
	 * Secrets in the config (api_key, token etc.) are stored encrypted; this
	 * returns the decrypted form for actual dispatch.
	 *
	 * @return array
	 */
	public static function get_provider_config() {
		$raw = get_option( self::OPT_PROVIDER_CONF, '' );
		if ( empty( $raw ) ) {
			return array();
		}
		$decrypted = ReportedIP_Hive_Two_Factor_Crypto::decrypt( $raw );
		if ( false === $decrypted ) {
			return array();
		}
		$decoded = json_decode( $decrypted, true );
		return is_array( $decoded ) ? $decoded : array();
	}

	/**
	 * Persist the provider config encrypted.
	 *
	 * @param array $config
	 * @return bool
	 */
	public static function save_provider_config( $config ) {
		if ( ! is_array( $config ) || empty( $config ) ) {
			delete_option( self::OPT_PROVIDER_CONF );
			return true;
		}
		$encrypted = ReportedIP_Hive_Two_Factor_Crypto::encrypt( wp_json_encode( $config ) );
		if ( false === $encrypted ) {
			return false;
		}
		update_option( self::OPT_PROVIDER_CONF, $encrypted, false );
		return true;
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

		$code = wp_rand( 100000, 999999 );

		$code_hash = wp_hash_password( (string) $code );
		set_transient(
			self::TRANSIENT_CODE_PREFIX . $user_id,
			array(
				'code_hash'  => $code_hash,
				'created_at' => time(),
				'attempts'   => 0,
			),
			self::CODE_TTL
		);

		$provider_class = self::get_active_provider_class();
		$config         = self::get_provider_config();
		$expiry_minutes = (int) ( self::CODE_TTL / 60 );

		$body = sprintf(
			/* translators: 1: 6-digit code, 2: validity in minutes */
			__( 'Your verification code: %1$d (valid for %2$d minutes). Never share this code.', 'reportedip-hive' ),
			$code,
			$expiry_minutes
		);

		$result = call_user_func( array( $provider_class, 'send' ), $phone, $body, $config );

		if ( is_wp_error( $result ) ) {
			$logger = ReportedIP_Hive_Logger::get_instance();
			$logger->warning(
				'2FA SMS dispatch failed',
				ReportedIP_Hive::get_client_ip(),
				array(
					'user_id'      => $user_id,
					'provider'     => call_user_func( array( $provider_class, 'id' ) ),
					'masked_phone' => self::mask_phone( $phone ),
					'error_code'   => $result->get_error_code(),
				)
			);
			return $result;
		}

		self::record_send( $user_id );

		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->info(
			'2FA SMS code dispatched',
			ReportedIP_Hive::get_client_ip(),
			array(
				'user_id'      => $user_id,
				'provider'     => call_user_func( array( $provider_class, 'id' ) ),
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
		$last = (int) ( $rate['last_sent'] ?? 0 );
		return max( 0, ( $last + self::COOLDOWN_SECONDS ) - time() );
	}

	/**
	 * Rate-limit check (window + cooldown). Returns true or WP_Error.
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

		$last = (int) ( $data['last_sent'] ?? 0 );
		if ( $now - $last < self::COOLDOWN_SECONDS ) {
			$wait = self::COOLDOWN_SECONDS - ( $now - $last );
			return new WP_Error(
				'reportedip_sms_cooldown',
				sprintf(
					/* translators: %d: seconds to wait */
					__( 'Please wait %d seconds before requesting a new code.', 'reportedip-hive' ),
					$wait
				)
			);
		}

		$window_start = (int) ( $data['window_start'] ?? $now );
		if ( $now - $window_start > self::RATE_WINDOW ) {
			return true;
		}

		$count = (int) ( $data['count'] ?? 0 );
		if ( $count >= self::MAX_SENDS_PER_WINDOW ) {
			return new WP_Error(
				'reportedip_sms_rate',
				__( 'Too many SMS sends in a short time. Please try again later.', 'reportedip-hive' )
			);
		}

		return true;
	}

	/**
	 * Record a successful send in the rate-limit window.
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
		$data['count']     = (int) ( $data['count'] ?? 0 ) + 1;
		$data['last_sent'] = $now;

		set_transient( $key, $data, self::RATE_WINDOW );
	}

	/**
	 * Load provider adapter classes.
	 */
	public static function load_providers() {
		$base = REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/sms-providers/';
		require_once $base . 'class-sms-provider-sevenio.php';
		require_once $base . 'class-sms-provider-sipgate.php';
		require_once $base . 'class-sms-provider-messagebird.php';
	}
}
