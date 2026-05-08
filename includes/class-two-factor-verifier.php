<?php
/**
 * Shared per-method 2FA code verification.
 *
 * Both the login challenge (`ReportedIP_Hive_Two_Factor`) and the password-
 * reset challenge (`ReportedIP_Hive_Two_Factor_Reset_Gate`) need to verify
 * the same code shapes (TOTP / SMS / Email / WebAuthn / Recovery). Before
 * this class was extracted the two callers carried bit-for-bit identical
 * switch statements, so a fix in one would silently miss the other.
 *
 * Logging is intentionally NOT performed here — each surface logs into its
 * own event namespace (`2fa_*` for login, `2fa_reset_*` for reset). Callers
 * may pass an `$on_internal_error` callback that receives a stable reason
 * code (`missing_secret`, `decrypt_failed`, `class_missing`, `unknown_method`)
 * so the surface-specific event types stay in the surface-specific class.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.1
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Two_Factor_Verifier
 *
 * Stateless helper. All methods are static — there is nothing to remember
 * between two verifications.
 */
final class ReportedIP_Hive_Two_Factor_Verifier {

	/**
	 * Verify a submitted code (or WebAuthn assertion payload) against the
	 * stored credentials for `$method` on `$user_id`.
	 *
	 * Returns false for any of:
	 *   - method-specific provider class is missing (SMS / WebAuthn)
	 *   - credential material is missing or unreadable (TOTP)
	 *   - the submitted code does not verify
	 *   - the method id is unknown
	 *
	 * The caller is expected to translate `false` into a generic "Invalid
	 * verification code" message; we do NOT differentiate user-facing
	 * messages by reason because that would leak account state to
	 * unauthenticated callers.
	 *
	 * @param int           $user_id           User to verify against.
	 * @param string        $method            Method identifier (totp / sms /
	 *                                         webauthn / recovery / email).
	 * @param string        $code              Submitted code or WebAuthn
	 *                                         assertion payload.
	 * @param callable|null $on_internal_error Optional callback invoked when
	 *                                         the verification cannot run
	 *                                         because credential material is
	 *                                         missing/corrupt or the provider
	 *                                         class is unavailable. Signature
	 *                                         `function(string $reason, string $method): void`.
	 * @return bool True iff the code verified successfully.
	 */
	public static function verify_method( int $user_id, string $method, string $code, $on_internal_error = null ): bool {
		switch ( $method ) {
			case ReportedIP_Hive_Two_Factor::METHOD_TOTP:
				return self::verify_totp( $user_id, $code, $on_internal_error );

			case ReportedIP_Hive_Two_Factor::METHOD_EMAIL:
				if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Email' ) ) {
					self::report_internal( $on_internal_error, 'class_missing', $method );
					return false;
				}
				return (bool) ReportedIP_Hive_Two_Factor_Email::verify_code( $user_id, $code );

			case ReportedIP_Hive_Two_Factor::METHOD_SMS:
				if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
					self::report_internal( $on_internal_error, 'class_missing', $method );
					return false;
				}
				return (bool) ReportedIP_Hive_Two_Factor_SMS::verify_code( $user_id, $code );

			case ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN:
				if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_WebAuthn' ) ) {
					self::report_internal( $on_internal_error, 'class_missing', $method );
					return false;
				}
				return (bool) ReportedIP_Hive_Two_Factor_WebAuthn::verify( $user_id, $code );

			case ReportedIP_Hive_Two_Factor::METHOD_RECOVERY:
				return (bool) ReportedIP_Hive_Two_Factor_Recovery::verify_code( $user_id, $code );

			default:
				self::report_internal( $on_internal_error, 'unknown_method', $method );
				return false;
		}
	}

	/**
	 * TOTP-specific path so the encryption / window-filter logic lives in
	 * exactly one place. Wraps secret retrieval + libsodium decryption +
	 * memory-zeroing around the `Two_Factor_TOTP::verify_code()` call.
	 *
	 * The `reportedip_2fa_totp_window` filter clamps to [0, 3] — anything
	 * larger would erode brute-force resistance.
	 *
	 * @param int           $user_id           User to verify against.
	 * @param string        $code              Submitted 6-digit code.
	 * @param callable|null $on_internal_error Optional callback for
	 *                                         missing-secret / decrypt-failed
	 *                                         situations.
	 * @return bool
	 */
	private static function verify_totp( int $user_id, string $code, $on_internal_error ): bool {
		$encrypted = get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET, true );
		if ( empty( $encrypted ) ) {
			self::report_internal( $on_internal_error, 'missing_secret', ReportedIP_Hive_Two_Factor::METHOD_TOTP );
			return false;
		}
		$secret = ReportedIP_Hive_Two_Factor_Crypto::decrypt( $encrypted );
		if ( false === $secret ) {
			self::report_internal( $on_internal_error, 'decrypt_failed', ReportedIP_Hive_Two_Factor::METHOD_TOTP );
			return false;
		}

		/**
		 * Configurable TOTP clock-skew tolerance in 30-second windows.
		 * Default 1 (±30 s). Admins can relax to 2 (±60 s) if users complain
		 * about clock drift, but larger windows reduce brute-force resistance.
		 *
		 * @param int $window  Tolerance windows.
		 * @param int $user_id User being verified.
		 * @since 1.4.0
		 */
		$window = (int) apply_filters( 'reportedip_2fa_totp_window', 1, $user_id );
		$window = max( 0, min( 3, $window ) );
		$result = (bool) ReportedIP_Hive_Two_Factor_TOTP::verify_code( $secret, $code, $window );
		ReportedIP_Hive_Two_Factor_Crypto::zero_memory( $secret );
		return $result;
	}

	/**
	 * Invoke the caller-supplied internal-error callback, if any. Swallowing
	 * exceptions here is intentional — verification correctness must never
	 * be derailed by a misbehaving logger.
	 *
	 * @param callable|null $callback Optional callback.
	 * @param string        $reason   Stable reason code.
	 * @param string        $method   Method identifier the verification was
	 *                                attempted for.
	 */
	private static function report_internal( $callback, string $reason, string $method ): void {
		if ( ! is_callable( $callback ) ) {
			return;
		}
		try {
			call_user_func( $callback, $reason, $method );
		} catch ( \Throwable $e ) {
			unset( $e );
		}
	}
}
