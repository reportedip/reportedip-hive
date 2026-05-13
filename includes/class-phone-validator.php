<?php
/**
 * Phone-Number Validator for ReportedIP Hive.
 *
 * Pure-function helpers for E.164 normalisation and display formatting.
 *
 * Routing policy lives on the server (the reportedip.de relay enforces an
 * internal country blacklist). Hive only validates that the input is a
 * well-formed E.164 number and forwards it to the relay; the relay returns
 * HTTP 422 with code "country_not_supported" when a number is rejected.
 *
 * Locally configured SMS providers (seven.io, sipgate, MessageBird) bypass
 * the relay entirely — the site operator pays directly and decides which
 * destinations to allow.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.6.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Phone_Validator
 */
class ReportedIP_Hive_Phone_Validator {

	/**
	 * Normalise an arbitrary phone-number input to a candidate E.164 string.
	 *
	 * @param string $input Raw input.
	 * @return string|null  Candidate '+'-prefixed digits string, or null on garbage.
	 */
	public static function normalise( $input ) {
		$stripped = preg_replace( '/[\s\(\)\-\.\/]/', '', $input );
		if ( null === $stripped || $stripped === '' ) {
			return null;
		}
		if ( 0 === strpos( $stripped, '00' ) ) {
			$stripped = '+' . substr( $stripped, 2 );
		}
		if ( '+' !== substr( $stripped, 0, 1 ) ) {
			return null;
		}
		$digits = substr( $stripped, 1 );
		if ( $digits === '' || ! ctype_digit( $digits ) ) {
			return null;
		}
		return '+' . $digits;
	}

	/**
	 * Strict E.164: '+' followed by 7–15 digits, leading digit 1–9.
	 *
	 * @param string $phone Phone number.
	 * @return bool
	 */
	public static function is_valid_e164( $phone ) {
		if ( $phone === '' ) {
			return false;
		}
		return (bool) preg_match( '/^\+[1-9]\d{6,14}$/', $phone );
	}

	/**
	 * Return the country-code prefix as a best-guess (1–3 digits after '+').
	 *
	 * The Hive plugin no longer maintains a country list; the server is the
	 * authority. This helper exists only to format display strings.
	 *
	 * @param string $phone Valid E.164 phone number.
	 * @return string|null
	 */
	public static function get_country_code( $phone ) {
		if ( ! self::is_valid_e164( $phone ) ) {
			return null;
		}
		return '+' . substr( $phone, 1, 3 );
	}

	/**
	 * Backwards-compatibility shim — was the EU whitelist gate, now a no-op
	 * pass-through that just re-checks E.164 validity.
	 *
	 * @deprecated 1.7.0 Routing decisions moved to the server. Use
	 *             {@see is_valid_e164()} instead. Kept so that older callers
	 *             do not break.
	 *
	 * @param string $phone Phone number.
	 * @return bool
	 */
	public static function is_eu( $phone ) {
		return self::is_valid_e164( $phone );
	}

	/**
	 * Pretty-print an E.164 number for display.
	 *
	 * @param string $phone Phone number.
	 * @return string
	 */
	public static function format_for_display( $phone ) {
		if ( ! self::is_valid_e164( $phone ) ) {
			return (string) $phone;
		}
		$cc   = self::get_country_code( $phone );
		$rest = substr( $phone, strlen( $cc ) );
		$head = substr( $rest, 0, 3 );
		$tail = substr( $rest, 3 );
		$tail = trim( chunk_split( $tail, 4, ' ' ) );
		return trim( $cc . ' ' . $head . ' ' . $tail );
	}
}
