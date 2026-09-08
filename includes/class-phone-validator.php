<?php
/**
 * Phone-Number Validator for ReportedIP Hive.
 *
 * Pure-function helpers for E.164 normalisation and display formatting.
 *
 * Routing policy lives on the server (the reportedip.com relay enforces an
 * internal country blacklist). Hive only validates that the input is a
 * well-formed E.164 number and forwards it to the relay; the relay returns
 * HTTP 422 with code "country_not_supported" when a number is rejected.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
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
}
