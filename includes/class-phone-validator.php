<?php
/**
 * Phone-Number Validator for ReportedIP Hive.
 *
 * Mirrors the server-side validator (defence in depth): Hive validates phone
 * numbers BEFORE handing them to the SMS provider, regardless of whether the
 * actual send goes through a local provider (Sevenio/Sipgate/MessageBird) or
 * the reportedip.de relay endpoint.
 *
 * EU country-code whitelist defaults match the service-side constant; can be
 * overridden via WP option `reportedip_hive_eu_phone_country_codes`
 * or filter `reportedip_hive_eu_phone_country_codes`.
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
 *
 * Pure-function helpers for E.164 normalisation and EU restriction.
 */
class ReportedIP_Hive_Phone_Validator {

	/**
	 * Default EU country codes (E.164 prefixes).
	 *
	 * @var string[]
	 */
	const DEFAULT_EU_CODES = array(
		'+49',
		'+43',
		'+41',
		'+31',
		'+32',
		'+352',
		'+33',
		'+39',
		'+34',
		'+351',
		'+48',
		'+420',
		'+421',
		'+36',
		'+45',
		'+46',
		'+47',
		'+358',
		'+353',
		'+354',
		'+30',
		'+386',
		'+385',
		'+359',
		'+40',
		'+371',
		'+370',
		'+372',
		'+356',
		'+357',
	);

	/**
	 * Normalise an arbitrary phone-number input to a candidate E.164 string.
	 *
	 * @param string $input Raw input.
	 * @return string|null  Candidate '+'-prefixed digits string, or null on garbage.
	 */
	public static function normalise( $input ) {
		if ( ! is_string( $input ) ) {
			return null;
		}
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
		if ( ! is_string( $phone ) || $phone === '' ) {
			return false;
		}
		return (bool) preg_match( '/^\+[1-9]\d{6,14}$/', $phone );
	}

	/**
	 * Get the country-code prefix matching the active whitelist (longest match).
	 *
	 * @param string        $phone     Valid E.164 phone number.
	 * @param string[]|null $whitelist Optional explicit whitelist.
	 * @return string|null
	 */
	public static function get_country_code( $phone, $whitelist = null ) {
		if ( ! self::is_valid_e164( $phone ) ) {
			return null;
		}
		if ( null === $whitelist ) {
			$whitelist = self::get_whitelist();
		}
		$sorted = $whitelist;
		usort(
			$sorted,
			static function ( $a, $b ) {
				return strlen( $b ) - strlen( $a );
			}
		);
		foreach ( $sorted as $cc ) {
			if ( 0 === strpos( $phone, $cc ) ) {
				return $cc;
			}
		}
		return '+' . substr( $phone, 1, 3 );
	}

	/**
	 * Whether the given phone number's country code is on the EU whitelist.
	 *
	 * @param string        $phone     Phone number.
	 * @param string[]|null $whitelist Optional explicit whitelist.
	 * @return bool
	 */
	public static function is_eu( $phone, $whitelist = null ) {
		if ( ! self::is_valid_e164( $phone ) ) {
			return false;
		}
		if ( null === $whitelist ) {
			$whitelist = self::get_whitelist();
		}
		foreach ( $whitelist as $cc ) {
			if ( 0 === strpos( $phone, $cc ) ) {
				return true;
			}
		}
		return false;
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

	/**
	 * Return the active EU country-code whitelist.
	 * Default constant + WP option override + filter.
	 *
	 * @return string[]
	 */
	public static function get_whitelist() {
		$list     = self::DEFAULT_EU_CODES;
		$override = get_option( 'reportedip_hive_eu_phone_country_codes', null );
		if ( is_array( $override ) && ! empty( $override ) ) {
			$list = $override;
		}
		$filtered = apply_filters( 'reportedip_hive_eu_phone_country_codes', $list );
		return is_array( $filtered ) ? array_values( array_unique( $filtered ) ) : $list;
	}
}
