<?php
/**
 * Two-Factor Recovery Codes Class for ReportedIP Hive.
 *
 * Generates, stores (hashed), and validates single-use recovery codes.
 * Recovery codes are the last resort when TOTP and email are unavailable.
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
 * Class ReportedIP_Hive_Two_Factor_Recovery
 *
 * Manages backup recovery codes for 2FA account recovery.
 */
class ReportedIP_Hive_Two_Factor_Recovery {

	/**
	 * Number of recovery codes to generate.
	 *
	 * @var int
	 */
	const CODE_COUNT = 10;

	/**
	 * Length of each recovery code (characters before formatting).
	 *
	 * @var int
	 */
	const CODE_LENGTH = 8;

	/**
	 * User meta key for storing hashed recovery codes.
	 *
	 * @var string
	 */
	const META_KEY_CODES = 'reportedip_hive_2fa_recovery_codes';

	/**
	 * User meta key for remaining code count.
	 *
	 * @var string
	 */
	const META_KEY_REMAINING = 'reportedip_hive_2fa_recovery_codes_remaining';

	/**
	 * Warning threshold for low recovery codes.
	 *
	 * @var int
	 */
	const LOW_CODE_WARNING = 3;

	/**
	 * Allowed characters for recovery codes (lowercase alphanumeric, no ambiguous chars).
	 *
	 * @var string
	 */
	const CHARSET = 'abcdefghjkmnpqrstuvwxyz23456789';

	/**
	 * Generate a set of plaintext recovery codes.
	 *
	 * @param int $count Number of codes to generate.
	 * @return array Array of plaintext codes in format 'xxxx-xxxx'.
	 */
	public static function generate_codes( $count = self::CODE_COUNT ) {
		$codes       = array();
		$charset_len = strlen( self::CHARSET );

		for ( $i = 0; $i < $count; $i++ ) {
			$code = '';
			for ( $j = 0; $j < self::CODE_LENGTH; $j++ ) {
				$code .= self::CHARSET[ random_int( 0, $charset_len - 1 ) ];
			}
			$codes[] = substr( $code, 0, 4 ) . '-' . substr( $code, 4 );
		}

		return $codes;
	}

	/**
	 * Hash and store recovery codes for a user.
	 *
	 * Replaces any existing codes.
	 *
	 * @param int   $user_id WordPress user ID.
	 * @param array $codes   Array of plaintext codes.
	 */
	public static function store_codes( $user_id, $codes ) {
		$hashed_codes = array();
		foreach ( $codes as $code ) {
			$normalized     = str_replace( '-', '', $code );
			$hashed_codes[] = wp_hash_password( $normalized );
		}

		update_user_meta( $user_id, self::META_KEY_CODES, wp_json_encode( $hashed_codes ) );
		update_user_meta( $user_id, self::META_KEY_REMAINING, count( $hashed_codes ) );
	}

	/**
	 * Verify a recovery code and consume it if valid.
	 *
	 * Each code can only be used once — it is removed from storage after verification.
	 *
	 * @param int    $user_id WordPress user ID.
	 * @param string $code    Recovery code to verify (with or without dash).
	 * @return bool True if valid (and now consumed), false otherwise.
	 */
	public static function verify_code( $user_id, $code ) {
		if ( ! is_string( $code ) || strlen( str_replace( '-', '', $code ) ) !== self::CODE_LENGTH ) {
			return false;
		}

		$normalized = strtolower( str_replace( '-', '', trim( $code ) ) );

		$stored_json = get_user_meta( $user_id, self::META_KEY_CODES, true );
		if ( empty( $stored_json ) ) {
			return false;
		}

		$hashed_codes = json_decode( $stored_json, true );
		if ( ! is_array( $hashed_codes ) || empty( $hashed_codes ) ) {
			return false;
		}

		$matched_index = null;
		foreach ( $hashed_codes as $index => $hash ) {
			if ( wp_check_password( $normalized, $hash ) ) {
				$matched_index = $index;
				break;
			}
		}

		if ( null === $matched_index ) {
			return false;
		}

		array_splice( $hashed_codes, $matched_index, 1 );
		update_user_meta( $user_id, self::META_KEY_CODES, wp_json_encode( $hashed_codes ) );
		update_user_meta( $user_id, self::META_KEY_REMAINING, count( $hashed_codes ) );

		return true;
	}

	/**
	 * Get the number of remaining recovery codes.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return int Number of remaining codes.
	 */
	public static function get_remaining_count( $user_id ) {
		return (int) get_user_meta( $user_id, self::META_KEY_REMAINING, true );
	}

	/**
	 * Check if recovery codes are running low.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool True if remaining codes are at or below warning threshold.
	 */
	public static function is_low( $user_id ) {
		$remaining = self::get_remaining_count( $user_id );
		return $remaining > 0 && $remaining <= self::LOW_CODE_WARNING;
	}

	/**
	 * Check if all recovery codes have been consumed.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return bool True if no recovery codes remain.
	 */
	public static function is_exhausted( $user_id ) {
		return self::get_remaining_count( $user_id ) === 0;
	}

	/**
	 * Generate new recovery codes, store them, and return the plaintext.
	 *
	 * This replaces all existing codes.
	 *
	 * @param int $user_id WordPress user ID.
	 * @return array Array of new plaintext codes.
	 */
	public static function regenerate_codes( $user_id ) {
		$codes = self::generate_codes();
		self::store_codes( $user_id, $codes );
		return $codes;
	}

	/**
	 * Delete all recovery codes for a user.
	 *
	 * @param int $user_id WordPress user ID.
	 */
	public static function delete_codes( $user_id ) {
		delete_user_meta( $user_id, self::META_KEY_CODES );
		delete_user_meta( $user_id, self::META_KEY_REMAINING );
	}
}
