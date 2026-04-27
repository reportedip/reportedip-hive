<?php
/**
 * Two-Factor TOTP Class for ReportedIP Hive.
 *
 * Self-contained RFC 6238 TOTP implementation.
 * No external library required — compatible with PHP 7.4+.
 * Works with Google Authenticator, Microsoft Authenticator, Authy, etc.
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
 * Class ReportedIP_Hive_Two_Factor_TOTP
 *
 * Implements RFC 6238 (TOTP) and RFC 4226 (HOTP) for time-based one-time passwords.
 */
class ReportedIP_Hive_Two_Factor_TOTP {

	/**
	 * Time step in seconds (standard: 30).
	 *
	 * @var int
	 */
	const TIME_STEP = 30;

	/**
	 * Code length in digits.
	 *
	 * @var int
	 */
	const CODE_LENGTH = 6;

	/**
	 * Secret length in bytes before Base32 encoding.
	 * 20 bytes = 160 bits (standard for TOTP).
	 *
	 * @var int
	 */
	const SECRET_BYTES = 20;

	/**
	 * Modulo divisor for code truncation (10^CODE_LENGTH = 1000000).
	 *
	 * @var int
	 */
	const CODE_MODULO = 1000000;

	/**
	 * Base32 alphabet per RFC 4648.
	 *
	 * @var string
	 */
	const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generate a new random TOTP secret.
	 *
	 * @return string Base32-encoded secret (32 characters for 20 bytes).
	 */
	public static function generate_secret() {
		$random_bytes = random_bytes( self::SECRET_BYTES );
		return self::base32_encode( $random_bytes );
	}

	/**
	 * Generate an otpauth:// URI for QR code generation.
	 *
	 * @param string $secret     Base32-encoded TOTP secret.
	 * @param string $user_login WordPress username or email.
	 * @param string $issuer     Service name (e.g. site name).
	 * @return string otpauth:// URI.
	 */
	public static function generate_qr_uri( $secret, $user_login, $issuer = '' ) {
		if ( empty( $issuer ) ) {
			$site_name = trim( (string) get_bloginfo( 'name' ) );
			$host      = wp_parse_url( home_url(), PHP_URL_HOST );
			if ( $host && false === stripos( $site_name, (string) $host ) ) {
				$issuer = $site_name ? $site_name . ' (' . $host . ')' : $host;
			} else {
				$issuer = $site_name ? $site_name : (string) $host;
			}
		}

		$issuer     = str_replace( ':', '-', (string) $issuer );
		$user_login = str_replace( ':', '-', $user_login );

		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $user_login );

		return sprintf(
			'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d',
			$label,
			$secret,
			rawurlencode( $issuer ),
			self::CODE_LENGTH,
			self::TIME_STEP
		);
	}

	/**
	 * Verify a TOTP code against a secret.
	 *
	 * Checks the current time step and ±window steps to account for clock drift.
	 *
	 * @param string $secret Base32-encoded TOTP secret.
	 * @param string $code   6-digit code to verify.
	 * @param int    $window Number of time steps to check in each direction (default: 1 = ±30s).
	 * @return bool True if the code is valid.
	 */
	public static function verify_code( $secret, $code, $window = 1 ) {
		if ( ! is_string( $code ) || ! preg_match( '/^\d{' . self::CODE_LENGTH . '}$/', $code ) ) {
			return false;
		}

		$current_step = self::get_time_step();

		for ( $offset = -$window; $offset <= $window; $offset++ ) {
			$expected = self::calculate_code( $secret, $current_step + $offset );
			if ( false === $expected ) {
				continue;
			}
			if ( hash_equals( $expected, $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Calculate a TOTP code for a given counter value.
	 *
	 * Implements RFC 4226 Section 5.3 (HOTP generation) with HMAC-SHA1.
	 *
	 * @param string $secret  Base32-encoded secret.
	 * @param int    $counter Counter value (time step).
	 * @return string|false 6-digit zero-padded code or false on error.
	 */
	public static function calculate_code( $secret, $counter ) {
		$key = self::base32_decode( $secret );
		if ( false === $key || strlen( $key ) < 1 ) {
			return false;
		}

		$counter_bytes = pack( 'N*', 0, $counter );

		$hash = hash_hmac( 'sha1', $counter_bytes, $key, true );
		if ( strlen( $hash ) < 20 ) {
			return false;
		}

		$offset = ord( $hash[19] ) & 0x0F;

		$binary = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xFF );

		$otp = $binary % self::CODE_MODULO;

		return str_pad( (string) $otp, self::CODE_LENGTH, '0', STR_PAD_LEFT );
	}

	/**
	 * Get the current TOTP time step.
	 *
	 * @param int|null $timestamp Unix timestamp (default: current time).
	 * @return int Current time step counter.
	 */
	public static function get_time_step( $timestamp = null ) {
		if ( null === $timestamp ) {
			$timestamp = time();
		}
		return (int) floor( $timestamp / self::TIME_STEP );
	}

	/**
	 * Encode binary data to Base32 (RFC 4648).
	 *
	 * @param string $data Binary data to encode.
	 * @return string Base32-encoded string.
	 */
	public static function base32_encode( $data ) {
		if ( $data === '' ) {
			return '';
		}

		$binary = '';
		for ( $i = 0, $len = strlen( $data ); $i < $len; $i++ ) {
			$binary .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		$result = '';
		$chunks = str_split( $binary, 5 );
		foreach ( $chunks as $chunk ) {
			$chunk   = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$result .= self::BASE32_ALPHABET[ bindec( $chunk ) ];
		}

		return $result;
	}

	/**
	 * Decode a Base32-encoded string to binary (RFC 4648).
	 *
	 * @param string $input Base32-encoded string.
	 * @return string|false Binary data or false on invalid input.
	 */
	public static function base32_decode( $input ) {
		if ( ! is_string( $input ) || $input === '' ) {
			return false;
		}

		$input = strtoupper( trim( $input ) );
		$input = rtrim( $input, '=' );

		if ( preg_match( '/[^A-Z2-7]/', $input ) ) {
			return false;
		}

		$binary = '';
		for ( $i = 0, $len = strlen( $input ); $i < $len; $i++ ) {
			$val = strpos( self::BASE32_ALPHABET, $input[ $i ] );
			if ( false === $val ) {
				return false;
			}
			$binary .= str_pad( decbin( $val ), 5, '0', STR_PAD_LEFT );
		}

		$result = '';
		$chunks = str_split( $binary, 8 );
		foreach ( $chunks as $chunk ) {
			if ( strlen( $chunk ) < 8 ) {
				break;
			}
			$result .= chr( bindec( $chunk ) );
		}

		return $result;
	}
}
