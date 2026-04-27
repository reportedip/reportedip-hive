<?php
/**
 * Two-Factor Crypto Class for ReportedIP Hive.
 *
 * Handles encryption and decryption of TOTP secrets at rest.
 * Uses libsodium (PHP 7.2+) as primary method with OpenSSL AES-256-GCM fallback.
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
 * Class ReportedIP_Hive_Two_Factor_Crypto
 *
 * Provides authenticated encryption for sensitive 2FA data (TOTP secrets).
 * Secrets are encrypted before storage in user meta and decrypted on read.
 */
class ReportedIP_Hive_Two_Factor_Crypto {

	/**
	 * Encryption method identifier for sodium.
	 *
	 * @var string
	 */
	const METHOD_SODIUM = 'sodium';

	/**
	 * Encryption method identifier for OpenSSL fallback.
	 *
	 * @var string
	 */
	const METHOD_OPENSSL = 'openssl';

	/**
	 * OpenSSL cipher algorithm.
	 *
	 * @var string
	 */
	const OPENSSL_CIPHER = 'aes-256-gcm';

	/**
	 * GCM authentication tag length in bytes (per AES-GCM specification).
	 *
	 * @var int
	 */
	const OPENSSL_GCM_TAG_LENGTH = 16;

	/**
	 * Cached result for sodium availability (null = not yet checked).
	 *
	 * @var bool|null
	 */
	private static $sodium_available = null;

	/**
	 * Cached result for OpenSSL availability (null = not yet checked).
	 *
	 * @var bool|null
	 */
	private static $openssl_available = null;

	/**
	 * Encrypt a plaintext string.
	 *
	 * Returns a base64-encoded string containing method prefix, nonce, and ciphertext.
	 * Format: base64( method_byte + nonce + ciphertext + tag )
	 *
	 * @param string $plaintext The data to encrypt.
	 * @return string|false Encrypted string or false on failure.
	 */
	public static function encrypt( $plaintext ) {
		if ( ! is_string( $plaintext ) || $plaintext === '' ) {
			return false;
		}

		$key = self::get_key();
		if ( false === $key ) {
			return false;
		}

		try {
			if ( self::has_sodium() ) {
				$result = self::encrypt_sodium( $plaintext, $key );
			} elseif ( self::has_openssl() ) {
				$result = self::encrypt_openssl( $plaintext, $key );
			} else {
				$result = false;
			}
		} finally {
			self::zero_memory( $key );
		}

		return $result;
	}

	/**
	 * Decrypt an encrypted string.
	 *
	 * @param string $encrypted The encrypted data (base64-encoded).
	 * @return string|false Decrypted plaintext or false on failure.
	 */
	public static function decrypt( $encrypted ) {
		if ( ! is_string( $encrypted ) || $encrypted === '' ) {
			return false;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Required for crypto storage format
		$raw = base64_decode( $encrypted, true );
		if ( false === $raw || strlen( $raw ) < 2 ) {
			return false;
		}

		$key = self::get_key();
		if ( false === $key ) {
			return false;
		}

		try {
			$method_byte = ord( $raw[0] );
			$payload     = substr( $raw, 1 );

			if ( 1 === $method_byte && self::has_sodium() ) {
				$result = self::decrypt_sodium( $payload, $key );
			} elseif ( 2 === $method_byte && self::has_openssl() ) {
				$result = self::decrypt_openssl( $payload, $key );
			} else {
				$result = false;
			}
		} finally {
			self::zero_memory( $key );
		}

		return $result;
	}

	/**
	 * Encrypt using libsodium.
	 *
	 * @param string $plaintext Data to encrypt.
	 * @param string $key       32-byte encryption key.
	 * @return string|false Base64-encoded encrypted data or false.
	 */
	private static function encrypt_sodium( $plaintext, $key ) {
		try {
			$nonce      = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$ciphertext = sodium_crypto_secretbox( $plaintext, $nonce, $key );

			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Required for crypto storage format
			return base64_encode( chr( 1 ) . $nonce . $ciphertext );
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * Decrypt using libsodium.
	 *
	 * @param string $payload Nonce + ciphertext.
	 * @param string $key     32-byte encryption key.
	 * @return string|false Decrypted plaintext or false.
	 */
	private static function decrypt_sodium( $payload, $key ) {
		$nonce_len = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;

		if ( strlen( $payload ) < $nonce_len + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) {
			return false;
		}

		$nonce      = substr( $payload, 0, $nonce_len );
		$ciphertext = substr( $payload, $nonce_len );

		try {
			$plaintext = sodium_crypto_secretbox_open( $ciphertext, $nonce, $key );
			return ( false === $plaintext ) ? false : $plaintext;
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * Encrypt using OpenSSL AES-256-GCM (fallback).
	 *
	 * @param string $plaintext Data to encrypt.
	 * @param string $key       32-byte encryption key.
	 * @return string|false Base64-encoded encrypted data or false.
	 */
	private static function encrypt_openssl( $plaintext, $key ) {
		$iv_len = openssl_cipher_iv_length( self::OPENSSL_CIPHER );
		if ( false === $iv_len ) {
			return false;
		}

		try {
			$iv  = random_bytes( $iv_len );
			$tag = '';

			$ciphertext = openssl_encrypt(
				$plaintext,
				self::OPENSSL_CIPHER,
				$key,
				OPENSSL_RAW_DATA,
				$iv,
				$tag,
				'',
				self::OPENSSL_GCM_TAG_LENGTH
			);

			if ( false === $ciphertext ) {
				return false;
			}

			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Required for crypto storage format
			return base64_encode( chr( 2 ) . $iv . $tag . $ciphertext );
		} catch ( \Exception $e ) {
			return false;
		}
	}

	/**
	 * Decrypt using OpenSSL AES-256-GCM (fallback).
	 *
	 * @param string $payload IV + tag + ciphertext.
	 * @param string $key     32-byte encryption key.
	 * @return string|false Decrypted plaintext or false.
	 */
	private static function decrypt_openssl( $payload, $key ) {
		$iv_len  = openssl_cipher_iv_length( self::OPENSSL_CIPHER );
		$tag_len = self::OPENSSL_GCM_TAG_LENGTH;

		if ( false === $iv_len || strlen( $payload ) < $iv_len + $tag_len + 1 ) {
			return false;
		}

		$iv         = substr( $payload, 0, $iv_len );
		$tag        = substr( $payload, $iv_len, $tag_len );
		$ciphertext = substr( $payload, $iv_len + $tag_len );

		$plaintext = openssl_decrypt(
			$ciphertext,
			self::OPENSSL_CIPHER,
			$key,
			OPENSSL_RAW_DATA,
			$iv,
			$tag
		);

		return ( false === $plaintext ) ? false : $plaintext;
	}

	/**
	 * Derive a 32-byte encryption key from WordPress salts.
	 *
	 * Prefers REPORTEDIP_AUTH_KEY constant if defined, falls back to AUTH_KEY.
	 *
	 * @return string|false 32-byte binary key or false if no key material available.
	 */
	private static function get_key() {
		if ( defined( 'REPORTEDIP_AUTH_KEY' ) && REPORTEDIP_AUTH_KEY !== '' ) {
			$key_material = REPORTEDIP_AUTH_KEY;
		} elseif ( defined( 'AUTH_KEY' ) && AUTH_KEY !== '' ) {
			$key_material = AUTH_KEY;
		} else {
			return false;
		}

		return hash( 'sha256', $key_material, true );
	}

	/**
	 * Securely zero memory containing sensitive data.
	 *
	 * @param string $data Data to zero out (passed by reference).
	 */
	public static function zero_memory( &$data ) {
		if ( self::has_sodium() && is_string( $data ) ) {
			$length = strlen( $data );
			try {
				sodium_memzero( $data );
			} catch ( \Exception $e ) {
				$data = str_repeat( "\0", $length );
			}
		} else {
			$length = is_string( $data ) ? strlen( $data ) : 0;
			$data   = str_repeat( "\0", $length );
		}
	}

	/**
	 * Check if libsodium is available.
	 *
	 * @return bool
	 */
	private static function has_sodium() {
		if ( null === self::$sodium_available ) {
			self::$sodium_available = function_exists( 'sodium_crypto_secretbox' );
		}
		return self::$sodium_available;
	}

	/**
	 * Check if OpenSSL with AES-256-GCM is available.
	 *
	 * @return bool
	 */
	private static function has_openssl() {
		if ( null === self::$openssl_available ) {
			self::$openssl_available = function_exists( 'openssl_encrypt' )
				&& in_array( self::OPENSSL_CIPHER, openssl_get_cipher_methods(), true );
		}
		return self::$openssl_available;
	}

	/**
	 * Check if any supported encryption method is available.
	 *
	 * @return bool
	 */
	public static function is_available() {
		return ( self::has_sodium() || self::has_openssl() ) && false !== self::get_key();
	}

	/**
	 * Get the active encryption method name.
	 *
	 * @return string|false Method name or false if none available.
	 */
	public static function get_active_method() {
		if ( self::has_sodium() ) {
			return self::METHOD_SODIUM;
		}
		if ( self::has_openssl() ) {
			return self::METHOD_OPENSSL;
		}
		return false;
	}
}
