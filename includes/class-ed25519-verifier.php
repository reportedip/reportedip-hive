<?php
/**
 * Shared Ed25519 detached-signature verifier for server-signed payloads.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.48
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Verifies detached Ed25519 signatures over exact payload strings against a
 * set of base64-encoded public keys.
 *
 * Extracted from the ruleset-sync verifier so every server-signed transport
 * (rulesets, cloud management) shares one implementation. The signing model
 * mirrors WordPress-core signed updates: the private key lives on the
 * service, only public keys ship in the plugin, and verification always runs
 * over the literal payload string — decoding happens after, never before, so
 * re-serialisation differences between client and server cannot bite.
 *
 * @since 2.1.48
 */
final class ReportedIP_Hive_Ed25519_Verifier {

	/**
	 * Verify a detached Ed25519 signature over the exact payload string
	 * against any of the accepted public keys.
	 *
	 * @param string   $payload         The exact signed payload string.
	 * @param string   $signature_b64   Base64-encoded detached signature.
	 * @param string[] $public_keys_b64 Base64-encoded Ed25519 public keys.
	 * @return bool True when the signature validates against an accepted key.
	 * @since  2.1.48
	 */
	public static function verify( $payload, $signature_b64, array $public_keys_b64 ) {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			return false;
		}
		if ( ! is_string( $payload ) || ! is_string( $signature_b64 ) || '' === $signature_b64 ) {
			return false;
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding a detached Ed25519 signature, not code.
		$sig = base64_decode( $signature_b64, true );
		if ( false === $sig || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) ) {
			return false;
		}
		foreach ( $public_keys_b64 as $pk_b64 ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding an Ed25519 public key, not code.
			$pk = base64_decode( (string) $pk_b64, true );
			if ( false === $pk || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pk ) ) {
				continue;
			}
			if ( sodium_crypto_sign_verify_detached( $sig, $payload, $pk ) ) {
				return true;
			}
		}
		return false;
	}
}
