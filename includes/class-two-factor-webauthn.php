<?php
/**
 * WebAuthn / FIDO2 / Passkey support.
 *
 * Minimal, self-contained Level-2 WebAuthn verifier for 2FA (second-factor)
 * use. No Composer dependency: we parse CBOR attestation objects + ES256/RS256
 * signatures with stdlib OpenSSL. This keeps the plugin slim for distribution
 * but only covers the subset needed for passkey/platform-authenticator 2FA:
 *   - RS256 and ES256 public keys
 *   - packed / none attestations (we do NOT verify attestation-CA chains —
 *     for 2FA that is acceptable; the enrolment ceremony happens after a
 *     valid password auth so attestation adds no meaningful entropy).
 *
 * Challenges are stashed in short-lived transients keyed by a server token
 * sent to the browser, so no auth-cookie is required during login-time
 * assertion (the nonce cookie set by filter_authenticate is reused).
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

// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode

class ReportedIP_Hive_Two_Factor_WebAuthn {

	const TRANSIENT_PREFIX = 'reportedip_2fa_webauthn_';
	const CHALLENGE_TTL    = 300;

	public function __construct() {
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_register_options', array( $this, 'ajax_register_options' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_register_verify', array( $this, 'ajax_register_verify' ) );
		add_action( 'wp_ajax_nopriv_reportedip_hive_2fa_webauthn_login_options', array( $this, 'ajax_login_options' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_login_options', array( $this, 'ajax_login_options' ) );
		add_action( 'wp_ajax_nopriv_reportedip_hive_2fa_webauthn_login_verify', array( $this, 'ajax_login_verify' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_login_verify', array( $this, 'ajax_login_verify' ) );
	}

	/* ------------------------------------------------------------------
	 * Registration ceremony (called during onboarding / profile setup).
	 * ------------------------------------------------------------------ */

	public function ajax_register_options() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );
		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission.', 'reportedip-hive' ) ) );
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			wp_send_json_error( array( 'message' => __( 'Invalid user.', 'reportedip-hive' ) ) );
		}

		$challenge = self::random_bytes( 32 );
		set_transient( self::TRANSIENT_PREFIX . 'register_' . $user_id, base64_encode( $challenge ), self::CHALLENGE_TTL );

		$rp_id    = self::rp_id();
		$existing = self::get_user_credentials( $user_id );
		$exclude  = array();
		foreach ( $existing as $cred ) {
			if ( ! empty( $cred['id'] ) ) {
				$exclude[] = array(
					'type'       => 'public-key',
					'id'         => $cred['id'],
					'transports' => $cred['transports'] ?? array(),
				);
			}
		}

		wp_send_json_success(
			array(
				'publicKey' => array(
					'challenge'              => self::b64url_encode( $challenge ),
					'rp'                     => array(
						'id'   => $rp_id,
						'name' => get_bloginfo( 'name' ),
					),
					'user'                   => array(
						'id'          => self::b64url_encode( sprintf( '%d', $user_id ) ),
						'name'        => $user->user_email,
						'displayName' => $user->display_name,
					),
					'pubKeyCredParams'       => array(
						array(
							'type' => 'public-key',
							'alg'  => -7,
						),
						array(
							'type' => 'public-key',
							'alg'  => -257,
						),
					),
					'authenticatorSelection' => array(
						'userVerification'   => 'preferred',
						'residentKey'        => 'preferred',
						'requireResidentKey' => false,
					),
					'timeout'                => 60000,
					'attestation'            => 'none',
					'excludeCredentials'     => $exclude,
				),
			)
		);
	}

	public function ajax_register_verify() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );
		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission.', 'reportedip-hive' ) ) );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce verified by check_ajax_referer() above; payload is a JSON string parsed via json_decode() with strict array check on the next line — invalid input is rejected before any further use.
		$raw        = isset( $_POST['credential'] ) ? wp_unslash( $_POST['credential'] ) : '';
		$credential = json_decode( $raw, true );
		if ( ! is_array( $credential ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid credential data.', 'reportedip-hive' ) ) );
		}

		$stored_challenge_b64 = get_transient( self::TRANSIENT_PREFIX . 'register_' . $user_id );
		if ( empty( $stored_challenge_b64 ) ) {
			wp_send_json_error( array( 'message' => __( 'Challenge expired, please start again.', 'reportedip-hive' ) ) );
		}
		delete_transient( self::TRANSIENT_PREFIX . 'register_' . $user_id );
		$stored_challenge = base64_decode( $stored_challenge_b64 );

		$client_data_json = self::b64url_decode( $credential['response']['clientDataJSON'] ?? '' );
		$client_data      = json_decode( $client_data_json, true );
		if ( ! is_array( $client_data ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid clientDataJSON.', 'reportedip-hive' ) ) );
		}
		if ( 'webauthn.create' !== ( $client_data['type'] ?? '' ) ) {
			wp_send_json_error( array( 'message' => __( 'clientDataJSON.type is wrong.', 'reportedip-hive' ) ) );
		}
		if ( ! hash_equals( $stored_challenge, self::b64url_decode( $client_data['challenge'] ?? '' ) ) ) {
			wp_send_json_error( array( 'message' => __( 'Challenge mismatch.', 'reportedip-hive' ) ) );
		}
		if ( rtrim( ( $client_data['origin'] ?? '' ), '/' ) !== rtrim( self::expected_origin(), '/' ) ) {
			wp_send_json_error( array( 'message' => __( 'Origin mismatch.', 'reportedip-hive' ) ) );
		}

		$attestation = self::b64url_decode( $credential['response']['attestationObject'] ?? '' );
		$parsed      = self::parse_attestation( $attestation );
		if ( is_wp_error( $parsed ) ) {
			wp_send_json_error( array( 'message' => $parsed->get_error_message() ) );
		}

		$auth_data = self::parse_authenticator_data( $parsed['authData'] );
		if ( is_wp_error( $auth_data ) ) {
			wp_send_json_error( array( 'message' => $auth_data->get_error_message() ) );
		}

		$rp_id_hash_expected = hash( 'sha256', self::rp_id(), true );
		if ( ! hash_equals( $rp_id_hash_expected, $auth_data['rp_id_hash'] ) ) {
			wp_send_json_error( array( 'message' => __( 'RP-ID hash mismatch.', 'reportedip-hive' ) ) );
		}
		if ( empty( $auth_data['credential_id'] ) || empty( $auth_data['public_key_cbor'] ) ) {
			wp_send_json_error( array( 'message' => __( 'Credential data incomplete.', 'reportedip-hive' ) ) );
		}

		$record = array(
			'id'         => self::b64url_encode( $auth_data['credential_id'] ),
			'public_key' => base64_encode( $auth_data['public_key_cbor'] ),
			'sign_count' => $auth_data['sign_count'],
			'created_at' => time(),
			'transports' => $credential['transports'] ?? array(),
			'name'       => isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : __( 'Passkey', 'reportedip-hive' ),
		);

		$creds   = self::get_user_credentials( $user_id );
		$creds[] = $record;
		self::save_user_credentials( $user_id, $creds );

		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_WEBAUTHN_ENABLED, '1' );
		if ( ! ReportedIP_Hive_Two_Factor::is_user_enabled( $user_id ) ) {
			ReportedIP_Hive_Two_Factor::enable_for_user( $user_id, ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN );
		}
		if ( 0 === ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user_id ) ) {
			ReportedIP_Hive_Two_Factor_Recovery::regenerate_codes( $user_id );
		}

		wp_send_json_success( array( 'message' => __( 'Passkey registriert.', 'reportedip-hive' ) ) );
	}

	/* ------------------------------------------------------------------
	 * Assertion ceremony (called during login challenge).
	 * ------------------------------------------------------------------ */

	public function ajax_login_options() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WebAuthn assertion flow runs after first-factor auth; identity is bound via the signed reportedip_hive_2fa_nonce cookie verified inside user_id_from_login_token() on the next line. A traditional WP nonce cannot be used here because the user is not yet logged in (nopriv endpoint).
		$token   = isset( $_POST['login_token'] ) ? sanitize_text_field( wp_unslash( $_POST['login_token'] ) ) : '';
		$user_id = self::user_id_from_login_token( $token );
		if ( ! $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid challenge token.', 'reportedip-hive' ) ) );
		}

		$challenge = self::random_bytes( 32 );
		set_transient( self::TRANSIENT_PREFIX . 'login_' . $user_id, base64_encode( $challenge ), self::CHALLENGE_TTL );

		$creds             = self::get_user_credentials( $user_id );
		$allow_credentials = array();
		foreach ( $creds as $cred ) {
			$allow_credentials[] = array(
				'type'       => 'public-key',
				'id'         => $cred['id'],
				'transports' => $cred['transports'] ?? array(),
			);
		}

		wp_send_json_success(
			array(
				'publicKey' => array(
					'challenge'        => self::b64url_encode( $challenge ),
					'rpId'             => self::rp_id(),
					'allowCredentials' => $allow_credentials,
					'userVerification' => 'preferred',
					'timeout'          => 60000,
				),
			)
		);
	}

	public function ajax_login_verify() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- WebAuthn assertion flow runs after first-factor auth; identity is bound via the signed reportedip_hive_2fa_nonce cookie verified inside user_id_from_login_token() on the next line. A traditional WP nonce cannot be used here because the user is not yet logged in (nopriv endpoint).
		$token   = isset( $_POST['login_token'] ) ? sanitize_text_field( wp_unslash( $_POST['login_token'] ) ) : '';
		$user_id = self::user_id_from_login_token( $token );
		if ( ! $user_id ) {
			wp_send_json_error( array( 'message' => __( 'Invalid challenge token.', 'reportedip-hive' ) ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Identity verified via signed cookie above; payload is a JSON string parsed via json_decode() with strict array check on the next line — invalid input is rejected before any further use.
		$raw       = isset( $_POST['credential'] ) ? wp_unslash( $_POST['credential'] ) : '';
		$assertion = json_decode( $raw, true );
		if ( ! is_array( $assertion ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid assertion data.', 'reportedip-hive' ) ) );
		}

		$ok = self::verify_assertion( $user_id, $assertion );
		if ( is_wp_error( $ok ) ) {
			wp_send_json_error( array( 'message' => $ok->get_error_message() ) );
		}

		set_transient( self::TRANSIENT_PREFIX . 'verified_' . $user_id, 1, 60 );
		wp_send_json_success( array( 'message' => __( 'Passkey verifiziert.', 'reportedip-hive' ) ) );
	}

	/**
	 * Verifier used by Two_Factor::verify_2fa_code() for method=webauthn.
	 *
	 * @param int    $user_id
	 * @param string $opaque_code The browser submits a literal "webauthn-ok" once
	 *                            ajax_login_verify succeeded — this handler then
	 *                            checks the short-lived transient.
	 * @return bool
	 */
	public static function verify( $user_id, $opaque_code ) {
		if ( 'webauthn-ok' !== $opaque_code ) {
			return false;
		}
		$flag = get_transient( self::TRANSIENT_PREFIX . 'verified_' . $user_id );
		if ( ! $flag ) {
			return false;
		}
		delete_transient( self::TRANSIENT_PREFIX . 'verified_' . $user_id );
		return true;
	}

	/* ------------------------------------------------------------------
	 * Credential store + helpers.
	 * ------------------------------------------------------------------ */

	public static function get_user_credentials( $user_id ) {
		$raw = get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_WEBAUTHN_CREDENTIALS, true );
		if ( empty( $raw ) ) {
			return array();
		}
		$decoded = json_decode( $raw, true );
		return is_array( $decoded ) ? $decoded : array();
	}

	public static function save_user_credentials( $user_id, $creds ) {
		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_WEBAUTHN_CREDENTIALS, wp_json_encode( $creds ) );
	}

	public static function rp_id() {
		return (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	public static function expected_origin() {
		$parts  = wp_parse_url( home_url() );
		$scheme = $parts['scheme'] ?? ( is_ssl() ? 'https' : 'http' );
		$host   = $parts['host'] ?? '';
		$port   = isset( $parts['port'] ) ? ':' . $parts['port'] : '';
		return $scheme . '://' . $host . $port;
	}

	/**
	 * Resolve the user id from the httpOnly login-nonce cookie set by
	 * filter_authenticate. The JS side never needs to know the token, which
	 * keeps it shielded from XSS.
	 *
	 * @return int 0 when invalid.
	 */
	private static function user_id_from_login_token( $token_unused = '' ) {
		unset( $token_unused );
		if ( empty( $_COOKIE[ ReportedIP_Hive_Two_Factor::NONCE_COOKIE ] ) ) {
			return 0;
		}
		$token = sanitize_text_field( wp_unslash( $_COOKIE[ ReportedIP_Hive_Two_Factor::NONCE_COOKIE ] ) );
		$hash  = hash( 'sha256', $token );
		$data  = get_transient( ReportedIP_Hive_Two_Factor::NONCE_PREFIX . $hash );
		return is_array( $data ) && ! empty( $data['user_id'] ) ? (int) $data['user_id'] : 0;
	}

	/**
	 * Verify a WebAuthn assertion signature.
	 *
	 * @return true|WP_Error
	 */
	private static function verify_assertion( $user_id, $assertion ) {
		$cred_id = $assertion['id'] ?? '';
		if ( empty( $cred_id ) ) {
			return new WP_Error( 'webauthn_no_id', __( 'Missing credential ID.', 'reportedip-hive' ) );
		}
		$creds = self::get_user_credentials( $user_id );
		$match = null;
		foreach ( $creds as $idx => $cred ) {
			if ( hash_equals( (string) $cred['id'], (string) $cred_id ) ) {
				$match = $idx;
				break;
			}
		}
		if ( null === $match ) {
			return new WP_Error( 'webauthn_unknown_cred', __( 'Unbekannter Passkey.', 'reportedip-hive' ) );
		}

		$client_data_json = self::b64url_decode( $assertion['response']['clientDataJSON'] ?? '' );
		$client_data      = json_decode( $client_data_json, true );
		if ( ! is_array( $client_data ) ) {
			return new WP_Error( 'webauthn_client_data', __( 'Invalid clientDataJSON.', 'reportedip-hive' ) );
		}
		if ( 'webauthn.get' !== ( $client_data['type'] ?? '' ) ) {
			return new WP_Error( 'webauthn_type', __( 'clientDataJSON.type is wrong.', 'reportedip-hive' ) );
		}

		$stored_challenge_b64 = get_transient( self::TRANSIENT_PREFIX . 'login_' . $user_id );
		if ( empty( $stored_challenge_b64 ) ) {
			return new WP_Error( 'webauthn_expired', __( 'Challenge expired.', 'reportedip-hive' ) );
		}
		delete_transient( self::TRANSIENT_PREFIX . 'login_' . $user_id );
		$stored_challenge = base64_decode( $stored_challenge_b64 );
		if ( ! hash_equals( $stored_challenge, self::b64url_decode( $client_data['challenge'] ?? '' ) ) ) {
			return new WP_Error( 'webauthn_challenge', __( 'Challenge mismatch.', 'reportedip-hive' ) );
		}
		if ( rtrim( ( $client_data['origin'] ?? '' ), '/' ) !== rtrim( self::expected_origin(), '/' ) ) {
			return new WP_Error( 'webauthn_origin', __( 'Origin mismatch.', 'reportedip-hive' ) );
		}

		$authenticator_data = self::b64url_decode( $assertion['response']['authenticatorData'] ?? '' );
		$signature          = self::b64url_decode( $assertion['response']['signature'] ?? '' );
		$auth_info          = self::parse_authenticator_data( $authenticator_data, false );
		if ( is_wp_error( $auth_info ) ) {
			return $auth_info;
		}
		$rp_id_hash_expected = hash( 'sha256', self::rp_id(), true );
		if ( ! hash_equals( $rp_id_hash_expected, $auth_info['rp_id_hash'] ) ) {
			return new WP_Error( 'webauthn_rp', __( 'RP-ID hash mismatch.', 'reportedip-hive' ) );
		}

		$client_data_hash = hash( 'sha256', $client_data_json, true );
		$signed_data      = $authenticator_data . $client_data_hash;

		$public_key_cbor = base64_decode( $creds[ $match ]['public_key'] );
		$pem             = self::cose_to_pem( $public_key_cbor );
		if ( is_wp_error( $pem ) ) {
			return $pem;
		}

		$ok = openssl_verify( $signed_data, $signature, $pem, OPENSSL_ALGO_SHA256 );
		if ( 1 !== $ok ) {
			return new WP_Error( 'webauthn_sig', __( 'Signature could not be verified.', 'reportedip-hive' ) );
		}

		if ( $auth_info['sign_count'] > 0 && $auth_info['sign_count'] <= (int) ( $creds[ $match ]['sign_count'] ?? 0 ) ) {
			return new WP_Error( 'webauthn_counter', __( 'Signature counter anomaly.', 'reportedip-hive' ) );
		}
		$creds[ $match ]['sign_count'] = $auth_info['sign_count'];
		$creds[ $match ]['last_used']  = time();
		self::save_user_credentials( $user_id, $creds );

		return true;
	}

	/* ------------------------------------------------------------------
	 * CBOR + COSE parsing (minimal, FIDO2-2FA subset).
	 * ------------------------------------------------------------------ */

	private static function parse_attestation( $bytes ) {
		$result = self::cbor_decode( $bytes, 0 );
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		list( $map, ) = $result;
		if ( ! is_array( $map ) || empty( $map['authData'] ) ) {
			return new WP_Error( 'webauthn_att', __( 'Attestation object is missing authData.', 'reportedip-hive' ) );
		}
		return $map;
	}

	private static function parse_authenticator_data( $auth_data, $expect_attested = true ) {
		if ( strlen( $auth_data ) < 37 ) {
			return new WP_Error( 'webauthn_authdata', __( 'authenticatorData is too short.', 'reportedip-hive' ) );
		}
		$rp_id_hash = substr( $auth_data, 0, 32 );
		$flags      = ord( $auth_data[32] );
		$sign_count = unpack( 'N', substr( $auth_data, 33, 4 ) )[1];

		$result = array(
			'rp_id_hash'      => $rp_id_hash,
			'flags'           => $flags,
			'sign_count'      => $sign_count,
			'credential_id'   => '',
			'public_key_cbor' => '',
		);

		$has_attested = (bool) ( $flags & 0x40 );
		if ( $has_attested && strlen( $auth_data ) >= 55 ) {
			$cred_id_len               = unpack( 'n', substr( $auth_data, 53, 2 ) )[1];
			$cred_id                   = substr( $auth_data, 55, $cred_id_len );
			$pk_start                  = 55 + $cred_id_len;
			$pk_cbor                   = substr( $auth_data, $pk_start );
			$result['credential_id']   = $cred_id;
			$result['public_key_cbor'] = $pk_cbor;
		} elseif ( $expect_attested ) {
			return new WP_Error( 'webauthn_authdata', __( 'Attested credential data is missing.', 'reportedip-hive' ) );
		}

		return $result;
	}

	/**
	 * Decode a COSE-formatted public key to PEM so OpenSSL can use it.
	 *
	 * @return string|WP_Error PEM-encoded public key.
	 */
	private static function cose_to_pem( $cbor ) {
		$decoded = self::cbor_decode( $cbor, 0 );
		if ( is_wp_error( $decoded ) ) {
			return $decoded;
		}
		list( $map, ) = $decoded;
		if ( ! is_array( $map ) ) {
			return new WP_Error( 'webauthn_cose', __( 'COSE key is not parseable.', 'reportedip-hive' ) );
		}
		$kty = $map[1] ?? null;
		$alg = $map[3] ?? null;

		if ( 2 === $kty && -7 === $alg ) {
			$x = $map[-2] ?? null;
			$y = $map[-3] ?? null;
			if ( ! is_string( $x ) || ! is_string( $y ) || 32 !== strlen( $x ) || 32 !== strlen( $y ) ) {
				return new WP_Error( 'webauthn_cose_ec', __( 'Invalid EC2 key.', 'reportedip-hive' ) );
			}
			$der = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04" . $x . $y;
			return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
		}
		if ( 3 === $kty && -257 === $alg ) {
			$n = $map[-1] ?? null;
			$e = $map[-2] ?? null;
			if ( ! is_string( $n ) || ! is_string( $e ) || '' === $n || '' === $e ) {
				return new WP_Error( 'webauthn_cose_rsa', __( 'Invalid RSA key.', 'reportedip-hive' ) );
			}
			$der = self::rsa_der( $n, $e );
			return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
		}
		return new WP_Error( 'webauthn_cose_alg', __( 'Unsupported COSE algorithm.', 'reportedip-hive' ) );
	}

	private static function rsa_der( $n, $e ) {
		$der_int     = function ( $bytes ) {
			if ( ord( $bytes[0] ) > 0x7f ) {
				$bytes = "\x00" . $bytes;
			}
			return "\x02" . self::der_len( strlen( $bytes ) ) . $bytes;
		};
		$seq_body    = $der_int( $n ) . $der_int( $e );
		$rsa_key_seq = "\x30" . self::der_len( strlen( $seq_body ) ) . $seq_body;
		$bit_string  = "\x03" . self::der_len( strlen( $rsa_key_seq ) + 1 ) . "\x00" . $rsa_key_seq;
		$alg_id      = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
		$spki_body   = $alg_id . $bit_string;
		return "\x30" . self::der_len( strlen( $spki_body ) ) . $spki_body;
	}

	private static function der_len( $len ) {
		if ( $len < 128 ) {
			return chr( $len );
		}
		$bytes = '';
		while ( $len > 0 ) {
			$bytes = chr( $len & 0xff ) . $bytes;
			$len >>= 8;
		}
		return chr( 0x80 | strlen( $bytes ) ) . $bytes;
	}

	/**
	 * Minimal CBOR decoder covering the subset used by WebAuthn (maps,
	 * byte-strings, text-strings, ints, arrays). Returns [value, new-offset].
	 *
	 * @return array|WP_Error
	 */
	private static function cbor_decode( $data, $offset ) {
		if ( $offset >= strlen( $data ) ) {
			return new WP_Error( 'cbor_eof', 'CBOR EOF' );
		}
		$first = ord( $data[ $offset++ ] );
		$major = $first >> 5;
		$add   = $first & 0x1f;

		$read_uint = function ( $add_info ) use ( &$data, &$offset ) {
			if ( $add_info < 24 ) {
				return $add_info;
			}
			if ( 24 === $add_info ) {
				$v = ord( $data[ $offset ] );
				++$offset;
				return $v;
			}
			if ( 25 === $add_info ) {
				$v       = unpack( 'n', substr( $data, $offset, 2 ) )[1];
				$offset += 2;
				return $v;
			}
			if ( 26 === $add_info ) {
				$v       = unpack( 'N', substr( $data, $offset, 4 ) )[1];
				$offset += 4;
				return $v;
			}
			if ( 27 === $add_info ) {
				$high    = unpack( 'N', substr( $data, $offset, 4 ) )[1];
				$low     = unpack( 'N', substr( $data, $offset + 4, 4 ) )[1];
				$offset += 8;
				return $high * 4294967296 + $low;
			}
			return 0;
		};

		switch ( $major ) {
			case 0:
				$v = $read_uint( $add );
				return array( $v, $offset );
			case 1:
				$v = $read_uint( $add );
				return array( -1 - $v, $offset );
			case 2:
				$len     = $read_uint( $add );
				$bs      = substr( $data, $offset, $len );
				$offset += $len;
				return array( $bs, $offset );
			case 3:
				$len     = $read_uint( $add );
				$ts      = substr( $data, $offset, $len );
				$offset += $len;
				return array( $ts, $offset );
			case 4:
				$len = $read_uint( $add );
				$arr = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$res = self::cbor_decode_at( $data, $offset );
					if ( is_wp_error( $res ) ) {
						return $res;
					}
					$arr[]  = $res[0];
					$offset = $res[1];
				}
				return array( $arr, $offset );
			case 5:
				$len = $read_uint( $add );
				$map = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$k = self::cbor_decode_at( $data, $offset );
					if ( is_wp_error( $k ) ) {
						return $k;
					} $offset = $k[1];
					$v        = self::cbor_decode_at( $data, $offset );
					if ( is_wp_error( $v ) ) {
						return $v;
					} $offset     = $v[1];
					$map[ $k[0] ] = $v[0];
				}
				return array( $map, $offset );
			case 7:
				if ( 20 === $add ) {
					return array( false, $offset );
				}
				if ( 21 === $add ) {
					return array( true, $offset );
				}
				if ( 22 === $add ) {
					return array( null, $offset );
				}
				return array( null, $offset );
			default:
				return new WP_Error( 'cbor_unsupported', 'Unsupported CBOR major type ' . $major );
		}
	}

	private static function cbor_decode_at( $data, $offset ) {
		return self::cbor_decode( $data, $offset );
	}

	/* ------------------------------------------------------------------
	 * Base64-URL helpers + CSPRNG.
	 * ------------------------------------------------------------------ */

	public static function b64url_encode( $bytes ) {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
	}

	public static function b64url_decode( $s ) {
		$pad = strlen( $s ) % 4;
		if ( $pad ) {
			$s .= str_repeat( '=', 4 - $pad ); }
		return base64_decode( strtr( $s, '-_', '+/' ) );
	}

	private static function random_bytes( $n ) {
		return random_bytes( $n );
	}
}
