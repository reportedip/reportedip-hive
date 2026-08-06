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
 * @author    Patrick Schlesinger <1@reportedip.com>
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

	/**
	 * Ceremony timeout in milliseconds. 120 s instead of the WebAuthn default
	 * 60 s because NFC-tap flows on phones routinely need the extra time
	 * (unlock phone, find the key, hold it steady against the reader).
	 *
	 * @since 2.1.33
	 */
	const CEREMONY_TIMEOUT_MS = 120000;

	/**
	 * Authenticator-data flag bits (WebAuthn L2 §6.1).
	 *
	 * @since 2.1.33
	 */
	const FLAG_USER_PRESENT  = 0x01;
	const FLAG_USER_VERIFIED = 0x04;

	public function __construct() {
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_register_options', array( $this, 'ajax_register_options' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_register_verify', array( $this, 'ajax_register_verify' ) );
		add_action( 'wp_ajax_nopriv_reportedip_hive_2fa_webauthn_login_options', array( $this, 'ajax_login_options' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_login_options', array( $this, 'ajax_login_options' ) );
		add_action( 'wp_ajax_nopriv_reportedip_hive_2fa_webauthn_login_verify', array( $this, 'ajax_login_verify' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_login_verify', array( $this, 'ajax_login_verify' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_list_keys', array( $this, 'ajax_list_keys' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_rename_key', array( $this, 'ajax_rename_key' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_webauthn_delete_key', array( $this, 'ajax_delete_key' ) );
	}

	/* ------------------------------------------------------------------
	 * Registration ceremony (called during onboarding / profile setup).
	 * ------------------------------------------------------------------ */

	public function ajax_register_options() {
		$user_id = self::key_management_user();
		self::throttle_registration( $user_id );
		if ( ! self::can_add_key( $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'Multiple security keys per account require the Business plan. Your first key stays free.', 'reportedip-hive' ) ) );
		}

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			wp_send_json_error( array( 'message' => __( 'Invalid user.', 'reportedip-hive' ) ) );
		}

		$challenge = self::random_bytes( 32 );
		set_transient( self::TRANSIENT_PREFIX . 'register_' . $user_id, base64_encode( $challenge ), self::CHALLENGE_TTL );

		$hint = isset( $_POST['hint'] ) ? sanitize_key( wp_unslash( $_POST['hint'] ) ) : '';
		if ( ! in_array( $hint, array( 'security-key', 'client-device', 'hybrid' ), true ) ) {
			$hint = '';
		}

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
						'id'          => self::user_handle( $user_id ),
						'name'        => $user->user_email,
						'displayName' => $user->display_name,
					),
					'pubKeyCredParams'       => self::pub_key_cred_params(),
					'authenticatorSelection' => self::authenticator_selection( $hint ),
					'hints'                  => '' !== $hint ? array( $hint ) : array(),
					'timeout'                => self::CEREMONY_TIMEOUT_MS,
					'attestation'            => self::advanced_available() ? 'direct' : 'none',
					'excludeCredentials'     => $exclude,
				),
			)
		);
	}

	/**
	 * COSE algorithms offered at registration, strongest first. Ed25519
	 * (-8) is offered only while libsodium can verify it later — otherwise
	 * a key registered today could never assert tomorrow.
	 *
	 * @return array<int,array{type:string,alg:int}>
	 * @since 2.1.34
	 */
	private static function pub_key_cred_params() {
		$algs = array( -7, -257 );
		if ( function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			array_unshift( $algs, -8 );
		}
		$params = array();
		foreach ( $algs as $alg ) {
			$params[] = array(
				'type' => 'public-key',
				'alg'  => $alg,
			);
		}
		return $params;
	}

	/**
	 * authenticatorSelection for the registration ceremony.
	 *
	 * residentKey stays 'discouraged' for second-factor use: a discoverable
	 * credential would consume one of a YubiKey's limited credential slots
	 * and force FIDO2-PIN enrolment mid-setup for no 2FA benefit (the login
	 * flow always supplies allowCredentials).
	 *
	 * @param string $hint Optional UI hint ('security-key'|'client-device'|'hybrid').
	 * @return array<string,mixed>
	 * @since 2.1.34
	 */
	private static function authenticator_selection( $hint = '' ) {
		$selection = array(
			'userVerification'   => self::user_verification_policy(),
			'residentKey'        => 'discouraged',
			'requireResidentKey' => false,
		);
		if ( 'security-key' === $hint ) {
			$selection['authenticatorAttachment'] = 'cross-platform';
		}
		if ( 'client-device' === $hint ) {
			$selection['authenticatorAttachment'] = 'platform';
		}
		return $selection;
	}

	/**
	 * Whether the Business-tier advanced security-key features are active:
	 * multiple keys per account, attestation-based model detection and the
	 * key-lifecycle mails. One key per account is free — the base 2FA
	 * protection is never gated.
	 *
	 * @return bool
	 * @since 2.1.36
	 */
	public static function advanced_available() {
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}
		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'webauthn_advanced' );
		return ! empty( $status['available'] );
	}

	/**
	 * Whether the user may register one more credential: always for the
	 * first key, Business+ beyond that.
	 *
	 * @param int $user_id User id.
	 * @return bool
	 * @since 2.1.36
	 */
	public static function can_add_key( $user_id ) {
		if ( empty( self::get_user_credentials( $user_id ) ) ) {
			return true;
		}
		return self::advanced_available();
	}

	/**
	 * Light per-user throttle for the registration options endpoint so a
	 * scripted caller cannot churn challenge transients (max 10 per 10
	 * minutes; the endpoint is priv + capability-checked already).
	 *
	 * @param int $user_id User the ceremony is requested for.
	 * @since 2.1.34
	 */
	private static function throttle_registration( $user_id ) {
		$key   = self::TRANSIENT_PREFIX . 'regthrottle_' . (int) $user_id;
		$count = (int) get_transient( $key );
		if ( $count >= 10 ) {
			wp_send_json_error( array( 'message' => __( 'Too many registration attempts. Please wait a few minutes.', 'reportedip-hive' ) ) );
		}
		set_transient( $key, $count + 1, 10 * MINUTE_IN_SECONDS );
	}

	/**
	 * Reject a login-ceremony AJAX call while the caller's IP is inside
	 * the shared 2FA lockout ladder.
	 *
	 * @since 2.1.34
	 */
	private static function reject_when_ip_locked_out() {
		$remaining = ReportedIP_Hive_Two_Factor::ip_lockout_remaining( ReportedIP_Hive::get_client_ip() );
		if ( $remaining > 0 ) {
			wp_send_json_error(
				array(
					'message' => sprintf(
						/* translators: %d: seconds remaining */
						__( 'Too many failed attempts. Try again in %d seconds.', 'reportedip-hive' ),
						$remaining
					),
				)
			);
		}
	}

	public function ajax_register_verify() {
		$user_id = self::key_management_user();

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce verified by check_ajax_referer() above; payload is a JSON string parsed via json_decode() with strict array check on the next line — invalid input is rejected before any further use.
		$raw        = isset( $_POST['credential'] ) ? wp_unslash( $_POST['credential'] ) : '';
		$credential = json_decode( $raw, true );
		if ( ! is_array( $credential ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid credential data.', 'reportedip-hive' ) ) );
		}

		if ( ! self::can_add_key( $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'Multiple security keys per account require the Business plan. Your first key stays free.', 'reportedip-hive' ) ) );
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
		if ( ! self::origin_allowed( $client_data['origin'] ?? '' ) ) {
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
		if ( ! ( $auth_data['flags'] & self::FLAG_USER_PRESENT ) ) {
			wp_send_json_error( array( 'message' => __( 'The authenticator did not confirm user presence.', 'reportedip-hive' ) ) );
		}
		if ( 'required' === self::user_verification_policy() && ! ( $auth_data['flags'] & self::FLAG_USER_VERIFIED ) ) {
			wp_send_json_error( array( 'message' => __( 'User verification is required but was not performed.', 'reportedip-hive' ) ) );
		}
		if ( empty( $auth_data['credential_id'] ) || empty( $auth_data['public_key_cbor'] ) ) {
			wp_send_json_error( array( 'message' => __( 'Credential data incomplete.', 'reportedip-hive' ) ) );
		}

		$record = array(
			'id'           => self::b64url_encode( $auth_data['credential_id'] ),
			'public_key'   => base64_encode( $auth_data['public_key_cbor'] ),
			'sign_count'   => $auth_data['sign_count'],
			'created_at'   => time(),
			'transports'   => self::sanitize_transports( $credential['transports'] ?? array() ),
			'uv'           => (bool) ( $auth_data['flags'] & self::FLAG_USER_VERIFIED ),
			'aaguid'       => (string) ( $auth_data['aaguid'] ?? '' ),
			'att_fmt'      => is_string( $parsed['fmt'] ?? null ) ? $parsed['fmt'] : '',
			'att_verified' => self::verify_packed_attestation( $parsed, hash( 'sha256', $client_data_json, true ) ),
			'name'         => isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : __( 'Passkey', 'reportedip-hive' ),
		);

		$creds   = self::get_user_credentials( $user_id );
		$creds[] = $record;
		self::save_user_credentials( $user_id, $creds );

		ReportedIP_Hive_Two_Factor::activate_method( $user_id, ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN );

		/**
		 * Fires after a new WebAuthn credential was stored for a user.
		 *
		 * @param int    $user_id User the key was registered for.
		 * @param string $name    User-visible key name.
		 * @since 2.1.34
		 */
		do_action( 'reportedip_hive_2fa_webauthn_key_registered', $user_id, $record['name'] );

		wp_send_json_success(
			array(
				'message' => __( 'Security key registered.', 'reportedip-hive' ),
				'keys'    => self::keys_for_display( $user_id ),
			)
		);
	}

	/* ------------------------------------------------------------------
	 * Key management (list / rename / delete individual credentials).
	 * ------------------------------------------------------------------ */

	/**
	 * Resolve and authorise the target user for a registration or
	 * key-management call. Sends a JSON error (and exits) when the caller
	 * lacks permission.
	 *
	 * @return int Authorised user id.
	 * @since 2.1.34
	 */
	private static function key_management_user() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );
		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission.', 'reportedip-hive' ) ) );
		}
		return $user_id;
	}

	/**
	 * List the user's credentials for the key-manager UI. The public key
	 * itself never leaves the server.
	 *
	 * @since 2.1.34
	 */
	public function ajax_list_keys() {
		$user_id = self::key_management_user();
		wp_send_json_success( array( 'keys' => self::keys_for_display( $user_id ) ) );
	}

	/**
	 * Build the sanitized key list for UI consumption.
	 *
	 * @param int $user_id User id.
	 * @return array<int,array<string,mixed>>
	 * @since 2.1.34
	 */
	public static function keys_for_display( $user_id ) {
		$format   = (string) get_option( 'date_format' ) . ' ' . (string) get_option( 'time_format' );
		$advanced = self::advanced_available();
		$keys     = array();
		foreach ( self::get_user_credentials( $user_id ) as $cred ) {
			$model = '';
			$icon  = '';
			if ( $advanced && ! empty( $cred['aaguid'] ) && class_exists( 'ReportedIP_Hive_WebAuthn_Aaguid_Registry' ) ) {
				$info = ReportedIP_Hive_WebAuthn_Aaguid_Registry::lookup( (string) $cred['aaguid'] );
				if ( null !== $info ) {
					$model = $info['label'];
					$icon  = $info['icon'];
				}
			}
			$keys[] = array(
				'id'         => (string) ( $cred['id'] ?? '' ),
				'name'       => (string) ( $cred['name'] ?? __( 'Security key', 'reportedip-hive' ) ),
				'model'      => $model,
				'icon'       => $icon,
				'transports' => is_array( $cred['transports'] ?? null ) ? $cred['transports'] : array(),
				'created_at' => ! empty( $cred['created_at'] ) ? wp_date( $format, (int) $cred['created_at'] ) : '',
				'last_used'  => ! empty( $cred['last_used'] ) ? wp_date( $format, (int) $cred['last_used'] ) : '',
			);
		}
		return $keys;
	}

	/**
	 * Rename a single credential.
	 *
	 * @since 2.1.34
	 */
	public function ajax_rename_key() {
		$user_id = self::key_management_user();
		$cred_id = isset( $_POST['credential_id'] ) ? sanitize_text_field( wp_unslash( $_POST['credential_id'] ) ) : '';
		$name    = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '';
		$name    = mb_substr( trim( $name ), 0, 64 );
		if ( '' === $cred_id || '' === $name ) {
			wp_send_json_error( array( 'message' => __( 'Missing credential ID or name.', 'reportedip-hive' ) ) );
		}

		$creds = self::get_user_credentials( $user_id );
		foreach ( $creds as $idx => $cred ) {
			if ( hash_equals( (string) ( $cred['id'] ?? '' ), $cred_id ) ) {
				$creds[ $idx ]['name'] = $name;
				self::save_user_credentials( $user_id, $creds );
				wp_send_json_success( array( 'keys' => self::keys_for_display( $user_id ) ) );
			}
		}
		wp_send_json_error( array( 'message' => __( 'Unknown security key.', 'reportedip-hive' ) ) );
	}

	/**
	 * Delete a single credential.
	 *
	 * Removing the last credential disables the webauthn method through the
	 * canonical disable path — unless webauthn is the user's only enabled
	 * method while 2FA is enforced for them; then the delete is refused so
	 * an enforced user cannot strand themselves without a second factor.
	 *
	 * @since 2.1.34
	 */
	public function ajax_delete_key() {
		$user_id = self::key_management_user();
		$cred_id = isset( $_POST['credential_id'] ) ? sanitize_text_field( wp_unslash( $_POST['credential_id'] ) ) : '';
		if ( '' === $cred_id ) {
			wp_send_json_error( array( 'message' => __( 'Missing credential ID.', 'reportedip-hive' ) ) );
		}

		$creds = self::get_user_credentials( $user_id );
		$match = null;
		foreach ( $creds as $idx => $cred ) {
			if ( hash_equals( (string) ( $cred['id'] ?? '' ), $cred_id ) ) {
				$match = $idx;
				break;
			}
		}
		if ( null === $match ) {
			wp_send_json_error( array( 'message' => __( 'Unknown security key.', 'reportedip-hive' ) ) );
		}

		$is_last = ( 1 === count( $creds ) );
		if ( $is_last ) {
			$enabled     = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id );
			$only_method = ( array( ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN ) === array_values( $enabled ) );
			$user        = get_userdata( $user_id );
			$enforced    = $user && ReportedIP_Hive_Two_Factor::is_enforced_for_user( $user );
			if ( $only_method && $enforced ) {
				wp_send_json_error(
					array(
						'message' => __( 'This is your only security key and two-factor authentication is required for your account. Set up another method before removing it.', 'reportedip-hive' ),
					)
				);
			}
		}

		$removed_name = (string) ( $creds[ $match ]['name'] ?? '' );
		unset( $creds[ $match ] );
		$creds = array_values( $creds );

		if ( empty( $creds ) ) {
			ReportedIP_Hive_Two_Factor::disable_method( $user_id, ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN );
		} else {
			self::save_user_credentials( $user_id, $creds );
		}

		/**
		 * Fires after a WebAuthn credential was removed from a user.
		 *
		 * @param int    $user_id User the key was removed from.
		 * @param string $name    User-visible key name.
		 * @since 2.1.34
		 */
		do_action( 'reportedip_hive_2fa_webauthn_key_removed', $user_id, $removed_name );

		wp_send_json_success(
			array(
				'keys'            => self::keys_for_display( $user_id ),
				'method_disabled' => empty( $creds ),
			)
		);
	}

	/* ------------------------------------------------------------------
	 * Assertion ceremony (called during login challenge).
	 * ------------------------------------------------------------------ */

	public function ajax_login_options() {
		self::reject_when_ip_locked_out();

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
					'userVerification' => self::user_verification_policy(),
					'timeout'          => self::CEREMONY_TIMEOUT_MS,
				),
			)
		);
	}

	public function ajax_login_verify() {
		self::reject_when_ip_locked_out();

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
			ReportedIP_Hive_Two_Factor::record_ip_failure( ReportedIP_Hive::get_client_ip() );
			wp_send_json_error( array( 'message' => $ok->get_error_message() ) );
		}

		set_transient( self::TRANSIENT_PREFIX . 'verified_' . $user_id, 1, 60 );
		wp_send_json_success( array( 'message' => __( 'Security key verified.', 'reportedip-hive' ) ) );
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

	/**
	 * Whitelist-filter client-supplied transport hints. The list is stored
	 * verbatim on the credential and echoed back into allowCredentials on
	 * every later ceremony, so it must never carry arbitrary client input.
	 *
	 * @param mixed $transports Raw transports value from the browser.
	 * @return string[] Sanitized transport identifiers.
	 * @since 2.1.33
	 */
	public static function sanitize_transports( $transports ) {
		if ( ! is_array( $transports ) ) {
			return array();
		}
		$allowed = array( 'usb', 'nfc', 'ble', 'hybrid', 'internal', 'smart-card' );
		$clean   = array();
		foreach ( $transports as $transport ) {
			if ( ! is_string( $transport ) ) {
				continue;
			}
			$transport = sanitize_key( $transport );
			if ( in_array( $transport, $allowed, true ) ) {
				$clean[] = $transport;
			}
		}
		return array_values( array_unique( $clean ) );
	}

	public static function rp_id() {
		/**
		 * Filter the WebAuthn Relying-Party ID.
		 *
		 * Escape hatch for subdomain multisite / domain-mapped networks: a
		 * network admin can return the registrable parent domain so one
		 * enrolment is valid network-wide. Changing the RP ID orphans
		 * credentials enrolled under the previous value — set it once,
		 * before rollout.
		 *
		 * @param string $rp_id Host derived from home_url().
		 * @since 2.1.35
		 */
		return (string) apply_filters( 'reportedip_hive_webauthn_rp_id', (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
	}

	/**
	 * Origins accepted for ceremony responses. Covers the home_url() and
	 * site_url() hosts (they can differ on WP-in-subdirectory installs
	 * with a separate dashboard host) plus a developer filter.
	 *
	 * @return string[] Scheme://host[:port] strings without trailing slash.
	 * @since 2.1.35
	 */
	public static function allowed_origins() {
		$origins = array( self::expected_origin() );
		$site    = wp_parse_url( site_url() );
		if ( is_array( $site ) && ! empty( $site['host'] ) ) {
			$scheme    = $site['scheme'] ?? 'https';
			$port      = isset( $site['port'] ) ? ':' . $site['port'] : '';
			$origins[] = $scheme . '://' . $site['host'] . $port;
		}

		/**
		 * Filter the accepted WebAuthn origins.
		 *
		 * @param string[] $origins Accepted origins.
		 * @since 2.1.35
		 */
		$origins = apply_filters( 'reportedip_hive_webauthn_allowed_origins', $origins );
		return array_values( array_unique( array_map( static fn( $o ) => rtrim( (string) $o, '/' ), (array) $origins ) ) );
	}

	/**
	 * Whether a client-reported origin is acceptable.
	 *
	 * @param string $origin Origin string from clientDataJSON.
	 * @return bool
	 * @since 2.1.35
	 */
	private static function origin_allowed( $origin ) {
		return in_array( rtrim( (string) $origin, '/' ), self::allowed_origins(), true );
	}

	/**
	 * Opaque per-user WebAuthn user handle (16 random bytes, base64url).
	 * Created lazily on first use; emitted as user.id so resident
	 * credentials no longer carry the guessable ASCII decimal WP user id.
	 *
	 * @param int $user_id User id.
	 * @return string base64url handle.
	 * @since 2.1.35
	 */
	public static function user_handle( $user_id ) {
		$handle = (string) get_user_meta( $user_id, 'reportedip_hive_2fa_webauthn_user_handle', true );
		if ( '' === $handle ) {
			$handle = self::b64url_encode( self::random_bytes( 16 ) );
			update_user_meta( $user_id, 'reportedip_hive_2fa_webauthn_user_handle', $handle );
		}
		return $handle;
	}

	/**
	 * User-verification policy for both ceremonies.
	 *
	 * Defaults to 'discouraged' — the Yubico-recommended value for pure
	 * second-factor use: a fresh YubiKey has no FIDO2 PIN set, and
	 * 'preferred'/'required' would force PIN enrolment mid-login. Platform
	 * authenticators (Windows Hello, Touch ID) verify the user intrinsically
	 * regardless of this value. When the filter returns 'required' the
	 * server additionally enforces the UV flag on every ceremony.
	 *
	 * @return string 'discouraged' | 'preferred' | 'required'.
	 * @since 2.1.33
	 */
	public static function user_verification_policy() {
		/**
		 * Filter the WebAuthn userVerification requirement.
		 *
		 * @param string $policy One of 'discouraged', 'preferred', 'required'.
		 * @since 2.1.33
		 */
		$policy = apply_filters( 'reportedip_hive_webauthn_user_verification', 'discouraged' );
		return in_array( $policy, array( 'discouraged', 'preferred', 'required' ), true ) ? $policy : 'discouraged';
	}

	public static function expected_origin() {
		$parts  = wp_parse_url( home_url() );
		$scheme = $parts['scheme'] ?? ( is_ssl() ? 'https' : 'http' );
		$host   = $parts['host'] ?? '';
		$port   = isset( $parts['port'] ) ? ':' . $parts['port'] : '';
		return $scheme . '://' . $host . $port;
	}

	/**
	 * Mint a short-lived ceremony token that binds the assertion endpoints to
	 * a user on surfaces where the login-nonce cookie does not exist (the
	 * password-reset gate proves identity via the reset key + resetpass
	 * cookie before calling this). The token only gates access to the
	 * assertion ceremony — passing it still requires the credential's
	 * private key.
	 *
	 * @param int $user_id User the ceremony is minted for.
	 * @return string Opaque token for the browser.
	 * @since 2.1.33
	 */
	public static function mint_login_token( $user_id ) {
		$token = self::b64url_encode( self::random_bytes( 32 ) );
		set_transient( self::TRANSIENT_PREFIX . 'token_' . hash( 'sha256', $token ), (int) $user_id, self::CHALLENGE_TTL );
		return $token;
	}

	/**
	 * Resolve the user id for the assertion ceremony. Primary path is the
	 * httpOnly login-nonce cookie set by filter_authenticate (the JS side
	 * never needs to know that token, which keeps it shielded from XSS).
	 * Fallback path is an explicit ceremony token minted via
	 * {@see mint_login_token()} for cookie-less surfaces such as the
	 * password-reset gate.
	 *
	 * @param string $token Optional ceremony token posted by the browser.
	 * @return int 0 when invalid.
	 */
	private static function user_id_from_login_token( $token = '' ) {
		if ( ! empty( $_COOKIE[ ReportedIP_Hive_Two_Factor::NONCE_COOKIE ] ) ) {
			$cookie = sanitize_text_field( wp_unslash( $_COOKIE[ ReportedIP_Hive_Two_Factor::NONCE_COOKIE ] ) );
			$hash   = hash( 'sha256', $cookie );
			$data   = get_transient( ReportedIP_Hive_Two_Factor::NONCE_PREFIX . $hash );
			if ( is_array( $data ) && ! empty( $data['user_id'] ) ) {
				return (int) $data['user_id'];
			}
		}
		if ( '' !== $token ) {
			$user_id = (int) get_transient( self::TRANSIENT_PREFIX . 'token_' . hash( 'sha256', $token ) );
			if ( $user_id > 0 ) {
				return $user_id;
			}
		}
		return 0;
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
			return new WP_Error( 'webauthn_unknown_cred', __( 'Unknown security key.', 'reportedip-hive' ) );
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
		if ( ! self::origin_allowed( $client_data['origin'] ?? '' ) ) {
			return new WP_Error( 'webauthn_origin', __( 'Origin mismatch.', 'reportedip-hive' ) );
		}
		$user_handle = (string) ( $assertion['response']['userHandle'] ?? '' );
		if ( '' !== $user_handle
			&& ! hash_equals( self::user_handle( $user_id ), $user_handle )
			&& ! hash_equals( self::b64url_encode( sprintf( '%d', $user_id ) ), $user_handle ) ) {
			return new WP_Error( 'webauthn_user_handle', __( 'The credential belongs to a different account.', 'reportedip-hive' ) );
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
		if ( ! ( $auth_info['flags'] & self::FLAG_USER_PRESENT ) ) {
			return new WP_Error( 'webauthn_no_user_presence', __( 'The authenticator did not confirm user presence.', 'reportedip-hive' ) );
		}
		if ( 'required' === self::user_verification_policy() && ! ( $auth_info['flags'] & self::FLAG_USER_VERIFIED ) ) {
			return new WP_Error( 'webauthn_no_user_verification', __( 'User verification is required but was not performed.', 'reportedip-hive' ) );
		}

		$client_data_hash = hash( 'sha256', $client_data_json, true );
		$signed_data      = $authenticator_data . $client_data_hash;

		$public_key_cbor = base64_decode( $creds[ $match ]['public_key'] );
		$ok              = self::verify_signature( $public_key_cbor, $signed_data, $signature );
		if ( is_wp_error( $ok ) ) {
			return $ok;
		}

		$new_count    = (int) $auth_info['sign_count'];
		$stored_count = (int) ( $creds[ $match ]['sign_count'] ?? 0 );
		if ( $new_count > $stored_count ) {
			$creds[ $match ]['sign_count'] = $new_count;
		} elseif ( 0 !== $new_count || 0 !== $stored_count ) {
			ReportedIP_Hive_Logger::get_instance()->log_security_event(
				'2fa_webauthn_counter_regression',
				ReportedIP_Hive::get_client_ip(),
				array(
					'user_id'       => (int) $user_id,
					'credential_id' => (string) $creds[ $match ]['id'],
					'stored_count'  => $stored_count,
					'asserted'      => $new_count,
				),
				'high'
			);

			/**
			 * Fires when an assertion is rejected for a non-advancing
			 * signature counter — the classic cloned-key indicator.
			 *
			 * @param int    $user_id       Affected user.
			 * @param string $credential_id Base64url credential id.
			 * @param string $name          User-visible key name.
			 * @since 2.1.34
			 */
			do_action(
				'reportedip_hive_2fa_webauthn_counter_regression',
				(int) $user_id,
				(string) $creds[ $match ]['id'],
				(string) ( $creds[ $match ]['name'] ?? '' )
			);
			return new WP_Error( 'webauthn_counter', __( 'Signature counter anomaly.', 'reportedip-hive' ) );
		}
		$creds[ $match ]['last_used'] = time();
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
			$result['aaguid']          = self::format_aaguid( substr( $auth_data, 37, 16 ) );
			$result['credential_id']   = $cred_id;
			$result['public_key_cbor'] = $pk_cbor;
		} elseif ( $expect_attested ) {
			return new WP_Error( 'webauthn_authdata', __( 'Attested credential data is missing.', 'reportedip-hive' ) );
		}

		return $result;
	}

	/**
	 * Render raw AAGUID bytes as the canonical dashed lower-case form.
	 * The all-zero AAGUID (sent when the browser strips attestation)
	 * renders as an empty string so callers can treat it as absent.
	 *
	 * @param string $bytes Raw 16 AAGUID bytes.
	 * @return string Dashed AAGUID or ''.
	 * @since 2.1.35
	 */
	private static function format_aaguid( $bytes ) {
		if ( 16 !== strlen( $bytes ) || str_repeat( "\0", 16 ) === $bytes ) {
			return '';
		}
		$hex = bin2hex( $bytes );
		return substr( $hex, 0, 8 ) . '-' . substr( $hex, 8, 4 ) . '-' . substr( $hex, 12, 4 )
			. '-' . substr( $hex, 16, 4 ) . '-' . substr( $hex, 20 );
	}

	/**
	 * Best-effort verification of a "packed" attestation statement.
	 *
	 * Deliberately fail-open: the result only feeds the model label in the
	 * key manager, never a policy decision (Yubico guidance: request direct
	 * attestation and store it, but do not require it). x5c path verifies
	 * the signature with the attestation certificate's public key;
	 * self-attestation verifies with the credential key itself. No CA-chain
	 * or MDS validation — that trade-off is documented in the class header.
	 *
	 * @param array  $att_map          Decoded attestation object (fmt / attStmt / authData).
	 * @param string $client_data_hash SHA-256 of clientDataJSON (raw bytes).
	 * @return bool True when the statement's signature verified.
	 * @since 2.1.35
	 */
	private static function verify_packed_attestation( $att_map, $client_data_hash ) {
		if ( 'packed' !== ( $att_map['fmt'] ?? '' ) || ! is_array( $att_map['attStmt'] ?? null ) ) {
			return false;
		}
		$stmt = $att_map['attStmt'];
		$alg  = $stmt['alg'] ?? null;
		$sig  = $stmt['sig'] ?? '';
		if ( ! is_string( $sig ) || '' === $sig || ! in_array( $alg, array( -7, -257 ), true ) ) {
			return false;
		}
		$signed = $att_map['authData'] . $client_data_hash;

		if ( isset( $stmt['x5c'][0] ) && is_string( $stmt['x5c'][0] ) && '' !== $stmt['x5c'][0] ) {
			$pem = "-----BEGIN CERTIFICATE-----\n"
				. chunk_split( base64_encode( $stmt['x5c'][0] ), 64, "\n" )
				. "-----END CERTIFICATE-----\n";
			$key = openssl_pkey_get_public( $pem );
			if ( false === $key ) {
				return false;
			}
			return 1 === openssl_verify( $signed, $sig, $key, OPENSSL_ALGO_SHA256 );
		}

		$auth_info = self::parse_authenticator_data( $att_map['authData'] );
		if ( is_wp_error( $auth_info ) || empty( $auth_info['public_key_cbor'] ) ) {
			return false;
		}
		return true === self::verify_signature( $auth_info['public_key_cbor'], $signed, $sig );
	}

	/**
	 * Verify an assertion signature against a stored COSE public key,
	 * dispatching on the key type: Ed25519 (OKP, -8) verifies through
	 * libsodium, EC2/RSA through OpenSSL via the PEM path.
	 *
	 * @param string $public_key_cbor Stored COSE key bytes.
	 * @param string $signed_data     authenticatorData . SHA-256(clientDataJSON).
	 * @param string $signature       Raw signature from the authenticator.
	 * @return true|WP_Error
	 * @since 2.1.34
	 */
	private static function verify_signature( $public_key_cbor, $signed_data, $signature ) {
		$decoded = self::cbor_decode( $public_key_cbor, 0 );
		if ( is_wp_error( $decoded ) ) {
			return $decoded;
		}
		list( $map, ) = $decoded;
		if ( ! is_array( $map ) ) {
			return new WP_Error( 'webauthn_cose', __( 'COSE key is not parseable.', 'reportedip-hive' ) );
		}

		if ( 1 === ( $map[1] ?? null ) && -8 === ( $map[3] ?? null ) ) {
			if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
				return new WP_Error( 'webauthn_eddsa_unavailable', __( 'Ed25519 verification is not available on this server.', 'reportedip-hive' ) );
			}
			$crv = $map[-1] ?? null;
			$x   = $map[-2] ?? null;
			if ( 6 !== $crv || ! is_string( $x ) || 32 !== strlen( $x ) || 64 !== strlen( $signature ) ) {
				return new WP_Error( 'webauthn_cose_okp', __( 'Invalid Ed25519 key.', 'reportedip-hive' ) );
			}
			if ( ! sodium_crypto_sign_verify_detached( $signature, $signed_data, $x ) ) {
				return new WP_Error( 'webauthn_sig', __( 'Signature could not be verified.', 'reportedip-hive' ) );
			}
			return true;
		}

		$pem = self::cose_map_to_pem( $map );
		if ( is_wp_error( $pem ) ) {
			return $pem;
		}
		$ok = openssl_verify( $signed_data, $signature, $pem, OPENSSL_ALGO_SHA256 );
		if ( 1 !== $ok ) {
			return new WP_Error( 'webauthn_sig', __( 'Signature could not be verified.', 'reportedip-hive' ) );
		}
		return true;
	}

	/**
	 * PEM assembly for an already-decoded COSE key map (EC2 P-256 or RSA).
	 *
	 * @param array $map Decoded COSE key map.
	 * @return string|WP_Error PEM-encoded public key.
	 * @since 2.1.34
	 */
	private static function cose_map_to_pem( $map ) {
		$kty = $map[1] ?? null;
		$alg = $map[3] ?? null;

		if ( 2 === $kty && -7 === $alg ) {
			$crv = $map[-1] ?? null;
			if ( 1 !== $crv ) {
				return new WP_Error( 'webauthn_cose_crv', __( 'Unsupported EC curve.', 'reportedip-hive' ) );
			}
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
	 * Maximum nesting depth accepted by the CBOR decoder. Well-formed
	 * CTAP2 output nests three levels at most; anything deeper is hostile
	 * or broken input.
	 *
	 * @since 2.1.35
	 */
	const CBOR_MAX_DEPTH = 8;

	/**
	 * Minimal CBOR decoder covering the subset used by WebAuthn (maps,
	 * byte-strings, text-strings, ints, arrays). Returns [value, new-offset].
	 *
	 * Hardened against malformed input: every multi-byte read is
	 * bounds-checked, indefinite-length items, tags and floats are rejected
	 * explicitly (instead of silently desyncing the stream), and recursion
	 * is capped at CBOR_MAX_DEPTH.
	 *
	 * @param string $data   CBOR bytes.
	 * @param int    $offset Read position.
	 * @param int    $depth  Current nesting depth.
	 * @return array|WP_Error
	 */
	private static function cbor_decode( $data, $offset, $depth = 0 ) {
		if ( $depth > self::CBOR_MAX_DEPTH ) {
			return new WP_Error( 'cbor_depth', 'CBOR nesting too deep' );
		}
		$total = strlen( $data );
		if ( $offset >= $total ) {
			return new WP_Error( 'cbor_eof', 'CBOR EOF' );
		}
		$first = ord( $data[ $offset++ ] );
		$major = $first >> 5;
		$add   = $first & 0x1f;

		if ( 31 === $add ) {
			return new WP_Error( 'cbor_indefinite', 'Indefinite-length CBOR items are not supported' );
		}

		$read_uint = function ( $add_info ) use ( &$data, &$offset, $total ) {
			if ( $add_info < 24 ) {
				return $add_info;
			}
			$widths = array(
				24 => 1,
				25 => 2,
				26 => 4,
				27 => 8,
			);
			if ( ! isset( $widths[ $add_info ] ) || $offset + $widths[ $add_info ] > $total ) {
				return null;
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
			$high    = unpack( 'N', substr( $data, $offset, 4 ) )[1];
			$low     = unpack( 'N', substr( $data, $offset + 4, 4 ) )[1];
			$offset += 8;
			return $high * 4294967296 + $low;
		};

		switch ( $major ) {
			case 0:
				$v = $read_uint( $add );
				if ( null === $v ) {
					return new WP_Error( 'cbor_truncated', 'Truncated CBOR integer' );
				}
				return array( $v, $offset );
			case 1:
				$v = $read_uint( $add );
				if ( null === $v ) {
					return new WP_Error( 'cbor_truncated', 'Truncated CBOR integer' );
				}
				return array( -1 - $v, $offset );
			case 2:
			case 3:
				$len = $read_uint( $add );
				if ( null === $len || $offset + $len > $total ) {
					return new WP_Error( 'cbor_truncated', 'Truncated CBOR string' );
				}
				$s       = substr( $data, $offset, $len );
				$offset += $len;
				return array( $s, $offset );
			case 4:
				$len = $read_uint( $add );
				if ( null === $len ) {
					return new WP_Error( 'cbor_truncated', 'Truncated CBOR array header' );
				}
				$arr = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$res = self::cbor_decode( $data, $offset, $depth + 1 );
					if ( is_wp_error( $res ) ) {
						return $res;
					}
					$arr[]  = $res[0];
					$offset = $res[1];
				}
				return array( $arr, $offset );
			case 5:
				$len = $read_uint( $add );
				if ( null === $len ) {
					return new WP_Error( 'cbor_truncated', 'Truncated CBOR map header' );
				}
				$map = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$k = self::cbor_decode( $data, $offset, $depth + 1 );
					if ( is_wp_error( $k ) ) {
						return $k;
					}
					$offset = $k[1];
					if ( ! is_int( $k[0] ) && ! is_string( $k[0] ) ) {
						return new WP_Error( 'cbor_key', 'Unsupported CBOR map key type' );
					}
					$v = self::cbor_decode( $data, $offset, $depth + 1 );
					if ( is_wp_error( $v ) ) {
						return $v;
					}
					$offset       = $v[1];
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
				return new WP_Error( 'cbor_float', 'CBOR floats and reserved simple values are not supported' );
			default:
				return new WP_Error( 'cbor_unsupported', 'Unsupported CBOR major type ' . $major );
		}
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
