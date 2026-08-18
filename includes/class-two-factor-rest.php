<?php
/**
 * REST-API endpoints for the 2FA challenge/verify flow.
 *
 * Route namespace:  reportedip-hive/v1
 *
 *   POST /2fa/challenge   Accept username + password; on match, return a
 *                         short-lived challenge token + the methods the
 *                         user has active. Application-password auth is
 *                         bypassed (same semantics as the browser flow).
 *   POST /2fa/verify      Accept {token, method, code}; on success set the
 *                         WordPress auth cookie and return a simple ok.
 *   GET  /2fa/methods     Introspect which methods the currently-authed
 *                         user has active. Handy for headless clients.
 *
 * WebAuthn assertion is already handled by admin-ajax endpoints and is not
 * duplicated here (AJAX is the canonical surface for browser flows).
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

class ReportedIP_Hive_Two_Factor_REST {

	const NAMESPACE_STR      = 'reportedip-hive/v1';
	const TRANSIENT_PREFIX   = 'reportedip_2fa_rest_';
	const FAIL_PREFIX        = 'reportedip_2fa_rest_fail_';
	const IP_THROTTLE_PREFIX = 'reportedip_2fa_rest_ip_';
	const TOKEN_TTL          = 300;
	const MAX_TOKEN_FAILS    = 5;
	const IP_VERIFY_LIMIT    = 30;
	const IP_CHALLENGE_LIMIT = 20;
	const IP_THROTTLE_WINDOW = 300;

	public function __construct() {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Refuse a cross-origin call to the unauthenticated endpoints.
	 *
	 * Both routes end in `wp_set_auth_cookie()`, and neither can carry a nonce
	 * because the caller is not authenticated yet. Without an origin check a
	 * cross-site form post logs the visitor's browser into an account of the
	 * attacker's choosing. A request with no Origin header is left alone —
	 * that is a native or server-side client, not a browser form post.
	 *
	 * @return true|WP_Error True when the request may proceed.
	 * @since  2.1.44
	 */
	private function reject_cross_origin() {
		$origin = isset( $_SERVER['HTTP_ORIGIN'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_ORIGIN'] ) ) : '';
		if ( '' === $origin ) {
			return true;
		}

		$origin_host = (string) wp_parse_url( $origin, PHP_URL_HOST );
		$site_host   = (string) wp_parse_url( home_url(), PHP_URL_HOST );

		if ( '' !== $origin_host && '' !== $site_host && strtolower( $origin_host ) === strtolower( $site_host ) ) {
			return true;
		}

		return new WP_Error(
			'reportedip_rest_cross_origin',
			__( 'Cross-origin authentication requests are not allowed.', 'reportedip-hive' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Returns the requester IP, falling back to REMOTE_ADDR.
	 *
	 * @return string
	 */
	private function client_ip() {
		if ( class_exists( 'ReportedIP_Hive' ) ) {
			$ip = (string) ReportedIP_Hive::get_client_ip();
			if ( '' !== $ip ) {
				return $ip;
			}
		}
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}

	/**
	 * Returns true if the IP is still under the per-window request limit.
	 *
	 * Uses site-transients (network-scoped) on Multisite so an attacker
	 * hitting multiple sub-sites cannot reset their counter by switching
	 * the host. On single-site `*_site_transient` falls through to the
	 * regular transient functions, so behaviour is unchanged from v1.x.
	 *
	 * @param string $ip      Client IP.
	 * @param string $bucket  Bucket name (e.g. 'verify', 'challenge').
	 * @param int    $limit   Maximum requests in the window.
	 * @return bool
	 */
	private function ip_within_limit( $ip, $bucket, $limit ) {
		if ( '' === $ip ) {
			return true;
		}
		$key     = self::IP_THROTTLE_PREFIX . $bucket . '_' . md5( $ip );
		$current = (int) get_site_transient( $key );
		return $current < $limit;
	}

	/**
	 * Increments the per-IP request counter for the given bucket.
	 *
	 * @param string $ip     Client IP.
	 * @param string $bucket Bucket name.
	 */
	private function bump_ip_counter( $ip, $bucket ) {
		if ( '' === $ip ) {
			return;
		}
		$key     = self::IP_THROTTLE_PREFIX . $bucket . '_' . md5( $ip );
		$current = (int) get_site_transient( $key );
		set_site_transient( $key, $current + 1, self::IP_THROTTLE_WINDOW );
	}

	public function register_routes() {
		register_rest_route(
			self::NAMESPACE_STR,
			'/2fa/challenge',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_challenge' ),
				'permission_callback' => '__return_true',
				'args'                => array(
					'username' => array( 'required' => true ),
					'password' => array( 'required' => true ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE_STR,
			'/2fa/verify',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_verify' ),
				'permission_callback' => '__return_true',
				'args'                => array(
					'token'  => array( 'required' => true ),
					'method' => array( 'required' => true ),
					'code'   => array( 'required' => true ),
				),
			)
		);

		register_rest_route(
			self::NAMESPACE_STR,
			'/2fa/methods',
			array(
				'methods'             => 'GET',
				'callback'            => array( $this, 'handle_methods' ),
				'permission_callback' => function () {
					return is_user_logged_in(); },
			)
		);
	}

	/**
	 * Challenge step — password auth + challenge-token issuance.
	 *
	 * Intentionally uses wp_authenticate() so that IP-block/reputation hooks
	 * and the 2FA filter stack run as usual; we then swap the WP_Error-based
	 * "needs 2FA" result for a structured REST response with a challenge token.
	 */
	public function handle_challenge( WP_REST_Request $request ) {
		$cross_origin = $this->reject_cross_origin();
		if ( is_wp_error( $cross_origin ) ) {
			return $cross_origin;
		}

		$ip = $this->client_ip();
		if ( ! $this->ip_within_limit( $ip, 'challenge', self::IP_CHALLENGE_LIMIT ) ) {
			return new WP_Error( 'reportedip_rest_throttled', __( 'Too many requests. Please try again later.', 'reportedip-hive' ), array( 'status' => 429 ) );
		}
		$this->bump_ip_counter( $ip, 'challenge' );

		$username = sanitize_user( (string) $request->get_param( 'username' ), true );
		$password = (string) $request->get_param( 'password' );

		if ( '' === $username || '' === $password ) {
			return new WP_Error( 'reportedip_rest_missing', __( 'Username and password are required.', 'reportedip-hive' ), array( 'status' => 400 ) );
		}

		$user = wp_authenticate( $username, $password );

		if ( is_wp_error( $user ) && 'reportedip_2fa_required' === $user->get_error_code() ) {
			$data  = $user->get_error_data();
			$token = $data['token'] ?? '';
			if ( empty( $token ) ) {
				return new WP_Error( 'reportedip_rest_no_token', __( 'Could not create challenge token.', 'reportedip-hive' ), array( 'status' => 500 ) );
			}

			$hash    = hash( 'sha256', $token );
			$nonce_d = get_transient( ReportedIP_Hive_Two_Factor::NONCE_PREFIX . $hash );
			$user_id = is_array( $nonce_d ) ? (int) ( $nonce_d['user_id'] ?? 0 ) : 0;
			if ( ! $user_id ) {
				return new WP_Error( 'reportedip_rest_no_user', __( 'Challenge context missing.', 'reportedip-hive' ), array( 'status' => 500 ) );
			}

			set_transient( self::TRANSIENT_PREFIX . $hash, $user_id, self::TOKEN_TTL );

			return rest_ensure_response(
				array(
					'status'  => 'challenge_required',
					'token'   => $token,
					'methods' => ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id ),
				)
			);
		}

		if ( is_wp_error( $user ) ) {
			return new WP_Error( $user->get_error_code(), $user->get_error_message(), array( 'status' => 401 ) );
		}

		wp_set_auth_cookie( $user->ID, false );
		wp_set_current_user( $user->ID );
		return rest_ensure_response(
			array(
				'status'  => 'authenticated',
				'user_id' => $user->ID,
			)
		);
	}

	/**
	 * Verify step — consume the challenge token and verify the submitted code.
	 */
	public function handle_verify( WP_REST_Request $request ) {
		$cross_origin = $this->reject_cross_origin();
		if ( is_wp_error( $cross_origin ) ) {
			return $cross_origin;
		}

		$ip = $this->client_ip();
		if ( ! $this->ip_within_limit( $ip, 'verify', self::IP_VERIFY_LIMIT ) ) {
			return new WP_Error( 'reportedip_rest_throttled', __( 'Too many requests. Please try again later.', 'reportedip-hive' ), array( 'status' => 429 ) );
		}
		$this->bump_ip_counter( $ip, 'verify' );

		$token  = (string) $request->get_param( 'token' );
		$method = sanitize_key( (string) $request->get_param( 'method' ) );
		$code   = (string) $request->get_param( 'code' );

		$hash     = hash( 'sha256', $token );
		$fail_key = self::FAIL_PREFIX . $hash;
		$user_id  = (int) get_transient( self::TRANSIENT_PREFIX . $hash );
		if ( $user_id <= 0 ) {
			return new WP_Error( 'reportedip_rest_invalid_token', __( 'Challenge token is invalid or expired.', 'reportedip-hive' ), array( 'status' => 401 ) );
		}

		$fails = (int) get_transient( $fail_key );
		if ( $fails >= self::MAX_TOKEN_FAILS ) {
			delete_transient( self::TRANSIENT_PREFIX . $hash );
			delete_transient( ReportedIP_Hive_Two_Factor::NONCE_PREFIX . $hash );
			delete_transient( $fail_key );
			return new WP_Error( 'reportedip_rest_locked', __( 'Too many failed attempts. Please request a new challenge.', 'reportedip-hive' ), array( 'status' => 401 ) );
		}

		$enabled_methods = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id );
		if ( ! in_array( $method, array_merge( $enabled_methods, array( ReportedIP_Hive_Two_Factor::METHOD_RECOVERY ) ), true ) ) {
			return new WP_Error( 'reportedip_rest_method', __( 'This method is not allowed for this user.', 'reportedip-hive' ), array( 'status' => 400 ) );
		}

		$ok = self::verify_for_user( $user_id, $method, $code );
		if ( ! $ok ) {
			set_transient( $fail_key, $fails + 1, self::TOKEN_TTL );

			/*
			 * Feed the shared ladder as well. The per-token and per-IP limits
			 * above are local to this endpoint, so guessing over REST used to
			 * leave no trace in the 2FA lockout state and never graduated to
			 * the IP block the browser path would have triggered.
			 */
			ReportedIP_Hive_Two_Factor::record_ip_failure( $ip );

			return new WP_Error( 'reportedip_rest_bad_code', __( 'Invalid code.', 'reportedip-hive' ), array( 'status' => 401 ) );
		}

		delete_transient( self::TRANSIENT_PREFIX . $hash );
		delete_transient( ReportedIP_Hive_Two_Factor::NONCE_PREFIX . $hash );
		delete_transient( $fail_key );

		wp_set_auth_cookie( $user_id, false );
		wp_set_current_user( $user_id );

		return rest_ensure_response(
			array(
				'status'  => 'authenticated',
				'user_id' => $user_id,
			)
		);
	}

	/**
	 * Currently active methods for the authenticated REST user.
	 */
	public function handle_methods( WP_REST_Request $request ) {
		unset( $request );
		$user_id = get_current_user_id();
		return rest_ensure_response(
			array(
				'user_id' => $user_id,
				'methods' => ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id ),
			)
		);
	}

	/**
	 * Verify a submitted code through the shared verifier.
	 *
	 * This used to be a hand-copied switch, which is exactly what extracting
	 * `Two_Factor_Verifier` was meant to end. It had already drifted: no
	 * WebAuthn case, the `reportedip_2fa_totp_window` filter ignored, the
	 * decrypted secret left in memory — and it would have missed the TOTP
	 * single-use enforcement too.
	 *
	 * @param int    $user_id User to verify against.
	 * @param string $method  Method identifier.
	 * @param string $code    Submitted code.
	 * @return bool
	 */
	private static function verify_for_user( $user_id, $method, $code ) {
		return ReportedIP_Hive_Two_Factor_Verifier::verify_method(
			(int) $user_id,
			(string) $method,
			(string) $code
		);
	}
}
