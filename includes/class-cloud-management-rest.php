<?php
/**
 * Cloud management REST transport — lets reportedip.com read the settings
 * schema/values and apply settings batches, in parallel to MainWP.
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
 * Signed REST endpoints for the reportedip.com fleet dashboard.
 *
 * Second transport of the remote-settings protocol (see
 * docs/remote-settings-protocol.md): the same three operations MainWP drives
 * through `mainwp_child_extra_execution`, exposed as REST routes that the
 * service calls directly. Every request carries an Ed25519-signed envelope
 * (`payload` string + detached `signature`); the handler verifies the literal
 * payload string, then enforces a freshness window, single-use request ids,
 * an audience binding to this site's announced host and a proof of the
 * account API key before any operation runs. The whole transport is opt-in
 * via the `reportedip_hive_cloud_management` option (default off).
 *
 * @since 2.1.48
 */
final class ReportedIP_Hive_Cloud_Management_REST {

	/**
	 * REST namespace shared with the 2FA routes.
	 */
	const NAMESPACE_STR = 'reportedip-hive/v1';

	/**
	 * Bundled Ed25519 public keys (base64) of the reportedip.com fleet signer.
	 * Separate keypair from the ruleset signing key; `next` is reserved so a
	 * rotation can ship before the service switches.
	 *
	 * @var array<string, string>
	 */
	const PUBLIC_KEYS = array(
		'current' => '',
		'next'    => '',
	);

	/**
	 * Maximum accepted signed payload size (bytes).
	 */
	const MAX_PAYLOAD_BYTES = 524288;

	/**
	 * Accepted clock skew between service and site (seconds, both directions).
	 */
	const TIME_WINDOW = 300;

	/**
	 * Replay-cache lifetime for consumed request ids (seconds).
	 */
	const REPLAY_TTL = 600;

	/**
	 * Per-IP request limit inside the throttle window.
	 */
	const IP_LIMIT = 30;

	/**
	 * Per-IP throttle window (seconds).
	 */
	const IP_WINDOW = 300;

	/**
	 * Opt-in option key (local-only, deliberately not remote-manageable).
	 */
	const OPTION_ENABLED = 'reportedip_hive_cloud_management';

	/**
	 * Authorization results memoized per request object.
	 *
	 * WordPress evaluates a route's permission callback twice per request
	 * (dispatch plus the Allow-header pass). Without a memo the second pass
	 * would consume the single-use request id and log a bogus replay for
	 * every successful call. Keyed by spl_object_id — deliberately NOT a
	 * request param, which a caller could inject through the body.
	 *
	 * @var array<int, true|WP_Error>
	 */
	private $auth_memo = array();

	/**
	 * Hook route registration.
	 *
	 * @since 2.1.48
	 */
	public function __construct() {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register the three signed management routes.
	 *
	 * @return void
	 * @since  2.1.48
	 */
	public function register_routes() {
		foreach ( array( 'schema', 'get', 'apply' ) as $action ) {
			register_rest_route(
				self::NAMESPACE_STR,
				'/remote/settings/' . $action,
				array(
					'methods'             => 'POST',
					'callback'            => array( $this, 'handle_request' ),
					'permission_callback' => array( $this, 'authorize_request' ),
					'args'                => array(
						'payload'   => array( 'required' => true ),
						'signature' => array( 'required' => true ),
					),
				)
			);
		}
	}

	/**
	 * Whether the site owner has enabled cloud management and the site is
	 * connected to the community network.
	 *
	 * @return bool
	 * @since  2.1.48
	 */
	public static function is_enabled() {
		if ( ! ReportedIP_Hive_Option_Routing::get( self::OPTION_ENABLED, false ) ) {
			return false;
		}
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		if ( ! $mode_manager->is_community_mode() ) {
			return false;
		}
		return '' !== (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );
	}

	/**
	 * Accepted fleet-signer public keys (base64), filterable for rotation
	 * and tests.
	 *
	 * @return array<int, string>
	 * @since  2.1.48
	 */
	public static function public_keys() {
		/* @phpstan-ignore-next-line arrayFilter.alwaysEmpty — the `current` slot is a build-time placeholder; the release ships a real key. */
		$keys = array_values( array_filter( self::PUBLIC_KEYS ) );
		/**
		 * Filter the accepted Ed25519 public keys (base64) for cloud
		 * management request verification.
		 *
		 * @param array<int, string> $keys Base64-encoded public keys.
		 */
		$keys = apply_filters( 'reportedip_hive_cloud_public_keys', $keys );
		return is_array( $keys ) ? $keys : array();
	}

	/**
	 * Full authorization chain: opt-in, throttle, signature, freshness,
	 * replay, audience and API-key proof. The verified, decoded payload is
	 * stashed on the request for the handler.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return true|WP_Error
	 * @since  2.1.48
	 */
	public function authorize_request( $request ) {
		$memo_key = spl_object_id( $request );
		if ( isset( $this->auth_memo[ $memo_key ] ) ) {
			return $this->auth_memo[ $memo_key ];
		}
		$result                       = $this->evaluate_request( $request );
		$this->auth_memo[ $memo_key ] = $result;
		return $result;
	}

	/**
	 * Single evaluation of the authorization chain (see authorize_request).
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return true|WP_Error
	 */
	private function evaluate_request( $request ) {
		if ( ! self::is_enabled() ) {
			return new WP_Error(
				'reportedip_cloud_disabled',
				__( 'Cloud management is not enabled on this site.', 'reportedip-hive' ),
				array( 'status' => 403 )
			);
		}

		$ip = $this->client_ip();
		if ( ! $this->ip_within_limit( $ip ) ) {
			return new WP_Error(
				'reportedip_cloud_throttled',
				__( 'Too many requests. Please try again later.', 'reportedip-hive' ),
				array( 'status' => 429 )
			);
		}
		$this->bump_ip_counter( $ip );

		$payload   = $request->get_param( 'payload' );
		$signature = $request->get_param( 'signature' );

		if ( ! is_string( $payload ) || '' === $payload || strlen( $payload ) > self::MAX_PAYLOAD_BYTES ) {
			return $this->reject( 'reportedip_cloud_invalid_payload', __( 'Invalid request payload.', 'reportedip-hive' ), 400, 'payload_too_large_or_invalid' );
		}

		if ( ! ReportedIP_Hive_Ed25519_Verifier::verify( $payload, (string) $signature, self::public_keys() ) ) {
			return $this->reject( 'reportedip_cloud_bad_signature', __( 'Request signature verification failed.', 'reportedip-hive' ), 401, 'signature_invalid' );
		}

		$data = json_decode( $payload, true );
		if ( ! is_array( $data ) ) {
			return $this->reject( 'reportedip_cloud_invalid_payload', __( 'Invalid request payload.', 'reportedip-hive' ), 400, 'payload_shape_invalid' );
		}

		$expected_action = $this->route_action( $request );
		$action          = isset( $data['action'] ) ? (string) $data['action'] : '';
		if ( '' === $expected_action || $action !== $expected_action ) {
			return $this->reject( 'reportedip_cloud_action_mismatch', __( 'Request action does not match the endpoint.', 'reportedip-hive' ), 400, 'action_mismatch' );
		}

		$issued_at = isset( $data['issued_at'] ) ? (int) $data['issued_at'] : 0;
		if ( abs( time() - $issued_at ) > self::TIME_WINDOW ) {
			return $this->reject( 'reportedip_cloud_expired', __( 'Request timestamp is outside the accepted window.', 'reportedip-hive' ), 401, 'issued_at_out_of_window' );
		}

		$request_id = isset( $data['request_id'] ) ? (string) $data['request_id'] : '';
		if ( '' === $request_id || strlen( $request_id ) > 64 ) {
			return $this->reject( 'reportedip_cloud_invalid_payload', __( 'Invalid request payload.', 'reportedip-hive' ), 400, 'request_id_invalid' );
		}
		$replay_key = 'reportedip_cloud_req_' . md5( $request_id );
		if ( get_site_transient( $replay_key ) ) {
			return $this->reject( 'reportedip_cloud_replayed', __( 'Request has already been processed.', 'reportedip-hive' ), 401, 'request_replayed' );
		}
		set_site_transient( $replay_key, 1, self::REPLAY_TTL );

		$site = isset( $data['site'] ) ? (string) $data['site'] : '';
		if ( '' === $site || $this->normalized_host( $site ) !== $this->own_host() ) {
			return $this->reject( 'reportedip_cloud_wrong_audience', __( 'Request is not addressed to this site.', 'reportedip-hive' ), 401, 'audience_mismatch' );
		}

		$api_key   = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );
		$key_proof = isset( $data['key_proof'] ) ? (string) $data['key_proof'] : '';
		if ( '' === $key_proof || ! hash_equals( hash( 'sha256', $api_key . $request_id ), $key_proof ) ) {
			return $this->reject( 'reportedip_cloud_bad_key_proof', __( 'Request account proof verification failed.', 'reportedip-hive' ), 401, 'key_proof_mismatch' );
		}

		$request->set_param( '_rip_cloud_payload', $data );
		return true;
	}

	/**
	 * Dispatch the verified operation and return the protocol envelope.
	 *
	 * @param WP_REST_Request $request Verified request.
	 * @return WP_REST_Response|WP_Error
	 * @since  2.1.48
	 */
	public function handle_request( $request ) {
		$data = $request->get_param( '_rip_cloud_payload' );
		if ( ! is_array( $data ) ) {
			return new WP_Error(
				'reportedip_cloud_invalid_payload',
				__( 'Invalid request payload.', 'reportedip-hive' ),
				array( 'status' => 400 )
			);
		}

		switch ( (string) $data['action'] ) {
			case 'schema':
				return rest_ensure_response(
					array( 'settings_schema' => ReportedIP_Hive_Settings_Registry::export_schema() )
				);

			case 'get':
				return rest_ensure_response(
					array( 'settings_values' => ReportedIP_Hive_Settings_Registry::values_envelope() )
				);

			case 'apply':
				$values_json = isset( $data['values_json'] ) ? (string) $data['values_json'] : '';
				$decoded     = json_decode( $values_json, true );
				if ( ! is_array( $decoded ) ) {
					return rest_ensure_response(
						array( 'settings_apply' => ReportedIP_Hive_Settings_Apply::invalid_payload_envelope() )
					);
				}
				return rest_ensure_response(
					array( 'settings_apply' => ReportedIP_Hive_Settings_Apply::apply( $decoded, 'cloud' ) )
				);
		}

		return new WP_Error(
			'reportedip_cloud_action_mismatch',
			__( 'Request action does not match the endpoint.', 'reportedip-hive' ),
			array( 'status' => 400 )
		);
	}

	/**
	 * Extract the trailing action segment from the matched route.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return string `schema`, `get`, `apply` or ''.
	 */
	private function route_action( $request ) {
		$route = (string) $request->get_route();
		if ( preg_match( '#/remote/settings/(schema|get|apply)$#', $route, $m ) ) {
			return $m[1];
		}
		return '';
	}

	/**
	 * Build a rejection error and log it as a security event so tampering
	 * attempts surface in the log like ruleset signature failures do.
	 *
	 * @param string $code    WP_Error code.
	 * @param string $message User-safe message.
	 * @param int    $status  HTTP status.
	 * @param string $reason  Machine-readable log reason.
	 * @return WP_Error
	 */
	private function reject( $code, $message, $status, $reason ) {
		if ( class_exists( 'ReportedIP_Hive_Logger' ) ) {
			ReportedIP_Hive_Logger::get_instance()->log_security_event(
				'cloud_management_auth_fail',
				$this->client_ip(),
				array( 'reason' => $reason ),
				'high'
			);
		}
		return new WP_Error( $code, $message, array( 'status' => $status ) );
	}

	/**
	 * Lowercased host with a leading `www.` stripped — matches the domain
	 * normalization the service applies to its domain registry.
	 *
	 * @param string $value Host or URL.
	 * @return string
	 */
	private function normalized_host( $value ) {
		$host = $value;
		if ( false !== strpos( $value, '//' ) ) {
			$host = (string) wp_parse_url( $value, PHP_URL_HOST );
		}
		$host = strtolower( trim( (string) $host, " \t\n\r\0\x0B." ) );
		if ( 0 === strpos( $host, 'www.' ) ) {
			$host = substr( $host, 4 );
		}
		return $host;
	}

	/**
	 * This site's announced host, normalized like the service registry.
	 *
	 * @return string
	 */
	private function own_host() {
		return $this->normalized_host( ReportedIP_Hive_API::api_site_url() );
	}

	/**
	 * Requester IP, proxy-aware with REMOTE_ADDR fallback.
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
	 * Whether the IP is still below the per-window request limit.
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	private function ip_within_limit( $ip ) {
		if ( '' === $ip ) {
			return true;
		}
		$current = (int) get_site_transient( 'reportedip_cloud_ip_' . md5( $ip ) );
		return $current < self::IP_LIMIT;
	}

	/**
	 * Increment the per-IP request counter.
	 *
	 * @param string $ip Client IP.
	 * @return void
	 */
	private function bump_ip_counter( $ip ) {
		if ( '' === $ip ) {
			return;
		}
		$key     = 'reportedip_cloud_ip_' . md5( $ip );
		$current = (int) get_site_transient( $key );
		set_site_transient( $key, $current + 1, self::IP_WINDOW );
	}
}
