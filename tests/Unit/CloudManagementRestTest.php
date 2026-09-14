<?php
/**
 * Unit tests for the signed cloud management REST transport.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.48
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-apply.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-ed25519-verifier.php';

	if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
		/**
		 * Minimal Mode-Manager double: community mode on, gated features off.
		 */
		class ReportedIP_Hive_Mode_Manager {
			/**
			 * Singleton accessor.
			 *
			 * @return self
			 */
			public static function get_instance() {
				return new self();
			}

			/**
			 * Community mode flag.
			 *
			 * @return bool
			 */
			public function is_community_mode() {
				return true;
			}

			/**
			 * Feature availability lookup.
			 *
			 * @param string $feature Feature slug.
			 * @return array<string, mixed>
			 */
			public function feature_status( $feature ) {
				unset( $feature );
				return array(
					'available' => false,
					'min_tier'  => 'Professional',
				);
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_API' ) ) {
		/**
		 * API-client double: only the announced site URL is needed here. The
		 * `www.` prefix is deliberate, the audience check must strip it the
		 * same way the service domain registry does.
		 */
		class ReportedIP_Hive_API {
			/**
			 * Announced site URL.
			 *
			 * @return string
			 */
			public static function api_site_url() {
				return 'https://www.example.com';
			}
		}
	}

	if ( ! class_exists( 'WP_REST_Request' ) ) {
		/**
		 * Tiny request double covering the parameter and route surface the
		 * transport uses.
		 */
		class WP_REST_Request {
			/**
			 * Parameter bag.
			 *
			 * @var array<string, mixed>
			 */
			private $params = array();

			/**
			 * Matched route.
			 *
			 * @var string
			 */
			private $route = '';

			/**
			 * Build a request double.
			 *
			 * @param array<string, mixed> $params Parameters.
			 * @param string               $route  Matched route.
			 */
			public function __construct( array $params = array(), $route = '' ) {
				$this->params = $params;
				$this->route  = $route;
			}

			/**
			 * Parameter getter.
			 *
			 * @param string $key Parameter name.
			 * @return mixed
			 */
			public function get_param( $key ) {
				return isset( $this->params[ $key ] ) ? $this->params[ $key ] : null;
			}

			/**
			 * Parameter setter.
			 *
			 * @param string $key   Parameter name.
			 * @param mixed  $value Value.
			 * @return void
			 */
			public function set_param( $key, $value ) {
				$this->params[ $key ] = $value;
			}

			/**
			 * Matched route getter.
			 *
			 * @return string
			 */
			public function get_route() {
				return $this->route;
			}
		}
	}

	if ( ! function_exists( 'rest_ensure_response' ) ) {
		/**
		 * Pass-through response wrapper for unit scope.
		 *
		 * @param mixed $response Handler return value.
		 * @return mixed
		 */
		function rest_ensure_response( $response ) {
			return $response;
		}
	}

	if ( ! function_exists( 'register_rest_route' ) ) {
		/**
		 * No-op route registration for unit scope.
		 *
		 * @param string               $route_namespace Namespace.
		 * @param string               $route           Route.
		 * @param array<string, mixed> $args            Route args.
		 * @return bool
		 */
		function register_rest_route( $route_namespace, $route, $args = array() ) {
			unset( $route_namespace, $route, $args );
			return true;
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-cloud-management-rest.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Covers the full authorization chain (opt-in, signature, freshness,
	 * replay, audience, key proof) and the envelope parity with MainWP.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class CloudManagementRestTest extends TestCase {

		/**
		 * Ed25519 secret key for the simulated fleet signer.
		 *
		 * @var string
		 */
		private $secret_key = '';

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']    = array(
				'reportedip_hive_cloud_management' => 1,
				'reportedip_hive_api_key'          => 'test-account-key',
			);
			$GLOBALS['wp_transients'] = array();

			$keypair          = sodium_crypto_sign_keypair();
			$this->secret_key = sodium_crypto_sign_secretkey( $keypair );
			$public_b64       = base64_encode( sodium_crypto_sign_publickey( $keypair ) );

			add_filter(
				'reportedip_hive_cloud_public_keys',
				static function ( $keys ) use ( $public_b64 ) {
					$keys[] = $public_b64;
					return $keys;
				}
			);
		}

		/**
		 * Build a signed request for the given action.
		 *
		 * @param string               $action    Endpoint action.
		 * @param array<string, mixed> $overrides Payload field overrides.
		 * @param string|null          $signature Forced signature (null = valid).
		 * @return \WP_REST_Request
		 */
		private function signed_request( $action, array $overrides = array(), $signature = null ) {
			$request_id = bin2hex( random_bytes( 16 ) );
			$payload    = array_merge(
				array(
					'action'     => $action,
					'site'       => 'example.com',
					'issued_at'  => time(),
					'request_id' => $request_id,
					'key_proof'  => hash( 'sha256', 'test-account-key' . $request_id ),
				),
				$overrides
			);
			if ( array_key_exists( 'request_id', $overrides ) || array_key_exists( 'key_proof', $overrides ) ) {
				$payload['key_proof'] = array_key_exists( 'key_proof', $overrides )
					? $overrides['key_proof']
					: hash( 'sha256', 'test-account-key' . $payload['request_id'] );
			}

			$payload_json = (string) wp_json_encode( $payload );
			$sig          = null === $signature
				? base64_encode( sodium_crypto_sign_detached( $payload_json, $this->secret_key ) )
				: $signature;

			return new \WP_REST_Request(
				array(
					'payload'   => $payload_json,
					'signature' => $sig,
				),
				'/reportedip-hive/v1/remote/settings/' . $action
			);
		}

		public function test_disabled_toggle_is_denied_uniformly() {
			$GLOBALS['wp_options']['reportedip_hive_cloud_management'] = 0;
			$rest   = new \ReportedIP_Hive_Cloud_Management_REST();
			$result = $rest->authorize_request( $this->signed_request( 'schema' ) );

			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_cloud_denied', $result->get_error_code() );
			$this->assertSame( 401, $result->get_error_data()['status'] );
		}

		public function test_valid_schema_request_returns_schema_envelope() {
			$rest    = new \ReportedIP_Hive_Cloud_Management_REST();
			$request = $this->signed_request( 'schema' );

			$this->assertTrue( $rest->authorize_request( $request ) );

			$response = $rest->handle_request( $request );
			$this->assertArrayHasKey( 'settings_schema', $response );
			$this->assertSame( \ReportedIP_Hive_Settings_Registry::SCHEMA_VERSION, $response['settings_schema']['schema_version'] );
		}

		public function test_valid_get_request_returns_values_envelope_with_hash() {
			$rest    = new \ReportedIP_Hive_Cloud_Management_REST();
			$request = $this->signed_request( 'get' );

			$this->assertTrue( $rest->authorize_request( $request ) );

			$response = $rest->handle_request( $request );
			$this->assertArrayHasKey( 'settings_values', $response );
			$this->assertSame( \ReportedIP_Hive_Settings_Registry::settings_hash(), $response['settings_values']['hash'] );
		}

		public function test_apply_envelope_matches_mainwp_shape_for_identical_input() {
			$values = array( 'reportedip_hive_failed_login_threshold' => 5 );

			$rest    = new \ReportedIP_Hive_Cloud_Management_REST();
			$request = $this->signed_request( 'apply', array( 'values_json' => (string) wp_json_encode( $values ) ) );

			$this->assertTrue( $rest->authorize_request( $request ) );
			$cloud = $rest->handle_request( $request );

			$mainwp = \ReportedIP_Hive_Settings_Apply::apply( $values, 'mainwp' );

			$this->assertSame( $mainwp, $cloud['settings_apply'] );
			$this->assertSame( 'unchanged', $cloud['settings_apply']['results']['reportedip_hive_failed_login_threshold']['status'] );
		}

		public function test_apply_with_malformed_values_json_returns_invalid_payload_envelope() {
			$rest    = new \ReportedIP_Hive_Cloud_Management_REST();
			$request = $this->signed_request( 'apply', array( 'values_json' => 'not-json' ) );

			$this->assertTrue( $rest->authorize_request( $request ) );

			$response = $rest->handle_request( $request );
			$this->assertSame( 'invalid_payload', $response['settings_apply']['error'] );
			$this->assertSame( 0, $response['settings_apply']['applied'] );
		}

		public function test_tampered_signature_is_rejected() {
			$rest    = new \ReportedIP_Hive_Cloud_Management_REST();
			$result  = $rest->authorize_request(
				$this->signed_request( 'schema', array(), base64_encode( str_repeat( 'x', SODIUM_CRYPTO_SIGN_BYTES ) ) )
			);

			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_cloud_denied', $result->get_error_code() );
		}

		public function test_stale_issued_at_is_rejected() {
			$rest   = new \ReportedIP_Hive_Cloud_Management_REST();
			$result = $rest->authorize_request(
				$this->signed_request( 'schema', array( 'issued_at' => time() - 4000 ) )
			);

			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_cloud_expired', $result->get_error_code() );
		}

		public function test_request_id_replay_is_rejected() {
			$rest    = new \ReportedIP_Hive_Cloud_Management_REST();
			$request = $this->signed_request( 'schema' );

			$this->assertTrue( $rest->authorize_request( $request ) );

			$replay_request = new \WP_REST_Request(
				array(
					'payload'   => $request->get_param( 'payload' ),
					'signature' => $request->get_param( 'signature' ),
				),
				$request->get_route()
			);
			$replay = $rest->authorize_request( $replay_request );
			$this->assertInstanceOf( \WP_Error::class, $replay );
			$this->assertSame( 'reportedip_cloud_replayed', $replay->get_error_code() );
		}

		public function test_second_permission_pass_on_same_request_is_memoized() {
			$rest    = new \ReportedIP_Hive_Cloud_Management_REST();
			$request = $this->signed_request( 'schema' );

			$this->assertTrue( $rest->authorize_request( $request ) );
			$this->assertTrue( $rest->authorize_request( $request ), 'The Allow-header pass re-evaluates the permission callback; it must not trip the replay guard.' );
		}

		public function test_wrong_audience_is_rejected() {
			$rest   = new \ReportedIP_Hive_Cloud_Management_REST();
			$result = $rest->authorize_request(
				$this->signed_request( 'schema', array( 'site' => 'other-site.com' ) )
			);

			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_cloud_wrong_audience', $result->get_error_code() );
		}

		public function test_wrong_key_proof_is_rejected() {
			$rest   = new \ReportedIP_Hive_Cloud_Management_REST();
			$result = $rest->authorize_request(
				$this->signed_request( 'schema', array( 'key_proof' => hash( 'sha256', 'wrong' ) ) )
			);

			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_cloud_bad_key_proof', $result->get_error_code() );
		}

		public function test_action_endpoint_mismatch_is_rejected() {
			$rest       = new \ReportedIP_Hive_Cloud_Management_REST();
			$request_id = bin2hex( random_bytes( 16 ) );
			$payload    = (string) wp_json_encode(
				array(
					'action'     => 'get',
					'site'       => 'example.com',
					'issued_at'  => time(),
					'request_id' => $request_id,
					'key_proof'  => hash( 'sha256', 'test-account-key' . $request_id ),
				)
			);
			$request    = new \WP_REST_Request(
				array(
					'payload'   => $payload,
					'signature' => base64_encode( sodium_crypto_sign_detached( $payload, $this->secret_key ) ),
				),
				'/reportedip-hive/v1/remote/settings/apply'
			);

			$result = $rest->authorize_request( $request );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'reportedip_cloud_action_mismatch', $result->get_error_code() );
		}
	}
}
