<?php
/**
 * Unit tests for the wp.org-style API telemetry transport (2.1.45).
 *
 * Locks down four behaviours: (1) `api_site_url()` announces the untrailed
 * home URL (network home URL on Multisite is covered by the Multisite suite);
 * (2) `api_user_agent()` follows the wp.org shape
 * `ReportedIP-Hive/{v} (WordPress/{wpv}; {site})`; (3) every request built by
 * `make_request()` carries the X-Rip-Site header plus the uniform User-Agent;
 * and (4) the HIBP password check never receives the site identity — neither
 * in its User-Agent nor as an X-Rip-Site header.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.45
 */

namespace {

	if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
		define( 'HOUR_IN_SECONDS', 3600 );
	}
	if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
		define( 'MINUTE_IN_SECONDS', 60 );
	}
	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}
	if ( ! defined( 'REPORTEDIP_HIVE_VERSION' ) ) {
		define( 'REPORTEDIP_HIVE_VERSION', '2.1.45-test' );
	}

	if ( ! function_exists( 'wp_remote_request' ) ) {
		function wp_remote_request( $url, $args = array() ) {
			$GLOBALS['rip_telemetry_requests'][] = array(
				'url'  => $url,
				'args' => $args,
			);
			$next = $GLOBALS['rip_telemetry_http_next'] ?? null;
			return null === $next ? new \WP_Error( 'no_network', 'Network calls disabled in unit tests' ) : $next;
		}
	}
	if ( ! function_exists( 'wp_remote_get' ) ) {
		function wp_remote_get( $url, $args = array() ) {
			return wp_remote_request( $url, $args );
		}
	}
	if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
		function wp_remote_retrieve_body( $r ) { return is_array( $r ) ? ( $r['body'] ?? '' ) : ''; }
	}
	if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
		function wp_remote_retrieve_response_code( $r ) { return is_array( $r ) ? ( $r['response']['code'] ?? 0 ) : 0; }
	}
	if ( ! function_exists( 'wp_remote_retrieve_header' ) ) {
		function wp_remote_retrieve_header( $r, $h ) { return is_array( $r ) ? ( $r['headers'][ $h ] ?? '' ) : ''; }
	}

	if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
		class ReportedIP_Hive_Logger {
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) { self::$instance = new self(); }
				return self::$instance;
			}
			public function log_security_event( ...$args ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			public static function truncate( $text, $len = 200 ) { return substr( (string) $text, 0, $len ); }
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-api-client.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-password-strength.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Captures the exact HTTP arguments each builder emits and asserts the
	 * telemetry contract on them.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class ApiTelemetryHeadersTest extends TestCase {

		protected function set_up() {
			parent::set_up();

			if ( ! class_exists( 'ReportedIP_Hive_Cache' ) ) {
				require_once dirname( __DIR__, 2 ) . '/includes/class-cache.php';
			}

			$GLOBALS['wp_transients']            = array();
			$GLOBALS['wp_options']               = array(
				'reportedip_hive_api_key'        => 'test-key',
				'reportedip_hive_api_endpoint'   => 'https://example.test/v2/',
				'reportedip_hive_operation_mode' => 'community',
			);
			$GLOBALS['rip_telemetry_requests']   = array();
			$GLOBALS['rip_telemetry_http_next']  = null;

			$prop = new \ReflectionProperty( '\ReportedIP_Hive_API', 'instance' );
			$prop->setValue( null, null );
		}

		private function api(): \ReportedIP_Hive_API {
			return \ReportedIP_Hive_API::get_instance();
		}

		private function last_request(): array {
			$requests = $GLOBALS['rip_telemetry_requests'];
			$this->assertNotEmpty( $requests, 'Expected at least one captured HTTP request.' );
			return end( $requests );
		}

		public function test_api_site_url_is_untrailed_home_url() {
			$this->assertSame( 'https://example.org', \ReportedIP_Hive_API::api_site_url() );
		}

		public function test_api_user_agent_follows_the_wporg_shape() {
			$ua = \ReportedIP_Hive_API::api_user_agent();

			$this->assertMatchesRegularExpression(
				'~^ReportedIP-Hive/[^ ]+ \(WordPress/.+; https://example\.org\)$~',
				$ua
			);
			$this->assertStringContainsString( 'ReportedIP-Hive/' . REPORTEDIP_HIVE_VERSION, $ua );
		}

		public function test_make_request_sends_site_header_and_uniform_user_agent() {
			$this->api()->verify_api_key( 'probe-key' );

			$request = $this->last_request();
			$headers = $request['args']['headers'];

			$this->assertSame( 'https://example.org', $headers['X-Rip-Site'] );
			$this->assertSame( \ReportedIP_Hive_API::api_user_agent(), $headers['User-Agent'] );
			$this->assertArrayNotHasKey(
				'user-agent',
				$request['args'],
				'The dead lowercase user-agent arg must stay removed — the header is the single source.'
			);
		}

		public function test_relay_request_sends_site_header_and_keeps_body_site_url() {
			$method = new \ReflectionMethod( \ReportedIP_Hive_API::class, 'relay_request' );
			$method->invoke(
				$this->api(),
				'relay-mail',
				array(
					'recipient' => 'user@example.org',
					'site_url'  => 'https://example.org',
				)
			);

			$request = $this->last_request();
			$headers = $request['args']['headers'];

			$this->assertSame( 'https://example.org', $headers['X-Rip-Site'] );
			$this->assertSame( \ReportedIP_Hive_API::api_user_agent(), $headers['User-Agent'] );
			$this->assertStringContainsString( '"site_url":"https:\/\/example.org"', (string) $request['args']['body'] );
		}

		public function test_hibp_check_never_carries_the_site_identity() {
			$GLOBALS['rip_telemetry_http_next'] = array(
				'response' => array( 'code' => 200 ),
				'body'     => "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n",
				'headers'  => array(),
			);

			$policy = \ReportedIP_Hive_Password_Strength::get_instance();
			$method = new \ReflectionMethod( \ReportedIP_Hive_Password_Strength::class, 'is_password_pwned' );
			$method->invoke( $policy, 'correct horse battery staple' );

			$request = $this->last_request();
			$args    = $request['args'];

			$this->assertStringContainsString( 'api.pwnedpasswords.com', (string) $request['url'] );

			$headers = isset( $args['headers'] ) ? (array) $args['headers'] : array();
			$this->assertArrayNotHasKey( 'X-Rip-Site', $headers, 'HIBP must never receive the site header.' );

			$ua = (string) ( $headers['User-Agent'] ?? ( $args['user-agent'] ?? '' ) );
			$this->assertStringNotContainsString( 'example.org', $ua, 'HIBP must never receive the site URL in its User-Agent.' );
		}
	}
}
