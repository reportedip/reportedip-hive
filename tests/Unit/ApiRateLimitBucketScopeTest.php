<?php
/**
 * Unit tests for the bucket-scoped server-side API rate-limit back-off.
 *
 * Locks down the 2.1.41 change that split the single global 429 back-off
 * transient into per-bucket transients: a server rate limit answered on the
 * report endpoint must no longer pause reputation lookups (and vice versa),
 * while the legacy global transient keeps pausing everything and the
 * null-bucket probe reports a limit in ANY bucket. Also verifies the two
 * call sites: `check_ip_reputation()` scopes its 429 to 'reputation' and
 * `report_ip()` scopes its 429 to 'submission'.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
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
		define( 'REPORTEDIP_HIVE_VERSION', '2.1.41-test' );
	}

	if ( ! class_exists( 'WP_Error' ) ) {
		class WP_Error {
			public $code;
			public $message;
			public function __construct( $code = '', $message = '' ) {
				$this->code    = $code;
				$this->message = $message;
			}
			public function get_error_code() { return $this->code; }
			public function get_error_message() { return $this->message; }
		}
	}

	if ( ! function_exists( 'is_wp_error' ) ) {
		function is_wp_error( $thing ) { return $thing instanceof \WP_Error; }
	}
	if ( ! function_exists( 'wp_remote_request' ) ) {
		function wp_remote_request( $url, $args = array() ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			$next = $GLOBALS['rip_bucket_http_next'] ?? null;
			return null === $next ? new \WP_Error( 'no_network', 'Network calls disabled in unit tests' ) : $next;
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
	if ( ! function_exists( 'esc_url_raw' ) ) {
		function esc_url_raw( $url ) { return is_string( $url ) ? trim( $url ) : ''; }
	}

	if ( ! class_exists( 'ReportedIP_Hive_Cache' ) ) {
		class ReportedIP_Hive_Cache {
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) { self::$instance = new self(); }
				return self::$instance;
			}
			public function get_reputation( $ip ) { return false; } // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			public function set_reputation( $ip, $data, $is_negative_result = false ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			public function clear_ip_cache( $ip ) { return true; } // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			public function get_cache_statistics() { return array(); }
			public function estimate_monthly_savings() { return array(); }
		}
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
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Exercises `set_rate_limited()` / `is_rate_limited()` bucket scoping and
	 * the 429 handling in `check_ip_reputation()` / `report_ip()`.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class ApiRateLimitBucketScopeTest extends TestCase {

		private const GLOBAL_KEY     = 'reportedip_hive_rate_limit_reset';
		private const REPUTATION_KEY = 'reportedip_hive_rate_limit_reset_reputation';
		private const SUBMISSION_KEY = 'reportedip_hive_rate_limit_reset_submission';
		private const META_KEY       = 'reportedip_hive_rate_limit_reset_meta';

		protected function set_up() {
			parent::set_up();

			$GLOBALS['wp_transients']        = array();
			$GLOBALS['wp_options']           = array(
				'reportedip_hive_api_key'        => 'test-key',
				'reportedip_hive_api_endpoint'   => 'https://example.test/v2/',
				'reportedip_hive_operation_mode' => 'community',
			);
			$GLOBALS['rip_bucket_http_next'] = null;

			$prop = new \ReflectionProperty( '\ReportedIP_Hive_API', 'instance' );
			$prop->setValue( null, null );

			$mm  = \ReportedIP_Hive_Mode_Manager::get_instance();
			$ref = new \ReflectionProperty( $mm, 'cached_mode' );
			$ref->setValue( $mm, null );
			$mm->flush_cached_tier();
		}

		private function api(): \ReportedIP_Hive_API {
			return \ReportedIP_Hive_API::get_instance();
		}

		/**
		 * Steer the tier read by the rate-limit resolver via the status transient.
		 *
		 * @param string $role Upstream userRole value.
		 */
		private function pretend_tier( string $role ): void {
			$GLOBALS['wp_transients']['reportedip_hive_api_status'] = array(
				'value'   => array( 'userRole' => $role ),
				'expires' => time() + 600,
			);
			\ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		}

		/**
		 * Programme the next HTTP response the stubbed transport returns.
		 *
		 * @param int   $code    HTTP status code.
		 * @param mixed $body    Response body (encoded to JSON when array).
		 * @param array $headers Optional response headers.
		 */
		private function set_http( int $code, $body = array(), array $headers = array() ): void {
			$GLOBALS['rip_bucket_http_next'] = array(
				'response' => array( 'code' => $code ),
				'body'     => is_string( $body ) ? $body : json_encode( $body ),
				'headers'  => $headers,
			);
		}

		public function test_set_rate_limited_without_bucket_writes_the_global_transient() {
			$reset = time() + 600;
			$this->api()->set_rate_limited( $reset );

			$this->assertSame( $reset, \get_transient( self::GLOBAL_KEY ) );
			$this->assertArrayNotHasKey( self::REPUTATION_KEY, $GLOBALS['wp_transients'] );
			$this->assertArrayNotHasKey( self::SUBMISSION_KEY, $GLOBALS['wp_transients'] );
			$this->assertArrayNotHasKey( self::META_KEY, $GLOBALS['wp_transients'] );
		}

		public function test_set_rate_limited_with_invalid_bucket_falls_back_to_the_global_transient() {
			$reset = time() + 600;
			$this->api()->set_rate_limited( $reset, 'galactic' );

			$this->assertSame( $reset, \get_transient( self::GLOBAL_KEY ) );
			$this->assertArrayNotHasKey( 'reportedip_hive_rate_limit_reset_galactic', $GLOBALS['wp_transients'] );
		}

		public function test_set_rate_limited_with_valid_bucket_writes_only_the_scoped_transient() {
			$reset = time() + 600;
			$this->api()->set_rate_limited( $reset, 'reputation' );

			$this->assertSame( $reset, \get_transient( self::REPUTATION_KEY ) );
			$this->assertArrayNotHasKey( self::GLOBAL_KEY, $GLOBALS['wp_transients'] );
			$this->assertArrayNotHasKey( self::SUBMISSION_KEY, $GLOBALS['wp_transients'] );
		}

		public function test_global_reset_still_pauses_every_bucket() {
			$this->api()->set_rate_limited( time() + 600 );

			$this->assertTrue( $this->api()->is_rate_limited( 'reputation' ) );
			$this->assertTrue( $this->api()->is_rate_limited( 'submission' ) );
			$this->assertTrue( $this->api()->is_rate_limited( 'meta' ) );
			$this->assertTrue( $this->api()->is_rate_limited( null ) );
		}

		public function test_submission_server_limit_does_not_pause_reputation() {
			$this->api()->set_rate_limited( time() + 600, 'submission' );

			$this->assertTrue( $this->api()->is_rate_limited( 'submission' ) );
			$this->assertFalse(
				$this->api()->is_rate_limited( 'reputation' ),
				'A server rate limit on the report endpoint must not pause reputation lookups.'
			);
			$this->assertFalse( $this->api()->is_rate_limited( 'meta' ) );
			$this->assertTrue(
				$this->api()->is_rate_limited( null ),
				'The null-bucket probe must report a limit in ANY bucket.'
			);
		}

		public function test_reputation_server_limit_does_not_pause_submission() {
			$this->api()->set_rate_limited( time() + 600, 'reputation' );

			$this->assertTrue( $this->api()->is_rate_limited( 'reputation' ) );
			$this->assertFalse( $this->api()->is_rate_limited( 'submission' ) );
			$this->assertTrue( $this->api()->is_rate_limited( null ) );
		}

		public function test_null_bucket_reflects_a_local_limit_in_any_bucket() {
			$this->pretend_tier( 'reportedip_free' );
			\set_transient( 'reportedip_hive_hourly_api_calls_reputation', 150, HOUR_IN_SECONDS );

			$this->assertTrue( $this->api()->is_rate_limited( 'reputation' ) );
			$this->assertFalse( $this->api()->is_rate_limited( 'submission' ) );
			$this->assertTrue(
				$this->api()->is_rate_limited( null ),
				'A locally exhausted bucket must surface through the null-bucket probe.'
			);
		}

		public function test_check_ip_reputation_429_scopes_the_backoff_to_the_reputation_bucket() {
			$before = time();
			$this->set_http( 429, array(), array( 'retry-after' => '120' ) );

			$this->assertFalse( $this->api()->check_ip_reputation( '203.0.113.9' ) );

			$reset = \get_transient( self::REPUTATION_KEY );
			$this->assertIsInt( $reset );
			$this->assertGreaterThanOrEqual( $before + 120, $reset );
			$this->assertLessThanOrEqual( time() + 120, $reset );
			$this->assertArrayNotHasKey( self::GLOBAL_KEY, $GLOBALS['wp_transients'] );
			$this->assertArrayNotHasKey( self::SUBMISSION_KEY, $GLOBALS['wp_transients'] );
			$this->assertFalse(
				$this->api()->is_rate_limited( 'submission' ),
				'A reputation 429 must leave the report path free to submit.'
			);
		}

		public function test_report_ip_429_scopes_the_backoff_to_the_submission_bucket() {
			$before = time();
			$this->set_http( 429, array(), array( 'retry-after' => '90' ) );

			$result = $this->api()->report_ip( '203.0.113.9', '18', 'brute force' );

			$this->assertFalse( $result['success'] );
			$reset = \get_transient( self::SUBMISSION_KEY );
			$this->assertIsInt( $reset );
			$this->assertGreaterThanOrEqual( $before + 90, $reset );
			$this->assertLessThanOrEqual( time() + 90, $reset );
			$this->assertArrayNotHasKey( self::GLOBAL_KEY, $GLOBALS['wp_transients'] );
			$this->assertArrayNotHasKey( self::REPUTATION_KEY, $GLOBALS['wp_transients'] );
			$this->assertTrue( $this->api()->is_rate_limited( 'submission' ) );
			$this->assertFalse(
				$this->api()->is_rate_limited( 'reputation' ),
				'A submission 429 must not make is_rate_limited( reputation ) true.'
			);
		}

		public function test_report_ip_429_without_retry_after_defaults_to_one_hour() {
			$before = time();
			$this->set_http( 429 );

			$this->api()->report_ip( '203.0.113.9', '18', 'brute force' );

			$reset = \get_transient( self::SUBMISSION_KEY );
			$this->assertIsInt( $reset );
			$this->assertGreaterThanOrEqual( $before + 3600, $reset );
			$this->assertLessThanOrEqual( time() + 3600, $reset );
		}
	}
}
