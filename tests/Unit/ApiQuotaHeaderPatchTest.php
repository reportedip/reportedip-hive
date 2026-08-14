<?php
/**
 * Unit tests for the header-driven quota patch and the post-report cache purge.
 *
 * Locks down two 2.1.41 behaviours on the API client: (1) the private
 * `patch_api_quota_from_headers()` helper only ever patches an EXISTING
 * `reportedip_hive_api_quota` transient from numeric X-RateLimit headers —
 * context 'check' moves the API-call counters, context 'report' the report
 * counters, "unlimited" is skipped, `reset_time` stays untouched and no
 * transient is conjured up when the cron has not created one yet; and (2) a
 * successful `report_ip()` drops the now-stale cached reputation for exactly
 * the reported IP via the real `ReportedIP_Hive_Cache::clear_ip_cache()`.
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
			$next = $GLOBALS['rip_quota_http_next'] ?? null;
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
	 * Exercises `patch_api_quota_from_headers()` via reflection plus the two
	 * live wirings (check success, report success) and the post-report
	 * reputation-cache purge with the real cache class.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class ApiQuotaHeaderPatchTest extends TestCase {

		private const QUOTA_KEY = 'reportedip_hive_api_quota';

		protected function set_up() {
			parent::set_up();

			if ( ! class_exists( 'ReportedIP_Hive_Cache' ) ) {
				require_once dirname( __DIR__, 2 ) . '/includes/class-cache.php';
			}

			$GLOBALS['wp_transients']       = array();
			$GLOBALS['wp_options']          = array(
				'reportedip_hive_api_key'        => 'test-key',
				'reportedip_hive_api_endpoint'   => 'https://example.test/v2/',
				'reportedip_hive_operation_mode' => 'community',
			);
			$GLOBALS['rip_quota_http_next'] = null;

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
		 * Invoke the private header-patch helper via reflection.
		 *
		 * @param mixed  $response Fake wp_remote_* response.
		 * @param string $context  'check' or 'report'.
		 */
		private function patch( $response, string $context ): void {
			$method = new \ReflectionMethod( \ReportedIP_Hive_API::class, 'patch_api_quota_from_headers' );
			$method->invoke( $this->api(), $response, $context );
		}

		/**
		 * Seed the quota transient the way the 6-hour cron would.
		 *
		 * @return array The seeded quota payload.
		 */
		private function seed_quota(): array {
			$quota = array(
				'remaining_api_calls' => 100,
				'daily_api_limit'     => 1000,
				'remaining_reports'   => 25,
				'daily_report_limit'  => 50,
				'daily_report_usage'  => 25,
				'reset_time'          => '2099-01-01T00:00:00+00:00',
				'user_role'           => 'reportedip_free',
			);
			\set_transient( self::QUOTA_KEY, $quota, 6 * HOUR_IN_SECONDS );
			return $quota;
		}

		private function quota(): array {
			return (array) \get_transient( self::QUOTA_KEY );
		}

		/**
		 * Build a fake response array in the shape the header stub reads.
		 *
		 * @param array $headers Response headers.
		 * @param int   $code    HTTP status code.
		 * @param mixed $body    Response body (encoded to JSON when array).
		 * @return array
		 */
		private function response( array $headers, int $code = 200, $body = '' ): array {
			return array(
				'response' => array( 'code' => $code ),
				'body'     => is_string( $body ) ? $body : json_encode( $body ),
				'headers'  => $headers,
			);
		}

		public function test_check_context_patches_only_the_api_call_counters() {
			$this->seed_quota();

			$this->patch(
				$this->response(
					array(
						'x-ratelimit-remaining' => '42',
						'x-ratelimit-limit'     => '900',
					)
				),
				'check'
			);

			$quota = $this->quota();
			$this->assertSame( 42, $quota['remaining_api_calls'] );
			$this->assertSame( 900, $quota['daily_api_limit'] );
			$this->assertSame( 25, $quota['remaining_reports'], 'A check response must not touch the report counters.' );
			$this->assertSame( 50, $quota['daily_report_limit'] );
			$this->assertSame( '2099-01-01T00:00:00+00:00', $quota['reset_time'], 'reset_time stays owned by the cron.' );
		}

		public function test_report_context_patches_only_the_report_counters() {
			$this->seed_quota();

			$this->patch(
				$this->response(
					array(
						'x-ratelimit-remaining' => '7',
						'x-ratelimit-limit'     => '40',
					)
				),
				'report'
			);

			$quota = $this->quota();
			$this->assertSame( 7, $quota['remaining_reports'] );
			$this->assertSame( 40, $quota['daily_report_limit'] );
			$this->assertSame( 100, $quota['remaining_api_calls'], 'A report response must not touch the API-call counters.' );
			$this->assertSame( 1000, $quota['daily_api_limit'] );
			$this->assertSame( '2099-01-01T00:00:00+00:00', $quota['reset_time'] );
		}

		public function test_non_numeric_remaining_header_leaves_the_quota_untouched() {
			$before = $this->seed_quota();

			$this->patch(
				$this->response(
					array(
						'x-ratelimit-remaining' => 'unlimited',
						'x-ratelimit-limit'     => '40',
					)
				),
				'report'
			);

			$this->assertSame( $before, $this->quota() );
		}

		public function test_non_numeric_limit_header_still_patches_remaining() {
			$this->seed_quota();

			$this->patch(
				$this->response(
					array(
						'x-ratelimit-remaining' => '42',
						'x-ratelimit-limit'     => 'unlimited',
					)
				),
				'check'
			);

			$quota = $this->quota();
			$this->assertSame( 42, $quota['remaining_api_calls'] );
			$this->assertSame( 1000, $quota['daily_api_limit'], 'A non-numeric limit header must be skipped.' );
		}

		public function test_missing_quota_transient_is_not_created() {
			$this->patch(
				$this->response(
					array(
						'x-ratelimit-remaining' => '42',
						'x-ratelimit-limit'     => '900',
					)
				),
				'check'
			);

			$this->assertArrayNotHasKey(
				self::QUOTA_KEY,
				$GLOBALS['wp_transients'],
				'The cron stays the sole owner of creating the quota snapshot.'
			);
		}

		public function test_check_success_response_patches_the_cached_quota() {
			$this->seed_quota();
			$GLOBALS['rip_quota_http_next'] = $this->response(
				array(
					'x-ratelimit-remaining' => '5',
					'x-ratelimit-limit'     => '150',
				),
				200,
				array( 'data' => array( 'abuseConfidencePercentage' => 10 ) )
			);

			$result = $this->api()->check_ip_reputation( '198.51.100.20' );

			$this->assertIsArray( $result );
			$quota = $this->quota();
			$this->assertSame( 5, $quota['remaining_api_calls'] );
			$this->assertSame( 150, $quota['daily_api_limit'] );
			$this->assertSame( 25, $quota['remaining_reports'] );
		}

		public function test_report_success_response_patches_the_cached_quota() {
			$this->seed_quota();
			$GLOBALS['rip_quota_http_next'] = $this->response(
				array(
					'x-ratelimit-remaining' => '9',
					'x-ratelimit-limit'     => '50',
				),
				200,
				array( 'data' => array( 'reportId' => 123 ) )
			);

			$result = $this->api()->report_ip( '198.51.100.7', '18', 'brute force' );

			$this->assertTrue( $result['success'] );
			$quota = $this->quota();
			$this->assertSame(
				9,
				$quota['remaining_reports'],
				'The header value must win over the optimistic local decrement.'
			);
			$this->assertSame( 50, $quota['daily_report_limit'] );
		}

		public function test_successful_report_clears_the_reputation_cache_for_that_ip() {
			$ip        = '198.51.100.7';
			$other     = '198.51.100.8';
			$key       = 'reportedip_' . 'reputation_' . hash( 'sha256', $ip );
			$other_key = 'reportedip_' . 'reputation_' . hash( 'sha256', $other );

			$cache = \ReportedIP_Hive_Cache::get_instance();
			$cache->set_reputation( $ip, array( 'abuseConfidencePercentage' => 80 ) );
			$cache->set_reputation( $other, array( 'abuseConfidencePercentage' => 10 ) );

			$this->assertArrayHasKey( $key, $GLOBALS['wp_transients'], 'Seeding must land on the documented key contract.' );
			$this->assertArrayHasKey( $other_key, $GLOBALS['wp_transients'] );

			$this->seed_quota();
			$GLOBALS['rip_quota_http_next'] = $this->response(
				array(),
				200,
				array( 'data' => array( 'reportId' => 123 ) )
			);

			$result = $this->api()->report_ip( $ip, '18', 'brute force' );

			$this->assertTrue( $result['success'] );
			$this->assertArrayNotHasKey(
				$key,
				$GLOBALS['wp_transients'],
				'A successful report must drop the stale cached reputation for that IP.'
			);
			$this->assertArrayHasKey(
				$other_key,
				$GLOBALS['wp_transients'],
				'The purge is scoped to the reported IP, not the whole cache.'
			);
		}
	}
}
