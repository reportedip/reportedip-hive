<?php
/**
 * Unit tests for the relay-quota caching, negative cache and throttle.
 *
 * Regression guard for the runaway `GET /relay-quota` polling: a cold or
 * error-returning install must not re-poll the service on every request.
 * Locks down that a failed call arms a cooldown so the next lookup short-
 * circuits, that the meta-bucket rate limit blocks the call outright, that an
 * HTTP 429 also seeds the global rate-limit reset, and that a success caches
 * the payload and clears the cooldown.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.16
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

	if ( ! function_exists( 'wp_remote_request' ) ) {
		function wp_remote_request( $url, $args = array() ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			$GLOBALS['__relay_http_calls'] = ( $GLOBALS['__relay_http_calls'] ?? 0 ) + 1;
			$next                          = $GLOBALS['__relay_http_next'] ?? null;
			return null === $next ? new \WP_Error( 'no_response', 'No response programmed' ) : $next;
		}
	}
	if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
		function wp_remote_retrieve_response_code( $r ) { return is_array( $r ) ? ( $r['response']['code'] ?? 0 ) : 0; }
	}
	if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
		function wp_remote_retrieve_body( $r ) { return is_array( $r ) ? ( $r['body'] ?? '' ) : ''; }
	}
	if ( ! function_exists( 'wp_remote_retrieve_header' ) ) {
		function wp_remote_retrieve_header( $r, $h ) { return is_array( $r ) ? ( $r['headers'][ $h ] ?? '' ) : ''; }
	}
	if ( ! function_exists( 'is_wp_error' ) ) {
		function is_wp_error( $thing ) { return $thing instanceof \WP_Error; }
	}
	if ( ! function_exists( 'get_bloginfo' ) ) {
		function get_bloginfo( $show = '' ) { return '6.9'; } // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'wp_json_encode' ) ) {
		function wp_json_encode( $data, $options = 0, $depth = 512 ) { return json_encode( $data, $options, $depth ); }
	}
	if ( ! function_exists( 'current_time' ) ) {
		function current_time( $type, $gmt = 0 ) { return 'mysql' === $type ? gmdate( 'Y-m-d H:i:s' ) : time(); } // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( '__' ) ) {
		function __( $text, $domain = '' ) { return $text; } // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'esc_url_raw' ) ) {
		function esc_url_raw( $url ) { return is_string( $url ) ? trim( $url ) : ''; }
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

	if ( ! class_exists( 'ReportedIP_Hive_Cache' ) ) {
		class ReportedIP_Hive_Cache {
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) {
					self::$instance = new self();
				}
				return self::$instance;
			}
			public function get_reputation( $ip ) { return false; } // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			public function set_reputation( $ip, $data, $is_negative_result = false ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
		class ReportedIP_Hive_Logger {
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) {
					self::$instance = new self();
				}
				return self::$instance;
			}
			public function log_security_event( ...$args ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			public static function truncate( $text, $len = 200 ) { return substr( (string) $text, 0, $len ); }
		}
	}

	if ( ! defined( 'REPORTEDIP_HIVE_VERSION' ) ) {
		define( 'REPORTEDIP_HIVE_VERSION', '2.0.26-test' );
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-api-client.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class RelayQuotaCacheTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();

			$GLOBALS['wp_transients']      = array();
			$GLOBALS['wp_options']         = array(
				'reportedip_hive_api_key'      => 'test-key',
				'reportedip_hive_api_endpoint' => 'https://example.test/v2/',
			);
			$GLOBALS['__relay_http_calls'] = 0;
			$GLOBALS['__relay_http_next']  = null;

			$prop = new \ReflectionProperty( '\ReportedIP_Hive_API', 'instance' );
			$prop->setValue( null, null );

			\ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		}

		private function api(): \ReportedIP_Hive_API {
			return \ReportedIP_Hive_API::get_instance();
		}

		/**
		 * Steer the tier read by the rate-limit resolver via the status transient.
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
			$GLOBALS['__relay_http_next'] = array(
				'response' => array( 'code' => $code ),
				'body'     => is_string( $body ) ? $body : json_encode( $body ),
				'headers'  => $headers,
			);
		}

		private function calls(): int {
			return (int) ( $GLOBALS['__relay_http_calls'] ?? 0 );
		}

		public function test_http_500_arms_cooldown_and_second_call_skips_http() {
			$this->pretend_tier( 'reportedip_professional' );
			$this->set_http( 500, array( 'error' => 'boom' ) );

			$first = $this->api()->get_relay_quota();
			$this->assertSame( 'http_500', $first['error'] );
			$this->assertSame( 1, $this->calls() );

			$second = $this->api()->get_relay_quota();
			$this->assertSame( 'client_backoff', $second['error'] );
			$this->assertSame( 1, $this->calls(), 'A cooldown must prevent a second outbound call.' );
		}

		public function test_wp_error_arms_cooldown() {
			$this->pretend_tier( 'reportedip_professional' );
			$GLOBALS['__relay_http_next'] = new \WP_Error( 'timeout', 'cURL timeout' );

			$first = $this->api()->get_relay_quota();
			$this->assertArrayHasKey( 'error', $first );
			$this->assertSame( 1, $this->calls() );

			$second = $this->api()->get_relay_quota();
			$this->assertSame( 'client_backoff', $second['error'] );
			$this->assertSame( 1, $this->calls() );
		}

		public function test_meta_rate_limit_blocks_call_without_http() {
			$this->pretend_tier( 'reportedip_professional' );
			$GLOBALS['wp_transients']['reportedip_hive_hourly_api_calls_meta'] = array(
				'value'   => 100,
				'expires' => time() + 3600,
			);

			$result = $this->api()->get_relay_quota();

			$this->assertSame( 'rate_limited', $result['error'] );
			$this->assertSame( 0, $this->calls(), 'An exhausted meta bucket must short-circuit before any HTTP call.' );
		}

		public function test_http_429_seeds_global_rate_limit_reset() {
			$this->pretend_tier( 'reportedip_professional' );
			$this->set_http( 429, array( 'code' => 'rate_limited' ), array( 'retry-after' => '120' ) );

			$result = $this->api()->get_relay_quota();

			$this->assertSame( 'http_429', $result['error'] );
			$reset = get_transient( 'reportedip_hive_rate_limit_reset' );
			$this->assertIsInt( $reset );
			$this->assertGreaterThan( time(), $reset, 'A 429 with Retry-After must seed the global rate-limit reset.' );
		}

		public function test_success_caches_payload_and_serves_from_cache() {
			$this->pretend_tier( 'reportedip_professional' );
			$this->set_http(
				200,
				array(
					'tier' => 'professional',
					'mail' => array(
						'used'  => 3,
						'limit' => 500,
					),
				)
			);

			$first = $this->api()->get_relay_quota();
			$this->assertSame( 'professional', $first['tier'] );
			$this->assertArrayHasKey( 'fetched_at', $first );
			$this->assertSame( 1, $this->calls() );

			$cached = get_transient( 'reportedip_hive_relay_quota' );
			$this->assertIsArray( $cached );

			$second = $this->api()->get_relay_quota();
			$this->assertSame( 'professional', $second['tier'] );
			$this->assertSame( 1, $this->calls(), 'A positive cache must serve the second call without HTTP.' );
		}

		/**
		 * Seed a realistic cached /relay-quota payload as the quota cron would.
		 */
		private function seed_quota_cache(): void {
			set_transient(
				'reportedip_hive_relay_quota',
				array(
					'tier'                => 'professional',
					'mail'                => array(
						'queued_total'   => 250,
						'limit'          => 500,
						'bundle_balance' => 556,
					),
					'sms'                 => array(
						'queued_total'   => 10,
						'limit'          => 25,
						'bundle_balance' => 31,
					),
					'mail_bundle_balance' => 556,
					'sms_bundle_balance'  => 31,
					'fetched_at'          => time() - 7200,
				),
				12 * HOUR_IN_SECONDS
			);
		}

		public function test_relay_mail_success_patches_quota_cache_instead_of_deleting() {
			$this->pretend_tier( 'reportedip_professional' );
			$this->seed_quota_cache();
			$this->set_http(
				200,
				array(
					'queue_id'        => 77,
					'remaining_quota' => array(
						'queued_total'   => 251,
						'limit'          => 500,
						'bundle_balance' => 555,
					),
				)
			);

			$result = $this->api()->relay_mail(
				array(
					'recipient' => 'user@example.test',
					'subject'   => 'Code',
					'body_text' => 'Body',
					'site_url'  => 'https://example.test',
				)
			);

			$this->assertTrue( $result['ok'] );

			$cached = get_transient( 'reportedip_hive_relay_quota' );
			$this->assertIsArray( $cached, 'A send with remaining_quota must keep the quota cache alive.' );
			$this->assertSame( 251, $cached['mail']['queued_total'] );
			$this->assertSame( 555, $cached['mail_bundle_balance'] );
			$this->assertSame( 10, $cached['sms']['queued_total'], 'The untouched channel must survive the patch.' );
			$this->assertGreaterThan( time() - 60, $cached['fetched_at'], 'The fetch timestamp must be renewed.' );
		}

		public function test_relay_sms_success_patches_sms_channel() {
			$this->pretend_tier( 'reportedip_professional' );
			$this->seed_quota_cache();
			$this->set_http(
				200,
				array(
					'queue_id'        => 78,
					'remaining_quota' => array(
						'queued_total'   => 11,
						'limit'          => 25,
						'bundle_balance' => 31,
					),
				)
			);

			$result = $this->api()->relay_sms(
				array(
					'recipient_phone' => '+491701234567',
					'message'         => 'Code 123456',
					'site_url'        => 'https://example.test',
				)
			);

			$this->assertTrue( $result['ok'] );

			$cached = get_transient( 'reportedip_hive_relay_quota' );
			$this->assertIsArray( $cached );
			$this->assertSame( 11, $cached['sms']['queued_total'] );
			$this->assertSame( 250, $cached['mail']['queued_total'], 'The untouched channel must survive the patch.' );
		}

		public function test_relay_send_without_remaining_quota_deletes_cache() {
			$this->pretend_tier( 'reportedip_professional' );
			$this->seed_quota_cache();
			$this->set_http( 200, array( 'queue_id' => 79 ) );

			$result = $this->api()->relay_mail(
				array(
					'recipient' => 'user@example.test',
					'site_url'  => 'https://example.test',
				)
			);

			$this->assertTrue( $result['ok'] );
			$this->assertFalse(
				get_transient( 'reportedip_hive_relay_quota' ),
				'Without fresh counters the stale cache must be invalidated as before.'
			);
		}

		public function test_relay_send_with_remaining_quota_but_no_cache_stays_empty() {
			$this->pretend_tier( 'reportedip_professional' );
			$this->set_http(
				200,
				array(
					'queue_id'        => 80,
					'remaining_quota' => array(
						'queued_total' => 1,
						'limit'        => 500,
					),
				)
			);

			$result = $this->api()->relay_mail(
				array(
					'recipient' => 'user@example.test',
					'site_url'  => 'https://example.test',
				)
			);

			$this->assertTrue( $result['ok'] );
			$this->assertFalse(
				get_transient( 'reportedip_hive_relay_quota' ),
				'A partial one-channel payload must not fabricate a full snapshot from nothing.'
			);
		}

		public function test_success_clears_a_stale_cooldown() {
			$this->pretend_tier( 'reportedip_professional' );
			set_transient(
				'reportedip_hive_relay_quota_cooldown',
				array(
					'until' => time() - 5,
					'code'  => 500,
				),
				HOUR_IN_SECONDS
			);
			$this->set_http( 200, array( 'tier' => 'professional' ) );

			$this->api()->get_relay_quota( true );

			$this->assertFalse(
				get_transient( 'reportedip_hive_relay_quota_cooldown' ),
				'A successful refresh must clear the negative cache.'
			);
		}
	}
}
