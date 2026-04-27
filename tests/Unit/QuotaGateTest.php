<?php
/**
 * Unit Tests for the API quota gate.
 *
 * Locks down ReportedIP_Hive_API::has_report_quota() against the
 * "unlimited tier reports stuck at remaining=-1" regression that
 * blocked queue draining for accounts with no daily report cap
 * (1.2.0 hotfix → 1.2.1). Service returns -1 for both
 * `daily_report_limit` and `remaining_reports` on unlimited tiers
 * (Enterprise / Honeypot); the gate must treat that as "yes, send".
 *
 * Tested via reflection — has_report_quota() is a public method on a
 * singleton whose construction touches Cache, Logger and Mode_Manager;
 * we instantiate with stubs.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.2.1
 */

namespace {

	if ( ! function_exists( 'wp_remote_request' ) ) {
		function wp_remote_request( $url, $args = array() ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return new \WP_Error( 'no_network', 'Network calls disabled in unit tests' );
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
	if ( ! function_exists( 'is_wp_error' ) ) {
		function is_wp_error( $thing ) { return $thing instanceof \WP_Error; }
	}
	if ( ! function_exists( 'set_transient' ) ) {
		function set_transient( $name, $value, $exp = 0 ) {
			global $wp_transients;
			$wp_transients[ $name ] = array( 'value' => $value, 'expires' => $exp > 0 ? time() + $exp : 0 );
			return true;
		}
	}
	if ( ! function_exists( 'delete_transient' ) ) {
		function delete_transient( $name ) {
			global $wp_transients;
			unset( $wp_transients[ $name ] );
			return true;
		}
	}
	if ( ! function_exists( 'esc_url_raw' ) ) {
		function esc_url_raw( $url ) { return is_string( $url ) ? trim( $url ) : ''; }
	}
	if ( ! function_exists( 'wp_json_encode' ) ) {
		function wp_json_encode( $data, $options = 0, $depth = 512 ) { return json_encode( $data, $options, $depth ); }
	}
	if ( ! function_exists( '__' ) ) {
		function __( $text, $domain = '' ) { return $text; } // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'wp_date' ) ) {
		function wp_date( $fmt, $ts = null ) { return gmdate( $fmt, $ts ?? time() ); }
	}
	if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
		define( 'HOUR_IN_SECONDS', 3600 );
	}
	if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
		define( 'MINUTE_IN_SECONDS', 60 );
	}
	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}

	if ( ! class_exists( 'WP_Error' ) ) {
		class WP_Error {
			public $code;
			public $message;
			public function __construct( $code = '', $message = '' ) { $this->code = $code; $this->message = $message; }
			public function get_error_code() { return $this->code; }
			public function get_error_message() { return $this->message; }
		}
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
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
		class ReportedIP_Hive_Mode_Manager {
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) { self::$instance = new self(); }
				return self::$instance;
			}
			public function can_use_api() { return true; }
			public function is_local_mode() { return false; }
			public function is_community_mode() { return true; }
		}
	}

	if ( ! defined( 'REPORTEDIP_HIVE_VERSION' ) ) {
		define( 'REPORTEDIP_HIVE_VERSION', '1.2.1-test' );
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-api-client.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class QuotaGateTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_transients'] = array();
			$GLOBALS['wp_options']    = array(
				'reportedip_hive_api_key'      => 'test-key',
				'reportedip_hive_api_endpoint' => 'https://example.test/v2/',
			);

			$prop = new \ReflectionProperty( '\ReportedIP_Hive_API', 'instance' );
			$prop->setAccessible( true );
			$prop->setValue( null, null );
		}

		private function api(): \ReportedIP_Hive_API {
			return \ReportedIP_Hive_API::get_instance();
		}

		private function set_quota( array $quota ): void {
			\set_transient( 'reportedip_hive_api_quota', $quota, 6 * HOUR_IN_SECONDS );
		}

		public function test_unlimited_tier_passes_gate() {
			$this->set_quota(
				array(
					'daily_report_limit' => -1,
					'remaining_reports'  => -1,
					'reset_time'         => '2099-01-01T00:00:00+00:00',
					'user_role'          => 'reportedip_enterprise',
				)
			);
			$this->assertTrue(
				$this->api()->has_report_quota(),
				'Unlimited tier (limit=-1) must NOT be treated as quota-exhausted.'
			);
		}

		public function test_zero_limit_blocks_gate() {
			$this->set_quota(
				array(
					'daily_report_limit' => 0,
					'remaining_reports'  => 0,
					'user_role'          => 'reportedip_free',
				)
			);
			$this->assertFalse(
				$this->api()->has_report_quota(),
				'A daily_report_limit of 0 means no report permission and must block.'
			);
		}

		public function test_finite_limit_with_remaining_passes() {
			$this->set_quota(
				array(
					'daily_report_limit' => 50,
					'remaining_reports'  => 17,
					'user_role'          => 'reportedip_free',
				)
			);
			$this->assertTrue(
				$this->api()->has_report_quota(),
				'Finite tier with reports left must pass.'
			);
		}

		public function test_finite_limit_exhausted_blocks() {
			$this->set_quota(
				array(
					'daily_report_limit' => 50,
					'remaining_reports'  => 0,
					'user_role'          => 'reportedip_free',
				)
			);
			$this->assertFalse(
				$this->api()->has_report_quota(),
				'Finite tier at zero remaining reports must block until reset.'
			);
		}

		public function test_no_cached_quota_passes_optimistically() {
			$this->assertTrue(
				$this->api()->has_report_quota(),
				'When no quota cache exists yet, the gate must allow the first call.'
			);
		}

		public function test_get_quota_status_unlimited_is_not_exhausted() {
			$this->set_quota(
				array(
					'daily_report_limit' => -1,
					'remaining_reports'  => -1,
					'reset_time'         => '2099-01-01T00:00:00+00:00',
					'user_role'          => 'reportedip_enterprise',
				)
			);
			$status = $this->api()->get_quota_status();
			$this->assertFalse( $status['exhausted'], 'Unlimited tier is never exhausted.' );
		}
	}
}
