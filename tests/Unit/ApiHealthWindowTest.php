<?php
/**
 * Unit tests for the rolling API-health window and its poisoned-stats migration.
 *
 * Locks down the 2.1.18 fix that replaced the lifetime success-rate counter
 * with a recency-weighted window: the window caps and ages out entries, the
 * degraded-health log self-heals after recovery, and `migrate_to_v11()` only
 * resets installs whose lifetime counter is actually poisoned.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.18
 */

namespace {

	if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
		define( 'MINUTE_IN_SECONDS', 60 );
	}
	if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
		define( 'HOUR_IN_SECONDS', 3600 );
	}
	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}
	if ( ! defined( 'REPORTEDIP_HIVE_VERSION' ) ) {
		define( 'REPORTEDIP_HIVE_VERSION', '2.1.18-test' );
	}

	if ( ! class_exists( 'WP_Error' ) ) {
		class WP_Error {
			public $code;
			public $message;
			public function __construct( $code = '', $message = '' ) {
				$this->code    = $code;
				$this->message = $message;
			}
		}
	}
	if ( ! function_exists( 'is_wp_error' ) ) {
		function is_wp_error( $thing ) {
			return $thing instanceof \WP_Error;
		}
	}
	if ( ! function_exists( 'wp_remote_request' ) ) {
		function wp_remote_request( $url, $args = array() ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return new \WP_Error( 'no_network', 'Network calls disabled in unit tests' );
		}
	}
	if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
		function wp_remote_retrieve_body( $r ) {
			return is_array( $r ) ? ( $r['body'] ?? '' ) : '';
		}
	}
	if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
		function wp_remote_retrieve_response_code( $r ) {
			return is_array( $r ) ? ( $r['response']['code'] ?? 0 ) : 0;
		}
	}
	if ( ! function_exists( 'wp_remote_retrieve_header' ) ) {
		function wp_remote_retrieve_header( $r, $h ) {
			return is_array( $r ) ? ( $r['headers'][ $h ] ?? '' ) : '';
		}
	}
	if ( ! function_exists( 'esc_url_raw' ) ) {
		function esc_url_raw( $url ) {
			return is_string( $url ) ? trim( $url ) : '';
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-api-client.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Captures security events so degraded/self-heal behaviour is observable.
	 */
	class Spy_Logger {

		/**
		 * Event types that were logged.
		 *
		 * @var string[]
		 */
		public $events = array();

		public function log_security_event( $type, $source, $details, $severity ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			$this->events[] = $type;
		}

		public static function truncate( $value, $length ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $value;
		}
	}

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class ApiHealthWindowTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
		}

		private function client(): \ReportedIP_Hive_API {
			$client = ( new \ReflectionClass( \ReportedIP_Hive_API::class ) )->newInstanceWithoutConstructor();
			$logger = new \ReflectionProperty( \ReportedIP_Hive_API::class, 'logger' );
			$logger->setValue( $client, new Spy_Logger() );
			return $client;
		}

		private function spy( \ReportedIP_Hive_API $client ): Spy_Logger {
			$logger = new \ReflectionProperty( \ReportedIP_Hive_API::class, 'logger' );
			return $logger->getValue( $client );
		}

		private function push( \ReportedIP_Hive_API $client, array $stats, bool $success ): array {
			$method = new \ReflectionMethod( \ReportedIP_Hive_API::class, 'push_recent_call' );
			return $method->invoke( $client, $stats, $success );
		}

		private function track( \ReportedIP_Hive_API $client, bool $success, $error_type = null ): void {
			$method = new \ReflectionMethod( \ReportedIP_Hive_API::class, 'track_api_call' );
			$method->invoke( $client, $success, 100.0, $error_type, 'meta', '' );
		}

		public function test_window_caps_at_fifty_entries() {
			$client = $this->client();
			$stats  = array();
			for ( $i = 0; $i < 60; $i++ ) {
				$stats = $this->push( $client, $stats, true );
			}

			$this->assertCount( 50, $stats['recent'] );
			$this->assertSame( 50, $stats['recent_total'] );
			$this->assertSame( 100.0, $stats['recent_success_rate'] );
		}

		public function test_window_drops_entries_older_than_seven_days() {
			$client = $this->client();
			$stats  = array(
				'recent' => array(
					array(
						't'  => time() - ( 8 * DAY_IN_SECONDS ),
						'ok' => 1,
					),
					array(
						't'  => time() - 60,
						'ok' => 0,
					),
				),
			);

			$stats = $this->push( $client, $stats, true );

			$this->assertSame( 2, $stats['recent_total'] );
			$this->assertSame( 50.0, $stats['recent_success_rate'] );
		}

		public function test_recent_success_rate_reflects_mix() {
			$client = $this->client();
			$stats  = array();
			for ( $i = 0; $i < 9; $i++ ) {
				$stats = $this->push( $client, $stats, true );
			}
			$stats = $this->push( $client, $stats, false );

			$this->assertSame( 10, $stats['recent_total'] );
			$this->assertSame( 90.0, $stats['recent_success_rate'] );
		}

		public function test_sustained_failures_log_degraded() {
			$client = $this->client();
			for ( $i = 0; $i < 12; $i++ ) {
				$this->track( $client, false, 'http_503' );
			}

			$stats = \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_stats', array() );
			$this->assertSame( 0.0, $stats['recent_success_rate'] );
			$this->assertContains( 'api_health_degraded', $this->spy( $client )->events );
		}

		public function test_health_self_heals_after_recovery() {
			$client = $this->client();
			for ( $i = 0; $i < 12; $i++ ) {
				$this->track( $client, false, 'http_503' );
			}
			for ( $i = 0; $i < 50; $i++ ) {
				$this->track( $client, true );
			}

			$stats = \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_stats', array() );
			$this->assertSame( 100.0, $stats['recent_success_rate'] );

			delete_transient( 'reportedip_hive_health_warning_logged' );
			$this->spy( $client )->events = array();
			$this->track( $client, true );

			$this->assertNotContains( 'api_health_degraded', $this->spy( $client )->events );
		}

		public function test_migration_resets_poisoned_stats() {
			\ReportedIP_Hive_Option_Routing::set(
				'reportedip_hive_api_stats',
				array(
					'total_calls'  => 100,
					'failed_calls' => 92,
					'success_rate' => 8.12,
				)
			);

			$this->run_v11();

			$after = \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_stats', array() );
			$this->assertSame( 0, $after['total_calls'] );
			$this->assertSame( 0, $after['failed_calls'] );
			$this->assertSame( 100.0, $after['recent_success_rate'] );
			$this->assertSame( array(), $after['recent'] );
		}

		public function test_migration_leaves_healthy_stats_untouched() {
			\ReportedIP_Hive_Option_Routing::set(
				'reportedip_hive_api_stats',
				array(
					'total_calls'  => 100,
					'failed_calls' => 1,
					'success_rate' => 99.0,
				)
			);

			$this->run_v11();

			$after = \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_stats', array() );
			$this->assertSame( 100, $after['total_calls'] );
			$this->assertArrayNotHasKey( 'recent', $after );
		}

		public function test_migration_is_noop_on_empty_stats() {
			$this->run_v11();

			$after = \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_stats', '__unset__' );
			$this->assertSame( '__unset__', $after );
		}

		private function run_v11(): void {
			$method = new \ReflectionMethod( \ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v11' );
			$method->invoke( null );
		}
	}
}
