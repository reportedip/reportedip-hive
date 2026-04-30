<?php
/**
 * Unit Tests for the cross-username Password-Spray bucket.
 *
 * Targets ReportedIP_Hive_Security_Monitor::record_username_for_spray_detection()
 * via reflection. The bucket is transient-backed and stores hashed usernames
 * with timestamps — these tests confirm:
 *
 *  - distinct usernames accumulate;
 *  - duplicate usernames do not inflate the count;
 *  - entries older than the configured timeframe are pruned;
 *  - empty usernames are ignored.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.2.0
 */

namespace {

	if ( ! function_exists( 'wp_salt' ) ) {
		function wp_salt() {
			return 'spray-test-salt';
		}
	}
	if ( ! function_exists( 'wp_unslash' ) ) {
		function wp_unslash( $value ) {
			return is_string( $value ) ? stripslashes( $value ) : $value;
		}
	}
	if ( ! function_exists( 'sanitize_text_field' ) ) {
		function sanitize_text_field( $str ) {
			return is_string( $str ) ? trim( $str ) : '';
		}
	}
	if ( ! function_exists( 'wp_json_encode' ) ) {
		function wp_json_encode( $data, $options = 0, $depth = 512 ) {
			return json_encode( $data, $options, $depth );
		}
	}
	if ( ! function_exists( 'current_time' ) ) {
		function current_time( $type = 'mysql' ) {
			return $type === 'timestamp' ? time() : gmdate( 'Y-m-d H:i:s' );
		}
	}
	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $hook, $value, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $value;
		}
	}
	if ( ! function_exists( 'add_action' ) ) {
		function add_action( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'add_filter' ) ) {
		function add_filter( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
		define( 'MINUTE_IN_SECONDS', 60 );
	}
	if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
		define( 'HOUR_IN_SECONDS', 3600 );
	}
	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}
	if ( ! defined( 'REPORTEDIP_USER_AGENT_MAX_LENGTH' ) ) {
		define( 'REPORTEDIP_USER_AGENT_MAX_LENGTH', 50 );
	}

	if ( ! class_exists( 'ReportedIP_Hive_Database' ) ) {
		class ReportedIP_Hive_Database {
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) {
					self::$instance = new self();
				}
				return self::$instance;
			}
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_API' ) ) {
		class ReportedIP_Hive_API {
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) {
					self::$instance = new self();
				}
				return self::$instance;
			}
			public function is_configured() {
				return false;
			}
			public function get_categories() {
				return array();
			}
			public function can_use_api() {
				return false;
			}
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
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
		class ReportedIP_Hive_Mode_Manager {
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) {
					self::$instance = new self();
				}
				return self::$instance;
			}
			public function is_local_mode() {
				return true;
			}
			public function is_community_mode() {
				return false;
			}
			public function can_use_api() {
				return false;
			}
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReflectionClass;
	use ReportedIP\Hive\Tests\TestCase;

	class PasswordSprayTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options']    = array(
				'reportedip_hive_password_spray_threshold' => 5,
				'reportedip_hive_password_spray_timeframe' => 10,
			);
			$GLOBALS['wp_transients'] = array();
		}

		private function call_record( string $ip, string $username ): void {
			$mon        = new \ReportedIP_Hive_Security_Monitor();
			$reflection = new ReflectionClass( $mon );
			$method     = $reflection->getMethod( 'record_username_for_spray_detection' );
			$method->invoke( $mon, $ip, $username );
		}

		private function bucket_for( string $ip ): array {
			$bucket = \get_transient( 'rip_spray_' . md5( $ip ) );
			return is_array( $bucket ) ? $bucket : array();
		}

		public function test_distinct_usernames_accumulate_in_bucket() {
			$ip = '203.0.113.1';
			foreach ( array( 'alice', 'bob', 'charlie', 'dave', 'eve' ) as $u ) {
				$this->call_record( $ip, $u );
			}
			$this->assertCount( 5, $this->bucket_for( $ip ), 'Five distinct usernames should produce five hash entries' );
		}

		public function test_duplicate_username_does_not_inflate_count() {
			$ip = '203.0.113.2';
			foreach ( array( 'alice', 'alice', 'alice', 'alice', 'bob' ) as $u ) {
				$this->call_record( $ip, $u );
			}
			$this->assertCount(
				2,
				$this->bucket_for( $ip ),
				'Duplicate usernames must collapse to one bucket entry per username'
			);
		}

		public function test_empty_username_is_ignored() {
			$ip = '203.0.113.3';
			$this->call_record( $ip, '' );
			$this->assertCount( 0, $this->bucket_for( $ip ), 'Empty username must not create a bucket entry' );
		}

		public function test_old_entries_are_pruned_inside_record() {
			$ip = '203.0.113.4';

			$old_hash                                                = substr( hash( 'sha256', 'olduser' . \wp_salt() ), 0, 16 );
			$bucket_key                                              = 'rip_spray_' . md5( $ip );
			$GLOBALS['wp_transients'][ $bucket_key ]                 = array(
				'value'   => array( $old_hash => time() - ( 30 * 60 ) ),
				'expires' => 0,
			);

			$this->call_record( $ip, 'fresh' );

			$bucket = $this->bucket_for( $ip );
			$this->assertCount(
				1,
				$bucket,
				'Old hash older than the spray timeframe must be pruned in record_username_for_spray_detection()'
			);
			$this->assertArrayNotHasKey( $old_hash, $bucket, 'Pruned hash must be gone from the bucket' );
		}

		public function test_username_is_case_insensitive() {
			$ip = '203.0.113.5';
			$this->call_record( $ip, 'Alice' );
			$this->call_record( $ip, 'alice' );
			$this->call_record( $ip, 'ALICE' );
			$this->assertCount(
				1,
				$this->bucket_for( $ip ),
				'Lowercased username hash must collide so case-only differences do not inflate the count'
			);
		}
	}
}
