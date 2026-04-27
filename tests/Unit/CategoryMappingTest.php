<?php
/**
 * Unit Tests for Security-Monitor category-id mapping.
 *
 * Validates that every sensor that ships with the plugin (incl. the 1.2.0
 * additions: user_enumeration / rest_abuse / app_password_abuse /
 * password_spray / scan_404 / wc_login_failed / geo_anomaly) has a
 * category-id mapping, that the IDs are integers, and that the
 * `reportedip_hive_event_category_map` filter is honoured.
 *
 * Tested without a database — we instantiate the security monitor with
 * stubbed singleton dependencies (Database, API, Logger, Mode_Manager).
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

	if ( ! function_exists( 'wp_json_encode' ) ) {
		function wp_json_encode( $data, $options = 0, $depth = 512 ) {
			return json_encode( $data, $options, $depth );
		}
	}
	if ( ! function_exists( 'wp_unslash' ) ) {
		function wp_unslash( $value ) {
			return is_string( $value ) ? stripslashes( $value ) : $value;
		}
	}
	if ( ! function_exists( 'sanitize_text_field' ) ) {
		function sanitize_text_field( $str ) {
			$str = is_string( $str ) ? $str : '';
			return trim( preg_replace( '/[\x00-\x1F\x7F]+/', '', $str ) );
		}
	}
	if ( ! function_exists( 'wp_salt' ) ) {
		function wp_salt() {
			return 'test-salt';
		}
	}
	if ( ! function_exists( 'current_time' ) ) {
		function current_time( $type = 'mysql' ) {
			return $type === 'timestamp' ? time() : gmdate( 'Y-m-d H:i:s' );
		}
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

	$GLOBALS['rip_filters_test_categories'] = array();

	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $hook, $value, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			if ( ! empty( $GLOBALS['rip_filters_test_categories'][ $hook ] ) ) {
				foreach ( $GLOBALS['rip_filters_test_categories'][ $hook ] as $cb ) {
					$value = call_user_func( $cb, $value, ...$args );
				}
			}
			return $value;
		}
	}
	if ( ! function_exists( 'add_filter' ) ) {
		function add_filter( $hook, $cb, $priority = 10, $args = 1 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			$GLOBALS['rip_filters_test_categories'][ $hook ][] = $cb;
		}
	}
	if ( ! function_exists( 'add_action' ) ) {
		function add_action( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}

	/*
	 * Minimal in-memory stand-ins for the singletons the security monitor
	 * pulls in via get_instance() — we only need them to exist and not blow
	 * up; the tests below never call methods on them.
	 */
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
		if ( ! function_exists( 'esc_url_raw' ) ) {
			function esc_url_raw( $url ) { return is_string( $url ) ? trim( $url ) : ''; }
		}
		if ( ! defined( 'REPORTEDIP_HIVE_VERSION' ) ) {
			define( 'REPORTEDIP_HIVE_VERSION', '1.2.1-test' );
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
		require_once dirname( __DIR__, 2 ) . '/includes/class-api-client.php';
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
	if ( ! class_exists( 'ReportedIP_Hive' ) ) {
		class ReportedIP_Hive {
			public static function get_client_ip() {
				return '127.0.0.1';
			}
			public static function sanitize_for_api_report( $r ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return 'test';
			}
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class CategoryMappingTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['rip_filters_test_categories'] = array();
		}

		private function monitor(): \ReportedIP_Hive_Security_Monitor {
			return new \ReportedIP_Hive_Security_Monitor();
		}

		public function test_legacy_event_types_are_mapped() {
			$mon = $this->monitor();
			$this->assertSame( array( 18 ), $mon->get_category_ids_for_event( 'failed_login' ) );
			$this->assertSame( array( 12 ), $mon->get_category_ids_for_event( 'comment_spam' ) );
			$this->assertSame( array( 21 ), $mon->get_category_ids_for_event( 'xmlrpc_abuse' ) );
		}

		public function test_new_sensors_have_mappings() {
			$mon = $this->monitor();
			$expected = array(
				'user_enumeration'   => array( 55 ),
				'rest_abuse'         => array( 34 ),
				'app_password_abuse' => array( 31, 18 ),
				'password_spray'     => array( 31, 18 ),
				'scan_404'           => array( 57, 56, 58 ),
				'wc_login_failed'    => array( 31 ),
				'geo_anomaly'        => array( 15 ),
			);
			foreach ( $expected as $event => $ids ) {
				$this->assertSame(
					$ids,
					$mon->get_category_ids_for_event( $event ),
					"Mapping for $event must match the documented IDs"
				);
			}
		}

		public function test_unknown_event_falls_back_to_hacking_category() {
			$mon = $this->monitor();
			$this->assertSame(
				array( 15 ),
				$mon->get_category_ids_for_event( 'totally_unknown_event' ),
				'Fallback must be category 15 (Hacking) so a missed mapping still produces a report'
			);
		}

		public function test_filter_can_remap_event_categories() {
			\add_filter(
				'reportedip_hive_event_category_map',
				static function ( $map ) {
					$map['user_enumeration'] = array( 99 );
					return $map;
				}
			);

			$mon = $this->monitor();
			$this->assertSame(
				array( 99 ),
				$mon->get_category_ids_for_event( 'user_enumeration' ),
				'Filter override must take effect on the returned IDs'
			);
		}

		public function test_all_returned_ids_are_integers() {
			$mon    = $this->monitor();
			$events = array(
				'failed_login',
				'comment_spam',
				'xmlrpc_abuse',
				'admin_scanning',
				'reputation_threat',
				'user_enumeration',
				'rest_abuse',
				'app_password_abuse',
				'password_spray',
				'scan_404',
				'wc_login_failed',
				'geo_anomaly',
			);
			foreach ( $events as $event ) {
				$ids = $mon->get_category_ids_for_event( $event );
				$this->assertNotEmpty( $ids, "Event $event must map to at least one category" );
				foreach ( $ids as $id ) {
					$this->assertIsInt( $id, "Event $event must map to integer IDs only — got " . var_export( $id, true ) );
					$this->assertGreaterThan( 0, $id, "Category id for $event must be > 0" );
				}
			}
		}
	}
}
