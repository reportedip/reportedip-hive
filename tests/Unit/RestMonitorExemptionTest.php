<?php
/**
 * Unit Tests for the REST monitor's logged-in exemption.
 *
 * Locks down the regression introduced in 1.2.0 where the global REST
 * rate-limit (60 / 5min by default) blocked admins out of their own
 * Block-Editor — the editor alone fires 50+ REST calls when an admin
 * opens a page (autosave, media library, taxonomy lookups, block
 * patterns, theme.json), instantly tripping the threshold.
 *
 * 1.2.2 hotfix: skip the gate entirely when `is_user_logged_in()` is
 * true. Authenticated REST traffic is not the threat model the sensor
 * exists for.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.2.2
 */

namespace {

	if ( ! function_exists( 'add_filter' ) ) {
		function add_filter( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'add_action' ) ) {
		function add_action( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $hook, $value, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $value;
		}
	}
	if ( ! function_exists( '__' ) ) {
		function __( $text, $domain = '' ) { return $text; } // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'is_user_logged_in' ) ) {
		function is_user_logged_in() {
			return ! empty( $GLOBALS['rip_test_logged_in'] );
		}
	}
	if ( ! function_exists( 'str_starts_with' ) ) {
		function str_starts_with( $haystack, $needle ) {
			return '' === $needle || 0 === strncmp( (string) $haystack, (string) $needle, strlen( (string) $needle ) );
		}
	}

	if ( ! class_exists( 'WP_Error' ) ) {
		class WP_Error {
			public $code;
			public $message;
			public function __construct( $code = '', $message = '' ) { $this->code = $code; $this->message = $message; }
			public function get_error_code() { return $this->code; }
		}
	}

	if ( ! class_exists( 'WP_REST_Request' ) ) {
		class WP_REST_Request {
			private $route;
			private $method;
			public function __construct( string $route = '/', string $method = 'GET' ) {
				$this->route  = $route;
				$this->method = $method;
			}
			public function get_route() { return $this->route; }
			public function get_method() { return $this->method; }
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-rest-monitor.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class RestMonitorExemptionTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options']        = array(
				'reportedip_hive_monitor_rest_api' => true,
			);
			$GLOBALS['rip_test_logged_in'] = false;
		}

		private function dispatch( string $route, string $method = 'GET' ) {
			$monitor = \ReportedIP_Hive_REST_Monitor::get_instance();
			$req     = new \WP_REST_Request( $route, $method );
			return $monitor->pre_dispatch( null, null, $req );
		}

		public function test_logged_in_user_skips_gate_even_on_sensitive_route() {
			$GLOBALS['rip_test_logged_in'] = true;
			$result                        = $this->dispatch( '/wp/v2/users?search=a' );
			$this->assertNull(
				$result,
				'Logged-in users must never hit the REST monitor — the Block Editor would lock admins out of their own backend otherwise.'
			);
		}

		public function test_logged_in_user_skips_gate_on_high_volume_route() {
			$GLOBALS['rip_test_logged_in'] = true;
			$result                        = $this->dispatch( '/wp/v2/posts/1/autosaves', 'POST' );
			$this->assertNull(
				$result,
				'Block Editor autosave must never be rate-limited for the logged-in author.'
			);
		}

		public function test_anonymous_request_still_passes_through_to_logic() {
			$GLOBALS['rip_test_logged_in'] = false;

			$existing = new \WP_Error( 'something_else', 'pre-existing error' );
			$monitor  = \ReportedIP_Hive_REST_Monitor::get_instance();
			$req      = new \WP_REST_Request( '/wp/v2/posts' );
			$result   = $monitor->pre_dispatch( $existing, null, $req );

			$this->assertSame(
				$existing,
				$result,
				'When a previous filter already returned a WP_Error, the REST monitor must keep it intact regardless of login state.'
			);
		}

		public function test_disabled_option_short_circuits_for_anyone() {
			$GLOBALS['wp_options']['reportedip_hive_monitor_rest_api'] = false;
			$GLOBALS['rip_test_logged_in']                              = false;

			$result = $this->dispatch( '/wp/v2/users' );
			$this->assertNull( $result, 'Disabled monitor must return early for anonymous users too.' );
		}
	}
}
