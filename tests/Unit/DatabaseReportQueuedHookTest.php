<?php
/**
 * Tests for the `reportedip_hive_report_queued` hook in queue_api_report().
 *
 * The hook must fire exactly once per report that actually entered the API
 * queue — after the public-IP drop, the cooldown check and the duplicate
 * check have all passed and the INSERT succeeded — and never for suppressed
 * duplicates. Exercised behaviourally against a recording `$wpdb` double
 * (the TimezoneConsistencyTest idiom) whose get_var() returns are sequenced
 * per test to steer the dedup path. The tests run in separate processes so
 * the main-class stand-in below (needed for the `is_public_ip()` guard) never
 * collides with the stand-ins other test files declare.
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

	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}

	if ( ! class_exists( 'ReportedIP_Hive' ) ) {
		/**
		 * Minimal stand-in for the main plugin class, which cannot be loaded in
		 * the unit harness. Superset of the methods other unit-test stand-ins
		 * declare so file load order can never change behaviour.
		 */
		class ReportedIP_Hive {

			/**
			 * Fixed client IP, mirroring the CategoryMappingTest stand-in.
			 *
			 * @return string
			 */
			public static function get_client_ip() {
				return '127.0.0.1';
			}

			/**
			 * Fixed comment payload, mirroring the CategoryMappingTest stand-in.
			 *
			 * @param mixed $report Raw report payload.
			 * @return string
			 */
			public static function sanitize_for_api_report( $report ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return 'test';
			}

			/**
			 * Loopback addresses count as the server's own.
			 *
			 * @param string $ip Candidate address.
			 * @return bool
			 */
			public static function is_own_server_ip( $ip ) {
				return in_array( (string) $ip, array( '127.0.0.1', '::1' ), true );
			}

			/**
			 * Same private/reserved-range rejection as the production helper.
			 *
			 * @param string $ip Candidate address.
			 * @return bool
			 */
			public static function is_public_ip( $ip ) {
				return false !== filter_var( (string) $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
			}
		}
	}

	if ( ! class_exists( 'Test_RQ_WPDB_Stub' ) ) {
		/**
		 * A `$wpdb` double that records prepares and inserts and serves
		 * pre-sequenced get_var() results so each test steers the dedup path.
		 */
		class Test_RQ_WPDB_Stub {

			/**
			 * Table prefix.
			 *
			 * @var string
			 */
			public $prefix = 'wp_';

			/**
			 * Network-wide table prefix.
			 *
			 * @var string
			 */
			public $base_prefix = 'wp_';

			/**
			 * Raw SQL passed to prepare().
			 *
			 * @var array<int, string>
			 */
			public $prepares = array();

			/**
			 * Every insert() call as {table, data}.
			 *
			 * @var array<int, array{table:string, data:array}>
			 */
			public $inserts = array();

			/**
			 * Queued get_var() return values, consumed front to back.
			 *
			 * @var array<int, int>
			 */
			public $get_var_returns = array();

			/**
			 * Record the SQL and return it unchanged.
			 *
			 * @param string $sql     SQL with placeholders.
			 * @param mixed  ...$args Placeholder values.
			 * @return string
			 */
			public function prepare( $sql, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				$this->prepares[] = $sql;
				return $sql;
			}

			/**
			 * Serve the next sequenced value, defaulting to 0.
			 *
			 * @param string|null $sql Ignored.
			 * @return int
			 */
			public function get_var( $sql = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				if ( array() === $this->get_var_returns ) {
					return 0;
				}
				return array_shift( $this->get_var_returns );
			}

			/**
			 * Record the write and report success.
			 *
			 * @param string     $table  Table name.
			 * @param array      $data   Column data.
			 * @param array|null $format Column formats.
			 * @return int
			 */
			public function insert( $table, $data, $format = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				$this->inserts[] = array(
					'table' => $table,
					'data'  => $data,
				);
				return 1;
			}
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class DatabaseReportQueuedHookTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';

			$GLOBALS['wpdb']          = new \Test_RQ_WPDB_Stub();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
			$GLOBALS['wp_actions']    = array();
		}

		/**
		 * Register a recording listener on the report-queued hook.
		 *
		 * @param array $captured Reference bucket the listener appends to.
		 * @return void
		 */
		private function capture_hook( array &$captured ): void {
			\add_action(
				'reportedip_hive_report_queued',
				static function ( $ip_address, $categories, $report_type ) use ( &$captured ) {
					$captured[] = array( $ip_address, $categories, $report_type );
				},
				10,
				3
			);
		}

		public function test_hook_fires_once_after_a_successful_insert() {
			$captured = array();
			$this->capture_hook( $captured );
			$GLOBALS['wpdb']->get_var_returns = array( 0, 0 );

			$db     = new \ReportedIP_Hive_Database();
			$result = $db->queue_api_report( '203.0.113.5', array( 18, 21 ), 'unit test report', 'negative', 'high' );

			$this->assertSame( 1, $result, 'A clean queue path must report the successful insert' );
			$this->assertCount( 1, $GLOBALS['wpdb']->inserts, 'Exactly one queue row must be written' );
			$this->assertSame( '18,21', $GLOBALS['wpdb']->inserts[0]['data']['category_ids'], 'Category IDs must be normalized to a comma-separated string' );
			$this->assertCount( 1, $captured, 'The hook must fire exactly once per queued report' );
			$this->assertSame( array( '203.0.113.5', '18,21', 'negative' ), $captured[0], 'Listeners must receive the IP, normalized categories and report type' );
		}

		public function test_hook_stays_silent_on_the_dedup_path() {
			$captured = array();
			$this->capture_hook( $captured );
			$GLOBALS['wpdb']->get_var_returns = array( 0, 1 );

			$db     = new \ReportedIP_Hive_Database();
			$result = $db->queue_api_report( '203.0.113.6', '18', 'duplicate report' );

			$this->assertFalse( $result, 'A pending duplicate must suppress the queue write' );
			$this->assertSame( array(), $GLOBALS['wpdb']->inserts, 'No queue row may be written on the dedup path' );
			$this->assertSame( array(), $captured, 'The hook must never fire for suppressed duplicates' );
		}

		public function test_hook_stays_silent_inside_the_cooldown_window() {
			$captured = array();
			$this->capture_hook( $captured );
			$GLOBALS['wpdb']->get_var_returns = array( 1 );

			$db     = new \ReportedIP_Hive_Database();
			$result = $db->queue_api_report( '203.0.113.6', '18', 'recently reported' );

			$this->assertFalse( $result, 'A recently completed report must suppress the queue write' );
			$this->assertSame( array(), $GLOBALS['wpdb']->inserts );
			$this->assertSame( array(), $captured, 'The hook must never fire inside the report cooldown' );
		}

		public function test_non_public_ips_never_reach_the_queue_or_the_hook() {
			$this->assertTrue(
				method_exists( 'ReportedIP_Hive', 'is_public_ip' ),
				'The main-class stand-in must carry is_public_ip() for the guard to be exercised'
			);

			$captured = array();
			$this->capture_hook( $captured );

			$db     = new \ReportedIP_Hive_Database();
			$result = $db->queue_api_report( '192.168.1.1', array( 18 ), 'private address' );

			$this->assertFalse( $result, 'A non-public address must be dropped before it reaches the queue' );
			$this->assertSame( array(), $GLOBALS['wpdb']->prepares, 'The guard must fire before any query runs' );
			$this->assertSame( array(), $GLOBALS['wpdb']->inserts );
			$this->assertSame( array(), $captured, 'The hook must never fire for dropped addresses' );
		}
	}
}
