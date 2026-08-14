<?php
/**
 * Unit tests for the atomic track_attempt() upsert.
 *
 * Locks down the 2.1.41 rewrite of `ReportedIP_Hive_Database::track_attempt()`
 * from a read-then-update pair (which lost counts under parallel failed-login
 * bursts) to a single `INSERT ... ON DUPLICATE KEY UPDATE` on the schema-v15
 * UNIQUE (ip_address, attempt_type) key. The IF() conditions re-implement the
 * one-hour idle window by reading the OLD `last_attempt`, so `last_attempt`
 * MUST remain the final assignment in the update list — MySQL evaluates the
 * list left to right and an earlier assignment would make the window
 * conditions compare against the freshly written value.
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

	if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
		define( 'MINUTE_IN_SECONDS', 60 );
	}
	if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
		define( 'HOUR_IN_SECONDS', 3600 );
	}
	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}

	if ( ! function_exists( 'current_time' ) ) {
		function current_time( $type = 'mysql', $gmt = 0 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return gmdate( 'Y-m-d H:i:s' );
		}
	}

	if ( ! function_exists( 'get_current_blog_id' ) ) {
		function get_current_blog_id() {
			return 1;
		}
	}

	if ( ! class_exists( 'Test_Upsert_WPDB_Stub' ) ) {
		/**
		 * A `$wpdb` stub that records every prepare() (SQL plus bound args),
		 * every query() and every read/write helper call, so the tests can
		 * assert the upsert is a single statement with no SELECT beforehand.
		 */
		class Test_Upsert_WPDB_Stub {
			public string $prefix      = 'wp_';
			public string $base_prefix = 'wp_';
			/** @var array<int, array{sql: string, args: array}> */
			public array $prepares = array();
			/** @var array<int, string> Raw SQL passed to query(). */
			public array $queries = array();
			/** @var array<int, string> SQL passed to any read helper. */
			public array $reads = array();
			/** @var array<int, array{table: string, data: array}> */
			public array $writes = array();

			public function prepare( $sql, ...$args ) {
				$this->prepares[] = array(
					'sql'  => (string) $sql,
					'args' => $args,
				);
				return (string) $sql;
			}

			public function query( $sql ) {
				$this->queries[] = (string) $sql;
				return 1;
			}

			public function get_var( $sql = null ) {
				$this->reads[] = (string) $sql;
				return 0;
			}

			public function get_row( $sql = null ) {
				$this->reads[] = (string) $sql;
				return null;
			}

			public function get_col( $sql = null ) {
				$this->reads[] = (string) $sql;
				return array();
			}

			public function get_results( $sql = null ) {
				$this->reads[] = (string) $sql;
				return array();
			}

			public function insert( $table, $data, $format = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				$this->writes[] = array(
					'table' => $table,
					'data'  => $data,
				);
				return 1;
			}

			public function update( $table, $data, $where, $format = null, $where_format = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				$this->writes[] = array(
					'table' => $table,
					'data'  => $data,
				);
				return 1;
			}

			public function replace( $table, $data, $format = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				$this->writes[] = array(
					'table' => $table,
					'data'  => $data,
				);
				return 1;
			}
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Exercises the single-statement upsert shape of track_attempt().
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TrackAttemptUpsertTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wpdb']          = new \Test_Upsert_WPDB_Stub();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
		}

		/**
		 * Run track_attempt() and return the captured wpdb stub.
		 *
		 * @param int $increment Offences to add at once.
		 * @return \Test_Upsert_WPDB_Stub
		 */
		private function track( int $increment = 1 ): \Test_Upsert_WPDB_Stub {
			$db = new \ReportedIP_Hive_Database();
			$db->track_attempt( '203.0.113.5', 'login', 'admin', 'TestUA', $increment );
			return $GLOBALS['wpdb'];
		}

		/**
		 * The executed SQL with runs of whitespace collapsed to single spaces.
		 *
		 * @param \Test_Upsert_WPDB_Stub $wpdb Captured stub.
		 * @return string
		 */
		private function normalized_sql( \Test_Upsert_WPDB_Stub $wpdb ): string {
			return (string) preg_replace( '/\s+/', ' ', $wpdb->queries[0] );
		}

		public function test_track_attempt_issues_exactly_one_query_and_no_reads() {
			$wpdb = $this->track( 3 );

			$this->assertCount( 1, $wpdb->queries, 'track_attempt must be a single atomic statement.' );
			$this->assertCount( 1, $wpdb->prepares );
			$this->assertSame( array(), $wpdb->reads, 'The old SELECT-then-UPDATE shape must be gone.' );
			$this->assertSame( array(), $wpdb->writes, 'No insert()/update() helper calls — one raw upsert only.' );
		}

		public function test_upsert_targets_the_unique_key_and_measures_the_window_in_utc() {
			$wpdb = $this->track( 3 );
			$sql  = $this->normalized_sql( $wpdb );

			$this->assertStringContainsString( 'INSERT INTO wp_reportedip_hive_attempts', $sql );
			$this->assertStringContainsString( 'ON DUPLICATE KEY UPDATE', $sql );
			$this->assertStringContainsString( 'UTC_TIMESTAMP()', $sql );
			$this->assertStringNotContainsString( 'NOW()', $sql, 'The idle window must not use the session-local NOW().' );
		}

		public function test_last_attempt_is_the_final_assignment_in_the_update_list() {
			$wpdb = $this->track();
			$sql  = $this->normalized_sql( $wpdb );

			$last_attempt_at = strrpos( $sql, 'last_attempt = VALUES(last_attempt)' );
			$this->assertNotFalse( $last_attempt_at, 'The update list must reassign last_attempt from VALUES().' );

			$earlier_assignments = array(
				'attempt_count = IF(',
				'first_attempt = IF(',
				'username = COALESCE(',
				'user_agent = COALESCE(',
			);

			foreach ( $earlier_assignments as $needle ) {
				$position = strrpos( $sql, $needle );
				$this->assertNotFalse( $position, "Update list must contain: {$needle}" );
				$this->assertGreaterThan(
					$position,
					$last_attempt_at,
					"last_attempt must be assigned after '{$needle}' — the IF() window conditions read its OLD value."
				);
			}
		}

		public function test_prepare_receives_ip_type_and_increment() {
			$wpdb    = $this->track( 3 );
			$prepare = $wpdb->prepares[0];

			$this->assertStringContainsString(
				'VALUES (%s, %s, %s, %s, %d, %s, %s)',
				(string) preg_replace( '/\s+/', ' ', $prepare['sql'] )
			);
			$this->assertSame( '203.0.113.5', $prepare['args'][0] );
			$this->assertSame( 'login', $prepare['args'][1] );
			$this->assertSame( 'admin', $prepare['args'][2] );
			$this->assertSame( 'TestUA', $prepare['args'][3] );
			$this->assertSame( 3, $prepare['args'][4] );
			$this->assertMatchesRegularExpression(
				'/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/',
				(string) $prepare['args'][5],
				'first_attempt must be bound as a UTC MySQL datetime.'
			);
			$this->assertSame( $prepare['args'][5], $prepare['args'][6], 'first_attempt and last_attempt share the same UTC stamp.' );
		}

		public function test_increment_is_clamped_to_at_least_one() {
			$wpdb = $this->track( 0 );

			$this->assertSame( 1, $wpdb->prepares[0]['args'][4] );
		}
	}
}
