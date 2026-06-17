<?php
/**
 * Regression guard for the timezone-consistency hotfix.
 *
 * The plugin stores expiry/attempt datetimes in UTC (via gmdate() /
 * current_time('mysql', true)) but historically compared them against the
 * MySQL session clock with NOW() / CURDATE(). On any host whose MySQL session
 * timezone is not UTC, that mismatch made:
 *
 *   - the per-IP attempt counter never accumulate inside its window
 *     (get_attempt_count), so the auto-block threshold was never reached, and
 *   - a freshly written block evaluate as already expired (is_blocked), so no
 *     offender ever stayed blocked.
 *
 * These guards lock every comparison on a UTC-written column to UTC_TIMESTAMP()
 * / UTC_DATE() and assert the block-expiry write is stamped in UTC, so a future
 * edit cannot silently reintroduce the NOW()-vs-UTC drift.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.14
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

	if ( ! class_exists( 'Test_TZ_WPDB_Stub' ) ) {
		/**
		 * A `$wpdb` stub that records every SQL string and the data written by
		 * replace()/insert()/update(), so the tests can assert the timezone
		 * function used in each comparison and write.
		 */
		class Test_TZ_WPDB_Stub {
			public string $prefix      = 'wp_';
			public string $base_prefix = 'wp_';
			/** @var array<int, string> Raw SQL passed to prepare(). */
			public array $prepares = array();
			/** @var array<int, string> Raw SQL passed to query(). */
			public array $queries = array();
			/** @var array<int, array{table:string, data:array}> */
			public array $writes = array();
			/** @var int|false */
			public $get_var_return = 0;

			public function prepare( string $sql, ...$args ): string { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				$this->prepares[] = $sql;
				return $sql;
			}

			public function query( $sql ) {
				$this->queries[] = $sql;
				return 1;
			}

			public function get_var( $sql = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return $this->get_var_return;
			}

			public function get_row( $sql = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return null;
			}

			public function replace( $table, $data, $format = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				$this->writes[] = array(
					'table' => $table,
					'data'  => $data,
				);
				return 1;
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
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TimezoneConsistencyTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wpdb']          = new \Test_TZ_WPDB_Stub();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
		}

		/**
		 * Concatenate every SQL string the stub captured (prepares + queries).
		 *
		 * @return string
		 */
		private function all_sql(): string {
			return implode( "\n", array_merge( $GLOBALS['wpdb']->prepares, $GLOBALS['wpdb']->queries ) );
		}

		/**
		 * The active-block check must compare blocked_until (written in UTC)
		 * against UTC_TIMESTAMP(), never the session-local NOW().
		 */
		public function test_is_blocked_compares_against_utc(): void {
			$db = new \ReportedIP_Hive_Database();
			$db->is_blocked( '1.2.3.4' );

			$sql = $this->all_sql();
			$this->assertStringContainsString( 'blocked_until > UTC_TIMESTAMP()', $sql );
			$this->assertStringNotContainsString( 'NOW()', $sql, 'is_blocked must not use the session-local NOW().' );
		}

		/**
		 * The windowed attempt counter must measure its timeframe from
		 * UTC_TIMESTAMP(), matching the UTC-written last_attempt column.
		 */
		public function test_get_attempt_count_window_is_utc(): void {
			$db = new \ReportedIP_Hive_Database();
			$db->get_attempt_count( '1.2.3.4', 'login', 15 );

			$sql = $this->all_sql();
			$this->assertStringContainsString( 'DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)', $sql );
			$this->assertStringNotContainsString( 'NOW()', $sql, 'get_attempt_count must not use the session-local NOW().' );
		}

		/**
		 * The crash-recovery sweep works on minute granularity, so its
		 * submitted_at / last_attempt windows must use UTC_TIMESTAMP().
		 */
		public function test_recover_stuck_processing_window_is_utc(): void {
			$db = new \ReportedIP_Hive_Database();
			$db->recover_stuck_processing( 10 );

			$sql = implode( "\n", $GLOBALS['wpdb']->queries );
			$this->assertStringContainsString( 'DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE)', $sql );
			$this->assertStringNotContainsString( 'NOW()', $sql, 'Recovery sweep must not use the session-local NOW().' );
		}

		/**
		 * The dedup window in queue_api_report touches created_at and
		 * last_attempt (both UTC) on sub-hour granularity and must be UTC.
		 */
		public function test_queue_dedup_window_is_utc(): void {
			$db = new \ReportedIP_Hive_Database();
			$db->queue_api_report( '1.2.3.4', '18', 'test' );

			$sql = $this->all_sql();
			$this->assertStringContainsString( 'UTC_TIMESTAMP()', $sql );
			$this->assertStringNotContainsString( 'NOW()', $sql, 'Queue dedup must not use the session-local NOW().' );
		}

		/**
		 * A sub-hour block must be stamped with a UTC blocked_until that lies in
		 * the future relative to the UTC clock — the value is_blocked() reads.
		 */
		public function test_block_for_minutes_writes_future_utc(): void {
			$db = new \ReportedIP_Hive_Database();
			$db->block_ip_for_minutes( '1.2.3.4', 'reason', 'automatic', 5 );

			$writes = array_filter(
				$GLOBALS['wpdb']->writes,
				static function ( $w ) {
					return isset( $w['data']['blocked_until'] );
				}
			);
			$this->assertNotEmpty( $writes, 'block_ip_for_minutes must stamp blocked_until.' );

			$write         = array_values( $writes )[0];
			$blocked_until = $write['data']['blocked_until'];

			$now_utc = gmdate( 'Y-m-d H:i:s' );
			$this->assertGreaterThan(
				$now_utc,
				$blocked_until,
				'A 5-minute block must expire in the future on the UTC clock is_blocked() reads.'
			);
		}
	}
}
