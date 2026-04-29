<?php
/**
 * Unit tests for the 1.5.3 queue-recovery hotfix.
 *
 * Locks down four behavioural changes that fix "API queue rows stuck pending
 * for 24+ hours":
 *
 *   1. `is_recently_processed()` only counts `completed` rows, so a stuck
 *      `processing` row no longer poisons that IP's cooldown for 24 h.
 *   2. `queue_api_report()` dedup window covers `failed` rows for 15 min so
 *      a transient API failure does not loop into duplicate inserts.
 *   3. `recover_stuck_processing()` resets `processing` rows whose worker
 *      crashed; rows still in flight (recent `submitted_at`) are left alone,
 *      and rows whose retries are exhausted graduate to `failed`.
 *   4. `cron_process_queue()` acquires a transient lock so two workers
 *      cannot race on the same recovered row.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.5.3
 */

namespace {

	if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
		define( 'MINUTE_IN_SECONDS', 60 );
	}

	if ( ! function_exists( 'current_time' ) ) {
		function current_time( $type = 'mysql', $gmt = 0 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return gmdate( 'Y-m-d H:i:s' );
		}
	}

	if ( ! class_exists( 'Test_Queue_WPDB_Stub' ) ) {
		/**
		 * A `$wpdb` stub that captures every SQL string and the arguments it
		 * was prepared with, plus controllable return values for `get_var()`
		 * (cooldown / dedup count) and `query()` (UPDATE row count).
		 */
		class Test_Queue_WPDB_Stub {
			public string $prefix = 'wp_';
			/** @var array<int, array{sql:string, args:array}> */
			public array $prepares = array();
			/** @var array<int, string> */
			public array $queries = array();
			/** @var int */
			public int $get_var_call = 0;
			/** @var array<int, int> Per-call return value, keyed by 0-based call index. */
			public array $get_var_returns = array();
			/** @var int Default return when no override is set. */
			public int $get_var_default = 0;
			/** @var int|false Return for $wpdb->query(). */
			public $query_return = 1;
			/** @var int|false Return for $wpdb->update(). */
			public $update_return = 1;
			/** @var array<int, array{table:string, data:array, where:array}> */
			public array $updates = array();

			public function prepare( string $sql, ...$args ): string {
				$this->prepares[] = array(
					'sql'  => $sql,
					'args' => $args,
				);
				return $sql;
			}

			public function query( $sql ) {
				$this->queries[] = $sql;
				return $this->query_return;
			}

			public function get_var( $sql ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				$idx = $this->get_var_call++;
				return array_key_exists( $idx, $this->get_var_returns )
					? $this->get_var_returns[ $idx ]
					: $this->get_var_default;
			}

			public function update( $table, $data, $where, $format = null, $where_format = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				$this->updates[] = array(
					'table' => $table,
					'data'  => $data,
					'where' => $where,
				);
				return $this->update_return;
			}

			public function insert( $table, $data, $format = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return 1;
			}
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-cron-handler.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class ApiQueueRecoveryTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wpdb']                = new \Test_Queue_WPDB_Stub();
			$GLOBALS['wp_options']          = array();
			$GLOBALS['wp_transients']       = array();
		}

		/**
		 * `is_recently_processed()` must only flag the IP as "recently
		 * reported" when a `completed` row exists. Pending/processing rows
		 * (which can be stuck) must NOT count.
		 */
		public function test_is_recently_processed_filters_to_completed_only(): void {
			$db = new \ReportedIP_Hive_Database();
			$db->is_recently_processed( '1.2.3.4', 24 );

			$this->assertGreaterThanOrEqual(
				2,
				count( $GLOBALS['wpdb']->prepares ),
				'Expected blocked-table query + queue-table query.'
			);

			$queue_query = $GLOBALS['wpdb']->prepares[1]['sql'];
			$this->assertStringContainsString(
				"status = 'completed'",
				$queue_query,
				'Cooldown query must filter to completed rows only.'
			);
			$this->assertStringNotContainsString(
				"IN ('completed', 'pending', 'processing')",
				$queue_query,
				'Pending/processing rows must NOT count toward the cooldown.'
			);
		}

		/**
		 * The 1.6 dedup at insert-time must additionally cover recent
		 * `failed` rows (15-min window) to prevent tight-loop duplication
		 * after a transient API failure.
		 */
		public function test_queue_api_report_dedup_includes_failed_15min_window(): void {
			$GLOBALS['wpdb']->get_var_returns = array(
				0 => 0,
				1 => 0,
				2 => 0,
			);

			$db = new \ReportedIP_Hive_Database();
			$db->queue_api_report( '5.6.7.8', '18', 'test' );

			$dedup_query = end( $GLOBALS['wpdb']->prepares )['sql'];
			$this->assertStringContainsString(
				"status = 'failed'",
				$dedup_query,
				'Dedup must include a failed-row predicate.'
			);
			$this->assertStringContainsString(
				'INTERVAL 15 MINUTE',
				$dedup_query,
				'Failed-row dedup window must be 15 minutes.'
			);
			$this->assertStringContainsString(
				"status IN ('pending', 'processing')",
				$dedup_query,
				'The original 1-hour pending/processing dedup must remain.'
			);
		}

		/**
		 * The recovery sweep must issue two UPDATEs: one resetting rows with
		 * retries left to `pending`, one marking exhausted rows as `failed`.
		 * Both must filter on `status = 'processing'` and the timeout
		 * window.
		 */
		public function test_recover_stuck_processing_issues_two_targeted_updates(): void {
			$db     = new \ReportedIP_Hive_Database();
			$result = $db->recover_stuck_processing( 10 );

			$this->assertIsArray( $result );
			$this->assertArrayHasKey( 'reset', $result );
			$this->assertArrayHasKey( 'failed', $result );

			$this->assertCount(
				2,
				$GLOBALS['wpdb']->queries,
				'Recovery sweep must issue exactly two UPDATEs.'
			);

			$reset_sql  = $GLOBALS['wpdb']->queries[0];
			$failed_sql = $GLOBALS['wpdb']->queries[1];

			$this->assertStringContainsString(
				"SET status = 'pending'",
				$reset_sql,
				'First UPDATE resets retryable rows to pending.'
			);
			$this->assertStringContainsString(
				'attempts < max_attempts',
				$reset_sql,
				'Reset only fires when retries are still available.'
			);
			$this->assertStringContainsString(
				"status = 'processing'",
				$reset_sql,
				'Reset only touches stuck processing rows.'
			);
			$this->assertStringContainsString(
				'INTERVAL %d MINUTE',
				$reset_sql,
				'Timeout interval must be a prepared placeholder.'
			);
			$this->assertSame(
				array( 10, 10 ),
				$GLOBALS['wpdb']->prepares[0]['args'],
				'Both submitted_at and last_attempt windows use the configured timeout.'
			);

			$this->assertStringContainsString(
				"SET status = 'failed'",
				$failed_sql,
				'Second UPDATE fails rows that exhausted retries.'
			);
			$this->assertStringContainsString(
				'attempts >= max_attempts',
				$failed_sql,
				'Failed branch only fires when retries are exhausted.'
			);
		}

		/**
		 * The recovery SQL must protect rows still in flight (recent
		 * `submitted_at`). Without this guard, a worker that takes 5 s to
		 * complete its HTTP call could be racing against a parallel cron
		 * resetting its own row.
		 */
		public function test_recover_stuck_processing_skips_recently_submitted_rows(): void {
			$db = new \ReportedIP_Hive_Database();
			$db->recover_stuck_processing( 10 );

			$reset_sql = $GLOBALS['wpdb']->queries[0];
			$this->assertStringContainsString(
				'submitted_at IS NULL',
				$reset_sql,
				'NULL submitted_at branch is required for legacy rows.'
			);
			$this->assertStringContainsString(
				'submitted_at IS NOT NULL',
				$reset_sql,
				'NOT-NULL submitted_at branch is required for in-flight skip.'
			);
		}

		/**
		 * `mark_report_submitted()` stamps the `submitted_at` column. The
		 * recovery sweep relies on this to differentiate live HTTP calls
		 * from crashed workers.
		 */
		public function test_mark_report_submitted_writes_submitted_at(): void {
			$db = new \ReportedIP_Hive_Database();
			$db->mark_report_submitted( 42 );

			$this->assertCount( 1, $GLOBALS['wpdb']->updates );
			$update = $GLOBALS['wpdb']->updates[0];
			$this->assertArrayHasKey( 'submitted_at', $update['data'] );
			$this->assertSame( 42, $update['where']['id'] );
		}

		/**
		 * The queue lock transient key is exposed as a class constant so the
		 * recovery sweep, the manual-trigger AJAX endpoint and the cron
		 * handler all agree on the same lock identifier. Locking down the
		 * literal here prevents accidental rename regressions.
		 */
		public function test_queue_lock_transient_constant_is_stable(): void {
			$this->assertSame(
				'reportedip_hive_queue_lock',
				\ReportedIP_Hive_Cron_Handler::QUEUE_LOCK_TRANSIENT,
				'Lock transient name must remain stable across releases.'
			);
		}
	}
}
