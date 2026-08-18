<?php
/**
 * Behavioural tests for three database-layer defects found in the 2.1.43 audit.
 *
 * These drive the real methods against a `$wpdb` stub that reproduces the parts
 * of WordPress that made each defect bite:
 *
 *  - `prepare()` counts placeholders and returns an empty string on a
 *    placeholder/argument mismatch, exactly as `wpdb::prepare()` does after
 *    `_doing_it_wrong()`. That is what turned an API-queue search beginning
 *    with s, d or f into an empty result.
 *  - `update()` can be told to fail, which is what made log anonymisation spin
 *    through its whole time budget without anonymising anything.
 *  - `query()` reports affected rows, so a lost claim race is observable.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.44
 */

namespace {

	if ( ! class_exists( 'Test_Query_Behaviour_WPDB' ) ) {
		/**
		 * A `$wpdb` stub whose prepare() enforces placeholder arity the way
		 * WordPress does, and whose write result is controllable.
		 */
		class Test_Query_Behaviour_WPDB {
			public string $prefix      = 'wp_';
			public string $base_prefix = 'wp_';

			/** @var array<int, string> Every statement handed to a read or write. */
			public array $statements = array();

			/** @var array<int, string> SQL that prepare() refused to build. */
			public array $prepare_failures = array();

			/** @var mixed Result returned by update(). */
			public $update_result = 1;

			/** @var mixed Result returned by query(). */
			public $query_result = 1;

			/** @var array<int, object> Rows returned by get_results(). */
			public array $rows = array();

			/** @var int Number of get_results() calls served. */
			public int $result_calls = 0;

			public function esc_like( $text ) {
				return addcslashes( (string) $text, '_%\\' );
			}

			/**
			 * Substitute placeholders, refusing a mismatched argument count.
			 *
			 * @param string $sql     Query with placeholders.
			 * @param mixed  ...$args Bound values.
			 * @return string Prepared SQL, or '' when the arity does not match.
							 */
			public function prepare( $sql, ...$args ) {
				$sql = (string) $sql;

				if ( 1 === count( $args ) && is_array( $args[0] ) ) {
					$args = $args[0];
				}

				$expected = preg_match_all( '/%[sdf]/', $sql );

				if ( $expected !== count( $args ) ) {
					$this->prepare_failures[] = $sql;
					return '';
				}

				$index = 0;
				return (string) preg_replace_callback(
					'/%([sdf])/',
					function ( $match ) use ( &$index, $args ) {
						$value = $args[ $index ];
						++$index;
						if ( 'd' === $match[1] ) {
							return (string) (int) $value;
						}
						if ( 'f' === $match[1] ) {
							return (string) (float) $value;
						}
						return "'" . str_replace( "'", "\\'", (string) $value ) . "'";
					},
					$sql
				);
			}

			public function query( $sql ) {
				$this->statements[] = (string) $sql;
				return $this->query_result;
			}

			public function get_results( $sql = null ) {
				$this->statements[] = (string) $sql;
				++$this->result_calls;
				return $this->rows;
			}

			public function get_var( $sql = null ) {
				$this->statements[] = (string) $sql;
				return 0;
			}

			public function get_row( $sql = null ) {
				$this->statements[] = (string) $sql;
				return null;
			}

			public function get_col( $sql = null ) {
				$this->statements[] = (string) $sql;
				return array();
			}

			public function insert( $table, $data, $format = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return 1;
			}

			public function update( $table, $data, $where, $format = null, $where_format = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return $this->update_result;
			}

			public function replace( $table, $data, $format = null ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
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
	class DatabaseQueryBehaviourTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wpdb']          = new \Test_Query_Behaviour_WPDB();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
		}

		/**
		 * The stub currently installed as $wpdb.
		 *
		 * @return \Test_Query_Behaviour_WPDB
		 */
		private function wpdb(): \Test_Query_Behaviour_WPDB {
			return $GLOBALS['wpdb'];
		}

		/**
		 * A queue row shaped like the real table.
		 *
		 * @param int $id Row id.
		 * @return object
		 */
		private function queue_row( int $id ): object {
			return (object) array(
				'id'           => $id,
				'ip_address'   => '203.0.113.' . $id,
				'report_type'  => 'negative',
				'category_ids' => '18',
				'comment'      => '',
				'details'      => '{"user_agent":"probe"}',
			);
		}

		/**
		 * A search term whose LIKE pattern begins with a placeholder letter is
		 * the exact case that used to break: '%spam%' contains '%s'.
		 */
		public function test_queue_search_survives_a_term_that_looks_like_a_placeholder() {
			$db = new \ReportedIP_Hive_Database();

			foreach ( array( 'spam', 'dns', 'foo' ) as $term ) {
				$this->wpdb()->statements       = array();
				$this->wpdb()->prepare_failures = array();

				$db->get_api_queue_items(
					array(
						'limit'  => 20,
						'offset' => 0,
						'search' => $term,
					)
				);

				$this->assertSame(
					array(),
					$this->wpdb()->prepare_failures,
					sprintf( 'Searching for "%s" must not produce a placeholder mismatch', $term )
				);

				$executed = end( $this->wpdb()->statements );
				$this->assertIsString( $executed );
				$this->assertNotSame( '', $executed, 'The listing query must not come back empty' );
				$this->assertStringContainsString( 'SELECT * FROM wp_reportedip_hive_api_queue', $executed );
				$this->assertStringContainsString( 'LIKE', $executed, 'The search term must reach the query' );
				$this->assertStringContainsString( $term, $executed );
				$this->assertStringContainsString( 'LIMIT 20 OFFSET 0', $executed, 'Pagination must still be bound' );
			}
		}

		public function test_queue_search_still_paginates_without_a_search_term() {
			$db = new \ReportedIP_Hive_Database();
			$db->get_api_queue_items( array( 'limit' => 5, 'offset' => 10 ) );

			$executed = end( $this->wpdb()->statements );
			$this->assertStringContainsString( 'LIMIT 5 OFFSET 10', $executed );
			$this->assertSame( array(), $this->wpdb()->prepare_failures );
		}

		public function test_claiming_a_queue_row_requires_it_to_be_unclaimed() {
			$db = new \ReportedIP_Hive_Database();
			$db->update_api_report_status( 42, 'processing' );

			$executed = end( $this->wpdb()->statements );
			$this->assertStringContainsString( "status IN ('pending', 'failed')", $executed, 'The claim must be conditional' );
			$this->assertStringContainsString( 'attempts = attempts + 1', $executed );
			$this->assertStringContainsString( 'WHERE id = 42', $executed );
		}

		public function test_a_lost_claim_race_is_reported_to_the_caller() {
			$this->wpdb()->query_result = 0;

			$db     = new \ReportedIP_Hive_Database();
			$result = $db->update_api_report_status( 42, 'processing' );

			$this->assertSame( 0, $result, 'Zero affected rows means another worker already claimed the row' );
		}

		public function test_anonymisation_stops_instead_of_spinning_when_writes_fail() {
			$rows = array();
			for ( $i = 1; $i <= 500; $i++ ) {
				$rows[] = (object) array(
					'id'      => $i,
					'details' => '{"username":"admin","user_agent":"probe"}',
				);
			}

			$this->wpdb()->rows          = $rows;
			$this->wpdb()->update_result = false;

			$db    = new \ReportedIP_Hive_Database();
			$start = microtime( true );
			$db->anonymize_old_data( 30 );
			$elapsed = microtime( true ) - $start;

			$this->assertLessThanOrEqual(
				2,
				$this->wpdb()->result_calls,
				'A failing write must end the batch loop, not re-fetch the same rows until the time budget expires'
			);
			$this->assertLessThan( 5.0, $elapsed, 'The loop must not burn its 20-second budget on a failing write' );
		}

		public function test_anonymisation_keeps_going_while_writes_succeed() {
			$rows = array();
			for ( $i = 1; $i <= 500; $i++ ) {
				$rows[] = (object) array(
					'id'      => $i,
					'details' => '{"username":"admin"}',
				);
			}

			$this->wpdb()->rows          = $rows;
			$this->wpdb()->update_result = 1;

			$db = new \ReportedIP_Hive_Database();
			$db->anonymize_old_data( 30 );

			$this->assertGreaterThan(
				1,
				$this->wpdb()->result_calls,
				'A full batch that wrote successfully must be followed by another fetch'
			);
		}
	}
}
