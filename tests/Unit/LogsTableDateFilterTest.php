<?php
/**
 * Tests for the date-range filter of the security-logs table.
 *
 * The Logs screen filters on `created_at`, which is stored in UTC, while the
 * admin enters site-local calendar days. The WHERE builder must therefore
 * translate each bound through get_gmt_from_date() (00:00:00 for the lower,
 * 23:59:59 for the upper day edge) and bind it via $wpdb->prepare(); a value
 * that is not a strict YYYY-MM-DD date must add no created_at bound at all.
 * The table is built without its constructor (WP_List_Table stubbed below)
 * and the private query builder is invoked via reflection against a
 * capturing $wpdb double, following the TimezoneConsistencyTest idiom.
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

	if ( ! class_exists( 'WP_List_Table' ) ) {
		/**
		 * Minimal WP_List_Table stand-in so the logs table class can be
		 * defined in the unit harness without wp-admin being present.
		 */
		class WP_List_Table {

			/**
			 * Table rows.
			 *
			 * @var array
			 */
			public $items = array();

			/**
			 * Constructor arguments.
			 *
			 * @var array
			 */
			protected $_args = array();

			/**
			 * Column-header triple.
			 *
			 * @var array
			 */
			protected $_column_headers = array();

			/**
			 * Store the constructor arguments.
			 *
			 * @param array $args List-table arguments.
			 */
			public function __construct( $args = array() ) {
				$this->_args = (array) $args;
			}

			/**
			 * Per-page setting; the stub returns the default unchanged.
			 *
			 * @param string $option        Screen option name.
			 * @param int    $default_value Fallback value.
			 * @return int
			 */
			public function get_items_per_page( $option, $default_value = 20 ) {
				return (int) $default_value;
			}

			/**
			 * Current page number; the stub pins page one.
			 *
			 * @return int
			 */
			public function get_pagenum() {
				return 1;
			}

			/**
			 * Pagination sink.
			 *
			 * @param array $args Pagination arguments.
			 * @return void
			 */
			public function set_pagination_args( $args ) {
			}

			/**
			 * Bulk-action probe; the stub reports none.
			 *
			 * @return false
			 */
			public function current_action() {
				return false;
			}
		}
	}

	if ( ! class_exists( 'Test_LT_WPDB_Stub' ) ) {
		/**
		 * A `$wpdb` double that records every prepare() call together with its
		 * bound arguments, so the tests can assert both the SQL fragment and
		 * the exact bound values.
		 */
		class Test_LT_WPDB_Stub {

			/**
			 * Site table prefix.
			 *
			 * @var string
			 */
			public string $prefix = 'wp_';

			/**
			 * Network-wide table prefix.
			 *
			 * @var string
			 */
			public string $base_prefix = 'wp_';

			/**
			 * Every prepare() call as {sql, args}.
			 *
			 * @var array<int, array{sql:string, args:array}>
			 */
			public array $prepares = array();

			/**
			 * Raw SQL handed to the read methods.
			 *
			 * @var array<int, string>
			 */
			public array $queries = array();

			/**
			 * Record the statement and return the raw SQL unchanged.
			 *
			 * @param string $sql     SQL with placeholders.
			 * @param mixed  ...$args Bound values.
			 * @return string
			 */
			public function prepare( string $sql, ...$args ): string {
				$this->prepares[] = array(
					'sql'  => $sql,
					'args' => $args,
				);
				return $sql;
			}

			/**
			 * Record the query and report zero rows.
			 *
			 * @param string|null $sql SQL string.
			 * @return int
			 */
			public function get_var( $sql = null ) {
				$this->queries[] = (string) $sql;
				return 0;
			}

			/**
			 * Record the query and return an empty result set.
			 *
			 * @param string|null $sql SQL string.
			 * @return array
			 */
			public function get_results( $sql = null ) {
				$this->queries[] = (string) $sql;
				return array();
			}

			/**
			 * Escape LIKE wildcards, mirroring wpdb::esc_like().
			 *
			 * @param string $text Raw text.
			 * @return string
			 */
			public function esc_like( $text ) {
				return addcslashes( (string) $text, '_%\\' );
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
	class LogsTableDateFilterTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wpdb'] = new \Test_LT_WPDB_Stub();
			unset( $_REQUEST['rip_date_from'], $_REQUEST['rip_date_to'] );

			require_once dirname( __DIR__, 2 ) . '/admin/class-logs-table.php';
		}

		protected function tearDown(): void {
			unset( $_REQUEST['rip_date_from'], $_REQUEST['rip_date_to'] );
			parent::tearDown();
		}

		/**
		 * Invoke the private query builder on a constructor-less table instance.
		 *
		 * @return void
		 */
		private function run_get_logs_data(): void {
			$table  = ( new \ReflectionClass( \ReportedIP_Hive_Logs_Table::class ) )->newInstanceWithoutConstructor();
			$method = new \ReflectionMethod( \ReportedIP_Hive_Logs_Table::class, 'get_logs_data' );
			$method->invoke( $table, 25, 1 );
		}

		/**
		 * Concatenate every SQL string the stub captured.
		 *
		 * @return string
		 */
		private function all_sql(): string {
			return implode(
				"\n",
				array_merge( array_column( $GLOBALS['wpdb']->prepares, 'sql' ), $GLOBALS['wpdb']->queries )
			);
		}

		/**
		 * The bound values of the first prepare whose SQL contains a fragment.
		 *
		 * @param string $fragment SQL fragment to look for.
		 * @return array|null
		 */
		private function args_for( string $fragment ): ?array {
			foreach ( $GLOBALS['wpdb']->prepares as $prepare ) {
				if ( false !== strpos( $prepare['sql'], $fragment ) ) {
					return $prepare['args'];
				}
			}
			return null;
		}

		public function test_valid_dates_produce_prepared_utc_day_bounds(): void {
			$_REQUEST['rip_date_from'] = '2026-08-01';
			$_REQUEST['rip_date_to']   = '2026-08-05';

			$this->run_get_logs_data();

			$this->assertSame(
				array( \get_gmt_from_date( '2026-08-01 00:00:00' ) ),
				$this->args_for( 'created_at >= %s' ),
				'The lower bound must be the site-local day start converted through get_gmt_from_date()'
			);
			$this->assertSame(
				array( \get_gmt_from_date( '2026-08-05 23:59:59' ) ),
				$this->args_for( 'created_at <= %s' ),
				'The upper bound must be the site-local day end converted through get_gmt_from_date()'
			);

			$sql = $this->all_sql();
			$this->assertStringContainsString( 'created_at >= %s', $sql, 'The lower bound must reach the executed WHERE clause' );
			$this->assertStringContainsString( 'created_at <= %s', $sql, 'The upper bound must reach the executed WHERE clause' );
		}

		public function test_a_single_valid_from_date_binds_only_the_lower_bound(): void {
			$_REQUEST['rip_date_from'] = '2026-08-01';

			$this->run_get_logs_data();

			$this->assertNotNull( $this->args_for( 'created_at >= %s' ) );
			$this->assertNull( $this->args_for( 'created_at <= %s' ) );
		}

		public function test_malformed_dates_add_no_created_at_bound(): void {
			$_REQUEST['rip_date_from'] = '01.08.2026';
			$_REQUEST['rip_date_to']   = "2026-08-05'; DROP TABLE wp_users; --";

			$this->run_get_logs_data();

			$sql = $this->all_sql();
			$this->assertStringNotContainsString(
				'created_at >=',
				$sql,
				'A value that is not a strict YYYY-MM-DD date must never become a lower bound'
			);
			$this->assertStringNotContainsString(
				'created_at <=',
				$sql,
				'A value that is not a strict YYYY-MM-DD date must never become an upper bound'
			);
		}
	}
}
