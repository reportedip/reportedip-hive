<?php
/**
 * The blocked list and the whitelist label the types and origins the free
 * plugin writes itself and hand every cell to a filter, so an add-on marks
 * its own rows; a row of an origin the free plugin does not manage stays
 * locked against removal, like the IP manager refuses it.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace {

	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}

	if ( ! class_exists( 'WP_List_Table' ) ) {
		/**
		 * Minimal WP_List_Table stand-in, the same surface as the one in
		 * LogsTableDateFilterTest, whichever file loads first.
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

	require_once dirname( __DIR__, 2 ) . '/admin/class-ip-cell.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-blocked-ips-table.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-whitelist-table.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @covers \ReportedIP_Hive_Blocked_IPs_Table
	 * @covers \ReportedIP_Hive_Whitelist_Table
	 */
	final class IpListMarksTest extends TestCase {

		/** @var mixed */
		private $filters_before;

		protected function set_up(): void {
			parent::set_up();
			$this->filters_before = $GLOBALS['wp_filters'] ?? array();
		}

		protected function tear_down(): void {
			$GLOBALS['wp_filters'] = $this->filters_before;
			parent::tear_down();
		}

		/**
		 * Render one cell of a table built without its constructor.
		 *
		 * @param string $class  Table class.
		 * @param string $method Cell method.
		 * @param object $item   Row.
		 * @param string $column Column, for column_default().
		 * @return string
		 */
		private function cell( string $class, string $method, object $item, string $column = '' ): string {
			$table  = ( new \ReflectionClass( $class ) )->newInstanceWithoutConstructor();
			$invoke = new \ReflectionMethod( $class, $method );
			return (string) ( '' === $column ? $invoke->invoke( $table, $item ) : $invoke->invoke( $table, $item, $column ) );
		}

		public function test_the_free_block_types_are_labelled_and_any_other_reads_as_automatic(): void {
			$this->assertStringContainsString( 'Manually Blocked', $this->cell( \ReportedIP_Hive_Blocked_IPs_Table::class, 'column_default', (object) array( 'block_type' => 'manual' ), 'block_type' ) );
			$this->assertStringContainsString( 'Community Reputation', $this->cell( \ReportedIP_Hive_Blocked_IPs_Table::class, 'column_default', (object) array( 'block_type' => 'reputation' ), 'block_type' ) );
			$this->assertSame( '<span class="block-type-badge auto">Auto-Blocked</span>', $this->cell( \ReportedIP_Hive_Blocked_IPs_Table::class, 'column_default', (object) array( 'block_type' => 'group' ), 'block_type' ), 'Without the add-on a 2.x group ban is just a block until it runs out.' );
		}

		public function test_an_add_on_labels_its_block_type_and_adds_it_to_the_filter(): void {
			add_filter(
				'reportedip_hive_block_type_badge',
				static function ( $badge, $type, $item ) {
					return 'extra' === $type ? '<b>' . $item->ip_address . '</b>' : $badge;
				},
				10,
				3
			);
			$this->assertSame( '<b>198.51.100.9</b>', $this->cell( \ReportedIP_Hive_Blocked_IPs_Table::class, 'column_default', (object) array( 'block_type' => 'extra', 'ip_address' => '198.51.100.9' ), 'block_type' ) );

			$this->assertSame( array( 'manual', 'automatic', 'reputation' ), array_keys( \ReportedIP_Hive_Blocked_IPs_Table::block_type_options() ) );
			add_filter(
				'reportedip_hive_block_type_options',
				static function ( $options ) {
					$options['extra'] = 'Extra';
					return $options;
				}
			);
			$this->assertSame( 'Extra', \ReportedIP_Hive_Blocked_IPs_Table::block_type_options()['extra'] );

			$GLOBALS['wp_filters']['reportedip_hive_block_type_options'] = array();
			add_filter( 'reportedip_hive_block_type_options', static fn() => null );
			$this->assertCount( 3, \ReportedIP_Hive_Blocked_IPs_Table::block_type_options(), 'A broken result leaves the free list.' );
		}

		public function test_the_whitelist_origin_is_filtered_and_a_foreign_row_stays_locked(): void {
			$manual = (object) array(
				'ip_address' => '198.51.100.1',
				'source'     => 'manual',
			);
			$group  = (object) array(
				'ip_address' => '198.51.100.2',
				'source'     => 'group',
			);
			$this->assertSame( '<span class="block-type-badge manual">Manual</span>', $this->cell( \ReportedIP_Hive_Whitelist_Table::class, 'column_default', $manual, 'source' ) );
			$this->assertSame( '<span class="block-type-badge">group</span>', $this->cell( \ReportedIP_Hive_Whitelist_Table::class, 'column_default', $group, 'source' ) );

			add_filter(
				'reportedip_hive_whitelist_origin',
				static function ( $html, $source ) {
					return 'group' === $source ? '<i>Group</i>' : $html;
				},
				10,
				3
			);
			$this->assertSame( '<i>Group</i>', $this->cell( \ReportedIP_Hive_Whitelist_Table::class, 'column_default', $group, 'source' ) );

			$this->assertStringContainsString( 'disabled="disabled"', $this->cell( \ReportedIP_Hive_Whitelist_Table::class, 'column_cb', $group ) );
			$this->assertStringContainsString( 'Managed in your reportedip.com account', $this->cell( \ReportedIP_Hive_Whitelist_Table::class, 'column_default', $group, 'actions' ) );
			$this->assertStringContainsString( 'value="198.51.100.1"', $this->cell( \ReportedIP_Hive_Whitelist_Table::class, 'column_cb', $manual ) );
		}
	}
}
