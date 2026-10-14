<?php
/**
 * Audit rows a 2.x release left behind keep their retention, export and
 * erasure while no add-on claims the table, and only then.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-legacy-data.php';

	/**
	 * A `$wpdb` double: one optional audit table, with or without the object
	 * columns, and a record of every statement.
	 */
	class Test_Legacy_Data_WPDB {

		/** @var string */
		public $base_prefix = 'wp_';

		/** @var bool */
		public $has_table = true;

		/** @var bool */
		public $has_objects = true;

		/** @var string[] */
		public $queries = array();

		/** @var array<int, object> */
		public $rows = array();

		/**
		 * Bind %d and %s like wpdb::prepare().
		 *
		 * @param string $sql  Statement.
		 * @param mixed  ...$args Values.
		 * @return string
		 */
		public function prepare( $sql, ...$args ) {
			$args = isset( $args[0] ) && is_array( $args[0] ) ? $args[0] : $args;
			foreach ( $args as $arg ) {
				$sql = (string) preg_replace( '/%[ds]/', is_int( $arg ) ? (string) $arg : "'" . $arg . "'", $sql, 1 );
			}
			return $sql;
		}

		/**
		 * @param string $text Text.
		 * @return string
		 */
		public function esc_like( $text ) {
			return addcslashes( $text, '_%\\' );
		}

		/**
		 * @param string $sql Statement.
		 * @return mixed
		 */
		public function get_var( $sql ) {
			$this->queries[] = $sql;
			if ( 0 === strpos( $sql, 'SHOW TABLES' ) ) {
				return $this->has_table ? 'wp_reportedip_hive_audit_log' : null;
			}
			if ( false !== strpos( $sql, 'information_schema.COLUMNS' ) ) {
				return $this->has_objects ? '1' : '0';
			}
			return null;
		}

		/**
		 * @param string $sql Statement.
		 * @return array<int, object>
		 */
		public function get_results( $sql ) {
			$this->queries[] = $sql;
			return $this->rows;
		}

		/**
		 * @param string $sql Statement.
		 * @return int
		 */
		public function query( $sql ) {
			$this->queries[] = $sql;
			return 2;
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @covers \ReportedIP_Hive_Legacy_Data
	 * @covers \ReportedIP_Hive_Schema::unclaimed_legacy_tables
	 */
	final class LegacyDataTest extends TestCase {

		/** @var mixed */
		private $wpdb_before;

		/** @var mixed */
		private $filters_before;

		/** @var \Test_Legacy_Data_WPDB */
		private $db;

		protected function set_up(): void {
			parent::set_up();
			$this->wpdb_before    = $GLOBALS['wpdb'] ?? null;
			$this->filters_before = $GLOBALS['wp_filters'] ?? array();
			$this->db             = new \Test_Legacy_Data_WPDB();
			$GLOBALS['wpdb']      = $this->db;
			unset( $GLOBALS['wp_filters']['reportedip_hive_schema_tables'] );
		}

		protected function tear_down(): void {
			$GLOBALS['wpdb']       = $this->wpdb_before;
			$GLOBALS['wp_filters'] = $this->filters_before;
			parent::tear_down();
		}

		/**
		 * Let an add-on claim the audit table, or take it out of the list.
		 *
		 * @param bool $claimed Whether the table is claimed.
		 */
		private function claim( bool $claimed ): void {
			add_filter(
				'reportedip_hive_schema_tables',
				static function ( $suffixes ) use ( $claimed ) {
					$suffixes = array_diff( $suffixes, array( 'reportedip_hive_audit_log' ) );
					return $claimed ? array_merge( $suffixes, array( 'reportedip_hive_audit_log' ) ) : array_values( $suffixes );
				}
			);
		}

		/**
		 * The user under request; the routine reads only the id.
		 *
		 * @return object
		 */
		private function user(): object {
			return (object) array( 'ID' => 7 );
		}

		public function test_the_list_follows_the_claim(): void {
			$this->claim( true );
			$this->assertSame( array(), \ReportedIP_Hive_Schema::unclaimed_legacy_tables() );
			$GLOBALS['wp_filters']['reportedip_hive_schema_tables'] = array();
			$this->claim( false );
			$this->assertSame( array( 'reportedip_hive_audit_log' ), \ReportedIP_Hive_Schema::unclaimed_legacy_tables() );
		}

		public function test_a_claimed_table_is_left_to_the_add_on(): void {
			$this->claim( true );
			$this->assertSame( 0, \ReportedIP_Hive_Legacy_Data::cleanup() );
			$this->assertSame( array(), \ReportedIP_Hive_Legacy_Data::export_items( $this->user() ) );
			$this->assertSame( 0, \ReportedIP_Hive_Legacy_Data::erase( $this->user() ) );
			$this->assertSame( array(), $this->db->queries, 'Not even an existence probe.' );
		}

		public function test_a_missing_table_is_left_alone(): void {
			$this->claim( false );
			$this->db->has_table = false;
			$this->assertSame( 0, \ReportedIP_Hive_Legacy_Data::cleanup() );
			$this->assertSame( array(), \ReportedIP_Hive_Legacy_Data::export_items( $this->user() ) );
			$this->assertSame( 0, \ReportedIP_Hive_Legacy_Data::erase( $this->user() ) );
			foreach ( $this->db->queries as $sql ) {
				$this->assertStringStartsWith( 'SHOW TABLES', $sql );
			}
		}

		public function test_cleanup_uses_the_stored_retention_or_the_2_x_default(): void {
			$this->claim( false );
			$this->assertSame( 2, \ReportedIP_Hive_Legacy_Data::cleanup() );
			$this->assertContains( 'DELETE FROM wp_reportedip_hive_audit_log WHERE created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 90 DAY) LIMIT 5000', $this->db->queries );

			$this->db->queries = array();
			$this->set_mocked_option( 'reportedip_hive_audit_retention_days', 30 );
			\ReportedIP_Hive_Legacy_Data::cleanup();
			$this->assertContains( 'DELETE FROM wp_reportedip_hive_audit_log WHERE created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY) LIMIT 5000', $this->db->queries );
		}

		public function test_export_lists_the_rows_of_the_user_and_about_the_user(): void {
			$this->claim( false );
			$this->db->rows = array(
				(object) array(
					'id'           => 12,
					'created_at'   => '2026-09-01 10:00:00',
					'ip'           => '198.51.100.7',
					'event_type'   => 'settings',
					'event_action' => 'updated',
					'event_data'   => '{"option":"blogname"}',
				),
			);
			$items = \ReportedIP_Hive_Legacy_Data::export_items( $this->user() );

			$this->assertCount( 1, $items );
			$this->assertSame( 'reportedip-hive-audit', $items[0]['group_id'] );
			$this->assertSame( 'rip-hive-audit-12', $items[0]['item_id'] );
			$this->assertSame( array( 'Time', 'Event', 'Action', 'IP address', 'Details' ), array_column( $items[0]['data'], 'name' ) );
			$this->assertSame( '198.51.100.7', $items[0]['data'][3]['value'] );
			$this->assertStringContainsString( "WHERE user_id = 7 OR (object_type = 'user' AND object_id = 7)", (string) end( $this->db->queries ) );
		}

		public function test_erase_blanks_actor_and_object_rows(): void {
			$this->claim( false );
			$this->assertSame( 4, \ReportedIP_Hive_Legacy_Data::erase( $this->user() ) );
			$updates = array_values( array_filter( $this->db->queries, static fn( $sql ) => 0 === strpos( $sql, 'UPDATE' ) ) );
			$this->assertSame(
				array(
					"UPDATE wp_reportedip_hive_audit_log SET username = '', ip = '', user_id = NULL, event_data = NULL WHERE user_id = 7",
					"UPDATE wp_reportedip_hive_audit_log SET object_label = NULL, event_data = NULL WHERE object_type = 'user' AND object_id = 7",
				),
				$updates
			);
		}

		public function test_a_table_from_before_2_1_62_has_no_object_rows(): void {
			$this->claim( false );
			$this->db->has_objects = false;

			\ReportedIP_Hive_Legacy_Data::export_items( $this->user() );
			$this->assertStringEndsWith( 'WHERE user_id = 7', (string) end( $this->db->queries ) );

			$this->db->queries = array();
			$this->assertSame( 2, \ReportedIP_Hive_Legacy_Data::erase( $this->user() ) );
			$updates = array_filter( $this->db->queries, static fn( $sql ) => 0 === strpos( $sql, 'UPDATE' ) );
			$this->assertCount( 1, $updates );
		}
	}
}
