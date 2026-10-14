<?php
/**
 * Multisite tests for the group state a 2.x release left behind: without
 * the add-on the free plugin lifts every group block and removes every
 * group whitelist entry through the IP manager, so both firewall layers
 * learn about it, and empties the group list; manual rows stay. With an
 * add-on claiming the group table it keeps out.
 *
 * The group table is created once per class (DDL commits the test
 * transaction, so it must not run inside a test); every test seeds its rows
 * inside the transaction, which the test case rolls back.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Legacy_Group_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Fully qualified name of the 2.x group table.
	 *
	 * @return string
	 */
	private static function group_table() {
		return ReportedIP_Hive_Schema::table( 'reportedip_hive_group_entries' );
	}

	public static function wpSetUpBeforeClass() {
		global $wpdb;
		$table = self::group_table();
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		$wpdb->query( "CREATE TABLE {$table} ( id bigint(20) unsigned NOT NULL AUTO_INCREMENT, ip_address varchar(45) NOT NULL, reporter varchar(100) NOT NULL DEFAULT '', kind varchar(16) NOT NULL DEFAULT '', categories varchar(255) NOT NULL DEFAULT '', origin varchar(16) NOT NULL DEFAULT 'report', since datetime DEFAULT NULL, expires datetime DEFAULT NULL, PRIMARY KEY  (id), UNIQUE KEY unique_ip (ip_address) )" );
	}

	public static function wpTearDownAfterClass() {
		global $wpdb;
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::group_table() );
	}

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		global $wpdb;
		$whitelist = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_WHITELIST );
		$blocked   = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_BLOCKED );
		$until     = gmdate( 'Y-m-d H:i:s', time() + DAY_IN_SECONDS );
		$wpdb->query( "DELETE FROM {$whitelist}" );
		$wpdb->query( "DELETE FROM {$blocked}" );
		$wpdb->query( 'DELETE FROM ' . self::group_table() );

		foreach ( array( array( '10.9.0.0/16', 'cidr', 'group' ), array( '203.0.113.5', 'ipv4', 'manual' ) ) as $row ) {
			$wpdb->insert(
				$whitelist,
				array(
					'ip_address' => $row[0],
					'ip_type'    => $row[1],
					'reason'     => 'seed',
					'added_by'   => 0,
					'source'     => $row[2],
					'is_active'  => 1,
				)
			);
		}
		foreach ( array( array( '198.51.100.10', 'group' ), array( '198.51.100.20', 'manual' ), array( '198.51.100.30', 'automatic' ) ) as $row ) {
			$wpdb->insert(
				$blocked,
				array(
					'ip_address'    => $row[0],
					'reason'        => 'seed',
					'block_type'    => $row[1],
					'blocked_until' => $until,
					'is_active'     => 1,
				)
			);
		}
		$wpdb->insert(
			self::group_table(),
			array(
				'ip_address' => '198.51.100.10',
				'reporter'   => 'web03',
			)
		);
		update_site_option( ReportedIP_Hive_Migration_Manager::VERSION_OPTION, ReportedIP_Hive_Migration_Manager::CURRENT_VERSION );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_group_etag', '"g1-9-3"' );
	}

	/**
	 * Active rows of a table, address to type or source.
	 *
	 * @param string $suffix Table suffix.
	 * @param string $column `block_type` or `source`.
	 * @return array<string,string>
	 */
	private function active( $suffix, $column ) {
		global $wpdb;
		$rows = $wpdb->get_results( 'SELECT ip_address, ' . $column . ' AS kind FROM ' . ReportedIP_Hive_Schema::table( $suffix ) . ' WHERE is_active = 1 ORDER BY ip_address' );
		$out  = array();
		foreach ( (array) $rows as $row ) {
			$out[ (string) $row->ip_address ] = (string) $row->kind;
		}
		return $out;
	}

	public function test_without_the_add_on_every_group_row_goes_and_both_layers_hear_of_it() {
		$this->assertContains( 'reportedip_hive_group_entries', ReportedIP_Hive_Schema::unclaimed_legacy_tables() );
		$unblocked = did_action( 'reportedip_hive_ip_unblocked' );
		$changed   = did_action( 'reportedip_hive_whitelist_changed' );

		$this->assertSame( 2, ReportedIP_Hive_Legacy_Data::release_groups() );

		$this->assertSame( array( '203.0.113.5' => 'manual' ), $this->active( ReportedIP_Hive_Schema::TABLE_WHITELIST, 'source' ) );
		$this->assertSame(
			array(
				'198.51.100.20' => 'manual',
				'198.51.100.30' => 'automatic',
			),
			$this->active( ReportedIP_Hive_Schema::TABLE_BLOCKED, 'block_type' )
		);
		$this->assertSame( 1, did_action( 'reportedip_hive_ip_unblocked' ) - $unblocked, 'The guard blocklist file is rewritten without the group ban.' );
		$this->assertSame( 1, did_action( 'reportedip_hive_whitelist_changed' ) - $changed, 'The guard is rebaked without the group whitelist entry.' );
		$this->assertFalse( ReportedIP_Hive_IP_Manager::get_instance()->is_whitelisted( '10.9.4.4' ) );

		global $wpdb;
		$this->assertSame( 0, (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::group_table() ) );
		$this->assertSame( '', (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_group_etag', '' ) );
		$this->assertSame( 0, ReportedIP_Hive_Legacy_Data::release_groups(), 'A second run finds nothing.' );
	}

	public function test_an_add_on_claiming_the_table_keeps_the_free_plugin_out() {
		$claim = static function ( $suffixes ) {
			return array_merge( (array) $suffixes, array( 'reportedip_hive_group_entries' ) );
		};
		add_filter( 'reportedip_hive_schema_tables', $claim );
		try {
			$this->assertSame( 0, ReportedIP_Hive_Legacy_Data::release_groups() );
		} finally {
			remove_filter( 'reportedip_hive_schema_tables', $claim );
		}
		$this->assertArrayHasKey( '10.9.0.0/16', $this->active( ReportedIP_Hive_Schema::TABLE_WHITELIST, 'source' ) );
		$this->assertArrayHasKey( '198.51.100.10', $this->active( ReportedIP_Hive_Schema::TABLE_BLOCKED, 'block_type' ) );
	}
}
