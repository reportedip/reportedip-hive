<?php
/**
 * Regression tests for re-adding a previously removed or expired whitelist entry.
 *
 * `remove_from_whitelist()` soft-deletes (`is_active = 0`) and expired entries
 * stay in the table, but the whitelist carries a UNIQUE KEY on `ip_address`.
 * A plain INSERT therefore failed with a duplicate-key error for every IP that
 * had ever been on the list — surfaced to admins as "Failed to whitelist IP
 * address." with no way to recover. These tests run against a real
 * WordPress + database.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.26
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Whitelist_Readd_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Skip the entire class on single-site test runs and make sure the plugin
	 * tables exist (idempotent).
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
	}

	/**
	 * Remove the fixture rows so repeated runs start clean.
	 */
	public function tear_down() {
		global $wpdb;
		$table = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_WHITELIST );
		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM $table WHERE ip_address IN (%s, %s)",
				'203.0.113.88',
				'2001:db8::88'
			)
		);
		parent::tear_down();
	}

	/**
	 * An IP removed from the whitelist must be addable again afterwards.
	 */
	public function test_readd_after_remove_succeeds() {
		$db = ReportedIP_Hive_Database::get_instance();

		$this->assertNotFalse( $db->add_to_whitelist( '203.0.113.88', 'first add' ) );
		$this->assertTrue( $db->remove_from_whitelist( '203.0.113.88' ) );

		$this->assertNotFalse(
			$db->add_to_whitelist( '203.0.113.88', 'second add' ),
			'Re-adding a soft-deleted IP must not fail on the unique_ip key.'
		);
		$this->assertTrue( $db->is_whitelisted( '203.0.113.88' ) );
	}

	/**
	 * An IPv6 entry whose expiry date has passed must be addable again.
	 */
	public function test_readd_after_expiry_succeeds() {
		global $wpdb;
		$db    = ReportedIP_Hive_Database::get_instance();
		$table = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_WHITELIST );

		$wpdb->insert(
			$table,
			array(
				'ip_address' => '2001:db8::88',
				'ip_type'    => 'ipv6',
				'reason'     => 'expired fixture',
				'added_by'   => 1,
				'expires_at' => '2020-01-01 00:00:00',
				'is_active'  => 1,
			),
			array( '%s', '%s', '%s', '%d', '%s', '%d' )
		);
		$this->assertFalse( $db->is_whitelisted( '2001:db8::88' ) );

		$this->assertNotFalse(
			$db->add_to_whitelist( '2001:db8::88', 'renewed' ),
			'Re-adding an expired IP must not fail on the unique_ip key.'
		);
		$this->assertTrue( $db->is_whitelisted( '2001:db8::88' ) );
	}

	/**
	 * The stale row is purged, not duplicated: exactly one row per IP remains.
	 */
	public function test_readd_leaves_single_active_row() {
		global $wpdb;
		$db    = ReportedIP_Hive_Database::get_instance();
		$table = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_WHITELIST );

		$db->add_to_whitelist( '203.0.113.88', 'first add' );
		$db->remove_from_whitelist( '203.0.113.88' );
		$db->add_to_whitelist( '203.0.113.88', 'second add' );

		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT is_active, reason FROM $table WHERE ip_address = %s", '203.0.113.88' )
		);
		$this->assertCount( 1, $rows );
		$this->assertSame( '1', (string) $rows[0]->is_active );
		$this->assertSame( 'second add', $rows[0]->reason );
	}
}
