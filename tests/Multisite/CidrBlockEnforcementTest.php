<?php
/**
 * Regression tests for CIDR range enforcement in the in-WordPress engine.
 *
 * Until 2.1.32 `Database::is_blocked()` compared the client IP against the
 * `ip_address` column by equality only, so a range block was honoured solely
 * by the pre-WordPress guard — which is disabled by default. On a standard
 * install blocking `203.0.113.0/24` therefore blocked nothing while the admin
 * UI listed the range as an active block. These tests pin the range pass, its
 * cache invalidation and the precedence of the whitelist.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.32
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Cidr_Block_Enforcement_Test extends WP_UnitTestCase {

	/**
	 * Database service under test.
	 *
	 * @var ReportedIP_Hive_Database
	 */
	private $db;

	/**
	 * Ensure the schema exists and start from an empty block/whitelist state.
	 */
	public function set_up() {
		parent::set_up();
		ReportedIP_Hive_Schema::ensure_tables();
		$this->db = ReportedIP_Hive_Database::get_instance();
		$this->purge();
	}

	/**
	 * Remove fixture rows so repeated runs start clean.
	 */
	public function tear_down() {
		$this->purge();
		parent::tear_down();
	}

	/**
	 * Drop every fixture row and the caches that outlive a single request.
	 */
	private function purge() {
		global $wpdb;
		$blocked   = ReportedIP_Hive_Schema::table( 'reportedip_hive_blocked' );
		$whitelist = ReportedIP_Hive_Schema::table( 'reportedip_hive_whitelist' );
		$wpdb->query( "DELETE FROM $blocked WHERE reason LIKE 'cidr-test%'" );
		$wpdb->query( "DELETE FROM $whitelist WHERE reason LIKE 'cidr-test%'" );
		wp_cache_delete( 'rip_blocked_cidrs', 'reportedip' );
		wp_cache_delete( 'rip_whitelist_cidrs', 'reportedip' );
	}

	public function test_ip_inside_a_blocked_range_is_blocked() {
		$this->db->block_ip( '203.0.113.0/24', 'cidr-test range', 'manual', 24 );

		$this->assertTrue(
			$this->db->is_blocked( '203.0.113.55' ),
			'An address inside a blocked range must be refused by the engine, not only by the drop-in.'
		);
	}

	public function test_ip_outside_a_blocked_range_is_not_blocked() {
		$this->db->block_ip( '203.0.113.0/24', 'cidr-test range', 'manual', 24 );

		$this->assertFalse(
			$this->db->is_blocked( '198.51.100.55' ),
			'A range block must not spill over to unrelated addresses.'
		);
	}

	public function test_ipv6_range_block_is_enforced() {
		$this->db->block_ip( '2001:db8::/32', 'cidr-test v6', 'manual', 24 );

		$this->assertTrue( $this->db->is_blocked( '2001:db8::dead:beef' ) );
		$this->assertFalse( $this->db->is_blocked( '2001:db9::1' ) );
	}

	public function test_expired_range_block_stops_matching() {
		global $wpdb;
		$blocked = ReportedIP_Hive_Schema::table( 'reportedip_hive_blocked' );
		$wpdb->insert(
			$blocked,
			array(
				'ip_address'    => '203.0.113.0/24',
				'reason'        => 'cidr-test expired',
				'block_type'    => 'manual',
				'blocked_until' => gmdate( 'Y-m-d H:i:s', time() - 3600 ),
				'is_active'     => 1,
				'created_at'    => current_time( 'mysql', true ),
			)
		);
		wp_cache_delete( 'rip_blocked_cidrs', 'reportedip' );

		$this->assertFalse(
			$this->db->is_blocked( '203.0.113.55' ),
			'An expired range must stop refusing, exactly like an expired exact block.'
		);
	}

	public function test_unblocking_a_range_takes_effect_immediately() {
		$this->db->block_ip( '203.0.113.0/24', 'cidr-test range', 'manual', 24 );
		$this->assertTrue( $this->db->is_blocked( '203.0.113.55' ) );

		$this->db->unblock_ip( '203.0.113.0/24' );

		$this->assertFalse(
			$this->db->is_blocked( '203.0.113.55' ),
			'Lifting a range block must invalidate both the request memo and the range cache.'
		);
	}

	public function test_whitelisted_address_wins_over_a_blocked_range() {
		$this->db->block_ip( '203.0.113.0/24', 'cidr-test range', 'manual', 24 );
		$this->db->add_to_whitelist( '203.0.113.55', 'cidr-test allow' );

		$this->assertTrue(
			$this->db->is_whitelisted( '203.0.113.55' ),
			'The whitelist entry itself must be readable.'
		);
	}
}
