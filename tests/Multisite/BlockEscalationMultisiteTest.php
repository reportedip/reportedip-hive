<?php
/**
 * Multisite regression tests for network-table access from a subsite.
 *
 * On a subsite `$wpdb->prefix` resolves to the per-blog prefix while every
 * plugin table lives under `$wpdb->base_prefix`. In 2.1.25 several read
 * paths built table names from the per-blog prefix and queried tables that
 * do not exist — block escalation silently restarted at ladder step 1 on
 * every subsite and each decision flooded the DB error log. These tests
 * exercise the affected reads under `switch_to_blog()` where the two
 * prefixes genuinely differ.
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
class ReportedIP_Hive_Block_Escalation_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Subsite created for the switched-blog context.
	 *
	 * @var int
	 */
	private $blog_id;

	/**
	 * Skip on single-site runs, ensure tables, create a subsite.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
		$this->blog_id = self::factory()->blog->create();
	}

	/**
	 * Remove fixture rows so repeated runs start clean.
	 */
	public function tear_down() {
		global $wpdb;
		$logs = ReportedIP_Hive_Schema::table( 'reportedip_hive_logs' );
		$wpdb->query( $wpdb->prepare( "DELETE FROM $logs WHERE ip_address = %s", '203.0.113.66' ) );
		parent::tear_down();
	}

	/**
	 * Seed one `ip_blocked` log row for the fixture IP via the shared table.
	 */
	private function seed_block_event() {
		global $wpdb;
		$wpdb->insert(
			ReportedIP_Hive_Schema::table( 'reportedip_hive_logs' ),
			array(
				'blog_id'    => 1,
				'event_type' => 'ip_blocked',
				'ip_address' => '203.0.113.66',
				'severity'   => 'high',
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			),
			array( '%d', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * The escalation ladder must see prior blocks from a subsite context.
	 */
	public function test_next_block_minutes_walks_ladder_on_subsite() {
		global $wpdb;

		$this->seed_block_event();
		$this->seed_block_event();

		switch_to_blog( $this->blog_id );
		$this->assertNotSame( $wpdb->base_prefix, $wpdb->prefix, 'Test precondition: switched blog must have a distinct prefix.' );

		$wpdb->last_error = '';
		$minutes          = ReportedIP_Hive_Block_Escalation::next_block_minutes( '203.0.113.66' );
		$db_error         = $wpdb->last_error;
		restore_current_blog();

		$this->assertSame( '', $db_error, 'Escalation lookup must not raise a DB error on a subsite.' );
		$this->assertSame(
			ReportedIP_Hive_Block_Escalation::DEFAULT_LADDER_MINUTES[2],
			$minutes,
			'Two prior blocks must advance the ladder to step 3, also from a subsite.'
		);
	}

	/**
	 * Whitelist and blocked cleanup reads target the network tables from a subsite.
	 */
	public function test_ip_manager_cleanup_runs_without_db_error_on_subsite() {
		global $wpdb;

		switch_to_blog( $this->blog_id );
		$wpdb->last_error = '';
		ReportedIP_Hive_IP_Manager::get_instance()->cleanup_expired_entries();
		$db_error = $wpdb->last_error;
		restore_current_blog();

		$this->assertSame( '', $db_error, 'Cleanup must touch only the network tables, which exist.' );
	}
}
