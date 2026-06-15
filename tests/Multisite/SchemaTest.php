<?php
/**
 * Multisite tests for ReportedIP_Hive_Schema.
 *
 * Verifies that the central schema is created on `base_prefix`, that the
 * blog-id-aware tables actually accept `blog_id`, and that
 * `cleanup_blog_data()` only touches the per-site rows.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Schema_Multisite_Test extends WP_UnitTestCase {

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
	}

	public function test_tables_live_under_base_prefix() {
		global $wpdb;
		$expected = $wpdb->base_prefix . 'reportedip_hive_logs';
		$actual   = ReportedIP_Hive_Schema::table( 'reportedip_hive_logs' );
		$this->assertSame( $expected, $actual );
	}

	public function test_blog_id_column_exists_on_logs() {
		$this->assertTrue(
			ReportedIP_Hive_Schema::column_exists( 'reportedip_hive_logs', 'blog_id' )
		);
		$this->assertTrue(
			ReportedIP_Hive_Schema::column_exists( 'reportedip_hive_api_queue', 'blog_id' )
		);
		$this->assertTrue(
			ReportedIP_Hive_Schema::column_exists( 'reportedip_hive_stats', 'blog_id' )
		);
	}

	public function test_network_tables_have_no_blog_id() {
		$this->assertFalse(
			ReportedIP_Hive_Schema::column_exists( 'reportedip_hive_whitelist', 'blog_id' )
		);
		$this->assertFalse(
			ReportedIP_Hive_Schema::column_exists( 'reportedip_hive_blocked', 'blog_id' )
		);
		$this->assertFalse(
			ReportedIP_Hive_Schema::column_exists( 'reportedip_hive_attempts', 'blog_id' )
		);
		$this->assertFalse(
			ReportedIP_Hive_Schema::column_exists( 'reportedip_hive_trusted_devices', 'blog_id' )
		);
		$this->assertFalse(
			ReportedIP_Hive_Schema::column_exists( 'reportedip_hive_waf_exceptions', 'blog_id' )
		);
	}

	public function test_waf_exceptions_table_exists_network_wide() {
		$this->assertTrue(
			ReportedIP_Hive_Schema::column_exists( 'reportedip_hive_waf_exceptions', 'scope' )
		);
		$this->assertSame(
			$GLOBALS['wpdb']->base_prefix . 'reportedip_hive_waf_exceptions',
			ReportedIP_Hive_Schema::table( 'reportedip_hive_waf_exceptions' )
		);
	}

	public function test_cleanup_blog_data_only_removes_target_blog_rows() {
		global $wpdb;
		$logs = ReportedIP_Hive_Schema::table( 'reportedip_hive_logs' );

		$wpdb->insert(
			$logs,
			array( 'blog_id' => 1, 'event_type' => 'test', 'ip_address' => '203.0.113.1' ),
			array( '%d', '%s', '%s' )
		);
		$wpdb->insert(
			$logs,
			array( 'blog_id' => 99, 'event_type' => 'test', 'ip_address' => '203.0.113.2' ),
			array( '%d', '%s', '%s' )
		);

		ReportedIP_Hive_Schema::cleanup_blog_data( 99 );

		$remaining_99 = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM $logs WHERE blog_id = %d", 99 )
		);
		$remaining_1  = (int) $wpdb->get_var(
			$wpdb->prepare( "SELECT COUNT(*) FROM $logs WHERE blog_id = %d", 1 )
		);

		$this->assertSame( 0, $remaining_99 );
		$this->assertGreaterThanOrEqual( 1, $remaining_1 );
	}
}
