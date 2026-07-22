<?php
/**
 * Multisite smoke test for the central never-block-a-good-bot guard.
 *
 * Confirms that a threshold trip from a subsite context spares an IP inside
 * the official crawler ranges: no block row is written and the averted
 * decision lands as `verified_bot_block_averted` in the shared network logs
 * table.
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
class ReportedIP_Hive_Bot_Guard_Multisite_Test extends WP_UnitTestCase {

	const CRAWLER_IP = '66.249.66.200';

	/**
	 * Skip on single-site, ensure tables, seed a ranged crawler ruleset.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
		ReportedIP_Hive_Rule_Store::set(
			'bot_signatures',
			array(
				'key'     => 'bot_signatures',
				'version' => 99,
				'rules'   => array(
					array(
						'ua'      => 'googlebot',
						'domains' => array( '.googlebot.com' ),
						'ranges'  => array( '66.249.64.0/19' ),
					),
				),
			)
		);
	}

	/**
	 * Drop the fixture rows and the seeded ruleset.
	 */
	public function tear_down() {
		global $wpdb;
		$logs    = ReportedIP_Hive_Schema::table( 'reportedip_hive_logs' );
		$blocked = ReportedIP_Hive_Schema::table( 'reportedip_hive_blocked' );
		$wpdb->query( $wpdb->prepare( "DELETE FROM $logs WHERE ip_address = %s", self::CRAWLER_IP ) );
		$wpdb->query( $wpdb->prepare( "DELETE FROM $blocked WHERE ip_address = %s", self::CRAWLER_IP ) );
		ReportedIP_Hive_Rule_Store::delete( 'bot_signatures' );
		delete_transient( ReportedIP_Hive_Bot_Verifier::CACHE_IP_PREFIX . md5( self::CRAWLER_IP . '|99' ) );
		parent::tear_down();
	}

	/**
	 * A threshold trip from a subsite must spare the ranged crawler IP and
	 * log the averted decision into the shared network logs table.
	 */
	public function test_threshold_trip_spares_ranged_crawler_ip_from_subsite() {
		global $wpdb;

		$blog_id = self::factory()->blog->create();
		$monitor = new ReportedIP_Hive_Security_Monitor();

		switch_to_blog( $blog_id );
		$monitor->handle_threshold_exceeded( self::CRAWLER_IP, 'failed_login', array( 'attempts' => 99 ) );
		restore_current_blog();

		$blocked = ReportedIP_Hive_Schema::table( 'reportedip_hive_blocked' );
		$this->assertSame(
			'0',
			(string) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $blocked WHERE ip_address = %s AND is_active = 1", self::CRAWLER_IP ) ),
			'An IP inside the official crawler ranges must never be auto-blocked.'
		);

		$logs = ReportedIP_Hive_Schema::table( 'reportedip_hive_logs' );
		$this->assertGreaterThan(
			0,
			(int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $logs WHERE ip_address = %s AND event_type = %s", self::CRAWLER_IP, 'verified_bot_block_averted' ) ),
			'The averted decision must land in the shared network logs table.'
		);
	}
}
