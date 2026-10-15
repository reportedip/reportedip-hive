<?php
/**
 * Multisite test of the v22 migration: the 2.x update checker scheduled its
 * cron event on every site that loaded it, the cleanup clears all of them.
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
class ReportedIP_Hive_Update_Checker_Leftover_Multisite_Test extends WP_UnitTestCase {

	const HOOK = 'puc_cron_check_updates-reportedip-hive';

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
	}

	public function test_every_site_loses_the_event_and_the_network_the_state() {
		$sub = self::factory()->blog->create();
		foreach ( array( get_main_site_id(), $sub ) as $site_id ) {
			switch_to_blog( $site_id );
			wp_schedule_event( time() + 3600, 'daily', self::HOOK );
			restore_current_blog();
		}
		update_site_option( 'external_updates-reportedip-hive', array( 'lastCheck' => 1 ) );

		$method = new ReflectionMethod( ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v22' );
		$method->invoke( null );

		foreach ( array( get_main_site_id(), $sub ) as $site_id ) {
			switch_to_blog( $site_id );
			$this->assertFalse( wp_next_scheduled( self::HOOK ), "site {$site_id}" );
			restore_current_blog();
		}
		$this->assertFalse( get_site_option( 'external_updates-reportedip-hive', false ) );
	}
}
