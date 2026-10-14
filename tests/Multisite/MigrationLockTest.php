<?php
/**
 * Multisite tests for the network-wide mutex of the migration manager.
 *
 * `add_site_option()` is not atomic on Multisite (sitemeta has no unique
 * key), so the lock is a row in the main site's options table taken with
 * `INSERT IGNORE`. The add-on uses the same primitive for its replay lock.
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
class ReportedIP_Hive_Migration_Lock_Multisite_Test extends WP_UnitTestCase {

	private const LOCK = 'reportedip_hive_test_lock';

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Migration_Manager::drop_lock( self::LOCK );
	}

	public function test_only_the_first_taker_holds_the_lock_on_every_site() {
		$this->assertTrue( ReportedIP_Hive_Migration_Manager::take_lock( self::LOCK, 60 ) );
		$this->assertFalse( ReportedIP_Hive_Migration_Manager::take_lock( self::LOCK, 60 ), 'a second request is refused' );

		$site = self::factory()->blog->create();
		switch_to_blog( $site );
		$this->assertFalse( ReportedIP_Hive_Migration_Manager::take_lock( self::LOCK, 60 ), 'the lock is network-wide, not per site' );
		restore_current_blog();

		ReportedIP_Hive_Migration_Manager::drop_lock( self::LOCK );
		$this->assertTrue( ReportedIP_Hive_Migration_Manager::take_lock( self::LOCK, 60 ), 'a released lock can be taken again' );
	}

	public function test_a_stale_lock_is_taken_over() {
		global $wpdb;
		$wpdb->insert(
			$wpdb->base_prefix . 'options',
			array(
				'option_name'  => self::LOCK,
				'option_value' => (string) ( time() - 120 ),
				'autoload'     => 'no',
			)
		);
		$this->assertTrue( ReportedIP_Hive_Migration_Manager::take_lock( self::LOCK, 60 ) );
		$this->assertFalse( ReportedIP_Hive_Migration_Manager::take_lock( self::LOCK, 60 ) );
	}
}
