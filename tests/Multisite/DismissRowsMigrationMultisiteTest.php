<?php
/**
 * Multisite test of the v23 migration: user meta is one network-wide
 * table, so one run removes the dated dismissal rows of every user, also
 * those written on a sub-site, and keeps the fixed 3.0.0 rows.
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
class ReportedIP_Hive_Dismiss_Rows_Migration_Multisite_Test extends WP_UnitTestCase {

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
	}

	public function test_dated_rows_of_every_site_go_and_fixed_rows_stay() {
		$main = self::factory()->user->create();
		$sub  = self::factory()->user->create();
		$blog = self::factory()->blog->create();
		add_user_to_blog( $blog, $sub, 'administrator' );

		update_user_meta( $main, 'reportedip_dismissed_no_api_key_2026-10-01', 1 );
		switch_to_blog( $blog );
		update_user_meta( $sub, 'reportedip_dismissed_rate_limited_2026-10-01-13', 1 );
		update_user_meta( $sub, 'reportedip_dismissed_readiness_abc123', 1 );
		restore_current_blog();
		update_user_meta( $main, 'reportedip_dismissed_no_api_key', time() );

		$method = new ReflectionMethod( ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v23' );
		$method->invoke( null );
		wp_cache_flush();

		$this->assertSame( '', get_user_meta( $main, 'reportedip_dismissed_no_api_key_2026-10-01', true ) );
		$this->assertSame( '', get_user_meta( $sub, 'reportedip_dismissed_rate_limited_2026-10-01-13', true ) );
		$this->assertSame( '', get_user_meta( $sub, 'reportedip_dismissed_readiness_abc123', true ) );
		$this->assertNotEmpty( get_user_meta( $main, 'reportedip_dismissed_no_api_key', true ), 'The fixed 3.0.0 row stays.' );
	}
}
