<?php
/**
 * The guard directory is the main site's on every site of the network.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.1.0
 */

/**
 * The guard bakes one queue and one blocklist path network-wide. A subsite
 * request that resolved its own uploads/sites/N directory wrote files the
 * guard never reads.
 */
class ReportedIP_Hive_Guard_Dir_Multisite_Test extends WP_UnitTestCase {

	public function test_subsite_resolves_the_main_site_guard_paths() {
		$manager   = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
		$main_dir  = $manager->guard_dir();
		$main_q    = $manager->queue_path();
		$main_list = $manager->blocklist_path();
		$this->assertNotSame( '', $main_dir );

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		try {
			$this->assertFalse( is_main_site() );
			$this->assertSame( $main_dir, $manager->guard_dir() );
			$this->assertSame( $main_q, $manager->queue_path() );
			$this->assertSame( $main_list, $manager->blocklist_path() );
			$this->assertStringNotContainsString( '/sites/' . $blog_id . '/', $manager->guard_dir() );
			$this->assertSame( $blog_id, get_current_blog_id(), 'The lookup must restore the current site.' );
		} finally {
			restore_current_blog();
		}
	}
}
