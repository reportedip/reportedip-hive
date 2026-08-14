<?php
/**
 * Multisite + lifecycle tests for the tor_exits ruleset.
 *
 * Verifies the WPMU contract for the exit-node feed: a ruleset stored on the
 * main site is network-wide (sitemeta) and therefore visible on every
 * sub-site, and the uninstall option sweep removes the stored ruleset and its
 * ETag site-transient along with the rest of the plugin state.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Tor_Ruleset_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Skip the entire class on single-site test runs.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Rule_Store::flush_cache();
	}

	/**
	 * A sample stored exit-node ruleset distinguishable from the bundled
	 * baseline (v0, empty).
	 *
	 * @return array<string,mixed>
	 */
	private function stored_ruleset() {
		return array(
			'key'     => 'tor_exits',
			'version' => 7,
			'rules'   => array( '185.220.101.34/32', '2001:db8::/64' ),
		);
	}

	/**
	 * A tor_exits ruleset stored on the main site is visible (sitemeta) on
	 * every sub-site.
	 */
	public function test_tor_ruleset_is_visible_across_subsites() {
		ReportedIP_Hive_Rule_Store::set( 'tor_exits', $this->stored_ruleset() );

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		ReportedIP_Hive_Rule_Store::flush_cache();

		$got = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'tor_exits' );
		$this->assertSame( 7, $got['version'], 'Sub-site must see the network-wide stored exit-node ruleset, not the empty baseline.' );
		$this->assertSame( array( '185.220.101.34/32', '2001:db8::/64' ), $got['rules'] );

		restore_current_blog();
	}

	/**
	 * The uninstall option sweep removes the stored tor_exits ruleset and its
	 * ETag site-transient (both carry the `reportedip_hive_` prefix).
	 */
	public function test_uninstall_sweep_removes_tor_ruleset_state() {
		ReportedIP_Hive_Rule_Store::set( 'tor_exits', $this->stored_ruleset() );
		set_site_transient( 'reportedip_hive_ruleset_etag_tor_exits', '"tor42"', 0 );

		$this->assertNotFalse( get_site_option( 'reportedip_hive_ruleset_tor_exits', false ) );
		$this->assertSame( '"tor42"', get_site_transient( 'reportedip_hive_ruleset_etag_tor_exits' ) );

		ReportedIP_Hive_Option_Routing::delete_all_plugin_options();
		ReportedIP_Hive_Rule_Store::flush_cache();

		$this->assertSame( '__gone__', get_site_option( 'reportedip_hive_ruleset_tor_exits', '__gone__' ), 'Uninstall must remove the stored tor_exits ruleset option.' );
		$this->assertFalse( get_site_transient( 'reportedip_hive_ruleset_etag_tor_exits' ), 'Uninstall must remove the tor_exits ETag transient.' );
	}
}
