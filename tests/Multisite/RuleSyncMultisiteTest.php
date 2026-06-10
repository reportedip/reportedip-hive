<?php
/**
 * Multisite + lifecycle tests for the rule delivery framework.
 *
 * Verifies the WPMU contract — rulesets are network-wide (sitemeta) and visible
 * on every sub-site, the sync cron is scheduled only on the main site — and the
 * lifecycle contract: the sync job is registered on schedule and removed on
 * clear, and the uninstall option sweep removes the stored rulesets and their
 * ETag site-transients.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.2.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Rule_Sync_Multisite_Test extends WP_UnitTestCase {

	const SYNC_HOOK = 'reportedip_hive_sync_rulesets';

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
	 * A sample stored ruleset distinguishable from the bundled baseline (v0).
	 *
	 * @return array<string,mixed>
	 */
	private function stored_ruleset() {
		return array(
			'key'     => 'waf',
			'version' => 42,
			'rules'   => array( array( 'id' => 'net_rule', 'pattern' => 'x' ) ),
		);
	}

	/**
	 * A ruleset stored on the main site is visible (sitemeta) on every sub-site.
	 */
	public function test_ruleset_is_visible_across_subsites() {
		ReportedIP_Hive_Rule_Store::set( 'waf', $this->stored_ruleset() );

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		ReportedIP_Hive_Rule_Store::flush_cache();

		$got = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'waf' );
		$this->assertSame( 42, $got['version'], 'Sub-site must see the network-wide stored ruleset, not the baseline.' );

		restore_current_blog();
	}

	/**
	 * The sync cron is scheduled on the main site and cleared again.
	 */
	public function test_sync_cron_scheduled_on_main_and_cleared() {
		ReportedIP_Hive_Cron_Handler::clear_cron_jobs_static();
		$this->assertFalse( wp_next_scheduled( self::SYNC_HOOK ) );

		ReportedIP_Hive_Cron_Handler::schedule_cron_jobs_static();
		$this->assertNotFalse( wp_next_scheduled( self::SYNC_HOOK ), 'Sync cron must be scheduled on the main site.' );

		ReportedIP_Hive_Cron_Handler::clear_cron_jobs_static();
		$this->assertFalse( wp_next_scheduled( self::SYNC_HOOK ), 'Deactivation must clear the sync cron.' );
	}

	/**
	 * On a sub-site the scheduler is a no-op (is_main_site guard).
	 */
	public function test_sync_cron_not_scheduled_on_subsite() {
		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );

		ReportedIP_Hive_Cron_Handler::clear_cron_jobs_static();
		ReportedIP_Hive_Cron_Handler::schedule_cron_jobs_static();
		$this->assertFalse( wp_next_scheduled( self::SYNC_HOOK ), 'A sub-site must not schedule the sync cron.' );

		restore_current_blog();
	}

	/**
	 * The uninstall option sweep removes stored rulesets and their ETag
	 * site-transients (both carry the `reportedip_hive_` prefix).
	 */
	public function test_uninstall_sweep_removes_ruleset_state() {
		ReportedIP_Hive_Rule_Store::set( 'waf', $this->stored_ruleset() );
		set_site_transient( 'reportedip_hive_ruleset_etag_waf', '"abc123"', 0 );

		$this->assertNotFalse( get_site_option( 'reportedip_hive_ruleset_waf', false ) );
		$this->assertSame( '"abc123"', get_site_transient( 'reportedip_hive_ruleset_etag_waf' ) );

		ReportedIP_Hive_Option_Routing::delete_all_plugin_options();
		ReportedIP_Hive_Rule_Store::flush_cache();

		$this->assertSame( '__gone__', get_site_option( 'reportedip_hive_ruleset_waf', '__gone__' ), 'Uninstall must remove the stored ruleset option.' );
		$this->assertFalse( get_site_transient( 'reportedip_hive_ruleset_etag_waf' ), 'Uninstall must remove the ruleset ETag transient.' );
	}
}
