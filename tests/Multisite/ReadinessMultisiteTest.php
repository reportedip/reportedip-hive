<?php
/**
 * Multisite behaviour of {@see ReportedIP_Hive_Readiness}.
 *
 * Every producer of a readiness issue is network-level, so the register is
 * network state: the dismissal option lives in sitemeta and is readable from
 * every sub-site, the mail-failure counter is shared across the network, and
 * a sub-site page load never writes the network-wide cache (its guard and
 * cron detectors are skipped and would otherwise poison it).
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Readiness_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Skip on single-site runs and start from clean network state.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}

		if ( ! class_exists( 'ReportedIP_Hive_Readiness' ) ) {
			require_once dirname( __DIR__, 2 ) . '/includes/class-readiness.php';
		}

		delete_site_option( ReportedIP_Hive_Readiness::OPT_STATE );
		delete_site_transient( ReportedIP_Hive_Readiness::CACHE_KEY );
		delete_site_transient( ReportedIP_Hive_Readiness::MAIL_FAIL_TRANSIENT );
	}

	/**
	 * Drop the network state again so the next test starts clean.
	 */
	public function tear_down() {
		delete_site_option( ReportedIP_Hive_Readiness::OPT_STATE );
		delete_site_transient( ReportedIP_Hive_Readiness::CACHE_KEY );
		delete_site_transient( ReportedIP_Hive_Readiness::MAIL_FAIL_TRANSIENT );
		parent::tear_down();
	}

	/**
	 * A dismissal taken in the Network Admin is network state: it lands in
	 * sitemeta, not in the main site's options table, and a sub-site sees it.
	 */
	public function test_dismiss_state_lands_in_sitemeta_and_is_visible_from_subsite() {
		$now = time();
		ReportedIP_Hive_Readiness::dismiss( 'queue_backlog', $now );

		$state = get_site_option( ReportedIP_Hive_Readiness::OPT_STATE );
		$this->assertIsArray( $state );
		$this->assertSame(
			$now + ReportedIP_Hive_Readiness::DISMISS_SECS,
			(int) $state['queue_backlog']['dismissed_until']
		);
		$this->assertFalse(
			get_option( ReportedIP_Hive_Readiness::OPT_STATE, false ),
			'Readiness state must not be written per site.'
		);

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		$from_subsite = ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Readiness::OPT_STATE, array() );
		restore_current_blog();

		$this->assertArrayHasKey( 'queue_backlog', $from_subsite );
	}

	/**
	 * Mail failures are counted once for the whole network, wherever the
	 * failing `wp_mail()` call happened.
	 */
	public function test_mail_failure_counter_is_network_wide() {
		$blog_id = self::factory()->blog->create();

		switch_to_blog( $blog_id );
		ReportedIP_Hive_Readiness::record_mail_failure( new WP_Error( 'wp_mail_failed', 'relay refused' ) );
		restore_current_blog();

		$record = get_site_transient( ReportedIP_Hive_Readiness::MAIL_FAIL_TRANSIENT );
		$this->assertIsArray( $record );
		$this->assertSame( 1, (int) $record['count'] );
	}

	/**
	 * The same narrower result must not be persisted either: pruning the
	 * guard and cron keys would wipe their first-seen timestamp and any
	 * dismissal a network administrator had taken.
	 */
	public function test_subsite_compute_does_not_prune_network_state() {
		$seed = array(
			'cron_stalled' => array(
				'first_seen'      => 1000,
				'dismissed_until' => 0,
			),
		);
		update_site_option( ReportedIP_Hive_Readiness::OPT_STATE, $seed );

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		ReportedIP_Hive_Readiness::open_issues( true );
		restore_current_blog();

		$this->assertSame(
			$seed,
			get_site_option( ReportedIP_Hive_Readiness::OPT_STATE ),
			'A sub-site must not rewrite the network-wide readiness state.'
		);
	}

	/**
	 * Writing is main-site only, reading is not: the cache is network-wide,
	 * so a sub-site render answers from it instead of paying for three more
	 * queries, and it sees the guard and cron issues its own detectors skip.
	 */
	public function test_subsite_reads_the_network_cache() {
		set_site_transient(
			ReportedIP_Hive_Readiness::CACHE_KEY,
			array(
				array(
					'key'         => 'cron_stalled',
					'severity'    => ReportedIP_Hive_Readiness::SEV_CRITICAL,
					'label'       => 'WP-Cron is not running',
					'message'     => 'seeded by the main site',
					'first_seen'  => 1000,
					'dismissable' => false,
				),
			),
			ReportedIP_Hive_Readiness::CACHE_TTL
		);

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		$issues = ReportedIP_Hive_Readiness::open_issues();
		restore_current_blog();

		$this->assertCount( 1, $issues );
		$this->assertSame( 'cron_stalled', $issues[0]['key'] );
		$this->assertArrayHasKey( 'settings_url', $issues[0] );
	}

	/**
	 * A sub-site view skips the guard and cron detectors, so it must not
	 * publish its narrower result as the network-wide cache.
	 */
	public function test_subsite_compute_does_not_write_network_cache() {
		$blog_id = self::factory()->blog->create();

		switch_to_blog( $blog_id );
		$issues = ReportedIP_Hive_Readiness::open_issues();
		restore_current_blog();

		$this->assertIsArray( $issues );
		$this->assertFalse(
			get_site_transient( ReportedIP_Hive_Readiness::CACHE_KEY ),
			'Only the main site may fill the network-wide readiness cache.'
		);
	}
}
