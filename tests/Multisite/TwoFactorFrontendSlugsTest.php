<?php
/**
 * Multisite coverage of the storefront 2FA slugs: the per-site override
 * wins over the network slug, the resolved value stays per blog, and a
 * save flushes the memo in the same request.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Two_Factor_Frontend_Slugs_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Skip on single-site runs, start from an empty memo.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Two_Factor_Frontend::flush_slug_memo();
	}

	/**
	 * The default slug is locked to the pre-2.0 value so existing installs
	 * do not flip to a different URL on upgrade.
	 */
	public function test_default_slugs_are_stable() {
		$this->assertSame( 'reportedip-hive-2fa', ReportedIP_Hive_Two_Factor_Frontend::DEFAULT_CHALLENGE_SLUG );
		$this->assertSame( 'reportedip-hive-2fa-setup', ReportedIP_Hive_Two_Factor_Frontend::DEFAULT_SETUP_SLUG );
	}

	/**
	 * A sub-site override wins over the network slug, for both slugs.
	 */
	public function test_site_override_wins_over_the_network_slug() {
		update_site_option( 'reportedip_hive_2fa_frontend_slug', 'network-2fa' );
		update_site_option( 'reportedip_hive_2fa_frontend_setup_slug', 'network-setup' );

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		update_option( 'reportedip_hive_2fa_frontend_slug_site_override', 'shop-2fa' );
		update_option( 'reportedip_hive_2fa_frontend_setup_slug_site_override', 'shop-setup' );

		$this->assertSame( 'shop-2fa', ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug() );
		$this->assertSame( 'shop-setup', ReportedIP_Hive_Two_Factor_Frontend::get_setup_slug() );
		restore_current_blog();

		$this->assertSame( 'network-2fa', ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug(), 'The main site keeps the network slug.' );
	}

	/**
	 * The resolved slug must not leak across `switch_to_blog()`.
	 */
	public function test_resolved_slug_is_kept_per_blog() {
		update_site_option( 'reportedip_hive_2fa_frontend_slug', 'network-2fa' );

		$site_a = self::factory()->blog->create();
		$site_b = self::factory()->blog->create();

		switch_to_blog( $site_a );
		update_option( 'reportedip_hive_2fa_frontend_slug_site_override', 'site-a-2fa' );
		$this->assertSame( 'site-a-2fa', ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug() );
		restore_current_blog();

		switch_to_blog( $site_b );
		$this->assertSame( 'network-2fa', ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug(), 'Site-B must not see Site-A cached override.' );
		restore_current_blog();
	}

	/**
	 * Saving the network slug flushes the memo, otherwise a save plus a
	 * render in the same request would echo the stale slug.
	 */
	public function test_memo_is_flushed_on_slug_update() {
		update_site_option( 'reportedip_hive_2fa_frontend_slug', 'before-save' );
		$this->assertSame( 'before-save', ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug() );

		update_site_option( 'reportedip_hive_2fa_frontend_slug', 'after-save' );
		$this->assertSame( 'after-save', ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug(), 'flush_slug_memo must fire on update_site_option_<slug-key>.' );
	}

	/**
	 * The overrides are per-site options, never network state.
	 */
	public function test_site_override_is_local_to_blog() {
		$site_a = self::factory()->blog->create();
		$site_b = self::factory()->blog->create();

		switch_to_blog( $site_a );
		$_POST['rip_2fa_frontend_slug_site_override'] = 'site-a-2fa';
		ReportedIP_Hive_Two_Factor_Frontend::save_site_overrides();
		unset( $_POST['rip_2fa_frontend_slug_site_override'] );
		restore_current_blog();

		$this->assertFalse( get_site_option( 'reportedip_hive_2fa_frontend_slug_site_override' ) );
		switch_to_blog( $site_b );
		$this->assertSame( '', (string) get_option( 'reportedip_hive_2fa_frontend_slug_site_override', '' ), 'Site-B must not see Site-A override.' );
		restore_current_blog();
		$this->assertSame( 'site-a-2fa', get_blog_option( $site_a, 'reportedip_hive_2fa_frontend_slug_site_override' ) );
	}
}
