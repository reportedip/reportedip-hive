<?php
/**
 * Multisite tests for the router-aware default seeding.
 *
 * Locks down the Workstream-D fix: activation / wizard-skip seeding goes
 * through ReportedIP_Hive_Defaults::seed_missing(), which must write
 * network-wide keys into sitemeta (visible from every sub-site) instead of a
 * single blog's wp_options — the scope bug the old raw add_option() seeding had.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.2
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Defaults_Seeding_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Skip the entire class on single-site test runs.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
	}

	/**
	 * A freshly-seeded network default lands in sitemeta and is readable from a sub-site.
	 */
	public function test_seed_missing_writes_network_default_to_sitemeta() {
		delete_site_option( 'reportedip_hive_failed_login_threshold' );
		delete_option( 'reportedip_hive_failed_login_threshold' );

		ReportedIP_Hive_Defaults::seed_missing();

		$this->assertSame( 5, (int) get_site_option( 'reportedip_hive_failed_login_threshold' ) );

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		$this->assertSame(
			5,
			(int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_threshold' ),
			'Sub-site must see the network-wide seeded default.'
		);
		restore_current_blog();
	}

	/**
	 * Seeding never overwrites an existing network value.
	 */
	public function test_seed_missing_preserves_existing_network_value() {
		update_site_option( 'reportedip_hive_failed_login_threshold', 99 );

		ReportedIP_Hive_Defaults::seed_missing();

		$this->assertSame( 99, (int) get_site_option( 'reportedip_hive_failed_login_threshold' ) );
	}

	/**
	 * The three per-site override keys are never network-seeded.
	 */
	public function test_seed_missing_skips_per_site_override_keys() {
		delete_site_option( 'reportedip_hive_2fa_enforce_roles_extra' );

		ReportedIP_Hive_Defaults::seed_missing();

		$this->assertFalse(
			get_site_option( 'reportedip_hive_2fa_enforce_roles_extra', false ),
			'Per-site override keys must not be seeded into sitemeta.'
		);
	}
}
