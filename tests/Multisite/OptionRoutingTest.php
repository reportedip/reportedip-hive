<?php
/**
 * Multisite tests for ReportedIP_Hive_Option_Routing.
 *
 * Verifies that the routing layer reaches into sitemeta for network options
 * and stays in `wp_options` for the explicit per-site keys, plus that the
 * resolve helpers merge values correctly.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Option_Routing_Multisite_Test extends WP_UnitTestCase {

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
	 * Network keys land in sitemeta and survive switch_to_blog().
	 */
	public function test_network_option_is_stored_in_sitemeta() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_api_endpoint', 'https://example.test/api' );

		$this->assertSame( 'https://example.test/api', get_site_option( 'reportedip_hive_api_endpoint' ) );

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		$this->assertSame(
			'https://example.test/api',
			ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_endpoint' )
		);
		restore_current_blog();
	}

	/**
	 * Site-override keys are per-site and do not bleed across sites.
	 */
	public function test_site_override_is_local_to_blog() {
		$site_a = self::factory()->blog->create();
		$site_b = self::factory()->blog->create();

		switch_to_blog( $site_a );
		ReportedIP_Hive_Option_Routing::set(
			'reportedip_hive_2fa_frontend_slug_site_override',
			'site-a-2fa'
		);
		restore_current_blog();

		switch_to_blog( $site_b );
		$this->assertSame(
			'',
			(string) ReportedIP_Hive_Option_Routing::get(
				'reportedip_hive_2fa_frontend_slug_site_override',
				''
			),
			'Site-B must not see Site-A override.'
		);
		restore_current_blog();

		switch_to_blog( $site_a );
		$this->assertSame(
			'site-a-2fa',
			ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_frontend_slug_site_override', '' )
		);
		restore_current_blog();
	}

	/**
	 * resolve_2fa_frontend_slug() prefers the per-site override over the network default.
	 */
	public function test_resolve_2fa_frontend_slug_prefers_site_override() {
		update_site_option( 'reportedip_hive_2fa_frontend_slug', 'network-default-2fa' );

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		update_option( 'reportedip_hive_2fa_frontend_slug_site_override', 'site-specific-2fa' );

		$this->assertSame(
			'site-specific-2fa',
			ReportedIP_Hive_Option_Routing::resolve_2fa_frontend_slug()
		);
		restore_current_blog();
	}

	/**
	 * resolve_2fa_enforce_roles() merges network and site lists, dedupes, sorts.
	 */
	public function test_resolve_2fa_enforce_roles_merges_additively() {
		update_site_option(
			'reportedip_hive_2fa_enforce_roles',
			array( 'administrator', 'editor' )
		);

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		update_option(
			'reportedip_hive_2fa_enforce_roles_extra',
			array( 'shop_manager', 'administrator' )
		);

		$resolved = ReportedIP_Hive_Option_Routing::resolve_2fa_enforce_roles();
		$this->assertSame( array( 'administrator', 'editor', 'shop_manager' ), $resolved );
		restore_current_blog();
	}
}
