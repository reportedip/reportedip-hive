<?php
/**
 * Multisite tests for the API telemetry site identity (2.1.45).
 *
 * A network counts as ONE licensed domain, so api_site_url() must announce
 * the network home URL from every sub-site — never the per-site home_url().
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.45
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Api_Telemetry_Multisite_Test extends WP_UnitTestCase {

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
	 * The announced site URL is the untrailed network home URL.
	 */
	public function test_api_site_url_is_network_home_url() {
		$this->assertSame(
			untrailingslashit( network_home_url() ),
			ReportedIP_Hive_API::api_site_url()
		);
	}

	/**
	 * Switching to a sub-site must not change the announced identity —
	 * the whole network occupies one domain slot.
	 */
	public function test_api_site_url_is_stable_across_sub_sites() {
		$network_identity = ReportedIP_Hive_API::api_site_url();

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		$sub_site_home = home_url();
		$announced     = ReportedIP_Hive_API::api_site_url();
		restore_current_blog();

		$this->assertSame( $network_identity, $announced );
		$this->assertNotSame( untrailingslashit( $sub_site_home ), $announced );
	}

	/**
	 * The User-Agent carries the network identity in the wp.org shape.
	 */
	public function test_api_user_agent_carries_network_identity() {
		$ua = ReportedIP_Hive_API::api_user_agent();

		$this->assertStringContainsString( 'ReportedIP-Hive/' . REPORTEDIP_HIVE_VERSION, $ua );
		$this->assertStringContainsString( '; ' . ReportedIP_Hive_API::api_site_url() . ')', $ua );
		$this->assertStringContainsString( 'WordPress/' . get_bloginfo( 'version' ), $ua );
	}
}
