<?php
/**
 * Multisite tests for the adaptive 2FA policies.
 *
 * The matrix is a network decision: a sub-site reads it but cannot change it,
 * the administrator latch counts network-wide, and a policy pushed to any
 * connected sub-site has to converge the whole network. These run against a
 * real WordPress + database so the option routing is exercised, not mocked.
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
class ReportedIP_Hive_Two_Factor_Policies_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Skip on single-site runs and pretend the Professional plan.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_known_tier', 'professional' );
		delete_site_transient( 'reportedip_hive_api_status' );
		delete_transient( 'reportedip_hive_api_status' );
		ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();

		ReportedIP_Hive_Option_Routing::set( ReportedIP_Hive_Login_Context::OPT_ADMIN_VERIFIED, time() );
	}

	/**
	 * Drop the pretended plan, the latch and the policy lists again.
	 */
	public function tear_down() {
		foreach ( ReportedIP_Hive_Two_Factor_Policies::TRIGGERS as $trigger ) {
			ReportedIP_Hive_Option_Routing::delete( ReportedIP_Hive_Two_Factor_Policies::option_key( $trigger ) );
		}
		ReportedIP_Hive_Option_Routing::delete( ReportedIP_Hive_Login_Context::OPT_ADMIN_VERIFIED );
		ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_known_tier' );
		ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		parent::tear_down();
	}

	/**
	 * A policy list written from a sub-site lands in sitemeta, never in the
	 * sub-site's own options table.
	 */
	public function test_policy_lists_are_stored_in_sitemeta() {
		$key     = ReportedIP_Hive_Two_Factor_Policies::option_key( 'new_ip' );
		$site_id = self::factory()->blog->create();

		switch_to_blog( $site_id );
		ReportedIP_Hive_Option_Routing::set( $key, '["editor"]' );
		restore_current_blog();

		$this->assertSame( '["editor"]', get_site_option( $key ) );
		$this->assertFalse( get_option( $key, false ) );
	}

	/**
	 * Every sub-site sees the network matrix.
	 */
	public function test_sub_site_reads_the_network_matrix() {
		ReportedIP_Hive_Option_Routing::set(
			ReportedIP_Hive_Two_Factor_Policies::option_key( 'new_ip' ),
			'["editor"]'
		);

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		$roles = ReportedIP_Hive_Two_Factor_Policies::roles_for( 'new_ip' );
		restore_current_blog();

		$this->assertSame( array( 'editor' ), $roles );
	}

	/**
	 * The administrator latch is one network-wide decision.
	 */
	public function test_admin_latch_is_network_wide() {
		ReportedIP_Hive_Option_Routing::delete( ReportedIP_Hive_Login_Context::OPT_ADMIN_VERIFIED );

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		$closed = ReportedIP_Hive_Login_Context::admin_latch_open();
		restore_current_blog();

		ReportedIP_Hive_Option_Routing::set( ReportedIP_Hive_Login_Context::OPT_ADMIN_VERIFIED, time() );

		switch_to_blog( $site_id );
		$open = ReportedIP_Hive_Login_Context::admin_latch_open();
		restore_current_blog();

		$this->assertFalse( $closed );
		$this->assertTrue( $open );
	}

	/**
	 * A remote apply arriving at a sub-site converges the network.
	 */
	public function test_remote_apply_of_a_policy_key_from_a_sub_site_converges_the_network() {
		$key     = ReportedIP_Hive_Two_Factor_Policies::option_key( 'new_subnet' );
		$site_id = self::factory()->blog->create();

		switch_to_blog( $site_id );
		$result = ReportedIP_Hive_Settings_Apply::apply( array( $key => '["editor"]' ), 'cloud' );
		restore_current_blog();

		$this->assertSame( 'applied', $result['results'][ $key ]['status'] );
		$this->assertSame( array( 'editor' ), ReportedIP_Hive_Two_Factor_Policies::roles_for( 'new_subnet' ) );
	}

	/**
	 * With the latch closed the sanitizer drops `administrator`, wherever the
	 * write comes from.
	 */
	public function test_administrator_is_stripped_while_the_latch_is_closed() {
		ReportedIP_Hive_Option_Routing::delete( ReportedIP_Hive_Login_Context::OPT_ADMIN_VERIFIED );

		$key    = ReportedIP_Hive_Two_Factor_Policies::option_key( 'new_device' );
		$result = ReportedIP_Hive_Settings_Apply::apply( array( $key => '["administrator","editor"]' ), 'cloud' );

		$this->assertSame( 'applied', $result['results'][ $key ]['status'] );
		$this->assertSame( array( 'editor' ), ReportedIP_Hive_Two_Factor_Policies::roles_for( 'new_device' ) );
	}
}
