<?php
/**
 * Multisite tests for what a network sees right after activation.
 *
 * A network activation used to land on the plugin list with no way into
 * the quickstart: the redirect skipped the network admin, the only place
 * the quickstart exists on Multisite. A sub-site administrator could also
 * spend the network-wide marker and end on a 403. The site-admin header
 * offered the same 403 through its "Open Network Admin" button.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.1
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Network_Activation_Journey_Test extends WP_UnitTestCase {

	const MARKER = 'reportedip_hive_activation_redirect';

	/**
	 * Skip on single-site runs and start every case with a fresh marker.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		if ( ! class_exists( 'ReportedIP_Hive_Quickstart' ) ) {
			require_once dirname( __DIR__, 2 ) . '/admin/class-quickstart.php';
		}
		if ( ! class_exists( 'ReportedIP_Hive_Admin_Settings' ) ) {
			require_once dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php';
		}
		$_SERVER['REQUEST_METHOD'] = 'GET';
		unset( $_GET['activate-multi'] );
		delete_site_option( 'reportedip_hive_wizard_completed' );
		ReportedIP_Hive_Option_Routing::flush_resolve_cache();
		set_site_transient( self::MARKER, true, 300 );
	}

	/**
	 * Restore the screen and the request globals.
	 */
	public function tear_down() {
		unset( $_GET['activate-multi'], $GLOBALS['current_screen'] );
		delete_site_transient( self::MARKER );
		parent::tear_down();
	}

	/**
	 * Quickstart instance without the constructor's hook wiring.
	 *
	 * @return ReportedIP_Hive_Quickstart
	 */
	private function quickstart() {
		$quickstart = ( new ReflectionClass( 'ReportedIP_Hive_Quickstart' ) )->newInstanceWithoutConstructor();
		$property   = new ReflectionProperty( 'ReportedIP_Hive_Quickstart', 'mode_manager' );
		$property->setValue( $quickstart, ReportedIP_Hive_Mode_Manager::get_instance() );
		return $quickstart;
	}

	/**
	 * Log in a super admin and put the request on a network admin screen.
	 *
	 * @return void
	 */
	private function as_super_admin_in_network_admin() {
		$user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		grant_super_admin( $user_id );
		wp_set_current_user( $user_id );
		set_current_screen( 'dashboard-network' );
	}

	/**
	 * A network activation leads the super admin into the network quickstart.
	 */
	public function test_network_activation_lands_on_the_network_quickstart() {
		$this->as_super_admin_in_network_admin();

		$this->assertSame(
			network_admin_url( 'admin.php?page=reportedip-hive-quickstart' ),
			$this->quickstart()->activation_redirect_url()
		);
		$this->assertFalse( get_site_transient( self::MARKER ), 'The marker is one-shot.' );
	}

	/**
	 * A bulk activation stays on the plugin list.
	 */
	public function test_bulk_activation_stays_on_the_plugin_list() {
		$this->as_super_admin_in_network_admin();
		$_GET['activate-multi'] = 'true';

		$this->assertSame( '', $this->quickstart()->activation_redirect_url() );
	}

	/**
	 * A sub-site administrator cannot open the network quickstart, so the
	 * request neither redirects nor spends the marker meant for the network.
	 */
	public function test_site_admin_keeps_the_marker_for_the_network_admin() {
		$site_id = self::factory()->blog->create();
		$user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		add_user_to_blog( $site_id, $user_id, 'administrator' );
		switch_to_blog( $site_id );
		wp_set_current_user( $user_id );
		set_current_screen( 'dashboard' );

		$url = $this->quickstart()->activation_redirect_url();
		restore_current_blog();

		$this->assertSame( '', $url );
		$this->assertNotFalse( get_site_transient( self::MARKER ), 'The marker must survive for the super admin.' );
	}

	/**
	 * The site-admin header links into the network admin only for a user
	 * who may open it; anyone else would land on core's 403 page.
	 */
	public function test_site_admin_header_hides_network_link_from_site_admins() {
		$site_id = self::factory()->blog->create();
		$user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		add_user_to_blog( $site_id, $user_id, 'administrator' );
		switch_to_blog( $site_id );
		wp_set_current_user( $user_id );

		ob_start();
		ReportedIP_Hive_Admin_Settings::render_site_admin_header( 'Title', 'Subtitle' );
		$html = (string) ob_get_clean();
		restore_current_blog();

		$this->assertStringNotContainsString( '/wp-admin/network/', $html );
	}

	/**
	 * A super admin on a sub-site keeps the shortcut.
	 */
	public function test_site_admin_header_keeps_network_link_for_super_admins() {
		$user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		grant_super_admin( $user_id );
		wp_set_current_user( $user_id );

		ob_start();
		ReportedIP_Hive_Admin_Settings::render_site_admin_header( 'Title', 'Subtitle' );
		$html = (string) ob_get_clean();

		$this->assertStringContainsString( '/wp-admin/network/admin.php?page=reportedip-hive', $html );
	}
}
