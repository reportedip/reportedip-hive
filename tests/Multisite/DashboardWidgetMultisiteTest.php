<?php
/**
 * Multisite tests for {@see ReportedIP_Hive_Dashboard_Widget} registration.
 *
 * Verifies the capability model on Multisite: sub-site dashboards show the
 * widget only to network admins (site admins are read-only by design), and
 * the network dashboard registers it via `wp_network_dashboard_setup`.
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
class ReportedIP_Hive_Dashboard_Widget_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Skip on single-site runs and load the wp-admin dashboard helpers the
	 * widget registration path depends on.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}

		if ( ! function_exists( 'add_meta_box' ) ) {
			require_once ABSPATH . 'wp-admin/includes/template.php';
		}
		if ( ! function_exists( 'wp_add_dashboard_widget' ) ) {
			require_once ABSPATH . 'wp-admin/includes/dashboard.php';
		}
		if ( ! class_exists( 'ReportedIP_Hive_Dashboard_Widget' ) ) {
			require_once dirname( __DIR__, 2 ) . '/admin/class-dashboard-widget.php';
		}

		$GLOBALS['wp_meta_boxes'] = array();
	}

	/**
	 * Reset the screen and meta-box registry between tests.
	 */
	public function tear_down() {
		$GLOBALS['wp_meta_boxes'] = array();
		set_current_screen( 'front' );
		parent::tear_down();
	}

	/**
	 * Whether the widget is registered for the given screen id.
	 *
	 * @param string $screen_id Screen id, e.g. 'dashboard' or 'dashboard-network'.
	 * @return bool
	 */
	private function widget_registered( $screen_id ) {
		return ! empty(
			$GLOBALS['wp_meta_boxes'][ $screen_id ]['normal']['high'][ ReportedIP_Hive_Dashboard_Widget::WIDGET_ID ]
		);
	}

	/**
	 * A sub-site administrator without network capabilities must not get
	 * the widget — site admins are read-only by design.
	 */
	public function test_widget_not_registered_for_subsite_admin_without_network_cap() {
		$blog_id = self::factory()->blog->create();
		$user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		add_user_to_blog( $blog_id, $user_id, 'administrator' );

		switch_to_blog( $blog_id );
		wp_set_current_user( $user_id );
		set_current_screen( 'dashboard' );

		ReportedIP_Hive_Dashboard_Widget::init();
		do_action( 'wp_dashboard_setup' );

		$this->assertFalse( $this->widget_registered( 'dashboard' ) );
		restore_current_blog();
	}

	/**
	 * A super admin gets the widget on a sub-site dashboard.
	 */
	public function test_widget_registered_for_super_admin_on_subsite() {
		$blog_id = self::factory()->blog->create();
		$user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		grant_super_admin( $user_id );

		switch_to_blog( $blog_id );
		wp_set_current_user( $user_id );
		set_current_screen( 'dashboard' );

		ReportedIP_Hive_Dashboard_Widget::init();
		do_action( 'wp_dashboard_setup' );

		$this->assertTrue( $this->widget_registered( 'dashboard' ) );
		restore_current_blog();
	}

	/**
	 * The network dashboard registers the widget for network admins.
	 */
	public function test_widget_registered_on_network_dashboard() {
		$user_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		grant_super_admin( $user_id );
		wp_set_current_user( $user_id );
		set_current_screen( 'dashboard-network' );

		ReportedIP_Hive_Dashboard_Widget::init();
		do_action( 'wp_network_dashboard_setup' );

		$this->assertTrue( $this->widget_registered( 'dashboard-network' ) );
	}
}
