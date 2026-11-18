<?php
/**
 * Multisite tests for switching the guard on with a home page check.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.10
 */

/**
 * The one-click paths (quickstart, next steps) switch the guard on and take
 * it back when the home page answers with a server error.
 *
 * @group ms-required
 */
class ReportedIP_Hive_Dropin_Checked_Switch_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Status the stubbed home page answers with, 0 for no answer.
	 *
	 * @var int
	 */
	private $status = 200;

	/**
	 * Skip on single-site, keep the guard files untouched, stub the loopback.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
		remove_all_actions( 'update_site_option_' . ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED );
		remove_all_actions( 'update_option_' . ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED );
		delete_site_option( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED );
		add_filter( 'pre_http_request', array( $this, 'answer' ) );
	}

	/**
	 * Drop the stub and the switch.
	 */
	public function tear_down() {
		remove_filter( 'pre_http_request', array( $this, 'answer' ) );
		delete_site_option( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED );
		parent::tear_down();
	}

	/**
	 * Stubbed HTTP answer.
	 *
	 * @return array<string,mixed>|WP_Error
	 */
	public function answer() {
		if ( 0 === $this->status ) {
			return new WP_Error( 'http_request_failed', 'timeout' );
		}
		return array(
			'headers'  => array(),
			'body'     => '',
			'response' => array(
				'code'    => $this->status,
				'message' => '',
			),
			'cookies'  => array(),
		);
	}

	/**
	 * Rows of one event type.
	 *
	 * @param string $event Event type.
	 * @return int
	 */
	private function events( $event ) {
		global $wpdb;
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . $wpdb->base_prefix . 'reportedip_hive_logs WHERE event_type = %s', $event ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * The CLI run is neither Apache nor FPM, like a bare nginx stack: the
	 * guard stays off.
	 */
	public function test_server_without_auto_install_keeps_the_guard_off() {
		$dropin = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
		$this->assertFalse( $dropin->supports_auto_install() );
		$this->assertFalse( $dropin->switch_on_checked() );
		$this->assertFalse( (bool) get_site_option( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ) );
		$this->assertSame( 0, $this->events( 'waf_dropin_switched_on' ) );
	}

	public function test_an_enabled_guard_is_left_alone() {
		update_site_option( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, 1 );
		$this->assertTrue( ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->switch_on_checked() );
		$this->assertSame( 0, $this->events( 'waf_dropin_switched_on' ) );
	}

	public function test_server_error_switches_the_guard_off_and_logs() {
		update_site_option( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, 1 );
		$this->status = 500;
		$this->assertFalse( ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->check_or_revert() );
		$this->assertFalse( (bool) get_site_option( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ) );
		$this->assertSame( 1, $this->events( 'waf_dropin_rolled_back' ) );
	}

	public function test_no_answer_and_a_healthy_page_keep_the_guard() {
		update_site_option( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, 1 );
		$dropin       = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
		$this->status = 0;
		$this->assertTrue( $dropin->check_or_revert() );
		$this->status = 200;
		$this->assertTrue( $dropin->check_or_revert() );
		$this->assertTrue( (bool) get_site_option( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false ) );
		$this->assertSame( 0, $this->events( 'waf_dropin_rolled_back' ) );
	}

	public function test_delayed_check_is_wired() {
		$this->assertSame( 10, has_action( ReportedIP_Hive_WAF_Dropin_Manager::CHECK_HOOK, array( ReportedIP_Hive_WAF_Dropin_Manager::get_instance(), 'on_check' ) ) );
	}
}
