<?php
/**
 * Multisite tests for the fixed counting window of the generic sensors.
 *
 * Before this fix the attempt counter of `track_generic_attempt()` only
 * restarted after an idle hour. A monitoring service that called the REST
 * API every 15 minutes therefore summed up over days, crossed the burst
 * threshold and was reported as "240 requests in 5 minutes" with every
 * further call. The refused report (`ip_whitelisted`) was not remembered
 * either, so the same report went out again with every detection.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.74
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Attempt_Window_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Test address from the documentation range.
	 *
	 * @var string
	 */
	private $ip = '198.51.100.77';

	/**
	 * Skip on single-site runs, ensure tables, start from a clean counter.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
		$this->clear();
	}

	/**
	 * Remove the rows and filters the cases wrote.
	 */
	public function tear_down() {
		$this->clear();
		remove_all_filters( 'pre_http_request' );
		parent::tear_down();
	}

	/**
	 * Delete the counter rows and the cached reputation of the test address.
	 */
	private function clear() {
		global $wpdb;
		$wpdb->delete( $wpdb->base_prefix . 'reportedip_hive_attempts', array( 'ip_address' => $this->ip ) );
		ReportedIP_Hive_Cache::get_instance()->clear_ip_cache( $this->ip );
	}

	/**
	 * Seed a counter row with its first and last attempt in the past.
	 *
	 * @param int $count     Stored count.
	 * @param int $first_ago Minutes since the first attempt.
	 * @param int $last_ago  Minutes since the last attempt.
	 */
	private function seed( $count, $first_ago, $last_ago ) {
		global $wpdb;
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$wpdb->base_prefix}reportedip_hive_attempts
					(ip_address, attempt_type, attempt_count, first_attempt, last_attempt)
				 VALUES (%s, 'rest_abuse', %d, DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE), DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d MINUTE))",
				$this->ip,
				$count,
				$first_ago,
				$last_ago
			)
		);
	}

	/**
	 * A trickle that never idled for an hour restarts once the window is over.
	 */
	public function test_a_counter_older_than_the_window_restarts_instead_of_summing_up() {
		$this->seed( 265, 3000, 3 );

		$db = new ReportedIP_Hive_Database();
		$db->track_attempt( $this->ip, 'rest_abuse', null, null, 1, 5, 5 );

		$this->assertSame( 1, $db->get_attempt_count( $this->ip, 'rest_abuse', 5 ) );
	}

	/**
	 * Attempts inside the window still add up, a real burst is still caught.
	 */
	public function test_attempts_inside_the_window_still_add_up() {
		$this->seed( 10, 2, 0 );

		$db = new ReportedIP_Hive_Database();
		$db->track_attempt( $this->ip, 'rest_abuse', null, null, 1, 5, 5 );

		$this->assertSame( 11, $db->get_attempt_count( $this->ip, 'rest_abuse', 5 ) );
	}

	/**
	 * Without a window the login counter keeps its idle-only behaviour.
	 */
	public function test_without_a_window_the_idle_rule_is_unchanged() {
		$this->seed( 4, 3000, 15 );

		$db = new ReportedIP_Hive_Database();
		$db->track_attempt( $this->ip, 'rest_abuse' );

		$this->assertSame( 5, $db->get_attempt_count( $this->ip, 'rest_abuse', 60 ) );
	}

	/**
	 * The generic tracker hands its timeframe in as the window, so one more
	 * call from a slow monitor no longer fires the burst threshold.
	 */
	public function test_the_generic_tracker_does_not_fire_on_a_slow_trickle() {
		$this->seed( 265, 3000, 3 );

		$monitor = new ReportedIP_Hive_Security_Monitor();
		$fired   = $monitor->track_generic_attempt( $this->ip, 'rest_abuse', 'rest_abuse', 240, 5 );

		$this->assertFalse( $fired );
		$this->assertSame( 1, ( new ReportedIP_Hive_Database() )->get_attempt_count( $this->ip, 'rest_abuse', 5 ) );
	}

	/**
	 * A report the network refuses as whitelisted is cached as
	 * infrastructure, so the next detection spares the address.
	 */
	public function test_a_whitelisted_refusal_is_cached_as_infrastructure() {
		ReportedIP_Hive_Option_Routing::set( ReportedIP_Hive_Mode_Manager::OPTION_MODE, ReportedIP_Hive_Mode_Manager::MODE_COMMUNITY );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_api_key', 'test0123456789abcdef0123456789abcd' );
		$mode = new ReflectionProperty( 'ReportedIP_Hive_Mode_Manager', 'cached_mode' );
		$mode->setValue( ReportedIP_Hive_Mode_Manager::get_instance(), null );

		add_filter(
			'pre_http_request',
			static function () {
				return array(
					'headers'  => array(),
					'body'     => wp_json_encode(
						array(
							'code'    => 'ip_whitelisted',
							'message' => 'This IP address is whitelisted',
						)
					),
					'response' => array(
						'code'    => 400,
						'message' => 'Bad Request',
					),
					'cookies'  => array(),
				);
			}
		);

		$result = ( new ReportedIP_Hive_API() )->report_ip( $this->ip, array( 34 ), 'test' );

		ReportedIP_Hive_Option_Routing::delete( ReportedIP_Hive_Mode_Manager::OPTION_MODE );
		ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_api_key' );
		$mode->setValue( ReportedIP_Hive_Mode_Manager::get_instance(), null );

		$this->assertTrue( $result['whitelisted'] );
		$envelope = ReportedIP_Hive_Cache::get_instance()->get_reputation( $this->ip );
		$this->assertIsArray( $envelope );
		$this->assertTrue( $envelope['data']['isWhitelisted'] );
	}
}
