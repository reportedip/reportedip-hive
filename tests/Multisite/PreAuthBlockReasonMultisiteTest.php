<?php
/**
 * The add-on block reason of the sign-in check: a listener on
 * `reportedip_hive_pre_auth_block_reason` can refuse a sign-in, but the free
 * plugin keeps the consequences. The whitelist still wins, the block lasts
 * at least an hour, an invalid answer blocks nothing and no answer is a
 * community report.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Pre_Auth_Block_Reason_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Saved REMOTE_ADDR.
	 *
	 * @var string|null
	 */
	private $remote;

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		$this->remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : null; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- restored in tear_down.
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_report_only_mode', 0 );
	}

	public function tear_down() {
		remove_all_filters( 'reportedip_hive_pre_auth_block_reason' );
		remove_all_filters( 'reportedip_hive_extra_block_hours' );
		if ( null === $this->remote ) {
			unset( $_SERVER['REMOTE_ADDR'] );
		} else {
			$_SERVER['REMOTE_ADDR'] = $this->remote;
		}
		parent::tear_down();
	}

	/**
	 * Run the sign-in check for an address.
	 *
	 * @param string  $ip   Client IP.
	 * @param WP_User $user User.
	 * @return WP_User|WP_Error
	 */
	private function check( $ip, $user ) {
		$_SERVER['REMOTE_ADDR'] = $ip;
		return ReportedIP_Hive::get_instance()->pre_auth_check( $user, '' );
	}

	/**
	 * Number of blocked rows for an address.
	 *
	 * @param string $ip Address.
	 * @return int
	 */
	private function blocked_rows( $ip ) {
		global $wpdb;
		$table = ReportedIP_Hive_Schema::table( 'reportedip_hive_blocked' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- test assertion.
		return (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE ip_address = %s", $ip ) );
	}

	public function test_a_slug_blocks_with_the_free_defaults_and_at_least_one_hour() {
		global $wpdb;
		add_filter(
			'reportedip_hive_pre_auth_block_reason',
			static function () {
				return 'blocked_by_reputation';
			}
		);
		add_filter( 'reportedip_hive_extra_block_hours', '__return_zero' );
		$user = self::factory()->user->create_and_get();

		$result = $this->check( '198.18.7.1', $user );
		$this->assertWPError( $result );
		$this->assertSame( 'ip_blocked', $result->get_error_code() );

		$table = ReportedIP_Hive_Schema::table( 'reportedip_hive_blocked' );
		$queue = ReportedIP_Hive_Schema::table( 'reportedip_hive_api_queue' );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- test assertions.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT reason, block_type, TIMESTAMPDIFF(MINUTE, UTC_TIMESTAMP(), blocked_until) AS minutes FROM {$table} WHERE ip_address = %s", '198.18.7.1' ) );
		$this->assertSame( 'blocked_by_reputation', $row->reason );
		$this->assertSame( 'reputation', $row->block_type );
		$this->assertGreaterThanOrEqual( 59, (int) $row->minutes, 'a listener cannot shorten the block below one hour' );
		$this->assertSame( 0, (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$queue} WHERE ip_address = %s", '198.18.7.1' ) ) );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	public function test_the_whitelist_and_an_invalid_answer_block_nothing() {
		add_filter(
			'reportedip_hive_pre_auth_block_reason',
			static function ( $reason, $ip ) {
				return '198.18.7.3' === $ip ? 'Not A Slug' : array( 'event' => 'blocked_by_reputation' );
			},
			10,
			2
		);
		$user = self::factory()->user->create_and_get();
		ReportedIP_Hive_Database::get_instance()->add_to_whitelist( '198.18.7.2', 'office' );

		$this->assertSame( $user, $this->check( '198.18.7.2', $user ), 'the whitelist wins over an add-on reason' );
		$this->assertSame( 0, $this->blocked_rows( '198.18.7.2' ) );
		$this->assertSame( $user, $this->check( '198.18.7.3', $user ), 'an answer that is not a slug blocks nothing' );
		$this->assertSame( 0, $this->blocked_rows( '198.18.7.3' ) );
	}

	public function test_without_a_listener_nothing_changes() {
		$user = self::factory()->user->create_and_get();
		$this->assertSame( $user, $this->check( '198.18.7.4', $user ) );
		$this->assertSame( 0, $this->blocked_rows( '198.18.7.4' ) );
	}
}
