<?php
/**
 * Multisite tests for the coordinated-attack detectors in Security_Monitor.
 *
 * Verifies that the distributed (rolling-window) detector catches a botnet
 * that rotates IPs across several minutes — the pattern that slips under the
 * legacy same-minute burst rule — and that the aggregate reads the network-wide
 * `base_prefix` table even when invoked from a sub-site context.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.29
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Hardening_Detection_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Fully-qualified attempts table name (network-wide).
	 *
	 * @var string
	 */
	private $attempts;

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
		$this->attempts = ReportedIP_Hive_Schema::table( 'reportedip_hive_attempts' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- test fixture reset.
		$GLOBALS['wpdb']->query( "TRUNCATE TABLE {$this->attempts}" );
	}

	/**
	 * Seed N distinct IPs, one failed-login row each, staggered one minute apart
	 * so no single calendar minute holds enough IPs to trip the burst rule.
	 *
	 * @param int $ip_count        Number of distinct IPs.
	 * @param int $attempts_per_ip attempt_count stored per IP.
	 * @return void
	 */
	private function seed_rotating_attack( $ip_count, $attempts_per_ip ) {
		global $wpdb;
		for ( $i = 0; $i < $ip_count; $i++ ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- test fixture insert.
			$wpdb->query(
				$wpdb->prepare(
					"INSERT INTO {$this->attempts} (ip_address, attempt_type, attempt_count, first_attempt, last_attempt)
					 VALUES (%s, 'login', %d, DATE_SUB(NOW(), INTERVAL %d MINUTE), DATE_SUB(NOW(), INTERVAL %d MINUTE))",
					'198.51.100.' . ( 10 + $i ),
					$attempts_per_ip,
					$i,
					$i
				)
			);
		}
	}

	/**
	 * Pull the single rolling-window row (or null) out of the detector result.
	 *
	 * @param array $rows check_coordinated_attacks() result.
	 * @return object|null
	 */
	private function rolling_row( array $rows ) {
		foreach ( $rows as $row ) {
			if ( ReportedIP_Hive_Hardening_Mode::is_rolling_window_label( (string) $row->time_window ) ) {
				return $row;
			}
		}
		return null;
	}

	public function test_rotating_botnet_is_detected_by_rolling_window() {
		$this->seed_rotating_attack( 6, 5 );

		$monitor = new ReportedIP_Hive_Security_Monitor();
		$rows    = $monitor->check_coordinated_attacks();

		$rolling = $this->rolling_row( $rows );
		$this->assertNotNull( $rolling, 'rotating botnet must be caught by the distributed detector' );
		$this->assertSame( 6, (int) $rolling->unique_ips );
		$this->assertSame( 30, (int) $rolling->total_attempts );

		$reason = $monitor->strongest_coordinated_reason( $rows );
		$this->assertSame( 6, (int) $reason['unique_ips'], 'strongest reason reflects the distributed hit' );
	}

	public function test_same_data_does_not_trip_the_minute_burst_rule() {
		$this->seed_rotating_attack( 6, 5 );

		$monitor = new ReportedIP_Hive_Security_Monitor();
		$rows    = $monitor->check_coordinated_attacks();

		foreach ( $rows as $row ) {
			if ( ! ReportedIP_Hive_Hardening_Mode::is_rolling_window_label( (string) $row->time_window ) ) {
				$this->fail( 'staggered IPs must not produce a same-minute burst row' );
			}
		}
		$this->assertTrue( true );
	}

	public function test_sparse_traffic_does_not_trigger() {
		$this->seed_rotating_attack( 2, 1 );

		$monitor = new ReportedIP_Hive_Security_Monitor();
		$rows    = $monitor->check_coordinated_attacks();

		$this->assertNull( $this->rolling_row( $rows ), 'two single attempts are below the distributed thresholds' );
	}

	public function test_detection_reads_network_wide_table_from_subsite() {
		$this->seed_rotating_attack( 6, 5 );

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		try {
			$monitor = new ReportedIP_Hive_Security_Monitor();
			$rows    = $monitor->check_coordinated_attacks();
			$rolling = $this->rolling_row( $rows );
			$this->assertNotNull( $rolling, 'detector must read base_prefix, not the sub-site prefix' );
			$this->assertSame( 6, (int) $rolling->unique_ips );
		} finally {
			restore_current_blog();
		}
	}
}
