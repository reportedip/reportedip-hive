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
	 * Fully-qualified logs table name (network-wide).
	 *
	 * @var string
	 */
	private $logs;

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
		$this->logs = ReportedIP_Hive_Schema::table( 'reportedip_hive_logs' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- test fixture reset.
		$GLOBALS['wpdb']->query( "TRUNCATE TABLE {$this->logs}" );
	}

	/**
	 * Seed N distinct IPs with M real `failed_login` rows each into the logs
	 * table, staggered 30 s apart so at most two IPs share any calendar minute
	 * (well under the burst rule) while all rows stay inside the rolling window.
	 *
	 * The detectors count individual log rows, so M rows per IP contribute M to
	 * `total_attempts` — mirroring how `wp_login_failed` logs one row per attempt.
	 *
	 * @param int $ip_count        Number of distinct IPs.
	 * @param int $attempts_per_ip Number of failed_login rows per IP.
	 * @return void
	 */
	private function seed_rotating_attack( $ip_count, $attempts_per_ip ) {
		global $wpdb;
		for ( $i = 0; $i < $ip_count; $i++ ) {
			for ( $a = 0; $a < $attempts_per_ip; $a++ ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- test fixture insert.
				$wpdb->query(
					$wpdb->prepare(
						"INSERT INTO {$this->logs} (event_type, ip_address, severity, created_at)
						 VALUES ('failed_login', %s, 'medium', DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d SECOND))",
						'198.51.100.' . ( 10 + $i ),
						$i * 30
					)
				);
			}
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
		$this->seed_rotating_attack( 12, 5 );

		$monitor = new ReportedIP_Hive_Security_Monitor();
		$rows    = $monitor->check_coordinated_attacks();

		$rolling = $this->rolling_row( $rows );
		$this->assertNotNull( $rolling, 'rotating botnet must be caught by the distributed detector' );
		$this->assertSame( 12, (int) $rolling->unique_ips );
		$this->assertSame( 60, (int) $rolling->total_attempts );

		$reason = $monitor->strongest_coordinated_reason( $rows );
		$this->assertSame( 12, (int) $reason['unique_ips'], 'strongest reason reflects the distributed hit' );
	}

	public function test_same_data_does_not_trip_the_minute_burst_rule() {
		$this->seed_rotating_attack( 12, 5 );

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
		$this->seed_rotating_attack( 12, 5 );

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		try {
			$monitor = new ReportedIP_Hive_Security_Monitor();
			$rows    = $monitor->check_coordinated_attacks();
			$rolling = $this->rolling_row( $rows );
			$this->assertNotNull( $rolling, 'detector must read base_prefix, not the sub-site prefix' );
			$this->assertSame( 12, (int) $rolling->unique_ips );
		} finally {
			restore_current_blog();
		}
	}
}
