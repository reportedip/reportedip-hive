<?php
/**
 * Tests for the once-per-window log of a coordinated attack.
 *
 * `Security_Monitor::check_coordinated_attacks()` runs on every hourly sweep
 * and on the realtime probe, and its 2 h lookback returns the same window
 * again and again. The marker from `log_marker_key()` keeps
 * `coordinated_attack_detected` to one row per window. The case runs the real
 * monitor with a recording logger injected via reflection and a `$wpdb`
 * double, following the SecurityMonitorThresholdHookTest idiom.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace {

	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}

	if ( ! class_exists( 'Test_CL_Logger_Stub' ) ) {
		/**
		 * Recording logger double.
		 */
		class Test_CL_Logger_Stub {

			/**
			 * Every log_security_event() call, verbatim.
			 *
			 * @var array<int, array>
			 */
			public $events = array();

			/**
			 * Record the call instead of writing a log row.
			 *
			 * @param mixed ...$args Log arguments.
			 * @return void
			 */
			public function log_security_event( ...$args ) {
				$this->events[] = $args;
			}
		}
	}

	if ( ! class_exists( 'Test_CL_WPDB_Stub' ) ) {
		/**
		 * `$wpdb` double: the minute query finds one burst, the rolling-window
		 * query finds nothing.
		 */
		class Test_CL_WPDB_Stub {

			/**
			 * Network table prefix.
			 *
			 * @var string
			 */
			public $base_prefix = 'wp_';

			/**
			 * Label of the burst the minute query returns.
			 *
			 * @var string
			 */
			public $time_window = '2026-10-13 10:00';

			/**
			 * One burst row for the minute query.
			 *
			 * @param string $sql Query.
			 * @return array<int, object>
			 */
			public function get_results( $sql ) {
				unset( $sql );
				return array(
					(object) array(
						'time_window'    => $this->time_window,
						'unique_ips'     => 12,
						'total_attempts' => 60,
					),
				);
			}

			/**
			 * No row for the rolling-window query.
			 *
			 * @param string $sql Query.
			 * @return null
			 */
			public function get_row( $sql ) {
				unset( $sql );
				return null;
			}

			/**
			 * The query as given, the double ignores the arguments.
			 *
			 * @param string $sql     Query.
			 * @param mixed  ...$args Placeholder values.
			 * @return string
			 */
			public function prepare( $sql, ...$args ) {
				unset( $args );
				return $sql;
			}
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class SecurityMonitorCoordinatedLogTest extends TestCase {

		public function test_a_window_is_logged_once_however_often_it_is_found() {
			require_once dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php';
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
			$GLOBALS['wpdb']          = new \Test_CL_WPDB_Stub();

			$logger  = new \Test_CL_Logger_Stub();
			$monitor = ( new \ReflectionClass( \ReportedIP_Hive_Security_Monitor::class ) )->newInstanceWithoutConstructor();
			( new \ReflectionProperty( \ReportedIP_Hive_Security_Monitor::class, 'logger' ) )->setValue( $monitor, $logger );

			$this->assertCount( 1, $monitor->check_coordinated_attacks() );
			$this->assertCount( 1, $monitor->check_coordinated_attacks(), 'a repeated sweep still hands every row to the listeners' );
			$this->assertSame( array( 'coordinated_attack_detected' ), array_column( $logger->events, 0 ), 'the same window must not be logged twice' );

			$GLOBALS['wpdb']->time_window = '2026-10-13 11:00';
			$monitor->check_coordinated_attacks();
			$this->assertCount( 2, $logger->events, 'a new window is logged again' );
		}
	}
}
