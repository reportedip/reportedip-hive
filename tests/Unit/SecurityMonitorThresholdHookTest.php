<?php
/**
 * Tests for the `reportedip_hive_threshold_exceeded` integration hook.
 *
 * `Security_Monitor::handle_threshold_exceeded()` fires the hook once per
 * confirmed sensor detection — after the own-server and verified-bot guards
 * have passed, before any consequence (threshold log, stats, auto-block,
 * community report, admin mail) runs. The behavioural cases run the real
 * monitor with stubbed collaborators injected via reflection (the singleton
 * chain behind the constructor is not constructible in the unit harness);
 * the exact position between the guards and the consequences is anchored via
 * source inspection following the SecurityMonitorBotGuardTest idiom. The
 * tests run in separate processes so the main-class stand-in below never
 * collides with the stand-ins other test files declare.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

namespace {

	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}

	if ( ! defined( 'REPORTEDIP_USER_AGENT_MAX_LENGTH' ) ) {
		define( 'REPORTEDIP_USER_AGENT_MAX_LENGTH', 50 );
	}

	if ( ! class_exists( 'ReportedIP_Hive' ) ) {
		/**
		 * Minimal stand-in for the main plugin class, which cannot be loaded in
		 * the unit harness. Superset of the methods other unit-test stand-ins
		 * declare so file load order can never change behaviour.
		 */
		class ReportedIP_Hive {

			/**
			 * Fixed client IP, mirroring the CategoryMappingTest stand-in.
			 *
			 * @return string
			 */
			public static function get_client_ip() {
				return '127.0.0.1';
			}

			/**
			 * Fixed comment payload, mirroring the CategoryMappingTest stand-in.
			 *
			 * @param mixed $report Raw report payload.
			 * @return string
			 */
			public static function sanitize_for_api_report( $report ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return 'test';
			}

			/**
			 * Loopback addresses count as the server's own for the guard tests.
			 *
			 * @param string $ip Candidate address.
			 * @return bool
			 */
			public static function is_own_server_ip( $ip ) {
				return in_array( (string) $ip, array( '127.0.0.1', '::1' ), true );
			}

			/**
			 * Same private/reserved-range rejection as the production helper.
			 *
			 * @param string $ip Candidate address.
			 * @return bool
			 */
			public static function is_public_ip( $ip ) {
				return false !== filter_var( (string) $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
			}
		}
	}

	if ( ! class_exists( 'Test_TH_Logger_Stub' ) ) {
		/**
		 * Recording logger double.
		 */
		class Test_TH_Logger_Stub {

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

	if ( ! class_exists( 'Test_TH_Database_Stub' ) ) {
		/**
		 * Recording database double for the daily-stats write.
		 */
		class Test_TH_Database_Stub {

			/**
			 * Stat types passed to update_daily_stats().
			 *
			 * @var array<int, string>
			 */
			public $stat_calls = array();

			/**
			 * Record the stat write.
			 *
			 * @param string $stat_type Stat bucket.
			 * @param int    $increment Increment amount.
			 * @return bool
			 */
			public function update_daily_stats( $stat_type, $increment = 1 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				$this->stat_calls[] = $stat_type;
				return true;
			}
		}
	}

	if ( ! class_exists( 'Test_TH_Mode_Stub' ) ) {
		/**
		 * Mode-manager double pinned to local mode so report_security_event()
		 * stays on the log-only path and never touches the API queue.
		 */
		class Test_TH_Mode_Stub {

			/**
			 * Always local mode.
			 *
			 * @return bool
			 */
			public function is_local_mode() {
				return true;
			}
		}
	}

	if ( ! class_exists( 'Test_TH_Cache_Stub' ) ) {
		/**
		 * Cache double — unused on the exercised path, present so the injected
		 * collaborator set matches the constructor's.
		 */
		class Test_TH_Cache_Stub {

			/**
			 * Always a cache miss.
			 *
			 * @param string $ip Candidate address.
			 * @return false
			 */
			public function get_reputation( $ip ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return false;
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
	class SecurityMonitorThresholdHookTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options']    = array(
				'reportedip_hive_auto_block'   => false,
				'reportedip_hive_notify_admin' => false,
			);
			$GLOBALS['wp_transients'] = array();
			$GLOBALS['wp_actions']    = array();
		}

		/**
		 * Real monitor with stubbed collaborators injected via reflection.
		 *
		 * @param \Test_TH_Logger_Stub $logger Recording logger double.
		 * @return \ReportedIP_Hive_Security_Monitor
		 */
		private function monitor( \Test_TH_Logger_Stub $logger ): \ReportedIP_Hive_Security_Monitor {
			require_once dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php';

			$monitor = ( new \ReflectionClass( \ReportedIP_Hive_Security_Monitor::class ) )->newInstanceWithoutConstructor();

			$collaborators = array(
				'database'     => new \Test_TH_Database_Stub(),
				'api_client'   => new \stdClass(),
				'logger'       => $logger,
				'mode_manager' => new \Test_TH_Mode_Stub(),
				'cache'        => new \Test_TH_Cache_Stub(),
			);

			foreach ( $collaborators as $property => $value ) {
				$prop = new \ReflectionProperty( \ReportedIP_Hive_Security_Monitor::class, $property );
				$prop->setValue( $monitor, $value );
			}

			return $monitor;
		}

		public function test_hook_fires_with_exact_args_for_a_public_ip() {
			$captured = array();
			\add_action(
				'reportedip_hive_threshold_exceeded',
				static function ( $ip_address, $event_type, $details ) use ( &$captured ) {
					$captured[] = array( $ip_address, $event_type, $details );
				},
				10,
				3
			);

			$logger  = new \Test_TH_Logger_Stub();
			$details = array(
				'attempts'  => 7,
				'threshold' => 5,
				'timeframe' => 15,
			);

			$this->monitor( $logger )->handle_threshold_exceeded( '203.0.113.7', 'failed_login', $details );

			$this->assertCount( 1, $captured, 'The hook must fire exactly once per confirmed detection' );
			$this->assertSame( array( '203.0.113.7', 'failed_login', $details ), $captured[0], 'Listeners must receive the IP, event slug and details verbatim' );
		}

		public function test_hook_does_not_fire_for_the_own_server_ip() {
			$fired = 0;
			\add_action(
				'reportedip_hive_threshold_exceeded',
				static function () use ( &$fired ) {
					++$fired;
				},
				10,
				3
			);

			$logger = new \Test_TH_Logger_Stub();
			$this->monitor( $logger )->handle_threshold_exceeded( '127.0.0.1', 'scan_404', array( 'path' => '/feed/' ) );

			$this->assertSame( 0, $fired, 'The own-server guard precedes the hook, so self-traffic must never reach listeners' );

			$logged_events = array_column( $logger->events, 0 );
			$this->assertContains( 'own_server_ip_block_averted', $logged_events, 'The averted decision must still be visible to operators' );
			$this->assertNotContains( 'scan_404_threshold_exceeded', $logged_events, 'The guard must stand down before the threshold log as well' );
		}

		public function test_hook_sits_between_the_guards_and_the_consequences() {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php' );
			$this->assertNotSame( '', $source, 'security-monitor source must be readable' );

			$handler_pos = strpos( $source, 'function handle_threshold_exceeded' );
			$this->assertNotFalse( $handler_pos );

			$body = substr( $source, $handler_pos );

			$own_ip_pos = strpos( $body, 'should_spare_own_server_ip' );
			$bot_pos    = strpos( $body, 'should_spare_verified_bot' );
			$hook_pos   = strpos( $body, "do_action( 'reportedip_hive_threshold_exceeded'" );
			$log_pos    = strpos( $body, 'log_security_event' );

			$this->assertNotFalse( $hook_pos, 'handle_threshold_exceeded() must fire the integration hook' );
			$this->assertNotFalse( $own_ip_pos );
			$this->assertNotFalse( $bot_pos );
			$this->assertNotFalse( $log_pos );

			$this->assertLessThan( $hook_pos, $own_ip_pos, 'The own-server guard must run before the hook fires' );
			$this->assertLessThan( $hook_pos, $bot_pos, 'The verified-bot guard must run before the hook fires' );
			$this->assertLessThan( $log_pos, $hook_pos, 'The hook must fire before the threshold-exceeded log entry' );
		}
	}
}
