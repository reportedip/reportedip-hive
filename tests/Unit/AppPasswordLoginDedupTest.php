<?php
/**
 * Tests for the app-password / failed-login dedup contract.
 *
 * One failed XML-RPC application-password login fires the
 * `application_password_failed_authentication` hook first and
 * `wp_login_failed` afterwards in the same request. The app-password sensor
 * logs and counts the wire attempt and increments a request-scoped claim
 * counter; the generic listener consumes one unit per `wp_login_failed` and
 * stands down for the duplicate row and `login` attempt bucket while spray
 * recording keeps running. The counter (not a boolean) is required because
 * XML-RPC `system.multicall` carries several independent attempts per
 * request. Behavioural cases run the real monitor with stubbed collaborators
 * injected via reflection; ordering inside `handle_failed_login()` and the
 * coordinated-detection query compensation are anchored via source inspection
 * following the SecurityMonitorThresholdHookTest idiom. The tests run in
 * separate processes so the stand-ins below never collide with the stand-ins
 * other test files declare.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.42
 */

namespace {

	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}

	if ( ! defined( 'REPORTEDIP_USER_AGENT_MAX_LENGTH' ) ) {
		define( 'REPORTEDIP_USER_AGENT_MAX_LENGTH', 50 );
	}

	if ( ! class_exists( 'Test_APD_Hardening_Stand_In' ) ) {
		/**
		 * Inert hardening-mode stand-in: threshold/timeframe pass through
		 * unchanged and the realtime coordinated probe short-circuits on
		 * `is_available()`, keeping the exercised login path free of database
		 * access the unit harness cannot provide. Aliased to
		 * `ReportedIP_Hive_Hardening_Mode` at runtime (never at file load —
		 * HardeningModeTest loads the real class during discovery in the same
		 * parent process, and a load-time declaration here would collide).
		 */
		class Test_APD_Hardening_Stand_In {

			/**
			 * Pass the configured threshold through unchanged.
			 *
			 * @param int $value Configured threshold.
			 * @return int
			 */
			public static function effective_failed_login_threshold( $value ) {
				return (int) $value;
			}

			/**
			 * Pass the configured timeframe through unchanged.
			 *
			 * @param int $value Configured timeframe.
			 * @return int
			 */
			public static function effective_failed_login_timeframe( $value ) {
				return (int) $value;
			}

			/**
			 * Hardening never available in the unit harness.
			 *
			 * @return bool
			 */
			public static function is_available() {
				return false;
			}
		}
	}

	if ( ! class_exists( 'Test_APD_Logger_Stub' ) ) {
		/**
		 * Recording logger double.
		 */
		class Test_APD_Logger_Stub {

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

	if ( ! class_exists( 'Test_APD_Database_Stub' ) ) {
		/**
		 * Recording database double for the attempt-tracking path.
		 */
		class Test_APD_Database_Stub {

			/**
			 * Every track_attempt() call, verbatim.
			 *
			 * @var array<int, array>
			 */
			public $tracked = array();

			/**
			 * Record the attempt instead of writing a counter row.
			 *
			 * @param mixed ...$args Attempt arguments.
			 * @return bool
			 */
			public function track_attempt( ...$args ) {
				$this->tracked[] = $args;
				return true;
			}

			/**
			 * No attempts on record.
			 *
			 * @param mixed ...$args Query arguments.
			 * @return int
			 */
			public function get_attempt_count( ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return 0;
			}

			/**
			 * Never blocked.
			 *
			 * @param string $ip Candidate address.
			 * @return bool
			 */
			public function is_blocked( $ip ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
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
	class AppPasswordLoginDedupTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
		}

		/**
		 * Real monitor with stubbed collaborators injected via reflection.
		 *
		 * @param \Test_APD_Database_Stub $database Recording database double.
		 * @param \Test_APD_Logger_Stub   $logger   Recording logger double.
		 * @return \ReportedIP_Hive_Security_Monitor
		 */
		private function monitor( \Test_APD_Database_Stub $database, \Test_APD_Logger_Stub $logger ): \ReportedIP_Hive_Security_Monitor {
			if ( ! class_exists( 'ReportedIP_Hive_Hardening_Mode' ) ) {
				class_alias( 'Test_APD_Hardening_Stand_In', 'ReportedIP_Hive_Hardening_Mode' );
			}

			require_once dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php';

			$monitor = ( new \ReflectionClass( \ReportedIP_Hive_Security_Monitor::class ) )->newInstanceWithoutConstructor();

			$collaborators = array(
				'database'     => $database,
				'api_client'   => new \stdClass(),
				'logger'       => $logger,
				'mode_manager' => new \stdClass(),
				'cache'        => new \stdClass(),
			);

			foreach ( $collaborators as $property => $value ) {
				$prop = new \ReflectionProperty( \ReportedIP_Hive_Security_Monitor::class, $property );
				$prop->setValue( $monitor, $value );
			}

			return $monitor;
		}

		public function test_counter_consumes_one_unit_per_wp_login_failed() {
			require_once dirname( __DIR__, 2 ) . '/includes/class-app-password-monitor.php';

			$this->assertFalse( \ReportedIP_Hive_App_Password_Monitor::consume_pending_failure(), 'A fresh request has no pending app-password failure to consume' );

			$prop = new \ReflectionProperty( \ReportedIP_Hive_App_Password_Monitor::class, 'pending_wire_failures' );
			$prop->setValue( null, 2 );

			$this->assertTrue( \ReportedIP_Hive_App_Password_Monitor::consume_pending_failure(), 'First multicall failure must be consumed' );
			$this->assertTrue( \ReportedIP_Hive_App_Password_Monitor::consume_pending_failure(), 'Second multicall failure must be consumed' );
			$this->assertFalse( \ReportedIP_Hive_App_Password_Monitor::consume_pending_failure(), 'A third wp_login_failed has no claim left and must log normally' );

			$prop->setValue( null, 5 );
			\ReportedIP_Hive_App_Password_Monitor::reset_pending_failures();
			$this->assertFalse( \ReportedIP_Hive_App_Password_Monitor::consume_pending_failure(), 'reset_pending_failures() must zero the counter' );
		}

		public function test_dedup_check_precedes_the_failed_login_log() {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
			$this->assertNotSame( '', $source, 'main plugin source must be readable' );

			$handler_pos = strpos( $source, 'function handle_failed_login' );
			$this->assertNotFalse( $handler_pos, 'handle_failed_login must exist' );

			$body = substr( $source, $handler_pos );

			$consume_pos = strpos( $body, 'ReportedIP_Hive_App_Password_Monitor::consume_pending_failure' );
			$log_pos     = strpos( $body, "log_security_event( 'failed_login'" );

			$this->assertNotFalse( $consume_pos, 'The listener must consult the app-password claim' );
			$this->assertNotFalse( $log_pos, 'The listener must still own the failed_login log' );
			$this->assertLessThan( $log_pos, $consume_pos, 'The claim must be consumed before the failed_login row is written' );

			$this->assertStringContainsString(
				'check_failed_login_threshold( $ip_address, $username, ! $deduped )',
				$body,
				'The dedup verdict must flow into the threshold check as the count flag'
			);
		}

		public function test_uncounted_call_skips_login_bucket_but_keeps_spray_recording() {
			$database = new \Test_APD_Database_Stub();
			$logger   = new \Test_APD_Logger_Stub();
			$monitor  = $this->monitor( $database, $logger );

			$result = $monitor->check_failed_login_threshold( '203.0.113.9', 'admin', false );

			$this->assertFalse( $result, 'An uncounted call must not report a threshold hit' );
			$this->assertSame( array(), $database->tracked, 'The login bucket must not be incremented for a deduped attempt' );

			$bucket = \get_transient( 'rip_spray_' . md5( '203.0.113.9' ) );
			$this->assertIsArray( $bucket, 'Spray-username recording must survive the dedup' );
			$this->assertCount( 1, $bucket, 'Exactly one username hash must be recorded' );
		}

		public function test_counted_call_tracks_the_login_bucket_once() {
			$database = new \Test_APD_Database_Stub();
			$logger   = new \Test_APD_Logger_Stub();
			$monitor  = $this->monitor( $database, $logger );

			$monitor->check_failed_login_threshold( '203.0.113.9', 'admin' );

			$this->assertCount( 1, $database->tracked, 'A normal attempt must be tracked exactly once' );
			$this->assertSame( '203.0.113.9', $database->tracked[0][0], 'The attempt must carry the client IP' );
			$this->assertSame( 'login', $database->tracked[0][1], 'The attempt must land in the login bucket' );
		}

		public function test_coordinated_queries_count_both_event_types() {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php' );
			$this->assertNotSame( '', $source, 'security-monitor source must be readable' );

			$this->assertSame(
				2,
				substr_count( $source, "IN ('failed_login','app_password_failed')" ),
				'Both coordinated-attack windows must count app_password_failed rows alongside failed_login, or deduped XML-RPC floods become invisible to hardening'
			);
		}
	}
}
