<?php
/**
 * Unit tests for the Hardening-Mode helper.
 *
 * Locks down the activation gate (PRO tier + master toggle), the effective
 * threshold clamping (`min( admin, hardening )`) and the transient-based state
 * machinery (`set_site_transient` semantics + lazy deactivation log).
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.8
 */

namespace {

	if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
		define( 'HOUR_IN_SECONDS', 3600 );
	}
	if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
		define( 'MINUTE_IN_SECONDS', 60 );
	}
	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}

	if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager_Stub_For_Hardening' ) ) {
		class ReportedIP_Hive_Mode_Manager_Stub_For_Hardening {
			public static $available = true;
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) {
					self::$instance = new self();
				}
				return self::$instance;
			}
			public function feature_status( $feature ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return array(
					'available' => self::$available,
					'reason'    => self::$available ? 'ok' : 'tier',
					'min_tier'  => 'professional',
				);
			}
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
		class_alias( 'ReportedIP_Hive_Mode_Manager_Stub_For_Hardening', 'ReportedIP_Hive_Mode_Manager' );
	}

	if ( ! class_exists( 'ReportedIP_Hive_Logger_Stub_For_Hardening' ) ) {
		class ReportedIP_Hive_Logger_Stub_For_Hardening {
			public static $events = array();
			private static $instance = null;
			public static function get_instance() {
				if ( null === self::$instance ) {
					self::$instance = new self();
				}
				return self::$instance;
			}
			public function log_security_event( $event, $ip, $details, $severity ) {
				self::$events[] = compact( 'event', 'ip', 'details', 'severity' );
			}
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
		class_alias( 'ReportedIP_Hive_Logger_Stub_For_Hardening', 'ReportedIP_Hive_Logger' );
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-hardening-mode.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class HardeningModeTest extends TestCase {

		protected function set_up() {
			parent::set_up();

			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			\ReportedIP_Hive_Logger_Stub_For_Hardening::$events          = array();
		}

		public function test_inactive_when_no_transient() {
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_active() );
			$this->assertNull( \ReportedIP_Hive_Hardening_Mode::expires_at() );
		}

		public function test_active_when_until_in_future() {
			$GLOBALS['wp_transients']['reportedip_hive_hardening_until'] = array(
				'value'   => time() + 600,
				'expires' => time() + 600,
			);

			$this->assertTrue( \ReportedIP_Hive_Hardening_Mode::is_active() );
			$this->assertGreaterThan( time(), \ReportedIP_Hive_Hardening_Mode::expires_at() );
		}

		public function test_expired_transient_treated_as_inactive_and_logs_once() {
			$GLOBALS['wp_transients']['reportedip_hive_hardening_until'] = array(
				'value'   => time() - 10,
				'expires' => time() + 86400,
			);

			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_active() );
			$logged = array_filter(
				\ReportedIP_Hive_Logger_Stub_For_Hardening::$events,
				static fn( $e ) => 'hardening_mode_deactivated' === $e['event']
			);
			$this->assertCount( 1, $logged, 'Expiry should log once via the lazy-write path.' );

			\ReportedIP_Hive_Logger_Stub_For_Hardening::$events = array();
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_active() );
			$logged_second_pass = array_filter(
				\ReportedIP_Hive_Logger_Stub_For_Hardening::$events,
				static fn( $e ) => 'hardening_mode_deactivated' === $e['event']
			);
			$this->assertCount( 0, $logged_second_pass, 'second call should not re-emit the deactivated event' );
		}

		public function test_effective_threshold_passes_through_when_inactive() {
			$this->assertSame( 5, \ReportedIP_Hive_Hardening_Mode::effective_failed_login_threshold( 5 ) );
			$this->assertSame( 15, \ReportedIP_Hive_Hardening_Mode::effective_failed_login_timeframe( 15 ) );
			$this->assertSame( 75, \ReportedIP_Hive_Hardening_Mode::effective_block_threshold( 75 ) );
		}

		public function test_effective_threshold_clamps_to_lower_during_hardening() {
			$GLOBALS['wp_transients']['reportedip_hive_hardening_until'] = array(
				'value'   => time() + 600,
				'expires' => time() + 600,
			);

			$this->assertSame( 2, \ReportedIP_Hive_Hardening_Mode::effective_failed_login_threshold( 5 ) );
			$this->assertSame( 5, \ReportedIP_Hive_Hardening_Mode::effective_failed_login_timeframe( 15 ) );
			$this->assertSame( 60, \ReportedIP_Hive_Hardening_Mode::effective_block_threshold( 75 ) );
		}

		public function test_effective_threshold_never_softens_stricter_admin_values() {
			$GLOBALS['wp_transients']['reportedip_hive_hardening_until'] = array(
				'value'   => time() + 600,
				'expires' => time() + 600,
			);

			$this->assertSame( 1, \ReportedIP_Hive_Hardening_Mode::effective_failed_login_threshold( 1 ) );
			$this->assertSame( 30, \ReportedIP_Hive_Hardening_Mode::effective_block_threshold( 30 ) );
		}

		public function test_activate_returns_false_when_tier_below_professional() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = false;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = true;

			$result = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 5, 'total_attempts' => 30, 'time_window' => '2026-05-20 10:00' ),
				'realtime'
			);

			$this->assertFalse( $result );
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_active() );
		}

		public function test_activate_returns_false_when_master_toggle_off() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = false;

			$result = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 5, 'total_attempts' => 30, 'time_window' => '2026-05-20 10:00' ),
				'realtime'
			);

			$this->assertFalse( $result );
		}

		public function test_activate_writes_transient_and_logs_event() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = true;

			$ok = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 7, 'total_attempts' => 42, 'time_window' => '2026-05-20 10:00' ),
				'realtime'
			);

			$this->assertTrue( $ok );
			$this->assertTrue( \ReportedIP_Hive_Hardening_Mode::is_active() );
			$logged = array_values(
				array_filter(
					\ReportedIP_Hive_Logger_Stub_For_Hardening::$events,
					static fn( $e ) => 'hardening_mode_activated' === $e['event']
				)
			);
			$this->assertNotEmpty( $logged );
			$this->assertSame( 'high', $logged[0]['severity'] );
			$this->assertSame( 7, $logged[0]['details']['unique_ips'] );
			$this->assertSame( 'realtime', $logged[0]['details']['trigger'] );
		}

		public function test_deactivate_clears_transient_and_logs_actor() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = true;
			\ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 5, 'total_attempts' => 25, 'time_window' => '2026-05-20 10:00' ),
				'cron'
			);

			\ReportedIP_Hive_Hardening_Mode::deactivate( 'admin' );

			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_active() );
			$logged = array_values(
				array_filter(
					\ReportedIP_Hive_Logger_Stub_For_Hardening::$events,
					static fn( $e ) => 'hardening_mode_deactivated' === $e['event']
				)
			);
			$this->assertNotEmpty( $logged );
			$this->assertSame( 'admin', $logged[0]['details']['actor'] );
		}

		public function test_activate_is_idempotent_unless_reason_more_severe() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_duration_minutes'] = 60;

			$first = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 4, 'total_attempts' => 30, 'time_window' => 'a' ),
				'cron'
			);
			$second = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 3, 'total_attempts' => 20, 'time_window' => 'b' ),
				'cron'
			);
			$third = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 10, 'total_attempts' => 80, 'time_window' => 'c' ),
				'cron'
			);

			$this->assertTrue( $first, 'first activation must take effect' );
			$this->assertFalse( $second, 'weaker reason must not extend the window' );
			$this->assertTrue( $third, 'stronger reason must re-arm the window' );
		}
	}
}
