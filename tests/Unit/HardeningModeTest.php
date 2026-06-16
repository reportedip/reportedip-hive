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
 * @author     Patrick Schlesinger <1@reportedip.de>
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
			public static $tier      = 'free';
			private static $instance  = null;
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
			public function tier_at_least( $min ) {
				$order = array(
					'free'         => 0,
					'contributor'  => 1,
					'professional' => 2,
					'business'     => 3,
					'enterprise'   => 4,
				);
				$cur  = isset( $order[ self::$tier ] ) ? $order[ self::$tier ] : 0;
				$need = isset( $order[ $min ] ) ? $order[ $min ] : 0;
				return $cur >= $need;
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
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$tier      = 'free';
			\ReportedIP_Hive_Logger_Stub_For_Hardening::$events          = array();
		}

		public function test_master_defaults_on_for_pro_when_option_absent() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$tier = 'professional';

			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::master_toggle_is_explicit() );
			$this->assertTrue( \ReportedIP_Hive_Hardening_Mode::is_master_enabled() );
		}

		public function test_master_defaults_off_for_free_when_option_absent() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$tier = 'free';

			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::master_toggle_is_explicit() );
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_master_enabled() );
		}

		public function test_explicit_off_wins_over_pro_default() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$tier      = 'professional';
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled'] = false;

			$this->assertTrue( \ReportedIP_Hive_Hardening_Mode::master_toggle_is_explicit() );
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_master_enabled() );
		}

		public function test_is_available_auto_on_for_pro_without_explicit_toggle() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$tier      = 'professional';
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;

			$this->assertTrue( \ReportedIP_Hive_Hardening_Mode::is_available() );
		}

		public function test_is_available_false_for_free_even_without_explicit_toggle() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$tier      = 'free';
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = false;

			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_available() );
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

		public function test_ttl_low_extends_window_without_overwriting_reason() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_duration_minutes'] = 60;

			\ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 35, 'total_attempts' => 200, 'time_window' => '2026-05-27 10:43' ),
				'cron'
			);

			$ttl_low = ( 60 * MINUTE_IN_SECONDS / 2 ) - 5;
			$GLOBALS['wp_transients']['reportedip_hive_hardening_until'] = array(
				'value'   => time() + $ttl_low,
				'expires' => time() + 90 * MINUTE_IN_SECONDS,
			);

			\ReportedIP_Hive_Logger_Stub_For_Hardening::$events = array();

			$re_arm = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 10, 'total_attempts' => 20, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);

			$this->assertTrue( $re_arm, 'TTL-low triggers extension' );

			$reason = \ReportedIP_Hive_Hardening_Mode::current_reason();
			$this->assertSame( 35, $reason['unique_ips'], 'reason must keep the stronger 35-IP trigger' );
			$this->assertSame( 200, $reason['total_attempts'] );
			$this->assertSame( '2026-05-27 10:43', $reason['time_window'] );

			$extended = array_values(
				array_filter(
					\ReportedIP_Hive_Logger_Stub_For_Hardening::$events,
					static fn( $e ) => 'hardening_mode_extended' === $e['event']
				)
			);
			$this->assertCount( 1, $extended, 'extension path emits hardening_mode_extended' );
			$this->assertSame( 'low', $extended[0]['severity'] );
			$this->assertSame( 35, $extended[0]['details']['preserved_reason']['unique_ips'] );

			$reactivated = array_values(
				array_filter(
					\ReportedIP_Hive_Logger_Stub_For_Hardening::$events,
					static fn( $e ) => 'hardening_mode_activated' === $e['event']
				)
			);
			$this->assertCount( 0, $reactivated, 'no high-severity activation log on plain extension' );
		}

		public function test_same_time_window_not_reactivated_within_retention() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_duration_minutes'] = 60;

			$first = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 10, 'total_attempts' => 20, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);
			$this->assertTrue( $first );

			\ReportedIP_Hive_Logger_Stub_For_Hardening::$events = array();

			$now = time();
			$GLOBALS['wp_transients']['reportedip_hive_hardening_until'] = array(
				'value'   => $now + 5,
				'expires' => $now + 90 * MINUTE_IN_SECONDS,
			);

			$replay = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 10, 'total_attempts' => 20, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);

			$this->assertFalse( $replay, 'same time-window must not re-emit even with TTL low' );
			$this->assertCount(
				0,
				array_filter(
					\ReportedIP_Hive_Logger_Stub_For_Hardening::$events,
					static fn( $e ) => in_array( $e['event'], array( 'hardening_mode_activated', 'hardening_mode_extended' ), true )
				),
				'no log events on suppressed replay of the same window'
			);
		}

		public function test_same_time_window_reactivates_when_more_severe() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_duration_minutes'] = 60;

			\ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 5, 'total_attempts' => 20, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);

			\ReportedIP_Hive_Logger_Stub_For_Hardening::$events = array();

			$escalated = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 25, 'total_attempts' => 80, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);

			$this->assertTrue( $escalated, 'stronger reason for the same window must re-arm' );
			$reason = \ReportedIP_Hive_Hardening_Mode::current_reason();
			$this->assertSame( 25, $reason['unique_ips'] );
		}

		public function test_post_natural_expiry_same_window_suppressed_unless_more_severe() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_duration_minutes'] = 60;

			\ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 10, 'total_attempts' => 20, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);

			$GLOBALS['wp_transients']['reportedip_hive_hardening_until'] = array(
				'value'   => time() - 10,
				'expires' => time() + 86400,
			);
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_active(), 'window naturally expired' );

			\ReportedIP_Hive_Logger_Stub_For_Hardening::$events = array();

			$replay = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 10, 'total_attempts' => 20, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);

			$this->assertFalse( $replay, 'same time_window after natural expiry must not re-arm (marker still suppresses)' );
			$this->assertCount(
				0,
				array_filter(
					\ReportedIP_Hive_Logger_Stub_For_Hardening::$events,
					static fn( $e ) => 'hardening_mode_activated' === $e['event']
				)
			);
		}

		public function test_post_natural_expiry_stronger_same_window_re_arms() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_duration_minutes'] = 60;

			\ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 5, 'total_attempts' => 20, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);

			$GLOBALS['wp_transients']['reportedip_hive_hardening_until'] = array(
				'value'   => time() - 10,
				'expires' => time() + 86400,
			);
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_active() );

			\ReportedIP_Hive_Logger_Stub_For_Hardening::$events = array();

			$re_armed = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 25, 'total_attempts' => 90, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);

			$this->assertTrue( $re_armed, 'stronger same-window candidate after expiry must re-arm' );
			$this->assertGreaterThan( time(), \ReportedIP_Hive_Hardening_Mode::expires_at() );
			$reason = \ReportedIP_Hive_Hardening_Mode::current_reason();
			$this->assertSame( 25, $reason['unique_ips'] );
		}

		public function test_deactivate_clears_marker_so_admin_override_sticks() {
			\ReportedIP_Hive_Mode_Manager_Stub_For_Hardening::$available = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_enabled']  = true;
			$GLOBALS['wp_options']['reportedip_hive_hardening_duration_minutes'] = 60;

			\ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 10, 'total_attempts' => 20, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);

			\ReportedIP_Hive_Hardening_Mode::deactivate( 'admin' );

			$marker_key = \ReportedIP_Hive_Hardening_Mode::window_marker_key( '2026-05-27 12:44' );
			$this->assertArrayNotHasKey( $marker_key, $GLOBALS['wp_transients'], 'deactivate() must clear the per-window marker' );

			\ReportedIP_Hive_Logger_Stub_For_Hardening::$events = array();

			$post = \ReportedIP_Hive_Hardening_Mode::activate(
				array( 'unique_ips' => 10, 'total_attempts' => 20, 'time_window' => '2026-05-27 12:44' ),
				'cron'
			);
			$this->assertTrue( $post, 'after admin deactivate, the marker is gone so a new sweep re-arms cleanly' );
		}

		public function test_window_marker_key_helper_returns_empty_on_blank() {
			$this->assertSame( '', \ReportedIP_Hive_Hardening_Mode::window_marker_key( '' ) );
			$this->assertSame( '', \ReportedIP_Hive_Hardening_Mode::window_marker_key( '   ' ) );
			$this->assertStringStartsWith( 'reportedip_hive_hardening_seen_', \ReportedIP_Hive_Hardening_Mode::window_marker_key( '2026-05-27 12:44' ) );
		}

		public function test_log_marker_key_helper_is_distinct_from_state_marker() {
			$wm = \ReportedIP_Hive_Hardening_Mode::window_marker_key( '2026-05-27 12:44' );
			$lm = \ReportedIP_Hive_Hardening_Mode::log_marker_key( '2026-05-27 12:44' );
			$this->assertNotSame( $wm, $lm, 'state marker and log-noise marker must live in separate transient namespaces' );
			$this->assertStringStartsWith( 'reportedip_hive_hardening_logged_window_', $lm );
		}

		public function test_distributed_detection_defaults_when_options_absent() {
			$this->assertSame( 10, \ReportedIP_Hive_Hardening_Mode::detect_window_minutes() );
			$this->assertSame( 10, \ReportedIP_Hive_Hardening_Mode::detect_min_ips() );
			$this->assertSame( 50, \ReportedIP_Hive_Hardening_Mode::detect_min_attempts() );
		}

		public function test_distributed_getters_clamp_out_of_range_values() {
			$GLOBALS['wp_options']['reportedip_hive_hardening_detect_window_minutes'] = 9999;
			$GLOBALS['wp_options']['reportedip_hive_hardening_detect_min_ips']        = 1;
			$GLOBALS['wp_options']['reportedip_hive_hardening_detect_min_attempts']   = 0;

			$this->assertSame( 120, \ReportedIP_Hive_Hardening_Mode::detect_window_minutes(), 'window clamps to 120 max' );
			$this->assertSame( 2, \ReportedIP_Hive_Hardening_Mode::detect_min_ips(), 'min IPs clamps to 2 floor' );
			$this->assertSame( 50, \ReportedIP_Hive_Hardening_Mode::detect_min_attempts(), 'zero falls back to default' );
		}

		public function test_breaches_distributed_thresholds_with_defaults() {
			$this->assertTrue( \ReportedIP_Hive_Hardening_Mode::breaches_distributed_thresholds( 10, 50 ) );
			$this->assertTrue( \ReportedIP_Hive_Hardening_Mode::breaches_distributed_thresholds( 20, 120 ) );
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::breaches_distributed_thresholds( 9, 50 ), 'too few IPs' );
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::breaches_distributed_thresholds( 10, 49 ), 'too few attempts' );
		}

		public function test_breaches_distributed_thresholds_honours_custom_options() {
			$GLOBALS['wp_options']['reportedip_hive_hardening_detect_min_ips']      = 3;
			$GLOBALS['wp_options']['reportedip_hive_hardening_detect_min_attempts'] = 10;

			$this->assertTrue( \ReportedIP_Hive_Hardening_Mode::breaches_distributed_thresholds( 3, 10 ) );
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::breaches_distributed_thresholds( 2, 10 ) );
		}

		public function test_rolling_window_bucket_label_is_stable_within_a_window() {
			$base  = 1700000000;
			$same  = \ReportedIP_Hive_Hardening_Mode::rolling_window_bucket_label( 10, $base );
			$later = \ReportedIP_Hive_Hardening_Mode::rolling_window_bucket_label( 10, $base + 120 );
			$next  = \ReportedIP_Hive_Hardening_Mode::rolling_window_bucket_label( 10, $base + 600 );

			$this->assertSame( $same, $later, 'same 10-min slice yields the same bucket label' );
			$this->assertNotSame( $same, $next, 'crossing the window boundary yields a new bucket label' );
			$this->assertStringStartsWith( 'rolling-10m-', $same );
		}

		public function test_is_rolling_window_label_discriminates_burst_from_distributed() {
			$this->assertTrue( \ReportedIP_Hive_Hardening_Mode::is_rolling_window_label( 'rolling-10m-2833333' ) );
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_rolling_window_label( '2026-05-27 12:44' ) );
			$this->assertFalse( \ReportedIP_Hive_Hardening_Mode::is_rolling_window_label( '' ) );
		}
	}
}
