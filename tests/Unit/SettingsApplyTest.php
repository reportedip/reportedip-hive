<?php
/**
 * Unit tests for the transport-agnostic settings apply service.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.47
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-apply.php';

	if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
		/**
		 * Recording Logger double: keeps every security event in memory so
		 * the apply audit event can be asserted.
		 */
		class ReportedIP_Hive_Logger {
			/**
			 * Recorded events as [type, ip, details, severity] rows.
			 *
			 * @var array<int, array<string, mixed>>
			 */
			public static $events = array();

			/**
			 * Singleton accessor.
			 *
			 * @return self
			 */
			public static function get_instance() {
				return new self();
			}

			/**
			 * Record one event.
			 *
			 * @param string $event_type Event type.
			 * @param string $ip_address IP address.
			 * @param array  $details    Event details.
			 * @param string $severity   Severity.
			 * @return int
			 */
			public function log_security_event( $event_type, $ip_address, $details = array(), $severity = 'medium' ) {
				self::$events[] = array(
					'type'     => $event_type,
					'ip'       => $ip_address,
					'details'  => $details,
					'severity' => $severity,
				);
				return count( self::$events );
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
		/**
		 * Minimal Mode-Manager double: every gated feature is unavailable, so
		 * tier-gated writes must come back as skipped_tier.
		 */
		class ReportedIP_Hive_Mode_Manager {
			/**
			 * Singleton accessor.
			 *
			 * @return self
			 */
			public static function get_instance() {
				return new self();
			}

			/**
			 * Feature availability lookup.
			 *
			 * @param string $feature Feature slug.
			 * @return array<string, mixed>
			 */
			public function feature_status( $feature ) {
				unset( $feature );
				return array(
					'available' => false,
					'min_tier'  => 'Professional',
				);
			}
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Covers the apply pipeline: unchanged detection, invalid/unknown/tier
	 * results, cross-field validation and hash movement.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class SettingsApplyTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']            = array();
			\ReportedIP_Hive_Logger::$events = array();
		}

		public function test_admin_origin_logs_its_own_event_type() {
			\ReportedIP_Hive_Settings_Apply::apply( array( 'reportedip_hive_auto_block' => 0 ), 'admin' );
			\ReportedIP_Hive_Settings_Apply::apply( array( 'reportedip_hive_auto_block' => 1 ), 'mainwp' );

			$this->assertCount( 2, \ReportedIP_Hive_Logger::$events );
			$this->assertSame( 'settings_admin_apply', \ReportedIP_Hive_Logger::$events[0]['type'] );
			$this->assertSame( 'admin', \ReportedIP_Hive_Logger::$events[0]['details']['origin'] );
			$this->assertSame( 'settings_remote_apply', \ReportedIP_Hive_Logger::$events[1]['type'] );
			$this->assertSame( 'mainwp', \ReportedIP_Hive_Logger::$events[1]['details']['origin'] );
		}

		public function test_apply_event_names_the_acting_user() {
			$GLOBALS['wp_current_user_id'] = 42;

			\ReportedIP_Hive_Settings_Apply::apply( array( 'reportedip_hive_auto_block' => 0 ), 'admin' );

			$this->assertSame( 42, \ReportedIP_Hive_Logger::$events[0]['details']['user_id'] );
		}

		public function test_unchanged_batch_logs_nothing() {
			\ReportedIP_Hive_Settings_Apply::apply( array( 'reportedip_hive_auto_block' => 1 ), 'admin' );

			$this->assertSame( array(), \ReportedIP_Hive_Logger::$events );
		}

		public function test_unchanged_value_counts_as_success_without_write() {
			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_failed_login_threshold' => 5 ),
				'test'
			);

			$this->assertSame( 'unchanged', $result['results']['reportedip_hive_failed_login_threshold']['status'] );
			$this->assertSame( 0, $result['applied'] );
			$this->assertSame( 1, $result['unchanged'] );
			$this->assertSame( 0, $result['failed'] );
		}

		public function test_changed_value_is_applied_and_readable() {
			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_failed_login_threshold' => '9' ),
				'test'
			);

			$this->assertSame( 'applied', $result['results']['reportedip_hive_failed_login_threshold']['status'] );
			$this->assertSame( 9, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_threshold' ) );
		}

		public function test_int_values_are_clamped_to_spec_range() {
			\ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_failed_login_threshold' => 5000 ),
				'test'
			);

			$this->assertSame( 100, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_threshold' ) );
		}

		public function test_block_threshold_is_clamped_to_the_false_positive_floor() {
			\ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_block_threshold' => 5 ),
				'test'
			);

			$this->assertSame(
				\ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD,
				\ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_threshold' ),
				'sub-floor reputation thresholds mostly block legitimate visitors and must clamp up'
			);
		}

		public function test_invalid_enum_is_rejected_without_write() {
			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_bot_action' => 'nuke' ),
				'test'
			);

			$this->assertSame( 'invalid', $result['results']['reportedip_hive_bot_action']['status'] );
			$this->assertSame( 1, $result['failed'] );
			$this->assertFalse( \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_bot_action', false ) );
		}

		public function test_atomic_batch_writes_nothing_when_one_key_is_rejected() {
			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array(
					'reportedip_hive_auto_block' => 0,
					'reportedip_hive_block_tor'  => 1,
					'reportedip_hive_bot_action' => 'nuke',
				),
				'admin',
				true
			);

			$this->assertSame( 0, $result['applied'] );
			$this->assertSame( 0, $result['unchanged'] );
			$this->assertSame( array( 'reportedip_hive_block_tor', 'reportedip_hive_bot_action' ), array_keys( $result['results'] ), 'only the rejections are reported' );
			$this->assertSame( 'skipped_tier', $result['results']['reportedip_hive_block_tor']['status'] );
			$this->assertSame( 'invalid', $result['results']['reportedip_hive_bot_action']['status'] );
			$this->assertArrayNotHasKey( 'reportedip_hive_auto_block', $GLOBALS['wp_options'], 'the passing sibling must not be written' );
			$this->assertSame( array(), \ReportedIP_Hive_Logger::$events, 'an aborted batch logs nothing' );
		}

		public function test_atomic_batch_applies_when_every_key_passes() {
			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array(
					'reportedip_hive_auto_block'             => 0,
					'reportedip_hive_failed_login_threshold' => 5,
				),
				'admin',
				true
			);

			$this->assertSame( 1, $result['applied'] );
			$this->assertSame( 1, $result['unchanged'] );
			$this->assertSame( 'applied', $result['results']['reportedip_hive_auto_block']['status'] );
			$this->assertSame( 'unchanged', $result['results']['reportedip_hive_failed_login_threshold']['status'] );
			$this->assertSame( 'settings_admin_apply', \ReportedIP_Hive_Logger::$events[0]['type'] );
		}

		public function test_unknown_key_is_reported_and_batch_continues() {
			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array(
					'reportedip_hive_does_not_exist' => 1,
					'reportedip_hive_auto_block'     => 0,
				),
				'test'
			);

			$this->assertSame( 'unknown_key', $result['results']['reportedip_hive_does_not_exist']['status'] );
			$this->assertSame( 'applied', $result['results']['reportedip_hive_auto_block']['status'] );
		}

		public function test_tier_gated_enable_is_skipped_without_write() {
			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_block_tor' => 1 ),
				'test'
			);

			$this->assertSame( 'skipped_tier', $result['results']['reportedip_hive_block_tor']['status'] );
			$this->assertSame( 0, $result['applied'] );
			$this->assertFalse( (bool) \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_tor', false ) );
		}

		public function test_tier_gated_disable_is_always_allowed() {
			$GLOBALS['wp_options']['reportedip_hive_block_tor'] = 1;

			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_block_tor' => 0 ),
				'test'
			);

			$this->assertSame( 'applied', $result['results']['reportedip_hive_block_tor']['status'] );
		}

		public function test_paranoia_level_one_passes_gate_but_two_is_skipped() {
			$GLOBALS['wp_options']['reportedip_hive_waf_paranoia'] = 2;

			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_waf_paranoia' => 1 ),
				'test'
			);
			$this->assertSame( 'applied', $result['results']['reportedip_hive_waf_paranoia']['status'] );

			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_waf_paranoia' => 3 ),
				'test'
			);
			$this->assertSame( 'skipped_tier', $result['results']['reportedip_hive_waf_paranoia']['status'] );
		}

		public function test_hide_login_cannot_be_enabled_without_slug() {
			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_hide_login_enabled' => 1 ),
				'test'
			);

			$this->assertSame( 'invalid', $result['results']['reportedip_hive_hide_login_enabled']['status'] );
			$this->assertFalse( (bool) \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_enabled', false ) );
		}

		public function test_hash_changes_only_when_a_value_changes() {
			$before = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$unchanged = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_auto_block' => 1 ),
				'test'
			);
			$this->assertSame( $before, $unchanged['hash'] );

			$changed = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_auto_block' => 0 ),
				'test'
			);
			$this->assertNotSame( $before, $changed['hash'] );
		}

		public function test_json_list_is_canonically_reencoded() {
			$result = \ReportedIP_Hive_Settings_Apply::apply(
				array( 'reportedip_hive_2fa_enforce_action' => 'lockout' ),
				'test'
			);
			$this->assertSame( 'applied', $result['results']['reportedip_hive_2fa_enforce_action']['status'] );
			$this->assertSame( 'lockout', \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_enforce_action' ) );
		}
	}
}
