<?php
/**
 * Unit tests for ReportedIP_Hive_Two_Factor_Recommend.
 *
 * Locks down the login-reminder counter, soft / hard threshold gating,
 * spam-guard, hardcap, role differentiation and reset-on-method-enabled.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.6.1
 */

namespace {

	if ( ! function_exists( 'get_user_meta' ) ) {
		function get_user_meta( $user_id, $key, $single = true ) {
			global $wp_user_meta;
			return isset( $wp_user_meta[ $user_id ][ $key ] ) ? $wp_user_meta[ $user_id ][ $key ] : '';
		}
	}
	if ( ! function_exists( 'update_user_meta' ) ) {
		function update_user_meta( $user_id, $key, $value ) {
			global $wp_user_meta;
			$wp_user_meta[ $user_id ][ $key ] = $value;
			return true;
		}
	}
	if ( ! function_exists( 'delete_user_meta' ) ) {
		function delete_user_meta( $user_id, $key ) {
			global $wp_user_meta;
			unset( $wp_user_meta[ $user_id ][ $key ] );
			return true;
		}
	}
	if ( ! function_exists( 'get_userdata' ) ) {
		function get_userdata( $id ) {
			global $wp_users;
			return isset( $wp_users[ $id ] ) ? $wp_users[ $id ] : false;
		}
	}
	if ( ! function_exists( 'sanitize_key' ) ) {
		function sanitize_key( $key ) {
			$key = strtolower( (string) $key );
			return preg_replace( '/[^a-z0-9_\-]/', '', $key );
		}
	}
	if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
		define( 'MINUTE_IN_SECONDS', 60 );
	}

	if ( ! class_exists( 'WP_User' ) ) {
		class WP_User {
			public $ID;
			public $roles = array();
			public function __construct( $id, $roles = array() ) {
				$this->ID    = (int) $id;
				$this->roles = (array) $roles;
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
		class ReportedIP_Hive_Two_Factor {
			public static $stub_user_methods    = array();
			public static $stub_allowed_methods = array( 'totp', 'email' );

			public static function get_user_enabled_methods( $user_id ) {
				return isset( self::$stub_user_methods[ $user_id ] )
					? self::$stub_user_methods[ $user_id ]
					: array();
			}
			public static function get_allowed_methods() {
				return self::$stub_allowed_methods;
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) ) {
		class ReportedIP_Hive_Two_Factor_Onboarding {
			const TRANSIENT_PREFIX = 'reportedip_2fa_onboarding_pending_';
			const TRANSIENT_TTL    = 1800;
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-recommend.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorRecommendTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
			$GLOBALS['wp_user_meta']  = array();
			$GLOBALS['wp_users']      = array(
				1 => new \WP_User( 1, array( 'administrator' ) ),
				2 => new \WP_User( 2, array( 'editor' ) ),
				3 => new \WP_User( 3, array( 'shop_manager' ) ),
				4 => new \WP_User( 4, array( 'customer' ) ),
				5 => new \WP_User( 5, array( 'subscriber' ) ),
			);
			\ReportedIP_Hive_Two_Factor::$stub_user_methods    = array();
			\ReportedIP_Hive_Two_Factor::$stub_allowed_methods = array( 'totp', 'email' );

			require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-recommend.php';
		}

		public function test_has_any_2fa_returns_false_when_no_methods() {
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Recommend::has_any_2fa( 1 ) );
		}

		public function test_has_any_2fa_returns_true_when_methods_present() {
			\ReportedIP_Hive_Two_Factor::$stub_user_methods[1] = array( 'totp' );
			$this->assertTrue( \ReportedIP_Hive_Two_Factor_Recommend::has_any_2fa( 1 ) );
		}

		public function test_is_site_method_available_false_when_allow_list_empty() {
			\ReportedIP_Hive_Two_Factor::$stub_allowed_methods = array();
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Recommend::is_site_method_available() );
		}

		public function test_is_site_method_available_true_when_at_least_one() {
			\ReportedIP_Hive_Two_Factor::$stub_allowed_methods = array( 'totp' );
			$this->assertTrue( \ReportedIP_Hive_Two_Factor_Recommend::is_site_method_available() );
		}

		public function test_on_login_increments_counter_from_zero_to_one() {
			\ReportedIP_Hive_Two_Factor_Recommend::on_login( 'admin', $GLOBALS['wp_users'][1] );
			$this->assertSame( 1, (int) $GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count'] );
		}

		public function test_on_login_no_double_increment_within_spam_guard() {
			\ReportedIP_Hive_Two_Factor_Recommend::on_login( 'admin', $GLOBALS['wp_users'][1] );
			\ReportedIP_Hive_Two_Factor_Recommend::on_login( 'admin', $GLOBALS['wp_users'][1] );
			$this->assertSame( 1, (int) $GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count'] );
		}

		public function test_on_login_increments_again_after_spam_guard() {
			\ReportedIP_Hive_Two_Factor_Recommend::on_login( 'admin', $GLOBALS['wp_users'][1] );
			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_last_seen'] = time() - 120;
			\ReportedIP_Hive_Two_Factor_Recommend::on_login( 'admin', $GLOBALS['wp_users'][1] );
			$this->assertSame( 2, (int) $GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count'] );
		}

		public function test_on_login_hardcap_at_99() {
			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count']     = 99;
			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_last_seen'] = time() - 120;
			\ReportedIP_Hive_Two_Factor_Recommend::on_login( 'admin', $GLOBALS['wp_users'][1] );
			$this->assertSame( 99, (int) $GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count'] );
		}

		public function test_on_login_resets_counter_when_user_already_has_2fa() {
			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count'] = 3;
			\ReportedIP_Hive_Two_Factor::$stub_user_methods[1]                = array( 'totp' );
			\ReportedIP_Hive_Two_Factor_Recommend::on_login( 'admin', $GLOBALS['wp_users'][1] );
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_reminder_count', $GLOBALS['wp_user_meta'][1] );
		}

		public function test_on_login_noop_when_reminder_disabled() {
			$GLOBALS['wp_options']['reportedip_hive_2fa_reminder_enabled'] = false;
			\ReportedIP_Hive_Two_Factor_Recommend::on_login( 'admin', $GLOBALS['wp_users'][1] );
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_reminder_count', $GLOBALS['wp_user_meta'][1] ?? array() );
		}

		public function test_on_login_noop_when_no_site_methods() {
			\ReportedIP_Hive_Two_Factor::$stub_allowed_methods = array();
			\ReportedIP_Hive_Two_Factor_Recommend::on_login( 'admin', $GLOBALS['wp_users'][1] );
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_reminder_count', $GLOBALS['wp_user_meta'][1] ?? array() );
		}

		public function test_on_login_skips_for_non_wp_user() {
			\ReportedIP_Hive_Two_Factor_Recommend::on_login( 'somebody', null );
			$this->assertSame( array(), $GLOBALS['wp_user_meta'] );
		}

		public function test_should_hard_block_false_below_threshold() {
			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count'] = 4;
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Recommend::should_hard_block( $GLOBALS['wp_users'][1] ) );
		}

		public function test_should_hard_block_true_at_threshold_for_admin() {
			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count'] = 5;
			$this->assertTrue( \ReportedIP_Hive_Two_Factor_Recommend::should_hard_block( $GLOBALS['wp_users'][1] ) );
		}

		public function test_should_hard_block_true_at_threshold_for_editor() {
			$GLOBALS['wp_user_meta'][2]['reportedip_hive_2fa_reminder_count'] = 5;
			$this->assertTrue( \ReportedIP_Hive_Two_Factor_Recommend::should_hard_block( $GLOBALS['wp_users'][2] ) );
		}

		public function test_should_hard_block_false_for_customer_even_above_threshold() {
			$GLOBALS['wp_user_meta'][4]['reportedip_hive_2fa_reminder_count'] = 99;
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Recommend::should_hard_block( $GLOBALS['wp_users'][4] ) );
		}

		public function test_should_hard_block_false_for_subscriber() {
			$GLOBALS['wp_user_meta'][5]['reportedip_hive_2fa_reminder_count'] = 99;
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Recommend::should_hard_block( $GLOBALS['wp_users'][5] ) );
		}

		public function test_should_hard_block_false_when_user_already_has_2fa() {
			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count'] = 99;
			\ReportedIP_Hive_Two_Factor::$stub_user_methods[1]                = array( 'email' );
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Recommend::should_hard_block( $GLOBALS['wp_users'][1] ) );
		}

		public function test_should_hard_block_respects_custom_threshold_and_roles() {
			$GLOBALS['wp_options']['reportedip_hive_2fa_reminder_hard_threshold'] = 3;
			$GLOBALS['wp_options']['reportedip_hive_2fa_reminder_hard_roles']     = '["administrator"]';

			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count'] = 3;
			$this->assertTrue( \ReportedIP_Hive_Two_Factor_Recommend::should_hard_block( $GLOBALS['wp_users'][1] ) );

			$GLOBALS['wp_user_meta'][2]['reportedip_hive_2fa_reminder_count'] = 99;
			$this->assertFalse(
				\ReportedIP_Hive_Two_Factor_Recommend::should_hard_block( $GLOBALS['wp_users'][2] ),
				'Editor should NOT be hard-blocked when only "administrator" is configured.'
			);
		}

		public function test_reset_clears_both_meta_keys() {
			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count']     = 4;
			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_last_seen'] = time();
			\ReportedIP_Hive_Two_Factor_Recommend::reset( 1, 'totp' );
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_reminder_count', $GLOBALS['wp_user_meta'][1] );
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_reminder_last_seen', $GLOBALS['wp_user_meta'][1] );
		}

		public function test_should_show_soft_false_when_count_zero() {
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Recommend::should_show_soft( 1 ) );
		}

		public function test_should_show_soft_true_for_customer_with_high_count() {
			$GLOBALS['wp_user_meta'][4]['reportedip_hive_2fa_reminder_count'] = 99;
			$this->assertTrue(
				\ReportedIP_Hive_Two_Factor_Recommend::should_show_soft( 4 ),
				'Customer above threshold sees soft banner because hard-block does not apply to that role.'
			);
		}

		public function test_should_show_soft_false_when_admin_in_hard_block() {
			$GLOBALS['wp_user_meta'][1]['reportedip_hive_2fa_reminder_count'] = 99;
			$this->assertFalse(
				\ReportedIP_Hive_Two_Factor_Recommend::should_show_soft( 1 ),
				'Admin past threshold gets hard-block, not soft banner.'
			);
		}
	}
}
