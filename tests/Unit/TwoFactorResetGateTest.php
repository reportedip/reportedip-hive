<?php
/**
 * Unit tests for the password-reset 2FA gate.
 *
 * Two layers of testing:
 *   1. Source-pattern matching locks down hook wiring, constants, and the
 *      contract with the central security monitor — refactors that drop
 *      these guarantees fail the test, even if the public API still loads.
 *   2. Pure-logic tests cover the eligibility / lockout decision functions
 *      using lightweight option + user-meta stubs.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.7.0
 */

namespace {

	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}

	if ( ! function_exists( 'add_action' ) ) {
		function add_action( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'add_filter' ) ) {
		function add_filter( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $hook, $value ) { return $value; } // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'sanitize_key' ) ) {
		function sanitize_key( $key ) {
			$key = strtolower( (string) $key );
			return preg_replace( '/[^a-z0-9_\-]/', '', $key );
		}
	}
	if ( ! function_exists( 'get_user_meta' ) ) {
		function get_user_meta( $user_id, $key, $single = true ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			$store = $GLOBALS['rip_test_user_meta'][ $user_id ] ?? array();
			return $store[ $key ] ?? '';
		}
	}
	if ( ! function_exists( 'update_user_meta' ) ) {
		function update_user_meta( $user_id, $key, $value ) {
			$GLOBALS['rip_test_user_meta'][ $user_id ][ $key ] = $value;
			return true;
		}
	}
	if ( ! function_exists( 'delete_user_meta' ) ) {
		function delete_user_meta( $user_id, $key ) {
			unset( $GLOBALS['rip_test_user_meta'][ $user_id ][ $key ] );
			return true;
		}
	}
	if ( ! function_exists( 'wp_json_encode' ) ) {
		function wp_json_encode( $data, $options = 0, $depth = 512 ) {
			return json_encode( $data, $options, $depth ); // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Stub_For_Reset' ) ) {
		/**
		 * Minimal Two_Factor stub: only the constants and static methods the
		 * Reset_Gate touches.
		 */
		class ReportedIP_Hive_Two_Factor_Stub_For_Reset {

			const METHOD_TOTP     = 'totp';
			const METHOD_EMAIL    = 'email';
			const METHOD_SMS      = 'sms';
			const METHOD_WEBAUTHN = 'webauthn';
			const METHOD_RECOVERY = 'recovery';

			const META_TOTP_SECRET = 'reportedip_hive_2fa_totp_secret';

			const LOCKOUT_THRESHOLDS = array(
				3  => 30,
				5  => 300,
				10 => 1800,
				15 => 3600,
			);

			public static function is_globally_enabled() {
				return (bool) ( $GLOBALS['wp_options']['reportedip_hive_2fa_enabled_global'] ?? false );
			}

			public static function get_user_enabled_methods( $user_id ) {
				return $GLOBALS['rip_test_user_methods'][ $user_id ] ?? array();
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Recovery_Stub_For_Reset' ) ) {
		class ReportedIP_Hive_Two_Factor_Recovery_Stub_For_Reset {
			public static function get_remaining_count( $user_id ) {
				return (int) ( $GLOBALS['rip_test_user_recovery'][ $user_id ] ?? 0 );
			}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor', false ) ) {
		class_alias( 'ReportedIP_Hive_Two_Factor_Stub_For_Reset', 'ReportedIP_Hive_Two_Factor' );
	}
	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Recovery', false ) ) {
		class_alias( 'ReportedIP_Hive_Two_Factor_Recovery_Stub_For_Reset', 'ReportedIP_Hive_Two_Factor_Recovery' );
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-reset-gate.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Isolation: this test stubs out ReportedIP_Hive_Two_Factor and
	 * ReportedIP_Hive_Two_Factor_Recovery so the eligibility / lockout
	 * logic can be exercised without booting the real classes (which
	 * require WordPress + a database). Stubs are wired via class_alias();
	 * if the real classes are loaded by another test in the same process,
	 * the alias becomes a no-op and the wrong methods are called. We run
	 * each test in its own process to keep the alias sticky.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorResetGateTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']            = array();
			$GLOBALS['rip_test_user_meta']    = array();
			$GLOBALS['rip_test_user_methods'] = array();
			$GLOBALS['rip_test_user_recovery'] = array();
		}

		private function source(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-reset-gate.php' );
		}

		public function test_class_registers_validate_password_reset_hook(): void {
			$this->assertStringContainsString(
				"add_action( 'validate_password_reset',",
				$this->source(),
				'Reset_Gate must hook validate_password_reset to gate the reset form before render.'
			);
		}

		public function test_class_registers_password_reset_hook(): void {
			$this->assertStringContainsString(
				"add_action( 'password_reset',",
				$this->source(),
				'Reset_Gate must hook password_reset as a last-mile guard before wp_set_password().'
			);
		}

		public function test_validate_password_reset_uses_priority_5(): void {
			$this->assertMatchesRegularExpression(
				"/add_action\(\s*'validate_password_reset'.*,\s*5\s*,/s",
				$this->source(),
				'validate_password_reset must run at priority 5 so plugins hooking at the default priority 10 see our error first.'
			);
		}

		public function test_password_reset_uses_priority_5(): void {
			$this->assertMatchesRegularExpression(
				"/add_action\(\s*'password_reset'.*,\s*5\s*,/s",
				$this->source(),
				'password_reset must run at priority 5 so the last-mile guard fires before any other reset listeners persist state.'
			);
		}

		public function test_email_method_is_excluded_by_default(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				"'[\"email\"]'",
				$source,
				'The default excluded-methods option must contain "email" — the recovery channel must not double as the second factor.'
			);
		}

		public function test_class_uses_canonical_threshold_handler(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'handle_threshold_exceeded(',
				$source,
				'Reset_Gate must escalate via the canonical handle_threshold_exceeded() entry point so failures share the IP-block ladder with login-flow failures.'
			);
			$this->assertStringContainsString(
				"'2fa_brute_force'",
				$source,
				"Reset_Gate must escalate with event_type '2fa_brute_force' so dashboards attribute the block correctly."
			);
		}

		public function test_token_lifetime_matches_email_otp(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'TOKEN_TTL = 600',
				$source,
				'Reset token lifetime must be 10 minutes (600 s), matching the email-OTP lifetime so a single mental model covers both flows.'
			);
		}

		public function test_token_is_bound_to_reset_key_and_ip(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				"hash( 'sha256', \$reset_key )",
				$source,
				'Token transient key must include sha256(reset_key) so each reset link gets its own token slot — multiple outstanding links cannot share state.'
			);
			$this->assertStringContainsString(
				'client_fingerprint',
				$source,
				'Token must be bound to a hash of the originating client IP so a leaked transient cannot be replayed from elsewhere.'
			);
		}

		public function test_password_reset_handler_consumes_token(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'consume_token',
				$source,
				'After a successful reset the token must be deleted (single-use) — otherwise an attacker who briefly knew the key could replay it within the 10-minute window.'
			);
		}

		public function test_get_excluded_methods_returns_email_by_default(): void {
			$methods = \ReportedIP_Hive_Two_Factor_Reset_Gate::get_excluded_methods( 1 );
			$this->assertSame(
				array( 'email' ),
				$methods,
				'With no override, get_excluded_methods() must return ["email"] so the email channel is rejected as a second factor.'
			);
		}

		public function test_get_excluded_methods_decodes_json_string(): void {
			$GLOBALS['wp_options']['reportedip_hive_2fa_password_reset_excluded_methods'] = '["email","sms"]';
			$methods = \ReportedIP_Hive_Two_Factor_Reset_Gate::get_excluded_methods( 1 );
			$this->assertSame( array( 'email', 'sms' ), $methods );
		}

		public function test_get_excluded_methods_handles_array_storage(): void {
			$GLOBALS['wp_options']['reportedip_hive_2fa_password_reset_excluded_methods'] = array( 'email', 'webauthn' );
			$methods = \ReportedIP_Hive_Two_Factor_Reset_Gate::get_excluded_methods( 1 );
			$this->assertSame( array( 'email', 'webauthn' ), $methods );
		}

		public function test_get_eligible_methods_excludes_email(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array( 'totp', 'email' );
			$GLOBALS['rip_test_user_recovery'][7] = 0;
			$eligible = \ReportedIP_Hive_Two_Factor_Reset_Gate::get_eligible_methods( 7 );
			$this->assertSame( array( 'totp' ), $eligible );
			$this->assertNotContains( 'email', $eligible );
		}

		public function test_get_eligible_methods_includes_recovery_when_codes_exist(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array( 'email' );
			$GLOBALS['rip_test_user_recovery'][7] = 5;
			$eligible = \ReportedIP_Hive_Two_Factor_Reset_Gate::get_eligible_methods( 7 );
			$this->assertSame( array( 'recovery' ), $eligible );
		}

		public function test_get_eligible_methods_with_no_factor_is_empty(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array( 'email' );
			$GLOBALS['rip_test_user_recovery'][7] = 0;
			$this->assertSame(
				array(),
				\ReportedIP_Hive_Two_Factor_Reset_Gate::get_eligible_methods( 7 )
			);
		}

		public function test_is_email_only_locked_blocks_email_only_user(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array( 'email' );
			$GLOBALS['rip_test_user_recovery'][7] = 0;
			$this->assertTrue( \ReportedIP_Hive_Two_Factor_Reset_Gate::is_email_only_locked( 7 ) );
		}

		public function test_is_email_only_locked_passes_when_recovery_codes_exist(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array( 'email' );
			$GLOBALS['rip_test_user_recovery'][7] = 4;
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Reset_Gate::is_email_only_locked( 7 ) );
		}

		public function test_is_email_only_locked_passes_when_other_factor_exists(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array( 'email', 'totp' );
			$GLOBALS['rip_test_user_recovery'][7] = 0;
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Reset_Gate::is_email_only_locked( 7 ) );
		}

		public function test_is_email_only_locked_disabled_by_option(): void {
			$GLOBALS['wp_options']['reportedip_hive_2fa_password_reset_block_email_only'] = false;
			$GLOBALS['rip_test_user_methods'][7]  = array( 'email' );
			$GLOBALS['rip_test_user_recovery'][7] = 0;
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Reset_Gate::is_email_only_locked( 7 ) );
		}

		public function test_feature_disabled_when_2fa_globally_off(): void {
			$GLOBALS['wp_options']['reportedip_hive_2fa_enabled_global']           = false;
			$GLOBALS['wp_options']['reportedip_hive_2fa_require_on_password_reset'] = true;
			$this->assertFalse(
				\ReportedIP_Hive_Two_Factor_Reset_Gate::is_feature_enabled(),
				'The reset gate must inherit the global 2FA off-switch — otherwise it could fire while users have no way to set up their second factor.'
			);
		}

		public function test_feature_disabled_when_opt_set_to_false(): void {
			$GLOBALS['wp_options']['reportedip_hive_2fa_enabled_global']           = true;
			$GLOBALS['wp_options']['reportedip_hive_2fa_require_on_password_reset'] = false;
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Reset_Gate::is_feature_enabled() );
		}

		public function test_feature_enabled_when_both_options_on(): void {
			$GLOBALS['wp_options']['reportedip_hive_2fa_enabled_global']           = true;
			$GLOBALS['wp_options']['reportedip_hive_2fa_require_on_password_reset'] = true;
			$this->assertTrue( \ReportedIP_Hive_Two_Factor_Reset_Gate::is_feature_enabled() );
		}
	}
}
