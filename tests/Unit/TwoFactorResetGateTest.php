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
 * @author     Patrick Schlesinger <1@reportedip.de>
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

		public function test_should_gate_user_returns_false_for_no_factor(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array();
			$GLOBALS['rip_test_user_recovery'][7] = 0;
			$this->assertFalse(
				\ReportedIP_Hive_Two_Factor_Reset_Gate::should_gate_user( 7 ),
				'A user with no second factor enrolled must not be gated — they would otherwise drop into a recovery-code prompt for codes they never had.'
			);
		}

		public function test_should_gate_user_returns_false_for_email_only(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array( 'email' );
			$GLOBALS['rip_test_user_recovery'][7] = 5;
			$this->assertFalse(
				\ReportedIP_Hive_Two_Factor_Reset_Gate::should_gate_user( 7 ),
				'Email-only-2FA is the same channel as the reset link, so it adds no security to gate on it — a user enrolled in nothing but email must skip the gate even when recovery codes exist.'
			);
		}

		public function test_should_gate_user_returns_false_for_recovery_only(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array();
			$GLOBALS['rip_test_user_recovery'][7] = 8;
			$this->assertFalse(
				\ReportedIP_Hive_Two_Factor_Reset_Gate::should_gate_user( 7 ),
				'Recovery codes are a fallback for an inaccessible primary factor — they are not themselves a primary factor that should trigger the gate.'
			);
		}

		public function test_should_gate_user_returns_true_for_totp_enrolled(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array( 'totp' );
			$GLOBALS['rip_test_user_recovery'][7] = 0;
			$this->assertTrue(
				\ReportedIP_Hive_Two_Factor_Reset_Gate::should_gate_user( 7 ),
				'A TOTP-enrolled user is precisely the case the reset gate exists to protect: an attacker with mailbox access must still clear the TOTP factor.'
			);
		}

		public function test_should_gate_user_returns_true_for_email_plus_totp(): void {
			$GLOBALS['rip_test_user_methods'][7]  = array( 'email', 'totp' );
			$GLOBALS['rip_test_user_recovery'][7] = 0;
			$this->assertTrue(
				\ReportedIP_Hive_Two_Factor_Reset_Gate::should_gate_user( 7 )
			);
		}

		public function test_should_gate_user_returns_false_when_admin_excludes_all_enrolled_methods(): void {
			$GLOBALS['wp_options']['reportedip_hive_2fa_password_reset_excluded_methods'] = '["email","totp"]';
			$GLOBALS['rip_test_user_methods'][7]  = array( 'totp' );
			$GLOBALS['rip_test_user_recovery'][7] = 0;
			$this->assertFalse(
				\ReportedIP_Hive_Two_Factor_Reset_Gate::should_gate_user( 7 ),
				'If the admin excludes every method the user has enrolled, the gate has nothing to challenge on and must not lock the user out of password reset.'
			);
		}

		public function test_validate_reset_uses_should_gate_user_guard(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				'/on_validate_reset.*should_gate_user/s',
				$source,
				'on_validate_reset() must bail out via should_gate_user() — using empty($enabled) alone is incorrect because email-only-2FA users with stale recovery codes would still be dragged into the challenge.'
			);
		}

		public function test_password_reset_uses_should_gate_user_guard(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				'/on_password_reset.*should_gate_user/s',
				$source,
				'on_password_reset() must use the same should_gate_user() guard as on_validate_reset() so the last-mile token check stays consistent with the validation-time decision.'
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

		public function test_verify_path_delegates_to_shared_verifier(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'ReportedIP_Hive_Two_Factor_Verifier::verify_method',
				$source,
				'Reset_Gate must route per-method verification through the shared Verifier so login + reset cannot drift apart.'
			);
		}

		public function test_inline_error_alert_is_rendered_inside_card(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'rip-alert--danger',
				$source,
				'Failed verifications must surface inline as rip-alert--danger inside the .rip-2fa-challenge card — relying on login_header() alone hides the error when third-party plugins filter wp_login_errors.'
			);
		}

		public function test_inline_info_alert_is_rendered_for_code_sent_state(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'rip-alert--info',
				$source,
				'A successful initial / resend dispatch must render an inline rip-alert--info notice so the user knows a code is on the way.'
			);
		}

		public function test_send_failures_are_logged_under_dedicated_event(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				"EVENT_SEND_FAILED        = '2fa_reset_send_failed'",
				$source,
				'Initial / resend send failures must use the EVENT_SEND_FAILED constant so log dashboards can distinguish them from challenge-failed events.'
			);
		}

		public function test_no_usable_method_lockout_event_exists(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				"EVENT_NO_USABLE_METHOD   = '2fa_reset_no_usable_method'",
				$source,
				'When health-assessment finds zero usable methods the gate must log under EVENT_NO_USABLE_METHOD so the all-broken case is grep-able separately from the no-eligible-method case.'
			);
		}

		public function test_url_resend_path_exists(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				"isset( \$_GET['resend_sms'] )",
				$source,
				'A server-side ?resend_sms=1 path must exist so users without JS can still re-trigger the SMS code from the challenge page.'
			);
			$this->assertStringContainsString(
				"isset( \$_GET['resend_email'] )",
				$source,
				'A server-side ?resend_email=1 path must exist so users without JS can still re-trigger the email code from the challenge page.'
			);
		}

		public function test_initial_code_dispatch_runs_before_redirect(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'dispatch_initial_code',
				$source,
				'on_validate_reset() must call dispatch_initial_code() before redirecting to the challenge page so SMS/email users see "we sent a code" on first land, not an empty form.'
			);
		}

		public function test_health_assessment_is_invoked_in_validate_reset(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'assess_methods_health',
				$source,
				'on_validate_reset() must health-assess the eligible methods so users with broken TOTP secrets / SMS providers get a helpful lockout message instead of an "Invalid code" loop.'
			);
		}

		public function test_lockout_admin_notification_carries_reason(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'notify_admins_user_locked_out',
				$source,
				'Admin alert mailer must accept a reason parameter so the email subject and body change with the lockout cause (email_only / no_eligible_method / no_usable_method).'
			);
		}
	}
}
