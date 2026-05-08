<?php
/**
 * Unit tests for the shared per-method 2FA code verifier.
 *
 * The verifier replaces two near-identical switch statements (one in the
 * login flow, one in the password-reset flow) so both surfaces verify
 * codes through the same code path. These tests lock down:
 *
 *   1. Source-pattern guarantees so the public API stays stable.
 *   2. Behaviour for unknown / unhandled methods (must return false and
 *      report `unknown_method` to the caller's logger callback).
 *   3. The internal-error callback contract so callers' surface-specific
 *      logging keeps working.
 *
 * The crypto / TOTP / SMS / WebAuthn provider classes themselves are not
 * exercised here — they have their own dedicated test suites.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.1
 */

namespace {

	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $hook, $value ) { return $value; } // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'get_user_meta' ) ) {
		function get_user_meta( $user_id, $key, $single = true ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			$store = $GLOBALS['rip_test_user_meta'][ $user_id ] ?? array();
			return $store[ $key ] ?? '';
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Stub_For_Verifier' ) ) {
		/**
		 * Minimal Two_Factor stub: only the constants the Verifier reads via
		 * static class access.
		 */
		class ReportedIP_Hive_Two_Factor_Stub_For_Verifier {
			const METHOD_TOTP     = 'totp';
			const METHOD_EMAIL    = 'email';
			const METHOD_SMS      = 'sms';
			const METHOD_WEBAUTHN = 'webauthn';
			const METHOD_RECOVERY = 'recovery';

			const META_TOTP_SECRET = 'reportedip_hive_2fa_totp_secret';
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor', false ) ) {
		class_alias( 'ReportedIP_Hive_Two_Factor_Stub_For_Verifier', 'ReportedIP_Hive_Two_Factor' );
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-verifier.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorVerifierTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['rip_test_user_meta'] = array();
		}

		private function source(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-verifier.php' );
		}

		public function test_verifier_class_is_final(): void {
			$this->assertStringContainsString(
				'final class ReportedIP_Hive_Two_Factor_Verifier',
				$this->source(),
				'Verifier must be final — subclassing would defeat the "single source of truth for verify" goal of this extraction.'
			);
		}

		public function test_verify_method_signature_accepts_callback(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				'/public static function verify_method\(\s*int \$user_id,\s*string \$method,\s*string \$code,\s*\$on_internal_error = null\s*\)\s*:\s*bool/',
				$source,
				'verify_method() must accept an optional on_internal_error callback as 4th positional arg so callers can route reasons into their surface-specific event log.'
			);
		}

		public function test_each_supported_method_has_a_case(): void {
			$source = $this->source();
			$this->assertStringContainsString( 'METHOD_TOTP', $source );
			$this->assertStringContainsString( 'METHOD_EMAIL', $source );
			$this->assertStringContainsString( 'METHOD_SMS', $source );
			$this->assertStringContainsString( 'METHOD_WEBAUTHN', $source );
			$this->assertStringContainsString( 'METHOD_RECOVERY', $source );
		}

		public function test_totp_path_clamps_window_filter(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'max( 0, min( 3, $window ) )',
				$source,
				'TOTP path must clamp the reportedip_2fa_totp_window filter to [0, 3] — anything wider erodes brute-force resistance.'
			);
		}

		public function test_totp_path_zeroes_secret_after_use(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'Two_Factor_Crypto::zero_memory( $secret )',
				$source,
				'After TOTP::verify_code() returns, the decrypted secret must be zeroed so it cannot be lifted from a process dump.'
			);
		}

		public function test_unknown_method_returns_false(): void {
			$received = array();
			$result   = \ReportedIP_Hive_Two_Factor_Verifier::verify_method(
				1,
				'definitely_not_a_real_method',
				'123456',
				function ( $reason, $method ) use ( &$received ): void {
					$received[] = array( $reason, $method );
				}
			);
			$this->assertFalse( $result );
			$this->assertSame(
				array( array( 'unknown_method', 'definitely_not_a_real_method' ) ),
				$received,
				'Unknown methods must trigger the on_internal_error callback with reason "unknown_method" so the caller can log it.'
			);
		}

		public function test_totp_with_missing_secret_reports_missing_secret(): void {
			$received = array();
			$result   = \ReportedIP_Hive_Two_Factor_Verifier::verify_method(
				42,
				\ReportedIP_Hive_Two_Factor::METHOD_TOTP,
				'123456',
				function ( $reason, $method ) use ( &$received ): void {
					$received[] = array( $reason, $method );
				}
			);
			$this->assertFalse( $result );
			$this->assertSame(
				array( array( 'missing_secret', 'totp' ) ),
				$received,
				'TOTP path must report missing_secret when META_TOTP_SECRET is empty (no Crypto call should be attempted).'
			);
		}

		public function test_callback_is_optional(): void {
			$result = \ReportedIP_Hive_Two_Factor_Verifier::verify_method(
				1,
				'unknown_method',
				'foo'
			);
			$this->assertFalse(
				$result,
				'verify_method() must work without a callback — many callers do not need surface-specific logging.'
			);
		}

		public function test_throwing_callback_does_not_break_verification(): void {
			$result = \ReportedIP_Hive_Two_Factor_Verifier::verify_method(
				1,
				'unknown_method',
				'foo',
				function ( $reason, $method ): void { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
					throw new \RuntimeException( 'logger blew up' );
				}
			);
			$this->assertFalse(
				$result,
				'A misbehaving logger must not derail verification — exceptions from the callback are swallowed by design.'
			);
		}
	}
}
