<?php
/**
 * Pins that a POST re-render of the 2FA challenge keeps the user on the
 * method they actually submitted, instead of snapping back to the stored
 * default method.
 *
 * Bug: a user with several methods (e.g. Email + SMS) switches to the SMS
 * tab, requests a code and submits it. When verification fails — wrong code,
 * expired code, or a soft lockout — handle_2fa_challenge() re-renders the
 * challenge. The render method was derived once from get_user_method()
 * (the stored default, usually Email) and the submitted method was only ever
 * read into a local variable, never written back. So the page came back with
 * the Email tab active and the freshly typed SMS code gone — the classic
 * "jumps back to Mail and my input is lost" report.
 *
 * The fix carries the submitted method into $method before the re-render, so
 * the chosen tab survives a failed attempt. The final allowed-methods guard
 * still validates the value, so a forged method falls back safely.
 *
 * Render path calls login_header() / exit, so — like
 * TwoFactorSessionExpiredFeedbackTest — this locks the behaviour down with
 * source assertions rather than a live request.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.22
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class TwoFactorMethodPreservedOnRerenderTest extends TestCase {

		private function source(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor.php' );
		}

		public function test_submitted_method_is_carried_into_render_method(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				'/\$method\s*=\s*\$submitted_method\s*;/',
				$source,
				'handle_2fa_challenge() must assign the submitted method back into $method on a POST re-render — otherwise a failed verify snaps the user back to the stored default method (usually Email) and discards the code they just typed.'
			);
		}

		public function test_submitted_method_originates_from_post(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				"/\\\$submitted_method\\s*=\\s*isset\\(\\s*\\\$_POST\\[\\s*'reportedip_2fa_method'\\s*\\]/",
				$source,
				'The preserved method must be derived from the posted reportedip_2fa_method field.'
			);
		}

		public function test_method_assignment_precedes_the_allowed_methods_guard(): void {
			$source            = $this->source();
			$assign_pos        = strpos( $source, '$method = $submitted_method' );
			$guard_pos         = strpos( $source, 'if ( ! in_array( $method, $allowed_methods, true ) ) {' );
			$this->assertNotFalse( $assign_pos, 'Submitted-method assignment must be present.' );
			$this->assertNotFalse( $guard_pos, 'The allowed-methods fallback guard must be present.' );
			$this->assertLessThan(
				$guard_pos,
				$assign_pos,
				'The submitted-method assignment must run before the allowed-methods guard so a forged or disabled method still falls back to a valid tab.'
			);
		}
	}
}
