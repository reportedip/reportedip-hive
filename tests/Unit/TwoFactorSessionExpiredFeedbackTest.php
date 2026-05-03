<?php
/**
 * Locks down the user-facing feedback path when a 2FA session is invalid.
 *
 * Before 1.6.5 the challenge handler silently `wp_safe_redirect()`-ed to
 * wp-login.php whenever the 15-minute nonce had expired or the SameSite=Strict
 * nonce cookie was missing (the latter is routine inside an iframe). Users
 * landed on a clean login form with no error message, so a late SMS code
 * looked like the form had simply discarded their submission.
 *
 * The fix has two halves and this test pins both:
 *   1. handle_2fa_challenge() must NOT call `wp_safe_redirect( wp_login_url() )`
 *      with no query parameter — it must call render_session_expired_page()
 *      so the user sees an explicit message.
 *   2. filter_login_errors() must translate the existing
 *      `?reportedip_2fa_locked=1` query flag into a visible WP_Error
 *      (previously the flag was set but never read anywhere).
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.6.5
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class TwoFactorSessionExpiredFeedbackTest extends TestCase {

		private function source(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor.php' );
		}

		public function test_no_silent_redirect_on_invalid_nonce(): void {
			$source = $this->source();
			$this->assertDoesNotMatchRegularExpression(
				'/wp_safe_redirect\(\s*wp_login_url\(\)\s*\)\s*;\s*\n\s*exit;/',
				$source,
				'handle_2fa_challenge() must not silently redirect to wp_login_url() — late SMS / iframe-stripped cookies leave users with no explanation. Call render_session_expired_page() instead.'
			);
		}

		public function test_render_session_expired_page_method_exists(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'private function render_session_expired_page(',
				$source,
				'render_session_expired_page() must exist as the explicit feedback path for an invalid 2FA nonce.'
			);
			$this->assertStringContainsString(
				"render_session_expired_page( 'expired' )",
				$source,
				"The 'expired' branch must be wired up for the nonce-missing path."
			);
			$this->assertStringContainsString(
				"render_session_expired_page( 'unknown_user' )",
				$source,
				"The 'unknown_user' branch must be wired up for the get_userdata() failure path."
			);
		}

		public function test_session_expired_page_uses_login_chrome(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'login_header(',
				$source,
				'render_session_expired_page() must reuse login_header() so the message appears inside the standard wp-login frame.'
			);
			$this->assertStringContainsString(
				'login_footer()',
				$source,
				'render_session_expired_page() must close the page with login_footer().'
			);
			$this->assertStringContainsString(
				"target=\"_top\"",
				$source,
				'The "Back to login" link must escape the iframe via target="_top" — without it the recovery link reloads inside the same broken iframe context that caused the failure.'
			);
		}

		public function test_filter_login_errors_is_registered(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				"add_filter( 'wp_login_errors', array( \$this, 'filter_login_errors' ), 10, 2 )",
				$source,
				'wp_login_errors filter must be hooked so the locked / expired query flags become visible WP_Error messages on wp-login.php.'
			);
		}

		public function test_filter_login_errors_handles_locked_flag(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				"/\\\$_GET\\[\\s*'reportedip_2fa_locked'\\s*\\]/",
				$source,
				'filter_login_errors() must read the reportedip_2fa_locked query flag — without it, the brute-force-lockout redirect at line 836 stays silent.'
			);
			$this->assertStringContainsString(
				"'reportedip_2fa_locked'",
				$source,
				'The locked-state WP_Error code must be added to the login_errors collection.'
			);
		}

		public function test_filter_login_errors_handles_expired_flag(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				"/\\\$_GET\\[\\s*'reportedip_2fa_expired'\\s*\\]/",
				$source,
				'filter_login_errors() must also read reportedip_2fa_expired so callers that prefer redirecting over the inline expired page still produce visible feedback.'
			);
			$this->assertStringContainsString(
				"'reportedip_2fa_session_expired'",
				$source,
				'The expired-state WP_Error code must be present so wp-login renders the "session expired" message.'
			);
		}

		public function test_user_enumeration_normalizer_lets_2fa_flags_through(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-user-enumeration.php' );
			$this->assertMatchesRegularExpression(
				"/normalize_login_errors\\(.*?reportedip_2fa_locked.*?reportedip_2fa_expired/s",
				$source,
				'normalize_login_errors() must skip the "Invalid credentials." mask when ?reportedip_2fa_locked=1 or ?reportedip_2fa_expired=1 is present — otherwise the wp_login_errors filter on Two_Factor is silently overwritten and users see a misleading credential-error message instead of the real session/lockout reason.'
			);
			$this->assertMatchesRegularExpression(
				"/normalize_login_errors\\(.*?action.*?reportedip_2fa/s",
				$source,
				"normalize_login_errors() must also skip the mask when ?action=reportedip_2fa is in the URL — that's the inline render_session_expired_page() path, which routes its message through login_header() and therefore through this same login_errors filter."
			);
		}

		public function test_filter_login_errors_returns_wp_error_instance(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				'/instanceof\s+\\\\?WP_Error/',
				$source,
				'filter_login_errors() must guard against non-WP_Error inputs by checking instanceof and re-instantiating, so the filter is safe even when other plugins return something unexpected.'
			);
			$this->assertMatchesRegularExpression(
				'/return\s+\$errors\s*;\s*\n\s*\}/',
				$source,
				'filter_login_errors() must return the (possibly augmented) WP_Error so the wp_login_errors filter chain stays intact.'
			);
		}
	}
}
