<?php
/**
 * Locks down the duplicate-submit hardening of the 2FA login challenge.
 *
 * Before 2.1.24 a duplicate POST of the challenge form (the six-digit
 * auto-submit racing an Enter press or a "Verify" click) stranded users on
 * the "session expired" page even though the winning request had already
 * verified the code, set the auth cookie and logged "2FA verification
 * successful" — the browser discards the winning response in favour of the
 * duplicate navigation, which finds the login nonce consumed.
 *
 * The fix has three halves and this test pins all of them:
 *   1. The success branch writes a short-lived consumed-nonce marker BEFORE
 *      cleanup_login_nonce() deletes the nonce, and
 *      maybe_replay_consumed_nonce() replays a duplicate bearer of the same
 *      token (same IP, 90-second window) into the identical sign-in.
 *   2. handle_2fa_challenge() redirects already-authenticated visitors away
 *      from the challenge instead of rendering the expired page.
 *   3. two-factor-login.js never calls the guard-bypassing `form.submit()`
 *      directly — every submit funnels through the double-submit guard.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.24
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class TwoFactorDuplicateSubmitTest extends TestCase {

		private function source(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor.php' );
		}

		private function login_js(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/assets/js/two-factor-login.js' );
		}

		public function test_consumed_marker_constants_exist(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				"const NONCE_CONSUMED_PREFIX = 'reportedip_2fa_done_'",
				$source,
				'The consumed-nonce marker needs its own transient prefix, distinct from the live nonce prefix.'
			);
			$this->assertMatchesRegularExpression(
				'/const NONCE_CONSUMED_TTL\s*=\s*\d+;/',
				$source,
				'The consumed-nonce marker must carry an explicit, short TTL.'
			);
		}

		public function test_success_branch_marks_nonce_consumed_before_cleanup(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				'/mark_login_nonce_consumed\([^;]*\);\s*\n\s*\$this->cleanup_login_nonce\(\);/',
				$source,
				'The consumed marker must be written BEFORE cleanup_login_nonce() deletes the nonce transient — afterwards the cookie token hash is the only remaining link to the duplicate request.'
			);
		}

		public function test_invalid_nonce_path_replays_before_expired_page(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				'/maybe_replay_consumed_nonce\(\);\s*\n\s*\$this->maybe_redirect_logged_in_user\(\s*\$context\s*\);\s*\n\s*\$this->render_session_expired_page\(\s*\'expired\'/',
				$source,
				'On an invalid nonce the handler must first try the consumed-nonce replay, then the logged-in short-circuit, and only then render the session-expired page.'
			);
		}

		public function test_replay_validates_ip_binding(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				'/function maybe_replay_consumed_nonce\(\).*?ReportedIP_Hive::get_client_ip\(\)\s*!==\s*\$consumed\[\'ip\'\]/s',
				$source,
				'The replay path must enforce the same IP binding as validate_login_nonce() — the marker mirrors a just-issued session and must not be portable across clients.'
			);
		}

		public function test_logged_in_visitors_are_redirected_not_errored(): void {
			$source = $this->source();
			$this->assertMatchesRegularExpression(
				'/function maybe_redirect_logged_in_user\(.*?is_user_logged_in\(\)/s',
				$source,
				'A signed-in visitor reloading or revisiting the challenge URL must be redirected away, not shown the misleading "session expired" error.'
			);
		}

		public function test_auth_cookie_helper_is_shared_by_both_paths(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'private function set_auth_cookie_with_remember(',
				$source,
				'The extended-remember filter sandwich must live in one helper so success and replay issue identical sessions.'
			);
			$this->assertGreaterThanOrEqual(
				2,
				substr_count( $source, '$this->set_auth_cookie_with_remember(' ),
				'Both the success branch and the consumed-nonce replay must go through set_auth_cookie_with_remember().'
			);
		}

		public function test_login_js_has_no_unguarded_form_submit(): void {
			$js = $this->login_js();
			$this->assertStringContainsString(
				'function submitFormOnce(',
				$js,
				'two-factor-login.js must funnel programmatic submits through the submitFormOnce() guard helper.'
			);
			$this->assertStringContainsString(
				"form.addEventListener( 'submit'",
				$js,
				'The form needs a submit listener so native submits (Enter, button click) hit the same double-submit guard.'
			);
			$this->assertMatchesRegularExpression(
				'/if\s*\(\s*submitting\s*\)\s*\{\s*\n\s*e\.preventDefault\(\);/',
				$js,
				'A second submit while one is in flight must be prevented — this is the duplicate POST that used to consume the nonce.'
			);
			$guarded = preg_replace( '/function submitFormOnce\(.*?\n\t\}/s', '', $js );
			$this->assertStringNotContainsString(
				'form.submit()',
				(string) $guarded,
				'No call site outside submitFormOnce() may use form.submit() — it bypasses the submit event and with it the guard.'
			);
		}
	}
}
