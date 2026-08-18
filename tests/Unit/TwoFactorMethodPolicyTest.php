<?php
/**
 * Guards that the method policy is enforced where it decides access.
 *
 * The profile UI hid cards for methods a site had switched off, but nothing
 * behind it checked:
 *
 *  - The login challenge passed `$_POST['reportedip_2fa_method']` straight to
 *    the verifier, which is a pure per-method switch. A method the policy no
 *    longer permitted still signed the user in as long as its secret had been
 *    left behind. The REST and password-reset surfaces always gated this.
 *  - The enrolment endpoints accepted any method, so a flag could be written
 *    for a disallowed one — going live the moment an admin re-enabled it —
 *    and a disallowed SMS or email enrolment burned managed relay quota on
 *    the way to being rejected.
 *
 * Recovery codes stay eligible unconditionally: they are the way back in when
 * every configured factor is unavailable.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.44
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class TwoFactorMethodPolicyTest extends TestCase {

		/**
		 * Read one source file from the plugin.
		 *
		 * @param string $relative Path relative to the plugin root.
		 * @return string
		 */
		private function source( string $relative ): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
		}

		/**
		 * Capture a method body from a source file.
		 *
		 * @param string $relative  Path relative to the plugin root.
		 * @param string $signature Method signature to start at.
		 * @param int    $length    Characters to capture.
		 * @return string
		 */
		private function method_body( string $relative, string $signature, int $length = 1400 ): string {
			$source = $this->source( $relative );
			$start  = strpos( $source, $signature );
			$this->assertNotFalse( $start, "$signature must exist in $relative" );

			return substr( $source, $start, $length );
		}

		public function test_login_verify_rejects_a_method_the_user_has_not_enabled() {
			$body = $this->method_body( 'includes/class-two-factor.php', 'private function verify_2fa_code(' );

			$this->assertStringContainsString(
				'get_user_enabled_methods',
				$body,
				'The submitted method must be checked against the live factors before any secret is read'
			);

			$guard_pos  = strpos( $body, 'in_array(' );
			$verify_pos = strpos( $body, 'Two_Factor_Verifier::verify_method' );
			$this->assertNotFalse( $guard_pos );
			$this->assertNotFalse( $verify_pos );
			$this->assertLessThan( $verify_pos, $guard_pos, 'The eligibility check must run before the verifier' );
		}

		public function test_recovery_stays_eligible_on_the_login_path() {
			$body = $this->method_body( 'includes/class-two-factor.php', 'private function verify_2fa_code(' );

			$this->assertStringContainsString(
				'METHOD_RECOVERY',
				$body,
				'Recovery codes must survive the guard — they are the fallback when no factor works'
			);
		}

		public function test_shared_enrolment_path_refuses_disallowed_methods() {
			$body = $this->method_body( 'includes/class-two-factor.php', 'public static function activate_method(' );

			$this->assertStringContainsString( 'get_allowed_methods()', $body, 'activate_method() is the single enrolment path and must enforce the policy' );

			$guard_pos  = strpos( $body, 'get_allowed_methods()' );
			$enable_pos = strpos( $body, 'enable_for_user(' );
			$this->assertNotFalse( $enable_pos );
			$this->assertLessThan( $enable_pos, $guard_pos, 'The policy check must precede activation' );
		}

		public function test_every_setup_endpoint_gates_on_the_policy() {
			$admin = $this->source( 'admin/class-two-factor-admin.php' );

			$this->assertStringContainsString( 'private function require_allowed_method(', $admin );

			foreach ( array( 'METHOD_TOTP', 'METHOD_EMAIL', 'METHOD_SMS' ) as $method ) {
				$this->assertStringContainsString(
					"require_allowed_method( ReportedIP_Hive_Two_Factor::$method )",
					$admin,
					"The $method setup endpoint must refuse a disallowed enrolment before doing any work"
				);
			}
		}

		public function test_sms_enrolment_is_gated_before_a_code_is_sent() {
			$body = $this->method_body( 'admin/class-two-factor-admin.php', 'public function ajax_setup_sms()', 2600 );

			$guard_pos = strpos( $body, 'require_allowed_method' );
			$this->assertNotFalse( $guard_pos, 'ajax_setup_sms() must check the policy' );

			$send_pos = strpos( $body, 'send_code' );
			if ( false !== $send_pos ) {
				$this->assertLessThan( $send_pos, $guard_pos, 'A disallowed method must not consume managed relay quota' );
			}
		}

		public function test_webauthn_registration_gates_on_the_policy() {
			$webauthn = $this->source( 'includes/class-two-factor-webauthn.php' );

			$this->assertStringContainsString( 'private static function require_method_allowed()', $webauthn );

			foreach ( array( 'public function ajax_register_options()', 'public function ajax_register_verify()' ) as $signature ) {
				$body = $this->method_body( 'includes/class-two-factor-webauthn.php', $signature, 1200 );
				$this->assertStringContainsString(
					'require_method_allowed()',
					$body,
					"$signature must refuse registration while the method is switched off"
				);
			}
		}
	}
}
