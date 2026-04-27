<?php
/**
 * Unit Tests for Password-Strength policy heuristic.
 *
 * Tests the local-only path of ReportedIP_Hive_Password_Strength::validate_password()
 * (length, character classes, common-password blocklist). The HIBP network
 * branch is exercised separately via integration tests when available — here
 * we set the option `reportedip_hive_password_check_hibp` to false so the
 * test does not make outbound HTTP.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.2.0
 */

namespace {

	if ( ! function_exists( 'add_action' ) ) {
		function add_action( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'wp_unslash' ) ) {
		function wp_unslash( $value ) {
			return is_string( $value ) ? stripslashes( $value ) : $value;
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-password-strength.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReflectionClass;
	use ReportedIP\Hive\Tests\TestCase;

	class PasswordPolicyTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options'] = array(
				'reportedip_hive_password_policy_enabled'   => true,
				'reportedip_hive_password_check_hibp'       => false,
				'reportedip_hive_password_min_length'       => 12,
				'reportedip_hive_password_min_classes'      => 3,
				'reportedip_hive_password_policy_all_users' => true,
				'reportedip_hive_2fa_enforce_roles'         => '[]',
			);
		}

		private function validate( string $password ): ?string {
			$instance   = \ReportedIP_Hive_Password_Strength::get_instance();
			$reflection = new ReflectionClass( $instance );
			$method     = $reflection->getMethod( 'validate_password' );
			$method->setAccessible( true );
			return $method->invoke( $instance, $password, null );
		}

		public function test_too_short_password_is_rejected() {
			$msg = $this->validate( 'Aa1$Aa1$' );
			$this->assertNotNull( $msg );
			$this->assertStringContainsString( '12', $msg );
		}

		public function test_minimum_length_passing_password() {
			$this->assertNull( $this->validate( 'Abcdef1234!@' ), 'Length-12 with 3 classes should pass' );
		}

		public function test_only_lowercase_is_rejected() {
			$this->assertNotNull(
				$this->validate( 'lowercaseonlypw' ),
				'Pure-lowercase password should fail the class requirement'
			);
		}

		public function test_two_classes_is_rejected_when_three_required() {
			$this->assertNotNull(
				$this->validate( 'OnlyLettersHere' ),
				'Mixed case alone is two classes — must fail when min_classes is 3'
			);
		}

		public function test_common_password_is_rejected() {
			$GLOBALS['wp_options']['reportedip_hive_password_min_length']  = 8;
			$GLOBALS['wp_options']['reportedip_hive_password_min_classes'] = 2;
			$this->assertNotNull(
				$this->validate( 'password123' ),
				'Common password "password123" must be rejected even when length and class requirements pass'
			);
		}

		public function test_disabled_policy_allows_anything() {
			$GLOBALS['wp_options']['reportedip_hive_password_policy_enabled'] = false;
			$this->assertNull(
				$this->validate( 'short' ),
				'When the policy is disabled, no validation runs'
			);
		}

		public function test_lower_min_classes_relaxes_requirement() {
			$GLOBALS['wp_options']['reportedip_hive_password_min_classes'] = 1;
			$this->assertNull(
				$this->validate( 'aaaaaaaaaaaa' ),
				'min_classes=1 makes a 12-char lowercase password pass'
			);
		}

		public function test_strong_password_passes() {
			$this->assertNull(
				$this->validate( 'kQ7!nzM2#fX9' ),
				'Strong random password should pass cleanly'
			);
		}
	}
}
