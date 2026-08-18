<?php
/**
 * Unit tests for TOTP verification and its single-use enforcement.
 *
 * RFC 6238 §5.2 requires that a code accepted once is not accepted again.
 * Nothing tracked the consumed time step, so a code captured in transit —
 * phishing proxy, shoulder-surf, plain HTTP — stayed valid for the remainder
 * of its window (90 seconds at the default tolerance, 210 at the widest) and
 * replayed in a second, parallel session. The login nonce is single-use and
 * covered replay inside one challenge only.
 *
 * Every other factor already invalidated its artefact on success: email and
 * SMS delete the transient, recovery codes are spliced out, WebAuthn advances
 * the signature counter.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.44
 */

namespace {

	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $hook, $value, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $value;
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-totp.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReflectionMethod;
	use ReportedIP\Hive\Tests\TestCase;

	class TotpSingleUseTest extends TestCase {

		private const SECRET = 'JBSWY3DPEHPK3PXP';

		/**
		 * Code for a given absolute time step.
		 *
		 * @param int $step Time step.
		 * @return string
		 */
		private function code_for_step( int $step ): string {
			$method = new ReflectionMethod( \ReportedIP_Hive_Two_Factor_TOTP::class, 'calculate_code' );
			$method->setAccessible( true );

			return (string) $method->invoke( null, self::SECRET, $step );
		}

		/**
		 * The time step the implementation considers current.
		 *
		 * @return int
		 */
		private function current_step(): int {
			$method = new ReflectionMethod( \ReportedIP_Hive_Two_Factor_TOTP::class, 'get_time_step' );
			$method->setAccessible( true );

			return (int) $method->invoke( null );
		}

		public function test_current_code_verifies() {
			$step = $this->current_step();

			$this->assertTrue( \ReportedIP_Hive_Two_Factor_TOTP::verify_code( self::SECRET, $this->code_for_step( $step ) ) );
		}

		public function test_matching_step_reports_the_step_the_code_belongs_to() {
			$step = $this->current_step();

			$this->assertSame( $step, \ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, $this->code_for_step( $step ) ) );
			$this->assertSame( $step - 1, \ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, $this->code_for_step( $step - 1 ) ) );
			$this->assertSame( $step + 1, \ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, $this->code_for_step( $step + 1 ) ) );
		}

		public function test_a_spent_step_is_refused() {
			$step = $this->current_step();
			$code = $this->code_for_step( $step );

			$this->assertNull(
				\ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, $code, 1, $step ),
				'A code whose step was already consumed must not verify again'
			);
		}

		public function test_every_step_up_to_the_spent_one_is_refused() {
			$step = $this->current_step();

			$this->assertNull(
				\ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, $this->code_for_step( $step - 1 ), 1, $step ),
				'An older code inside the drift window must not be usable after a newer one was accepted'
			);
		}

		public function test_the_next_step_still_verifies_after_one_is_spent() {
			$step = $this->current_step();

			$this->assertSame(
				$step + 1,
				\ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, $this->code_for_step( $step + 1 ), 1, $step ),
				'Consuming a code must not lock the user out of the following one'
			);
		}

		public function test_a_wrong_code_never_matches() {
			$this->assertNull( \ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, '000000', 1, 0 ) );
			$this->assertNull( \ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, 'abcdef' ) );
			$this->assertNull( \ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, '12345' ) );
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_TOTP::verify_code( self::SECRET, '12345678' ) );
		}

		public function test_window_zero_rejects_neighbouring_steps() {
			$step = $this->current_step();

			$this->assertNull( \ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, $this->code_for_step( $step - 1 ), 0 ) );
			$this->assertSame( $step, \ReportedIP_Hive_Two_Factor_TOTP::matching_step( self::SECRET, $this->code_for_step( $step ), 0 ) );
		}

		public function test_verifier_persists_and_honours_the_consumed_step() {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-verifier.php' );
			$start  = strpos( $source, 'private static function verify_totp(' );
			$this->assertNotFalse( $start );
			$body = substr( $source, $start );

			$this->assertStringContainsString( 'META_TOTP_LAST_STEP', $body, 'The verifier must read and write the consumed step' );
			$this->assertStringContainsString( 'matching_step(', $body );
			$this->assertStringContainsString( 'update_user_meta(', $body, 'A successful verification must mark the step spent' );
			$this->assertStringContainsString( 'zero_memory(', $body, 'The decrypted secret must still be wiped' );
		}

		public function test_rest_surface_routes_through_the_shared_verifier() {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-rest.php' );
			$start  = strpos( $source, 'private static function verify_for_user(' );
			$this->assertNotFalse( $start );
			$body = substr( $source, $start );

			$this->assertStringContainsString(
				'Two_Factor_Verifier::verify_method',
				$body,
				'A local copy of the switch drifts and would bypass single-use enforcement'
			);
			$this->assertStringNotContainsString( 'META_TOTP_SECRET', $body, 'REST must not read the secret itself' );
		}
	}
}
