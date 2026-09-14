<?php
/**
 * The block message must reach the sign-in form unmasked.
 *
 * The anti-enumeration sensor rewrites login errors to "Invalid credentials."
 * unless the error code is outside its masking list and, in the fallback
 * branch, where `global $errors` is not a WP_Error, the text carries one of
 * its passthrough needles. A block message that gets masked leaves a locked
 * out user chasing a password problem that does not exist.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-user-block.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-user-enumeration.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReflectionClass;
	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class UserBlockLoginErrorTest extends TestCase {

		/**
		 * Start from an empty user-meta bucket.
		 */
		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_user_meta'] = array();
		}

		/**
		 * Drop the user-meta bucket again.
		 */
		protected function tear_down() {
			$GLOBALS['wp_user_meta'] = array();
			parent::tear_down();
		}

		/**
		 * Read the login passthrough needle list.
		 *
		 * @return string[]
		 */
		private function login_needles(): array {
			$reflection = new ReflectionClass( \ReportedIP_Hive_User_Enumeration::class );
			return (array) $reflection->getConstant( 'PASSTHROUGH_NEEDLES_LOGIN' );
		}

		/**
		 * Whether a message carries at least one passthrough needle.
		 *
		 * @param string $message Message to check.
		 * @return bool
		 */
		private function passes_unmasked( string $message ): bool {
			foreach ( $this->login_needles() as $needle ) {
				if ( '' !== $needle && false !== stripos( $message, (string) $needle ) ) {
					return true;
				}
			}
			return false;
		}

		public function test_default_message_carries_a_passthrough_needle(): void {
			$this->assertTrue(
				$this->passes_unmasked( \ReportedIP_Hive_User_Block::default_message() ),
				'The default block message must survive normalize_login_errors().'
			);
		}

		public function test_custom_message_inherits_the_needle(): void {
			$GLOBALS['wp_user_meta'][11][ \ReportedIP_Hive_User_Block::META ] = array(
				'blocked_at' => '2026-09-08 10:00:00',
				'message'    => 'Your access ended with your last working day.',
			);

			$message = \ReportedIP_Hive_User_Block::message_for( 11 );

			$this->assertStringContainsString( 'Your access ended with your last working day.', $message );
			$this->assertTrue(
				$this->passes_unmasked( $message ),
				'An operator message without a needle would be replaced by "Invalid credentials."'
			);
		}

		public function test_error_code_is_outside_both_masking_lists(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-user-enumeration.php' );
			$code   = \ReportedIP_Hive_User_Block::ERROR_CODE;

			$this->assertStringContainsString(
				"\$mask_codes = array( 'invalid_username', 'invalid_email', 'incorrect_password', 'invalid_credentials' )",
				$source
			);
			$this->assertStringContainsString(
				"\$leaky_codes = array( 'invalid_username', 'invalid_email', 'incorrect_password' )",
				$source
			);
			$this->assertStringNotContainsString( $code, $source );
		}
	}
}
