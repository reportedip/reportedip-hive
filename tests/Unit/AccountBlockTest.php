<?php
/**
 * Unit tests for the account-block enforcement of the free plugin.
 *
 * The record shape and the text caps are pure statics and are exercised
 * directly. The hook priorities that make the deny path safe, and the rule
 * that neither enforcement nor unblocking ever asks the plan or the add-on,
 * are anchored by source inspection, the established pattern from
 * SecurityMonitorBotGuardTest. Writing a block is tested with the add-on.
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
	require_once dirname( __DIR__ ) . '/stubs/two-factor-runtime-stubs.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-account-block.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class AccountBlockTest extends TestCase {

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
		 * Read one source file from the plugin.
		 *
		 * @param string $relative Path relative to the plugin root.
		 * @return string
		 */
		private function source( string $relative ): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
		}

		public function test_normalize_rejects_anything_without_a_timestamp(): void {
			$this->assertNull( \ReportedIP_Hive_Account_Block::normalize( '' ) );
			$this->assertNull( \ReportedIP_Hive_Account_Block::normalize( 'blocked' ) );
			$this->assertNull( \ReportedIP_Hive_Account_Block::normalize( array() ) );
			$this->assertNull( \ReportedIP_Hive_Account_Block::normalize( array( 'message' => 'hi' ) ) );
		}

		public function test_normalize_pads_the_record_shape(): void {
			$record = \ReportedIP_Hive_Account_Block::normalize( array( 'blocked_at' => '2026-09-08 10:00:00' ) );

			$this->assertSame(
				array(
					'blocked_at' => '2026-09-08 10:00:00',
					'blocked_by' => 0,
					'message'    => '',
					'note'       => '',
				),
				$record
			);
		}

		public function test_sanitize_texts_caps_both_fields(): void {
			$texts = \ReportedIP_Hive_Account_Block::sanitize_texts(
				str_repeat( 'm', 900 ),
				str_repeat( 'n', 1400 )
			);

			$this->assertSame( \ReportedIP_Hive_Account_Block::MESSAGE_MAX, mb_strlen( $texts['message'] ) );
			$this->assertSame( \ReportedIP_Hive_Account_Block::NOTE_MAX, mb_strlen( $texts['note'] ) );
		}

		public function test_sanitize_texts_strips_control_characters(): void {
			$texts = \ReportedIP_Hive_Account_Block::sanitize_texts( "clean\x00text", "note\x08here" );

			$this->assertSame( 'cleantext', $texts['message'] );
			$this->assertSame( 'notehere', $texts['note'] );
		}

		public function test_message_for_falls_back_to_the_default_sentence(): void {
			$this->assertSame(
				\ReportedIP_Hive_Account_Block::default_message(),
				\ReportedIP_Hive_Account_Block::message_for( 42 )
			);
		}

		public function test_message_for_appends_the_operator_text(): void {
			$GLOBALS['wp_user_meta'][42][ \ReportedIP_Hive_Account_Block::META ] = array(
				'blocked_at' => '2026-09-08 10:00:00',
				'message'    => 'Call HR on 555-0100.',
			);

			$message = \ReportedIP_Hive_Account_Block::message_for( 42 );

			$this->assertStringStartsWith( \ReportedIP_Hive_Account_Block::default_message(), $message );
			$this->assertStringContainsString( 'Call HR on 555-0100.', $message );
		}

		public function test_is_blocked_follows_the_meta_record(): void {
			$this->assertFalse( \ReportedIP_Hive_Account_Block::is_blocked( 42 ) );

			$GLOBALS['wp_user_meta'][42][ \ReportedIP_Hive_Account_Block::META ] = array( 'blocked_at' => '2026-09-08 10:00:00' );

			$this->assertTrue( \ReportedIP_Hive_Account_Block::is_blocked( 42 ) );
		}

		/**
		 * The deny path only works if it runs after core's credential check
		 * (20) and before the 2FA challenge and the error-code masking (99).
		 */
		public function test_hooks_carry_the_documented_priorities_and_arg_counts(): void {
			$source = $this->source( 'includes/class-account-block.php' );

			$this->assertStringContainsString(
				"add_filter( 'authenticate', array( __CLASS__, 'deny_authenticate' ), 30, 3 )",
				$source
			);
			$this->assertStringContainsString(
				"add_filter( 'determine_current_user', array( __CLASS__, 'deny_current_user' ), 99 )",
				$source
			);
			$this->assertStringContainsString(
				"add_action( 'validate_password_reset', array( __CLASS__, 'deny_password_reset' ), 4, 2 )",
				$source
			);
		}

		/**
		 * Enforcement and unblocking must never consult the plan or the
		 * add-on: an account blocked under 2.x, or while the add-on ran,
		 * stays blocked when only the free plugin is left, and a lapsed
		 * licence may not hand a released account its access back.
		 */
		public function test_enforcement_and_unblock_never_ask_the_plan(): void {
			$source = $this->source( 'includes/class-account-block.php' );

			foreach ( array( 'is_available', 'feature_status', 'tier', 'REPORTEDIP_HIVE_PRO', 'Audit' ) as $needle ) {
				$this->assertStringNotContainsString( $needle, $source, "account block enforcement must not depend on $needle" );
			}
			$this->assertStringContainsString(
				'ReportedIP_Hive_Account_Block::register_hooks();',
				$this->source( 'reportedip-hive.php' ),
				'the free bootstrap registers the enforcement on its own'
			);
		}

		/**
		 * The free plugin lifts a block and tells the add-on, which writes
		 * the audit row 2.1.74 wrote from here.
		 */
		public function test_unblock_lifts_the_record_and_announces_it(): void {
			$GLOBALS['wp_user_meta'][42][ \ReportedIP_Hive_Account_Block::META ] = array( 'blocked_at' => '2026-09-08 10:00:00' );
			$heard = array();
			add_action(
				'reportedip_hive_user_unblocked',
				static function ( $user_id ) use ( &$heard ) {
					$heard[] = $user_id;
				}
			);

			$this->assertTrue( \ReportedIP_Hive_Account_Block::unblock( 42 ) );
			$this->assertFalse( \ReportedIP_Hive_Account_Block::is_blocked( 42 ) );
			$this->assertSame( array( 42 ), $heard );
		}

		/**
		 * A refused sign-in of a blocked account carries the correct password
		 * and must not feed the IP failed-login ladder.
		 */
		public function test_failed_login_listener_skips_the_block_error_code(): void {
			$source = $this->source( 'reportedip-hive.php' );

			$this->assertStringContainsString(
				"add_action( 'wp_login_failed', array( \$this, 'handle_failed_login' ), 10, 2 )",
				$source
			);
			$this->assertStringContainsString(
				'in_array( ReportedIP_Hive_Account_Block::ERROR_CODE, $error->get_error_codes(), true )',
				$source
			);
		}

		/**
		 * The block record is the one piece of plugin-owned user meta that
		 * lives outside the 2FA key list, so the opt-in "delete everything on
		 * uninstall" path has to name it explicitly or it survives a removal
		 * that promised total cleanup.
		 */
		public function test_uninstall_deletes_the_account_block_meta(): void {
			$source    = $this->source( 'reportedip-hive.php' );
			$uninstall = substr( $source, (int) strpos( $source, 'public static function uninstall(' ) );
			$uninstall = substr( $uninstall, 0, (int) strpos( $uninstall, "\n\t}" ) );

			$this->assertStringContainsString(
				"delete_metadata( 'user', 0, ReportedIP_Hive_Account_Block::META, '', true )",
				$uninstall
			);
		}
	}
}
