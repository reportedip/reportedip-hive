<?php
/**
 * Unit tests for the account-block state machine.
 *
 * The record shape, the text caps and the refusal rules are pure statics and
 * are exercised directly. `block()` itself depends on the plugin's runtime
 * singletons (session tokens, 2FA engine, audit logger), so its contract —
 * the hook priorities that make the deny path safe, and the order in which it
 * revokes access — is anchored by source inspection, the established pattern
 * from SecurityMonitorBotGuardTest.
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
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class UserBlockTest extends TestCase {

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
			$this->assertNull( \ReportedIP_Hive_User_Block::normalize( '' ) );
			$this->assertNull( \ReportedIP_Hive_User_Block::normalize( 'blocked' ) );
			$this->assertNull( \ReportedIP_Hive_User_Block::normalize( array() ) );
			$this->assertNull( \ReportedIP_Hive_User_Block::normalize( array( 'message' => 'hi' ) ) );
		}

		public function test_normalize_pads_the_record_shape(): void {
			$record = \ReportedIP_Hive_User_Block::normalize( array( 'blocked_at' => '2026-09-08 10:00:00' ) );

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
			$texts = \ReportedIP_Hive_User_Block::sanitize_texts(
				str_repeat( 'm', 900 ),
				str_repeat( 'n', 1400 )
			);

			$this->assertSame( \ReportedIP_Hive_User_Block::MESSAGE_MAX, mb_strlen( $texts['message'] ) );
			$this->assertSame( \ReportedIP_Hive_User_Block::NOTE_MAX, mb_strlen( $texts['note'] ) );
		}

		public function test_sanitize_texts_strips_control_characters(): void {
			$texts = \ReportedIP_Hive_User_Block::sanitize_texts( "clean\x00text", "note\x08here" );

			$this->assertSame( 'cleantext', $texts['message'] );
			$this->assertSame( 'notehere', $texts['note'] );
		}

		/**
		 * @dataProvider refusal_cases
		 *
		 * @param int      $actor    Acting administrator.
		 * @param int      $target   Target account.
		 * @param bool     $super    Whether the target is a super admin.
		 * @param int|null $others   Other unblocked administrators, null when not an admin.
		 * @param string   $expected Expected refusal token.
		 */
		public function test_refusal_reason( int $actor, int $target, bool $super, ?int $others, string $expected ): void {
			$this->assertSame(
				$expected,
				\ReportedIP_Hive_User_Block::refusal_reason( $actor, $target, $super, $others )
			);
		}

		/**
		 * Refusal matrix.
		 *
		 * @return array<string,array{0:int,1:int,2:bool,3:int|null,4:string}>
		 */
		public static function refusal_cases(): array {
			return array(
				'self block'                 => array( 7, 7, false, null, 'self' ),
				'super admin'                => array( 7, 9, true, null, 'super_admin' ),
				'self wins over super admin' => array( 9, 9, true, null, 'self' ),
				'last unblocked admin'       => array( 7, 9, false, 0, 'last_admin' ),
				'admin with a peer left'     => array( 7, 9, false, 1, '' ),
				'ordinary account'           => array( 7, 9, false, null, '' ),
			);
		}

		public function test_message_for_falls_back_to_the_default_sentence(): void {
			$this->assertSame(
				\ReportedIP_Hive_User_Block::default_message(),
				\ReportedIP_Hive_User_Block::message_for( 42 )
			);
		}

		public function test_message_for_appends_the_operator_text(): void {
			$GLOBALS['wp_user_meta'][42][ \ReportedIP_Hive_User_Block::META ] = array(
				'blocked_at' => '2026-09-08 10:00:00',
				'message'    => 'Call HR on 555-0100.',
			);

			$message = \ReportedIP_Hive_User_Block::message_for( 42 );

			$this->assertStringStartsWith( \ReportedIP_Hive_User_Block::default_message(), $message );
			$this->assertStringContainsString( 'Call HR on 555-0100.', $message );
		}

		public function test_is_blocked_follows_the_meta_record(): void {
			$this->assertFalse( \ReportedIP_Hive_User_Block::is_blocked( 42 ) );

			$GLOBALS['wp_user_meta'][42][ \ReportedIP_Hive_User_Block::META ] = array( 'blocked_at' => '2026-09-08 10:00:00' );

			$this->assertTrue( \ReportedIP_Hive_User_Block::is_blocked( 42 ) );
		}

		/**
		 * The deny path only works if it runs after core's credential check
		 * (20) and before the 2FA challenge and the error-code masking (99).
		 */
		public function test_hooks_carry_the_documented_priorities_and_arg_counts(): void {
			$source = $this->source( 'includes/class-user-block.php' );

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
		 * Sessions and trusted devices must be gone before the audit row is
		 * written, so a crash between the steps never leaves a "blocked" trail
		 * next to a still-usable session.
		 */
		public function test_block_revokes_access_before_it_writes_the_audit_row(): void {
			$source = $this->source( 'includes/class-user-block.php' );
			$body   = substr( $source, (int) strpos( $source, 'public static function block(' ) );
			$body   = substr( $body, 0, (int) strpos( $body, 'public static function update_texts(' ) );

			$destroy = strpos( $body, '->destroy_all()' );
			$revoke  = strpos( $body, 'revoke_all_trusted_devices(' );
			$audit   = strpos( $body, "->record(" );

			$this->assertIsInt( $destroy );
			$this->assertIsInt( $revoke );
			$this->assertIsInt( $audit );
			$this->assertLessThan( $revoke, $destroy );
			$this->assertLessThan( $audit, $revoke );
		}

		/**
		 * Enforcement and unblocking must never consult the plan: a lapsed
		 * licence may not hand a released account its access back.
		 */
		public function test_only_the_write_side_is_tier_gated(): void {
			$source = $this->source( 'includes/class-user-block.php' );

			foreach ( array( 'unblock', 'deny_authenticate', 'deny_current_user', 'deny_password_reset' ) as $method ) {
				$start = (int) strpos( $source, 'public static function ' . $method . '(' );
				$body  = substr( $source, $start, 1800 );
				$body  = substr( $body, 0, (int) strpos( $body, "\n\t}" ) );
				$this->assertStringNotContainsString( 'is_available()', $body, "$method must not be tier-gated" );
			}

			$start = (int) strpos( $source, 'public static function block(' );
			$body  = substr( $source, $start, 2500 );
			$this->assertStringContainsString( 'is_available()', $body, 'block() must be tier-gated' );
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
				'in_array( ReportedIP_Hive_User_Block::ERROR_CODE, $error->get_error_codes(), true )',
				$source
			);
		}

		/**
		 * The users list posts through a GET form and `wp-admin/users.php`
		 * redirects to a URL without `_wpnonce` before it dispatches
		 * `handle_bulk_actions-users`, so a handler hooked there can never pass
		 * `check_admin_referer( 'bulk-users' )`. The single-site bulk action has
		 * to run on `load-users.php`, while the request is still intact.
		 */
		public function test_single_site_bulk_action_runs_before_the_nonce_is_stripped(): void {
			$source = $this->source( 'admin/class-user-admin.php' );

			$this->assertStringContainsString(
				"add_action( 'load-users.php', array( \$this, 'handle_bulk_single_site' ) )",
				$source
			);
			$this->assertStringNotContainsString( "handle_bulk_actions-users'", $source );
			$this->assertStringContainsString(
				"add_filter( 'handle_network_bulk_actions-users-network', array( \$this, 'handle_bulk_network' ), 10, 3 )",
				$source
			);
		}

		/**
		 * Network Admin dispatches `network_admin_notices`, never
		 * `admin_notices`, so the bulk result would be invisible on multisite.
		 */
		public function test_bulk_result_notice_reaches_network_admin(): void {
			$source = $this->source( 'admin/class-user-admin.php' );

			$this->assertStringContainsString(
				"add_action( 'all_admin_notices', array( \$this, 'show_users_notice' ) )",
				$source
			);
		}
	}
}
