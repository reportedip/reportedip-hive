<?php
/**
 * GDPR wiring for the account block and the per-session IP address.
 *
 * An erasure request may not lift a security block — the account would be
 * back the moment the request completes. The free-text fields go, the block
 * itself is reported as retained. Conversely the export must be complete: the
 * proxy-aware session IP is Hive's own field and is absent from core's
 * session export group.
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

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class PrivacyEraserTest extends TestCase {

		/**
		 * Read one source file from the plugin.
		 *
		 * @param string $relative Path relative to the plugin root.
		 * @return string
		 */
		private function source( string $relative ): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
		}

		public function test_eraser_clears_the_texts_and_retains_the_block(): void {
			$source = $this->source( 'includes/class-privacy.php' );
			$body   = substr( $source, (int) strpos( $source, 'public function erase_personal_data(' ) );

			$this->assertStringContainsString( "ReportedIP_Hive_User_Block::update_texts( \$user->ID, '', '' )", $body );
			$this->assertStringContainsString( '$retained   = 1;', $body );
			$this->assertStringContainsString( "'items_retained' => \$retained", $body );
			$this->assertStringNotContainsString( 'User_Block::unblock(', $body );
		}

		/**
		 * The sign-in history exists for users who never enabled 2FA, so it
		 * cannot ride along with the 2FA eraser — that one only runs when a
		 * second factor is active.
		 */
		public function test_eraser_drops_the_sign_in_history_for_every_user(): void {
			$source = $this->source( 'includes/class-privacy.php' );
			$body   = substr( $source, (int) strpos( $source, 'public function erase_personal_data(' ) );

			$this->assertStringContainsString(
				'delete_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_LOGIN_CONTEXT )',
				$body
			);
		}

		/**
		 * The export has to carry the lists the adaptive triggers compare
		 * against, not just the last sign-in.
		 */
		public function test_exporter_covers_the_sign_in_history(): void {
			$source = $this->source( 'includes/class-privacy.php' );
			$body   = substr( $source, (int) strpos( $source, 'public function export_personal_data(' ) );
			$body   = substr( $body, 0, (int) strpos( $body, 'public function erase_personal_data(' ) );

			$this->assertStringContainsString( "'reportedip-hive-login-context'", $body );
			$this->assertStringContainsString( 'ReportedIP_Hive_Login_Context::get(', $body );
			foreach ( array( 'nets', 'uas', 'countries' ) as $list ) {
				$this->assertStringContainsString( "\$login_context['{$list}']", $body );
			}
		}

		public function test_exporter_covers_the_block_and_the_session_ip(): void {
			$source = $this->source( 'includes/class-privacy.php' );
			$body   = substr( $source, (int) strpos( $source, 'public function export_personal_data(' ) );
			$body   = substr( $body, 0, (int) strpos( $body, 'public function erase_personal_data(' ) );

			$this->assertStringContainsString( "'reportedip-hive-account-block'", $body );
			$this->assertStringContainsString( "'reportedip-hive-sessions'", $body );
			$this->assertStringContainsString( 'ReportedIP_Hive_User_Sessions::display_ip(', $body );
		}

		/**
		 * The note is exported to the data subject, so the profile label must
		 * not promise that it stays internal.
		 */
		public function test_note_label_does_not_promise_secrecy(): void {
			$source = $this->source( 'admin/class-user-admin.php' );

			$this->assertStringContainsString( 'Administrator note (not shown at login)', $source );
			$this->assertStringNotContainsString( 'never shown to the user', $source );
		}
	}
}
