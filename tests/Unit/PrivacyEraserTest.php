<?php
/**
 * GDPR wiring for the account block and the per-session IP address.
 *
 * An erasure request may not lift a security block, the account would be
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

		/**
		 * The export reads the stored history itself and pads a partial or
		 * broken row to the full shape.
		 *
		 * @runInSeparateProcess
		 * @preserveGlobalState disabled
		 */
		public function test_export_reads_the_stored_history_without_the_add_on(): void {
			require_once dirname( __DIR__ ) . '/stubs/two-factor-runtime-stubs.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-privacy.php';
			$read = new \ReflectionMethod( \ReportedIP_Hive_Privacy::class, 'stored_login_context' );

			$GLOBALS['wp_user_meta'][4]['reportedip_hive_login_context'] = (string) wp_json_encode(
				array(
					'last'                => array(
						'ip' => '198.51.100.4',
						'ts' => 1700000000,
					),
					'logins_since_verify' => 3,
					'nets'                => array( '198.51.100.0/24' ),
					'uas'                 => 'broken',
				)
			);
			$context = $read->invoke( null, 4 );

			$this->assertSame( '198.51.100.4', $context['last']['ip'] );
			$this->assertSame( '', $context['last']['country'] );
			$this->assertSame( 1700000000, $context['last']['ts'] );
			$this->assertSame( 3, $context['logins_since_verify'] );
			$this->assertSame( array( '198.51.100.0/24' ), $context['nets'] );
			$this->assertSame( array(), $context['uas'] );
			$this->assertSame( 0, $read->invoke( null, 5 )['last']['ts'], 'No row, no history.' );
		}

		public function test_eraser_clears_the_texts_and_retains_the_block(): void {
			$source = $this->source( 'includes/class-privacy.php' );
			$body   = substr( $source, (int) strpos( $source, 'public function erase_personal_data(' ) );

			$this->assertStringContainsString( "ReportedIP_Hive_User_Block::update_texts( \$user->ID, '', '' )", $body );
			$this->assertStringContainsString( '$retained   = 1;', $body );
			$this->assertStringContainsString( "'retained' => \$retained", $body );
			$this->assertStringContainsString( "'items_retained' => (int) ( \$result['retained'] ?? \$retained )", $body );
			$this->assertStringNotContainsString( 'User_Block::unblock(', $body );
		}

		/**
		 * The sign-in history exists for users who never enabled 2FA, so it
		 * cannot ride along with the 2FA eraser, that one only runs when a
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
			$this->assertStringContainsString( 'self::stored_login_context( $user->ID )', $body );
			$this->assertStringContainsString( 'ReportedIP_Hive_Two_Factor::META_LOGIN_CONTEXT', $source, 'The history is read from the meta, also while the add-on that records it is inactive.' );
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
		 * The audit table belongs to the add-on: the free exporter and eraser
		 * reach it only through the legacy routine (rows a 2.x release left
		 * behind, no add-on claiming them) and hand the rest to the filters.
		 */
		public function test_audit_rows_go_through_the_legacy_routine_and_the_filters(): void {
			$source = $this->source( 'includes/class-privacy.php' );

			$this->assertStringNotContainsString( 'reportedip_hive_audit_log', $source );
			$this->assertStringContainsString( 'ReportedIP_Hive_Legacy_Data::export_items( $user )', $source );
			$this->assertStringContainsString( 'ReportedIP_Hive_Legacy_Data::erase( $user )', $source );
			$this->assertStringContainsString( "apply_filters( 'reportedip_hive_privacy_export_items', \$items, \$user )", $source );
			$this->assertStringContainsString( "'reportedip_hive_privacy_erase',", $source );
			$this->assertLessThan( strpos( $source, "'reportedip_hive_privacy_erase'," ), strpos( $source, 'ReportedIP_Hive_Legacy_Data::erase( $user )' ) );
		}
	}
}
