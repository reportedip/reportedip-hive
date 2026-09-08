<?php
/**
 * The audit trail's event filter must offer every type that is written.
 *
 * A type that is recorded but missing from the filter drop-down is invisible
 * to the compliance reader who needs it — the trail is only useful if the
 * rows can be found again.
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

	class AuditLogTableFiltersTest extends TestCase {

		/**
		 * Read one source file from the plugin.
		 *
		 * @param string $relative Path relative to the plugin root.
		 * @return string
		 */
		private function source( string $relative ): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
		}

		public function test_filter_offers_the_new_event_types(): void {
			$source = $this->source( 'admin/class-audit-log-table.php' );

			$this->assertStringContainsString( "'user_block'     => __( 'Account block'", $source );
			$this->assertStringContainsString( "'session'        => __( 'Session'", $source );
		}

		public function test_new_actions_carry_a_badge_class(): void {
			$source = $this->source( 'admin/class-audit-log-table.php' );

			foreach ( array( 'blocked', 'unblocked', 'terminated', 'terminated_all' ) as $action ) {
				$this->assertMatchesRegularExpression(
					"/in_array\( \\\$action, array\([^)]*'" . preg_quote( $action, '/' ) . "'/",
					$source,
					"Audit action $action needs a badge class."
				);
			}
		}

		/**
		 * The public wrapper must keep the tier and opt-out gate the automatic
		 * listeners have; `log_event()` itself stays private.
		 */
		public function test_record_wrapper_keeps_the_gate(): void {
			$source = $this->source( 'includes/class-audit-logger.php' );
			$body   = substr( $source, (int) strpos( $source, 'public function record(' ) );
			$body   = substr( $body, 0, (int) strpos( $body, 'private function log_event(' ) );

			$this->assertStringContainsString( 'self::is_available()', $body );
			$this->assertStringContainsString( 'reportedip_hive_audit_enabled', $body );
			$this->assertStringContainsString( 'private function log_event(', $source );
		}
	}
}
