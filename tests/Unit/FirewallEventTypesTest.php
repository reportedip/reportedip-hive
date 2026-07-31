<?php
/**
 * Regression guard: every event type the Firewall page counts must be one the
 * plugin actually writes.
 *
 * The Firewall overview listed `scan_404`, but the scan detector funnels 404s
 * through the shared attempt tracker, which logs only the generated
 * `scan_404_threshold_exceeded` variant. The counter and the log filter
 * therefore reported zero forever while scanners were being blocked and their
 * IPs laddered — a silent, self-consistent lie. This test locks the two lists
 * together so a new counter cannot drift from the writer again.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.30
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/admin/class-admin-firewall.php';

	/**
	 * @covers \ReportedIP_Hive_Admin_Firewall
	 */
	class FirewallEventTypesTest extends TestCase {

		/**
		 * Concatenated plugin sources, without the tests themselves.
		 */
		private function sources(): string {
			$root  = dirname( __DIR__, 2 );
			$files = array_merge(
				glob( $root . '/includes/*.php' ) ?: array(),
				glob( $root . '/includes/*/*.php' ) ?: array(),
				glob( $root . '/admin/*.php' ) ?: array(),
				array( $root . '/reportedip-hive.php' )
			);

			$body = '';
			foreach ( $files as $file ) {
				$body .= (string) file_get_contents( $file ) . "\n";
			}
			return $body;
		}

		public function test_every_counted_event_type_has_a_writer(): void {
			$sources = $this->sources();

			foreach ( \ReportedIP_Hive_Admin_Firewall::FIREWALL_EVENT_TYPES as $type ) {
				if ( str_ends_with( $type, '_threshold_exceeded' ) ) {
					$base = substr( $type, 0, -strlen( '_threshold_exceeded' ) );
					$this->assertMatchesRegularExpression(
						'/(?:track_generic_attempt|handle_threshold_exceeded)\((?:[^;]{0,200}?)\'' . preg_quote( $base, '/' ) . '\'/s',
						$sources,
						"No code path feeds '{$base}' into the threshold tracker, so '{$type}' can never be logged."
					);
					continue;
				}

				$this->assertMatchesRegularExpression(
					'/log_security_event\((?:[^;]{0,240}?)\'' . preg_quote( $type, '/' ) . '\'/s',
					$sources,
					"The Firewall page counts '{$type}', but nothing logs it."
				);
			}
		}

		/**
		 * The bare base type is the trap that caused the bug: it reads plausible
		 * and is used all over the detector, but it is never a stored event type.
		 */
		public function test_bare_scan_404_is_not_counted(): void {
			$this->assertNotContains(
				'scan_404',
				\ReportedIP_Hive_Admin_Firewall::FIREWALL_EVENT_TYPES,
				'scan_404 is an attempt-tracker key, not a logged event type.'
			);
		}
	}
}
