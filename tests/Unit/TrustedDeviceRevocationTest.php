<?php
/**
 * Locks the trusted_devices table behind one owner.
 *
 * Three callers used to issue their own DELETE against the trusted_devices
 * table (the geo-anomaly sensor, the user-deletion hook and the GDPR eraser)
 * next to the 2FA engine's `revoke_all_trusted_devices()`. Four copies of
 * one statement drift: a column rename, a cache layer or a revocation hook
 * added to the helper would silently miss the copies. This test keeps every
 * revocation on the helper.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Source-inspection guard: every DELETE against the trusted_devices table
	 * outside the 2FA engine is a regression.
	 *
	 * @since 2.1.51
	 */
	class TrustedDeviceRevocationTest extends TestCase {

		/**
		 * Plugin source files, keyed by repo-relative path.
		 *
		 * @return array<string,string>
		 */
		private function sources(): array {
			$root  = dirname( __DIR__, 2 );
			$files = array_merge(
				glob( $root . '/includes/*.php' ) ?: array(),
				glob( $root . '/includes/*/*.php' ) ?: array(),
				glob( $root . '/admin/*.php' ) ?: array(),
				array( $root . '/reportedip-hive.php' )
			);

			$out = array();
			foreach ( $files as $file ) {
				$out[ substr( str_replace( DIRECTORY_SEPARATOR, '/', $file ), strlen( str_replace( DIRECTORY_SEPARATOR, '/', $root ) ) + 1 ) ] = (string) file_get_contents( $file );
			}
			return $out;
		}

		/**
		 * No file except class-two-factor.php may delete from the trusted_devices table.
		 */
		public function test_only_two_factor_deletes_from_trusted_devices(): void {
			$checked = 0;
			foreach ( $this->sources() as $path => $source ) {
				if ( 'includes/class-two-factor.php' === $path ) {
					continue;
				}
				preg_match_all( '/\$wpdb->delete\(|DELETE\s+FROM/i', $source, $m, PREG_OFFSET_CAPTURE );
				foreach ( $m[0] as $hit ) {
					$offset   = (int) $hit[1];
					$fn_start = strrpos( substr( $source, 0, $offset ), 'function ' );
					$fn_start = false === $fn_start ? 0 : $fn_start;
					$stmt_end = strpos( $source, ';', $offset );
					$stmt_end = false === $stmt_end ? strlen( $source ) : $stmt_end;
					$window   = substr( $source, $fn_start, $stmt_end - $fn_start );
					++$checked;
					$this->assertDoesNotMatchRegularExpression(
						'/trusted_devices/i',
						$window,
						"{$path} deletes from the trusted_devices table directly; route it through ReportedIP_Hive_Two_Factor::revoke_all_trusted_devices()."
					);
				}
			}
			$this->assertGreaterThan( 0, $checked, 'The scan found no DELETE statements at all; the source glob is broken.' );
		}

		/**
		 * The three former direct callers must call the shared helper.
		 */
		public function test_known_callers_use_the_helper(): void {
			$sources = $this->sources();
			foreach ( array( 'includes/class-geo-anomaly.php', 'includes/class-privacy.php', 'reportedip-hive.php' ) as $path ) {
				$this->assertStringContainsString(
					'ReportedIP_Hive_Two_Factor::revoke_all_trusted_devices(',
					$sources[ $path ],
					"{$path} must revoke trusted devices through the shared helper."
				);
			}
		}
	}
}
