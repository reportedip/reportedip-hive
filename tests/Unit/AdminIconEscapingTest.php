<?php
/**
 * Guard: an inline SVG icon is never emitted through `wp_kses_post()`.
 *
 * WordPress' post allowlist contains no `svg`, `path`, `polyline`, `line`,
 * `circle` or `ellipse` element, so `wp_kses_post()` deletes an inline icon
 * whole and leaves an empty container behind. That is exactly what happened to
 * the three health cards and their status pills on the System Status page:
 * the markup was correct, the icons were simply filtered away before they
 * reached the browser.
 *
 * The plugin already owns the right tool, `Admin_Settings::kses_inline_svg()`,
 * which allows the icon vocabulary and nothing else. This scan makes the wrong
 * one impossible to reintroduce.
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

	class AdminIconEscapingTest extends TestCase {

		/**
		 * Every PHP file that renders admin or template markup.
		 *
		 * @return string[]
		 */
		private function markup_files(): array {
			$root  = dirname( __DIR__, 2 );
			$files = array();
			foreach ( array( '/admin', '/templates' ) as $dir ) {
				$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root . $dir ) );
				foreach ( $iterator as $file ) {
					if ( $file->isFile() && 'php' === $file->getExtension() ) {
						$files[] = $file->getPathname();
					}
				}
			}

			return $files;
		}

		public function test_no_icon_is_filtered_through_wp_kses_post(): void {
			$offenders = array();
			$scanned   = 0;

			foreach ( $this->markup_files() as $path ) {
				++$scanned;
				foreach ( (array) file( $path ) as $number => $line ) {
					if ( false === strpos( $line, 'wp_kses_post(' ) ) {
						continue;
					}
					if ( false === stripos( $line, 'icon' ) && false === stripos( $line, 'svg' ) ) {
						continue;
					}
					$offenders[] = basename( $path ) . ':' . ( $number + 1 ) . ' ' . trim( $line );
				}
			}

			$this->assertGreaterThan( 0, $scanned, 'No markup file was scanned, the file walk has drifted from the tree.' );
			$this->assertSame(
				array(),
				$offenders,
				"wp_kses_post() strips inline SVG. Use ReportedIP_Hive_Admin_Settings::kses_inline_svg() instead:\n" . implode( "\n", $offenders )
			);
		}

		/**
		 * The System Status health cards are the concrete regression: both the
		 * card icon and the status pill lost their glyph.
		 */
		public function test_system_status_health_cards_use_the_svg_helper(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php' );

			$this->assertStringContainsString( "self::kses_inline_svg( \$item['icon'] )", $source );
			$this->assertStringContainsString( 'self::kses_inline_svg( $pill_icons[ $status_class ] )', $source );
		}
	}
}
