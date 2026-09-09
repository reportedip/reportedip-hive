<?php
/**
 * Guard: the test suite calls no reflection method PHP has deprecated.
 *
 * `ReflectionProperty::setAccessible()` and `ReflectionMethod::setAccessible()`
 * have done nothing since PHP 8.1 and are deprecated as of 8.5. The CI matrix
 * runs 8.5 with deprecations promoted to failures, and the local stack is 8.4,
 * so a call like that passes every local run and turns the pipeline red only
 * after the push. Thirteen tests failed that way on the 2.1.51 release commit.
 *
 * The plugin requires PHP 8.1, so dropping the calls is behaviour-preserving
 * across the whole supported range. This scan keeps them from coming back.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.52
 */

declare(strict_types=1);

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class ReflectionDeprecationTest extends TestCase {

		/**
		 * Every PHP file under tests/ and the shipped source directories.
		 *
		 * @return string[]
		 */
		private function php_files(): array {
			$root  = dirname( __DIR__, 2 );
			$files = array();
			foreach ( array( '/tests', '/includes', '/admin', '/templates' ) as $dir ) {
				if ( ! is_dir( $root . $dir ) ) {
					continue;
				}
				$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root . $dir ) );
				foreach ( $iterator as $file ) {
					if ( ! $file->isFile() || 'php' !== $file->getExtension() ) {
						continue;
					}
					/* This guard names the forbidden call in its own text. */
					if ( realpath( $file->getPathname() ) === realpath( __FILE__ ) ) {
						continue;
					}
					$files[] = $file->getPathname();
				}
			}

			return $files;
		}

		public function test_no_deprecated_reflection_setaccessible_call(): void {
			$root      = dirname( __DIR__, 2 );
			$offenders = array();

			foreach ( $this->php_files() as $path ) {
				foreach ( (array) file( $path ) as $number => $line ) {
					if ( false === strpos( $line, 'setAccessible' ) ) {
						continue;
					}
					$offenders[] = str_replace( $root, '', $path ) . ':' . ( $number + 1 );
				}
			}

			$this->assertSame(
				array(),
				$offenders,
				"setAccessible() is a no-op since PHP 8.1 and deprecated in 8.5, where CI turns deprecations into failures. Drop the call:\n"
					. implode( "\n", $offenders )
			);
		}
	}
}
