<?php
/**
 * Architecture invariant test for network-wide table prefix usage.
 *
 * All seven plugin tables live under `$wpdb->base_prefix`. On Multisite,
 * `$wpdb->prefix` resolves to the per-blog prefix (`wp_2_…`) and points at a
 * table that never exists — reads silently return nothing and flood the DB
 * error log (this disabled block escalation on every subsite in 2.1.25).
 * Outside the data layer the only sanctioned accessor is
 * `ReportedIP_Hive_Schema::table()`; this scan trips on any reintroduction
 * of a `$wpdb->prefix`-built plugin table name.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.26
 */

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class PrefixInvariantTest extends TestCase {

		/**
		 * Collect every shipped PHP source file (main file, includes/, admin/).
		 *
		 * @return string[] Absolute paths.
		 */
		private function shipped_sources(): array {
			$root  = dirname( __DIR__, 2 );
			$files = array( $root . '/reportedip-hive.php' );
			foreach ( array( 'includes', 'admin' ) as $dir ) {
				$iterator = new \RecursiveIteratorIterator(
					new \RecursiveDirectoryIterator( $root . '/' . $dir, \FilesystemIterator::SKIP_DOTS )
				);
				foreach ( $iterator as $file ) {
					if ( 'php' === strtolower( $file->getExtension() ) ) {
						$files[] = $file->getPathname();
					}
				}
			}
			return $files;
		}

		public function test_no_per_blog_prefix_reaches_plugin_tables() {
			$offenders = array();
			foreach ( $this->shipped_sources() as $path ) {
				$source = (string) file_get_contents( $path );
				if ( false !== strpos( $source, "\$wpdb->prefix . 'reportedip_hive" ) ) {
					$offenders[] = basename( $path );
				}
			}

			$this->assertSame(
				array(),
				$offenders,
				'Plugin tables are network-wide: build their names via ReportedIP_Hive_Schema::table() (base_prefix), never $wpdb->prefix. Offending files: ' . implode( ', ', $offenders )
			);
		}
	}
}
