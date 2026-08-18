<?php
/**
 * Guards that inline fallbacks agree with the canonical defaults registry.
 *
 * `Option_Routing::get()` takes a fallback used only while the option is
 * missing from the database. Several sensors passed a different value than
 * `Defaults::SAFE_OPTIONS` declares — the 404 burst threshold read 8 where the
 * registry says 12, comment spam 3 against 5, the REST burst cap 60 against
 * 240. Seeding on activation and upgrade means the fallback rarely fires, so
 * the contradiction stayed invisible while quietly making the registry a
 * second, non-authoritative source of truth.
 *
 * This scans the source for `Option_Routing::get( 'reportedip_hive_*', <literal> )`
 * and fails when a literal contradicts the registry.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.44
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class InlineDefaultConsistencyTest extends TestCase {

		/**
		 * Options whose inline fallback legitimately differs from the registry.
		 *
		 * Keep this list short and justified — each entry is a place where the
		 * canonical default deliberately does not apply.
		 *
		 * @var array<string, string>
		 */
		private const EXEMPT = array(
			// Tier downgrade intentionally narrows the offer to the free methods.
			'reportedip_hive_2fa_allowed_methods' => 'context-specific narrowing',
		);

		/**
		 * Numeric and boolean defaults worth pinning.
		 *
		 * @return array<string, scalar>
		 */
		private function canonical(): array {
			require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';

			return \ReportedIP_Hive_Defaults::all_option_defaults();
		}

		/**
		 * Every plugin source file.
		 *
		 * @return string[]
		 */
		private function source_files(): array {
			$root  = dirname( __DIR__, 2 );
			$files = array();

			foreach ( array( '/includes', '/admin' ) as $dir ) {
				$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root . $dir ) );
				foreach ( $iterator as $file ) {
					if ( $file->isFile() && 'php' === $file->getExtension() ) {
						$files[] = $file->getPathname();
					}
				}
			}

			$files[] = $root . '/reportedip-hive.php';

			return $files;
		}

		public function test_inline_fallbacks_match_the_registry() {
			$canonical = $this->canonical();
			$conflicts = array();

			foreach ( $this->source_files() as $path ) {
				$source = (string) file_get_contents( $path );

				if ( ! preg_match_all(
					"/Option_Routing::get\(\s*'(reportedip_hive_[a-z0-9_]+)'\s*,\s*(true|false|-?\d+)\s*\)/i",
					$source,
					$matches,
					PREG_SET_ORDER
				) ) {
					continue;
				}

				foreach ( $matches as $match ) {
					$option = $match[1];
					if ( ! array_key_exists( $option, $canonical ) || isset( self::EXEMPT[ $option ] ) ) {
						continue;
					}

					$literal  = strtolower( $match[2] );
					$inline   = 'true' === $literal ? true : ( 'false' === $literal ? false : (int) $literal );
					$expected = $canonical[ $option ];

					if ( is_bool( $expected ) || is_bool( $inline ) ) {
						$matches_registry = (bool) $inline === (bool) $expected;
					} elseif ( is_numeric( $expected ) ) {
						$matches_registry = (int) $inline === (int) $expected;
					} else {
						continue;
					}

					if ( ! $matches_registry ) {
						$conflicts[] = sprintf(
							'%s: %s inline=%s registry=%s',
							basename( $path ),
							$option,
							var_export( $inline, true ),
							var_export( $expected, true )
						);
					}
				}
			}

			$this->assertSame(
				array(),
				$conflicts,
				"Inline fallbacks must not contradict Defaults::SAFE_OPTIONS:\n" . implode( "\n", $conflicts )
			);
		}

		public function test_the_previously_divergent_sensors_now_agree() {
			$canonical = $this->canonical();

			$this->assertSame( 12, $canonical['reportedip_hive_scan_404_threshold'] );
			$this->assertSame( 2, $canonical['reportedip_hive_scan_404_timeframe'] );
			$this->assertSame( 5, $canonical['reportedip_hive_comment_spam_threshold'] );
			$this->assertSame( 240, $canonical['reportedip_hive_rest_threshold'] );

			$detector = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-scan-detector.php' );
			$this->assertStringContainsString( "'reportedip_hive_scan_404_threshold', 12 )", $detector );
			$this->assertStringContainsString( "'reportedip_hive_scan_404_timeframe', 2 )", $detector );

			$monitor = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php' );
			$this->assertStringContainsString( "'reportedip_hive_comment_spam_threshold', 5 )", $monitor );

			$rest = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-rest-monitor.php' );
			$this->assertStringContainsString( "'reportedip_hive_rest_threshold', 240 )", $rest );
		}
	}
}
