<?php
/**
 * Unit tests for the Decoy `.htaccess` writer.
 *
 * Exercises the marker block contents and the move-above-WordPress logic
 * against a temp file (no Docker, no real filesystem permissions). The
 * `sync()` / `remove()` paths are covered indirectly by driving
 * `insert_with_markers()` from WP-Core.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.11
 */

namespace {

	if ( ! function_exists( 'wp_parse_url' ) ) {
		function wp_parse_url( $url, $component = -1 ) {
			return parse_url( $url, $component );
		}
	}
	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $tag, $value ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $value;
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-decoy-path-block.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class DecoyHtaccessWriterTest extends TestCase {

		public function test_block_lines_are_idempotent() {
			$a = \ReportedIP_Hive_Decoy_Path_Block::htaccess_block_lines();
			$b = \ReportedIP_Hive_Decoy_Path_Block::htaccess_block_lines();
			$this->assertSame( $a, $b );
		}

		public function test_block_lines_use_rewrite_not_forbidden() {
			$combined = implode( "\n", \ReportedIP_Hive_Decoy_Path_Block::htaccess_block_lines() );
			$this->assertStringContainsString( 'RewriteRule ^ /index.php [L,QSA]', $combined );
			$this->assertStringNotContainsString( '[F,L]', $combined );
			$this->assertStringNotContainsString( 'return 403', $combined );
		}

		public function test_block_lines_contain_all_default_paths() {
			$combined = implode( "\n", \ReportedIP_Hive_Decoy_Path_Block::htaccess_block_lines() );
			foreach ( \ReportedIP_Hive_Decoy_Path_Block::DEFAULT_PATHS as $path ) {
				$escaped = str_replace( '.', '\\.', ltrim( $path, '/' ) );
				$this->assertStringContainsString( $escaped, $combined, $path . ' missing from alternation' );
			}
		}
	}
}
