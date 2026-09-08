<?php
/**
 * Unit tests for the shared `.htaccess` marker-block lifecycle.
 *
 * Driven against a temp file through a throwaway subclass, so the strip path
 * (which must remove the whole BEGIN/END pair instead of leaving an empty
 * skeleton) is covered without Docker or real file permissions.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

namespace {

	if ( ! function_exists( 'add_action' ) ) {
		function add_action( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'get_home_path' ) ) {
		function get_home_path() {
			return sys_get_temp_dir() . '/';
		}
	}
	if ( ! function_exists( 'insert_with_markers' ) ) {
		function insert_with_markers( $filename, $marker, $insertion ) {
			$existing = file_exists( $filename ) ? (string) file_get_contents( $filename ) : '';
			$pattern  = '/# BEGIN ' . preg_quote( $marker, '/' ) . '.*?# END ' . preg_quote( $marker, '/' ) . '\R?/s';
			$existing = (string) preg_replace( $pattern, '', $existing );
			$block    = '# BEGIN ' . $marker . "\n" . implode( "\n", (array) $insertion ) . "\n" . '# END ' . $marker . "\n";
			return false !== file_put_contents( $filename, rtrim( $existing, "\r\n" ) . "\n" . $block );
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-option-routing.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-htaccess-block-writer.php';

	/**
	 * Throwaway writer pointed at a temp file.
	 */
	class RIP_Test_Block_Writer extends ReportedIP_Hive_Htaccess_Block_Writer {

		const MARKER = 'ReportedIP Hive Test';

		const HEAL_LOCK_TRANSIENT = 'reportedip_hive_test_block_heal';

		/**
		 * Target file path.
		 *
		 * @var string
		 */
		public $path = '';

		/**
		 * @return string
		 */
		protected function option_key() {
			return 'reportedip_hive_test_block_enabled';
		}

		/**
		 * @return bool
		 */
		protected function option_default() {
			return false;
		}

		/**
		 * @return string[]
		 */
		protected function block_lines() {
			return array( 'Header set X-Test "1"' );
		}

		/**
		 * @return string
		 */
		public function get_target_path() {
			return $this->path;
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class HtaccessBlockWriterTest extends TestCase {

		/**
		 * Temp file the writer operates on.
		 *
		 * @var string
		 */
		private $path = '';

		/**
		 * Writer under test.
		 *
		 * @var \RIP_Test_Block_Writer
		 */
		private $writer;

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options'] = array();
			$this->path            = (string) tempnam( sys_get_temp_dir(), 'riphta' );
			$this->writer          = new \RIP_Test_Block_Writer();
			$this->writer->path    = $this->path;
		}

		protected function tear_down() {
			if ( '' !== $this->path && file_exists( $this->path ) ) {
				unlink( $this->path );
			}
			parent::tear_down();
		}

		public function test_sync_writes_the_block_when_the_option_is_on(): void {
			file_put_contents( $this->path, "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n" );
			$GLOBALS['wp_options']['reportedip_hive_test_block_enabled'] = true;

			$this->assertTrue( $this->writer->sync() );
			$this->assertTrue( $this->writer->is_block_present() );
			$this->assertStringContainsString( 'Header set X-Test "1"', (string) file_get_contents( $this->path ) );
		}

		public function test_sync_off_strips_the_pair_and_leaves_no_skeleton(): void {
			$GLOBALS['wp_options']['reportedip_hive_test_block_enabled'] = true;
			file_put_contents( $this->path, "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n" );
			$this->writer->sync();

			$GLOBALS['wp_options']['reportedip_hive_test_block_enabled'] = false;
			$this->assertTrue( $this->writer->sync() );

			$contents = (string) file_get_contents( $this->path );
			$this->assertStringNotContainsString( '# BEGIN ' . \RIP_Test_Block_Writer::MARKER, $contents );
			$this->assertStringNotContainsString( '# END ' . \RIP_Test_Block_Writer::MARKER, $contents );
			$this->assertStringContainsString( '# BEGIN WordPress', $contents, 'Surrounding directives must survive.' );
			$this->assertFalse( $this->writer->is_block_present() );
		}

		public function test_sync_off_does_not_create_the_file(): void {
			unlink( $this->path );
			$GLOBALS['wp_options']['reportedip_hive_test_block_enabled'] = false;

			$this->assertTrue( $this->writer->sync() );
			$this->assertFileDoesNotExist( $this->path );
		}

		public function test_remove_on_a_file_without_the_marker_changes_nothing(): void {
			$original = "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n";
			file_put_contents( $this->path, $original );

			$this->assertFalse( $this->writer->remove() );
			$this->assertSame( $original, (string) file_get_contents( $this->path ) );
		}

		public function test_is_block_present_is_false_for_a_missing_file(): void {
			unlink( $this->path );
			$this->assertFalse( $this->writer->is_block_present() );
		}
	}
}
