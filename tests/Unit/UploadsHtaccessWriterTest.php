<?php
/**
 * Unit tests for the uploads `.htaccess` block and its copy-paste snippets.
 *
 * The directive set is a security contract: it must deny by request, never by
 * interpreter configuration. `php_flag engine off` and `Options -ExecCGI`
 * return a 500 on stacks without mod_php or without `AllowOverride Options`,
 * which is exactly the situation in which the site owner would never notice.
 *
 * The lifecycle cases drive the real writer against a temp directory standing
 * in for the uploads basedir, so a sync that appends instead of replacing its
 * marker block shows up here.
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
	if ( ! function_exists( 'is_multisite' ) ) {
		function is_multisite() {
			return false;
		}
	}
	if ( ! function_exists( 'wp_parse_url' ) ) {
		function wp_parse_url( $url, $component = -1 ) {
			return -1 === $component ? parse_url( $url ) : parse_url( $url, $component );
		}
	}
	if ( ! function_exists( 'wp_get_upload_dir' ) ) {
		function wp_get_upload_dir() {
			return array(
				'basedir' => isset( $GLOBALS['rip_test_uploads_basedir'] )
					? $GLOBALS['rip_test_uploads_basedir']
					: '/var/www/html/wp-content/uploads',
				'baseurl' => 'https://example.test/wp-content/uploads',
				'error'   => false,
			);
		}
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
	require_once dirname( __DIR__, 2 ) . '/includes/class-uploads-htaccess-writer.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class UploadsHtaccessWriterTest extends TestCase {

		/**
		 * Temp directory standing in for the uploads basedir.
		 *
		 * @var string
		 */
		private $uploads_dir = '';

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']               = array();
			$this->uploads_dir                   = sys_get_temp_dir() . '/rip-uploads-' . uniqid();
			$GLOBALS['rip_test_uploads_basedir'] = $this->uploads_dir;
			mkdir( $this->uploads_dir );
		}

		protected function tear_down() {
			$file = $this->uploads_dir . '/.htaccess';
			if ( file_exists( $file ) ) {
				unlink( $file );
			}
			if ( '' !== $this->uploads_dir && is_dir( $this->uploads_dir ) ) {
				rmdir( $this->uploads_dir );
			}
			unset( $GLOBALS['rip_test_uploads_basedir'] );
			parent::tear_down();
		}

		/**
		 * The block as one string.
		 *
		 * @return string
		 */
		private function block(): string {
			return implode( "\n", \ReportedIP_Hive_Uploads_Htaccess_Writer::htaccess_block_lines() );
		}

		/**
		 * The `FilesMatch` expression as a runnable PCRE pattern, read back
		 * from the directive the writer emits.
		 *
		 * @return string
		 */
		private function files_match_pattern(): string {
			$line = \ReportedIP_Hive_Uploads_Htaccess_Writer::htaccess_block_lines()[0];

			$this->assertSame(
				1,
				preg_match( '/^<FilesMatch "(.+)">$/', $line, $matches ),
				'The block must open with a FilesMatch directive.'
			);

			return '#' . $matches[1] . '#';
		}

		public function test_block_denies_every_executable_extension(): void {
			$block = $this->block();

			$this->assertStringContainsString( '<FilesMatch', $block );
			foreach ( array( 'php', 'phtml', 'php[0-9]', 'phps', 'phar', 'pl', 'py', 'cgi', 'sh', 'shtml' ) as $ext ) {
				$this->assertStringContainsString( $ext, $block, "Extension {$ext} missing from the deny list." );
			}
		}

		public function test_block_carries_both_authorisation_dialects(): void {
			$block = $this->block();

			$this->assertStringContainsString( 'Require all denied', $block, 'Apache 2.4 form missing.' );
			$this->assertStringContainsString( 'Deny from all', $block, 'Apache 2.2 fallback missing.' );
			$this->assertStringContainsString( 'mod_authz_core.c', $block );
		}

		public function test_block_never_touches_the_interpreter_configuration(): void {
			$block = $this->block();

			$this->assertStringNotContainsString( 'php_flag', $block, 'php_flag 500s the site where mod_php is absent.' );
			$this->assertStringNotContainsString( 'Options', $block, 'Options needs AllowOverride Options and 500s without it.' );
		}

		public function test_the_denied_extension_match_survives_a_second_extension(): void {
			$pattern = $this->files_match_pattern();

			foreach ( array( 'shell.php', 'shell.PHP', 'shell.php.jpg', 'shell.php5.png', 'shell.phtml.gif', 'payload.phar.txt' ) as $name ) {
				$this->assertSame( 1, preg_match( $pattern, $name ), "{$name} must be refused." );
			}

			foreach ( array( 'holiday.jpg', 'summer.shirt.jpg', 'floor.plan.pdf', 'my.python.notes.txt' ) as $name ) {
				$this->assertSame( 0, preg_match( $pattern, $name ), "{$name} is media and must stay reachable." );
			}
		}

		public function test_repeated_sync_leaves_exactly_one_block(): void {
			$file = $this->uploads_dir . '/.htaccess';
			file_put_contents( $file, "# BEGIN WordPress\nRewriteEngine On\n# END WordPress\n" );
			$GLOBALS['wp_options']['reportedip_hive_block_uploads_php'] = true;

			$writer = \ReportedIP_Hive_Uploads_Htaccess_Writer::get_instance();
			$this->assertTrue( $writer->sync() );
			$this->assertTrue( $writer->sync() );

			$contents = (string) file_get_contents( $file );
			$this->assertSame(
				1,
				substr_count( $contents, '# BEGIN ' . \ReportedIP_Hive_Uploads_Htaccess_Writer::MARKER ),
				'A second sync must replace the block, never append a second one.'
			);
			$this->assertSame( 1, substr_count( $contents, 'Require all denied' ) );
			$this->assertStringContainsString( '# BEGIN WordPress', $contents, 'Surrounding directives must survive.' );
		}

		public function test_sync_off_strips_the_block_from_the_uploads_htaccess(): void {
			$file = $this->uploads_dir . '/.htaccess';
			$GLOBALS['wp_options']['reportedip_hive_block_uploads_php'] = true;

			$writer = \ReportedIP_Hive_Uploads_Htaccess_Writer::get_instance();
			$writer->sync();
			$this->assertTrue( $writer->is_block_present() );

			$GLOBALS['wp_options']['reportedip_hive_block_uploads_php'] = false;
			$this->assertTrue( $writer->sync() );

			$contents = (string) file_get_contents( $file );
			$this->assertStringNotContainsString( '# BEGIN ' . \ReportedIP_Hive_Uploads_Htaccess_Writer::MARKER, $contents );
			$this->assertStringNotContainsString( '# END ' . \ReportedIP_Hive_Uploads_Htaccess_Writer::MARKER, $contents );
			$this->assertFalse( $writer->is_block_present() );
		}

		public function test_apache_snippet_is_the_block_with_a_headline(): void {
			$snippet = \ReportedIP_Hive_Uploads_Htaccess_Writer::htaccess_snippet();

			$this->assertStringStartsWith( '# ReportedIP Hive', $snippet );
			$this->assertStringContainsString( 'Require all denied', $snippet );
		}

		public function test_nginx_snippet_denies_the_uploads_path(): void {
			$snippet = \ReportedIP_Hive_Uploads_Htaccess_Writer::nginx_snippet();

			$this->assertStringContainsString( 'deny all;', $snippet );
			$this->assertStringContainsString( '/wp-content/uploads', $snippet );
			$this->assertStringContainsString( 'location ~*', $snippet );
		}

		public function test_target_path_is_the_uploads_htaccess(): void {
			$this->assertSame(
				$this->uploads_dir . '/.htaccess',
				\ReportedIP_Hive_Uploads_Htaccess_Writer::get_instance()->get_target_path()
			);
		}

		public function test_option_constant_matches_the_registry_key(): void {
			$this->assertSame( 'reportedip_hive_block_uploads_php', \ReportedIP_Hive_Uploads_Htaccess_Writer::OPTION );
		}
	}
}
