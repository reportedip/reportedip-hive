<?php
/**
 * Unit tests for the uploads `.htaccess` block and its copy-paste snippets.
 *
 * The directive set is a security contract: it must deny by request, never by
 * interpreter configuration. `php_flag engine off` and `Options -ExecCGI`
 * return a 500 on stacks without mod_php or without `AllowOverride Options`,
 * which is exactly the situation in which the site owner would never notice.
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
				'basedir' => '/var/www/html/wp-content/uploads',
				'baseurl' => 'https://example.test/wp-content/uploads',
				'error'   => false,
			);
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
		 * The block as one string.
		 *
		 * @return string
		 */
		private function block(): string {
			return implode( "\n", \ReportedIP_Hive_Uploads_Htaccess_Writer::htaccess_block_lines() );
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

		public function test_block_lines_are_idempotent(): void {
			$this->assertSame(
				\ReportedIP_Hive_Uploads_Htaccess_Writer::htaccess_block_lines(),
				\ReportedIP_Hive_Uploads_Htaccess_Writer::htaccess_block_lines()
			);
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
				'/var/www/html/wp-content/uploads/.htaccess',
				\ReportedIP_Hive_Uploads_Htaccess_Writer::get_instance()->get_target_path()
			);
		}

		public function test_option_constant_matches_the_registry_key(): void {
			$this->assertSame( 'reportedip_hive_block_uploads_php', \ReportedIP_Hive_Uploads_Htaccess_Writer::OPTION );
		}
	}
}
