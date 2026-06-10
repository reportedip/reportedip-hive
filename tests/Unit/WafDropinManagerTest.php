<?php
/**
 * Unit tests for the pre-WordPress WAF drop-in manager.
 *
 * Covers the parts that must be correct without a live server: server
 * detection, the nginx snippet, directive stripping (the orphan-prevention
 * primitive) and the generated guard baking the active rules in.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.2.0
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-rule-store.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-rule-sync.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-waf.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-waf-dropin-manager.php';

	/**
	 * @covers \ReportedIP_Hive_WAF_Dropin_Manager
	 */
	class WafDropinManagerTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options'] = array();
			$GLOBALS['wp_filters'] = array();
			if ( ! defined( 'WP_CONTENT_DIR' ) ) {
				define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/rip-wp-content' );
			}
			\ReportedIP_Hive_Rule_Store::flush_cache();
		}

		private function mgr(): \ReportedIP_Hive_WAF_Dropin_Manager {
			return \ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
		}

		private function call_private( string $method, array $args ) {
			$ref = new \ReflectionMethod( \ReportedIP_Hive_WAF_Dropin_Manager::class, $method );
			$ref->setAccessible( true );
			return $ref->invoke( $this->mgr(), ...$args );
		}

		public function test_detect_server_recognises_nginx(): void {
			$_SERVER['SERVER_SOFTWARE'] = 'nginx/1.25.3';
			$this->assertSame( 'nginx', $this->mgr()->detect_server() );
		}

		public function test_detect_server_recognises_apache(): void {
			$_SERVER['SERVER_SOFTWARE'] = 'Apache/2.4.57 (Unix)';
			$this->assertSame( 'apache', $this->mgr()->detect_server() );
		}

		public function test_detect_server_unknown_when_blank(): void {
			$_SERVER['SERVER_SOFTWARE'] = '';
			$this->assertSame( 'unknown', $this->mgr()->detect_server() );
		}

		public function test_nginx_snippet_includes_resolved_path(): void {
			$snippet = $this->mgr()->nginx_snippet();
			$this->assertStringContainsString( 'auto_prepend_file=', $snippet );
			$this->assertStringContainsString( 'reportedip-hive-waf.php', $snippet );
			$this->assertStringContainsString( 'fastcgi_param PHP_VALUE', $snippet );
		}

		public function test_strip_directive_removes_marker_and_keeps_surroundings(): void {
			$file = tempnam( sys_get_temp_dir(), 'rip-htaccess-' );
			$body = "# top user rule\n# BEGIN ReportedIP Hive WAF\nphp_value auto_prepend_file \"/x.php\"\n# END ReportedIP Hive WAF\n# bottom user rule\n";
			file_put_contents( $file, $body );

			$ok = $this->call_private( 'strip_directive', array( $file ) );
			$this->assertTrue( $ok );

			$after = (string) file_get_contents( $file );
			$this->assertStringNotContainsString( 'ReportedIP Hive WAF', $after );
			$this->assertStringContainsString( '# top user rule', $after );
			$this->assertStringContainsString( '# bottom user rule', $after );
			unlink( $file );
		}

		public function test_strip_directive_missing_file_is_success(): void {
			$this->assertTrue( $this->call_private( 'strip_directive', array( sys_get_temp_dir() . '/does-not-exist-rip.htaccess' ) ) );
		}

		public function test_generate_prepend_bakes_rules_and_guard_marker(): void {
			$php = $this->call_private( 'generate_prepend', array() );
			$this->assertStringContainsString( "define( 'REPORTEDIP_HIVE_WAF_DROPIN'", $php );
			$this->assertStringContainsString( 'reportedip_hive_dropin_ip_match', $php );
			$this->assertStringContainsString( 'waf_sqli_union', $php, 'The baseline rules must be baked into the guard.' );
		}

		public function test_generated_guard_is_valid_php(): void {
			$php  = $this->call_private( 'generate_prepend', array() );
			$file = tempnam( sys_get_temp_dir(), 'rip-guard-' ) . '.php';
			file_put_contents( $file, $php );
			$output    = array();
			$exit_code = 0;
			exec( escapeshellarg( PHP_BINARY ) . ' -l ' . escapeshellarg( $file ) . ' 2>&1', $output, $exit_code );
			unlink( $file );
			$this->assertSame( 0, $exit_code, 'Generated guard must be syntactically valid PHP: ' . implode( "\n", $output ) );
		}
	}
}
