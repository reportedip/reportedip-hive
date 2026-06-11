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
 * @since      2.1.2
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
			$GLOBALS['wp_actions'] = array();
			if ( ! defined( 'WP_CONTENT_DIR' ) ) {
				define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/rip-wp-content' );
			}
			\ReportedIP_Hive_Rule_Store::flush_cache();
			$flag = new \ReflectionProperty( \ReportedIP_Hive_WAF_Dropin_Manager::class, 'resync_queued' );
			$flag->setValue( $this->mgr(), false );
		}

		private function mgr(): \ReportedIP_Hive_WAF_Dropin_Manager {
			return \ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
		}

		private function call_private( string $method, array $args ) {
			$ref = new \ReflectionMethod( \ReportedIP_Hive_WAF_Dropin_Manager::class, $method );
			return $ref->invoke( $this->mgr(), ...$args );
		}

		private function count_shutdown_syncs(): int {
			$count = 0;
			foreach ( (array) ( $GLOBALS['wp_actions']['shutdown'] ?? array() ) as $action ) {
				if ( is_array( $action['callback'] ) && 'run_queued_resync' === ( $action['callback'][1] ?? '' ) ) {
					++$count;
				}
			}
			return $count;
		}

		private function assert_valid_php( string $php ): void {
			$file = tempnam( sys_get_temp_dir(), 'rip-guard-' ) . '.php';
			file_put_contents( $file, $php );
			$output    = array();
			$exit_code = 0;
			exec( escapeshellarg( PHP_BINARY ) . ' -l ' . escapeshellarg( $file ) . ' 2>&1', $output, $exit_code );
			unlink( $file );
			$this->assertSame( 0, $exit_code, 'Generated guard must be syntactically valid PHP: ' . implode( "\n", $output ) );
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

		public function test_user_ini_block_uses_semicolon_markers_and_parses_as_ini(): void {
			$file = tempnam( sys_get_temp_dir(), 'rip-userini-' );
			$ok   = $this->call_private( 'write_user_ini_directive', array( $file, array( 'auto_prepend_file=/srv/wp-content/reportedip-hive-waf.php' ) ) );
			$this->assertTrue( $ok );

			$after = (string) file_get_contents( $file );
			$this->assertStringContainsString( '; BEGIN ReportedIP Hive WAF', $after );
			$this->assertStringContainsString( '; END ReportedIP Hive WAF', $after );
			$this->assertStringNotContainsString( '# BEGIN', $after, 'Hash comments are invalid INI since PHP 7 and must never reach .user.ini.' );

			$parsed = parse_ini_file( $file );
			$this->assertIsArray( $parsed, 'The written .user.ini must survive the PHP INI parser.' );
			$this->assertSame( '/srv/wp-content/reportedip-hive-waf.php', $parsed['auto_prepend_file'] );
			unlink( $file );
		}

		public function test_user_ini_writer_replaces_broken_legacy_hash_block(): void {
			$file   = tempnam( sys_get_temp_dir(), 'rip-userini-' );
			$legacy = "memory_limit=256M\n"
				. "# BEGIN ReportedIP Hive WAF\n"
				. "# The directives (lines) between \"BEGIN ReportedIP Hive WAF\" and \"END ReportedIP Hive WAF\" are\n"
				. "# dynamically generated, and should only be modified via WordPress filters.\n"
				. "# Any changes to the directives between these markers will be overwritten.\n"
				. "auto_prepend_file=/old/path.php\n"
				. "# END ReportedIP Hive WAF\n";
			file_put_contents( $file, $legacy );
			$this->assertFalse( @parse_ini_file( $file ), 'Precondition: the legacy insert_with_markers() block must break INI parsing.' );

			$ok = $this->call_private( 'write_user_ini_directive', array( $file, array( 'auto_prepend_file=/new/path.php' ) ) );
			$this->assertTrue( $ok );

			$after = (string) file_get_contents( $file );
			$this->assertStringNotContainsString( '# BEGIN', $after );
			$this->assertStringContainsString( 'memory_limit=256M', $after, 'Foreign directives outside the marker block must survive.' );

			$parsed = parse_ini_file( $file );
			$this->assertIsArray( $parsed );
			$this->assertSame( '/new/path.php', $parsed['auto_prepend_file'] );
			$this->assertSame( '256M', $parsed['memory_limit'] );
			unlink( $file );
		}

		public function test_user_ini_writer_is_idempotent(): void {
			$file = tempnam( sys_get_temp_dir(), 'rip-userini-' );
			$this->call_private( 'write_user_ini_directive', array( $file, array( 'auto_prepend_file=/x.php' ) ) );
			$this->call_private( 'write_user_ini_directive', array( $file, array( 'auto_prepend_file=/x.php' ) ) );

			$after = (string) file_get_contents( $file );
			$this->assertSame( 1, substr_count( $after, '; BEGIN ReportedIP Hive WAF' ), 'Re-running the writer must replace, not duplicate, the block.' );
			unlink( $file );
		}

		public function test_strip_directive_removes_semicolon_block(): void {
			$file = tempnam( sys_get_temp_dir(), 'rip-userini-' );
			file_put_contents( $file, "upload_max_filesize=64M\n; BEGIN ReportedIP Hive WAF\nauto_prepend_file=/x.php\n; END ReportedIP Hive WAF\n" );

			$this->assertTrue( $this->call_private( 'strip_directive', array( $file ) ) );

			$after = (string) file_get_contents( $file );
			$this->assertStringNotContainsString( 'ReportedIP Hive WAF', $after );
			$this->assertStringContainsString( 'upload_max_filesize=64M', $after );
			unlink( $file );
		}

		public function test_generate_prepend_bakes_rules_and_guard_marker(): void {
			$php = $this->call_private( 'generate_prepend', array() );
			$this->assertStringContainsString( "define( 'REPORTEDIP_HIVE_WAF_DROPIN'", $php );
			$this->assertStringContainsString( 'reportedip_hive_dropin_ip_match', $php );
			$this->assertStringContainsString( 'waf_sqli_union', $php, 'The baseline rules must be baked into the guard.' );
		}

		public function test_generated_guard_is_valid_php(): void {
			$this->assert_valid_php( $this->call_private( 'generate_prepend', array() ) );
		}

		public function test_queue_resync_noop_when_dropin_disabled(): void {
			$this->mgr()->queue_resync();
			$this->assertSame( 0, $this->count_shutdown_syncs(), 'A disabled drop-in must never queue a rebake.' );
		}

		public function test_ruleset_applied_waf_queues_single_shutdown_resync(): void {
			$GLOBALS['wp_options'][ \ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED ] = true;
			$this->mgr()->on_ruleset_applied( 'waf' );
			$this->mgr()->on_ruleset_applied( 'waf' );
			$this->mgr()->queue_resync();
			$this->assertSame( 1, $this->count_shutdown_syncs(), 'Multiple triggers in one request must queue exactly one rebake.' );
		}

		public function test_ruleset_applied_other_keys_do_not_queue(): void {
			$GLOBALS['wp_options'][ \ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED ] = true;
			foreach ( array( 'bot_signatures', 'disposable_domains', 'scan_paths' ) as $key ) {
				$this->mgr()->on_ruleset_applied( $key );
			}
			$this->assertSame( 0, $this->count_shutdown_syncs(), 'Only the waf ruleset is baked into the guard.' );
		}

		public function test_generate_prepend_bakes_trusted_header_when_configured(): void {
			$GLOBALS['wp_options']['reportedip_hive_trusted_ip_header'] = 'HTTP_X_FORWARDED_FOR';
			$php = $this->call_private( 'generate_prepend', array() );
			$this->assertStringContainsString( "'HTTP_X_FORWARDED_FOR'", $php );
			$this->assertStringContainsString( 'FILTER_VALIDATE_IP', $php );
			$this->assert_valid_php( $php );
		}

		public function test_generate_prepend_defaults_to_remote_addr_only(): void {
			$php = $this->call_private( 'generate_prepend', array() );
			$this->assertStringContainsString( "\$trusted = ''", $php, 'Without a configured trusted header the guard must not read any proxy header.' );
			$this->assertStringContainsString( 'REMOTE_ADDR', $php );
		}
	}
}
