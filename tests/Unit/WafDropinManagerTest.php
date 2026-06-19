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

		/**
		 * Execute the freshly generated guard in an isolated PHP subprocess with
		 * the given superglobals and report the verdict. The guard prints
		 * "Forbidden" and exits on a block; otherwise the bootstrap reaches the
		 * trailing "PASS". This exercises the real generated code end to end.
		 *
		 * @param array $server REQUEST_URI / REMOTE_ADDR / HTTP_USER_AGENT etc.
		 * @param array $cookie Request cookies.
		 * @param array $post   POST body.
		 * @return string "Forbidden" when blocked, "PASS" when allowed through.
		 */
		private function run_guard( array $server, array $cookie = array(), array $post = array() ): string {
			$server += array( 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_USER_AGENT' => 'Mozilla/5.0' );
			$guard   = tempnam( sys_get_temp_dir(), 'rip-guard-' ) . '.php';
			file_put_contents( $guard, $this->call_private( 'generate_prepend', array() ) );
			$boot = tempnam( sys_get_temp_dir(), 'rip-boot-' ) . '.php';
			file_put_contents(
				$boot,
				"<?php\n"
					. '$_SERVER = ' . var_export( $server, true ) . ";\n"
					. '$_COOKIE = ' . var_export( $cookie, true ) . ";\n"
					. '$_POST = ' . var_export( $post, true ) . ";\n"
					. 'include ' . var_export( $guard, true ) . ";\n"
					. "echo 'PASS';\n"
			);
			$output    = array();
			$exit_code = 0;
			exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $boot ), $output, $exit_code );
			unlink( $guard );
			unlink( $boot );
			return trim( implode( '', $output ) );
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
			$this->assertSame( 'unknown', $this->mgr()->detect_server( 'cli' ) );
		}

		public function test_detect_server_prefers_user_ini_under_nginx_fpm(): void {
			$_SERVER['SERVER_SOFTWARE'] = 'nginx/1.25.3';
			$this->assertSame(
				'fpm',
				$this->mgr()->detect_server( 'fpm-fcgi' ),
				'nginx fronting PHP-FPM must wire the directive via .user.ini, not the partial-coverage nginx snippet.'
			);
		}

		public function test_detect_server_litespeed_uses_user_ini(): void {
			$_SERVER['SERVER_SOFTWARE'] = 'LiteSpeed';
			$this->assertSame( 'fpm', $this->mgr()->detect_server( 'litespeed' ) );
		}

		public function test_detect_server_mod_php_uses_htaccess(): void {
			$_SERVER['SERVER_SOFTWARE'] = 'Apache/2.4.57 (Unix)';
			$this->assertSame( 'apache', $this->mgr()->detect_server( 'apache2handler' ) );
		}

		public function test_detect_server_bare_nginx_without_fpm_falls_back_to_snippet(): void {
			$_SERVER['SERVER_SOFTWARE'] = 'nginx/1.25.3';
			$this->assertSame(
				'nginx',
				$this->mgr()->detect_server( 'cli' ),
				'Only nginx without a FastCGI PHP SAPI keeps the manual-snippet path.'
			);
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

		/**
		 * The guard helper functions are declared conditionally
		 * (`if ( ! function_exists() )`), so they are NOT hoisted. The immediately
		 * invoked guard closure calls them, therefore every helper MUST appear
		 * before the closure or the guard fatals and fails open on the first
		 * request that reads the body or evaluates an exception.
		 */
		public function test_guard_defines_helpers_before_the_closure(): void {
			$php     = $this->call_private( 'generate_prepend', array() );
			$closure = strpos( $php, '(function () {' );
			$this->assertNotFalse( $closure );
			foreach ( array(
				'reportedip_hive_dropin_flatten',
				'reportedip_hive_dropin_ip_match',
				'reportedip_hive_dropin_loc_match',
				'reportedip_hive_dropin_excepted',
				'reportedip_hive_dropin_has_login_cookie',
			) as $fn ) {
				$def = strpos( $php, 'function ' . $fn . '(' );
				$this->assertNotFalse( $def, "Guard must define {$fn}()." );
				$this->assertLessThan( $closure, $def, "{$fn}() must be declared before the guard closure runs." );
			}
		}

		public function test_guard_wires_exception_allowlist(): void {
			$php = $this->call_private( 'generate_prepend', array() );
			$this->assertStringContainsString( '$exceptions =', $php );
			$this->assertStringContainsString( 'reportedip_hive_dropin_excepted( $exceptions, $rule', $php );
			$this->assertStringContainsString( 'reportedip_hive_dropin_loc_match( $ex, $req_path, $ip )', $php );
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

		public function test_neutralize_guard_keeps_file_as_inert_stub(): void {
			$path = $this->mgr()->prepend_path();
			$this->assertNotSame( '', $path );
			if ( ! is_dir( dirname( $path ) ) ) {
				mkdir( dirname( $path ), 0777, true );
			}
			file_put_contents( $path, "<?php\ndefine( 'REPORTEDIP_HIVE_WAF_DROPIN', 2 );\n" );

			$ok = $this->call_private( 'neutralize_guard', array() );
			$this->assertTrue( $ok );

			$this->assertFileExists( $path, 'The guard must be neutralised, never deleted — a dangling auto_prepend_file would 500 the whole site.' );
			$after = (string) file_get_contents( $path );
			$this->assertStringNotContainsString( "define( 'REPORTEDIP_HIVE_WAF_DROPIN'", $after, 'The inert stub must not define the active marker, so is_running() reports false.' );
			$this->assertStringContainsString( 'return;', $after );
			$this->assert_valid_php( $after );

			unlink( $path );
		}

		public function test_neutralize_guard_is_noop_when_file_absent(): void {
			$path = $this->mgr()->prepend_path();
			if ( '' !== $path && file_exists( $path ) ) {
				unlink( $path );
			}
			$this->assertTrue( $this->call_private( 'neutralize_guard', array() ) );
			$this->assertFileDoesNotExist( $path, 'Neutralisation must not create a guard file where none existed.' );
		}

		public function test_generate_prepend_bakes_engine_report_and_skip_flags(): void {
			$php = $this->call_private( 'generate_prepend', array() );
			$this->assertStringContainsString( 'if ( ! true || false ) { return; }', $php, 'Default state bakes engine=enabled, report-only=off.' );
			$this->assertStringContainsString( '$skip_body = true &&', $php, 'Authenticated body-skip defaults on.' );
			$this->assert_valid_php( $php );
		}

		public function test_guard_skips_body_for_authenticated_editor(): void {
			$verdict = $this->run_guard(
				array( 'REQUEST_URI' => '/wp-admin/admin-ajax.php' ),
				array( 'wordpress_logged_in_abc123' => 'editor|1700000000|token|hmac' ),
				array( 'content' => '<script>alert(1)</script>' )
			);
			$this->assertSame( 'PASS', $verdict, 'A signed-in editor posting rich content must not be blocked.' );
		}

		public function test_guard_blocks_body_attack_when_not_authenticated(): void {
			$verdict = $this->run_guard(
				array( 'REQUEST_URI' => '/wp-admin/admin-ajax.php' ),
				array(),
				array( 'content' => '<script>alert(1)</script>' )
			);
			$this->assertSame( 'Forbidden', $verdict, 'Without a login cookie the body must still be inspected.' );
		}

		public function test_guard_still_blocks_url_traversal_when_authenticated(): void {
			$verdict = $this->run_guard(
				array( 'REQUEST_URI' => '/wp-admin/admin-ajax.php?file=../../../../etc/passwd' ),
				array( 'wordpress_logged_in_abc123' => 'editor|1700000000|token|hmac' ),
				array()
			);
			$this->assertSame( 'Forbidden', $verdict, 'URL-based attacks must be caught even for authenticated sessions.' );
		}

		public function test_guard_inspects_body_when_skip_disabled(): void {
			$GLOBALS['wp_options'][ \ReportedIP_Hive_WAF::OPT_DROPIN_SKIP_AUTHENTICATED ] = false;
			$verdict = $this->run_guard(
				array( 'REQUEST_URI' => '/wp-admin/admin-ajax.php' ),
				array( 'wordpress_logged_in_abc123' => 'editor|1700000000|token|hmac' ),
				array( 'content' => '<script>alert(1)</script>' )
			);
			$this->assertSame( 'Forbidden', $verdict, 'With the skip option off the body is inspected even when authenticated.' );
		}

		public function test_guard_is_noop_when_engine_disabled(): void {
			$GLOBALS['wp_options'][ \ReportedIP_Hive_WAF::OPT_ENABLED ] = false;
			$verdict = $this->run_guard(
				array( 'REQUEST_URI' => '/' ),
				array(),
				array( 'q' => '<script>alert(1)</script>' )
			);
			$this->assertSame( 'PASS', $verdict, 'Disabling the WAF engine must also neutralise the pre-WordPress guard.' );
		}

		public function test_guard_is_noop_in_report_only_mode(): void {
			$GLOBALS['wp_options'][ \ReportedIP_Hive_WAF::OPT_REPORT_ONLY ] = true;
			$verdict = $this->run_guard(
				array( 'REQUEST_URI' => '/' ),
				array(),
				array( 'q' => '<script>alert(1)</script>' )
			);
			$this->assertSame( 'PASS', $verdict, 'Report-only mode must not block at the pre-WordPress layer.' );
		}
	}
}
