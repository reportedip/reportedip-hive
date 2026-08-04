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

		public function test_detect_web_server_reports_nginx_behind_php_fpm(): void {
			$this->assertSame(
				'nginx',
				$this->mgr()->detect_web_server( 'fpm-fcgi', 'nginx/1.25.3' ),
				'The FastCGI SAPI must not be read as Apache — nginx never evaluates .htaccess.'
			);
		}

		public function test_detect_web_server_reports_apache_behind_php_fpm(): void {
			$this->assertSame(
				'apache',
				$this->mgr()->detect_web_server( 'fpm-fcgi', 'Apache/2.4.57 (Unix)' ),
				'Apache with proxy_fcgi still evaluates .htaccess.'
			);
		}

		public function test_detect_web_server_reports_mod_php_without_server_software(): void {
			$this->assertSame( 'apache', $this->mgr()->detect_web_server( 'apache2handler', '' ) );
		}

		public function test_detect_web_server_reports_litespeed(): void {
			$this->assertSame( 'litespeed', $this->mgr()->detect_web_server( 'litespeed', 'LiteSpeed' ) );
		}

		public function test_detect_web_server_unknown_when_unidentifiable(): void {
			$this->assertSame( 'unknown', $this->mgr()->detect_web_server( 'cli', '' ) );
		}

		public function test_supports_htaccess_only_for_apache_and_litespeed(): void {
			$this->assertTrue( $this->mgr()->supports_htaccess( 'fpm-fcgi', 'Apache/2.4.57 (Unix)' ) );
			$this->assertTrue( $this->mgr()->supports_htaccess( 'apache2handler', '' ) );
			$this->assertTrue( $this->mgr()->supports_htaccess( 'litespeed', 'LiteSpeed' ) );
			$this->assertFalse(
				$this->mgr()->supports_htaccess( 'fpm-fcgi', 'nginx/1.25.3' ),
				'nginx + PHP-FPM must never be advertised as .htaccess-managed.'
			);
			$this->assertFalse(
				$this->mgr()->supports_htaccess( 'cli', '' ),
				'An unidentified server must not be claimed as .htaccess-capable.'
			);
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
			$this->assertStringContainsString( 'waf_rest_batch_desync', $php, 'The REST batch-desync baseline rule must be baked into the guard.' );
			$this->assertStringContainsString( 'waf_rest_batch_nested', $php, 'The REST nested-batch baseline rule must be baked into the guard.' );
		}

		/**
		 * The pre-WordPress guard must decode the raw body before matching, just
		 * like the in-WordPress engine, so a percent-encoded payload in a JSON
		 * body cannot slip past the drop-in (added in 2.1.25). run_guard() cannot
		 * feed php://input, so the behaviour is locked by the engine test in
		 * WafTest; here we assert the decode step is present in the generated PHP.
		 */
		public function test_generated_guard_decodes_raw_body(): void {
			$php = $this->call_private( 'generate_prepend', array() );
			$this->assertStringContainsString( 'rawurldecode( $raw )', $php, 'The guard must append a decoded variant of the raw body.' );
			$this->assert_valid_php( $php );
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
			$this->assertStringContainsString( 'if ( false ) { return; }', $php, 'Default state bakes report-only=off.' );
			$this->assertStringContainsString( 'if ( ! true || empty( $rules ) ) { return; }', $php, 'Default state bakes engine=enabled.' );
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

		/**
		 * Remove both the live queue and a leftover rotation from earlier runs.
		 */
		private function reset_queue(): void {
			$queue = $this->mgr()->queue_path();
			foreach ( array( $queue, $queue . '.processing' ) as $file ) {
				if ( '' !== $queue && file_exists( $file ) ) {
					unlink( $file );
				}
			}
		}

		/**
		 * The whole point of the bridge: a block at the pre-WordPress layer must
		 * leave a record behind, because the guard itself can neither log nor
		 * escalate. Without this line the firewall counter stays at zero while
		 * attacks are being blocked, and a repeat offender is never laddered
		 * into an IP block.
		 */
		public function test_guard_appends_blocked_hit_to_queue(): void {
			$this->reset_queue();
			$queue = $this->mgr()->queue_path();
			$this->assertNotSame( '', $queue, 'The queue path must resolve when uploads are available.' );

			$verdict = $this->run_guard( array( 'REQUEST_URI' => '/?f=../../etc/passwd', 'REMOTE_ADDR' => '198.51.100.7' ) );
			$this->assertSame( 'Forbidden', $verdict );

			$this->assertFileExists( $queue, 'A blocked request must be queued for import.' );
			$lines = array_values( array_filter( explode( "\n", (string) file_get_contents( $queue ) ) ) );
			$this->assertCount( 1, $lines, 'Exactly one hit must be queued.' );

			$entry = json_decode( $lines[0], true );
			$this->assertIsArray( $entry );
			$this->assertSame( 'waf_traversal', $entry['rule'] );
			$this->assertSame( 'path_traversal', $entry['group'] );
			$this->assertSame( '198.51.100.7', $entry['ip'] );
			$this->assertStringContainsString( '../', (string) $entry['matched'], 'The matched fragment is what tells a real attack from a false positive.' );
			$this->assertGreaterThan( 0, (int) $entry['time'] );
			$this->assertLessThanOrEqual( time() + 1, (int) $entry['time'], 'The hit time must be a UTC unix timestamp, never a site-local clock reading.' );
		}

		/**
		 * A request the guard lets through must not grow the queue.
		 */
		public function test_guard_queues_nothing_when_request_passes(): void {
			$this->reset_queue();
			$this->assertSame( 'PASS', $this->run_guard( array( 'REQUEST_URI' => '/shop/' ) ) );
			$this->assertFileDoesNotExist( $this->mgr()->queue_path() );
		}

		/**
		 * While WordPress is unreachable nothing drains the queue, so the guard
		 * must stop appending once the file hits its ceiling — otherwise a
		 * sustained attack fills the disk.
		 */
		public function test_guard_stops_queueing_at_the_size_ceiling(): void {
			$this->reset_queue();
			$queue = $this->mgr()->queue_path();
			file_put_contents( $queue, str_repeat( 'x', \ReportedIP_Hive_WAF_Dropin_Manager::QUEUE_MAX_BYTES + 1 ) );
			$before = filesize( $queue );

			$this->assertSame( 'Forbidden', $this->run_guard( array( 'REQUEST_URI' => '/?f=../../etc/passwd' ) ), 'Blocking must continue even when the queue is full.' );
			clearstatcache( true, $queue );
			$this->assertSame( $before, filesize( $queue ), 'A full queue must not grow any further.' );

			$this->reset_queue();
		}

		/**
		 * Draining rotates the live file away first, so a hit arriving mid-drain
		 * lands in a fresh file instead of being truncated into oblivion.
		 */
		public function test_drain_rotates_and_consumes_the_queue(): void {
			$this->reset_queue();
			$queue = $this->mgr()->queue_path();
			file_put_contents( $queue, wp_json_encode( array( 'time' => time(), 'ip' => '198.51.100.8', 'rule' => 'waf_traversal', 'group' => 'path_traversal' ) ) . "\n" );

			$this->mgr()->drain_queue();

			$this->assertFileDoesNotExist( $queue, 'The live queue must be rotated away.' );
			$this->assertFileDoesNotExist( $queue . '.processing', 'A fully drained rotation must be deleted.' );
		}

		/**
		 * More hits than one pass imports must survive for the next pass rather
		 * than being dropped with the file.
		 */
		public function test_drain_keeps_overflow_for_the_next_pass(): void {
			$this->reset_queue();
			$queue = $this->mgr()->queue_path();
			$total = \ReportedIP_Hive_WAF_Dropin_Manager::QUEUE_BATCH + 25;
			$rows  = array();
			for ( $i = 0; $i < $total; $i++ ) {
				$rows[] = wp_json_encode( array( 'time' => time(), 'ip' => '198.51.100.9', 'rule' => 'waf_traversal', 'group' => 'path_traversal' ) );
			}
			file_put_contents( $queue, implode( "\n", $rows ) . "\n" );

			$this->mgr()->drain_queue();

			$this->assertFileExists( $queue . '.processing', 'The unprocessed tail must be kept.' );
			$rest = array_values( array_filter( explode( "\n", (string) file_get_contents( $queue . '.processing' ) ) ) );
			$this->assertCount( 25, $rest, 'Exactly the overflow beyond one batch must remain.' );

			$this->reset_queue();
		}

		/**
		 * A malformed line must never abort the import of the rest.
		 */
		public function test_drain_survives_corrupt_lines(): void {
			$this->reset_queue();
			$queue = $this->mgr()->queue_path();
			file_put_contents( $queue, "not json\n{\"ip\":\"198.51.100.10\",\"rule\":\"waf_xss_script\"}\n\n" );

			$this->mgr()->drain_queue();

			$this->assertFileDoesNotExist( $queue . '.processing' );
		}

		/**
		 * Seed the guard's blocklist file and remove it again after the test.
		 */
		private function seed_blocklist( string $body ): void {
			$this->call_private( 'ensure_queue_dir', array() );
			file_put_contents( $this->mgr()->blocklist_path(), $body );
		}

		private function clear_blocklist(): void {
			$path = $this->mgr()->blocklist_path();
			if ( '' !== $path && file_exists( $path ) ) {
				unlink( $path );
			}
		}

		/**
		 * An IP the plugin has blocked must be refused by the pre-WordPress
		 * layer too. Otherwise "extended protection" stops attack payloads but
		 * still hands every request of a known offender to WordPress — the gap
		 * this file exists to close.
		 */
		public function test_guard_refuses_a_blocked_ip(): void {
			$this->seed_blocklist( "198.51.100.20\t" . ( time() + 600 ) . "\n" );
			$verdict = $this->run_guard( array( 'REQUEST_URI' => '/shop/', 'REMOTE_ADDR' => '198.51.100.20' ) );
			$this->clear_blocklist();
			$this->assertSame( 'Forbidden', $verdict );
		}

		public function test_guard_refuses_a_permanently_blocked_ip(): void {
			$this->seed_blocklist( "198.51.100.21\t0\n" );
			$verdict = $this->run_guard( array( 'REQUEST_URI' => '/', 'REMOTE_ADDR' => '198.51.100.21' ) );
			$this->clear_blocklist();
			$this->assertSame( 'Forbidden', $verdict, 'A block without an expiry is permanent.' );
		}

		/**
		 * An expired block must stop refusing, or the guard would keep an
		 * offender out long after WordPress released them.
		 */
		public function test_guard_lets_an_expired_block_through(): void {
			$this->seed_blocklist( "198.51.100.22\t" . ( time() - 60 ) . "\n" );
			$verdict = $this->run_guard( array( 'REQUEST_URI' => '/', 'REMOTE_ADDR' => '198.51.100.22' ) );
			$this->clear_blocklist();
			$this->assertSame( 'PASS', $verdict );
		}

		/**
		 * A near-miss must not match: the lookup is anchored per line, so a
		 * longer IP that merely starts with a blocked one stays free.
		 */
		public function test_guard_does_not_refuse_a_prefix_lookalike(): void {
			$this->seed_blocklist( "198.51.100.2\t" . ( time() + 600 ) . "\n" );
			$verdict = $this->run_guard( array( 'REQUEST_URI' => '/', 'REMOTE_ADDR' => '198.51.100.23' ) );
			$this->clear_blocklist();
			$this->assertSame( 'PASS', $verdict );
		}

		/**
		 * The whitelist is the one thing that outranks a block, exactly as in
		 * WordPress — otherwise an admin could lock themselves out at a layer
		 * where no plugin can help them.
		 */
		public function test_guard_whitelist_outranks_the_blocklist(): void {
			$php = $this->call_private( 'generate_prepend', array() );

			$whitelisted = strpos( $php, 'foreach ( $whitelist as $entry )' );
			$block_range = strpos( $php, 'foreach ( $block_cidr as $entry )' );
			$block_exact = strpos( $php, 'reportedip_hive_dropin_is_blocked( $blocklist' );

			$this->assertNotFalse( $whitelisted );
			$this->assertNotFalse( $block_range );
			$this->assertNotFalse( $block_exact );
			$this->assertLessThan( $block_range, $whitelisted, 'A whitelisted IP must return before any block is evaluated.' );
			$this->assertLessThan( $block_exact, $whitelisted );
		}

		/**
		 * IP blocks come from the auto-block ladder, not from the WAF engine, so
		 * switching rule inspection off must not switch blocking off with it.
		 */
		public function test_guard_enforces_blocks_with_the_waf_engine_disabled(): void {
			$GLOBALS['wp_options'][ \ReportedIP_Hive_WAF::OPT_ENABLED ] = false;
			$this->seed_blocklist( "198.51.100.25\t" . ( time() + 600 ) . "\n" );
			$verdict = $this->run_guard( array( 'REQUEST_URI' => '/', 'REMOTE_ADDR' => '198.51.100.25' ) );
			$this->clear_blocklist();
			$this->assertSame( 'Forbidden', $verdict );
		}

		/**
		 * Report-only means "observe, never interfere" — for blocks as well.
		 */
		public function test_guard_ignores_blocks_in_report_only_mode(): void {
			$GLOBALS['wp_options']['reportedip_hive_report_only_mode'] = true;
			$this->seed_blocklist( "198.51.100.26\t" . ( time() + 600 ) . "\n" );
			$verdict = $this->run_guard( array( 'REQUEST_URI' => '/', 'REMOTE_ADDR' => '198.51.100.26' ) );
			$this->clear_blocklist();
			$this->assertSame( 'PASS', $verdict, 'The global report-only switch must reach the pre-WordPress layer too.' );
		}

		/**
		 * A fresh block must reach the guard within the same request instead of
		 * waiting for the hourly self-heal.
		 */
		public function test_new_block_is_appended_for_the_guard(): void {
			$GLOBALS['wp_options'][ \ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED ] = true;
			$this->clear_blocklist();

			$this->mgr()->on_ip_blocked( '198.51.100.27', 'brute force', gmdate( 'Y-m-d H:i:s', time() + 1800 ) );

			$body = (string) file_get_contents( $this->mgr()->blocklist_path() );
			$this->clear_blocklist();
			$this->assertMatchesRegularExpression( '/^198\.51\.100\.27\t\d{10}$/m', $body );
		}

		/**
		 * The two WAF layers must evaluate the same rule set. A rule active in
		 * WordPress but missing from the guard would be a hole an attacker can
		 * walk through whenever the guard answers first.
		 */
		public function test_guard_carries_every_active_engine_rule(): void {
			$php   = $this->call_private( 'generate_prepend', array() );
			$rules = \ReportedIP_Hive_WAF::get_instance()->get_active_rules();

			$this->assertNotEmpty( $rules, 'The engine must expose rules for this comparison to mean anything.' );
			foreach ( $rules as $rule ) {
				$this->assertStringContainsString( "'" . $rule['id'] . "'", $php, "Rule {$rule['id']} runs in WordPress but is missing from the guard." );
				$this->assertStringContainsString( var_export( $rule['pattern'], true ), $php, "Rule {$rule['id']} is baked with a different pattern than the engine uses." ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Reproducing the literal the generator bakes, so the comparison sees the same escaping.
			}
		}

		/**
		 * Fold entries through the private grouper and return the groups.
		 *
		 * @param array<int,array<string,mixed>> $entries Queue entries.
		 * @return array<string,array<string,mixed>>
		 */
		private function group( array $entries ): array {
			$groups = array();
			$ref    = new \ReflectionMethod( \ReportedIP_Hive_WAF_Dropin_Manager::class, 'group_entry' );
			foreach ( $entries as $entry ) {
				$ref->invokeArgs( $this->mgr(), array( &$groups, $entry ) );
			}
			return $groups;
		}

		/**
		 * A scanner sweeping twenty spellings of one endpoint is a single
		 * finding. Kept apart, those rows buried every other event on the
		 * firewall page and let one ten-second burst own the 30-day statistic.
		 */
		public function test_repeat_offences_against_one_rule_collapse_into_a_group(): void {
			$entries = array();
			foreach ( array( '/wp-json/batch/v1', '/wp-json//batch/v1', '/?rest_route=/batch/v1' ) as $i => $uri ) {
				$entries[] = array( 'time' => 1785481200 + $i, 'ip' => '198.51.100.30', 'rule' => 'waf_rest_batch_desync', 'uri' => $uri );
			}

			$groups = $this->group( $entries );

			$this->assertCount( 1, $groups );
			$group = reset( $groups );
			$this->assertSame( 3, $group['count'] );
			$this->assertCount( 3, $group['targets'], 'Each distinct target is kept for diagnosis.' );
			$this->assertSame( 1785481200, $group['entry']['time'], 'The group inherits the time the sweep started.' );
		}

		public function test_different_ips_or_rules_stay_separate(): void {
			$groups = $this->group(
				array(
					array( 'time' => 1785481200, 'ip' => '198.51.100.31', 'rule' => 'waf_xss_script', 'uri' => '/a' ),
					array( 'time' => 1785481201, 'ip' => '198.51.100.31', 'rule' => 'waf_traversal', 'uri' => '/b' ),
					array( 'time' => 1785481202, 'ip' => '198.51.100.32', 'rule' => 'waf_xss_script', 'uri' => '/c' ),
				)
			);

			$this->assertCount( 3, $groups, 'Grouping must never merge separate attackers or separate rules.' );
		}

		/**
		 * The sample is bounded so a sweep with thousands of variants cannot
		 * grow a single log row without limit.
		 */
		public function test_target_sample_is_bounded(): void {
			$entries = array();
			for ( $i = 0; $i < 40; $i++ ) {
				$entries[] = array( 'time' => 1785481200, 'ip' => '198.51.100.33', 'rule' => 'waf_traversal', 'uri' => '/probe-' . $i );
			}

			$groups = $this->group( $entries );
			$group  = reset( $groups );

			$this->assertSame( 40, $group['count'], 'Every offence still counts toward the ladder.' );
			$this->assertCount( \ReportedIP_Hive_WAF::AGGREGATE_URI_SAMPLE, $group['targets'] );
		}

		public function test_duplicate_targets_are_not_sampled_twice(): void {
			$groups = $this->group(
				array(
					array( 'time' => 1785481200, 'ip' => '198.51.100.34', 'rule' => 'waf_traversal', 'uri' => '/same' ),
					array( 'time' => 1785481201, 'ip' => '198.51.100.34', 'rule' => 'waf_traversal', 'uri' => '/same' ),
				)
			);
			$group  = reset( $groups );

			$this->assertSame( 2, $group['count'] );
			$this->assertSame( array( '/same' ), $group['targets'] );
		}

		/**
		 * The rotation is atomic, the import is not: without a lock the queue
		 * cron and an admin request can import the same rotated file twice,
		 * doubling both the log and the offence counter behind the ladder.
		 */
		public function test_a_second_drain_backs_off_while_one_is_running(): void {
			$this->reset_queue();
			$queue = $this->mgr()->queue_path();
			file_put_contents( $queue, wp_json_encode( array( 'time' => time(), 'ip' => '198.51.100.35', 'rule' => 'waf_traversal' ) ) . "\n" );

			set_site_transient( \ReportedIP_Hive_WAF_Dropin_Manager::DRAIN_LOCK_TRANSIENT, 1, 300 );
			$this->mgr()->drain_queue();

			$this->assertFileExists( $queue, 'A locked drain must leave the queue untouched for the running one.' );

			delete_site_transient( \ReportedIP_Hive_WAF_Dropin_Manager::DRAIN_LOCK_TRANSIENT );
			$this->mgr()->drain_queue();
			$this->assertFileDoesNotExist( $queue, 'Once the lock clears the queue is drained normally.' );

			$this->reset_queue();
		}

		public function test_drain_releases_its_lock(): void {
			$this->reset_queue();
			$this->mgr()->drain_queue();

			$this->assertFalse( (bool) get_site_transient( \ReportedIP_Hive_WAF_Dropin_Manager::DRAIN_LOCK_TRANSIENT ), 'A finished drain must not leave the lock behind.' );
		}

		/**
		 * The queue holds client IPs, so it must never be fetchable over HTTP.
		 */
		public function test_queue_directory_carries_access_guards(): void {
			$this->call_private( 'ensure_queue_dir', array() );
			$dir = dirname( $this->mgr()->queue_path() );
			$this->assertFileExists( $dir . '/index.php' );
			$this->assertFileExists( $dir . '/.htaccess' );
			$this->assertStringContainsString( 'denied', (string) file_get_contents( $dir . '/.htaccess' ) );
			$this->assertMatchesRegularExpression( '/waf-hits-[0-9a-f]{16}\.ndjson$/', $this->mgr()->queue_path(), 'The file name must carry a per-site token so it cannot be guessed.' );
		}
	}
}
