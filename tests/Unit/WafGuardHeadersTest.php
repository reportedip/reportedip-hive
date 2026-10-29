<?php
/**
 * The pre-WordPress guard sends the planned security headers, so a page a
 * cache drop-in delivers before WordPress loads carries them too.
 *
 * Runs the generated guard in an isolated subprocess, the way
 * WafGuardHelperParityTest does, and asks its header helper which lines it
 * would send for a given request.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.5
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReflectionMethod;
	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-security-headers.php';

	class WafGuardHeadersTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options'] = array();
		}

		/**
		 * Generate the guard and return the header lines it sends for each request.
		 *
		 * @param array<int,array<string,string>> $requests $_SERVER shapes.
		 * @return array<int,string[]>
		 */
		private function lines_for( array $requests ): array {
			$manager = \ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
			$method  = new ReflectionMethod( \ReportedIP_Hive_WAF_Dropin_Manager::class, 'generate_prepend' );
			$source  = (string) $method->invoke( $manager );

			$guard = tempnam( sys_get_temp_dir(), 'rip-hdr-guard-' );
			file_put_contents( $guard, $source );
			$boot = tempnam( sys_get_temp_dir(), 'rip-hdr-boot-' );
			file_put_contents(
				$boot,
				"<?php\n"
					. '$_SERVER = ' . var_export( array( 'REMOTE_ADDR' => '198.51.100.200', 'REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET' ), true ) . ";\n"
					. "\$_COOKIE = array();\n\$_POST = array();\n"
					. 'include ' . var_export( $guard, true ) . ";\n"
					. '$baked = ' . var_export( \ReportedIP_Hive_Security_Headers::planned_headers(), true ) . ";\n"
					. '$requests = ' . var_export( $requests, true ) . ";\n"
					. "\$out = array();\n"
					. "foreach ( \$requests as \$server ) { \$out[] = reportedip_hive_dropin_header_lines( \$baked, \$server ); }\n"
					. "echo json_encode( array( 'lines' => \$out ) );\n"
			);

			$output    = array();
			$exit_code = 0;
			exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $boot ), $output, $exit_code );
			unlink( $guard );
			unlink( $boot );

			$this->assertSame( 0, $exit_code, 'Guard probe must run cleanly: ' . implode( "\n", $output ) );
			$decoded = json_decode( trim( implode( '', $output ) ), true );
			$this->assertIsArray( $decoded, 'Guard probe must return JSON, got: ' . implode( '', $output ) );

			return $decoded['lines'];
		}

		public function test_the_planned_headers_are_baked_into_the_guard(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			$method = new ReflectionMethod( \ReportedIP_Hive_WAF_Dropin_Manager::class, 'generate_prepend' );
			$source = (string) $method->invoke( \ReportedIP_Hive_WAF_Dropin_Manager::get_instance() );

			$this->assertStringContainsString( "'X-Content-Type-Options' => 'nosniff'", $source );
			$this->assertStringContainsString( 'reportedip_hive_dropin_header_lines(', $source );
			$this->assertStringNotContainsString( '__RIP_HEADERS__', $source );
		}

		public function test_front_end_requests_get_the_headers_admin_and_login_do_not(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			add_filter(
				'reportedip_hive_planned_headers',
				static function ( $headers ) {
					$headers['Strict-Transport-Security'] = 'max-age=300';
					return $headers;
				}
			);
			try {
				$lines = $this->lines_for(
					array(
						array( 'SCRIPT_FILENAME' => '/var/www/html/index.php', 'HTTPS' => 'on' ),
						array( 'SCRIPT_FILENAME' => '/var/www/html/index.php' ),
						array( 'SCRIPT_FILENAME' => '/var/www/html/wp-admin/index.php', 'HTTPS' => 'on' ),
						array( 'SCRIPT_FILENAME' => '/var/www/html/wp-login.php', 'HTTPS' => 'on' ),
						array( 'SCRIPT_FILENAME' => 'C:\\www\\index.php', 'SERVER_PORT' => '443' ),
					)
				);
			} finally {
				unset( $GLOBALS['wp_filters']['reportedip_hive_planned_headers'] );
			}

			$this->assertContains( 'X-Content-Type-Options: nosniff', $lines[0] );
			$this->assertContains( 'Strict-Transport-Security: max-age=300', $lines[0] );
			$this->assertContains( 'X-Content-Type-Options: nosniff', $lines[1] );
			$this->assertNotContains( 'Strict-Transport-Security: max-age=300', $lines[1], 'HSTS over HTTPS only' );
			$this->assertSame( array(), $lines[2], 'wp-admin gets no front-end headers' );
			$this->assertSame( array(), $lines[3], 'wp-login.php is not the front controller' );
			$this->assertContains( 'Strict-Transport-Security: max-age=300', $lines[4], 'Windows paths and port 443 count' );
		}

		public function test_nothing_is_sent_while_the_master_switch_is_off(): void {
			$lines = $this->lines_for( array( array( 'SCRIPT_FILENAME' => '/var/www/html/index.php' ) ) );
			$this->assertSame( array( array() ), $lines );
		}
	}
}
