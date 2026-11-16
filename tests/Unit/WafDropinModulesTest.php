<?php
/**
 * Tests for the generic guard extension points.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.1.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

require_once dirname( __DIR__, 2 ) . '/includes/class-request-path.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-rule-store.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-rule-sync.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-waf.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-waf-dropin-manager.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-proxy-trust.php';

/**
 * The module loader, the queue kind switch and the shared IP list format.
 *
 * @covers \ReportedIP_Hive_WAF_Dropin_Manager
 */
class WafDropinModulesTest extends TestCase {

	/**
	 * Reset the hook and option doubles.
	 */
	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['wp_options'] = array();
		$GLOBALS['wp_filters'] = array();
		$GLOBALS['wp_actions'] = array();
		if ( ! defined( 'WP_CONTENT_DIR' ) ) {
			define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/rip-wp-content' );
		}
		\ReportedIP_Hive_Rule_Store::flush_cache();
	}

	/**
	 * The manager under test.
	 *
	 * @return \ReportedIP_Hive_WAF_Dropin_Manager
	 */
	private function mgr(): \ReportedIP_Hive_WAF_Dropin_Manager {
		return \ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
	}

	/**
	 * Freshly generated guard source.
	 *
	 * @return string
	 */
	private function guard_source(): string {
		$ref = new \ReflectionMethod( \ReportedIP_Hive_WAF_Dropin_Manager::class, 'generate_prepend' );
		return (string) $ref->invoke( $this->mgr() );
	}

	/**
	 * Run PHP code after the generated guard in a subprocess.
	 *
	 * @param string $tail   PHP statements run after the guard include.
	 * @param array  $server Request superglobal.
	 * @return string Trimmed output.
	 */
	private function run_after_guard( string $tail, array $server = array() ): string {
		$server += array(
			'REMOTE_ADDR'     => '203.0.113.50',
			'REQUEST_URI'     => '/',
			'HTTP_USER_AGENT' => 'Mozilla/5.0',
			'REQUEST_METHOD'  => 'GET',
		);
		$guard  = tempnam( sys_get_temp_dir(), 'rip-mod-guard-' );
		file_put_contents( $guard, $this->guard_source() );
		$boot = tempnam( sys_get_temp_dir(), 'rip-mod-boot-' );
		file_put_contents(
			$boot,
			"<?php\n"
				. '$_SERVER = ' . var_export( $server, true ) . ";\n"
				. "\$_COOKIE = array();\n\$_POST = array();\n"
				. 'include ' . var_export( $guard, true ) . ";\n"
				. $tail . "\n"
		);
		$output = array();
		exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $boot ) . ' 2>&1', $output );
		unlink( $guard );
		unlink( $boot );
		return trim( implode( '', $output ) );
	}

	/**
	 * Ask the guard's own matcher about each IP in a list body.
	 *
	 * @param string   $body List file contents.
	 * @param string[] $ips  Addresses to look up.
	 * @return string One 1/0 per address.
	 */
	private function guard_lookup( string $body, array $ips ): string {
		$file = tempnam( sys_get_temp_dir(), 'rip-list-' );
		file_put_contents( $file, $body );
		$tail = '$ips = ' . var_export( $ips, true ) . ";\n"
			. "foreach ( \$ips as \$one ) { echo reportedip_hive_dropin_is_blocked( " . var_export( $file, true ) . ', $one ) ? 1 : 0; }';
		$out  = $this->run_after_guard( $tail );
		unlink( $file );
		return $out;
	}

	/**
	 * A list built for an add-on reads back through the guard's own matcher.
	 */
	public function test_build_ip_list_is_read_by_the_guard_matcher() {
		$body = \ReportedIP_Hive_WAF_Dropin_Manager::build_ip_list(
			array(
				'198.51.100.7' => time() + 3600,
				'203.0.113.9'  => 0,
				'10.0.0.0/8'   => 0,
			)
		);
		$this->assertSame( '110', $this->guard_lookup( $body, array( '198.51.100.7', '203.0.113.9', '192.0.2.1' ) ) );
		$this->assertStringNotContainsString( '10.0.0.0/8', $body, 'Ranges never enter the exact-IP list.' );
	}

	/**
	 * An expired row is written but no longer matches.
	 */
	public function test_build_ip_list_expired_row_does_not_match() {
		$body = \ReportedIP_Hive_WAF_Dropin_Manager::build_ip_list( array( '198.51.100.8' => time() - 5 ) );
		$this->assertStringContainsString( "198.51.100.8\t", $body );
		$this->assertSame( '0', $this->guard_lookup( $body, array( '198.51.100.8' ) ) );
	}

	/**
	 * The guard directory is the queue directory, created on demand.
	 */
	public function test_guard_dir_is_the_queue_directory() {
		$dir = $this->mgr()->guard_dir();
		$this->assertNotSame( '', $dir );
		$this->assertDirectoryExists( $dir );
		$this->assertSame( $dir, dirname( $this->mgr()->queue_path() ) );
	}
}
