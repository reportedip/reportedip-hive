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
	 * Throwaway files removed in tearDown().
	 *
	 * @var string[]
	 */
	private $temp_files = array();

	/**
	 * Reset the hook and option doubles.
	 */
	protected function setUp(): void {
		parent::setUp();
		$this->reset_globals();
		if ( ! defined( 'WP_CONTENT_DIR' ) ) {
			define( 'WP_CONTENT_DIR', sys_get_temp_dir() . '/rip-wp-content' );
		}
		\ReportedIP_Hive_Rule_Store::flush_cache();
		$this->clear_guard_files();
	}

	/**
	 * Remove every file a test left behind and reset the doubles.
	 */
	protected function tearDown(): void {
		foreach ( $this->temp_files as $file ) {
			if ( file_exists( $file ) ) {
				unlink( $file );
			}
		}
		$this->temp_files = array();
		$this->clear_guard_files();
		$this->reset_globals();
		parent::tearDown();
	}

	/**
	 * Empty the option and hook doubles.
	 *
	 * @return void
	 */
	private function reset_globals(): void {
		$GLOBALS['wp_options'] = array();
		$GLOBALS['wp_filters'] = array();
		$GLOBALS['wp_actions'] = array();
	}

	/**
	 * Remove the live queue, a leftover rotation, the lock and the blocklist.
	 *
	 * @return void
	 */
	private function clear_guard_files(): void {
		$queue = $this->mgr()->queue_path();
		$files = array( $queue, $queue . '.processing', $queue . '.lock', $this->mgr()->blocklist_path() );
		foreach ( $files as $file ) {
			if ( '' !== $queue && file_exists( $file ) ) {
				unlink( $file );
			}
		}
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
	 * A temp file that tearDown() removes.
	 *
	 * @param string $prefix Name prefix.
	 * @param string $body   Contents.
	 * @return string Path.
	 */
	private function temp_file( string $prefix, string $body ): string {
		$file = tempnam( sys_get_temp_dir(), $prefix );
		file_put_contents( $file, $body );
		$this->temp_files[] = $file;
		return $file;
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
	 * @param string      $tail   PHP statements run after the guard include.
	 * @param array       $server Request superglobal.
	 * @param string|null $source Guard source, null for a fresh one.
	 * @return string Trimmed output.
	 */
	private function run_after_guard( string $tail, array $server = array(), ?string $source = null ): string {
		$server += array(
			'REMOTE_ADDR'     => '203.0.113.50',
			'REQUEST_URI'     => '/',
			'HTTP_USER_AGENT' => 'Mozilla/5.0',
			'REQUEST_METHOD'  => 'GET',
		);
		$guard  = $this->temp_file( 'rip-mod-guard-', null === $source ? $this->guard_source() : $source );
		$boot   = $this->temp_file(
			'rip-mod-boot-',
			"<?php\n"
				. '$_SERVER = ' . var_export( $server, true ) . ";\n"
				. "\$_COOKIE = array();\n\$_POST = array();\n"
				. 'include ' . var_export( $guard, true ) . ";\n"
				. $tail . "\n"
		);
		$output = array();
		exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $boot ) . ' 2>&1', $output );
		return trim( implode( '', $output ) );
	}

	/**
	 * Run the guard and print PASS when it lets the request through.
	 *
	 * @param array       $server Request superglobal.
	 * @param string|null $source Guard source, null for a fresh one.
	 * @return string Trimmed output.
	 */
	private function run_guard( array $server = array(), ?string $source = null ): string {
		return $this->run_after_guard( "echo 'PASS';", $server, $source );
	}

	/**
	 * Ask the guard's own matcher about each IP in a list body.
	 *
	 * @param string   $body List file contents.
	 * @param string[] $ips  Addresses to look up.
	 * @return string One 1/0 per address.
	 */
	private function guard_lookup( string $body, array $ips ): string {
		$file = $this->temp_file( 'rip-list-', $body );
		$tail = '$ips = ' . var_export( $ips, true ) . ";\n"
			. 'foreach ( $ips as $one ) { echo reportedip_hive_dropin_is_blocked( ' . var_export( $file, true ) . ', $one ) ? 1 : 0; }';
		return $this->run_after_guard( $tail );
	}

	/**
	 * Register guard modules through the documented filter.
	 *
	 * @param array $modules Module rows.
	 * @return void
	 */
	private function register_modules( array $modules ): void {
		add_filter(
			'reportedip_hive_guard_modules',
			static function () use ( $modules ) {
				return $modules;
			}
		);
	}

	/**
	 * Register one module whose body is the given code.
	 *
	 * @param string $id   Module id.
	 * @param string $body Function body, `$ip`, `$config`, `$env` in scope.
	 * @param array  $config Module config.
	 * @return string Module file path.
	 */
	private function register_module( string $id, string $body, array $config = array() ): string {
		$file = $this->module_file( 'function reportedip_hive_guard_module_' . $id . '( $ip, $config, $env ) { ' . $body . ' }' );
		$this->register_modules(
			array(
				array(
					'id'     => $id,
					'file'   => $file,
					'config' => $config,
				),
			)
		);
		return $file;
	}

	/**
	 * Write a throwaway module file.
	 *
	 * @param string $code PHP code after the open tag.
	 * @return string Path.
	 */
	private function module_file( string $code ): string {
		return $this->temp_file( 'rip-module-', "<?php\n" . $code );
	}

	/**
	 * Seed the guard's blocklist.
	 *
	 * @param string $ip Address to block permanently.
	 * @return void
	 */
	private function seed_blocklist( string $ip ): void {
		$this->mgr()->guard_dir();
		file_put_contents( $this->mgr()->blocklist_path(), \ReportedIP_Hive_WAF_Dropin_Manager::build_ip_list( array( $ip => 0 ) ) );
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

	/**
	 * A registered module is baked with its id, file and config.
	 */
	public function test_modules_are_baked_into_the_guard() {
		$file = $this->register_module( 'demo', '', array( 'x' => 1 ) );
		$src  = $this->guard_source();
		$this->assertStringContainsString( "'id' => 'demo'", $src );
		$this->assertStringContainsString( var_export( $file, true ), $src );
		$this->assertStringContainsString( 'reportedip_hive_guard_module_', $src );
		$this->assertStringNotContainsString( '__RIP_MODULES__', $src );
	}

	/**
	 * Malformed rows never reach the guard.
	 */
	public function test_malformed_modules_are_dropped() {
		$this->register_modules(
			array(
				array(
					'id'   => 'bad id!',
					'file' => '/nope.php',
				),
				'x',
				array( 'file' => '/a.php' ),
				array(
					'id'   => 'ok',
					'file' => array( '/a.php' ),
				),
			)
		);
		$this->assertSame( array(), $this->mgr()->modules_snapshot() );
	}

	/**
	 * The first row of an id wins, a second row with the same id is dropped.
	 */
	public function test_duplicate_module_ids_keep_the_first_row() {
		$this->register_modules(
			array(
				array(
					'id'   => 'dup',
					'file' => '/first.php',
				),
				array(
					'id'   => 'other',
					'file' => '/other.php',
				),
				array(
					'id'   => 'dup',
					'file' => '/second.php',
				),
			)
		);
		$snapshot = $this->mgr()->modules_snapshot();
		$this->assertSame( array( 'dup', 'other' ), array_column( $snapshot, 'id' ) );
		$this->assertSame( '/first.php', $snapshot[0]['file'] );
	}

	/**
	 * Without modules the guard bakes an empty list.
	 */
	public function test_no_modules_bake_an_empty_list() {
		$this->assertSame( array(), $this->mgr()->modules_snapshot() );
		$this->assertStringContainsString( '$modules = array (' . "\n" . ')', $this->guard_source() );
	}

	/**
	 * The generated guard carries format version 11.
	 */
	public function test_generated_guard_carries_version_eleven() {
		$this->assertStringContainsString( "define( 'REPORTEDIP_HIVE_WAF_DROPIN', 11 );", $this->guard_source() );
	}

	/**
	 * The documented rebake action queues a resync.
	 */
	public function test_rebake_action_is_wired() {
		$ctor = new \ReflectionMethod( \ReportedIP_Hive_WAF_Dropin_Manager::class, '__construct' );
		$ctor->invoke( $this->mgr() );
		$callbacks = array_column( (array) ( $GLOBALS['wp_actions']['reportedip_hive_guard_rebake'] ?? array() ), 'callback' );
		$this->assertContains( array( $this->mgr(), 'queue_resync' ), $callbacks );
	}

	/**
	 * The guard calls the module with the client IP, its config and the env.
	 */
	public function test_guard_runs_the_module() {
		$this->register_module(
			'probe',
			'echo json_encode( array( $ip, $config, $env["report_only"], isset( $env["queue"], $env["queue_max"], $env["https"] ) ) );',
			array( 'limit' => 5 )
		);
		$this->assertSame( '["203.0.113.50",{"limit":5},false,true]PASS', $this->run_guard() );
	}

	/**
	 * The env carries the same HTTPS verdict as the guard's header logic.
	 */
	public function test_env_https_follows_the_shared_test() {
		$this->register_module( 'tls', 'echo $env["https"] ? "S" : "P";' );
		$this->assertSame( 'SPASS', $this->run_guard( array( 'HTTPS' => 'on' ) ) );
		$this->assertSame( 'SPASS', $this->run_guard( array( 'HTTPS' => 'ON' ) ) );
		$this->assertSame( 'SPASS', $this->run_guard( array( 'HTTPS' => '1' ) ) );
		$this->assertSame( 'SPASS', $this->run_guard( array( 'SERVER_PORT' => '443' ) ) );
		$this->assertSame( 'PPASS', $this->run_guard( array( 'HTTPS' => 'off' ) ) );
		$this->assertSame( 'PPASS', $this->run_guard() );
	}

	/**
	 * Report-only still runs modules, lets a blocklisted IP and a rule match
	 * through, and the module decides from $env.
	 */
	public function test_guard_runs_modules_in_report_only_mode() {
		$GLOBALS['wp_options']['reportedip_hive_report_only_mode'] = true;
		$this->register_module( 'ro', 'echo $env["report_only"] ? "RO" : "LIVE";' );
		$this->seed_blocklist( '198.51.100.63' );
		$this->assertSame( 'ROPASS', $this->run_guard() );
		$this->assertSame(
			'ROPASS',
			$this->run_guard(
				array(
					'REMOTE_ADDR' => '198.51.100.63',
					'REQUEST_URI' => '/?f=../../etc/passwd',
				)
			),
			'Report-only lets a blocklisted IP and a rule match through, the module still runs.'
		);
	}

	/**
	 * A throwing or missing module never takes the request down.
	 */
	public function test_broken_modules_fail_open() {
		$boom = $this->module_file( 'function reportedip_hive_guard_module_boom( $ip, $config, $env ) { throw new RuntimeException( "x" ); }' );
		$ok   = $this->module_file( 'function reportedip_hive_guard_module_after( $ip, $config, $env ) { echo "OK"; }' );
		$this->register_modules(
			array(
				array(
					'id'   => 'missing',
					'file' => sys_get_temp_dir() . '/rip-no-such-module.php',
				),
				array(
					'id'   => 'boom',
					'file' => $boom,
				),
				array(
					'id'   => 'after',
					'file' => $ok,
				),
			)
		);
		$this->assertSame( 'OKPASS', $this->run_guard() );
	}

	/**
	 * A module file that defines no entry function fails open, the rules still run.
	 */
	public function test_included_file_without_function_fails_open() {
		$this->register_modules(
			array(
				array(
					'id'   => 'empty',
					'file' => $this->module_file( 'return;' ),
				),
			)
		);
		$this->assertSame( 'PASS', $this->run_guard() );
		$this->assertSame( 'Forbidden', $this->run_guard( array( 'REQUEST_URI' => '/?f=../../etc/passwd' ) ) );
	}

	/**
	 * A blocked IP is refused before any module sees it.
	 */
	public function test_blocked_ip_never_reaches_a_module() {
		$this->seed_blocklist( '198.51.100.60' );
		$this->register_module( 'seen', 'echo "SEEN";' );
		$this->assertSame( 'Forbidden', $this->run_guard( array( 'REMOTE_ADDR' => '198.51.100.60' ) ) );
	}

	/**
	 * A whitelisted IP leaves the guard before any module sees it.
	 */
	public function test_whitelisted_ip_never_reaches_a_module() {
		$this->register_module( 'seen', 'echo "SEEN";' );
		$source = preg_replace( '/\$whitelist  = array \(\n\);/', '$whitelist  = array( \'203.0.113.50\' );', $this->guard_source(), 1, $count );
		$this->assertSame( 1, $count, 'The baked whitelist must be found in the guard.' );
		$this->assertSame( 'PASS', $this->run_guard( array(), $source ) );
		$this->assertSame( 'SEENPASS', $this->run_guard( array( 'REMOTE_ADDR' => '203.0.113.51' ), $source ) );
	}

	/**
	 * Objects in a module config never reach the guard, and the rules still apply.
	 */
	public function test_object_in_config_is_dropped_and_rules_still_apply() {
		$this->register_module(
			'cfg',
			'echo json_encode( $config );',
			array(
				'keep'   => 1,
				'obj'    => new \stdClass(),
				'nested' => array(
					'o' => new \ArrayObject(),
					'n' => null,
				),
			)
		);
		$snapshot = $this->mgr()->modules_snapshot();
		$this->assertSame(
			array(
				'keep'   => 1,
				'nested' => array( 'n' => null ),
			),
			$snapshot[0]['config']
		);
		$this->assertStringNotContainsString( '__set_state', $this->guard_source() );
		$this->assertSame( '{"keep":1,"nested":{"n":null}}Forbidden', $this->run_guard( array( 'REQUEST_URI' => '/?f=../../etc/passwd' ) ) );
	}

	/**
	 * A module list that fails to load skips the modules, never the rules.
	 */
	public function test_broken_module_list_still_runs_the_rules() {
		$this->register_modules(
			array(
				array(
					'id'   => 'x',
					'file' => '/nope.php',
				),
			)
		);
		$source = preg_replace( '/\$modules = array \(.*?\n\);/s', '$modules = RipNoSuchClass::__set_state( array() );', $this->guard_source(), 1, $count );
		$this->assertSame( 1, $count, 'The baked module list must be found in the guard.' );
		$this->assertSame( 'PASS', $this->run_guard( array(), $source ) );
		$this->assertSame( 'Forbidden', $this->run_guard( array( 'REQUEST_URI' => '/?f=../../etc/passwd' ), $source ) );
	}

	/**
	 * A queue line with a foreign kind goes to the action, not to the WAF.
	 */
	public function test_foreign_kind_is_dispatched_to_the_action() {
		$seen = array();
		add_action(
			'reportedip_hive_guard_queue_entry',
			static function ( $entry ) use ( &$seen ) {
				$seen[] = $entry;
			}
		);
		$this->mgr()->guard_dir();
		$lines = array(
			wp_json_encode(
				array(
					'kind' => 'load_shield',
					'time' => time(),
					'exp'  => 3,
				)
			),
			wp_json_encode(
				array(
					'kind'  => 'waf',
					'time'  => time(),
					'ip'    => '198.51.100.61',
					'rule'  => 'waf_traversal',
					'group' => 'path_traversal',
				)
			),
			wp_json_encode(
				array(
					'time' => time(),
					'ip'   => '198.51.100.62',
					'rule' => 'waf_traversal',
				)
			),
		);
		file_put_contents( $this->mgr()->queue_path(), implode( "\n", $lines ) . "\n" );
		$this->mgr()->drain_queue();
		$this->assertCount( 1, $seen, 'Only the foreign line reaches the action; waf and legacy lines stay with the WAF.' );
		$this->assertSame( 'load_shield', $seen[0]['kind'] );
		$this->assertSame( 3, $seen[0]['exp'] );
	}

	/**
	 * The guard tags its own queue lines as waf.
	 */
	public function test_guard_queue_line_carries_the_waf_kind() {
		$this->assertSame( 'Forbidden', $this->run_guard( array( 'REQUEST_URI' => '/?f=../../etc/passwd' ) ) );
		$lines = array_values( array_filter( explode( "\n", (string) file_get_contents( $this->mgr()->queue_path() ) ) ) );
		$this->assertCount( 1, $lines );
		$this->assertSame( 'waf', json_decode( $lines[0], true )['kind'] );
	}
}
