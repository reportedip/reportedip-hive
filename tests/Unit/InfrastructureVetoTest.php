<?php
/**
 * Tests for the never-block infrastructure veto.
 *
 * `Security_Monitor::should_spare_infrastructure_ip()` consults the LOCAL
 * reputation cache (never a live API call) and vetoes the auto-block when the
 * cached envelope flags the IP as community-whitelisted infrastructure
 * (`data.isWhitelisted`). The behavioural cases seed the REAL
 * `ReportedIP_Hive_Cache` through `set_reputation()` so the envelope contract
 * ('data' nesting, negative-cache shape, cache-key derivation) is validated
 * end to end against the transient stubs; the private predicate is invoked
 * via reflection on a monitor built without its constructor. The companion
 * veto in `pre_auth_check()` cannot run in the unit harness (the main plugin
 * file is not loadable), so it is anchored via source inspection following
 * the IsPublicIpTest idiom. Separate processes keep the real cache/logger
 * singletons isolated from the stand-ins other test files declare.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

namespace {

	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}

	if ( ! defined( 'REPORTEDIP_USER_AGENT_MAX_LENGTH' ) ) {
		define( 'REPORTEDIP_USER_AGENT_MAX_LENGTH', 50 );
	}

	if ( ! class_exists( 'Test_IV_Logger_Stub' ) ) {
		/**
		 * Recording logger double injected into the monitor under test.
		 */
		class Test_IV_Logger_Stub {

			/**
			 * Every log_security_event() call, verbatim.
			 *
			 * @var array<int, array>
			 */
			public $events = array();

			/**
			 * Record the call instead of writing a log row.
			 *
			 * @param mixed ...$args Log arguments.
			 * @return void
			 */
			public function log_security_event( ...$args ) {
				$this->events[] = $args;
			}
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class InfrastructureVetoTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();

			$root = dirname( __DIR__, 2 );
			require_once $root . '/includes/class-database.php';
			require_once $root . '/includes/class-logger.php';
			require_once $root . '/includes/class-cache.php';
			require_once $root . '/includes/class-security-monitor.php';
		}

		/**
		 * The real cache singleton, fresh per isolated test process.
		 *
		 * @return \ReportedIP_Hive_Cache
		 */
		private function cache(): \ReportedIP_Hive_Cache {
			return \ReportedIP_Hive_Cache::get_instance();
		}

		/**
		 * Invoke the private veto on a monitor with the real cache and a
		 * recording logger injected.
		 *
		 * @param string               $ip     Candidate address.
		 * @param string               $event  Sensor event slug.
		 * @param \Test_IV_Logger_Stub $logger Recording logger double.
		 * @return bool
		 */
		private function invoke_veto( string $ip, string $event, \Test_IV_Logger_Stub $logger ): bool {
			$monitor = ( new \ReflectionClass( \ReportedIP_Hive_Security_Monitor::class ) )->newInstanceWithoutConstructor();

			$collaborators = array(
				'cache'  => $this->cache(),
				'logger' => $logger,
			);

			foreach ( $collaborators as $property => $value ) {
				$prop = new \ReflectionProperty( \ReportedIP_Hive_Security_Monitor::class, $property );
				$prop->setAccessible( true );
				$prop->setValue( $monitor, $value );
			}

			$method = new \ReflectionMethod( \ReportedIP_Hive_Security_Monitor::class, 'should_spare_infrastructure_ip' );
			$method->setAccessible( true );

			return (bool) $method->invoke( $monitor, $ip, $event );
		}

		/**
		 * The once-per-hour log-gate transient key the veto uses.
		 *
		 * @param string $ip    Candidate address.
		 * @param string $event Sensor event slug.
		 * @return string
		 */
		private function gate_key( string $ip, string $event ): string {
			return 'reportedip_hive_infra_spared_' . md5( $ip . '|' . $event );
		}

		public function test_whitelisted_infrastructure_is_spared_and_gate_set() {
			$ip = '203.0.113.9';
			$this->cache()->set_reputation(
				$ip,
				array(
					'isWhitelisted'             => true,
					'abuseConfidencePercentage' => 90,
				)
			);

			$logger = new \Test_IV_Logger_Stub();
			$this->assertTrue( $this->invoke_veto( $ip, 'scan_404', $logger ), 'A cached isWhitelisted flag must veto the auto-block' );
			$this->assertNotFalse( \get_transient( $this->gate_key( $ip, 'scan_404' ) ), 'The once-per-hour log gate must be set' );

			$this->assertContains( 'infrastructure_spared', array_column( $logger->events, 0 ), 'The averted block must be visible to operators' );
		}

		public function test_spared_log_is_throttled_by_the_gate() {
			$ip = '203.0.113.10';
			$this->cache()->set_reputation( $ip, array( 'isWhitelisted' => true ) );

			$logger = new \Test_IV_Logger_Stub();
			$this->assertTrue( $this->invoke_veto( $ip, 'rest_abuse', $logger ) );
			$this->assertTrue( $this->invoke_veto( $ip, 'rest_abuse', $logger ), 'The veto itself must keep holding on repeat hits' );

			$spared = array_filter(
				array_column( $logger->events, 0 ),
				static function ( $event_type ) {
					return 'infrastructure_spared' === $event_type;
				}
			);
			$this->assertCount( 1, $spared, 'The gate must limit the log to one entry per hour per IP/event pair' );
		}

		public function test_uncached_ip_is_not_spared() {
			$logger = new \Test_IV_Logger_Stub();
			$this->assertFalse( $this->invoke_veto( '198.51.100.4', 'scan_404', $logger ), 'No cached reputation means no veto — never a live API call' );
			$this->assertSame( array(), $logger->events );
			$this->assertFalse( \get_transient( $this->gate_key( '198.51.100.4', 'scan_404' ) ), 'No gate must be set when the veto declines' );
		}

		public function test_envelope_without_whitelist_flag_is_not_spared() {
			$ip = '198.51.100.5';
			$this->cache()->set_reputation( $ip, array( 'abuseConfidencePercentage' => 95 ) );

			$logger = new \Test_IV_Logger_Stub();
			$this->assertFalse( $this->invoke_veto( $ip, 'scan_404', $logger ), 'A hostile reputation without the whitelist flag must stay blockable' );
		}

		public function test_explicit_false_whitelist_flag_is_not_spared() {
			$ip = '198.51.100.6';
			$this->cache()->set_reputation(
				$ip,
				array(
					'isWhitelisted'             => false,
					'abuseConfidencePercentage' => 40,
				)
			);

			$logger = new \Test_IV_Logger_Stub();
			$this->assertFalse( $this->invoke_veto( $ip, 'xmlrpc_abuse', $logger ) );
		}

		public function test_negative_cache_entry_is_not_spared() {
			$ip = '198.51.100.7';
			$this->cache()->set_reputation( $ip, false, true );

			$logger = new \Test_IV_Logger_Stub();
			$this->assertFalse( $this->invoke_veto( $ip, 'scan_404', $logger ), 'A negative-cache envelope (data === false) carries no whitelist verdict' );
		}

		public function test_reputation_cache_key_contract() {
			$ip = '203.0.113.20';
			$this->cache()->set_reputation( $ip, array( 'isWhitelisted' => true ) );

			$this->assertArrayHasKey(
				'reportedip_reputation_' . hash( 'sha256', $ip ),
				$GLOBALS['wp_transients'],
				'set_reputation() must store under the documented reputation cache key so the veto reads the same slot'
			);
		}

		public function test_pre_auth_check_derives_the_veto_from_the_reputation_flag() {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
			$start  = strpos( $source, 'function pre_auth_check' );
			$this->assertNotFalse( $start, 'pre_auth_check() must exist' );

			$body = substr( $source, $start, 8000 );

			$assign_pos = strpos( $body, '$is_infrastructure = ' );
			$this->assertNotFalse( $assign_pos, 'pre_auth_check() must derive the infrastructure veto from the reputation envelope' );

			$assign_end = strpos( $body, ';', $assign_pos );
			$this->assertNotFalse( $assign_end );
			$assignment = substr( $body, $assign_pos, $assign_end - $assign_pos );
			$this->assertStringContainsString(
				'isWhitelisted',
				$assignment,
				'The veto must come from the isWhitelisted reputation flag'
			);
			$this->assertStringContainsString(
				'is_array( $reputation )',
				$assignment,
				'The veto must guard against a non-array reputation payload'
			);

			$this->assertStringContainsString(
				'$exceeds_threshold && ! $is_infrastructure',
				$body,
				'The reputation block must stand down for community-whitelisted infrastructure'
			);
		}
	}
}
