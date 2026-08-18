<?php
/**
 * Differential test: the baked guard's IP matcher must agree with the engine's.
 *
 * The two WAF layers must decide identically, but they carry separate
 * implementations of the same primitives — the engine calls
 * `Database::ip_in_cidr()`, while the pre-WordPress guard ships its own
 * `reportedip_hive_dropin_ip_match()` because it runs before WordPress and can
 * call nothing. Existing coverage pins the *rule* list across both layers and
 * asserts the guard's helper functions exist by name; nothing compared what
 * they actually return.
 *
 * That gap matters: whitelist entries, CIDR blocks and IP-scoped exceptions
 * are all decided by this one function. A divergence means an address the
 * engine treats as whitelisted gets a 403 before WordPress loads, or a range
 * the engine blocks walks through.
 *
 * This runs the generated guard in an isolated subprocess and compares its
 * verdict against the engine's for the same inputs.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.44
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReflectionMethod;
	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';

	class WafGuardHelperParityTest extends TestCase {

		/**
		 * (ip, cidr) pairs covering the shapes the matcher has to agree on.
		 *
		 * @return array<int, array{0:string,1:string}>
		 */
		private function fixtures(): array {
			return array(
				array( '203.0.113.9', '203.0.113.0/24' ),
				array( '203.0.113.9', '203.0.113.9' ),
				array( '203.0.114.9', '203.0.113.0/24' ),
				array( '203.0.113.9', '203.0.113.8/31' ),
				array( '203.0.113.9', '203.0.113.9/32' ),
				array( '203.0.113.9', '0.0.0.0/0' ),
				array( '10.0.0.7', '10.0.0.0/8' ),
				array( '10.1.2.3', '10.0.0.0/16' ),
				array( '192.168.1.1', '192.168.0.0/23' ),
				array( '192.168.2.1', '192.168.0.0/23' ),
				// IPv6, including partial-byte masks.
				array( '2001:db8::1', '2001:db8::/32' ),
				array( '2001:db8::1', '2001:db8::1' ),
				array( '2001:db9::1', '2001:db8::/32' ),
				array( '2001:db8::1', '2001:db8::/128' ),
				array( '2001:db8::1', '::/0' ),
				array( '2001:db8:0:1::1', '2001:db8::/48' ),
				array( '2001:db8:0:1::1', '2001:db8::/47' ),
				array( 'fe80::1', 'fe80::/10' ),
				// Cross-family: must never match either way.
				array( '203.0.113.9', '2001:db8::/32' ),
				array( '2001:db8::1', '203.0.113.0/24' ),
				// Malformed input must be refused consistently.
				array( '203.0.113.9', '203.0.113.0/33' ),
				array( '203.0.113.9', '203.0.113.0/-1' ),
				array( 'not-an-ip', '203.0.113.0/24' ),
				array( '203.0.113.9', 'not-a-cidr' ),
				array( '', '203.0.113.0/24' ),
				array( '203.0.113.9', '' ),
			);
		}

		/**
		 * Ask the generated guard for its verdict on every fixture.
		 *
		 * @return array<int, bool>
		 */
		private function guard_verdicts(): array {
			$manager = \ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
			$method  = new ReflectionMethod( \ReportedIP_Hive_WAF_Dropin_Manager::class, 'generate_prepend' );
			$method->setAccessible( true );
			$guard_source = (string) $method->invoke( $manager );

			$guard = tempnam( sys_get_temp_dir(), 'rip-parity-guard-' ) . '.php';
			file_put_contents( $guard, $guard_source );

			$boot = tempnam( sys_get_temp_dir(), 'rip-parity-boot-' ) . '.php';
			file_put_contents(
				$boot,
				"<?php\n"
					. '$_SERVER = ' . var_export( array( 'REMOTE_ADDR' => '198.51.100.200', 'REQUEST_URI' => '/', 'HTTP_USER_AGENT' => 'parity-probe', 'REQUEST_METHOD' => 'GET' ), true ) . ";\n"
					. "\$_COOKIE = array();\n\$_POST = array();\n"
					. 'include ' . var_export( $guard, true ) . ";\n"
					. '$cases = ' . var_export( $this->fixtures(), true ) . ";\n"
					. "\$out = array();\n"
					. "foreach ( \$cases as \$case ) { \$out[] = reportedip_hive_dropin_ip_match( \$case[0], \$case[1] ) ? 1 : 0; }\n"
					. "echo json_encode( \$out );\n"
			);

			$output    = array();
			$exit_code = 0;
			exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $boot ), $output, $exit_code );
			unlink( $guard );
			unlink( $boot );

			$this->assertSame( 0, $exit_code, 'Guard probe must run cleanly: ' . implode( "\n", $output ) );

			$decoded = json_decode( trim( implode( '', $output ) ), true );
			$this->assertIsArray( $decoded, 'Guard probe must return a JSON verdict list, got: ' . implode( '', $output ) );

			return array_map( 'boolval', $decoded );
		}

		public function test_guard_ip_matcher_agrees_with_the_engine() {
			$fixtures = $this->fixtures();
			$guard    = $this->guard_verdicts();

			$this->assertCount( count( $fixtures ), $guard, 'One verdict per fixture' );

			$divergences = array();
			foreach ( $fixtures as $index => $case ) {
				$engine = (bool) \ReportedIP_Hive_Database::ip_in_cidr( $case[0], $case[1] );

				if ( $engine !== $guard[ $index ] ) {
					$divergences[] = sprintf(
						'%s in %s — engine=%s guard=%s',
						'' === $case[0] ? '(empty)' : $case[0],
						'' === $case[1] ? '(empty)' : $case[1],
						$engine ? 'match' : 'no match',
						$guard[ $index ] ? 'match' : 'no match'
					);
				}
			}

			$this->assertSame(
				array(),
				$divergences,
				"The pre-WordPress guard and the in-WordPress engine must reach the same verdict:\n" . implode( "\n", $divergences )
			);
		}

		public function test_cross_family_comparisons_never_match_in_either_layer() {
			$guard    = $this->guard_verdicts();
			$fixtures = $this->fixtures();

			foreach ( $fixtures as $index => $case ) {
				$ip_is_v6   = false !== strpos( $case[0], ':' );
				$cidr_is_v6 = false !== strpos( $case[1], ':' );

				if ( '' === $case[0] || '' === $case[1] || $ip_is_v6 === $cidr_is_v6 ) {
					continue;
				}

				$this->assertFalse(
					$guard[ $index ],
					sprintf( 'Guard must not match %s against %s across address families', $case[0], $case[1] )
				);
				$this->assertFalse(
					(bool) \ReportedIP_Hive_Database::ip_in_cidr( $case[0], $case[1] ),
					sprintf( 'Engine must not match %s against %s across address families', $case[0], $case[1] )
				);
			}
		}
	}
}
