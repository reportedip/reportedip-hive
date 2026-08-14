<?php
/**
 * Tests for the verbose marker on the reputation cache envelope.
 *
 * `check_ip_reputation( $ip, $verbose )` used to answer a verbose request
 * from whatever envelope the cache held, so a prior non-verbose check
 * silently stripped ISP/usage-type/Tor data from the lookup surface for a
 * full cache TTL. The envelope now carries a `verbose` flag:
 * `get_reputation( $ip, true )` treats a non-verbose (or legacy, pre-marker)
 * envelope as a miss without deleting it, while a verbose envelope satisfies
 * both read modes. The cases seed the REAL `ReportedIP_Hive_Cache` through
 * `set_reputation()` against the transient stubs; separate processes keep
 * the cache/logger singletons isolated from stand-ins other tests declare.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class CacheVerboseTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		$GLOBALS['wp_options']    = array();
		$GLOBALS['wp_transients'] = array();

		$root = dirname( __DIR__, 2 );
		require_once $root . '/includes/class-database.php';
		require_once $root . '/includes/class-logger.php';
		require_once $root . '/includes/class-cache.php';
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
	 * The transient key set_reputation() writes for an IP.
	 *
	 * @param string $ip Address.
	 * @return string
	 */
	private function cache_key( string $ip ): string {
		return 'reportedip_reputation_' . hash( 'sha256', $ip );
	}

	public function test_non_verbose_envelope_does_not_satisfy_a_verbose_read() {
		$ip = '203.0.113.30';
		$this->cache()->set_reputation( $ip, array( 'abuseConfidencePercentage' => 40 ) );

		$this->assertFalse(
			$this->cache()->get_reputation( $ip, true ),
			'A non-verbose envelope must read as a miss when verbose data is required'
		);

		$plain = $this->cache()->get_reputation( $ip );
		$this->assertIsArray( $plain, 'The same envelope must keep serving non-verbose reads' );
		$this->assertSame( 40, $plain['data']['abuseConfidencePercentage'] );
	}

	public function test_verbose_envelope_satisfies_both_read_modes() {
		$ip = '203.0.113.31';
		$this->cache()->set_reputation(
			$ip,
			array(
				'abuseConfidencePercentage' => 90,
				'isp'                       => 'Example Carrier',
			),
			false,
			true
		);

		$verbose = $this->cache()->get_reputation( $ip, true );
		$this->assertIsArray( $verbose, 'A verbose envelope must satisfy a verbose read' );
		$this->assertSame( 'Example Carrier', $verbose['data']['isp'] );
		$this->assertTrue( $verbose['verbose'] );

		$plain = $this->cache()->get_reputation( $ip );
		$this->assertIsArray( $plain, 'A verbose envelope must also satisfy a non-verbose read' );
		$this->assertSame( 90, $plain['data']['abuseConfidencePercentage'] );
	}

	public function test_legacy_envelope_without_marker_is_treated_as_non_verbose() {
		$ip = '203.0.113.32';
		\set_transient(
			$this->cache_key( $ip ),
			array(
				'data'        => array( 'abuseConfidencePercentage' => 55 ),
				'cached_at'   => gmdate( 'Y-m-d H:i:s' ),
				'ip_address'  => $ip,
				'is_negative' => false,
				'ttl'         => 3600,
			),
			3600
		);

		$this->assertFalse(
			$this->cache()->get_reputation( $ip, true ),
			'An envelope written before the marker existed must not satisfy a verbose read'
		);

		$plain = $this->cache()->get_reputation( $ip );
		$this->assertIsArray( $plain, 'A legacy envelope must keep serving non-verbose reads' );
		$this->assertSame( 55, $plain['data']['abuseConfidencePercentage'] );
	}

	public function test_insufficient_envelope_is_not_deleted_by_the_verbose_read() {
		$ip = '203.0.113.33';
		$this->cache()->set_reputation( $ip, array( 'abuseConfidencePercentage' => 10 ) );

		$this->assertFalse( $this->cache()->get_reputation( $ip, true ) );
		$this->assertArrayHasKey(
			$this->cache_key( $ip ),
			$GLOBALS['wp_transients'],
			'The verbose miss must leave the non-verbose envelope in place for later plain reads'
		);
	}
}
