<?php
/**
 * Tests for ReportedIP_Hive_IP_Manager::ipv6_network_cidr().
 *
 * The whitelist "Add my IP" prefill must offer the enclosing /64 network
 * for IPv6 visitors — consumer connections rotate the interface identifier
 * inside their delegated prefix, so a /128 entry locks the user out on the
 * next rotation (see the schuh-eder.com support case). The helper zeroes
 * the host bits via inet_pton/inet_ntop and must refuse IPv4 and garbage
 * input with null so callers can fall back to the plain address.
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
class Ipv6NetworkCidrTest extends TestCase {

	protected function setUp(): void {
		parent::setUp();
		require_once dirname( __DIR__, 2 ) . '/includes/class-ip-manager.php';
	}

	public function test_canonical_ipv6_yields_its_64_network() {
		$this->assertSame(
			'2001:db8:abcd:12::/64',
			\ReportedIP_Hive_IP_Manager::ipv6_network_cidr( '2001:0db8:abcd:0012:0000:0000:0000:0001' )
		);
	}

	public function test_compressed_ipv6_yields_its_64_network() {
		$this->assertSame(
			'2001:db8:abcd:12::/64',
			\ReportedIP_Hive_IP_Manager::ipv6_network_cidr( '2001:db8:abcd:12::ffff' )
		);
	}

	public function test_already_network_address_is_unchanged() {
		$this->assertSame(
			'2001:db8:abcd:12::/64',
			\ReportedIP_Hive_IP_Manager::ipv6_network_cidr( '2001:db8:abcd:12::' )
		);
	}

	public function test_ipv4_input_returns_null() {
		$this->assertNull( \ReportedIP_Hive_IP_Manager::ipv6_network_cidr( '192.0.2.1' ) );
	}

	public function test_garbage_input_returns_null() {
		$this->assertNull( \ReportedIP_Hive_IP_Manager::ipv6_network_cidr( 'not-an-ip' ) );
		$this->assertNull( \ReportedIP_Hive_IP_Manager::ipv6_network_cidr( '' ) );
	}

	public function test_custom_prefix_56_zeroes_the_trailing_byte_bits() {
		$this->assertSame(
			'2001:db8:abcd:1200::/56',
			\ReportedIP_Hive_IP_Manager::ipv6_network_cidr( '2001:db8:abcd:1234::1', 56 )
		);
	}

	public function test_out_of_range_prefix_returns_null() {
		$this->assertNull( \ReportedIP_Hive_IP_Manager::ipv6_network_cidr( '2001:db8::1', 0 ) );
		$this->assertNull( \ReportedIP_Hive_IP_Manager::ipv6_network_cidr( '2001:db8::1', 129 ) );
	}
}
