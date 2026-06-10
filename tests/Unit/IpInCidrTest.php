<?php
/**
 * Unit tests for the shared CIDR matcher.
 *
 * Locks the canonical IPv4/IPv6 range test reused by the verified-bot sensor:
 * in-range and out-of-range verdicts, bare-IP equality and malformed input.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.2.0
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';

	/**
	 * @covers \ReportedIP_Hive_Database::ip_in_cidr
	 */
	class IpInCidrTest extends TestCase {

		public function test_ipv4_inside_range(): void {
			$this->assertTrue( \ReportedIP_Hive_Database::ip_in_cidr( '192.168.1.5', '192.168.1.0/24' ) );
		}

		public function test_ipv4_outside_range(): void {
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '192.168.2.5', '192.168.1.0/24' ) );
		}

		public function test_bare_ip_equality(): void {
			$this->assertTrue( \ReportedIP_Hive_Database::ip_in_cidr( '203.0.113.7', '203.0.113.7' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '203.0.113.8', '203.0.113.7' ) );
		}

		public function test_ipv6_inside_range(): void {
			$this->assertTrue( \ReportedIP_Hive_Database::ip_in_cidr( '2001:db8::1', '2001:db8::/32' ) );
		}

		public function test_ipv6_outside_range(): void {
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '2001:db9::1', '2001:db8::/32' ) );
		}

		public function test_malformed_input_is_false(): void {
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( 'not-an-ip', '192.168.1.0/24' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '192.168.1.5', '' ) );
		}
	}
}
