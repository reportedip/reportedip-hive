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
 * @since      2.1.2
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

		/**
		 * Regression: a v4 IP tested against a v6 CIDR used to feed a /128 mask
		 * into the 32-bit shift and raise "bit shift by negative number". It must
		 * now return false (mismatched family) instead of crashing the request.
		 */
		public function test_v4_ip_against_v6_cidr_does_not_crash(): void {
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '66.249.66.78', '2a03:2880::/29' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '66.249.66.78', '::1/128' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '127.0.0.1', '2001:db8::/64' ) );
		}

		/**
		 * Regression: a v6 IP tested against a v4 CIDR must also be a clean false.
		 */
		public function test_v6_ip_against_v4_cidr_is_false(): void {
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '2001:db8::1', '192.168.1.0/24' ) );
		}

		/**
		 * Out-of-bounds and malformed masks must be rejected, never shifted.
		 */
		public function test_out_of_range_masks_are_false(): void {
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '192.168.1.5', '192.168.1.0/33' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '192.168.1.5', '192.168.1.0/-1' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '2001:db8::1', '2001:db8::/129' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '192.168.1.5', '192.168.1.0/abc' ) );
		}

		/**
		 * A /0 range matches every same-family address (mask shift edge case).
		 */
		public function test_zero_mask_matches_all_same_family(): void {
			$this->assertTrue( \ReportedIP_Hive_Database::ip_in_cidr( '8.8.8.8', '0.0.0.0/0' ) );
			$this->assertTrue( \ReportedIP_Hive_Database::ip_in_cidr( '203.0.113.1', '10.0.0.0/0' ) );
		}

		/**
		 * Exact /32 and /128 host routes still match the single address.
		 */
		public function test_host_routes_match_single_address(): void {
			$this->assertTrue( \ReportedIP_Hive_Database::ip_in_cidr( '203.0.113.7', '203.0.113.7/32' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '203.0.113.8', '203.0.113.7/32' ) );
			$this->assertTrue( \ReportedIP_Hive_Database::ip_in_cidr( '2001:db8::1', '2001:db8::1/128' ) );
		}
	}
}
