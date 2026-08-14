<?php
/**
 * Unit tests for the trusted-proxy source validation.
 *
 * Locks the two halves of the anti-spoofing contract: parse_ranges() reduces
 * the raw textarea option to a clean, de-duplicated IP/CIDR list (dropping
 * comments, blanks and garbage), and source_is_trusted() only lets peers
 * inside that list supply the client-IP header — with the empty list keeping
 * the trust-every-peer pre-2.1.41 behaviour.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-proxy-trust.php';

	/**
	 * @covers \ReportedIP_Hive_Proxy_Trust
	 */
	class ProxyTrustTest extends TestCase {

		public function test_parse_ranges_keeps_valid_entries_in_order(): void {
			$raw = "203.0.113.7\n2001:db8::/32\n198.51.100.0/24\n2001:db8::5";

			$this->assertSame(
				array( '203.0.113.7', '2001:db8::/32', '198.51.100.0/24', '2001:db8::5' ),
				\ReportedIP_Hive_Proxy_Trust::parse_ranges( $raw ),
				'Valid IPv4/IPv6/CIDR entries must survive in input order.'
			);
		}

		public function test_parse_ranges_skips_blank_and_comment_lines(): void {
			$raw = "\n# load balancers\n203.0.113.7\n\n   \n# end of list\n";

			$this->assertSame( array( '203.0.113.7' ), \ReportedIP_Hive_Proxy_Trust::parse_ranges( $raw ) );
		}

		public function test_parse_ranges_drops_garbage_entries(): void {
			$raw = "not-an-ip\n1.2.3.4/33\n::1/129\n1.2.3.4/-1\n1.2.3.4/x\n999.1.1.1\n198.51.100.0/24";

			$this->assertSame(
				array( '198.51.100.0/24' ),
				\ReportedIP_Hive_Proxy_Trust::parse_ranges( $raw ),
				'Non-IP tokens and implausible masks (v4 > /32, v6 > /128) must be dropped silently.'
			);
		}

		public function test_parse_ranges_drops_duplicates(): void {
			$raw = "203.0.113.7\n203.0.113.7\n198.51.100.0/24\n198.51.100.0/24";

			$this->assertSame( array( '203.0.113.7', '198.51.100.0/24' ), \ReportedIP_Hive_Proxy_Trust::parse_ranges( $raw ) );
		}

		public function test_parse_ranges_accepts_crlf_and_lf_input(): void {
			$expected = array( '203.0.113.7', '198.51.100.0/24' );

			$this->assertSame( $expected, \ReportedIP_Hive_Proxy_Trust::parse_ranges( "203.0.113.7\r\n198.51.100.0/24" ) );
			$this->assertSame( $expected, \ReportedIP_Hive_Proxy_Trust::parse_ranges( "203.0.113.7\n198.51.100.0/24" ) );
		}

		/**
		 * An empty range list means every peer may supply the header — that is
		 * the pre-2.1.41 behaviour and keeps existing configurations working.
		 */
		public function test_empty_ranges_trust_every_peer(): void {
			$this->assertTrue( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '203.0.113.9', array() ) );
			$this->assertTrue( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '', array() ) );
		}

		public function test_exact_ip_match(): void {
			$ranges = array( '198.51.100.7' );

			$this->assertTrue( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '198.51.100.7', $ranges ) );
			$this->assertFalse( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '198.51.100.8', $ranges ) );
		}

		public function test_ipv4_cidr_containment(): void {
			$this->assertTrue( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '198.51.100.7', array( '198.51.100.0/24' ) ) );
			$this->assertFalse( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '198.51.100.7', array( '203.0.113.0/24' ) ) );
		}

		public function test_ipv6_cidr_containment(): void {
			$this->assertTrue( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '2001:db8::5', array( '2001:db8::/32' ) ) );
			$this->assertFalse( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '2001:db9::5', array( '2001:db8::/32' ) ) );
		}

		/**
		 * With a non-empty list an unparseable peer address must never be
		 * trusted — '' and the 'unknown' sentinel are what a broken server
		 * environment hands over, and both would otherwise bypass the check.
		 */
		public function test_invalid_remote_addr_is_untrusted(): void {
			$ranges = array( '198.51.100.0/24' );

			$this->assertFalse( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '', $ranges ) );
			$this->assertFalse( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( 'unknown', $ranges ) );
		}

		public function test_family_mismatch_is_untrusted(): void {
			$this->assertFalse( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '2001:db8::5', array( '198.51.100.0/24' ) ), 'A v6 peer can never fall inside a v4 range.' );
			$this->assertFalse( \ReportedIP_Hive_Proxy_Trust::source_is_trusted( '198.51.100.7', array( '2001:db8::/32' ) ), 'A v4 peer can never fall inside a v6 range.' );
		}
	}
}
