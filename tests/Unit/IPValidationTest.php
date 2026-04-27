<?php
/**
 * Unit Tests for IP Validation functionality.
 *
 * Tests IP address validation without WordPress dependencies.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.0.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Test class for IP validation functionality.
 */
class IPValidationTest extends TestCase {

	/**
	 * Test valid IPv4 addresses.
	 *
	 * @dataProvider valid_ipv4_provider
	 * @param string $ip The IP address to test.
	 */
	public function test_valid_ipv4_addresses( $ip ) {
		$this->assertTrue(
			filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) !== false,
			"$ip should be a valid IPv4 address"
		);
	}

	/**
	 * Data provider for valid IPv4 addresses.
	 *
	 * @return array
	 */
	public function valid_ipv4_provider() {
		return array(
			'standard public IP'    => array( '8.8.8.8' ),
			'google DNS'            => array( '8.8.4.4' ),
			'cloudflare DNS'        => array( '1.1.1.1' ),
			'private class A'       => array( '10.0.0.1' ),
			'private class B'       => array( '172.16.0.1' ),
			'private class C'       => array( '192.168.1.1' ),
			'localhost'             => array( '127.0.0.1' ),
			'broadcast'             => array( '255.255.255.255' ),
			'zero address'          => array( '0.0.0.0' ),
			'max octets'            => array( '255.255.255.254' ),
		);
	}

	/**
	 * Test invalid IPv4 addresses.
	 *
	 * @dataProvider invalid_ipv4_provider
	 * @param string $ip The IP address to test.
	 */
	public function test_invalid_ipv4_addresses( $ip ) {
		$this->assertFalse(
			filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) !== false,
			"$ip should be an invalid IPv4 address"
		);
	}

	/**
	 * Data provider for invalid IPv4 addresses.
	 *
	 * @return array
	 */
	public function invalid_ipv4_provider() {
		return array(
			'empty string'          => array( '' ),
			'too many octets'       => array( '1.2.3.4.5' ),
			'too few octets'        => array( '1.2.3' ),
			'octet too large'       => array( '256.1.1.1' ),
			'negative octet'        => array( '-1.1.1.1' ),
			'letters in IP'         => array( 'abc.def.ghi.jkl' ),
			'mixed letters numbers' => array( '192.168.1.abc' ),
			'double dot'            => array( '192..168.1.1' ),
			'leading zero'          => array( '192.168.01.1' ),
			'IPv6 address'          => array( '2001:4860:4860::8888' ),
			'just text'             => array( 'not-an-ip' ),
			'null value'            => array( null ),
		);
	}

	/**
	 * Test valid IPv6 addresses.
	 *
	 * @dataProvider valid_ipv6_provider
	 * @param string $ip The IP address to test.
	 */
	public function test_valid_ipv6_addresses( $ip ) {
		$this->assertTrue(
			filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) !== false,
			"$ip should be a valid IPv6 address"
		);
	}

	/**
	 * Data provider for valid IPv6 addresses.
	 *
	 * @return array
	 */
	public function valid_ipv6_provider() {
		return array(
			'google DNS'            => array( '2001:4860:4860::8888' ),
			'cloudflare DNS'        => array( '2606:4700:4700::1111' ),
			'full address'          => array( '2001:0db8:0000:0000:0000:0000:0000:0001' ),
			'compressed zeros'      => array( '2001:db8::1' ),
			'loopback'              => array( '::1' ),
			'all zeros'             => array( '::' ),
			'link local'            => array( 'fe80::1' ),
			'mixed notation'        => array( '::ffff:192.168.1.1' ),
		);
	}

	/**
	 * Test invalid IPv6 addresses.
	 *
	 * @dataProvider invalid_ipv6_provider
	 * @param string $ip The IP address to test.
	 */
	public function test_invalid_ipv6_addresses( $ip ) {
		$this->assertFalse(
			filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) !== false,
			"$ip should be an invalid IPv6 address"
		);
	}

	/**
	 * Data provider for invalid IPv6 addresses.
	 *
	 * @return array
	 */
	public function invalid_ipv6_provider() {
		return array(
			'IPv4 address'          => array( '192.168.1.1' ),
			'too many groups'       => array( '2001:db8:0:0:0:0:0:0:0' ),
			'invalid hex'           => array( '2001:db8:0:0:0:0:0:ghij' ),
			'double compression'    => array( '2001::db8::1' ),
			'empty string'          => array( '' ),
			'just text'             => array( 'not-an-ipv6' ),
		);
	}

	/**
	 * Test valid CIDR notation.
	 *
	 * @dataProvider valid_cidr_provider
	 * @param string $cidr The CIDR to test.
	 */
	public function test_valid_cidr_notation( $cidr ) {
		$this->assertTrue(
			$this->is_valid_cidr( $cidr ),
			"$cidr should be a valid CIDR notation"
		);
	}

	/**
	 * Data provider for valid CIDR notations.
	 *
	 * @return array
	 */
	public function valid_cidr_provider() {
		return array(
			'IPv4 /32'         => array( '192.168.1.1/32' ),
			'IPv4 /24'         => array( '192.168.1.0/24' ),
			'IPv4 /16'         => array( '192.168.0.0/16' ),
			'IPv4 /8'          => array( '10.0.0.0/8' ),
			'IPv4 /0'          => array( '0.0.0.0/0' ),
			'IPv6 /128'        => array( '2001:db8::1/128' ),
			'IPv6 /64'         => array( '2001:db8::/64' ),
			'IPv6 /48'         => array( '2001:db8::/48' ),
			'IPv6 /32'         => array( '2001:db8::/32' ),
		);
	}

	/**
	 * Test invalid CIDR notation.
	 *
	 * @dataProvider invalid_cidr_provider
	 * @param string $cidr The CIDR to test.
	 */
	public function test_invalid_cidr_notation( $cidr ) {
		$this->assertFalse(
			$this->is_valid_cidr( $cidr ),
			"$cidr should be an invalid CIDR notation"
		);
	}

	/**
	 * Data provider for invalid CIDR notations.
	 *
	 * @return array
	 */
	public function invalid_cidr_provider() {
		return array(
			'IPv4 mask > 32'      => array( '192.168.1.0/33' ),
			'IPv4 negative mask'  => array( '192.168.1.0/-1' ),
			'IPv6 mask > 128'     => array( '2001:db8::/129' ),
			'invalid IP in CIDR'  => array( '999.999.999.999/24' ),
			'no mask'             => array( '192.168.1.1/' ),
			'no IP'               => array( '/24' ),
			'text mask'           => array( '192.168.1.0/abc' ),
			'empty string'        => array( '' ),
			'plain IP'            => array( '192.168.1.1' ),
		);
	}

	/**
	 * Test private IP detection.
	 *
	 * @dataProvider private_ip_provider
	 * @param string $ip          The IP address to test.
	 * @param bool   $is_private  Expected result.
	 */
	public function test_private_ip_detection( $ip, $is_private ) {
		$result = filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false;
		$this->assertEquals(
			$is_private,
			$result,
			sprintf( '%s should %sbe detected as private/reserved', $ip, $is_private ? '' : 'not ' )
		);
	}

	/**
	 * Data provider for private IP detection.
	 *
	 * @return array
	 */
	public function private_ip_provider() {
		return array(
			'10.x.x.x'            => array( '10.0.0.1', true ),
			'10.255.255.255'      => array( '10.255.255.255', true ),
			'172.16.x.x'          => array( '172.16.0.1', true ),
			'172.31.255.255'      => array( '172.31.255.255', true ),
			'192.168.x.x'         => array( '192.168.1.1', true ),
			'localhost'           => array( '127.0.0.1', true ),
			'link-local'          => array( '169.254.1.1', true ),

			'google DNS'          => array( '8.8.8.8', false ),
			'cloudflare DNS'      => array( '1.1.1.1', false ),
			'random public'       => array( '203.0.113.1', false ),

			'172.15.255.255'      => array( '172.15.255.255', false ),
			'172.32.0.0'          => array( '172.32.0.0', false ),
		);
	}

	/**
	 * Test IP version detection.
	 *
	 * @dataProvider ip_version_provider
	 * @param string   $ip              The IP address to test.
	 * @param int|null $expected_version Expected IP version (4, 6, or null for invalid).
	 */
	public function test_ip_version_detection( $ip, $expected_version ) {
		$version = $this->get_ip_version( $ip );
		$this->assertEquals(
			$expected_version,
			$version,
			sprintf( '%s should be detected as IPv%s', $ip, $expected_version ?? 'invalid' )
		);
	}

	/**
	 * Data provider for IP version detection.
	 *
	 * @return array
	 */
	public function ip_version_provider() {
		return array(
			'IPv4 public'     => array( '8.8.8.8', 4 ),
			'IPv4 private'    => array( '192.168.1.1', 4 ),
			'IPv4 localhost'  => array( '127.0.0.1', 4 ),
			'IPv6 full'       => array( '2001:4860:4860::8888', 6 ),
			'IPv6 loopback'   => array( '::1', 6 ),
			'IPv6 compressed' => array( '2001:db8::1', 6 ),
			'invalid'         => array( 'not-an-ip', null ),
			'empty'           => array( '', null ),
		);
	}

	/**
	 * Helper method to validate CIDR notation.
	 *
	 * @param string $cidr The CIDR to validate.
	 * @return bool
	 */
	private function is_valid_cidr( $cidr ) {
		if ( empty( $cidr ) || strpos( $cidr, '/' ) === false ) {
			return false;
		}

		$parts = explode( '/', $cidr, 2 );
		if ( count( $parts ) !== 2 ) {
			return false;
		}

		list( $ip, $mask ) = $parts;

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		if ( ! is_numeric( $mask ) ) {
			return false;
		}

		$mask = (int) $mask;

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return $mask >= 0 && $mask <= 32;
		} elseif ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return $mask >= 0 && $mask <= 128;
		}

		return false;
	}

	/**
	 * Helper method to get IP version.
	 *
	 * @param string $ip The IP address.
	 * @return int|null
	 */
	private function get_ip_version( $ip ) {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return 4;
		} elseif ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return 6;
		}
		return null;
	}
}
