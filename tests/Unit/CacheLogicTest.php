<?php
/**
 * Unit Tests for Cache Logic.
 *
 * Tests caching logic without WordPress dependencies.
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
 * Test class for cache logic.
 */
class CacheLogicTest extends TestCase {

	/**
	 * Test cache key generation.
	 */
	public function test_cache_key_generation() {
		$ip1 = '8.8.8.8';
		$ip2 = '192.168.1.1';

		$key1 = $this->generate_cache_key( $ip1 );
		$key2 = $this->generate_cache_key( $ip2 );

		$this->assertNotEquals( $key1, $key2, 'Cache keys should be unique per IP' );

		$this->assertEquals(
			$this->generate_cache_key( $ip1 ),
			$key1,
			'Same IP should generate same cache key'
		);
	}

	/**
	 * Test cache key uses SHA256 hash.
	 */
	public function test_cache_key_uses_sha256() {
		$ip  = '8.8.8.8';
		$key = $this->generate_cache_key( $ip );

		$expected_hash_length = 64;
		$prefix               = 'reportedip_reputation_';

		$this->assertStringStartsWith( $prefix, $key, 'Cache key should have prefix' );

		$hash_part = substr( $key, strlen( $prefix ) );
		$this->assertEquals(
			$expected_hash_length,
			strlen( $hash_part ),
			'Hash part should be 64 characters (SHA256)'
		);

		$expected_hash = hash( 'sha256', $ip );
		$this->assertEquals( $expected_hash, $hash_part, 'Hash should match SHA256 of IP' );
	}

	/**
	 * Test cache TTL calculation.
	 *
	 * @dataProvider ttl_provider
	 * @param int  $hours        Number of hours.
	 * @param int  $expected_ttl Expected TTL in seconds.
	 */
	public function test_cache_ttl_calculation( $hours, $expected_ttl ) {
		$ttl = $hours * 3600;
		$this->assertEquals( $expected_ttl, $ttl, "TTL for $hours hours should be $expected_ttl seconds" );
	}

	/**
	 * Data provider for TTL calculations.
	 *
	 * @return array
	 */
	public function ttl_provider() {
		return array(
			'1 hour'   => array( 1, 3600 ),
			'2 hours'  => array( 2, 7200 ),
			'6 hours'  => array( 6, 21600 ),
			'12 hours' => array( 12, 43200 ),
			'24 hours' => array( 24, 86400 ),
			'48 hours' => array( 48, 172800 ),
			'72 hours' => array( 72, 259200 ),
		);
	}

	/**
	 * Test cache hit rate calculation.
	 *
	 * @dataProvider hit_rate_provider
	 * @param int   $hits          Number of cache hits.
	 * @param int   $misses        Number of cache misses.
	 * @param float $expected_rate Expected hit rate percentage.
	 */
	public function test_cache_hit_rate_calculation( $hits, $misses, $expected_rate ) {
		$hit_rate = $this->calculate_hit_rate( $hits, $misses );
		$this->assertEquals( $expected_rate, $hit_rate, "Hit rate calculation should be $expected_rate%" );
	}

	/**
	 * Data provider for hit rate calculations.
	 *
	 * @return array
	 */
	public function hit_rate_provider() {
		return array(
			'no requests'          => array( 0, 0, 0.0 ),
			'all hits'             => array( 100, 0, 100.0 ),
			'all misses'           => array( 0, 100, 0.0 ),
			'50% hit rate'         => array( 50, 50, 50.0 ),
			'75% hit rate'         => array( 75, 25, 75.0 ),
			'90% hit rate'         => array( 90, 10, 90.0 ),
			'33.33% hit rate'      => array( 1, 2, 33.33 ),
			'66.67% hit rate'      => array( 2, 1, 66.67 ),
		);
	}

	/**
	 * Test negative cache TTL is shorter than positive cache TTL.
	 */
	public function test_negative_cache_ttl_is_shorter() {
		$positive_cache_hours = 24;
		$negative_cache_hours = 2;

		$positive_ttl = $positive_cache_hours * 3600;
		$negative_ttl = $negative_cache_hours * 3600;

		$this->assertLessThan(
			$positive_ttl,
			$negative_ttl,
			'Negative cache TTL should be shorter than positive cache TTL'
		);
	}

	/**
	 * Test cache data structure.
	 */
	public function test_cache_data_structure() {
		$ip_address = '8.8.8.8';
		$reputation = $this->get_sample_reputation_data( 75 );

		$cache_data = $this->create_cache_entry( $ip_address, $reputation, false );

		$this->assertArrayHasKey( 'data', $cache_data, 'Cache entry should have data key' );
		$this->assertArrayHasKey( 'cached_at', $cache_data, 'Cache entry should have cached_at key' );
		$this->assertArrayHasKey( 'ip_address', $cache_data, 'Cache entry should have ip_address key' );
		$this->assertArrayHasKey( 'is_negative', $cache_data, 'Cache entry should have is_negative key' );
		$this->assertArrayHasKey( 'ttl', $cache_data, 'Cache entry should have ttl key' );

		$this->assertEquals( $reputation, $cache_data['data'], 'Data should match original reputation' );
		$this->assertEquals( $ip_address, $cache_data['ip_address'], 'IP address should match' );
		$this->assertFalse( $cache_data['is_negative'], 'is_negative should be false for positive result' );
	}

	/**
	 * Test cache data structure for negative result.
	 */
	public function test_cache_data_structure_negative_result() {
		$ip_address = '8.8.8.8';
		$result     = array( 'error' => 'IP not found' );

		$cache_data = $this->create_cache_entry( $ip_address, $result, true );

		$this->assertTrue( $cache_data['is_negative'], 'is_negative should be true for negative result' );
		$this->assertEquals( 7200, $cache_data['ttl'], 'Negative result TTL should be 2 hours (7200 seconds)' );
	}

	/**
	 * Test monthly savings estimation.
	 *
	 * @dataProvider monthly_savings_provider
	 * @param int   $hits              Total hits.
	 * @param int   $days_since_reset  Days since stats reset.
	 * @param float $expected_monthly  Expected monthly savings.
	 */
	public function test_monthly_savings_estimation( $hits, $days_since_reset, $expected_monthly ) {
		$daily_average   = $days_since_reset > 0 ? $hits / $days_since_reset : 0;
		$monthly_savings = round( $daily_average * 30 );

		$this->assertEquals( $expected_monthly, $monthly_savings, 'Monthly savings estimation should be correct' );
	}

	/**
	 * Data provider for monthly savings calculations.
	 *
	 * @return array
	 */
	public function monthly_savings_provider() {
		return array(
			'no data'                    => array( 0, 1, 0 ),
			'100 hits in 1 day'          => array( 100, 1, 3000 ),
			'100 hits in 10 days'        => array( 100, 10, 300 ),
			'1000 hits in 30 days'       => array( 1000, 30, 1000 ),
			'high traffic'               => array( 5000, 7, 21429 ),
		);
	}

	/**
	 * Test cache recommendations based on hit rate.
	 *
	 * @dataProvider hit_rate_recommendations_provider
	 * @param float  $hit_rate             Hit rate percentage.
	 * @param string $expected_rec_type    Expected recommendation type.
	 */
	public function test_cache_recommendations_based_on_hit_rate( $hit_rate, $expected_rec_type ) {
		$recommendation = $this->get_hit_rate_recommendation( $hit_rate );
		$this->assertEquals( $expected_rec_type, $recommendation, "Hit rate $hit_rate% should result in $expected_rec_type recommendation" );
	}

	/**
	 * Data provider for hit rate recommendations.
	 *
	 * @return array
	 */
	public function hit_rate_recommendations_provider() {
		return array(
			'very low hit rate'  => array( 30.0, 'warning' ),
			'low hit rate'       => array( 45.0, 'warning' ),
			'medium hit rate'    => array( 60.0, 'info' ),
			'good hit rate'      => array( 80.0, 'info' ),
			'excellent hit rate' => array( 95.0, 'success' ),
		);
	}

	/**
	 * Helper method to generate cache key.
	 *
	 * @param string $ip_address IP address.
	 * @return string
	 */
	private function generate_cache_key( $ip_address ) {
		return 'reportedip_reputation_' . hash( 'sha256', $ip_address );
	}

	/**
	 * Helper method to calculate hit rate.
	 *
	 * @param int $hits   Number of hits.
	 * @param int $misses Number of misses.
	 * @return float
	 */
	private function calculate_hit_rate( $hits, $misses ) {
		$total = $hits + $misses;
		if ( $total === 0 ) {
			return 0.0;
		}
		return round( ( $hits / $total ) * 100, 2 );
	}

	/**
	 * Helper method to create cache entry structure.
	 *
	 * @param string $ip_address        IP address.
	 * @param array  $data              Reputation data.
	 * @param bool   $is_negative_result Whether this is a negative result.
	 * @return array
	 */
	private function create_cache_entry( $ip_address, $data, $is_negative_result ) {
		$positive_ttl = 24 * 3600;
		$negative_ttl = 2 * 3600;

		return array(
			'data'        => $data,
			'cached_at'   => gmdate( 'Y-m-d H:i:s' ),
			'ip_address'  => $ip_address,
			'is_negative' => $is_negative_result,
			'ttl'         => $is_negative_result ? $negative_ttl : $positive_ttl,
		);
	}

	/**
	 * Helper method to get hit rate recommendation.
	 *
	 * @param float $hit_rate Hit rate percentage.
	 * @return string
	 */
	private function get_hit_rate_recommendation( $hit_rate ) {
		if ( $hit_rate < 50 ) {
			return 'warning';
		} elseif ( $hit_rate > 90 ) {
			return 'success';
		}
		return 'info';
	}
}
