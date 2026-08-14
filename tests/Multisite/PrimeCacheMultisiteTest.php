<?php
/**
 * Multisite regression test: prime_cache() must not poison the network
 * option cache with raw serialized values.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @since      2.1.41
 */

namespace ReportedIP\Hive\Tests\Multisite;

use WP_UnitTestCase;

/**
 * Core's get_network_option() unserializes BEFORE caching and trusts a
 * cache hit verbatim. The bulk prime therefore has to store unserialized
 * values — a raw serialized string turns every array-valued network option
 * into a PHP-serialization string until the cache expires (observed as a
 * fatal TypeError in the cache-stats counters on shutdown).
 *
 * @since 2.1.41
 */
class ReportedIP_Hive_Prime_Cache_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Skip the whole class on single-site runs.
	 *
	 * @return void
	 */
	public function set_up(): void {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite-only test.' );
		}
	}

	/**
	 * An array-valued network option must survive the bulk cache prime.
	 *
	 * @return void
	 */
	public function test_primed_array_option_stays_an_array() {
		$value = array(
			'hits'   => 7,
			'misses' => 3,
		);
		update_site_option( 'reportedip_hive_cache_stats', $value );

		wp_cache_flush();
		\ReportedIP_Hive_Option_Routing::flush_resolve_cache();
		\ReportedIP_Hive_Option_Routing::prime_cache();

		$primed = get_site_option( 'reportedip_hive_cache_stats' );
		$this->assertIsArray( $primed, 'Primed network option must come back unserialized.' );
		$this->assertSame( $value, $primed );

		delete_site_option( 'reportedip_hive_cache_stats' );
	}

	/**
	 * Scalar network options keep working through the primed cache.
	 *
	 * @return void
	 */
	public function test_primed_scalar_option_round_trips() {
		update_site_option( 'reportedip_hive_block_threshold', 82 );

		wp_cache_flush();
		\ReportedIP_Hive_Option_Routing::flush_resolve_cache();
		\ReportedIP_Hive_Option_Routing::prime_cache();

		$this->assertEquals( 82, get_site_option( 'reportedip_hive_block_threshold' ) );

		delete_site_option( 'reportedip_hive_block_threshold' );
	}
}
