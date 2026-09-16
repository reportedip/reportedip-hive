<?php
/**
 * Unit tests for the page-cache purge.
 *
 * The case that always happens in the wild is the one where none of the seven
 * cache plugins is installed. A purge that fatals there would take down every
 * save of the switch that triggers it, so the bare run is what this pins down.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.58
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

require_once dirname( __DIR__, 2 ) . '/includes/class-cache-flush.php';

/**
 * @covers \ReportedIP_Hive_Cache_Flush
 */
class CacheFlushTest extends TestCase {

	public function test_the_purge_runs_without_a_single_cache_plugin(): void {
		$fired = 0;

		\add_action(
			'reportedip_hive_page_caches_purged',
			static function () use ( &$fired ) {
				++$fired;
			}
		);

		\ReportedIP_Hive_Cache_Flush::purge_pages();

		$this->assertSame( 1, $fired, 'The purge did not announce itself, so a site with an unknown cache cannot hook in.' );
	}

	/**
	 * Every entry has to be a function or an action this class can reach for
	 * without a fatal, which means a plain name and nothing else.
	 */
	public function test_the_purge_targets_are_plain_names(): void {
		foreach ( array_merge( \ReportedIP_Hive_Cache_Flush::PURGE_FUNCTIONS, \ReportedIP_Hive_Cache_Flush::PURGE_ACTIONS ) as $name ) {
			$this->assertMatchesRegularExpression( '/^[a-z][a-z0-9_]+$/', $name );
		}
	}
}
