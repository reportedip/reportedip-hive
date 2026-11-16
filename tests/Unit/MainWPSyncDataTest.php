<?php
/**
 * Unit tests for the add-on filter on the MainWP sync answer.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.1.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

require_once dirname( __DIR__, 2 ) . '/includes/class-mainwp-integration.php';

/**
 * An add-on can append values to the sync answer, a broken listener cannot
 * empty it.
 *
 * @covers \ReportedIP_Hive_MainWP_Integration::sync_data
 */
class MainWPSyncDataTest extends TestCase {

	/**
	 * Filters registered before the test.
	 *
	 * @var array
	 */
	private $filters_before = array();

	protected function set_up() {
		parent::set_up();
		$this->filters_before = $GLOBALS['wp_filters'] ?? array();
		unset( $GLOBALS['wp_filters']['reportedip_hive_mainwp_sync_data'] );
	}

	protected function tear_down() {
		$GLOBALS['wp_filters'] = $this->filters_before;
		parent::tear_down();
	}

	public function test_without_listener_returns_metrics() {
		$this->assertSame( array( 'version' => '3.1.0' ), \ReportedIP_Hive_MainWP_Integration::sync_data( array( 'version' => '3.1.0' ), 30 ) );
	}

	public function test_listener_appends_values_and_sees_days() {
		add_filter(
			'reportedip_hive_mainwp_sync_data',
			static function ( $metrics, $days ) {
				$metrics['extra'] = $days;
				return $metrics;
			},
			10,
			2
		);
		$this->assertSame(
			array(
				'version' => '3.1.0',
				'extra'   => 7,
			),
			\ReportedIP_Hive_MainWP_Integration::sync_data( array( 'version' => '3.1.0' ), 7 )
		);
	}

	public function test_non_array_result_keeps_metrics() {
		add_filter(
			'reportedip_hive_mainwp_sync_data',
			static function () {
				return false;
			}
		);
		$this->assertSame( array( 'version' => '3.1.0' ), \ReportedIP_Hive_MainWP_Integration::sync_data( array( 'version' => '3.1.0' ), 30 ) );
	}
}
