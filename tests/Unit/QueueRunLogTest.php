<?php
/**
 * Unit tests for the queue-run log filter.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.74
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * @covers \ReportedIP_Hive_Cron_Handler::queue_run_did_work
 */
class QueueRunLogTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		require_once dirname( __DIR__, 2 ) . '/includes/class-cron-handler.php';
	}

	public function test_an_empty_run_is_not_logged(): void {
		$this->assertFalse(
			\ReportedIP_Hive_Cron_Handler::queue_run_did_work(
				array(
					'processed' => 0,
					'errors'    => 0,
					'total'     => 0,
					'recovered' => array(
						'reset'  => 0,
						'failed' => 0,
					),
				)
			)
		);
		$this->assertFalse( \ReportedIP_Hive_Cron_Handler::queue_run_did_work( array( 'processed' => 0 ) ) );
	}

	public function test_a_run_that_did_something_is_logged(): void {
		$this->assertTrue( \ReportedIP_Hive_Cron_Handler::queue_run_did_work( array( 'processed' => 3 ) ) );
		$this->assertTrue( \ReportedIP_Hive_Cron_Handler::queue_run_did_work( array( 'errors' => 1 ) ) );
		$this->assertTrue( \ReportedIP_Hive_Cron_Handler::queue_run_did_work( array( 'recovered' => array( 'reset' => 2 ) ) ) );
		$this->assertTrue( \ReportedIP_Hive_Cron_Handler::queue_run_did_work( array( 'recovered' => array( 'failed' => 1 ) ) ) );
	}
}
