<?php
/**
 * Unit tests for the hook the hourly scan fires with coordinated attacks.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.5
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * @covers \ReportedIP_Hive_Cron_Handler::cron_sync_reputation
 */
class CoordinatedAttacksHookTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		require_once dirname( __DIR__, 2 ) . '/includes/class-cron-handler.php';
		unset( $GLOBALS['wp_actions']['reportedip_hive_coordinated_attacks_found'] );
	}

	protected function tear_down() {
		unset( $GLOBALS['wp_actions']['reportedip_hive_coordinated_attacks_found'] );
		parent::tear_down();
	}

	public function test_a_single_row_reaches_listeners_as_a_list(): void {
		$row      = (object) array( 'unique_ips' => 12, 'total_attempts' => 60, 'time_window' => '2026-10-27 22:05' );
		$received = null;
		add_action(
			'reportedip_hive_coordinated_attacks_found',
			static function ( $attacks ) use ( &$received ) {
				$received = $attacks;
			}
		);

		$monitor = new class( $row ) {
			private $row;
			public function __construct( $row ) {
				$this->row = $row;
			}
			public function check_coordinated_attacks() {
				return array( $this->row );
			}
		};
		$logger = new class() {
			public $critical = array();
			public function critical( $message ) {
				$this->critical[] = $message;
			}
		};

		$handler = ( new \ReflectionClass( \ReportedIP_Hive_Cron_Handler::class ) )->newInstanceWithoutConstructor();
		( new \ReflectionProperty( \ReportedIP_Hive_Cron_Handler::class, 'security_monitor' ) )->setValue( $handler, $monitor );
		( new \ReflectionProperty( \ReportedIP_Hive_Cron_Handler::class, 'logger' ) )->setValue( $handler, $logger );

		$handler->cron_sync_reputation();

		$this->assertSame( array( $row ), $received, 'do_action() would unwrap the one-row list into the bare object' );
		$this->assertSame( array(), $logger->critical );
	}
}
