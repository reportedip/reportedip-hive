<?php
/**
 * Unit tests for the v16 threshold-floor normalisation migration.
 *
 * Locks down `migrate_to_v16()`: stored reputation-block thresholds below
 * `ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD` are lifted onto the floor
 * (both the community threshold and the hardening variant), values at or
 * above the floor stay untouched, and `CURRENT_VERSION` is at 16 so the
 * migration actually runs on upgrade.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.50
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Exercises `ReportedIP_Hive_Migration_Manager::migrate_to_v16()`.
 *
 * @since 2.1.50
 */
class MigrationV16Test extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options'] = array();
	}

	private function run_v16(): void {
		$method = new \ReflectionMethod( \ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v16' );
		$method->invoke( null );
	}

	public function test_current_version_is_sixteen() {
		$this->assertSame( 16, \ReportedIP_Hive_Migration_Manager::CURRENT_VERSION );
	}

	public function test_sub_floor_thresholds_are_lifted_onto_the_floor() {
		\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_block_threshold', 10 );
		\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_hardening_block_threshold', 15 );

		$this->run_v16();

		$floor = \ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD;
		$this->assertSame( $floor, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_threshold', null ) );
		$this->assertSame( $floor, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_block_threshold', null ) );
	}

	public function test_compliant_thresholds_stay_untouched() {
		\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_block_threshold', 75 );
		\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_hardening_block_threshold', 60 );

		$this->run_v16();

		$this->assertSame( 75, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_threshold', null ) );
		$this->assertSame( 60, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_block_threshold', null ) );
	}

	public function test_absent_options_are_not_seeded() {
		$this->run_v16();

		$this->assertNull( \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_threshold', null ) );
		$this->assertNull( \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hardening_block_threshold', null ) );
	}
}
