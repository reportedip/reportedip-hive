<?php
/**
 * Unit tests for the v22 migration: leftovers of the 2.x update checker.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace {
	if ( ! function_exists( 'wp_clear_scheduled_hook' ) ) {
		/**
		 * Records the hooks a test unschedules.
		 *
		 * @param string $hook Cron hook.
		 * @return int
		 */
		function wp_clear_scheduled_hook( $hook ) {
			$GLOBALS['rip_cleared_hooks'][] = (string) $hook;
			return 1;
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Exercises `ReportedIP_Hive_Migration_Manager::migrate_to_v22()`.
	 *
	 * @since 3.0.0
	 */
	class MigrationV22Test extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']        = array();
			$GLOBALS['rip_cleared_hooks'] = array();
		}

		private function run_v22(): void {
			$method = new \ReflectionMethod( \ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v22' );
			$method->invoke( null );
		}

		public function test_current_version_is_at_least_twenty_two() {
			$this->assertGreaterThanOrEqual( 22, \ReportedIP_Hive_Migration_Manager::CURRENT_VERSION );
		}

		public function test_the_update_checker_cron_and_state_are_removed() {
			update_option( 'external_updates-reportedip-hive', array( 'lastCheck' => 1 ) );
			update_option( 'reportedip_hive_api_key', 'kept' );

			$this->run_v22();

			$this->assertContains( 'puc_cron_check_updates-reportedip-hive', $GLOBALS['rip_cleared_hooks'] );
			$this->assertFalse( get_option( 'external_updates-reportedip-hive', false ) );
			$this->assertSame( 'kept', get_option( 'reportedip_hive_api_key' ), 'Only the update checker state goes.' );
		}

		public function test_a_second_run_is_harmless() {
			$this->run_v22();
			$this->run_v22();

			$this->assertFalse( get_option( 'external_updates-reportedip-hive', false ) );
		}
	}
}
