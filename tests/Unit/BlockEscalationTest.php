<?php
/**
 * Unit tests for the progressive block-escalation ladder.
 *
 * Locks down the 1.5.0 behaviour change: the duration the plugin hands to
 * `block_ip()` must come from the configured ladder, indexed by the count
 * of prior `ip_blocked` events for the same IP within the reset window.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.5.0
 */

namespace {

	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}

	if ( ! function_exists( 'get_option' ) ) {
		function get_option( $key, $default = false ) {
			return $GLOBALS['wp_options'][ $key ] ?? $default;
		}
	}

	if ( ! class_exists( 'Test_WPDB_Stub' ) ) {
		/**
		 * Tiny $wpdb stub — captures the prepare-call args and returns a
		 * predetermined block-count from the global state.
		 */
		class Test_WPDB_Stub {
			public string $prefix = 'wp_';

			public function prepare( string $sql, ...$args ): string {
				$GLOBALS['rip_test_last_prepare_args'] = $args;
				return $sql;
			}

			public function get_var( $sql ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return $GLOBALS['rip_test_block_count'] ?? 0;
			}
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-block-escalation.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class BlockEscalationTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wpdb']                       = new \Test_WPDB_Stub();
			$GLOBALS['wp_options']                 = array();
			$GLOBALS['rip_test_block_count']       = 0;
			$GLOBALS['rip_test_last_prepare_args'] = array();
		}

		public function test_first_offence_returns_first_ladder_step() {
			$GLOBALS['rip_test_block_count'] = 0;
			$this->assertSame(
				5,
				\ReportedIP_Hive_Block_Escalation::next_block_minutes( '1.2.3.4' ),
				'A clean IP should hit ladder step 1 (5 minutes by default).'
			);
		}

		public function test_progression_walks_the_ladder() {
			$ladder = \ReportedIP_Hive_Block_Escalation::DEFAULT_LADDER_MINUTES;

			foreach ( $ladder as $index => $expected ) {
				$GLOBALS['rip_test_block_count'] = $index;
				$this->assertSame(
					$expected,
					\ReportedIP_Hive_Block_Escalation::next_block_minutes( '1.2.3.4' ),
					sprintf( 'After %d prior blocks the next duration must be ladder[%d] = %d min.', $index, $index, $expected )
				);
			}
		}

		public function test_excessive_offences_cap_at_last_ladder_step() {
			$ladder           = \ReportedIP_Hive_Block_Escalation::DEFAULT_LADDER_MINUTES;
			$last             = end( $ladder );
			$GLOBALS['rip_test_block_count'] = count( $ladder ) + 99;

			$this->assertSame(
				$last,
				\ReportedIP_Hive_Block_Escalation::next_block_minutes( '1.2.3.4' ),
				'Past the end of the ladder, the cap is the last entry — never longer, never wraps to step 1.'
			);
		}

		public function test_custom_ladder_option_is_respected() {
			$GLOBALS['wp_options']['reportedip_hive_block_ladder_minutes'] = '10,60,1440';
			$GLOBALS['rip_test_block_count']                                = 1;

			$this->assertSame(
				60,
				\ReportedIP_Hive_Block_Escalation::next_block_minutes( '1.2.3.4' ),
				'Custom ladder must override the default.'
			);
		}

		public function test_invalid_ladder_falls_back_to_default() {
			$GLOBALS['wp_options']['reportedip_hive_block_ladder_minutes'] = 'banana,,-5,not-a-number';
			$GLOBALS['rip_test_block_count']                                = 0;

			$this->assertSame(
				5,
				\ReportedIP_Hive_Block_Escalation::next_block_minutes( '1.2.3.4' ),
				'Garbage ladder input must fall back to the default first step.'
			);
		}

		public function test_reset_days_clamps_to_sane_range() {
			$GLOBALS['wp_options']['reportedip_hive_block_ladder_reset_days'] = 9999;
			$this->assertSame( 365, \ReportedIP_Hive_Block_Escalation::get_reset_days(), 'Reset days clamps at 365.' );

			$GLOBALS['wp_options']['reportedip_hive_block_ladder_reset_days'] = -5;
			$this->assertSame( 1, \ReportedIP_Hive_Block_Escalation::get_reset_days(), 'Reset days lower bound is 1.' );
		}

		public function test_is_enabled_defaults_on() {
			$this->assertTrue(
				\ReportedIP_Hive_Block_Escalation::is_enabled(),
				'Progressive blocking ships default-on so the bug-free flow is the default.'
			);

			$GLOBALS['wp_options']['reportedip_hive_block_escalation_enabled'] = false;
			$this->assertFalse( \ReportedIP_Hive_Block_Escalation::is_enabled() );
		}
	}
}
