<?php
/**
 * Unit tests for the setup-wizard field schema.
 *
 * Guards the invariant that fixes the 1.x "rendered but never saved" bug:
 * every option-backed wizard field must have a default in the canonical map,
 * and the per-step save must honour bool-absent-is-false, int clamping and
 * protection-preset expansion.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.2
 */

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-wizard-schema.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class WizardSchemaTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options'] = array();
		}

		public function test_save_steps_are_a_subset_of_field_steps() {
			foreach ( \ReportedIP_Hive_Wizard_Schema::SAVE_STEPS as $step ) {
				$this->assertContains( $step, \ReportedIP_Hive_Wizard_Schema::FIELD_STEPS );
			}
			$this->assertContains( 7, \ReportedIP_Hive_Wizard_Schema::FIELD_STEPS, 'Hide Login is a field step…' );
			$this->assertNotContains( 7, \ReportedIP_Hive_Wizard_Schema::SAVE_STEPS, '…but is saved by the wizard helper, not the schema.' );
		}

		public function test_every_option_backed_field_has_a_default() {
			$defaults = array_keys( \ReportedIP_Hive_Defaults::all_option_defaults() );

			foreach ( \ReportedIP_Hive_Wizard_Schema::FIELD_STEPS as $step ) {
				foreach ( \ReportedIP_Hive_Wizard_Schema::fields( $step ) as $field ) {
					if ( empty( $field['option'] ) ) {
						continue;
					}
					$this->assertContains(
						$field['option'],
						$defaults,
						sprintf( 'Wizard field "%s" (step %d) writes %s which has no canonical default.', $field['name'], $step, $field['option'] )
					);
				}
			}
		}

		public function test_save_step_5_persists_bools_and_clamps_ints() {
			\ReportedIP_Hive_Wizard_Schema::save_step(
				5,
				array(
					'minimal_logging'     => 0,
					'data_retention_days' => 5,
					'auto_anonymize_days' => 500,
					'log_user_agents'     => 1,
				)
			);

			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_minimal_logging', null ) );
			$this->assertSame( 7, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_data_retention_days', null ), 'clamped to min' );
			$this->assertSame( 90, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_anonymize_days', null ), 'clamped to max' );
			$this->assertSame( 1, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_user_agents', null ) );
			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_referer_domains', null ), 'absent checkbox = false' );
			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_delete_data_on_uninstall', null ), 'absent checkbox = false' );
		}

		public function test_save_step_3_expands_protection_preset_and_respects_absent_toggles() {
			\ReportedIP_Hive_Wizard_Schema::save_step(
				3,
				array(
					'protection_level'       => 'high',
					'monitor_failed_logins'  => 1,
					'auto_block'             => 0,
				)
			);

			$this->assertSame( 3, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_threshold', null ) );
			$this->assertSame( 15, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_timeframe', null ) );
			$this->assertSame( 48, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_duration', null ) );
			$this->assertSame( 50, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_threshold', null ) );

			$this->assertSame( 1, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_failed_logins', null ) );
			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_block', null ) );
			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_comments', null ), 'absent toggle = false' );
		}

		public function test_unknown_protection_level_falls_back_to_medium() {
			\ReportedIP_Hive_Wizard_Schema::save_step( 3, array( 'protection_level' => 'bogus' ) );

			$this->assertSame( 5, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_threshold', null ) );
			$this->assertSame( 24, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_duration', null ) );
		}

		public function test_save_step_ignores_non_save_steps() {
			\ReportedIP_Hive_Wizard_Schema::save_step( 7, array( 'hide_login_enabled' => 1 ) );
			\ReportedIP_Hive_Wizard_Schema::save_step( 99, array() );

			$this->assertSame( array(), $GLOBALS['wp_options'], 'steps outside SAVE_STEPS write nothing here' );
		}
	}
}
