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
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.2
 */

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
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
			$this->assertContains( 8, \ReportedIP_Hive_Wizard_Schema::FIELD_STEPS, 'Hide Login is a field step…' );
			$this->assertNotContains( 8, \ReportedIP_Hive_Wizard_Schema::SAVE_STEPS, '…but is saved by the wizard helper, not the schema.' );
		}

		public function test_save_step_4_persists_firewall_fields() {
			\ReportedIP_Hive_Wizard_Schema::save_step(
				4,
				array(
					'waf_enabled'             => 1,
					'bot_action'              => 'block',
					'disposable_email_action' => 'bogus-value',
				)
			);

			$this->assertSame( 1, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_waf_enabled', null ) );
			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_waf_report_only', null ), 'absent checkbox = false' );
			$this->assertSame( 'block', \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_bot_action', null ) );
			$this->assertSame( 'monitor', \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_disposable_email_action', null ), 'invalid enum falls back to the safe default' );
			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_comment_honeypot_enabled', null ), 'absent checkbox = false' );
		}

		public function test_save_step_9_takes_footer_choices_from_the_registry() {
			\ReportedIP_Hive_Wizard_Schema::save_step(
				9,
				array(
					'promote_enabled' => 1,
					'promote_variant' => 'banner',
					'promote_align'   => 'nonsense',
				)
			);

			$this->assertSame( 1, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_footer_enabled', null ) );
			$this->assertSame( 'badge', \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_footer_variant', null ), 'a variant the registry does not list falls back to the default' );
			$this->assertSame( 'center', \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_footer_align', null ), 'an alignment the registry does not list falls back to the default' );
		}

		public function test_wizard_ranges_and_choices_come_from_the_registry() {
			$spec = \ReportedIP_Hive_Settings_Registry::spec();

			foreach ( \ReportedIP_Hive_Wizard_Schema::FIELD_STEPS as $step ) {
				foreach ( \ReportedIP_Hive_Wizard_Schema::fields( $step ) as $field ) {
					$this->assertArrayNotHasKey( 'min', $field, $field['name'] );
					$this->assertArrayNotHasKey( 'max', $field, $field['name'] );
					$this->assertArrayNotHasKey( 'allowed', $field, $field['name'] );
					if ( 'enum' === $field['kind'] ) {
						$this->assertNotEmpty( $spec[ $field['option'] ]['allowed'], $field['name'] . ' needs registry choices' );
					}
				}
			}
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

		public function test_save_step_6_persists_bools_and_clamps_ints() {
			\ReportedIP_Hive_Wizard_Schema::save_step(
				6,
				array(
					'minimal_logging'     => 0,
					'data_retention_days' => 0,
					'auto_anonymize_days' => 500,
					'log_user_agents'     => 1,
				)
			);

			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_minimal_logging', null ) );
			$this->assertSame( 1, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_data_retention_days', null ), 'clamped to the registry minimum' );
			$this->assertSame( 365, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_auto_anonymize_days', null ), 'clamped to the registry maximum' );
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
			$this->assertSame( 60, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_threshold', null ) );

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
			\ReportedIP_Hive_Wizard_Schema::save_step( 8, array( 'hide_login_enabled' => 1 ) );
			\ReportedIP_Hive_Wizard_Schema::save_step( 99, array() );

			$this->assertSame( array(), $GLOBALS['wp_options'], 'steps outside SAVE_STEPS write nothing here' );
		}

		/**
		 * The wizard tells the reader that the administrator role stays
		 * unselectable until an administrator has passed one challenge, and the
		 * sanitiser drops the role regardless. Without `disabled()` on the
		 * input the wizard still offers the tick, so the setting is discarded
		 * silently after a save. The settings page has always disabled it; the
		 * two surfaces have to agree.
		 */
		public function test_wizard_disables_the_administrator_policy_tick_until_the_latch_opens() {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-setup-wizard.php' );

			foreach ( array( '2fa_policy_new_country[]', '2fa_policy_new_device[]' ) as $field ) {
				$offset = strpos( $source, $field );
				$this->assertNotFalse( $offset, "wizard no longer renders {$field}" );

				$input = substr( $source, $offset, 400 );
				$this->assertStringContainsString(
					"disabled( 'administrator' === \$rip_slug && ! \$rip_policy_latch )",
					$input,
					"the administrator tick for {$field} is offered although the latch may be closed"
				);
			}
		}
	}
}
