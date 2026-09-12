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
	require_once dirname( __DIR__, 2 ) . '/includes/class-hide-login.php';

	if ( ! defined( 'OBJECT' ) ) {
		define( 'OBJECT', 'OBJECT' );
	}
	if ( ! function_exists( 'get_page_by_path' ) ) {
		function get_page_by_path( $page_path, $output = OBJECT, $post_type = 'page' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return null;
		}
	}
	if ( ! function_exists( 'get_term_by' ) ) {
		function get_term_by( $field, $value, $taxonomy = '', $output = OBJECT ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return false;
		}
	}
	if ( ! function_exists( 'get_taxonomies' ) ) {
		function get_taxonomies( $args = array(), $output = 'names' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return array();
		}
	}
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
			$this->assertSame( \ReportedIP_Hive_Wizard_Schema::FIELD_STEPS, \ReportedIP_Hive_Wizard_Schema::SAVE_STEPS, 'every field step is saved by the schema, Hide Login included' );
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
			\ReportedIP_Hive_Wizard_Schema::save_step( 2, array( 'mode' => 'community' ) );
			\ReportedIP_Hive_Wizard_Schema::save_step( 99, array() );

			$this->assertSame( array(), $GLOBALS['wp_options'], 'steps outside SAVE_STEPS write nothing here' );
		}

		public function test_save_step_8_enables_hide_login_with_a_valid_slug() {
			\ReportedIP_Hive_Wizard_Schema::save_step(
				8,
				array(
					'hide_login_enabled'       => 1,
					'hide_login_slug'          => 'My Secret Door',
					'hide_login_response_mode' => '404',
				)
			);

			$this->assertSame( 1, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_enabled', null ) );
			$this->assertSame( 'my-secret-door', \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_slug', null ), 'the registry sanitizer canonicalises the slug' );
			$this->assertSame( '404', \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_response_mode', null ) );
		}

		/**
		 * @dataProvider unusable_slugs
		 * @param string $slug Posted slug.
		 */
		public function test_save_step_8_never_enables_hide_login_on_an_unusable_slug( $slug ) {
			$GLOBALS['wp_options']['reportedip_hive_hide_login_slug'] = 'old-door';

			\ReportedIP_Hive_Wizard_Schema::save_step(
				8,
				array(
					'hide_login_enabled' => 1,
					'hide_login_slug'    => $slug,
				)
			);

			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_enabled', null ), 'a refused slug leaves the feature off' );
			$this->assertSame( 'old-door', \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_slug', null ), 'a refused slug never overwrites the stored one' );
		}

		/**
		 * @return array<string, array<int, string>>
		 */
		public function unusable_slugs() {
			return array(
				'too short' => array( 'ab' ),
				'reserved'  => array( 'wp-admin' ),
			);
		}

		public function test_save_step_8_with_the_switch_off_keeps_the_slug_and_disables() {
			$GLOBALS['wp_options']['reportedip_hive_hide_login_enabled'] = 1;

			\ReportedIP_Hive_Wizard_Schema::save_step(
				8,
				array(
					'hide_login_slug'          => 'kept-door',
					'hide_login_response_mode' => 'block_page',
				)
			);

			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_enabled', null ) );
			$this->assertSame( 'kept-door', \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_slug', null ), 'the slug survives so the wizard can prefill it next time' );
		}

		/**
		 * Settings-API sanitizers run on every option write, and the one on the
		 * hide-login switch refuses "on" while no slug is stored. Writing the
		 * switch first therefore never enables the feature; the unit stubs
		 * cannot see that filter, so the order is pinned here.
		 */
		public function test_step_8_writes_the_slug_before_the_switch() {
			$order = array_column( \ReportedIP_Hive_Wizard_Schema::fields( 8 ), 'name' );

			$this->assertLessThan( array_search( 'hide_login_enabled', $order, true ), array_search( 'hide_login_slug', $order, true ) );
		}

		public function test_protection_presets_respect_the_reputation_floor() {
			foreach ( \ReportedIP_Hive_Wizard_Schema::protection_presets() as $level => $preset ) {
				$this->assertGreaterThanOrEqual( \ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD, $preset['block_threshold'], $level );
				foreach ( $preset as $suffix => $value ) {
					$clean = \ReportedIP_Hive_Settings_Registry::sanitize( 'reportedip_hive_' . $suffix, $value );
					$this->assertSame( $value, $clean, "preset {$level}: {$suffix} must survive its registry sanitizer unchanged" );
				}
			}
		}

		/**
		 * The wizard markup carries no ranges or choices of its own: number
		 * inputs read min/max from the registry, and every select option is one
		 * the registry allows. This is what keeps the wizard from drifting away
		 * from the settings page again.
		 */
		public function test_wizard_markup_takes_ranges_and_choices_from_the_registry() {
			$markup = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-setup-wizard.php' );

			$this->assertDoesNotMatchRegularExpression( '/\b(min|max)="\d+"/', $markup, 'hard-coded number ranges in the wizard markup' );

			$spec = \ReportedIP_Hive_Settings_Registry::spec();
			foreach ( \ReportedIP_Hive_Wizard_Schema::FIELD_STEPS as $step ) {
				foreach ( \ReportedIP_Hive_Wizard_Schema::fields( $step ) as $field ) {
					if ( 'enum' !== $field['kind'] || ! preg_match( '/<select[^>]*name="' . preg_quote( $field['name'], '/' ) . '"(.*?)<\/select>/s', $markup, $select ) ) {
						continue;
					}
					preg_match_all( '/<option value="([^"]*)"/', $select[1], $options );
					$this->assertNotEmpty( $options[1], $field['name'] );
					$this->assertSame(
						array(),
						array_values( array_diff( $options[1], $spec[ $field['option'] ]['allowed'] ) ),
						$field['name'] . ' offers a choice the registry does not allow'
					);
				}
			}
		}

		public function test_wizard_selects_for_integer_options_stay_inside_the_registry_range() {
			$markup = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-setup-wizard.php' );

			foreach ( array( 'data_retention_days', 'auto_anonymize_days' ) as $name ) {
				$this->assertTrue( (bool) preg_match( '/<select[^>]*name="' . $name . '"(.*?)<\/select>/s', $markup, $select ), $name );
				preg_match_all( '/<option value="(\d+)"/', $select[1], $options );
				$limits = \ReportedIP_Hive_Wizard_Schema::limits( 'reportedip_hive_' . $name );
				foreach ( $options[1] as $value ) {
					$this->assertGreaterThanOrEqual( $limits['min'], (int) $value, $name );
					$this->assertLessThanOrEqual( $limits['max'], (int) $value, $name );
				}
			}
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
