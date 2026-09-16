<?php
/**
 * Protection page: pure helpers behind the generic settings renderer.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.56
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-protection-page.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Protection_Page;

	/**
	 * @covers ReportedIP_Hive_Protection_Page
	 */
	final class ProtectionPageTest extends TestCase {

		public function test_collect_values_turns_the_post_of_one_section_into_registry_values(): void {
			$post   = array(
				'rip_section'                          => 'blocking',
				'reportedip_hive_block_duration'       => '48',
				'reportedip_hive_block_tor'            => '1',
				'reportedip_hive_block_ladder_minutes' => '5, 15, 30',
			);
			$values = ReportedIP_Hive_Protection_Page::collect_values( $post, 'blocking' );

			$this->assertSame( '48', $values['reportedip_hive_block_duration'] );
			$this->assertSame( '1', $values['reportedip_hive_block_tor'] );
			$this->assertSame( '0', $values['reportedip_hive_auto_block'], 'an unticked switch of the section is posted as 0' );
			$this->assertSame( '0', $values['reportedip_hive_report_only_mode'] );
			$this->assertArrayNotHasKey( 'reportedip_hive_waf_enabled', $values, 'keys of other sections are never touched' );
			$this->assertArrayNotHasKey( 'rip_section', $values );
		}

		public function test_collect_values_posts_an_empty_list_for_an_unticked_checkbox_group(): void {
			$values = ReportedIP_Hive_Protection_Page::collect_values( array( 'rip_section' => 'account_security' ), 'account_security' );
			$this->assertSame( array(), $values['reportedip_hive_2fa_enforce_roles'] );
			$this->assertSame( '0', $values['reportedip_hive_2fa_enabled_global'] );
		}

		public function test_collect_values_expands_the_preset_into_the_four_threshold_keys(): void {
			$values = ReportedIP_Hive_Protection_Page::collect_values(
				array(
					'rip_section'          => 'detection',
					'rip_protection_level' => 'high',
				),
				'detection'
			);
			$this->assertSame( 3, $values['reportedip_hive_failed_login_threshold'] );
			$this->assertSame( 15, $values['reportedip_hive_failed_login_timeframe'] );
			$this->assertSame( 48, $values['reportedip_hive_block_duration'] );
			$this->assertSame( 60, $values['reportedip_hive_block_threshold'] );
		}

		public function test_collect_values_ignores_an_unknown_preset_and_a_custom_marker(): void {
			$values = ReportedIP_Hive_Protection_Page::collect_values(
				array(
					'rip_section'                            => 'detection',
					'rip_protection_level'                   => 'custom',
					'reportedip_hive_failed_login_threshold' => '9',
				),
				'detection'
			);
			$this->assertSame( '9', $values['reportedip_hive_failed_login_threshold'] );
			$this->assertArrayNotHasKey( 'reportedip_hive_block_threshold', $values );
		}

		public function test_current_preset_names_the_matching_level_or_custom(): void {
			$this->assertSame(
				'medium',
				ReportedIP_Hive_Protection_Page::current_preset(
					array(
						'reportedip_hive_failed_login_threshold' => 5,
						'reportedip_hive_failed_login_timeframe' => 15,
						'reportedip_hive_block_duration'         => 24,
						'reportedip_hive_block_threshold'        => 75,
					)
				)
			);
			$this->assertSame(
				'custom',
				ReportedIP_Hive_Protection_Page::current_preset(
					array(
						'reportedip_hive_failed_login_threshold' => 5,
						'reportedip_hive_failed_login_timeframe' => 15,
						'reportedip_hive_block_duration'         => 24,
						'reportedip_hive_block_threshold'        => 50,
					)
				)
			);
		}

		public function test_visible_keys_in_simple_mode_are_the_simple_keys_of_the_section(): void {
			$keys = ReportedIP_Hive_Protection_Page::visible_keys( 'blocking', false, array() );
			$this->assertSame( array( 'reportedip_hive_auto_block', 'reportedip_hive_report_only_mode' ), $keys );

			$all = ReportedIP_Hive_Protection_Page::visible_keys( 'blocking', true, array() );
			$this->assertContains( 'reportedip_hive_block_ladder_minutes', $all );
			$this->assertContains( 'reportedip_hive_auto_block', $all );
		}

		public function test_sections_without_a_simple_key_are_reported(): void {
			$this->assertTrue( ReportedIP_Hive_Protection_Page::section_is_expert_only( 'headers', array() ) );
			$this->assertFalse( ReportedIP_Hive_Protection_Page::section_is_expert_only( 'blocking', array() ) );
			$this->assertFalse( ReportedIP_Hive_Protection_Page::section_is_expert_only( 'forms', array() ), 'form protection carries its own day-to-day switches' );
		}

		/**
		 * The one visibility rule, in every case it has to answer.
		 */
		public function test_is_visible_covers_static_conditional_and_expert(): void {
			$plain      = array( 'kind' => 'bool' );
			$simple     = array(
				'kind'   => 'bool',
				'simple' => true,
			);
			$formidable = array(
				'kind'        => 'bool',
				'simple_form' => 'formidable',
			);

			$this->assertTrue( ReportedIP_Hive_Protection_Page::is_visible( $simple, false, array() ) );
			$this->assertFalse( ReportedIP_Hive_Protection_Page::is_visible( $plain, false, array() ) );
			$this->assertTrue( ReportedIP_Hive_Protection_Page::is_visible( $plain, true, array() ), 'the expert view holds nothing back' );

			$this->assertFalse(
				ReportedIP_Hive_Protection_Page::is_visible( $formidable, false, array( 'cf7' ) ),
				'a switch for a plugin this site does not run stays out of the simple view'
			);
			$this->assertTrue(
				ReportedIP_Hive_Protection_Page::is_visible( $formidable, false, array( 'cf7', 'formidable' ) ),
				'the plugin is here, so its switch is a day-to-day setting'
			);
			$this->assertTrue( ReportedIP_Hive_Protection_Page::is_visible( $formidable, true, array() ) );
		}

		public function test_an_adapter_switch_joins_the_simple_view_with_its_plugin(): void {
			$without = ReportedIP_Hive_Protection_Page::visible_keys( 'forms', false, array() );
			$this->assertContains( 'reportedip_hive_form_proof_enabled', $without );
			$this->assertNotContains( 'reportedip_hive_form_proof_formidable', $without );
			$this->assertContains( 'reportedip_hive_form_proof_formidable', ReportedIP_Hive_Protection_Page::expert_only_keys( 'forms', false, array() ) );

			$with = ReportedIP_Hive_Protection_Page::visible_keys( 'forms', false, array( 'formidable' ) );
			$this->assertContains( 'reportedip_hive_form_proof_formidable', $with );
			$this->assertNotContains( 'reportedip_hive_form_proof_cf7', $with );
			$this->assertNotContains( 'reportedip_hive_form_proof_formidable', ReportedIP_Hive_Protection_Page::expert_only_keys( 'forms', false, array( 'formidable' ) ) );
		}

		/**
		 * The guard against silent data loss: the simple view draws a stand-in
		 * for every expert setting so the search finds it, and that stand-in
		 * must never carry anything a browser would post back. A control here
		 * would reach `collect_values()` empty on the next save of the section
		 * and overwrite the stored setting without a word.
		 */
		public function test_the_simple_view_never_renders_a_control_for_an_expert_setting(): void {
			$spec    = \ReportedIP_Hive_Settings_Registry::spec();
			$checked = 0;

			foreach ( array_keys( \ReportedIP_Hive_Settings_Registry::sections() ) as $section ) {
				$visible = ReportedIP_Hive_Protection_Page::visible_keys( $section, false, array() );
				$held    = ReportedIP_Hive_Protection_Page::expert_only_keys( $section, false, array() );
				$this->assertSame(
					ReportedIP_Hive_Protection_Page::visible_keys( $section, true, array() ),
					array_values( array_intersect( array_keys( $spec ), array_merge( $visible, $held ) ) ),
					"Section {$section} loses a key between the two views."
				);

				foreach ( $held as $key ) {
					$html = ReportedIP_Hive_Protection_Page::hint_markup( $key, $spec[ $key ], 'https://example.org/jump' );
					$this->assertStringNotContainsString( 'name=', $html, "{$key} would be posted back from the simple view." );
					$this->assertStringNotContainsString( '<input', $html, "{$key} renders an input in the simple view." );
					$this->assertStringNotContainsString( '<select', $html, "{$key} renders a select in the simple view." );
					$this->assertStringNotContainsString( '<textarea', $html, "{$key} renders a textarea in the simple view." );
					$this->assertStringContainsString(
						'data-search="' . htmlspecialchars( ReportedIP_Hive_Protection_Page::search_terms( $key, $spec[ $key ] ), ENT_QUOTES ) . '"',
						$html,
						"{$key} is not searchable in the simple view."
					);
					++$checked;
				}
			}

			$this->assertGreaterThan( 50, $checked, 'the simple view holds back far more than fifty settings' );
			$this->assertSame( array(), ReportedIP_Hive_Protection_Page::expert_only_keys( 'blocking', true, array() ), 'the expert view holds nothing back' );
		}

		public function test_expert_summary_names_a_few_settings_and_counts_the_rest(): void {
			$this->assertSame( '', ReportedIP_Hive_Protection_Page::expert_summary( array() ) );
			$this->assertSame(
				'Expert mode adds Tor blocking, HSTS here.',
				ReportedIP_Hive_Protection_Page::expert_summary( array( 'Tor blocking', 'HSTS' ) )
			);
			$this->assertSame(
				'Expert mode adds A, B, C and 2 more settings here.',
				ReportedIP_Hive_Protection_Page::expert_summary( array( 'A', 'B', 'C', 'D', 'E' ) )
			);
			$this->assertSame(
				'Expert mode adds A, B, C and 1 more setting here.',
				ReportedIP_Hive_Protection_Page::expert_summary( array( 'A', 'B', 'C', 'D' ) )
			);
		}

		public function test_field_markup_carries_the_registry_name_and_the_lock(): void {
			$html = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_block_tor',
				array(
					'kind'        => 'bool',
					'label'       => 'Block Tor',
					'description' => 'Refuse Tor.',
				),
				'0',
				array(
					'available' => false,
					'min_tier'  => 'professional',
					'reason'    => 'tier',
					'label'     => 'Tor',
				)
			);
			$this->assertStringContainsString( 'name="reportedip_hive_block_tor"', $html );
			$this->assertStringContainsString( 'disabled', $html );
			$this->assertStringContainsString( 'data-search="', $html );
			$this->assertStringContainsString( 'rip-protection__field--locked', $html );

			$open = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_block_duration',
				array(
					'kind'        => 'int',
					'min'         => 0,
					'max'         => 8760,
					'label'       => 'Duration',
					'description' => '',
				),
				'24',
				array( 'available' => true )
			);
			$this->assertStringContainsString( 'type="number"', $open );
			$this->assertStringContainsString( 'min="0"', $open );
			$this->assertStringContainsString( 'max="8760"', $open );
			$this->assertStringContainsString( 'value="24"', $open );
			$this->assertStringNotContainsString( 'disabled', $open );

			$enum = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_bot_action',
				array(
					'kind'        => 'enum',
					'allowed'     => array( 'flag', 'off', 'block' ),
					'label'       => 'Bots',
					'description' => '',
				),
				'block',
				array( 'available' => true )
			);
			$this->assertStringContainsString( '<option value="block" selected', $enum );

			$list = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_2fa_enforce_roles',
				array(
					'kind'        => 'json_list',
					'choices'     => 'roles',
					'label'       => 'Roles',
					'description' => '',
				),
				array( 'editor' ),
				array( 'available' => true ),
				array(
					'administrator' => 'Administrator',
					'editor'        => 'Editor',
				)
			);
			$this->assertStringContainsString( 'name="reportedip_hive_2fa_enforce_roles[]"', $list );
			$this->assertStringContainsString( 'value="editor" checked', $list );
			$this->assertStringContainsString( 'value="administrator" ', $list );

			$stored = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_2fa_enforce_roles',
				array(
					'kind'        => 'json_list',
					'choices'     => 'roles',
					'label'       => 'Roles',
					'description' => '',
				),
				'["administrator"]',
				array( 'available' => true ),
				array(
					'administrator' => 'Administrator',
					'editor'        => 'Editor',
				)
			);
			$this->assertStringContainsString( 'value="administrator" checked', $stored );
			$this->assertStringNotContainsString( 'value="editor" checked', $stored );
		}

		public function test_every_registry_kind_renders_an_input_with_its_name(): void {
			foreach ( \ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
				$html = ReportedIP_Hive_Protection_Page::field_markup(
					$key,
					$entry,
					'json_list' === $entry['kind'] ? array() : '',
					array( 'available' => true ),
					'json_list' === $entry['kind'] ? array( 'x' => 'X' ) : array()
				);
				$this->assertStringContainsString( 'name="' . $key, $html, $key );
			}
		}

		/**
		 * Mode manager stand-in: every plan feature is unavailable.
		 */
		private function locked_manager(): object {
			return new class() {
				/**
				 * @param string $feature Feature key.
				 * @return array<string,mixed>
				 */
				public function feature_status( $feature ) {
					return array(
						'available' => false,
						'reason'    => 'tier',
						'min_tier'  => 'professional',
						'label'     => $feature,
					);
				}
			};
		}

		public function test_a_plan_gated_field_is_locked_unless_flagged_partial_or_switched_on(): void {
			$manager = $this->locked_manager();

			$tor_off = ReportedIP_Hive_Protection_Page::field_status( array( 'kind' => 'bool', 'tier' => 'tor_blocking' ), 'reportedip_hive_block_tor', '0', $manager );
			$this->assertFalse( $tor_off['available'] );
			$this->assertArrayNotHasKey( 'partial', $tor_off, 'a switch that is off stays locked' );

			$tor_on = ReportedIP_Hive_Protection_Page::field_status( array( 'kind' => 'bool', 'tier' => 'tor_blocking' ), 'reportedip_hive_block_tor', '1', $manager );
			$this->assertTrue( $tor_on['partial'], 'a switch that is on can still be switched off' );

			$gate  = static function ( $value ) {
				return count( array_filter( explode( "\n", (string) $value ) ) ) > 10;
			};
			$short = ReportedIP_Hive_Protection_Page::field_status(
				array( 'kind' => 'textarea', 'tier' => 'x', 'tier_gate' => $gate, 'partial' => true ),
				'k',
				"a\nb",
				$manager
			);
			$this->assertTrue( $short['partial'], 'a partial list inside the free range stays editable' );

			$long = ReportedIP_Hive_Protection_Page::field_status(
				array( 'kind' => 'textarea', 'tier' => 'x', 'tier_gate' => $gate, 'partial' => true ),
				'k',
				implode( "\n", range( 1, 11 ) ),
				$manager
			);
			$this->assertArrayNotHasKey( 'partial', $long, 'a list already over the line is locked' );

			$policy = ReportedIP_Hive_Protection_Page::field_status(
				array( 'kind' => 'json_list', 'tier' => '2fa_policies', 'tier_gate' => static function () { return false; } ),
				'reportedip_hive_2fa_policy_new_ip',
				array(),
				$manager
			);
			$this->assertArrayNotHasKey( 'partial', $policy, 'a gate without the partial flag locks the field' );

			$free = ReportedIP_Hive_Protection_Page::field_status( array( 'kind' => 'int' ), 'reportedip_hive_block_duration', '24', $manager );
			$this->assertTrue( $free['available'] );
		}

		public function test_the_plan_marker_names_the_plan_in_both_directions(): void {
			$this->assertSame(
				'',
				ReportedIP_Hive_Protection_Page::tier_marker_state( array( 'kind' => 'int' ), array( 'available' => true ) ),
				'a field without a plan entry carries no marker'
			);

			$this->assertSame(
				'included',
				ReportedIP_Hive_Protection_Page::tier_marker_state(
					array( 'kind' => 'bool', 'tier' => 'tor_blocking' ),
					array( 'available' => true, 'min_tier' => 'professional' )
				),
				'a plan feature the customer has says which plan it belongs to'
			);

			$this->assertSame(
				'locked',
				ReportedIP_Hive_Protection_Page::tier_marker_state(
					array( 'kind' => 'bool', 'tier' => 'tor_blocking' ),
					array( 'available' => false, 'reason' => 'tier', 'min_tier' => 'professional' )
				)
			);

			$this->assertSame(
				'locked',
				ReportedIP_Hive_Protection_Page::tier_marker_state(
					array( 'kind' => 'textarea', 'tier' => 'x', 'partial' => true ),
					array( 'available' => false, 'reason' => 'tier', 'min_tier' => 'professional', 'partial' => true )
				),
				'a partial field is editable but still names the plan its higher range needs'
			);

			$this->assertSame(
				'included',
				ReportedIP_Hive_Protection_Page::tier_marker_state(
					array( 'kind' => 'bool', 'ui_lock' => 'frontend_2fa' ),
					array( 'available' => true, 'min_tier' => 'professional' )
				)
			);
			$this->assertSame(
				'locked',
				ReportedIP_Hive_Protection_Page::tier_marker_state(
					array( 'kind' => 'bool', 'ui_lock' => 'frontend_2fa' ),
					array( 'available' => false, 'reason' => 'tier', 'min_tier' => 'professional' )
				)
			);

			$this->assertSame(
				'',
				ReportedIP_Hive_Protection_Page::tier_marker_state(
					array( 'kind' => 'bool', 'tier' => 'form_adapters' ),
					array( 'available' => false, 'reason' => 'runtime', 'note' => 'Contact Form 7 is not active on this site.' )
				),
				'a lock that comes from the server, not from the plan, carries a note instead'
			);
		}

		public function test_writable_values_drops_hidden_and_locked_keys_and_forces_forced_switches(): void {
			$values   = array(
				'reportedip_hive_auto_block'             => '1',
				'reportedip_hive_block_tor'              => '0',
				'reportedip_hive_block_duration'         => '48',
				'reportedip_hive_block_ladder_minutes'   => '',
				'reportedip_hive_block_admin_guests'     => '0',
				'reportedip_hive_failed_login_threshold' => 3,
			);
			$visible  = array( 'reportedip_hive_auto_block', 'reportedip_hive_block_tor', 'reportedip_hive_block_duration', 'reportedip_hive_block_admin_guests' );
			$statuses = array(
				'reportedip_hive_block_tor'          => array( 'available' => false ),
				'reportedip_hive_block_duration'     => array(
					'available' => false,
					'partial'   => true,
				),
				'reportedip_hive_block_admin_guests' => array(
					'available' => false,
					'forced'    => true,
				),
			);
			$this->assertSame(
				array(
					'reportedip_hive_auto_block'             => '1',
					'reportedip_hive_block_duration'         => '48',
					'reportedip_hive_block_admin_guests'     => '1',
					'reportedip_hive_failed_login_threshold' => 3,
				),
				ReportedIP_Hive_Protection_Page::writable_values( $values, $visible, $statuses )
			);
		}

		public function test_fixed_choices_stay_checked_disabled_and_in_the_post(): void {
			$html = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_rest_allowed_roles',
				array(
					'kind'        => 'json_list',
					'choices'     => 'roles',
					'label'       => 'Roles',
					'description' => '',
				),
				array(),
				array( 'available' => true ),
				array(
					'administrator' => array(
						'label'    => 'Administrator',
						'disabled' => true,
						'fixed'    => true,
					),
					'editor'        => array(
						'label'    => 'Editor',
						'disabled' => false,
						'fixed'    => false,
					),
				)
			);
			$this->assertStringContainsString( 'value="administrator" checked disabled', $html );
			$this->assertStringContainsString( '<input type="hidden" name="reportedip_hive_rest_allowed_roles[]" value="administrator" />', $html );
			$this->assertStringContainsString( 'value="editor" ', $html );
			$this->assertStringNotContainsString( 'value="editor" checked', $html );
		}

		public function test_section_state_tints_on_green_off_red_and_everything_else_neutral(): void {
			$this->assertSame(
				array(
					'text' => 'on',
					'tone' => 'success',
				),
				ReportedIP_Hive_Protection_Page::section_state( 'waf', array( 'reportedip_hive_waf_enabled' => 1 ) )
			);
			$this->assertSame(
				array(
					'text' => 'off',
					'tone' => 'danger',
				),
				ReportedIP_Hive_Protection_Page::section_state( 'waf', array( 'reportedip_hive_waf_enabled' => 0 ) )
			);
			$this->assertSame(
				'neutral',
				ReportedIP_Hive_Protection_Page::section_state( 'lockdown', array( 'reportedip_hive_rest_access_mode' => 'open' ) )['tone'],
				'a status that says neither on nor off carries no verdict'
			);
		}

		public function test_section_status_still_returns_the_plain_text(): void {
			$this->assertSame( 'on', ReportedIP_Hive_Protection_Page::section_status( 'waf', array( 'reportedip_hive_waf_enabled' => 1 ) ) );
		}

		public function test_the_section_head_carries_the_chevron_and_the_tinted_status(): void {
			$html = ReportedIP_Hive_Protection_Page::summary_markup(
				array(
					'label'       => 'Firewall',
					'description' => 'Request inspection.',
				),
				array(
					'text' => 'off',
					'tone' => 'danger',
				)
			);
			$this->assertStringContainsString( 'class="rip-protection__chevron"', $html );
			$this->assertStringContainsString( '<polyline points="6 9 12 15 18 9"/>', $html );
			$this->assertStringContainsString( 'rip-badge--danger', $html );

			$css = (string) file_get_contents( dirname( __DIR__, 2 ) . '/assets/css/design-system.css' );
			$this->assertMatchesRegularExpression( '/\.rip-protection__section > summary \{[^}]*list-style: none;/s', $css, 'the native marker is off' );
			$this->assertStringContainsString( '.rip-protection__section > summary::-webkit-details-marker', $css );
			$this->assertStringContainsString( '.rip-protection__section[open] > summary .rip-protection__chevron', $css, 'the chevron turns while the card is open' );
		}

		public function test_a_runtime_note_is_rendered_without_a_plan_marker(): void {
			$html = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_monitor_woocommerce',
				array(
					'kind'        => 'bool',
					'label'       => 'WooCommerce',
					'description' => 'Watch the shop.',
				),
				'0',
				array(
					'available' => false,
					'reason'    => 'runtime',
					'note'      => 'WooCommerce is not installed on this site.',
				)
			);
			$this->assertStringContainsString( 'disabled', $html );
			$this->assertStringContainsString( 'WooCommerce is not installed on this site.', $html );
			$this->assertStringNotContainsString( 'rip-tier', $html );
		}
	}
}
