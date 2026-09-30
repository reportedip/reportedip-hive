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
	require_once dirname( __DIR__, 2 ) . '/includes/class-form-adapters.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-login-context.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php';
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

		public function test_field_markup_carries_the_registry_name_and_the_lock(): void {
			$html = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_block_tor',
				array(
					'kind'        => 'bool',
					'tier'        => 'tor_blocking',
					'label'       => 'Block Tor',
					'description' => 'Refuse Tor.',
				),
				'0',
				array(
					'available'  => false,
					'min_tier'   => 'professional',
					'reason'     => 'tier',
					'label'      => 'Tor',
					'plan_label' => 'Professional',
					'plan_url'   => 'https://reportedip.com/pricing/#tor_blocking',
				)
			);
			$this->assertStringNotContainsString( 'name="reportedip_hive_block_tor"', $html, 'a plan-locked switch posts nothing' );
			$this->assertStringNotContainsString( '<input', $html );
			$this->assertStringContainsString( 'data-search="', $html );
			$this->assertStringContainsString( 'rip-protection__field--locked', $html );
			$this->assertStringContainsString( 'rip-protection__plan', $html );
			$this->assertStringContainsString( 'href="https://reportedip.com/pricing/#tor_blocking"', $html );
			$this->assertStringContainsString( 'Learn more', $html );
			$this->assertStringNotContainsString( 'rip-protection__state', $html, 'no on/off text without a switch' );

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

		public function test_tabs_cover_every_registry_section_exactly_once(): void {
			$seen = array();
			foreach ( ReportedIP_Hive_Protection_Page::tabs() as $slug => $tab ) {
				$this->assertMatchesRegularExpression( '/^[a-z]+$/', $slug );
				$this->assertNotSame( '', (string) $tab['label'] );
				$this->assertNotSame( '', (string) $tab['advice'] );
				$this->assertNotSame( '', ReportedIP_Hive_Protection_Page::tab_icon( $tab['icon'] ), "tab {$slug} has no icon" );
				foreach ( $tab['sections'] as $section ) {
					$this->assertArrayNotHasKey( $section, $seen, "section {$section} sits in two tabs" );
					$seen[ $section ] = $slug;
				}
			}
			$this->assertEqualsCanonicalizing(
				array_keys( \ReportedIP_Hive_Settings_Registry::sections() ),
				array_keys( $seen ),
				'the tabs hold exactly the registry sections'
			);
		}

		public function test_tab_of_names_the_tab_of_a_section(): void {
			$this->assertSame( 'firewall', ReportedIP_Hive_Protection_Page::tab_of( 'headers' ) );
			$this->assertSame( 'basics', ReportedIP_Hive_Protection_Page::tab_of( 'detection' ) );
			$this->assertSame( '', ReportedIP_Hive_Protection_Page::tab_of( 'nope' ) );
		}

		/**
		 * @return array<string,array<string,mixed>>
		 */
		private function statuses_for( string $section, array $status ): array {
			$out = array();
			foreach ( ReportedIP_Hive_Protection_Page::visible_keys( $section, true, array() ) as $key ) {
				$out[ $key ] = $status;
			}
			return $out;
		}

		public function test_section_locked_needs_every_key_behind_the_plan(): void {
			$locked = array(
				'available' => false,
				'reason'    => 'tier',
				'min_tier'  => 'professional',
			);
			$this->assertTrue( ReportedIP_Hive_Protection_Page::section_locked( 'hardening_mode', $this->statuses_for( 'hardening_mode', $locked ) ) );

			$partly = $this->statuses_for( 'hardening_mode', $locked );
			$partly['reportedip_hive_hardening_duration_minutes'] = array( 'available' => true );
			$this->assertFalse( ReportedIP_Hive_Protection_Page::section_locked( 'hardening_mode', $partly ), 'one open key opens the section' );

			$partial = $this->statuses_for( 'hardening_mode', $locked + array( 'partial' => true ) );
			$this->assertFalse( ReportedIP_Hive_Protection_Page::section_locked( 'hardening_mode', $partial ), 'a partial field is editable' );

			$runtime = $this->statuses_for( 'hardening_mode', array( 'available' => false, 'reason' => 'runtime' ) );
			$this->assertFalse( ReportedIP_Hive_Protection_Page::section_locked( 'hardening_mode', $runtime ), 'a runtime lock is not a plan lock' );

			$this->assertFalse( ReportedIP_Hive_Protection_Page::section_locked( 'blocking', array() ), 'no status means open' );
		}

		public function test_tab_state_aggregates_the_section_states(): void {
			$on = array(
				'reportedip_hive_waf_enabled'      => 1,
				'reportedip_hive_headers_enabled'  => 1,
				'reportedip_hive_rest_access_mode' => 'open',
			);
			$this->assertSame(
				array( 'text' => 'Active', 'tone' => 'success', 'plan' => '' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'firewall', $on, array() ),
				'lockdown is neutral and does not count'
			);

			$some = array( 'reportedip_hive_waf_enabled' => 1 ) + $on;
			$some['reportedip_hive_headers_enabled'] = 0;
			$this->assertSame(
				array( 'text' => '1 of 2 active', 'tone' => 'neutral', 'plan' => '' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'firewall', $some, array() )
			);

			$off = $on;
			$off['reportedip_hive_waf_enabled']     = 0;
			$off['reportedip_hive_headers_enabled'] = 0;
			$this->assertSame(
				array( 'text' => 'Off', 'tone' => 'danger', 'plan' => '' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'firewall', $off, array() )
			);
		}

		public function test_tab_state_names_the_plan_when_every_section_is_locked(): void {
			$locked   = array(
				'available' => false,
				'reason'    => 'tier',
				'min_tier'  => 'professional',
			);
			$statuses = $this->statuses_for( 'hardening_mode', $locked ) + $this->statuses_for( 'twofa_policies', $locked );
			$this->assertSame(
				array( 'text' => '', 'tone' => 'neutral', 'plan' => 'professional' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'advanced', array(), $statuses )
			);

			$this->assertSame(
				array( 'text' => '', 'tone' => 'neutral', 'plan' => '' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'nope', array(), array() ),
				'an unknown tab counts nothing and shows no pill'
			);

			$paid = $this->statuses_for( 'twofa_policies', $locked );
			$this->assertSame(
				array( 'text' => 'Active', 'tone' => 'success', 'plan' => '' ),
				ReportedIP_Hive_Protection_Page::tab_state( 'advanced', array( 'reportedip_hive_hardening_realtime_detection' => 1 ), $paid ),
				'one open section decides, a locked one is left out'
			);
		}

		public function test_reset_values_keeps_only_the_recommendation_of_the_tab(): void {
			$firewall = ReportedIP_Hive_Protection_Page::reset_values( 'firewall', 'professional', 'community' );
			$this->assertSame( 1, $firewall['reportedip_hive_headers_enabled'] );
			$this->assertSame( 1, $firewall['reportedip_hive_hsts_enabled'] );
			$this->assertSame( 'block', $firewall['reportedip_hive_bot_action'] );
			$this->assertArrayNotHasKey( 'reportedip_hive_block_tor', $firewall, 'a key of another tab is left alone' );
			$this->assertArrayNotHasKey( 'reportedip_hive_waf_enabled', $firewall, 'a key without a recommendation is left alone' );

			$free = ReportedIP_Hive_Protection_Page::reset_values( 'firewall', 'free', 'local' );
			$this->assertSame( 'flag', $free['reportedip_hive_bot_action'] );
			$this->assertArrayNotHasKey( 'reportedip_hive_hsts_enabled', $free );

			$this->assertSame( array(), ReportedIP_Hive_Protection_Page::reset_values( 'nope', 'free', 'local' ) );
		}

		public function test_switches_numbers_and_choices_render_as_rows(): void {
			$bool = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_auto_block',
				array( 'kind' => 'bool', 'label' => 'Auto block', 'description' => 'Block.' ),
				'1',
				array( 'available' => true )
			);
			$this->assertStringContainsString( 'rip-protection__field--row', $bool );
			$this->assertStringContainsString( '<span class="rip-protection__state" data-on="Active" data-off="Off" aria-hidden="true">Active</span>', $bool );

			$off = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_auto_block',
				array( 'kind' => 'bool', 'label' => 'Auto block', 'description' => 'Block.' ),
				'0',
				array( 'available' => true )
			);
			$this->assertStringContainsString( 'aria-hidden="true">Off</span>', $off );

			$int = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_block_duration',
				array( 'kind' => 'int', 'min' => 0, 'max' => 10, 'label' => 'Duration', 'description' => '' ),
				'5',
				array( 'available' => true )
			);
			$this->assertStringContainsString( 'rip-protection__field--row', $int );
			$this->assertStringNotContainsString( 'rip-protection__state', $int );

			$text = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_trusted_proxy_ranges',
				array( 'kind' => 'textarea', 'label' => 'Ranges', 'description' => '' ),
				'',
				array( 'available' => true )
			);
			$this->assertStringNotContainsString( 'rip-protection__field--row', $text );
		}

		public function test_a_plan_locked_list_keeps_its_disabled_control(): void {
			$html = ReportedIP_Hive_Protection_Page::field_markup(
				'reportedip_hive_prohibited_usernames',
				array( 'kind' => 'textarea', 'tier' => 'registration_rules_unlimited', 'label' => 'Names', 'description' => '' ),
				"a\nb",
				array( 'available' => false, 'reason' => 'tier', 'min_tier' => 'professional' )
			);
			$this->assertStringContainsString( '<textarea', $html, 'stored text stays readable' );
			$this->assertStringContainsString( 'disabled', $html );
			$this->assertStringNotContainsString( 'rip-protection__plan', $html );
		}

		public function test_plan_row_markup_is_a_badge_and_a_link(): void {
			$html = ReportedIP_Hive_Protection_Page::plan_row_markup( 'Professional', 'https://example.org/p#f' );
			$this->assertSame(
				'<span class="rip-protection__plan"><span class="rip-badge rip-badge--warning">Professional feature</span><a class="rip-button rip-button--secondary rip-button--sm" href="https://example.org/p#f" target="_blank" rel="noopener">Learn more</a></span>',
				$html
			);
		}

		/**
		 * @return array{0:array<string,mixed>,1:array<string,array<string,mixed>>,2:array<string,array<string,string>>}
		 */
		private function section_fixture(): array {
			$current  = \ReportedIP_Hive_Defaults::all_option_defaults();
			$statuses = array();
			$choices  = array();
			foreach ( \ReportedIP_Hive_Settings_Registry::spec() as $key => $entry ) {
				$statuses[ $key ] = array( 'available' => true );
				if ( 'json_list' === $entry['kind'] ) {
					$choices[ $key ] = array( 'x' => 'X' );
				}
			}
			return array( $current, $statuses, $choices );
		}

		public function test_section_markup_puts_main_rows_first_and_the_rest_behind_details(): void {
			list( $current, $statuses, $choices ) = $this->section_fixture();

			$closed = ReportedIP_Hive_Protection_Page::section_markup( 'blocking', $current, $statuses, false, array(), array(), $choices );
			$this->assertStringContainsString( 'id="blocking"', $closed );
			$this->assertStringContainsString( 'class="rip-protection__section-head"', $closed );
			$this->assertStringContainsString( 'rip-protection__status', $closed );
			$this->assertStringContainsString( '<details class="rip-protection__details">', $closed );
			$this->assertStringContainsString( 'Show technical details', $closed );
			$this->assertLessThan(
				strpos( $closed, 'name="reportedip_hive_block_ladder_minutes"' ),
				strpos( $closed, '<details' ),
				'an expert key sits inside the details'
			);
			$this->assertGreaterThan(
				strpos( $closed, 'name="reportedip_hive_auto_block"' ),
				strpos( $closed, '<details' ),
				'a simple key sits before the details'
			);

			$open = ReportedIP_Hive_Protection_Page::section_markup( 'blocking', $current, $statuses, true, array(), array(), $choices );
			$this->assertStringContainsString( '<details class="rip-protection__details" open>', $open );

			$headers = ReportedIP_Hive_Protection_Page::section_markup( 'headers', $current, $statuses, false, array(), array(), $choices );
			$this->assertLessThan(
				strpos( $headers, 'name="reportedip_hive_' ),
				strpos( $headers, '<details' ),
				'a section without a main row is head plus details: every field sits inside the details'
			);

			$errors = ReportedIP_Hive_Protection_Page::section_markup( 'blocking', $current, $statuses, false, array(), array( 'reportedip_hive_block_duration' => 'Too long.' ), $choices );
			$this->assertStringContainsString( 'data-for="reportedip_hive_block_duration">Too long.', $errors );

			$detection = ReportedIP_Hive_Protection_Page::section_markup( 'detection', $current, $statuses, false, array(), array(), $choices );
			$this->assertStringContainsString( 'name="rip_protection_level"', $detection );

			$forms = ReportedIP_Hive_Protection_Page::section_markup( 'forms', $current, $statuses, false, array( 'cf7' ), array(), $choices );
			$this->assertLessThan( strpos( $forms, '<details' ), strpos( $forms, 'name="reportedip_hive_form_proof_cf7"' ), 'a detected form plugin makes its switch a main row' );
			$this->assertStringContainsString( 'Gravity Forms is not active on this site.', $forms, 'a missing form plugin is named in the details' );
		}

		public function test_section_markup_renders_every_key_of_the_section(): void {
			list( $current, $statuses, $choices ) = $this->section_fixture();
			foreach ( array_keys( \ReportedIP_Hive_Settings_Registry::sections() ) as $section ) {
				$html = ReportedIP_Hive_Protection_Page::section_markup( $section, $current, $statuses, false, array(), array(), $choices );
				foreach ( ReportedIP_Hive_Protection_Page::visible_keys( $section, true, array() ) as $key ) {
					$this->assertStringContainsString( 'name="' . $key, $html, "{$section} does not render {$key}" );
				}
			}
		}
	}
}
