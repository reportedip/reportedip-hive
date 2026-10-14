<?php
/**
 * Unit tests for the canonical defaults registry.
 *
 * Locks down the single-source-of-truth invariants introduced when
 * `ReportedIP_Hive::get_default_options()` and the former `SAFE_OPTIONS` map
 * were merged: the alias, the resolved `2fa_enforce_roles` default, the
 * prefix invariant and the router-aware, only-if-absent seeding behaviour.
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
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-effects.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class DefaultsRegistryTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options'] = array();
		}

		public function test_all_option_defaults_alias_matches_safe_options() {
			$this->assertSame(
				\ReportedIP_Hive_Defaults::all_option_defaults(),
				\ReportedIP_Hive_Defaults::safe_options(),
				'safe_options() must alias all_option_defaults() exactly.'
			);
		}

		public function test_two_factor_enforce_roles_default_is_resolved_to_administrator() {
			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();
			$this->assertArrayHasKey( 'reportedip_hive_2fa_enforce_roles', $defaults );
			$this->assertSame(
				'["administrator"]',
				$defaults['reportedip_hive_2fa_enforce_roles'],
				'The merged map must resolve the historical [] vs ["administrator"] conflict to the secure default.'
			);
		}

		public function test_every_key_is_prefixed_and_map_not_empty() {
			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();
			$this->assertNotEmpty( $defaults );
			foreach ( array_keys( $defaults ) as $key ) {
				$this->assertStringStartsWith( 'reportedip_hive_', $key, "Default key {$key} is missing the plugin prefix." );
			}
		}

		public function test_per_site_override_keys_are_absent() {
			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_frontend_slug_site_override', $defaults );
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_frontend_setup_slug_site_override', $defaults );
			$this->assertArrayNotHasKey( 'reportedip_hive_2fa_enforce_roles_extra', $defaults );
		}

		public function test_medium_preset_equals_the_option_defaults() {
			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();
			$medium   = \ReportedIP_Hive_Defaults::protection_presets()['medium'];
			$this->assertSame(
				array( 'failed_login_threshold', 'failed_login_timeframe', 'block_duration', 'block_threshold' ),
				array_keys( $medium )
			);
			foreach ( $medium as $suffix => $value ) {
				$this->assertSame(
					$defaults[ 'reportedip_hive_' . $suffix ],
					$value,
					"Medium preset and option default for {$suffix} must not drift."
				);
			}
		}

		public function test_seed_missing_writes_every_default_through_the_router() {
			$this->assertSame( array(), $GLOBALS['wp_options'] );

			\ReportedIP_Hive_Defaults::seed_missing();

			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();
			foreach ( $defaults as $key => $value ) {
				$expected = is_bool( $value ) ? ( $value ? 1 : 0 ) : $value;
				$this->assertSame(
					$expected,
					\ReportedIP_Hive_Option_Routing::get( $key, '__missing__' ),
					"seed_missing() did not persist {$key} (booleans are stored as 1/0 to avoid the get_option false-default footgun)."
				);
			}
		}

		public function test_seed_missing_does_not_overwrite_existing_values() {
			$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = 99;
			$GLOBALS['wp_options']['reportedip_hive_2fa_enforce_roles']      = '["editor"]';

			\ReportedIP_Hive_Defaults::seed_missing();

			$this->assertSame( 99, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_failed_login_threshold', null ) );
			$this->assertSame( '["editor"]', \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_enforce_roles', null ) );
			$this->assertSame( 0, \ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', '__missing__' ) );
		}

		/**
		 * Seeding owes a setting the side effects its registry entry declares.
		 *
		 * A side effect only ran when a channel wrote the setting. A default
		 * that nobody writes left a clock such as the adapter grace at zero,
		 * which reads as "never enforce": the work of a protection without its
		 * effect.
		 */
		public function test_seeding_owes_a_setting_its_declared_effect() {
			$tokens = \ReportedIP_Hive_Defaults::seed_effect_tokens( array( 'reportedip_hive_form_proof_cf7' ) );

			$this->assertContains( 'stamp_form_adapters_since', $tokens );
		}

		/**
		 * A setting without a declared side effect owes nothing, and a token
		 * declared by two settings is still queued once.
		 */
		public function test_seed_effect_tokens_are_declared_and_unique() {
			$this->assertSame( array(), \ReportedIP_Hive_Defaults::seed_effect_tokens( array( 'reportedip_hive_headers_enabled' ) ) );
			$this->assertSame( array(), \ReportedIP_Hive_Defaults::seed_effect_tokens( array() ) );

			$adapters = \ReportedIP_Hive_Defaults::seed_effect_tokens(
				array(
					'reportedip_hive_form_proof_cf7',
					'reportedip_hive_form_proof_formidable',
					'reportedip_hive_form_proof_elementor',
				)
			);

			$this->assertSame( array( 'stamp_form_adapters_since' ), $adapters );
		}

		/**
		 * The community check on forms is recommended wherever it can work.
		 *
		 * It needs the community network, not a paid plan, so the mode decides
		 * and the tier does not.
		 */
		public function test_the_community_check_on_forms_follows_the_mode() {
			foreach ( array( 'free', 'contributor', 'professional', 'business' ) as $tier ) {
				$community = \ReportedIP_Hive_Defaults::recommended( $tier, 'community' );
				$local     = \ReportedIP_Hive_Defaults::recommended( $tier, 'local' );

				$this->assertSame( 1, $community['reportedip_hive_reputation_on_forms'] ?? null, $tier . ' on the community network' );
				$this->assertArrayNotHasKey( 'reportedip_hive_reputation_on_forms', $local, $tier . ' on Local Shield' );
			}
		}

		public function test_first_seeded_version_records_the_origin_once() {
			$this->assertSame( '', \ReportedIP_Hive_Defaults::first_seeded_version(), 'A fresh install has no origin yet.' );

			$GLOBALS['wp_options']['reportedip_hive_seeded_version'] = '2.1.74';
			$this->assertSame( '2.1.74', \ReportedIP_Hive_Defaults::first_seeded_version(), 'Before the marker the previous seed answers.' );

			\ReportedIP_Hive_Defaults::note_first_seeded_version( '2.1.74' );
			\ReportedIP_Hive_Defaults::note_first_seeded_version( '3.0.0' );
			$GLOBALS['wp_options']['reportedip_hive_seeded_version'] = '3.0.0';
			$this->assertSame( '2.1.74', \ReportedIP_Hive_Defaults::first_seeded_version(), 'The origin is written once.' );

			$GLOBALS['wp_options'] = array();
			\ReportedIP_Hive_Defaults::note_first_seeded_version( '' );
			$this->assertSame( REPORTEDIP_HIVE_VERSION, \ReportedIP_Hive_Defaults::first_seeded_version(), 'A fresh install records the running version.' );
		}
	}
}
