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
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.2
 */

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
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

		public function test_wizard_protection_defaults_all_resolve_to_booleans() {
			$protection = \ReportedIP_Hive_Defaults::wizard_protection_defaults();
			$this->assertCount( 11, $protection );
			foreach ( $protection as $key => $value ) {
				$this->assertIsBool( $value, "wizard_protection default {$key} must be boolean." );
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
	}
}
