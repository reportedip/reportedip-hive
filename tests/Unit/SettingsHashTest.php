<?php
/**
 * Unit tests for the settings drift fingerprint.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.47
 */

declare(strict_types=1);

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * The hash must be stable across value representations and blind to
	 * non-remote keys, otherwise every dashboard shows phantom drift.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class SettingsHashTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options'] = array();
		}

		public function test_hash_is_prefixed_and_deterministic() {
			$first  = \ReportedIP_Hive_Settings_Registry::settings_hash();
			$second = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$this->assertStringStartsWith( 'sha256:', $first );
			$this->assertSame( $first, $second );
		}

		public function test_hash_is_stable_across_boolean_representations() {
			$GLOBALS['wp_options']['reportedip_hive_auto_block'] = true;
			$as_bool = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$GLOBALS['wp_options']['reportedip_hive_auto_block'] = 1;
			$as_int = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$GLOBALS['wp_options']['reportedip_hive_auto_block'] = '1';
			$as_string = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$this->assertSame( $as_bool, $as_int );
			$this->assertSame( $as_bool, $as_string );
		}

		public function test_hash_is_stable_across_integer_representations() {
			$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = 7;
			$as_int = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = '7';
			$as_string = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$this->assertSame( $as_int, $as_string );
		}

		public function test_hash_changes_when_a_remote_value_changes() {
			$before = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = 42;

			$this->assertNotSame( $before, \ReportedIP_Hive_Settings_Registry::settings_hash() );
		}

		public function test_hash_ignores_non_remote_options() {
			$before = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$GLOBALS['wp_options']['reportedip_hive_api_key']        = 'secret-key';
			$GLOBALS['wp_options']['reportedip_hive_operation_mode'] = 'community';

			$this->assertSame( $before, \ReportedIP_Hive_Settings_Registry::settings_hash() );
		}

		/**
		 * A value on its default contributes nothing, whatever its stored
		 * representation. This is what keeps a release that seeds new keys
		 * from flipping every site to drift.
		 */
		public function test_hash_ignores_values_that_sit_on_their_default() {
			$absent = \ReportedIP_Hive_Settings_Registry::settings_hash();

			$defaults = \ReportedIP_Hive_Defaults::all_option_defaults();
			$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = (string) $defaults['reportedip_hive_failed_login_threshold'];
			$GLOBALS['wp_options']['reportedip_hive_auto_block']             = (bool) $defaults['reportedip_hive_auto_block'];
			$GLOBALS['wp_options']['reportedip_hive_rest_allowed_roles']     = json_decode( (string) $defaults['reportedip_hive_rest_allowed_roles'], true );

			$this->assertSame( $absent, \ReportedIP_Hive_Settings_Registry::settings_hash() );
		}

		/**
		 * 3.0.0 changed two shipped defaults (SMS left the allowed 2FA
		 * methods, the breached-password check became opt-in). A 2.1.74 site
		 * that kept the old defaults then hashed them as changed, and every
		 * dashboard showed drift after the update without a value change.
		 * The hash keeps the 2.1.74 reference for both keys: this option set
		 * hashed to exactly this value under 2.1.74.
		 */
		public function test_a_2_1_74_site_keeps_its_hash_across_the_update() {
			$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods']    = '["totp","email","webauthn","sms"]';
			$GLOBALS['wp_options']['reportedip_hive_password_check_hibp']    = '1';
			$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = '42';

			$this->assertSame(
				'sha256:fbcdbcff06ef4d88a42012cf9e343e455df426b0212fefaee9643fe8f73ed890',
				\ReportedIP_Hive_Settings_Registry::settings_hash()
			);
		}

		public function test_hash_moves_when_a_value_returns_to_its_default() {
			$GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] = 42;
			$changed = \ReportedIP_Hive_Settings_Registry::settings_hash();

			unset( $GLOBALS['wp_options']['reportedip_hive_failed_login_threshold'] );

			$this->assertNotSame( $changed, \ReportedIP_Hive_Settings_Registry::settings_hash() );
		}
	}
}
