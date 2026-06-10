<?php
/**
 * Pins the global option sanitisers for the 2FA allowed-methods and enforce-roles
 * options against the "setup wizard saves only TOTP / drops all enforced roles" bug.
 *
 * {@see register_setting()} installs `sanitize_option_*` filters for these two
 * keys, so the sanitisers run on EVERY write — the settings form, the setup
 * wizard, the tier-upgrade lifecycle, settings import and WP-CLI. The original
 * implementations only understood the settings-form shape:
 *
 *  - allowed-methods read the per-method `$_POST['reportedip_hive_2fa_method_*']`
 *    checkboxes and ignored their `$input`, so a direct JSON write (the wizard)
 *    found no checkboxes and collapsed to TOTP only;
 *  - enforce-roles required `is_array( $input )` and returned '[]' for the JSON
 *    array string the wizard writes, silently wiping every enforced role.
 *
 * These cases lock in that a direct value passes through untouched while the
 * settings-form checkbox path stays authoritative.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.28
 */

namespace {

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
		require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor.php';
	}

	if ( ! function_exists( 'wp_roles' ) ) {
		/**
		 * Stub WP_Roles provider exposing the default role slugs.
		 *
		 * @return object
		 */
		function wp_roles() {
			return new class() {
				/**
				 * Role slug => display name map.
				 *
				 * @return array<string, string>
				 */
				public function get_names() {
					return array(
						'administrator' => 'Administrator',
						'editor'        => 'Editor',
						'author'        => 'Author',
						'contributor'   => 'Contributor',
						'subscriber'    => 'Subscriber',
					);
				}
			};
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/admin/class-two-factor-admin.php';

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorSettingsSanitizersTest extends TestCase {

		/**
		 * Reset the POST superglobal so checkbox detection starts clean.
		 */
		protected function set_up() {
			parent::set_up();
			$_POST = array();
		}

		/**
		 * Restore the POST superglobal.
		 */
		protected function tear_down() {
			$_POST = array();
			parent::tear_down();
		}

		public function test_wizard_json_methods_pass_through_unchanged() {
			$out = \ReportedIP_Hive_Two_Factor_Admin::sanitize_allowed_methods( '["totp","webauthn","email"]' );
			$this->assertSame( array( 'totp', 'webauthn', 'email' ), json_decode( $out, true ) );
		}

		public function test_array_methods_are_validated_and_kept() {
			$out = \ReportedIP_Hive_Two_Factor_Admin::sanitize_allowed_methods( array( 'totp', 'sms', 'bogus' ) );
			$this->assertSame( array( 'totp', 'sms' ), json_decode( $out, true ) );
		}

		public function test_empty_methods_value_falls_back_to_totp() {
			$out = \ReportedIP_Hive_Two_Factor_Admin::sanitize_allowed_methods( '[]' );
			$this->assertSame( array( 'totp' ), json_decode( $out, true ) );
		}

		public function test_settings_form_checkboxes_remain_authoritative() {
			$_POST['reportedip_hive_2fa_method_totp']  = '1';
			$_POST['reportedip_hive_2fa_method_email'] = '1';
			$out = \ReportedIP_Hive_Two_Factor_Admin::sanitize_allowed_methods( '' );
			$this->assertSame( array( 'totp', 'email' ), json_decode( $out, true ) );
		}

		public function test_settings_form_with_one_checkbox_does_not_leak_the_value() {
			$_POST['reportedip_hive_2fa_method_webauthn'] = '1';
			$out = \ReportedIP_Hive_Two_Factor_Admin::sanitize_allowed_methods( '["totp","email","sms"]' );
			$this->assertSame( array( 'webauthn' ), json_decode( $out, true ) );
		}

		public function test_wizard_json_roles_pass_through_unchanged() {
			$out = \ReportedIP_Hive_Two_Factor_Admin::sanitize_enforce_roles( '["administrator","editor"]' );
			$this->assertSame( array( 'administrator', 'editor' ), json_decode( $out, true ) );
		}

		public function test_settings_form_array_roles_are_validated() {
			$out = \ReportedIP_Hive_Two_Factor_Admin::sanitize_enforce_roles( array( 'administrator', 'ghost', 'editor' ) );
			$this->assertSame( array( 'administrator', 'editor' ), json_decode( $out, true ) );
		}

		public function test_empty_roles_value_yields_empty_array() {
			$this->assertSame( '[]', \ReportedIP_Hive_Two_Factor_Admin::sanitize_enforce_roles( '' ) );
			$this->assertSame( '[]', \ReportedIP_Hive_Two_Factor_Admin::sanitize_enforce_roles( '[]' ) );
		}

		public function test_canonical_valid_methods_is_the_single_source() {
			$this->assertSame(
				array( 'totp', 'email', 'webauthn', 'sms' ),
				\ReportedIP_Hive_Two_Factor::valid_methods(),
				'valid_methods() is the one allow-list every 2FA write validates against; recovery is excluded.'
			);
		}

		public function test_filter_valid_methods_drops_unknowns_and_dedupes() {
			$this->assertSame(
				array( 'webauthn', 'totp' ),
				\ReportedIP_Hive_Two_Factor::filter_valid_methods( array( 'webauthn', 'bogus', 'totp', 'totp' ) )
			);
		}

		public function test_filter_valid_roles_drops_unknowns_and_dedupes() {
			$this->assertSame(
				array( 'administrator', 'editor' ),
				\ReportedIP_Hive_Two_Factor::filter_valid_roles( array( 'administrator', 'ghost', 'editor', 'administrator' ) )
			);
		}
	}
}
