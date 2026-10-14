<?php
/**
 * Pins the global option sanitisers for the 2FA allowed-methods and enforce-roles
 * options against the "setup wizard saves only TOTP / drops all enforced roles" bug.
 *
 * {@see register_setting()} installs `sanitize_option_*` filters for these two
 * keys, so the sanitisers run on EVERY write, the settings form, the setup
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
 * @author     Patrick Schlesinger <1@reportedip.com>
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

		public function test_canonical_valid_methods_is_the_single_source() {
			$this->assertSame(
				array( 'totp', 'email', 'webauthn' ),
				\ReportedIP_Hive_Two_Factor::valid_methods(),
				'valid_methods() is the one allow-list every 2FA write validates against; recovery is excluded, further methods come only through the registry.'
			);
		}

		public function test_valid_methods_follow_the_registry_filter() {
			add_filter(
				'reportedip_hive_2fa_methods',
				static function ( array $methods ) {
					$methods['carrier_pigeon'] = array(
						'meta_key' => 'reportedip_hive_2fa_carrier_pigeon_enabled',
						'label'    => 'Carrier pigeon',
						'verify'   => '__return_false',
					);
					return $methods;
				}
			);
			\ReportedIP_Hive_Two_Factor::flush_methods();

			$this->assertSame(
				array( 'carrier_pigeon', 'totp' ),
				\ReportedIP_Hive_Two_Factor::filter_valid_methods( array( 'carrier_pigeon', 'sms', 'totp' ) )
			);
		}

		public function test_filter_valid_methods_drops_unknowns_and_dedupes() {
			$this->assertSame(
				array( 'webauthn', 'totp' ),
				\ReportedIP_Hive_Two_Factor::filter_valid_methods( array( 'webauthn', 'bogus', 'totp', 'totp' ) )
			);
		}

		/**
		 * Saving the settings on a site whose add-on is inactive must not
		 * drop the add-on's method from the stored policy: the form only
		 * posts the methods it shows.
		 */
		public function test_an_unknown_stored_slug_survives_a_save() {
			require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-login-context.php';
			require_once dirname( __DIR__, 2 ) . '/admin/class-protection-page.php';
			$key = 'reportedip_hive_2fa_allowed_methods';
			$this->set_mocked_option( $key, '["totp","email","sms"]' );

			$posted = \ReportedIP_Hive_Protection_Page::collect_values( array( $key => array( 'totp', 'webauthn' ) ), 'account_security' );
			$this->assertSame( '["totp","webauthn","sms"]', \ReportedIP_Hive_Settings_Registry::sanitize( $key, $posted[ $key ] ) );

			$this->assertSame( '["sms"]', \ReportedIP_Hive_Settings_Registry::sanitize( $key, array() ), 'Unticking every shown method keeps the stored slug as well.' );
			$this->assertSame( array( 'totp', 'email' ), \ReportedIP_Hive_Two_Factor::get_allowed_methods(), 'An unknown slug never counts for the effective policy.' );
		}

		public function test_sanitize_allowed_methods_keeps_unknown_slugs_of_the_right_shape_only() {
			$this->assertSame(
				array( 'totp', 'sms' ),
				\ReportedIP_Hive_Two_Factor::sanitize_allowed_methods( array( 'totp', 'sms', 'Bad Slug', str_repeat( 'x', 33 ), array( 'nested' ), 'totp' ) )
			);
		}

		/**
		 * A stored slug nobody registers is never offered, allowed, enrolled
		 * or verified.
		 */
		public function test_an_unknown_slug_is_never_offered_or_verified() {
			require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-verifier.php';
			$this->set_mocked_option( 'reportedip_hive_2fa_allowed_methods', '["totp","sms"]' );

			$this->assertSame( array( 'totp' ), \ReportedIP_Hive_Two_Factor::get_allowed_methods() );
			$this->assertFalse( \ReportedIP_Hive_Two_Factor::is_method_allowed( 'sms' ) );
			$this->assertArrayNotHasKey( 'sms', \ReportedIP_Hive_Settings_Registry::choice_values( 'methods' ) );
			$this->assertFalse( \ReportedIP_Hive_Two_Factor::activate_method( 3, 'sms' ) );
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Verifier::verify_method( 3, 'sms', '123456' ) );
		}

		/**
		 * The allowed-methods list keeps the wording it had in 2.1.74.
		 */
		public function test_choice_labels_keep_their_wording() {
			require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';

			$this->assertSame(
				array(
					'totp'     => 'Authenticator app (TOTP)',
					'email'    => 'E-mail code',
					'webauthn' => 'Security key / passkey',
				),
				\ReportedIP_Hive_Settings_Registry::choice_values( 'methods' )
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
