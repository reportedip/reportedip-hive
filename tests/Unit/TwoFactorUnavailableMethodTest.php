<?php
/**
 * Pins what an account experiences whose only second factor is a method no
 * active plugin provides any more, for example SMS while the add-on that
 * registers it is inactive.
 *
 * Without the guard such an account looked like one without 2FA: the
 * enabled list is built from the registered methods only, so the password
 * alone signed it in. The rule is now:
 *
 *  - the sign-in is challenged, not let through and not refused;
 *  - the challenge accepts the account's recovery codes (and nothing it
 *    cannot verify);
 *  - a warning in the log tells an administrator which method is missing;
 *  - the method's own data (enabled flag, phone number) stays untouched, so
 *    the method works again the moment its add-on is back.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Loads the real classes in set_up(), which only runs in the child
	 * process: at discovery other test files already declare their own
	 * doubles under the same names.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorUnavailableMethodTest extends TestCase {

		private const USER_ID = 7;

		/**
		 * An account that set up SMS as its only method, as the 2.1.x plugin
		 * stored it.
		 */
		protected function set_up() {
			parent::set_up();
			require_once dirname( __DIR__ ) . '/stubs/two-factor-runtime-stubs.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-verifier.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor.php';
			$GLOBALS['wp_options']                  = array();
			$GLOBALS['wp_transients']               = array();
			$GLOBALS['rip_test_logs']               = array();
			$GLOBALS['rip_test_recovery_remaining'] = array( self::USER_ID => 4 );
			$GLOBALS['rip_test_recovery_code']      = array( self::USER_ID => 'abcd-efgh' );
			$GLOBALS['rip_test_doing_ajax']         = true;
			$GLOBALS['wp_user_meta']                = array(
				self::USER_ID => array(
					'reportedip_hive_2fa_enabled'     => '1',
					'reportedip_hive_2fa_method'      => 'sms',
					'reportedip_hive_2fa_sms_enabled' => '1',
					'reportedip_hive_2fa_sms_number'  => 'encrypted-number',
				),
			);
			$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'] = '["totp","email","webauthn","sms"]';
			\ReportedIP_Hive_Two_Factor::flush_methods();
		}

		/**
		 * Register a stand-in for the add-on's SMS method.
		 */
		private function register_sms(): void {
			add_filter(
				'reportedip_hive_2fa_methods',
				static function ( array $methods ) {
					$methods['sms'] = array(
						'meta_key' => 'reportedip_hive_2fa_sms_enabled',
						'label'    => 'SMS code',
						'verify'   => static function () {
							return true;
						},
					);
					return $methods;
				}
			);
			\ReportedIP_Hive_Two_Factor::flush_methods();
		}

		public function test_an_account_whose_only_method_is_unregistered_is_reported(): void {
			$this->assertSame( array(), \ReportedIP_Hive_Two_Factor::get_user_enabled_methods( self::USER_ID ) );
			$this->assertSame( 'sms', \ReportedIP_Hive_Two_Factor::unavailable_method( self::USER_ID ) );
		}

		public function test_the_method_counts_again_once_it_is_registered(): void {
			$this->register_sms();

			$this->assertSame( array( 'sms' ), \ReportedIP_Hive_Two_Factor::get_user_enabled_methods( self::USER_ID ) );
			$this->assertSame( '', \ReportedIP_Hive_Two_Factor::unavailable_method( self::USER_ID ) );
		}

		public function test_accounts_without_2fa_or_with_a_working_method_are_not_affected(): void {
			unset( $GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_enabled'] );
			$this->assertSame( '', \ReportedIP_Hive_Two_Factor::unavailable_method( self::USER_ID ), 'Without the 2FA flag the leftover data is not a factor.' );

			$GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_enabled']      = '1';
			$GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_totp_enabled'] = '1';
			$this->assertSame( '', \ReportedIP_Hive_Two_Factor::unavailable_method( self::USER_ID ), 'A working method is challenged as usual.' );
		}

		public function test_sign_in_is_challenged_instead_of_let_through(): void {
			$two_factor = new \ReportedIP_Hive_Two_Factor();
			$result     = $two_factor->filter_authenticate( new \WP_User( self::USER_ID ), 'jane', 'secret' );

			$this->assertInstanceOf( \WP_Error::class, $result, 'The password alone must not sign in an account that has a second factor.' );
			$this->assertSame( 'reportedip_2fa_required', $result->get_error_code(), 'The account must reach the challenge, not a hard refusal.' );

			$warnings = array_filter(
				$GLOBALS['rip_test_logs'],
				static function ( $entry ) {
					return 'warning' === $entry['level'];
				}
			);
			$this->assertCount( 1, $warnings, 'An administrator needs to see why the usual method is not offered.' );
			$this->assertSame( 'sms', array_values( $warnings )[0]['args'][2]['method'] );
		}

		public function test_an_account_without_2fa_still_signs_in_with_the_password(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ] = array();

			$two_factor = new \ReportedIP_Hive_Two_Factor();
			$user       = new \WP_User( self::USER_ID );

			$this->assertSame( $user, $two_factor->filter_authenticate( $user, 'jane', 'secret' ) );
		}

		public function test_the_challenge_accepts_recovery_codes_only(): void {
			$verify = new \ReflectionMethod( \ReportedIP_Hive_Two_Factor::class, 'verify_2fa_code' );
			$two_factor = new \ReportedIP_Hive_Two_Factor();

			$this->assertTrue( $verify->invoke( $two_factor, self::USER_ID, 'abcd-efgh', 'recovery' ), 'Recovery codes are the way back in.' );
			$this->assertFalse( $verify->invoke( $two_factor, self::USER_ID, '123456', 'sms' ), 'A method nobody can verify must never pass.' );
		}

		public function test_the_method_data_survives_the_sign_in_attempt(): void {
			$two_factor = new \ReportedIP_Hive_Two_Factor();
			$two_factor->filter_authenticate( new \WP_User( self::USER_ID ), 'jane', 'secret' );

			$meta = $GLOBALS['wp_user_meta'][ self::USER_ID ];
			$this->assertSame( '1', $meta['reportedip_hive_2fa_sms_enabled'] );
			$this->assertSame( 'encrypted-number', $meta['reportedip_hive_2fa_sms_number'] );
			$this->assertSame( 'sms', $meta['reportedip_hive_2fa_method'] );
		}

		public function test_the_challenge_falls_back_to_the_recovery_tab(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor.php' );

			$this->assertStringContainsString(
				'$method = empty( $allowed_methods ) ? self::METHOD_RECOVERY : $allowed_methods[0];',
				$source,
				'Without a usable method the challenge must open on the recovery codes, not on tabs for methods the user never set up.'
			);
		}
	}
}
