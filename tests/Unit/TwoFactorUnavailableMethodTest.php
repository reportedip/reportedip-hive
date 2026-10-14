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

namespace {

	if ( ! function_exists( 'delete_metadata' ) ) {
		/**
		 * Records each deleted meta key in $GLOBALS['rip_test_deleted_meta'].
		 *
		 * @param string $type       Object type.
		 * @param int    $object_id  Object id.
		 * @param string $meta_key   Meta key.
		 * @param mixed  $meta_value Meta value.
		 * @param bool   $delete_all Whether all objects are affected.
		 * @return bool
		 */
		function delete_metadata( $type, $object_id, $meta_key, $meta_value = '', $delete_all = false ) {
			unset( $meta_value );
			$GLOBALS['rip_test_deleted_meta'][] = array( $type, $object_id, $meta_key, $delete_all );
			return true;
		}
	}
}

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

		public function test_the_challenge_page_explains_the_missing_method(): void {
			$template = (string) file_get_contents( dirname( __DIR__, 2 ) . '/templates/two-factor-challenge.php' );

			$this->assertStringContainsString( '$no_method   = empty( $allowed_methods );', $template );
			$this->assertStringContainsString( 'Enter one of your recovery codes to continue.', $template, 'With codes left the page says what to do.' );
			$this->assertStringContainsString( 'Please ask an administrator to reset two-factor authentication for your account.', $template, 'Without codes the page names the way out instead of an empty form.' );
			$this->assertStringContainsString( "\$is_active = ( ReportedIP_Hive_Two_Factor::METHOD_RECOVERY === \$method );", $template, 'The recovery panel must open by itself when it is the only way in.' );
		}

		public function test_the_challenge_falls_back_to_the_recovery_tab(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor.php' );

			$this->assertStringContainsString(
				'$method = empty( $allowed_methods ) ? self::METHOD_RECOVERY : $allowed_methods[0];',
				$source,
				'Without a usable method the challenge must open on the recovery codes, not on tabs for methods the user never set up.'
			);
		}

		/**
		 * TOTP plus SMS, TOTP disallowed by the site policy, SMS without its
		 * add-on: 2.1.74 challenged this account by SMS. It must reach the
		 * recovery-code challenge, not sign in with the password alone.
		 */
		public function test_an_account_whose_registered_methods_are_all_disallowed_is_challenged(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_method']       = 'totp';
			$GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_totp_enabled'] = '1';
			$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods']                 = '["email","webauthn","sms"]';
			\ReportedIP_Hive_Two_Factor::flush_methods();

			$this->assertSame( array(), \ReportedIP_Hive_Two_Factor::get_user_enabled_methods( self::USER_ID ) );
			$this->assertSame( 'sms', \ReportedIP_Hive_Two_Factor::unavailable_method( self::USER_ID ), 'The flag of the missing method names it.' );

			$result = ( new \ReportedIP_Hive_Two_Factor() )->filter_authenticate( new \WP_User( self::USER_ID ), 'jane', 'secret' );
			$this->assertInstanceOf( \WP_Error::class, $result, 'The password alone must not sign this account in.' );
			$this->assertSame( 'reportedip_2fa_required', $result->get_error_code() );
		}

		/**
		 * Without a flag of a missing method the policy decision stands: an
		 * account whose only method was disallowed signs in with the password
		 * and the log says why.
		 */
		public function test_an_account_with_only_disallowed_registered_methods_keeps_the_policy_decision(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ] = array(
				'reportedip_hive_2fa_enabled'      => '1',
				'reportedip_hive_2fa_method'       => 'totp',
				'reportedip_hive_2fa_totp_enabled' => '1',
			);
			$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'] = '["email","webauthn"]';
			\ReportedIP_Hive_Two_Factor::flush_methods();

			$this->assertSame( '', \ReportedIP_Hive_Two_Factor::unavailable_method( self::USER_ID ) );
		}

		/**
		 * TOTP plus SMS, policy without either, SMS without its add-on:
		 * 2.1.74 let this account through with the policy warning, because
		 * the policy dropped SMS as well. The missing method only counts
		 * while the stored policy still names it.
		 */
		public function test_a_missing_method_the_policy_dropped_does_not_count(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_totp_enabled'] = '1';
			$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods']                 = '["email","webauthn"]';
			\ReportedIP_Hive_Two_Factor::flush_methods();

			$this->assertSame( '', \ReportedIP_Hive_Two_Factor::unavailable_method( self::USER_ID ) );

			$user = new \WP_User( self::USER_ID );
			$this->assertSame( $user, ( new \ReportedIP_Hive_Two_Factor() )->filter_authenticate( $user, 'jane', 'secret' ), 'The policy decision stands, as in 2.1.74.' );
			$warnings = array_filter(
				$GLOBALS['rip_test_logs'],
				static function ( $entry ) {
					return 'warning' === $entry['level'];
				}
			);
			$this->assertCount( 1, $warnings, 'The policy warning is logged.' );
		}

		/**
		 * The stored default only counts as well while the policy names it.
		 */
		public function test_a_stored_default_the_policy_dropped_does_not_count(): void {
			unset( $GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_sms_enabled'] );
			$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'] = '["totp","email","webauthn"]';
			$this->assertSame( '', \ReportedIP_Hive_Two_Factor::unavailable_method( self::USER_ID ) );

			$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'] = '["totp","email","webauthn","sms"]';
			$this->assertSame( 'sms', \ReportedIP_Hive_Two_Factor::unavailable_method( self::USER_ID ) );
		}

		/**
		 * The lossless policy keeps at most sixteen unregistered slugs.
		 */
		public function test_the_policy_keeps_at_most_sixteen_unregistered_slugs(): void {
			$junk = array();
			for ( $i = 0; $i < 40; $i++ ) {
				$junk[] = 'junk' . $i;
			}
			$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'] = '["sms"]';

			$result = \ReportedIP_Hive_Two_Factor::sanitize_allowed_methods( array_merge( array( 'totp', 'email' ), $junk ) );

			$this->assertSame( array( 'totp', 'email' ), array_slice( $result, 0, 2 ), 'Registered methods are never capped.' );
			$this->assertCount( 2 + \ReportedIP_Hive_Two_Factor::MAX_UNREGISTERED_ALLOWED, $result );
			$this->assertNotContains( 'junk39', $result );
		}

		/**
		 * A full reset removes every 2FA key of the user, the ones of a
		 * method no active plugin registers included.
		 */
		public function test_a_full_reset_removes_the_data_of_the_missing_method(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_sms_number_pending'] = 'encrypted-pending';
			$GLOBALS['wp_user_meta'][ self::USER_ID ]['unrelated_meta']                         = 'stays';

			\ReportedIP_Hive_Two_Factor::disable_for_user( self::USER_ID );

			$this->assertSame( array( 'unrelated_meta' => 'stays' ), $GLOBALS['wp_user_meta'][ self::USER_ID ] );
		}

		/**
		 * A full reset keeps exactly the keys 2.1.x kept: the reminder
		 * opt-out, the reset-challenge counter and the WebAuthn user handle.
		 */
		public function test_a_full_reset_keeps_the_keep_list(): void {
			$kept = array(
				'reportedip_hive_2fa_reminder_optout'       => 1,
				'reportedip_hive_2fa_reset_failed_attempts' => 2,
				'reportedip_hive_2fa_webauthn_user_handle'  => 'handle',
			);
			$GLOBALS['wp_user_meta'][ self::USER_ID ] = $kept + $GLOBALS['wp_user_meta'][ self::USER_ID ];

			\ReportedIP_Hive_Two_Factor::disable_for_user( self::USER_ID );

			$this->assertSame( $kept, $GLOBALS['wp_user_meta'][ self::USER_ID ] );
		}

		/**
		 * The GDPR eraser removes the kept keys together with the 2FA data.
		 */
		public function test_the_eraser_removes_the_keep_list(): void {
			require_once dirname( __DIR__, 2 ) . '/admin/class-two-factor-admin.php';
			$GLOBALS['wp_user_meta'][1] = array(
				'reportedip_hive_2fa_reminder_optout'       => 1,
				'reportedip_hive_2fa_reset_failed_attempts' => 2,
				'reportedip_hive_2fa_webauthn_user_handle'  => 'handle',
			);

			$admin  = ( new \ReflectionClass( \ReportedIP_Hive_Two_Factor_Admin::class ) )->newInstanceWithoutConstructor();
			$result = $admin->erase_personal_data( 'admin@example.org' );

			$this->assertSame( 1, $result['items_removed'] );
			$this->assertSame( array(), \ReportedIP_Hive_Two_Factor::stored_meta_keys( 1 ) );
		}

		/**
		 * Turning the last visible method off keeps 2FA on while the stored
		 * policy still names the missing method, and its data stays
		 * untouched, as in 2.1.74 where SMS stayed the remaining method.
		 */
		public function test_turning_off_the_last_visible_method_keeps_the_missing_method(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_method']       = 'totp';
			$GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_totp_enabled'] = '1';
			\ReportedIP_Hive_Two_Factor::flush_methods();

			$this->assertTrue( \ReportedIP_Hive_Two_Factor::disable_method( self::USER_ID, 'totp' ) );

			$meta = $GLOBALS['wp_user_meta'][ self::USER_ID ];
			$this->assertSame( '1', $meta['reportedip_hive_2fa_enabled'], '2FA stays on.' );
			$this->assertSame( '1', $meta['reportedip_hive_2fa_sms_enabled'] );
			$this->assertSame( 'encrypted-number', $meta['reportedip_hive_2fa_sms_number'] );
			$this->assertSame( 'sms', $meta['reportedip_hive_2fa_method'], 'The remaining method becomes the default.' );
			$this->assertSame( 'sms', \ReportedIP_Hive_Two_Factor::unavailable_method( self::USER_ID ) );
		}

		/**
		 * With the missing method dropped from the stored policy, removing
		 * the last visible method turns 2FA off completely, as 2.1.74 did.
		 */
		public function test_turning_off_the_last_method_turns_2fa_off_when_the_policy_dropped_the_missing_one(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_method']       = 'totp';
			$GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_totp_enabled'] = '1';
			$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods']                 = '["totp","email","webauthn"]';
			\ReportedIP_Hive_Two_Factor::flush_methods();

			$this->assertTrue( \ReportedIP_Hive_Two_Factor::disable_method( self::USER_ID, 'totp' ) );

			$this->assertSame( array(), \ReportedIP_Hive_Two_Factor::stored_meta_keys( self::USER_ID ) );
		}

		/**
		 * The GDPR eraser removes the 2FA data of an account even when no
		 * method of it is active here, for example a stored phone number.
		 */
		public function test_the_eraser_removes_the_data_of_the_missing_method(): void {
			require_once dirname( __DIR__, 2 ) . '/admin/class-two-factor-admin.php';
			$GLOBALS['wp_user_meta'][1] = array(
				'reportedip_hive_2fa_sms_number' => 'encrypted-number',
			);

			$admin  = ( new \ReflectionClass( \ReportedIP_Hive_Two_Factor_Admin::class ) )->newInstanceWithoutConstructor();
			$result = $admin->erase_personal_data( 'admin@example.org' );

			$this->assertSame( 1, $result['items_removed'] );
			$this->assertSame( array(), \ReportedIP_Hive_Two_Factor::stored_meta_keys( 1 ) );
		}

		/**
		 * Uninstall and the full data reset find the stored 2FA keys by
		 * prefix, so the keys of a method nobody registers go as well.
		 */
		public function test_uninstall_and_data_reset_delete_every_stored_2fa_key(): void {
			$GLOBALS['rip_test_deleted_meta'] = array();
			$GLOBALS['wpdb']                  = new class() {

				/**
				 * User meta table.
				 *
				 * @var string
				 */
				public $usermeta = 'wp_usermeta';

				/**
				 * Last prepared LIKE pattern.
				 *
				 * @var string
				 */
				public $pattern = '';

				/**
				 * @param string $text Text.
				 * @return string
				 */
				public function esc_like( $text ) {
					return addcslashes( $text, '_%\\' );
				}

				/**
				 * @param string $query Query.
				 * @param mixed  ...$args Arguments.
				 * @return string
				 */
				public function prepare( $query, ...$args ) {
					$this->pattern = (string) $args[0];
					return $query;
				}

				/**
				 * @return string[]
				 */
				public function get_col() {
					return array( 'reportedip_hive_2fa_sms_number', 'reportedip_hive_2fa_totp_secret' );
				}
			};

			\ReportedIP_Hive_Two_Factor::delete_all_user_meta();

			$deleted = array_column( $GLOBALS['rip_test_deleted_meta'], 2 );
			$this->assertSame( 'reportedip\_hive\_2fa\_%', $GLOBALS['wpdb']->pattern );
			$this->assertContains( 'reportedip_hive_2fa_sms_number', $deleted, 'A key nobody registers is found by its prefix.' );
			$this->assertContains( 'reportedip_hive_2fa_totp_secret', $deleted );
			$this->assertContains( 'reportedip_hive_login_context', $deleted, 'The known keys outside the prefix stay covered.' );
			$this->assertSame( count( $deleted ), count( array_unique( $deleted ) ), 'Each key is deleted once.' );
			$this->assertSame( array( true ), array_values( array_unique( array_column( $GLOBALS['rip_test_deleted_meta'], 3 ) ) ), 'Every user loses the key.' );

			$root = dirname( __DIR__, 2 );
			$this->assertStringContainsString( 'ReportedIP_Hive_Two_Factor::delete_all_user_meta();', (string) file_get_contents( $root . '/reportedip-hive.php' ), 'Uninstall uses the prefix sweep.' );
			$this->assertStringContainsString( 'ReportedIP_Hive_Two_Factor::delete_all_user_meta();', (string) file_get_contents( $root . '/includes/class-ajax-handler.php' ), 'The full data reset uses the prefix sweep.' );
		}
	}
}
