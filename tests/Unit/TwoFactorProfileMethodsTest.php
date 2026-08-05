<?php
/**
 * Unit tests for the shared 2FA method-activation layer behind the profile
 * section, the onboarding wizard and WebAuthn key registration.
 *
 * Two layers:
 *   1. Behaviour tests drive the real ReportedIP_Hive_Two_Factor statics
 *      (activate_method, set_user_method) against the option + user-meta
 *      stubs from the unit bootstrap, with a recovery-code stub that counts
 *      regenerations — adding a second method must never destroy existing
 *      recovery codes or clobber the user's chosen default method.
 *   2. Source-pattern tests lock down that every enrolment surface routes
 *      through activate_method(), that TOTP setup refuses to silently
 *      replace a confirmed secret, and that the default-method and
 *      disable-method AJAX endpoints stay wired.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.36
 */

namespace {

	if ( ! defined( 'DAY_IN_SECONDS' ) ) {
		define( 'DAY_IN_SECONDS', 86400 );
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Recovery', false ) ) {
		/**
		 * Recovery stub: remaining count comes from a global, regenerations
		 * are counted so tests can assert codes were (not) destroyed.
		 */
		class ReportedIP_Hive_Two_Factor_Recovery {
			/**
			 * Remaining-code count from the test-controlled global.
			 *
			 * @param int $user_id User id.
			 * @return int
			 */
			public static function get_remaining_count( $user_id ) {
				return (int) ( $GLOBALS['rip_test_recovery_remaining'][ $user_id ] ?? 0 );
			}

			/**
			 * Count the regeneration and refill the stub balance.
			 *
			 * @param int $user_id User id.
			 * @return string[]
			 */
			public static function regenerate_codes( $user_id ) {
				$GLOBALS['rip_test_recovery_regenerations'][ $user_id ] =
					( $GLOBALS['rip_test_recovery_regenerations'][ $user_id ] ?? 0 ) + 1;
				$GLOBALS['rip_test_recovery_remaining'][ $user_id ] = 10;
				return array( 'aaaa-bbbb' );
			}

			/**
			 * Disable-path helper, unused in these tests.
			 *
			 * @param int $user_id User id.
			 */
			public static function delete_codes( $user_id ) {}
		}
	}

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor', false ) ) {
		require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor.php';
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Isolation: exercises the real ReportedIP_Hive_Two_Factor statics against
	 * the lightweight option / user-meta stubs from the unit bootstrap. Runs in
	 * separate processes so the private static methods cache and the global
	 * meta buckets cannot leak between cases.
	 *
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorProfileMethodsTest extends TestCase {

		private const USER_ID = 7;

		/**
		 * Reset the in-memory option / user-meta / recovery buckets.
		 */
		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']                    = array();
			$GLOBALS['wp_user_meta']                  = array();
			$GLOBALS['rip_test_recovery_remaining']   = array();
			$GLOBALS['rip_test_recovery_regenerations'] = array();
		}

		/**
		 * Plugin-root file source for wiring guards.
		 *
		 * @param string $relative Relative path.
		 * @return string
		 */
		private function source( string $relative ): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
		}

		/**
		 * Extract one method body from a source string.
		 *
		 * @param string $source Source code.
		 * @param string $name   Method name.
		 * @return string
		 */
		private function method_body( string $source, string $name ): string {
			$start = strpos( $source, 'function ' . $name . '(' );
			$this->assertNotFalse( $start, "Method {$name} must exist." );
			$end = strpos( $source, "\n\t/**", $start );
			return substr( $source, $start, ( false === $end ? strlen( $source ) : $end ) - $start );
		}

		public function test_first_method_activates_full_2fa(): void {
			$codes = \ReportedIP_Hive_Two_Factor::activate_method( self::USER_ID, 'totp' );
			$this->assertIsArray( $codes, 'The first method must hand the fresh recovery codes back to the caller.' );

			$meta = $GLOBALS['wp_user_meta'][ self::USER_ID ];
			$this->assertSame( '1', $meta['reportedip_hive_2fa_enabled'] );
			$this->assertSame( 'totp', $meta['reportedip_hive_2fa_method'] );
			$this->assertSame( '1', $meta['reportedip_hive_2fa_totp_enabled'] );
			$this->assertSame(
				1,
				$GLOBALS['rip_test_recovery_regenerations'][ self::USER_ID ] ?? 0,
				'The first method must provision recovery codes.'
			);
		}

		public function test_additional_method_preserves_primary_and_recovery_codes(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ] = array(
				'reportedip_hive_2fa_enabled'       => '1',
				'reportedip_hive_2fa_method'        => 'email',
				'reportedip_hive_2fa_email_enabled' => '1',
			);
			$GLOBALS['rip_test_recovery_remaining'][ self::USER_ID ] = 8;

			$this->assertNull(
				\ReportedIP_Hive_Two_Factor::activate_method( self::USER_ID, 'totp' ),
				'No fresh codes may be returned while existing codes survive.'
			);

			$meta = $GLOBALS['wp_user_meta'][ self::USER_ID ];
			$this->assertSame( '1', $meta['reportedip_hive_2fa_totp_enabled'] );
			$this->assertSame(
				'email',
				$meta['reportedip_hive_2fa_method'],
				'Adding a second method must not clobber the chosen default method.'
			);
			$this->assertSame(
				0,
				$GLOBALS['rip_test_recovery_regenerations'][ self::USER_ID ] ?? 0,
				'Adding a second method must not destroy existing recovery codes.'
			);
			$this->assertSame(
				array( 'totp', 'email' ),
				\ReportedIP_Hive_Two_Factor::get_user_enabled_methods( self::USER_ID ),
				'The methods cache must be flushed so the new method is visible in-request.'
			);
		}

		public function test_additional_method_refills_exhausted_recovery_codes(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ] = array(
				'reportedip_hive_2fa_enabled'       => '1',
				'reportedip_hive_2fa_method'        => 'email',
				'reportedip_hive_2fa_email_enabled' => '1',
			);
			$GLOBALS['rip_test_recovery_remaining'][ self::USER_ID ] = 0;

			\ReportedIP_Hive_Two_Factor::activate_method( self::USER_ID, 'totp' );

			$this->assertSame( 1, $GLOBALS['rip_test_recovery_regenerations'][ self::USER_ID ] ?? 0 );
		}

		public function test_activate_method_rejects_unknown_method(): void {
			$this->assertFalse( \ReportedIP_Hive_Two_Factor::activate_method( self::USER_ID, 'carrier-pigeon' ) );
			$this->assertArrayNotHasKey( self::USER_ID, $GLOBALS['wp_user_meta'] );
		}

		public function test_set_user_method_rejects_inactive_method(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ] = array(
				'reportedip_hive_2fa_method'       => 'totp',
				'reportedip_hive_2fa_totp_enabled' => '1',
			);

			$this->assertFalse( \ReportedIP_Hive_Two_Factor::set_user_method( self::USER_ID, 'email' ) );
			$this->assertSame( 'totp', $GLOBALS['wp_user_meta'][ self::USER_ID ]['reportedip_hive_2fa_method'] );
		}

		public function test_set_user_method_stores_active_method(): void {
			$GLOBALS['wp_user_meta'][ self::USER_ID ] = array(
				'reportedip_hive_2fa_method'        => 'totp',
				'reportedip_hive_2fa_totp_enabled'  => '1',
				'reportedip_hive_2fa_email_enabled' => '1',
			);

			$this->assertTrue( \ReportedIP_Hive_Two_Factor::set_user_method( self::USER_ID, 'email' ) );
			$this->assertSame( 'email', \ReportedIP_Hive_Two_Factor::get_user_method( self::USER_ID ) );
		}

		public function test_every_enrolment_surface_routes_through_activate_method(): void {
			$admin    = $this->source( 'admin/class-two-factor-admin.php' );
			$webauthn = $this->source( 'includes/class-two-factor-webauthn.php' );

			$this->assertSame(
				3,
				substr_count( $admin, '::activate_method(' ),
				'TOTP, email and SMS enrolment must all use the shared activation path.'
			);
			$this->assertSame( 1, substr_count( $webauthn, '::activate_method(' ) );
			$this->assertStringNotContainsString(
				'enable_for_user(',
				$admin,
				'No enrolment endpoint may call enable_for_user directly — it clobbers the default method.'
			);
			$this->assertStringNotContainsString( 'enable_for_user(', $webauthn );
		}

		public function test_confirm_totp_no_longer_destroys_recovery_codes(): void {
			$body = $this->method_body( $this->source( 'admin/class-two-factor-admin.php' ), 'ajax_confirm_totp' );

			$this->assertStringContainsString(
				'activate_method',
				$body,
				'confirm_totp must use the shared activation path, which only mints codes when the user has none.'
			);
			$this->assertStringNotContainsString(
				'regenerate_codes',
				$body,
				'confirm_totp must not regenerate recovery codes itself.'
			);
		}

		public function test_setup_totp_refuses_silent_secret_replacement(): void {
			$body = $this->method_body( $this->source( 'admin/class-two-factor-admin.php' ), 'ajax_setup_totp' );

			$this->assertStringContainsString(
				'totp_already_configured',
				$body,
				'A confirmed authenticator connection must not be overwritten without the explicit replace flag.'
			);
			$this->assertStringContainsString( "\$_POST['replace']", $body );
		}

		public function test_profile_management_endpoints_are_wired(): void {
			$admin = $this->source( 'admin/class-two-factor-admin.php' );

			$this->assertStringContainsString( 'wp_ajax_reportedip_hive_2fa_set_primary_method', $admin );
			$this->assertStringContainsString( 'wp_ajax_reportedip_hive_2fa_disable_method', $admin );
		}
	}
}
