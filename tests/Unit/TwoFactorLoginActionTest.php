<?php
/**
 * Locks the login hooks fired after a passed 2FA challenge.
 *
 * A challenged sign-in never runs through `wp_signon()`: the authenticate
 * filter redirects into the challenge first, so core never reaches its
 * `wp_login` call. Until 2.1.51 the plugin issued the auth cookie itself and
 * fired nothing, which left every login listener (audit trail, geo anomaly,
 * new-device mail, 2FA reminder reset) blind to exactly the logins that had
 * proven the most. Both sign-in surfaces must now fire
 * `reportedip_hive_2fa_verified` and then `wp_login`; the consumed-nonce
 * replay must not fire them a second time, and the password-only REST
 * sign-in must fire `wp_login` as well.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * Source-inspection guard for the post-challenge login hooks.
	 *
	 * @since 2.1.51
	 */
	class TwoFactorLoginActionTest extends TestCase {

		const LOGIN_ACTION = 'do_action( \'wp_login\', $user->user_login, $user );';

		/**
		 * Plugin source of one file under includes/, with line endings normalised.
		 *
		 * @param string $file File name below includes/.
		 * @return string
		 */
		private function source( string $file ): string {
			$raw = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/' . $file );
			return str_replace( "\r\n", "\n", $raw );
		}

		/**
		 * The two sign-in surfaces: file, expected plugin action call, expected wp_login count.
		 *
		 * @return array<string,array<int,string|int>>
		 */
		public static function surfaces(): array {
			return array(
				'browser challenge' => array(
					'class-two-factor.php',
					'do_action( \'reportedip_hive_2fa_verified\', (int) $user_id, (string) $method, (string) $context );',
					1,
				),
				'rest verify'       => array(
					'class-two-factor-rest.php',
					'do_action( \'reportedip_hive_2fa_verified\', (int) $user_id, (string) $method, \'rest\' );',
					2,
				),
			);
		}

		/**
		 * Every sign-in surface fires the plugin action first and wp_login right after it.
		 *
		 * @dataProvider surfaces
		 *
		 * @param string $file          File name below includes/.
		 * @param string $verified_call Exact plugin action call expected once.
		 * @param int    $login_calls   Expected number of wp_login calls in the file.
		 */
		public function test_surface_fires_verified_then_wp_login( string $file, string $verified_call, int $login_calls ): void {
			$source = $this->source( $file );

			$this->assertSame(
				1,
				substr_count( $source, $verified_call ),
				"{$file} must fire reportedip_hive_2fa_verified exactly once with user id, verified method and the surface context (the replay path re-issues the same session and must stay silent)."
			);
			$this->assertSame(
				$login_calls,
				substr_count( $source, self::LOGIN_ACTION ),
				"{$file} must fire wp_login with the wp_signon() signature on every sign-in path it owns."
			);

			$verified = strpos( $source, $verified_call );
			$login    = strpos( $source, self::LOGIN_ACTION, (int) $verified );

			$this->assertNotFalse( $verified );
			$this->assertNotFalse( $login, "{$file} must fire wp_login after reportedip_hive_2fa_verified." );
			$this->assertLessThan(
				400,
				$login - $verified,
				"{$file} must fire wp_login right after reportedip_hive_2fa_verified so listeners can read the verified method first."
			);
		}

		/**
		 * The browser hooks fire after the session exists and before the device is trusted.
		 *
		 * Geo_Anomaly::on_login() may revoke every trusted device of the user;
		 * firing wp_login after create_trusted_device() would silently void the
		 * "trust this device" choice made on this very login.
		 */
		public function test_browser_hooks_fire_after_cookie_and_before_device_trust(): void {
			$source = $this->source( 'class-two-factor.php' );
			$login  = strpos( $source, self::LOGIN_ACTION );
			$cookie = strpos( $source, '$this->set_auth_cookie_with_remember( $user_id, $remember );' );
			$trust  = strpos( $source, '$this->create_trusted_device( $user_id );' );

			$this->assertNotFalse( $login );
			$this->assertNotFalse( $cookie );
			$this->assertNotFalse( $trust );
			$this->assertLessThan( $login, $cookie, 'wp_login must fire after the auth cookie is set, as wp_signon() does.' );
			$this->assertLessThan( $trust, $login, 'wp_login must fire before the trusted-device row is created.' );
		}

		/**
		 * The REST surface resolves a WP_User before firing, since only the id is in scope.
		 */
		public function test_rest_surface_resolves_user_before_firing(): void {
			$source   = $this->source( 'class-two-factor-rest.php' );
			$lookup   = strpos( $source, '$user = get_userdata( $user_id );' );
			$verified = strpos( $source, 'do_action( \'reportedip_hive_2fa_verified\'' );
			$login    = strpos( $source, self::LOGIN_ACTION, (int) $verified );

			$this->assertNotFalse( $lookup );
			$this->assertNotFalse( $login );
			$this->assertLessThan( $login, $lookup, 'wp_login needs the WP_User object; the REST verify route only holds the id.' );
		}

		/**
		 * The password-only REST sign-in (no second factor configured) fires wp_login as well.
		 */
		public function test_rest_password_only_sign_in_fires_wp_login(): void {
			$source = $this->source( 'class-two-factor-rest.php' );
			$cookie = strpos( $source, 'wp_set_auth_cookie( $user->ID, false );' );
			$login  = strpos( $source, self::LOGIN_ACTION, (int) $cookie );
			$reply  = strpos( $source, "'status'  => 'authenticated'" );

			$this->assertNotFalse( $cookie );
			$this->assertNotFalse( $login );
			$this->assertNotFalse( $reply );
			$this->assertLessThan( $reply, $login, 'The /2fa/challenge password-only branch must fire wp_login before answering.' );
		}
	}
}
