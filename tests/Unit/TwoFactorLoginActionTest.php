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
 * replay must not fire them a second time.
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
		 * The two sign-in surfaces, keyed by file with the full expected plugin action call.
		 *
		 * @return array<string,array<int,string>>
		 */
		public static function surfaces(): array {
			return array(
				'browser challenge' => array(
					'class-two-factor.php',
					'do_action( \'reportedip_hive_2fa_verified\', (int) $user_id, (string) $method, (string) $context );',
				),
				'rest verify'       => array(
					'class-two-factor-rest.php',
					'do_action( \'reportedip_hive_2fa_verified\', (int) $user_id, (string) $method, \'rest\' );',
				),
			);
		}

		/**
		 * Every sign-in surface fires the plugin action first and wp_login second, exactly once.
		 *
		 * @dataProvider surfaces
		 */
		public function test_surface_fires_verified_then_wp_login_once( string $file, string $verified_call ): void {
			$source = $this->source( $file );

			$this->assertSame(
				1,
				substr_count( $source, $verified_call ),
				"{$file} must fire reportedip_hive_2fa_verified exactly once with user id, verified method and the surface context (the replay path re-issues the same session and must stay silent)."
			);
			$this->assertSame(
				1,
				substr_count( $source, self::LOGIN_ACTION ),
				"{$file} must fire wp_login with the wp_signon() signature exactly once."
			);
			$this->assertLessThan(
				strpos( $source, self::LOGIN_ACTION ),
				strpos( $source, $verified_call ),
				"{$file} must fire reportedip_hive_2fa_verified before wp_login so listeners can read the verified method first."
			);
		}

		/**
		 * The browser hooks fire after the session exists and before the browser is sent on.
		 */
		public function test_browser_hooks_fire_after_cookie_and_before_redirect(): void {
			$source = $this->source( 'class-two-factor.php' );
			$login  = strpos( $source, self::LOGIN_ACTION );
			$cookie = strpos( $source, '$this->set_auth_cookie_with_remember( $user_id, $remember );' );

			$this->assertNotFalse( $login );
			$this->assertNotFalse( $cookie );
			$this->assertLessThan( $login, $cookie, 'wp_login must fire after the auth cookie is set, as wp_signon() does.' );
			$this->assertStringStartsWith(
				self::LOGIN_ACTION . "\n\n\t\t\t\t\t\twp_safe_redirect( \$redirect_to );\n\t\t\t\t\t\texit;",
				substr( $source, $login ),
				'The success branch must still end in the post-verify redirect right after the hooks fired.'
			);
		}

		/**
		 * The REST surface resolves a WP_User before firing, since only the id is in scope.
		 */
		public function test_rest_surface_resolves_user_before_firing(): void {
			$source = $this->source( 'class-two-factor-rest.php' );
			$lookup = strpos( $source, '$user = get_userdata( $user_id );' );
			$login  = strpos( $source, self::LOGIN_ACTION );

			$this->assertNotFalse( $lookup );
			$this->assertNotFalse( $login );
			$this->assertLessThan( $login, $lookup, 'wp_login needs the WP_User object; the REST verify route only holds the id.' );
		}
	}
}
