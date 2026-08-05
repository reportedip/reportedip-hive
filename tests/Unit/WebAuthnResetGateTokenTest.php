<?php
/**
 * Unit tests for the WebAuthn ceremony-token bridge.
 *
 * The password-reset gate has no login-nonce cookie, so it mints an opaque
 * token via mint_login_token() and the browser posts it back to the
 * assertion AJAX endpoints. These tests pin the mint → resolve → expiry
 * contract and the precedence of the cookie path over the token path.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.33
 */

namespace {

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Token' ) ) {
		/**
		 * Constants-only Two_Factor stub for loading the WebAuthn class.
		 */
		class ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Token {
			const METHOD_WEBAUTHN           = 'webauthn';
			const META_WEBAUTHN_ENABLED     = 'reportedip_hive_2fa_webauthn_enabled';
			const META_WEBAUTHN_CREDENTIALS = 'reportedip_hive_2fa_webauthn_credentials';
			const NONCE_COOKIE              = 'reportedip_2fa_token';
			const NONCE_PREFIX              = 'reportedip_2fa_nonce_';
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor', false ) ) {
		class_alias( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Token', 'ReportedIP_Hive_Two_Factor' );
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-webauthn.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Two_Factor_WebAuthn;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class WebAuthnResetGateTokenTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_transients'] = array();
			unset( $_COOKIE['reportedip_2fa_token'] );
		}

		/**
		 * Invoke the private resolver.
		 *
		 * @param string $token Posted ceremony token.
		 * @return int
		 */
		private function resolve( string $token = '' ): int {
			$method = new \ReflectionMethod( ReportedIP_Hive_Two_Factor_WebAuthn::class, 'user_id_from_login_token' );
			$method->setAccessible( true );
			return (int) $method->invoke( null, $token );
		}

		public function test_minted_token_resolves_to_user(): void {
			$token = ReportedIP_Hive_Two_Factor_WebAuthn::mint_login_token( 42 );
			$this->assertNotSame( '', $token );
			$this->assertSame( 42, $this->resolve( $token ) );
		}

		public function test_unknown_token_resolves_to_zero(): void {
			$this->assertSame( 0, $this->resolve( 'not-a-real-token' ) );
			$this->assertSame( 0, $this->resolve( '' ) );
		}

		public function test_token_is_stored_hashed_not_verbatim(): void {
			$token = ReportedIP_Hive_Two_Factor_WebAuthn::mint_login_token( 42 );
			foreach ( array_keys( $GLOBALS['wp_transients'] ) as $key ) {
				$this->assertStringNotContainsString(
					$token,
					$key,
					'The raw token must never appear in a transient key — only its SHA-256.'
				);
			}
			$this->assertSame( 42, $this->resolve( $token ) );
		}

		public function test_expired_token_resolves_to_zero(): void {
			$token = ReportedIP_Hive_Two_Factor_WebAuthn::mint_login_token( 42 );
			$key   = 'reportedip_2fa_webauthn_token_' . hash( 'sha256', $token );
			$this->assertArrayHasKey( $key, $GLOBALS['wp_transients'] );
			$GLOBALS['wp_transients'][ $key ]['expires'] = time() - 10;
			$this->assertSame( 0, $this->resolve( $token ) );
		}

		public function test_cookie_path_wins_over_posted_token(): void {
			$cookie_token                       = 'cookie-token-value';
			$_COOKIE['reportedip_2fa_token']    = $cookie_token;
			$GLOBALS['wp_transients'][ 'reportedip_2fa_nonce_' . hash( 'sha256', $cookie_token ) ] = array(
				'value'   => array( 'user_id' => 7 ),
				'expires' => 0,
			);

			$posted = ReportedIP_Hive_Two_Factor_WebAuthn::mint_login_token( 42 );
			$this->assertSame(
				7,
				$this->resolve( $posted ),
				'When the signed login-nonce cookie is present it must take precedence over any posted token.'
			);
		}
	}
}
