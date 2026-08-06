<?php
/**
 * Unit tests for the 2.1.34 security-key management layer.
 *
 * Covers the behavioural pieces that run without a browser:
 *
 *   1. Ed25519 (EdDSA, COSE -8) assertions verify through libsodium and the
 *      algorithm is only offered while sodium is available.
 *   2. keys_for_display() never leaks the public key and formats dates.
 *   3. Registration parameters: residentKey stays 'discouraged', hints map
 *      to authenticatorAttachment.
 *   4. Wiring guards (source-pattern): rate limiting on the login AJAX
 *      endpoints, the CLI lockout guard, and the notification hooks.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.34
 */

namespace {

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Mgmt' ) ) {
		/**
		 * Constants-only Two_Factor stub for loading the WebAuthn class.
		 */
		class ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Mgmt {
			const METHOD_WEBAUTHN           = 'webauthn';
			const META_WEBAUTHN_ENABLED     = 'reportedip_hive_2fa_webauthn_enabled';
			const META_WEBAUTHN_CREDENTIALS = 'reportedip_hive_2fa_webauthn_credentials';
			const NONCE_COOKIE              = 'reportedip_2fa_token';
			const NONCE_PREFIX              = 'reportedip_2fa_nonce_';
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor', false ) ) {
		class_alias( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Mgmt', 'ReportedIP_Hive_Two_Factor' );
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
	class WebAuthnKeyManagementTest extends TestCase {

		private const USER_ID = 11;

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_transients'] = array();
			$GLOBALS['wp_user_meta']  = array();
			$GLOBALS['wp_filters']    = array();
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

		public function test_ed25519_assertion_verifies_via_sodium(): void {
			if ( ! function_exists( 'sodium_crypto_sign_keypair' ) ) {
				$this->markTestSkipped( 'libsodium is unavailable.' );
			}

			$pair = sodium_crypto_sign_keypair();
			$pk   = sodium_crypto_sign_publickey( $pair );
			$sk   = sodium_crypto_sign_secretkey( $pair );

			$cose_okp = "\xa4\x01\x01\x03\x27\x20\x06\x21\x58\x20" . $pk;
			$cred_id  = ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( random_bytes( 16 ) );
			update_user_meta(
				self::USER_ID,
				\ReportedIP_Hive_Two_Factor::META_WEBAUTHN_CREDENTIALS,
				wp_json_encode(
					array(
						array(
							'id'         => $cred_id,
							'public_key' => base64_encode( $cose_okp ),
							'sign_count' => 0,
							'created_at' => time(),
							'transports' => array( 'usb' ),
							'name'       => 'Ed25519 key',
						),
					)
				)
			);

			$challenge = random_bytes( 32 );
			set_transient( 'reportedip_2fa_webauthn_login_' . self::USER_ID, base64_encode( $challenge ), 300 );

			$client_data_json = (string) wp_json_encode(
				array(
					'type'      => 'webauthn.get',
					'challenge' => ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $challenge ),
					'origin'    => 'https://example.org',
				)
			);
			$auth_data        = hash( 'sha256', 'example.org', true ) . chr( 0x01 ) . pack( 'N', 9 );
			$signature        = sodium_crypto_sign_detached( $auth_data . hash( 'sha256', $client_data_json, true ), $sk );

			$assertion = array(
				'id'       => $cred_id,
				'type'     => 'public-key',
				'response' => array(
					'clientDataJSON'    => ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $client_data_json ),
					'authenticatorData' => ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $auth_data ),
					'signature'         => ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $signature ),
				),
			);

			$method = new \ReflectionMethod( ReportedIP_Hive_Two_Factor_WebAuthn::class, 'verify_assertion' );
			$this->assertTrue( $method->invoke( null, self::USER_ID, $assertion ) );

			$flipped                            = $assertion;
			$raw                                = ReportedIP_Hive_Two_Factor_WebAuthn::b64url_decode( $assertion['response']['signature'] );
			$raw[3]                             = chr( ord( $raw[3] ) ^ 0xff );
			$flipped['response']['signature']   = ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( $raw );
			set_transient( 'reportedip_2fa_webauthn_login_' . self::USER_ID, base64_encode( $challenge ), 300 );
			$result = $method->invoke( null, self::USER_ID, $flipped );
			$this->assertInstanceOf( \WP_Error::class, $result );
		}

		public function test_pub_key_cred_params_offer_eddsa_first_when_sodium_present(): void {
			if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
				$this->markTestSkipped( 'libsodium is unavailable.' );
			}
			$method = new \ReflectionMethod( ReportedIP_Hive_Two_Factor_WebAuthn::class, 'pub_key_cred_params' );
			$algs = array_column( $method->invoke( null ), 'alg' );
			$this->assertSame( array( -8, -7, -257 ), $algs );
		}

		public function test_authenticator_selection_defaults_and_hints(): void {
			$method = new \ReflectionMethod( ReportedIP_Hive_Two_Factor_WebAuthn::class, 'authenticator_selection' );

			$plain = $method->invoke( null, '' );
			$this->assertSame( 'discouraged', $plain['residentKey'], 'residentKey must stay discouraged — preferred would consume YubiKey slots and force PIN setup.' );
			$this->assertArrayNotHasKey( 'authenticatorAttachment', $plain );

			$hardware = $method->invoke( null, 'security-key' );
			$this->assertSame( 'cross-platform', $hardware['authenticatorAttachment'] );

			$platform = $method->invoke( null, 'client-device' );
			$this->assertSame( 'platform', $platform['authenticatorAttachment'] );
		}

		public function test_keys_for_display_never_exposes_public_key(): void {
			update_user_meta(
				self::USER_ID,
				\ReportedIP_Hive_Two_Factor::META_WEBAUTHN_CREDENTIALS,
				wp_json_encode(
					array(
						array(
							'id'         => 'abc123',
							'public_key' => base64_encode( 'SECRET-KEY-MATERIAL' ),
							'sign_count' => 7,
							'created_at' => 1700000000,
							'last_used'  => 1700000500,
							'transports' => array( 'usb', 'nfc' ),
							'name'       => 'Office key',
						),
						array(
							'id'         => 'def456',
							'public_key' => base64_encode( 'MORE-KEY-MATERIAL' ),
							'sign_count' => 0,
						),
					)
				)
			);

			$keys = ReportedIP_Hive_Two_Factor_WebAuthn::keys_for_display( self::USER_ID );
			$this->assertCount( 2, $keys );
			foreach ( $keys as $key ) {
				$this->assertArrayNotHasKey( 'public_key', $key );
				$this->assertArrayNotHasKey( 'sign_count', $key );
			}
			$this->assertSame( 'Office key', $keys[0]['name'] );
			$this->assertNotSame( '', $keys[0]['created_at'] );
			$this->assertSame( array( 'usb', 'nfc' ), $keys[0]['transports'] );
			$this->assertSame( '', $keys[1]['last_used'], 'A never-used key must render an empty last_used.' );
			$this->assertNotSame( '', $keys[1]['name'], 'Records without a name fall back to a generic label.' );
		}

		public function test_sanitize_transports_filters_unknown_values(): void {
			$this->assertSame(
				array( 'usb', 'nfc' ),
				ReportedIP_Hive_Two_Factor_WebAuthn::sanitize_transports( array( 'usb', 'nfc', 'usb', 'teleport', 123, array( 'x' ) ) )
			);
			$this->assertSame( array(), ReportedIP_Hive_Two_Factor_WebAuthn::sanitize_transports( 'not-an-array' ) );
			$this->assertSame( array( 'smart-card' ), ReportedIP_Hive_Two_Factor_WebAuthn::sanitize_transports( array( 'smart-card' ) ) );
		}

		public function test_login_endpoints_are_rate_limited(): void {
			$source = $this->source( 'includes/class-two-factor-webauthn.php' );
			$this->assertSame(
				2,
				substr_count( $source, 'self::reject_when_ip_locked_out();' ),
				'Both login AJAX endpoints must check the shared per-IP lockout ladder at entry.'
			);
			$this->assertStringContainsString(
				'ReportedIP_Hive_Two_Factor::record_ip_failure',
				$source,
				'A failed AJAX assertion must feed the same ladder as a wrong form code.'
			);
		}

		public function test_cli_refuses_credential_less_webauthn_enable(): void {
			$source = $this->source( 'includes/class-two-factor-cli.php' );
			$this->assertStringContainsString( 'get_user_credentials', $source );
			$this->assertStringContainsString(
				"empty( \$assoc['force'] )",
				$source,
				'CLI enable --method=webauthn must refuse without credentials unless --force is passed (lockout footgun).'
			);
		}

		public function test_notifications_wire_the_key_lifecycle_hooks(): void {
			$source = $this->source( 'includes/class-two-factor-notifications.php' );
			$this->assertStringContainsString( 'reportedip_hive_2fa_webauthn_key_registered', $source );
			$this->assertStringContainsString( 'reportedip_hive_2fa_webauthn_key_removed', $source );
			$this->assertStringContainsString( 'reportedip_hive_2fa_webauthn_counter_regression', $source );
		}

		public function test_first_key_is_free_and_more_keys_are_gated(): void {
			$this->assertTrue(
				ReportedIP_Hive_Two_Factor_WebAuthn::can_add_key( self::USER_ID ),
				'The first key must always be allowed — base 2FA protection is never gated.'
			);

			update_user_meta(
				self::USER_ID,
				\ReportedIP_Hive_Two_Factor::META_WEBAUTHN_CREDENTIALS,
				wp_json_encode( array( array( 'id' => 'abc' ) ) )
			);
			$this->assertFalse(
				ReportedIP_Hive_Two_Factor_WebAuthn::can_add_key( self::USER_ID ),
				'Without the Business webauthn_advanced feature a second key must be refused (fail-closed when Mode_Manager is absent).'
			);
		}

		public function test_webauthn_advanced_is_business_gated_in_the_feature_matrix(): void {
			$source = $this->source( 'includes/class-mode-manager.php' );
			$this->assertStringContainsString( "'webauthn_advanced'", $source );
			$position = strpos( $source, "'webauthn_advanced'" );
			$window   = substr( $source, $position, 220 );
			$this->assertStringContainsString(
				"'requires_tier' => 'business'",
				$window,
				'webauthn_advanced must be Business-gated (decision 2026-08-05, PRICING-PLAN.md history 1.9).'
			);
		}

		public function test_register_endpoints_enforce_the_key_limit_server_side(): void {
			$source = $this->source( 'includes/class-two-factor-webauthn.php' );
			$this->assertSame(
				2,
				substr_count( $source, 'self::can_add_key( $user_id )' ),
				'Both register endpoints (options + verify) must enforce the tier key limit — the UI hint alone is not a gate.'
			);
		}

		public function test_lifecycle_mails_are_gated_but_clone_warning_is_not(): void {
			$source = $this->source( 'includes/class-two-factor-notifications.php' );
			$registered = substr( $source, strpos( $source, 'function on_key_registered' ), 400 );
			$removed    = substr( $source, strpos( $source, 'function on_key_removed' ), 400 );
			$regression = substr( $source, strpos( $source, 'function on_counter_regression' ), 500 );
			$this->assertStringContainsString( 'advanced_available', $registered );
			$this->assertStringContainsString( 'advanced_available', $removed );
			$this->assertStringNotContainsString(
				'advanced_available',
				$regression,
				'The cloned-key warning is protection, not comfort — it must reach every tier.'
			);
		}
	}
}
