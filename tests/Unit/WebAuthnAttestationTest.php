<?php
/**
 * Unit tests for the 2.1.35 attestation / identification layer.
 *
 * Covers AAGUID extraction and formatting, the AAGUID-to-model registry,
 * the fail-open packed-attestation verification (self-attestation path),
 * the opaque user handle, and the RP-ID / origin flexibility filters.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.35
 */

namespace {

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Att' ) ) {
		/**
		 * Constants-only Two_Factor stub for loading the WebAuthn class.
		 */
		class ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Att {
			const METHOD_WEBAUTHN           = 'webauthn';
			const META_WEBAUTHN_ENABLED     = 'reportedip_hive_2fa_webauthn_enabled';
			const META_WEBAUTHN_CREDENTIALS = 'reportedip_hive_2fa_webauthn_credentials';
			const NONCE_COOKIE              = 'reportedip_2fa_token';
			const NONCE_PREFIX              = 'reportedip_2fa_nonce_';
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor', false ) ) {
		class_alias( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Att', 'ReportedIP_Hive_Two_Factor' );
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-webauthn.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-webauthn-aaguid-registry.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Two_Factor_WebAuthn;
	use ReportedIP_Hive_WebAuthn_Aaguid_Registry;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class WebAuthnAttestationTest extends TestCase {

		/**
		 * Static throwaway P-256 key shared with WebAuthnAssertionTest.
		 */
		private const FIXTURE_EC_PEM = <<<'PEM'
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGZcH9vfxPOJ1rWgJBXKun4e8gDEyIRUNzJ8+t6La9EioAoGCCqGSM49
AwEHoUQDQgAEgA9iyGDCCaVf+zN1PtCks6n5GgE3rtT3TvI2EFxEKsGRVorYo9Wy
1CBJ+8QYHG0gNqEAGewmoHtY/HI7OhYHbQ==
-----END EC PRIVATE KEY-----
PEM;

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_transients'] = array();
			$GLOBALS['wp_user_meta']  = array();
			$GLOBALS['wp_filters']    = array();
		}

		/**
		 * Invoke a private static method on the WebAuthn class.
		 *
		 * @param string $name Method name.
		 * @param mixed  ...$args Arguments.
		 * @return mixed
		 */
		private function call( string $name, ...$args ) {
			$method = new \ReflectionMethod( ReportedIP_Hive_Two_Factor_WebAuthn::class, $name );
			return $method->invoke( null, ...$args );
		}

		/**
		 * Assemble attested authenticatorData with a given AAGUID.
		 *
		 * @param string $aaguid_bytes 16 raw bytes.
		 * @param string $cose         Trailing COSE key CBOR.
		 * @return string
		 */
		private function attested_auth_data( string $aaguid_bytes, string $cose = "\xa1\x01\x02" ): string {
			$cred_id = random_bytes( 16 );
			return hash( 'sha256', 'example.org', true ) . chr( 0x41 ) . pack( 'N', 1 )
				. $aaguid_bytes . pack( 'n', strlen( $cred_id ) ) . $cred_id . $cose;
		}

		public function test_aaguid_is_extracted_and_formatted(): void {
			$aaguid = hex2bin( '2fc0579f811347eab116bb5a8db9202a' );
			$parsed = $this->call( 'parse_authenticator_data', $this->attested_auth_data( $aaguid ) );
			$this->assertIsArray( $parsed );
			$this->assertSame( '2fc0579f-8113-47ea-b116-bb5a8db9202a', $parsed['aaguid'] );
		}

		public function test_zero_aaguid_renders_empty(): void {
			$parsed = $this->call( 'parse_authenticator_data', $this->attested_auth_data( str_repeat( "\0", 16 ) ) );
			$this->assertIsArray( $parsed );
			$this->assertSame( '', $parsed['aaguid'], 'The zero AAGUID (attestation stripped) must read as absent.' );
		}

		public function test_registry_resolves_yubikey_models(): void {
			$info = ReportedIP_Hive_WebAuthn_Aaguid_Registry::lookup( '2fc0579f-8113-47ea-b116-bb5a8db9202a' );
			$this->assertNotNull( $info );
			$this->assertStringContainsString( 'YubiKey 5', $info['label'] );
			$this->assertSame( 'key', $info['icon'] );

			$hello = ReportedIP_Hive_WebAuthn_Aaguid_Registry::lookup( '08987058-cadc-4b81-b6e1-30de50dcbe96' );
			$this->assertNotNull( $hello );
			$this->assertSame( 'Windows Hello', $hello['label'] );
			$this->assertSame( 'device', $hello['icon'] );

			$this->assertNull( ReportedIP_Hive_WebAuthn_Aaguid_Registry::lookup( '00000000-0000-0000-0000-000000000000' ) );
			$this->assertNull( ReportedIP_Hive_WebAuthn_Aaguid_Registry::lookup( 'ffffffff-ffff-ffff-ffff-ffffffffffff' ) );
			$this->assertNull( ReportedIP_Hive_WebAuthn_Aaguid_Registry::lookup( '' ) );
		}

		public function test_packed_self_attestation_verifies_and_fails_open(): void {
			$key     = openssl_pkey_get_private( self::FIXTURE_EC_PEM );
			$details = openssl_pkey_get_details( $key );
			$x       = str_pad( $details['ec']['x'], 32, "\0", STR_PAD_LEFT );
			$y       = str_pad( $details['ec']['y'], 32, "\0", STR_PAD_LEFT );
			$cose    = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" . $x . "\x22\x58\x20" . $y;

			$auth_data        = $this->attested_auth_data( random_bytes( 16 ), $cose );
			$client_data_hash = hash( 'sha256', 'client-data', true );
			openssl_sign( $auth_data . $client_data_hash, $sig, $key, OPENSSL_ALGO_SHA256 );

			$att_map = array(
				'fmt'      => 'packed',
				'authData' => $auth_data,
				'attStmt'  => array(
					'alg' => -7,
					'sig' => $sig,
				),
			);
			$this->assertTrue( $this->call( 'verify_packed_attestation', $att_map, $client_data_hash ) );

			$tampered                  = $att_map;
			$tampered['attStmt']['sig'][8] = chr( ord( $sig[8] ) ^ 0xff );
			$this->assertFalse(
				$this->call( 'verify_packed_attestation', $tampered, $client_data_hash ),
				'A tampered statement must simply read as unverified — never as an error that blocks registration.'
			);

			$none = array(
				'fmt'      => 'none',
				'authData' => $auth_data,
				'attStmt'  => array(),
			);
			$this->assertFalse( $this->call( 'verify_packed_attestation', $none, $client_data_hash ) );
		}

		public function test_user_handle_is_opaque_and_stable(): void {
			$first  = ReportedIP_Hive_Two_Factor_WebAuthn::user_handle( 55 );
			$second = ReportedIP_Hive_Two_Factor_WebAuthn::user_handle( 55 );
			$this->assertSame( $first, $second, 'The handle must be minted once and reused.' );
			$this->assertNotSame( ReportedIP_Hive_Two_Factor_WebAuthn::b64url_encode( '55' ), $first );
			$this->assertSame( 16, strlen( (string) ReportedIP_Hive_Two_Factor_WebAuthn::b64url_decode( $first ) ) );
			$this->assertNotSame( $first, ReportedIP_Hive_Two_Factor_WebAuthn::user_handle( 56 ) );
		}

		public function test_allowed_origins_include_home_and_filter_additions(): void {
			$origins = ReportedIP_Hive_Two_Factor_WebAuthn::allowed_origins();
			$this->assertContains( 'https://example.org', $origins );

			$GLOBALS['wp_filters']['reportedip_hive_webauthn_allowed_origins'] = array(
				array(
					'callback'      => static function ( $list ) {
						$list[] = 'https://admin.example.org/';
						return $list;
					},
					'accepted_args' => 1,
				),
			);
			$origins = ReportedIP_Hive_Two_Factor_WebAuthn::allowed_origins();
			$this->assertContains( 'https://admin.example.org', $origins, 'Filter additions must be normalised (trailing slash stripped).' );
		}

		public function test_rp_id_filter_overrides_host(): void {
			$this->assertSame( 'example.org', ReportedIP_Hive_Two_Factor_WebAuthn::rp_id() );
			$GLOBALS['wp_filters']['reportedip_hive_webauthn_rp_id'] = array(
				array(
					'callback'      => static function () {
						return 'example.net';
					},
					'accepted_args' => 1,
				),
			);
			$this->assertSame( 'example.net', ReportedIP_Hive_Two_Factor_WebAuthn::rp_id() );
		}
	}
}
