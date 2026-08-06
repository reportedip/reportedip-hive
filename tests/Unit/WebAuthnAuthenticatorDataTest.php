<?php
/**
 * Unit tests for the WebAuthn authenticatorData parser.
 *
 * Locks down the fixed byte layout (WebAuthn L2 §6.1): rpIdHash 0-31,
 * flags 32, signCount 33-36, then AAGUID 37-52, credentialIdLength 53-54
 * and credentialId from 55 when the AT flag is set. Any offset drift here
 * breaks every registration, so the offsets are pinned by fixture.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.33
 */

namespace {

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_AuthData' ) ) {
		/**
		 * Constants-only Two_Factor stub for loading the WebAuthn class.
		 */
		class ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_AuthData {
			const METHOD_WEBAUTHN           = 'webauthn';
			const META_WEBAUTHN_ENABLED     = 'reportedip_hive_2fa_webauthn_enabled';
			const META_WEBAUTHN_CREDENTIALS = 'reportedip_hive_2fa_webauthn_credentials';
			const NONCE_COOKIE              = 'reportedip_2fa_token';
			const NONCE_PREFIX              = 'reportedip_2fa_nonce_';
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor', false ) ) {
		class_alias( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_AuthData', 'ReportedIP_Hive_Two_Factor' );
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
	class WebAuthnAuthenticatorDataTest extends TestCase {

		/**
		 * Invoke the private parser.
		 *
		 * @param string $bytes           Raw authenticatorData.
		 * @param bool   $expect_attested Whether attested credential data is required.
		 * @return array|\WP_Error
		 */
		private function parse( string $bytes, bool $expect_attested = true ) {
			$method = new \ReflectionMethod( ReportedIP_Hive_Two_Factor_WebAuthn::class, 'parse_authenticator_data' );
			return $method->invoke( null, $bytes, $expect_attested );
		}

		/**
		 * Assemble authenticatorData with attested credential data.
		 *
		 * @param string $rp_id_hash 32-byte hash.
		 * @param int    $flags      Flag byte.
		 * @param int    $count      Sign counter.
		 * @param string $aaguid     16-byte AAGUID.
		 * @param string $cred_id    Credential id bytes.
		 * @param string $cose       Trailing COSE key CBOR.
		 * @return string
		 */
		private function attested( string $rp_id_hash, int $flags, int $count, string $aaguid, string $cred_id, string $cose ): string {
			return $rp_id_hash . chr( $flags ) . pack( 'N', $count )
				. $aaguid . pack( 'n', strlen( $cred_id ) ) . $cred_id . $cose;
		}

		public function test_flags_and_counter_are_extracted(): void {
			$bytes  = hash( 'sha256', 'example.org', true ) . chr( 0x05 ) . pack( 'N', 1337 );
			$parsed = $this->parse( $bytes, false );

			$this->assertIsArray( $parsed );
			$this->assertSame( 0x05, $parsed['flags'] );
			$this->assertSame( 1337, $parsed['sign_count'] );
			$this->assertSame( hash( 'sha256', 'example.org', true ), $parsed['rp_id_hash'] );
		}

		public function test_attested_credential_data_offsets(): void {
			$aaguid  = str_repeat( "\xAB", 16 );
			$cred_id = random_bytes( 20 );
			$cose    = "\xa1\x01\x02";
			$bytes   = $this->attested( hash( 'sha256', 'example.org', true ), 0x41, 3, $aaguid, $cred_id, $cose );

			$parsed = $this->parse( $bytes );
			$this->assertIsArray( $parsed );
			$this->assertSame( $cred_id, $parsed['credential_id'], 'credentialId must start at byte 55 (after the 16-byte AAGUID + 2-byte length).' );
			$this->assertSame( $cose, $parsed['public_key_cbor'], 'The COSE key must be everything after the credentialId.' );
			$this->assertSame( 3, $parsed['sign_count'] );
		}

		public function test_short_data_is_rejected(): void {
			$result = $this->parse( str_repeat( "\x00", 36 ), false );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'webauthn_authdata', $result->get_error_code() );
		}

		public function test_missing_attested_data_is_rejected_when_expected(): void {
			$bytes  = hash( 'sha256', 'example.org', true ) . chr( 0x01 ) . pack( 'N', 0 );
			$result = $this->parse( $bytes, true );
			$this->assertInstanceOf( \WP_Error::class, $result );
			$this->assertSame( 'webauthn_authdata', $result->get_error_code() );
		}
	}
}
