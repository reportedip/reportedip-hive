<?php
/**
 * Unit tests for the hardened in-house CBOR decoder.
 *
 * RFC 8949 example vectors pin the happy path; the hostile-input vectors
 * pin the 2.1.35 hardening: truncated buffers error instead of returning
 * short garbage, indefinite-length items / tags / floats are rejected
 * explicitly instead of desyncing the stream, and nesting is depth-capped.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.35
 */

namespace {

	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Cbor' ) ) {
		/**
		 * Constants-only Two_Factor stub for loading the WebAuthn class.
		 */
		class ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Cbor {
			const METHOD_WEBAUTHN           = 'webauthn';
			const META_WEBAUTHN_ENABLED     = 'reportedip_hive_2fa_webauthn_enabled';
			const META_WEBAUTHN_CREDENTIALS = 'reportedip_hive_2fa_webauthn_credentials';
			const NONCE_COOKIE              = 'reportedip_2fa_token';
			const NONCE_PREFIX              = 'reportedip_2fa_nonce_';
		}
	}
	if ( ! class_exists( 'ReportedIP_Hive_Two_Factor', false ) ) {
		class_alias( 'ReportedIP_Hive_Two_Factor_Stub_For_WebAuthn_Cbor', 'ReportedIP_Hive_Two_Factor' );
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
	class WebAuthnCborTest extends TestCase {

		/**
		 * Decode a hex-encoded CBOR buffer through the private decoder.
		 *
		 * @param string $hex Hex bytes.
		 * @return array|\WP_Error
		 */
		private function decode( string $hex ) {
			$method = new \ReflectionMethod( ReportedIP_Hive_Two_Factor_WebAuthn::class, 'cbor_decode' );
			return $method->invoke( null, (string) hex2bin( $hex ), 0 );
		}

		/**
		 * @dataProvider provide_rfc8949_vectors
		 *
		 * @param string $hex      CBOR hex.
		 * @param mixed  $expected Decoded value.
		 */
		public function test_rfc8949_vectors( string $hex, $expected ): void {
			$result = $this->decode( $hex );
			$this->assertIsArray( $result, 'Vector ' . $hex . ' must decode.' );
			$this->assertSame( $expected, $result[0] );
		}

		/**
		 * RFC 8949 appendix-A subset relevant to CTAP2 payloads.
		 *
		 * @return array<string,array{0:string,1:mixed}>
		 */
		public static function provide_rfc8949_vectors(): array {
			return array(
				'uint 0'          => array( '00', 0 ),
				'uint 23'         => array( '17', 23 ),
				'uint 24'         => array( '1818', 24 ),
				'uint 256'        => array( '190100', 256 ),
				'uint 1000000'    => array( '1a000f4240', 1000000 ),
				'neg -1'          => array( '20', -1 ),
				'neg -100'        => array( '3863', -100 ),
				'bytes 01020304'  => array( '4401020304', "\x01\x02\x03\x04" ),
				'text foo'        => array( '63666f6f', 'foo' ),
				'array [1,2,3]'   => array( '83010203', array( 1, 2, 3 ) ),
				'map {1:2,3:4}'   => array(
					'a201020304',
					array(
						1 => 2,
						3 => 4,
					),
				),
				'false'           => array( 'f4', false ),
				'true'            => array( 'f5', true ),
				'nested map'      => array(
					'a26161016162820203',
					array(
						'a' => 1,
						'b' => array( 2, 3 ),
					),
				),
			);
		}

		/**
		 * @dataProvider provide_hostile_vectors
		 *
		 * @param string $hex           CBOR hex.
		 * @param string $expected_code Expected WP_Error code.
		 */
		public function test_hostile_input_errors_cleanly( string $hex, string $expected_code ): void {
			$result = $this->decode( $hex );
			$this->assertInstanceOf( \WP_Error::class, $result, 'Vector ' . $hex . ' must be rejected.' );
			$this->assertSame( $expected_code, $result->get_error_code() );
		}

		/**
		 * Hostile / malformed vectors the pre-2.1.35 decoder mishandled.
		 *
		 * @return array<string,array{0:string,1:string}>
		 */
		public static function provide_hostile_vectors(): array {
			return array(
				'empty buffer'              => array( '', 'cbor_eof' ),
				'truncated uint16'          => array( '1901', 'cbor_truncated' ),
				'truncated uint64'          => array( '1b00000001', 'cbor_truncated' ),
				'byte string past EOF'      => array( '4401', 'cbor_truncated' ),
				'text string past EOF'      => array( '63666f', 'cbor_truncated' ),
				'huge string length'        => array( '5affffffff00', 'cbor_truncated' ),
				'indefinite byte string'    => array( '5f42010243030405ff', 'cbor_indefinite' ),
				'indefinite array'          => array( '9f0102ff', 'cbor_indefinite' ),
				'tag (major 6)'             => array( 'c11a514b67b0', 'cbor_unsupported' ),
				'float64'                   => array( 'fb3ff199999999999a', 'cbor_float' ),
				'float32'                   => array( 'fa47c35000', 'cbor_float' ),
				'half float'                => array( 'f93e00', 'cbor_float' ),
				'array key of array type'   => array( 'a1810102', 'cbor_key' ),
				'nesting past depth cap'    => array( str_repeat( '81', 10 ) . '00', 'cbor_depth' ),
				'truncated array element'   => array( '8201', 'cbor_eof' ),
				'truncated map value'       => array( 'a101', 'cbor_eof' ),
			);
		}

		public function test_trailing_bytes_after_first_item_are_ignored(): void {
			$result = $this->decode( '01ffffffff' );
			$this->assertIsArray( $result );
			$this->assertSame( 1, $result[0] );
			$this->assertSame( 1, $result[1], 'Offset must stop after the first complete item (COSE keys are followed by extension bytes).' );
		}
	}
}
