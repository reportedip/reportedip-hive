<?php
/**
 * Tests for the bound form challenge: minting, verifying, difficulty.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.64
 */

namespace {
	if ( ! function_exists( 'wp_salt' ) ) {
		function wp_salt( $scheme = 'auth' ) {
			return 'unit-test-salt-' . $scheme;
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-form-proof.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-form-challenge.php';

	/**
	 * The challenge is signed, bound to its surface, expires, is good once and
	 * fails open. Every refusal reason has a case, and so does the ladder.
	 */
	class FormChallengeTest extends TestCase {

		private const NOW = 1000000;

		/**
		 * Brute-force a nonce the way the browser does.
		 */
		private function solve( array $minted ): string {
			$seed  = $minted['seed'];
			$bits  = (int) $minted['bits'];
			$nonce = 0;

			while ( true ) {
				$hex    = dechex( $nonce );
				$digest = hash( 'sha256', $seed . $hex, true );

				if ( \ReportedIP_Hive_Form_Proof::leading_zero_bits( $digest ) >= $bits ) {
					return $hex;
				}

				++$nonce;
			}
		}

		public function test_a_solved_token_verifies(): void {
			$minted = \ReportedIP_Hive_Form_Challenge::mint( 10, self::NOW );
			$nonce  = $this->solve( $minted );

			$this->assertSame( 'ok', \ReportedIP_Hive_Form_Challenge::verify( $minted['token'], $nonce, self::NOW + 5 ) );
		}

		public function test_mint_returns_the_four_fields(): void {
			$minted = \ReportedIP_Hive_Form_Challenge::mint( 0, self::NOW );

			$this->assertSame( array( 'token', 'seed', 'bits', 'expires' ), array_keys( $minted ) );
			$this->assertSame( 0, $minted['bits'] );
			$this->assertSame( self::NOW + \ReportedIP_Hive_Form_Challenge::TTL, $minted['expires'] );
			$this->assertSame( 16, strlen( $minted['seed'] ) );
		}

		public function test_expired_token_is_refused(): void {
			$minted = \ReportedIP_Hive_Form_Challenge::mint( 0, self::NOW );

			$this->assertSame( 'expired', \ReportedIP_Hive_Form_Challenge::verify( $minted['token'], '0', self::NOW + \ReportedIP_Hive_Form_Challenge::TTL + 1 ) );
		}

		public function test_a_tampered_signature_is_refused(): void {
			$minted = \ReportedIP_Hive_Form_Challenge::mint( 0, self::NOW );

			$this->assertSame( 'signature', \ReportedIP_Hive_Form_Challenge::verify( $minted['token'] . 'x', '0', self::NOW + 5 ) );
			$this->assertSame( 'signature', \ReportedIP_Hive_Form_Challenge::verify( 'no-dot-here', '0', self::NOW + 5 ) );
		}

		public function test_a_forged_claim_set_is_refused(): void {
			$minted  = \ReportedIP_Hive_Form_Challenge::mint( 20, self::NOW );
			$dot     = strrpos( $minted['token'], '.' );
			$sig     = substr( $minted['token'], $dot + 1 );
			$claims  = json_decode( base64_decode( strtr( substr( $minted['token'], 0, $dot ), '-_', '+/' ) ), true );
			$claims['b'] = 0;
			$forged  = rtrim( strtr( base64_encode( wp_json_encode( $claims ) ), '+/', '-_' ), '=' ) . '.' . $sig;

			$this->assertSame( 'signature', \ReportedIP_Hive_Form_Challenge::verify( $forged, '0', self::NOW + 5 ) );
		}

		public function test_a_token_is_single_use(): void {
			$minted = \ReportedIP_Hive_Form_Challenge::mint( 0, self::NOW );

			$this->assertSame( 'ok', \ReportedIP_Hive_Form_Challenge::verify( $minted['token'], '0', self::NOW + 5 ) );
			$this->assertSame( 'replay', \ReportedIP_Hive_Form_Challenge::verify( $minted['token'], '0', self::NOW + 6 ) );
		}

		public function test_zero_bits_needs_no_solution(): void {
			$minted = \ReportedIP_Hive_Form_Challenge::mint( 0, self::NOW );

			$this->assertSame( 'ok', \ReportedIP_Hive_Form_Challenge::verify( $minted['token'], '0', self::NOW + 5 ) );
		}

		public function test_a_wrong_nonce_at_positive_bits_is_pow(): void {
			$minted = \ReportedIP_Hive_Form_Challenge::mint( 20, self::NOW );

			$this->assertSame( 'pow', \ReportedIP_Hive_Form_Challenge::verify( $minted['token'], 'deadbeef', self::NOW + 5 ) );
		}

		public function test_bits_climb_with_the_mint_rate(): void {
			$this->assertSame( 14, \ReportedIP_Hive_Form_Challenge::bits_for( 1, false ) );
			$this->assertSame( 14, \ReportedIP_Hive_Form_Challenge::bits_for( 8, false ) );
			$this->assertSame( 15, \ReportedIP_Hive_Form_Challenge::bits_for( 9, false ) );
			$this->assertSame( 15, \ReportedIP_Hive_Form_Challenge::bits_for( 16, false ) );
			$this->assertSame( 16, \ReportedIP_Hive_Form_Challenge::bits_for( 17, false ) );
			$this->assertSame( 22, \ReportedIP_Hive_Form_Challenge::bits_for( 100000, false ) );
			$this->assertSame( 16, \ReportedIP_Hive_Form_Challenge::bits_for( 1, true ) );
		}

		public function test_bits_are_clamped_to_the_range(): void {
			$minted = \ReportedIP_Hive_Form_Challenge::mint( 99, self::NOW );

			$this->assertSame( \ReportedIP_Hive_Form_Challenge::BITS_MAX, $minted['bits'] );

			$minted = \ReportedIP_Hive_Form_Challenge::mint( -5, self::NOW );

			$this->assertSame( 0, $minted['bits'] );
		}

		public function test_the_proof_value_splits_into_token_and_nonce(): void {
			$minted = \ReportedIP_Hive_Form_Challenge::mint( 0, self::NOW );
			$split  = \ReportedIP_Hive_Form_Challenge::split( $minted['token'] . '.abc' );

			$this->assertSame( $minted['token'], $split['token'] );
			$this->assertSame( 'abc', $split['nonce'] );
			$this->assertTrue( \ReportedIP_Hive_Form_Challenge::looks_like_token( $minted['token'] . '.abc' ) );
		}

		/**
		 * @dataProvider not_tokens
		 */
		public function test_markers_and_old_payloads_are_not_tokens( string $value ): void {
			$this->assertFalse( \ReportedIP_Hive_Form_Challenge::looks_like_token( $value ) );
		}

		public static function not_tokens(): array {
			return array(
				'plain marker'       => array( '1' ),
				'old bucket payload' => array( '497261.2ca0' ),
				'empty'              => array( '' ),
				'one dot only'       => array( 'abc.def' ),
			);
		}
	}
}
