<?php
/**
 * Unit tests for the form execution proof.
 *
 * Locks the four-way verdict. The two halves that carry the feature are the
 * boundary between "we rendered here and the script did not run" and "this form
 * was never ours", conflating them is what turns a spam filter into a site
 * that refuses every comment on a hand-written theme.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.53
 */

namespace {
	if ( ! function_exists( 'wp_salt' ) ) {
		function wp_salt( $scheme = 'auth' ) {
			return 'unit-test-salt-' . $scheme;
		}
	}

	if ( ! function_exists( 'wp_generate_password' ) ) {
		function wp_generate_password( $length = 12, $special_chars = true, $extra_special_chars = false ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return substr( str_repeat( 'a1b2c3d4e5f6', (int) ceil( $length / 12 ) ), 0, (int) $length );
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-form-proof.php';

	/**
	 * @covers \ReportedIP_Hive_Form_Proof
	 */
	class FormProofTest extends TestCase {

		private const DECOY = 'reportedip_hive_hp';
		private const PROOF = 'rip_a1b2c3d4e5';

		/**
		 * Run the verdict with the stock field names.
		 *
		 * @param array<string,mixed> $post Request body fields.
		 * @return string
		 */
		private function verdict( array $post ): string {
			return \ReportedIP_Hive_Form_Proof::evaluate( $post, self::PROOF, self::DECOY );
		}

		public function test_empty_anchor_with_proof_is_proved(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::PROVED,
				$this->verdict(
					array(
						self::DECOY => '',
						self::PROOF => '1',
					)
				)
			);
		}

		public function test_filled_anchor_beats_a_present_proof(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::TRIPPED,
				$this->verdict(
					array(
						self::DECOY => 'http://spam.example',
						self::PROOF => '1',
					)
				)
			);
		}

		public function test_anchor_without_proof_is_failed(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::FAILED,
				$this->verdict( array( self::DECOY => '' ) )
			);
		}

		public function test_empty_proof_value_does_not_count(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::FAILED,
				$this->verdict(
					array(
						self::DECOY => '',
						self::PROOF => '   ',
					)
				)
			);
		}

		/**
		 * The anchor is the authority on whether we rendered. A proof field on
		 * its own is a field we did not plant, arriving on a form we did not
		 * render.
		 */
		public function test_proof_without_anchor_is_absent(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::ABSENT,
				$this->verdict( array( self::PROOF => '1' ) )
			);
		}

		/**
		 * A comment submitted over the REST API carries its body as JSON, so
		 * `$_POST` stays empty. That must read as "not our form", never as a
		 * failed proof.
		 */
		public function test_rest_submission_with_empty_body_is_absent(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::ABSENT,
				$this->verdict( array() )
			);
		}

		public function test_whitespace_only_anchor_counts_as_empty(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::PROVED,
				$this->verdict(
					array(
						self::DECOY => "  \n\t ",
						self::PROOF => '1',
					)
				)
			);
		}

		public function test_array_in_the_anchor_is_tripped(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::TRIPPED,
				$this->verdict(
					array(
						self::DECOY => array( 'a', 'b' ),
						self::PROOF => '1',
					)
				)
			);
		}

		public function test_array_in_the_proof_does_not_prove(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::FAILED,
				$this->verdict(
					array(
						self::DECOY => '',
						self::PROOF => array( '1' ),
					)
				)
			);
		}

		public function test_empty_decoy_name_is_absent(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::ABSENT,
				\ReportedIP_Hive_Form_Proof::evaluate( array( self::DECOY => '' ), self::PROOF, '' )
			);
		}

		public function test_missing_field_name_never_proves(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::FAILED,
				\ReportedIP_Hive_Form_Proof::evaluate( array( self::DECOY => '' ), '', self::DECOY )
			);
		}

		public function test_field_name_shape_is_enforced(): void {
			$this->assertTrue( \ReportedIP_Hive_Form_Proof::is_valid_field_name( 'rip_a1b2c3d4e5' ) );
			$this->assertFalse( \ReportedIP_Hive_Form_Proof::is_valid_field_name( '' ) );
			$this->assertFalse( \ReportedIP_Hive_Form_Proof::is_valid_field_name( 'rip_short' ) );
			$this->assertFalse( \ReportedIP_Hive_Form_Proof::is_valid_field_name( 'rip_A1B2C3D4E5' ) );
			$this->assertFalse( \ReportedIP_Hive_Form_Proof::is_valid_field_name( 'other_a1b2c3d4' ) );
			$this->assertFalse( \ReportedIP_Hive_Form_Proof::is_valid_field_name( 'rip_a1b2c3d4e5x' ) );
		}

		public function test_generated_names_pass_their_own_validator(): void {
			for ( $i = 0; $i < 20; $i++ ) {
				$name = \ReportedIP_Hive_Form_Proof::generate_field_name();
				$this->assertTrue(
					\ReportedIP_Hive_Form_Proof::is_valid_field_name( $name ),
					'Generated name rejected by the validator: ' . $name
				);
			}
		}

		/**
		 * The name is derived from the WordPress password generator, not from
		 * a constant. The shared test stub is deterministic, so the derivation
		 * is what can be asserted here; the randomness itself is core's job.
		 */
		public function test_the_name_is_derived_from_the_password_generator(): void {
			$expected = 'rip_' . substr(
				strtolower( preg_replace( '/[^A-Za-z0-9]/', '', \wp_generate_password( 32, false, false ) ) ),
				0,
				10
			);

			$this->assertSame( $expected, \ReportedIP_Hive_Form_Proof::generate_field_name() );
		}

		public function test_anchor_markup_carries_the_script_contract(): void {
			$markup = \ReportedIP_Hive_Form_Proof::anchor_markup( self::DECOY, self::PROOF, 'Leave this field empty' );

			$this->assertStringContainsString( 'class="rip-fp-anchor"', $markup );
			$this->assertStringContainsString( 'data-n="' . self::PROOF . '"', $markup );
			$this->assertStringContainsString( 'name="' . self::DECOY . '"', $markup );
			$this->assertStringContainsString( 'value=""', $markup );
		}

		public function test_anchor_markup_stays_out_of_the_reading_order(): void {
			$markup = \ReportedIP_Hive_Form_Proof::anchor_markup( self::DECOY, self::PROOF, 'Leave this field empty' );

			$this->assertStringContainsString( 'aria-hidden="true"', $markup );
			$this->assertStringContainsString( 'rip-hp-field', $markup );
			$this->assertStringContainsString( 'tabindex="-1"', $markup );
			$this->assertStringContainsString( 'autocomplete="off"', $markup );
		}

		/**
		 * Two protected forms on one page each render an anchor. A fixed `id`
		 * would then be in the document twice, and the `for` of both labels
		 * would point at the first field.
		 */
		public function test_anchor_markup_carries_no_identifier(): void {
			$markup = \ReportedIP_Hive_Form_Proof::anchor_markup( self::DECOY, self::PROOF, 'Leave this field empty' );

			$this->assertStringNotContainsString( ' id=', $markup );
			$this->assertStringNotContainsString( ' for=', $markup );
		}

		/**
		 * Without an identifier the label has to reach its field through the
		 * nesting, so the input belongs inside the label element.
		 */
		public function test_the_label_wraps_the_field(): void {
			$markup = \ReportedIP_Hive_Form_Proof::anchor_markup( self::DECOY, self::PROOF, 'Leave this field empty' );

			$this->assertMatchesRegularExpression( '#<label>[^<]*<input\b[^>]*></label>#', $markup );
		}

		/**
		 * A forgotten allowlist entry would strip the label back out in
		 * `print_anchor()` and leave the field without its description.
		 */
		public function test_the_allowlist_admits_the_wrapping_label(): void {
			$allowed = \ReportedIP_Hive_Form_Proof::anchor_kses();

			$this->assertArrayHasKey( 'label', $allowed );
			$this->assertArrayNotHasKey( 'for', $allowed['label'] );
			$this->assertArrayNotHasKey( 'id', $allowed['input'] );
		}

		/**
		 * Nothing request-specific may reach the markup, or a full-page cache
		 * would serve one visitor's token to everyone else.
		 */
		public function test_anchor_markup_is_identical_across_calls(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::anchor_markup( self::DECOY, self::PROOF, 'Leave this field empty' ),
				\ReportedIP_Hive_Form_Proof::anchor_markup( self::DECOY, self::PROOF, 'Leave this field empty' )
			);
		}
		/**
		 * @dataProvider leading_zero_bit_cases
		 *
		 * @param string $hex      Digest as hex.
		 * @param int    $expected Expected leading zero bits.
		 */
		public function test_leading_zero_bits_counts_the_digest( string $hex, int $expected ): void {
			$this->assertSame( $expected, \ReportedIP_Hive_Form_Proof::leading_zero_bits( hex2bin( $hex ) ) );
		}

		/**
		 * @return array<string, array{0:string, 1:int}>
		 */
		public static function leading_zero_bit_cases(): array {
			return array(
				'first bit set'    => array( 'ff', 0 ),
				'one zero bit'     => array( '7f', 1 ),
				'four zero bits'   => array( '0f', 4 ),
				'seven zero bits'  => array( '01', 7 ),
				'one empty byte'   => array( '00ff', 8 ),
				'twelve zero bits' => array( '000f', 12 ),
				'two empty bytes'  => array( '0000ff', 16 ),
				'all zero'         => array( '0000', 16 ),
			);
		}

		/**
		 * The shortcut this whole feature exists to close: the proof field name
		 * is readable in the page, so a script can post it back and look like a
		 * browser. With the computation demanded, a value that solves nothing is
		 * no longer evidence.
		 */
		public function test_a_copied_proof_field_no_longer_counts(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::FAILED,
				\ReportedIP_Hive_Form_Proof::resolve( \ReportedIP_Hive_Form_Proof::PROVED, true, false )
			);
		}

		public function test_a_solved_computation_stays_proved(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::PROVED,
				\ReportedIP_Hive_Form_Proof::resolve( \ReportedIP_Hive_Form_Proof::PROVED, true, true )
			);
		}

		/**
		 * Free plans, plain HTTP and the grace after switching on all land here.
		 * The plain marker has to keep working, or the feature turns every
		 * cached page into a wave of false positives on the day it is enabled.
		 */
		public function test_without_a_demand_the_plain_marker_still_proves(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::PROVED,
				\ReportedIP_Hive_Form_Proof::resolve( \ReportedIP_Hive_Form_Proof::PROVED, false, false )
			);
		}

		/**
		 * @dataProvider untouched_verdicts
		 *
		 * @param string $verdict Structural verdict.
		 */
		public function test_only_proved_can_be_revoked( string $verdict ): void {
			$this->assertSame( $verdict, \ReportedIP_Hive_Form_Proof::resolve( $verdict, true, false ) );
			$this->assertSame( $verdict, \ReportedIP_Hive_Form_Proof::resolve( $verdict, true, true ) );
		}

		/**
		 * @return array<string, array{0:string}>
		 */
		public static function untouched_verdicts(): array {
			return array(
				'tripped' => array( \ReportedIP_Hive_Form_Proof::TRIPPED ),
				'failed'  => array( \ReportedIP_Hive_Form_Proof::FAILED ),
				'absent'  => array( \ReportedIP_Hive_Form_Proof::ABSENT ),
			);
		}

		public function test_the_challenge_endpoint_reaches_the_markup(): void {
			$markup = \ReportedIP_Hive_Form_Proof::anchor_markup( self::DECOY, self::PROOF, 'x', 'https://example.test/wp-json/reportedip-hive/v1/form/challenge' );

			$this->assertStringContainsString( 'data-e="https://example.test/wp-json/reportedip-hive/v1/form/challenge"', $markup );
			$this->assertStringNotContainsString( 'data-s', $markup );
		}

		/**
		 * Without a challenge the bytes have to match the pre-computation
		 * markup exactly, or every cached page in the wild changes meaning.
		 */
		public function test_markup_without_a_challenge_carries_no_attributes(): void {
			$markup = \ReportedIP_Hive_Form_Proof::anchor_markup( self::DECOY, self::PROOF, 'Leave this field empty' );

			$this->assertStringNotContainsString( 'data-e', $markup );
		}

		/**
		 * A forgotten allowlist entry would strip the challenge back out again
		 * in `print_anchor()`, leaving a feature that silently does nothing.
		 */
		public function test_the_allowlist_admits_the_challenge_attributes(): void {
			$allowed = \ReportedIP_Hive_Form_Proof::anchor_kses();

			$this->assertArrayHasKey( 'data-e', $allowed['input'] );
			$this->assertArrayNotHasKey( 'data-s', $allowed['input'] );
		}

		/**
		 * The three surfaces this plugin owns must keep their bare field names,
		 * or every cached page in the wild stops matching what the server reads.
		 *
		 * @dataProvider own_surfaces
		 *
		 * @param string $surface Surface identifier.
		 */
		public function test_an_own_surface_carries_no_prefix( string $surface ): void {
			$this->assertSame( '', \ReportedIP_Hive_Form_Proof::surface_prefix( $surface ) );
		}

		/**
		 * @return array<string, array{0:string}>
		 */
		public static function own_surfaces(): array {
			return array(
				'comment'      => array( 'comment' ),
				'register'     => array( 'register' ),
				'lostpassword' => array( 'lostpassword' ),
			);
		}

		/**
		 * Contact Form 7 copies every posted key without a leading underscore
		 * into its own posted data, where it reaches the mail, the stored entry
		 * and the posted-data hash. The prefix is what keeps our two fields out.
		 */
		public function test_a_third_party_surface_carries_the_prefix(): void {
			$this->assertSame( '_', \ReportedIP_Hive_Form_Proof::surface_prefix( 'cf7' ) );
			$this->assertSame( '_', \ReportedIP_Hive_Form_Proof::surface_prefix( 'elementor' ) );
			$this->assertSame( '_', \ReportedIP_Hive_Form_Proof::surface_prefix( '' ) );
		}

		/**
		 * The verdict reads names it is handed, so the prefixed pair has to
		 * produce the same four answers as the bare pair.
		 *
		 * @dataProvider prefixed_cases
		 *
		 * @param array<string,mixed> $post     Request body fields, keyed by suffix.
		 * @param string              $expected Expected verdict.
		 */
		public function test_the_prefixed_names_yield_the_same_verdicts( array $post, string $expected ): void {
			$prefix = \ReportedIP_Hive_Form_Proof::surface_prefix( 'cf7' );
			$body   = array();

			foreach ( $post as $name => $value ) {
				$body[ $prefix . $name ] = $value;
			}

			$this->assertSame(
				$expected,
				\ReportedIP_Hive_Form_Proof::evaluate( $body, $prefix . self::PROOF, $prefix . self::DECOY )
			);
		}

		/**
		 * @return array<string, array{0:array<string,mixed>, 1:string}>
		 */
		public static function prefixed_cases(): array {
			return array(
				'proved'  => array(
					array(
						self::DECOY => '',
						self::PROOF => '1',
					),
					\ReportedIP_Hive_Form_Proof::PROVED,
				),
				'tripped' => array(
					array(
						self::DECOY => 'http://spam.example',
						self::PROOF => '1',
					),
					\ReportedIP_Hive_Form_Proof::TRIPPED,
				),
				'failed'  => array(
					array( self::DECOY => '' ),
					\ReportedIP_Hive_Form_Proof::FAILED,
				),
				'absent'  => array(
					array( self::PROOF => '1' ),
					\ReportedIP_Hive_Form_Proof::ABSENT,
				),
			);
		}

		/**
		 * An unprefixed body must not be read by a prefixed surface, or a
		 * comment form and a contact form on one page would answer for each
		 * other.
		 */
		public function test_a_prefixed_surface_ignores_the_bare_fields(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::ABSENT,
				\ReportedIP_Hive_Form_Proof::evaluate(
					array(
						self::DECOY => '',
						self::PROOF => '1',
					),
					'_' . self::PROOF,
					'_' . self::DECOY
				)
			);
		}

		public function test_the_adapter_grace_holds_the_strict_reading_back(): void {
			$this->assertFalse( \ReportedIP_Hive_Form_Proof::grace_elapsed( 1000, 1000, 86400 ) );
			$this->assertFalse( \ReportedIP_Hive_Form_Proof::grace_elapsed( 1000, 87399, 86400 ) );
			$this->assertTrue( \ReportedIP_Hive_Form_Proof::grace_elapsed( 1000, 87400, 86400 ) );
		}

		/**
		 * Nothing switched on means nothing stamped, and an unstamped start has
		 * to read as lenient: a switch written by a channel that never ran the
		 * side effect must not make the site strict behind the operator's back.
		 */
		public function test_without_a_stamp_the_lenient_reading_stands(): void {
			$this->assertFalse( \ReportedIP_Hive_Form_Proof::grace_elapsed( 0, 9999999, 86400 ) );
		}

		/**
		 * @dataProvider payload_cases
		 *
		 * @param string   $raw      Submitted field value.
		 * @param string   $proof    Expected proof part.
		 * @param int|null $seconds  Expected duration.
		 */
		public function test_a_payload_splits_into_proof_and_duration( string $raw, string $proof, ?int $seconds ): void {
			$this->assertSame(
				array(
					'proof'   => $proof,
					'seconds' => $seconds,
				),
				\ReportedIP_Hive_Form_Proof::split_payload( $raw )
			);
		}

		/**
		 * @return array<string, array{0:string, 1:string, 2:int|null}>
		 */
		public static function payload_cases(): array {
			return array(
				'plain marker with a duration' => array( '1~7', '1', 7 ),
				'solved payload with one'      => array( '497086.1a2b~7', '497086.1a2b', 7 ),
				'no suffix at all'             => array( '497086.1a2b', '497086.1a2b', null ),
				'plain marker without one'     => array( '1', '1', null ),
				'empty suffix'                 => array( '1~', '1', null ),
				'not a number'                 => array( '1~abc', '1', null ),
				'signed'                       => array( '1~-3', '1', null ),
				'five digits'                  => array( '1~10000', '1', null ),
				'four digits'                  => array( '1~9999', '1', 9999 ),
				'zero'                         => array( '1~0', '1', 0 ),
				'a second separator'           => array( '1~7~9', '1', null ),
				'nothing before the separator' => array( '~7', '', 7 ),
				'empty'                        => array( '', '', null ),
			);
		}

		public function test_the_fast_threshold_is_clamped(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::FAST_SECONDS_MIN,
				\ReportedIP_Hive_Form_Proof::clamp_fast_seconds( 0 )
			);
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::FAST_SECONDS_MIN,
				\ReportedIP_Hive_Form_Proof::clamp_fast_seconds( -30 )
			);
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::FAST_SECONDS_MAX,
				\ReportedIP_Hive_Form_Proof::clamp_fast_seconds( PHP_INT_MAX )
			);
			$this->assertSame( 5, \ReportedIP_Hive_Form_Proof::clamp_fast_seconds( 5 ) );
			$this->assertSame( 3, \ReportedIP_Hive_Form_Proof::clamp_fast_seconds( \ReportedIP_Hive_Form_Proof::FAST_SECONDS ) );
		}

		public function test_the_grace_filter_value_is_clamped(): void {
			$this->assertTrue( \ReportedIP_Hive_Form_Proof::grace_elapsed( 1000, 1000, -5 ) );
			$this->assertFalse(
				\ReportedIP_Hive_Form_Proof::grace_elapsed( 1000, 1000 + \ReportedIP_Hive_Form_Proof::ADAPTER_GRACE_MAX - 1, PHP_INT_MAX )
			);
			$this->assertTrue(
				\ReportedIP_Hive_Form_Proof::grace_elapsed( 1000, 1000 + \ReportedIP_Hive_Form_Proof::ADAPTER_GRACE_MAX, PHP_INT_MAX )
			);
		}
	}
}
