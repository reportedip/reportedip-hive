<?php
/**
 * Unit tests for the form execution proof.
 *
 * Locks the four-way verdict. The two halves that carry the feature are the
 * boundary between "we rendered here and the script did not run" and "this form
 * was never ours" — conflating them is what turns a spam filter into a site
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
		 * Nothing request-specific may reach the markup, or a full-page cache
		 * would serve one visitor's token to everyone else.
		 */
		public function test_anchor_markup_is_identical_across_calls(): void {
			$this->assertSame(
				\ReportedIP_Hive_Form_Proof::anchor_markup( self::DECOY, self::PROOF, 'Leave this field empty' ),
				\ReportedIP_Hive_Form_Proof::anchor_markup( self::DECOY, self::PROOF, 'Leave this field empty' )
			);
		}

		public function test_the_surface_list_is_the_documented_set(): void {
			$this->assertSame(
				array( 'comment', 'register', 'lostpassword' ),
				\ReportedIP_Hive_Form_Proof::SURFACES
			);
		}
	}
}
