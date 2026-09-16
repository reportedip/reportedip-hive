<?php
/**
 * Unit tests for the generator-tag stripper of the attack-surface switches.
 *
 * `hide_software_info` used to take off only the tag WordPress writes itself,
 * while every plugin that announces its version kept doing so. An Elementor
 * site therefore published its exact build although the switch said the
 * software was hidden. The stripper closes that, and these cases pin the two
 * halves that matter: it has to catch a generator tag whoever wrote it, and it
 * has to leave everything else alone.
 *
 * The pattern carries a back reference, so a broken edit turns it into
 * something that silently matches nothing. That is exactly how the first
 * version of this shipped, and why the cases below exist.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.58
 */

namespace {

	if ( ! function_exists( 'add_action' ) ) {
		function add_action( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'add_filter' ) ) {
		function add_filter( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'remove_action' ) ) {
		function remove_action( $hook, $cb, $priority = 10 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( '__' ) ) {
		function __( $text, $domain = '' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $text;
		}
	}
	if ( ! function_exists( 'str_starts_with' ) ) {
		function str_starts_with( $haystack, $needle ) {
			return '' === $needle || 0 === strncmp( (string) $haystack, (string) $needle, strlen( (string) $needle ) );
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-option-routing.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-attack-surface.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP_Hive_Attack_Surface;
	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @covers \ReportedIP_Hive_Attack_Surface::strip_generators
	 */
	class AttackSurfaceGeneratorTest extends TestCase {

		/**
		 * Markup that has to lose its generator tag.
		 *
		 * @return array<string, array{0: string}>
		 */
		public static function announcing_markup() {
			return array(
				'WordPress core'    => array( '<meta name="generator" content="WordPress 7.1" />' ),
				'Elementor'         => array( '<meta name="generator" content="Elementor 3.34.0; features: e_font_icon_svg; settings: css_print_method-external">' ),
				'single quotes'     => array( "<meta name='generator' content='Yoast SEO 24.1' />" ),
				'attributes before' => array( '<meta charset="utf-8" name="generator" content="WooCommerce 9.4">' ),
				'uppercase name'    => array( '<META NAME="GENERATOR" CONTENT="Something 1.0">' ),
			);
		}

		/**
		 * @dataProvider announcing_markup
		 * @param string $markup Markup carrying a generator tag.
		 */
		public function test_a_generator_tag_is_removed_whoever_wrote_it( $markup ) {
			$this->assertSame( '', ReportedIP_Hive_Attack_Surface::strip_generators( $markup ) );
		}

		/**
		 * Markup that has to survive untouched.
		 *
		 * @return array<string, array{0: string}>
		 */
		public static function innocent_markup() {
			return array(
				'a longer name'       => array( '<meta name="generator-hint" content="keep me">' ),
				'another meta'        => array( '<meta name="viewport" content="width=device-width">' ),
				'the word in a title' => array( '<title>Our generator range</title>' ),
				'a link element'      => array( '<link rel="EditURI" href="https://example.com/xmlrpc.php?rsd" />' ),
				'nothing at all'      => array( '' ),
			);
		}

		/**
		 * @dataProvider innocent_markup
		 * @param string $markup Markup without a generator tag.
		 */
		public function test_everything_else_is_left_alone( $markup ) {
			$this->assertSame( $markup, ReportedIP_Hive_Attack_Surface::strip_generators( $markup ) );
		}

		/**
		 * The realistic case: one head holding several tags, of which exactly
		 * the announcing ones go.
		 */
		public function test_a_whole_head_keeps_everything_but_the_announcements() {
			$head = '<meta charset="utf-8">' . "\n"
				. '<meta name="generator" content="WordPress 7.1" />' . "\n"
				. '<title>A site</title>' . "\n"
				. '<meta name="generator" content="Elementor 3.34.0">' . "\n"
				. '<link rel="EditURI" href="https://example.com/xmlrpc.php?rsd" />';

			$clean = ReportedIP_Hive_Attack_Surface::strip_generators( $head );

			$this->assertStringNotContainsString( 'name="generator"', $clean );
			$this->assertStringContainsString( '<meta charset="utf-8">', $clean );
			$this->assertStringContainsString( '<title>A site</title>', $clean );
			$this->assertStringContainsString( 'rel="EditURI"', $clean );
		}

		/**
		 * A quote that opens one way and closes the other is not a tag any
		 * browser reads as a generator announcement, and the back reference is
		 * what keeps it out.
		 */
		public function test_mismatched_quotes_are_not_treated_as_a_generator() {
			$markup = '<meta name="generator\' content="odd">';

			$this->assertSame( $markup, ReportedIP_Hive_Attack_Surface::strip_generators( $markup ) );
		}
	}
}
