<?php
/**
 * Unit tests for the exclusions handed to caching and optimisation plugins.
 *
 * None of the optimisers is installed in the test stack, so every case calls
 * the callback directly with the list shape the optimiser passes in. That
 * each callback is registered on a real WordPress is checked by
 * {@see ReportedIP_Hive_Optimizer_Compat_Multisite_Test}.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.7
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;
use ReportedIP_Hive_Optimizer_Compat as Compat;

require_once dirname( __DIR__, 2 ) . '/includes/class-optimizer-compat.php';

/**
 * @covers \ReportedIP_Hive_Optimizer_Compat
 */
class OptimizerCompatTest extends TestCase {

	protected function tear_down() {
		unset( $GLOBALS['wp_filters']['reportedip_hive_optimizer_exclusions'] );
		parent::tear_down();
	}

	public function test_unused_css_removers_keep_the_decoy_rule(): void {
		$list = Compat::add_selectors( array( '.theme-keep' ) );

		$this->assertContains( '.rip-hp-field', $list );
		$this->assertContains( '.theme-keep', $list, 'An entry of the site owner was dropped.' );
		$this->assertContains( 'reportedip-hive-form-proof-inline-css', Compat::add_style_ids( array() ) );
		$this->assertSame( $list, Compat::add_selectors( $list ), 'A second pass added a duplicate.' );
	}

	public function test_delay_defer_and_minify_lists_get_the_proof_script(): void {
		$this->assertContains( '/assets/js/form-proof', Compat::add_paths( array() ) );
		$this->assertContains( '/assets/js/two-factor-login', Compat::add_paths( array() ) );
		$this->assertContains( 'reportedip-hive-form-proof', Compat::add_handles( array() ) );
		$this->assertContains( 'reportedip-hive-form-proof', Compat::add_handles( '' ), 'An empty option string broke the list.' );
	}

	/**
	 * WP Rocket wraps each entry in `#` delimiters and matches it as a
	 * pattern, so the fragment must arrive quoted and still match the URL
	 * of both the free and the add-on script.
	 */
	public function test_wp_rocket_patterns_are_quoted_and_match(): void {
		$urls = array(
			'https://example.org/wp-content/plugins/reportedip-hive/assets/js/form-proof.js?ver=3.0.7',
			'https://example.org/wp-content/plugins/reportedip-hive-pro/assets/js/form-proof.js?ver=3.0.6',
		);

		foreach ( $urls as $url ) {
			$hit = false;
			foreach ( Compat::add_patterns( array() ) as $pattern ) {
				$this->assertNotFalse( @preg_match( '#' . $pattern . '#', '' ), 'Invalid pattern: ' . $pattern );
				$hit = $hit || 1 === preg_match( '#' . $pattern . '#', $url );
			}
			$this->assertTrue( $hit, 'No pattern matches ' . $url );
		}
	}

	public function test_comma_lists_stay_strings_and_arrays_stay_arrays(): void {
		$csv = Compat::add_csv( 'seal.js, js/jquery/jquery.js' );

		$this->assertIsString( $csv );
		$this->assertStringContainsString( 'seal.js', $csv );
		$this->assertStringContainsString( '/assets/js/form-proof', $csv );
		$this->assertSame( $csv, Compat::add_csv( $csv ), 'A second pass added a duplicate.' );
		$this->assertContains( '/assets/js/form-proof', Compat::add_csv( array( 'seal.js' => '' ) ) );
	}

	public function test_per_handle_questions_are_answered_no_only_for_ours(): void {
		$this->assertFalse( Compat::veto_handle( true, 'reportedip-hive-form-proof' ) );
		$this->assertFalse( Compat::veto_handle( true, 'reportedip-hive-two-factor-login' ) );
		$this->assertTrue( Compat::veto_handle( true, 'jquery' ) );
		$this->assertFalse( Compat::veto_tag( true, '<script src="/wp-content/plugins/reportedip-hive/assets/js/form-proof.js"></script>' ) );
		$this->assertTrue( Compat::veto_tag( true, '<script src="/theme.js"></script>' ) );
	}

	/**
	 * Rocket Loader honours `data-cfasync` only ahead of `src`.
	 */
	public function test_script_tag_gets_the_attributes_ahead_of_src(): void {
		$tag  = "<script src=\"https://example.org/form-proof.js\" id=\"reportedip-hive-form-proof-js\"></script>\n";
		$done = Compat::script_tag( $tag, 'reportedip-hive-form-proof' );

		$this->assertStringStartsWith( '<script ' . Compat::SCRIPT_ATTRIBUTES . ' src=', $done );
		$this->assertSame( $done, Compat::script_tag( $done, 'reportedip-hive-form-proof' ), 'A second pass doubled the attributes.' );
		$this->assertSame( $tag, Compat::script_tag( $tag, 'jquery' ) );
	}

	public function test_the_filter_extends_the_lists(): void {
		\add_filter(
			'reportedip_hive_optimizer_exclusions',
			static function ( $exclusions ) {
				$exclusions['handles'][] = 'addon-script';
				$exclusions['handles'][] = 'reportedip-hive-form-proof';
				return $exclusions;
			}
		);

		$handles = Compat::exclusions()['handles'];

		$this->assertContains( 'addon-script', $handles );
		$this->assertSame( array_values( array_unique( $handles ) ), $handles );
		$this->assertFalse( Compat::veto_handle( true, 'addon-script' ) );
	}

	public function test_a_broken_filter_falls_back_to_the_defaults(): void {
		\add_filter(
			'reportedip_hive_optimizer_exclusions',
			static function () {
				return 'nonsense';
			}
		);

		$this->assertContains( '.rip-hp-field', Compat::exclusions()['selectors'] );
	}
}
