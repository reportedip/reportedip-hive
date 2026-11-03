<?php
/**
 * Multisite tests for the optimiser exclusions and the self-hiding anchor.
 *
 * Against a real WordPress: every optimiser filter carries the plugin's
 * callback once it has booted, and the anchor keeps its off-screen `style`
 * through the shared allowlist and through the post allowlist that Contact
 * Form 7 runs its form markup through.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.7
 */

/**
 * @covers ReportedIP_Hive_Optimizer_Compat
 */
class ReportedIP_Hive_Optimizer_Compat_Multisite_Test extends WP_UnitTestCase {

	public function test_every_optimiser_filter_is_wired(): void {
		ReportedIP_Hive_Optimizer_Compat::get_instance();

		$wired = array(
			'add_selectors' => ReportedIP_Hive_Optimizer_Compat::SELECTOR_FILTERS,
			'add_style_ids' => ReportedIP_Hive_Optimizer_Compat::STYLE_ID_FILTERS,
			'add_paths'     => ReportedIP_Hive_Optimizer_Compat::PATH_FILTERS,
			'add_patterns'  => ReportedIP_Hive_Optimizer_Compat::PATTERN_FILTERS,
			'add_csv'       => ReportedIP_Hive_Optimizer_Compat::CSV_FILTERS,
			'add_handles'   => ReportedIP_Hive_Optimizer_Compat::HANDLE_FILTERS,
			'veto_handle'   => ReportedIP_Hive_Optimizer_Compat::HANDLE_VETO_FILTERS,
			'veto_tag'      => array( 'w3tc_minify_js_do_tag_minification' ),
			'script_tag'    => array( 'script_loader_tag' ),
		);

		foreach ( $wired as $method => $filters ) {
			foreach ( $filters as $filter ) {
				$this->assertNotFalse(
					has_filter( $filter, array( 'ReportedIP_Hive_Optimizer_Compat', $method ) ),
					$filter . ' is not wired to ' . $method . '.'
				);
			}
		}
	}

	public function test_the_optimisers_get_the_entries_through_their_filters(): void {
		ReportedIP_Hive_Optimizer_Compat::get_instance();

		$this->assertContains( '.rip-hp-field', apply_filters( 'rocket_rucss_safelist', array() ) );
		$this->assertContains( '/assets/js/form-proof', apply_filters( 'litespeed_optm_js_defer_exc', array() ) );
		$this->assertFalse( apply_filters( 'wphb_minify_resource', true, 'reportedip-hive-form-proof', 'scripts', '' ) );
	}

	public function test_the_anchor_keeps_its_style_through_kses(): void {
		$markup = ReportedIP_Hive_Form_Proof::anchor_markup( '_rip_hp', '_rip_proof', 'Leave this field empty' );

		$shared = wp_kses( $markup, ReportedIP_Hive_Form_Proof::anchor_kses() );
		$post   = wp_kses_post( $markup );

		foreach ( array( $shared, $post ) as $printed ) {
			$this->assertStringContainsString( 'position:absolute', $printed );
			$this->assertStringContainsString( 'left:-9999px', $printed );
			$this->assertStringContainsString( 'overflow:hidden', $printed );
		}
	}
}
