<?php
/**
 * Unit tests for the support bundle's scrubbing and summary.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.73
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-support-bundle.php';

	/**
	 * @covers \ReportedIP_Hive_Support_Bundle
	 */
	class SupportBundleTest extends TestCase {

		public function test_ipv4_is_cut_to_its_slash_24(): void {
			$this->assertSame( '203.0.113.0/24', \ReportedIP_Hive_Support_Bundle::network( '203.0.113.77' ) );
		}

		public function test_ipv6_is_cut_to_its_slash_48(): void {
			$this->assertSame( '2a09:bac2:2961::/48', \ReportedIP_Hive_Support_Bundle::network( '2a09:bac2:2961:2482::3a3:19' ) );
		}

		public function test_a_non_address_is_not_echoed(): void {
			$this->assertSame( 'other', \ReportedIP_Hive_Support_Bundle::network( 'system' ) );
			$this->assertSame( '', \ReportedIP_Hive_Support_Bundle::network( '' ) );
		}

		public function test_path_drops_query_and_fragment(): void {
			$this->assertSame( '/kontakt/', \ReportedIP_Hive_Support_Bundle::path_only( '/kontakt/?email=a@b.de&token=x#top' ) );
			$this->assertSame( '/', \ReportedIP_Hive_Support_Bundle::path_only( '?s=1' ) );
		}

		public function test_scrub_masks_mail_and_query(): void {
			$out = \ReportedIP_Hive_Support_Bundle::scrub( 'sent to jane.doe@example.org via /x?key=secret' );

			$this->assertStringNotContainsString( 'jane.doe', $out );
			$this->assertStringContainsString( '***@example.org', $out );
			$this->assertStringNotContainsString( 'secret', $out );
		}

		public function test_no_identifying_detail_key_is_carried(): void {
			foreach ( array( 'username', 'user_login', 'email', 'password', 'api_key', 'token', 'uri', 'claimed_ua', 'message', 'comment' ) as $key ) {
				$this->assertNotContains( $key, \ReportedIP_Hive_Support_Bundle::DETAIL_KEYS, "the detail key {$key} must stay on the site" );
			}
		}

		public function test_periods_stay_inside_the_cap(): void {
			foreach ( \ReportedIP_Hive_Support_Bundle::PERIODS as $days ) {
				$this->assertLessThanOrEqual( \ReportedIP_Hive_Support_Bundle::MAX_DAYS, $days );
			}
		}

		public function test_summary_groups_form_refusals_and_block_causes(): void {
			$recent = array(
				array(
					'type'    => 'form_proof_failed',
					'ip'      => '2a09:bac2:2961::/48',
					'details' => array(
						'surface'      => 'gravity_forms',
						'verdict'      => 'failed',
						'reason'       => 'replay',
						'request_path' => '/musik-arena/',
					),
				),
				array(
					'type'    => 'form_proof_failed',
					'ip'      => '2a09:bac2:2961::/48',
					'details' => array(
						'surface'      => 'gravity_forms',
						'verdict'      => 'failed',
						'reason'       => 'replay',
						'request_path' => '/musik-arena/',
					),
				),
				array(
					'type'    => 'ip_blocked',
					'ip'      => '172.70.130.0/24',
					'details' => array(
						'trigger_event'    => 'waf_block',
						'duration_minutes' => '5',
					),
				),
			);

			$summary = \ReportedIP_Hive_Support_Bundle::summarize( $recent );

			$this->assertSame( 2, $summary['form_proof']['gravity_forms | failed | replay | /musik-arena/'] );
			$this->assertSame( 1, $summary['block_cause']['waf_block | 5 min'] );
			$this->assertSame( 2, $summary['networks']['form_proof_failed | 2a09:bac2:2961::/48'] );
		}

		public function test_waf_paths_name_the_ajax_action(): void {
			$recent = array(
				array(
					'type'    => 'waf_block',
					'ip'      => '109.40.178.0/24',
					'details' => array(
						'rule'        => 'waf_xss_svg_iframe',
						'path'        => '/wp-admin/admin-ajax.php',
						'ajax_action' => 'rocket_beacon',
					),
				),
				array(
					'type'    => 'waf_block',
					'ip'      => '62.60.130.0/24',
					'details' => array(
						'rule' => 'waf_file_probe',
						'path' => '/.env',
					),
				),
			);

			$summary = \ReportedIP_Hive_Support_Bundle::summarize( $recent );

			$this->assertSame( 1, $summary['waf_paths']['/wp-admin/admin-ajax.php | rocket_beacon'] );
			$this->assertSame( 1, $summary['waf_paths']['/.env'] );
			$this->assertContains( 'ajax_action', \ReportedIP_Hive_Support_Bundle::DETAIL_KEYS );
			$this->assertContains( 'matched', \ReportedIP_Hive_Support_Bundle::DETAIL_KEYS );
		}
	}
}
