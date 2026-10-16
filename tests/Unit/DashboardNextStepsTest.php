<?php
/**
 * Dashboard next steps: recommendation deviation and step values; the
 * upsell chooser lives in the add-on (PlanCardsTest).
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.57
 */

declare(strict_types=1);

namespace {
	if ( ! defined( 'REPORTEDIP_HIVE_SITE_URL' ) ) {
		define( 'REPORTEDIP_HIVE_SITE_URL', 'https://reportedip.com' );
	}
	require_once dirname( __DIR__, 2 ) . '/includes/class-form-adapters.php';
	require_once dirname( __DIR__, 2 ) . '/admin/class-dashboard-next-steps.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Dashboard_Next_Steps;

	/**
	 * @covers ReportedIP_Hive_Dashboard_Next_Steps
	 */
	final class DashboardNextStepsTest extends TestCase {

		public function test_deviation_counts_only_recommended_keys_that_differ(): void {
			$recommended = array(
				'reportedip_hive_block_tor'           => true,
				'reportedip_hive_headers_enabled'     => true,
				'reportedip_hive_data_retention_days' => 90,
			);
			$current     = array(
				'reportedip_hive_block_tor'           => '1',
				'reportedip_hive_headers_enabled'     => '0',
				'reportedip_hive_data_retention_days' => 90,
				'reportedip_hive_other'               => 'x',
			);
			$this->assertSame( array( 'reportedip_hive_headers_enabled' ), ReportedIP_Hive_Dashboard_Next_Steps::deviations( $recommended, $current ) );
			$this->assertSame(
				array(),
				ReportedIP_Hive_Dashboard_Next_Steps::deviations(
					$recommended,
					array(
						'reportedip_hive_block_tor'           => 1,
						'reportedip_hive_headers_enabled'     => 1,
						'reportedip_hive_data_retention_days' => '90',
					)
				)
			);
		}

		public function test_completed_at_accepts_the_stored_utc_datetime_and_an_epoch(): void {
			$this->assertSame( 1789200000, ReportedIP_Hive_Dashboard_Next_Steps::completed_at_timestamp( '2026-09-12 08:00:00' ), 'MySQL UTC string' );
			$this->assertSame( 1789200000, ReportedIP_Hive_Dashboard_Next_Steps::completed_at_timestamp( 1789200000 ), 'epoch int' );
			$this->assertSame( 1789200000, ReportedIP_Hive_Dashboard_Next_Steps::completed_at_timestamp( '1789200000' ), 'epoch string' );
			$this->assertSame( 0, ReportedIP_Hive_Dashboard_Next_Steps::completed_at_timestamp( '' ) );
			$this->assertSame( 0, ReportedIP_Hive_Dashboard_Next_Steps::completed_at_timestamp( false ) );
			$this->assertSame( 0, ReportedIP_Hive_Dashboard_Next_Steps::completed_at_timestamp( 'not a date' ) );
		}

		public function test_score_potential_sums_switched_off_items_per_protection_section(): void {
			$base  = 'https://example.test/wp-admin/admin.php?page=reportedip-hive-protection#';
			$items = array(
				array( 'present' => true,  'available' => true,  'enabled' => false, 'weight' => 6, 'settings_url' => $base . 'lockdown' ),
				array( 'present' => true,  'available' => true,  'enabled' => false, 'weight' => 2, 'settings_url' => $base . 'lockdown' ),
				array( 'present' => true,  'available' => true,  'enabled' => false, 'weight' => 12, 'settings_url' => $base . 'headers' ),
				array( 'present' => true,  'available' => true,  'enabled' => true,  'weight' => 14, 'settings_url' => $base . 'hide_login' ),
				array( 'present' => true,  'available' => false, 'enabled' => false, 'weight' => 6, 'settings_url' => $base . 'hardening_mode' ),
				array( 'present' => false, 'available' => true,  'enabled' => false, 'weight' => 4, 'settings_url' => $base . 'lockdown' ),
				array( 'present' => true,  'available' => true,  'enabled' => false, 'weight' => 15, 'settings_url' => 'https://example.test/wp-admin/admin.php?page=reportedip-hive-community' ),
			);
			$this->assertSame(
				array(
					'lockdown' => 8,
					'headers'  => 12,
				),
				ReportedIP_Hive_Dashboard_Next_Steps::score_potential( $items )
			);
			$this->assertSame( array(), ReportedIP_Hive_Dashboard_Next_Steps::score_potential( array() ) );
		}

		public function test_step_actions_map_every_advisory_key(): void {
			foreach ( array( 'hide_login_off', 'dropin_not_running', 'community_pending', 'own_2fa_missing' ) as $key ) {
				$this->assertArrayHasKey( $key, ReportedIP_Hive_Dashboard_Next_Steps::step_actions(), $key );
			}
			$this->assertArrayNotHasKey( 'badge_off', ReportedIP_Hive_Dashboard_Next_Steps::step_actions(), 'A credit badge is no security step.' );
			$this->assertSame( array(), ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'badge_off', array() ) );
			$this->assertArrayNotHasKey( 'frontend_2fa_available', ReportedIP_Hive_Dashboard_Next_Steps::step_actions(), 'The storefront step comes with the add-on.' );
			$this->assertSame( array(), ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'frontend_2fa_available', array() ) );
			$this->assertSame(
				array(
					'reportedip_hive_hide_login_slug'    => 'secret-door',
					'reportedip_hive_hide_login_enabled' => 1,
				),
				ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'hide_login_off', array( 'slug' => 'secret-door' ) )
			);
			$this->assertSame( array(), ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'community_pending', array() ), 'link-only steps write nothing' );

			$this->assertArrayNotHasKey( 'group_available', ReportedIP_Hive_Dashboard_Next_Steps::step_actions(), 'The group step comes with the add-on.' );
			$this->assertSame( array(), ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'group_available', array() ) );
		}

		public function test_an_add_on_step_writes_through_the_values_filter(): void {
			$filters_before = $GLOBALS['wp_filters'] ?? array();
			try {
				add_filter(
					'reportedip_hive_next_step_values',
					static function ( $values, $step, $input ) {
						return 'extra_issue' === $step ? array( 'reportedip_hive_extra' => (string) ( $input['slug'] ?? '' ) ) : $values;
					},
					10,
					3
				);
				$this->assertSame( array( 'reportedip_hive_extra' => 'x' ), ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'extra_issue', array( 'slug' => 'x' ) ) );
				$this->assertSame(
					array(
						'reportedip_hive_hide_login_slug'    => 'door',
						'reportedip_hive_hide_login_enabled' => 1,
					),
					ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'hide_login_off', array( 'slug' => 'door' ) ),
					'A free step never reaches the filter.'
				);

				$GLOBALS['wp_filters']['reportedip_hive_next_step_values'] = array();
				add_filter( 'reportedip_hive_next_step_values', static fn() => 'broken' );
				$this->assertSame( array(), ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'extra_issue', array() ) );
			} finally {
				$GLOBALS['wp_filters'] = $filters_before;
			}
		}

		public function test_the_dashboard_names_no_plan_and_no_price(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-dashboard-next-steps.php' );
			foreach ( array( 'pricing_url', 'See plans', 'Promo_Manager', 'choose_upsell', '4.97' ) as $needle ) {
				$this->assertStringNotContainsString( $needle, $source, $needle );
			}
			$this->assertStringContainsString( "do_action( 'reportedip_hive_dashboard_next_steps_after', \$tier );", $source );
			$this->assertStringContainsString( "do_action( 'reportedip_hive_status_banner_links', \$tier );", $source );
		}

		public function test_an_add_on_adds_a_link_step_and_a_broken_result_changes_nothing(): void {
			$filters_before = $GLOBALS['wp_filters'] ?? array();
			try {
				add_filter(
					'reportedip_hive_next_step_actions',
					static function ( $actions ) {
						$actions['extra_issue'] = array(
							'label' => 'Open',
							'write' => false,
						);
						return $actions;
					}
				);
				$this->assertSame( 'Open', ReportedIP_Hive_Dashboard_Next_Steps::step_actions()['extra_issue']['label'] );

				$GLOBALS['wp_filters']['reportedip_hive_next_step_actions'] = array();
				add_filter( 'reportedip_hive_next_step_actions', static fn() => null );
				$this->assertArrayHasKey( 'hide_login_off', ReportedIP_Hive_Dashboard_Next_Steps::step_actions() );
			} finally {
				$GLOBALS['wp_filters'] = $filters_before;
			}

			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-dashboard-next-steps.php' );
			$this->assertStringNotContainsString( 'How groups work', $source, 'The documentation label travels with the action.' );
			$this->assertStringContainsString( "! empty( \$action['doc'] ) && ! empty( \$action['doc_label'] )", $source );
		}
	}
}
