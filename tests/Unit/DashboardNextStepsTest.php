<?php
/**
 * Dashboard next steps: recommendation deviation, step values and the
 * upsell chooser.
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
	require_once dirname( __DIR__, 2 ) . '/includes/class-promo-manager.php';
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

		public function test_upsell_chooser_follows_the_spec_table(): void {
			$none = array(
				'woocommerce' => false,
				'multisite'   => false,
				'users'       => 3,
			);
			$shop = array(
				'woocommerce' => true,
				'multisite'   => false,
				'users'       => 3,
			);
			$net  = array(
				'woocommerce' => false,
				'multisite'   => true,
				'users'       => 3,
			);
			$team = array(
				'woocommerce' => false,
				'multisite'   => false,
				'users'       => 26,
			);
			$this->assertSame( 'mail_sms_relay', ReportedIP_Hive_Dashboard_Next_Steps::choose_upsell( 'free', $none ) );
			$this->assertSame( 'wc_frontend_2fa', ReportedIP_Hive_Dashboard_Next_Steps::choose_upsell( 'contributor', $shop ) );
			$this->assertNull( ReportedIP_Hive_Dashboard_Next_Steps::choose_upsell( 'professional', $none ) );
			$this->assertSame( 'business_signal', ReportedIP_Hive_Dashboard_Next_Steps::choose_upsell( 'professional', $net ) );
			$this->assertSame( 'business_signal', ReportedIP_Hive_Dashboard_Next_Steps::choose_upsell( 'professional', $team ) );
			$this->assertSame( 'referral', ReportedIP_Hive_Dashboard_Next_Steps::choose_upsell( 'business', $none ) );
			$this->assertSame( 'referral', ReportedIP_Hive_Dashboard_Next_Steps::choose_upsell( 'enterprise', $none ) );
		}

		public function test_business_signal_threshold_is_twenty_five_users(): void {
			$this->assertFalse(
				ReportedIP_Hive_Dashboard_Next_Steps::business_signal(
					array(
						'woocommerce' => false,
						'multisite'   => false,
						'users'       => 25,
					)
				)
			);
			$this->assertTrue(
				ReportedIP_Hive_Dashboard_Next_Steps::business_signal(
					array(
						'woocommerce' => false,
						'multisite'   => false,
						'users'       => 26,
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
			foreach ( array( 'hide_login_off', 'frontend_2fa_available', 'badge_off', 'dropin_not_running', 'community_pending', 'own_2fa_missing' ) as $key ) {
				$this->assertArrayHasKey( $key, ReportedIP_Hive_Dashboard_Next_Steps::step_actions(), $key );
			}
			$this->assertSame( array( 'reportedip_hive_auto_footer_enabled' => 1 ), ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'badge_off', array() ) );
			$this->assertSame( array( 'reportedip_hive_2fa_frontend_enabled' => 1 ), ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'frontend_2fa_available', array() ) );
			$this->assertSame(
				array(
					'reportedip_hive_hide_login_slug'    => 'secret-door',
					'reportedip_hive_hide_login_enabled' => 1,
				),
				ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'hide_login_off', array( 'slug' => 'secret-door' ) )
			);
			$this->assertSame( array(), ReportedIP_Hive_Dashboard_Next_Steps::step_values( 'community_pending', array() ), 'link-only steps write nothing' );
		}
	}
}
