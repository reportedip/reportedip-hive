<?php
/**
 * Unit tests for the recommendation delta a tier upgrade applies.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.54
 */

namespace {
	require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-settings-registry.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-tier-upgrade.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @covers \ReportedIP_Hive_Tier_Upgrade::select_upgrade_values
	 */
	class TierUpgradeRecommendedDiffTest extends TestCase {

		private function select( array $current ): array {
			return \ReportedIP_Hive_Tier_Upgrade::select_upgrade_values(
				\ReportedIP_Hive_Defaults::recommended( 'free' ),
				\ReportedIP_Hive_Defaults::recommended( 'professional' ),
				\ReportedIP_Hive_Defaults::all_option_defaults(),
				$current
			);
		}

		public function test_untouched_options_receive_the_pro_recommendation(): void {
			$seed     = \ReportedIP_Hive_Defaults::all_option_defaults();
			$selected = $this->select(
				array(
					'reportedip_hive_block_tor'           => $seed['reportedip_hive_block_tor'],
					'reportedip_hive_data_retention_days' => $seed['reportedip_hive_data_retention_days'],
				)
			);
			$this->assertSame( 1, $selected['reportedip_hive_block_tor'] );
			$this->assertSame( 90, $selected['reportedip_hive_data_retention_days'] );
		}

		public function test_an_admin_chosen_value_is_left_alone(): void {
			$selected = $this->select( array( 'reportedip_hive_data_retention_days' => 14 ) );
			$this->assertArrayNotHasKey( 'reportedip_hive_data_retention_days', $selected );
		}

		public function test_a_value_still_on_the_old_recommendation_is_replaced(): void {
			$selected = $this->select( array( 'reportedip_hive_bot_action' => 'block' ) );
			$this->assertArrayNotHasKey( 'reportedip_hive_bot_action', $selected, 'bot_action is identical on both tiers, nothing to apply.' );
			$selected = $this->select( array( 'reportedip_hive_data_retention_days' => 30 ) );
			$this->assertSame( 90, $selected['reportedip_hive_data_retention_days'] );
		}

		public function test_keys_shared_by_both_tiers_are_never_selected(): void {
			$selected = $this->select( array() );
			$this->assertArrayNotHasKey( 'reportedip_hive_headers_enabled', $selected );
			$this->assertArrayNotHasKey( 'reportedip_hive_failed_login_threshold', $selected );
		}

		public function test_missing_current_value_counts_as_untouched(): void {
			$selected = $this->select( array() );
			$this->assertSame( 1, $selected['reportedip_hive_hsts_enabled'] );
		}

		public function test_business_over_professional_lifts_retention_and_the_advanced_adapters(): void {
			$selected = \ReportedIP_Hive_Tier_Upgrade::select_upgrade_values(
				\ReportedIP_Hive_Defaults::recommended( 'professional' ),
				\ReportedIP_Hive_Defaults::recommended( 'business' ),
				\ReportedIP_Hive_Defaults::all_option_defaults(),
				array(
					'reportedip_hive_data_retention_days' => 90,
					'reportedip_hive_audit_enabled'       => 1,
				)
			);
			$this->assertSame(
				array(
					'reportedip_hive_audit_enabled'         => 1,
					'reportedip_hive_data_retention_days'   => 365,
					'reportedip_hive_form_proof_elementor'  => 1,
					'reportedip_hive_form_proof_formidable' => 1,
					'reportedip_hive_form_proof_gravity'    => 1,
					'reportedip_hive_form_proof_um'         => 1,
					'reportedip_hive_form_proof_wpforms'    => 1,
				),
				$selected
			);
		}
	}
}
