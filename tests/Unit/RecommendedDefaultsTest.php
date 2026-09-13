<?php
/**
 * Unit tests for the tier-staged recommendation map.
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
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @covers \ReportedIP_Hive_Defaults::recommended
	 */
	class RecommendedDefaultsTest extends TestCase {

		private const TIERS = array( 'free', 'contributor', 'professional', 'business', 'enterprise' );

		private const NOT_REMOTE = array(
			'reportedip_hive_api_key',
			'reportedip_hive_cloud_management',
			'reportedip_hive_delete_data_on_uninstall',
			'reportedip_hive_operation_mode',
			'reportedip_hive_api_endpoint',
			'reportedip_hive_waf_dropin_enabled',
			'reportedip_hive_hardening_enabled',
		);

		public function test_every_key_is_a_registry_key(): void {
			$spec = \ReportedIP_Hive_Settings_Registry::spec();
			foreach ( self::TIERS as $tier ) {
				foreach ( array_keys( \ReportedIP_Hive_Defaults::recommended( $tier ) ) as $key ) {
					$this->assertArrayHasKey( $key, $spec, "$key is recommended for $tier but is not a registry key." );
					$this->assertNotContains( $key, self::NOT_REMOTE, "$key must never be part of a recommendation." );
				}
			}
		}

		public function test_every_tier_contains_the_lower_tier(): void {
			$previous = array();
			foreach ( self::TIERS as $tier ) {
				$current = \ReportedIP_Hive_Defaults::recommended( $tier );
				foreach ( $previous as $key => $value ) {
					$this->assertArrayHasKey( $key, $current, "$tier lost $key that a lower tier recommends." );
				}
				$previous = $current;
			}
		}

		public function test_free_and_contributor_are_identical(): void {
			$this->assertSame(
				\ReportedIP_Hive_Defaults::recommended( 'free' ),
				\ReportedIP_Hive_Defaults::recommended( 'contributor' )
			);
		}

		public function test_professional_unlocks_tor_hsts_and_retention(): void {
			$pro = \ReportedIP_Hive_Defaults::recommended( 'professional' );
			$this->assertSame( 1, $pro['reportedip_hive_block_tor'] );
			$this->assertSame( 1, $pro['reportedip_hive_hsts_enabled'] );
			$this->assertSame( 0, $pro['reportedip_hive_hsts_preload'] );
			$this->assertSame( 90, $pro['reportedip_hive_data_retention_days'] );
			$this->assertArrayNotHasKey( 'reportedip_hive_audit_enabled', $pro );
		}

		public function test_adaptive_policies_are_never_recommended(): void {
			foreach ( self::TIERS as $tier ) {
				$map = \ReportedIP_Hive_Defaults::recommended( $tier );
				$this->assertArrayNotHasKey( 'reportedip_hive_2fa_policy_new_country', $map, "$tier must not recommend a policy the registry filter would strip." );
				$this->assertArrayNotHasKey( 'reportedip_hive_2fa_policy_new_device', $map );
			}
		}

		public function test_rank_orders_the_three_levels(): void {
			$this->assertSame( 0, \ReportedIP_Hive_Defaults::recommendation_rank( 'free' ) );
			$this->assertSame( 0, \ReportedIP_Hive_Defaults::recommendation_rank( 'contributor' ) );
			$this->assertSame( 1, \ReportedIP_Hive_Defaults::recommendation_rank( 'professional' ) );
			$this->assertSame( 2, \ReportedIP_Hive_Defaults::recommendation_rank( 'business' ) );
			$this->assertSame( 2, \ReportedIP_Hive_Defaults::recommendation_rank( 'enterprise' ) );
			$this->assertSame( 0, \ReportedIP_Hive_Defaults::recommendation_rank( 'reportedip_honeypot' ) );
		}

		public function test_business_unlocks_audit_and_one_year_retention(): void {
			$biz = \ReportedIP_Hive_Defaults::recommended( 'business' );
			$this->assertSame( 1, $biz['reportedip_hive_audit_enabled'] );
			$this->assertSame( 365, $biz['reportedip_hive_data_retention_days'] );
			$this->assertSame( $biz, \ReportedIP_Hive_Defaults::recommended( 'enterprise' ) );
		}

		public function test_local_mode_keeps_bot_action_on_flag(): void {
			$this->assertSame( 'block', \ReportedIP_Hive_Defaults::recommended( 'free', 'community' )['reportedip_hive_bot_action'] );
			$this->assertSame( 'flag', \ReportedIP_Hive_Defaults::recommended( 'free', 'local' )['reportedip_hive_bot_action'] );
		}

		public function test_unknown_tier_falls_back_to_free(): void {
			$this->assertSame(
				\ReportedIP_Hive_Defaults::recommended( 'free' ),
				\ReportedIP_Hive_Defaults::recommended( 'reportedip_honeypot' )
			);
		}

		public function test_medium_preset_is_part_of_every_recommendation(): void {
			$free = \ReportedIP_Hive_Defaults::recommended( 'free' );
			foreach ( \ReportedIP_Hive_Defaults::protection_presets()['medium'] as $suffix => $value ) {
				$this->assertSame( $value, $free[ 'reportedip_hive_' . $suffix ] );
			}
		}

		public function test_every_recommended_value_survives_its_registry_sanitizer(): void {
			$spec = \ReportedIP_Hive_Settings_Registry::spec();
			foreach ( self::TIERS as $tier ) {
				foreach ( array( 'community', 'local' ) as $mode ) {
					foreach ( \ReportedIP_Hive_Defaults::recommended( $tier, $mode ) as $key => $value ) {
						$clean = \ReportedIP_Hive_Settings_Registry::sanitize_kind( (string) $spec[ $key ]['kind'], $value, $spec[ $key ] );
						$this->assertFalse( is_wp_error( $clean ), "$tier/$mode: $key is rejected by its sanitizer." );
						$this->assertSame(
							\ReportedIP_Hive_Settings_Registry::normalize_value( $key, $value ),
							\ReportedIP_Hive_Settings_Registry::normalize_value( $key, $clean ),
							"$tier/$mode: $key does not survive its sanitizer unchanged."
						);
					}
				}
			}
		}

		public function test_every_preset_respects_the_reputation_floor(): void {
			foreach ( \ReportedIP_Hive_Defaults::protection_presets() as $level => $preset ) {
				$this->assertGreaterThanOrEqual( \ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD, $preset['block_threshold'], "Preset $level undercuts the reputation floor." );
			}
		}

		public function test_preset_map_has_four_levels_with_four_values_each(): void {
			$presets = \ReportedIP_Hive_Defaults::protection_presets();
			$this->assertSame( array( 'low', 'medium', 'high', 'paranoid' ), array_keys( $presets ) );
			foreach ( $presets as $level => $values ) {
				$this->assertSame(
					array( 'failed_login_threshold', 'failed_login_timeframe', 'block_duration', 'block_threshold' ),
					array_keys( $values ),
					"Preset $level must set exactly the four base thresholds."
				);
			}
		}
	}
}
