<?php
/**
 * Unit tests for the tier-bound triple-bucket API rate-limit contract.
 *
 * Locks down `Mode_Manager::default_api_rate_limits_for_tier()`,
 * `get_api_rate_limit_snapshot()` and `is_community_layer_degraded()` so
 * future tier changes cannot silently regress the per-bucket caps that the
 * admin "API call usage" card and the degraded-banner helper rely on.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.7
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class ApiRateLimitBucketsTest extends TestCase {

	protected function set_up() {
		parent::set_up();

		if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
			define( 'HOUR_IN_SECONDS', 3600 );
		}
		if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
			define( 'MINUTE_IN_SECONDS', 60 );
		}

		$GLOBALS['wp_options']    = array();
		$GLOBALS['wp_transients'] = array();

		require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';

		\ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
	}

	private function pretend_tier( string $tier ): void {
		$role_map = array(
			'free'         => 'reportedip_free',
			'contributor'  => 'reportedip_contributor',
			'professional' => 'reportedip_professional',
			'business'     => 'reportedip_business',
			'enterprise'   => 'reportedip_enterprise',
			'honeypot'     => 'reportedip_honeypot',
		);

		$GLOBALS['wp_transients']['reportedip_hive_api_status'] = array(
			'value'   => array( 'userRole' => $role_map[ $tier ] ?? 'reportedip_free' ),
			'expires' => time() + 600,
		);
		\ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
	}

	private function pretend_mode( string $mode ): void {
		$GLOBALS['wp_options']['reportedip_hive_operation_mode'] = $mode;
		$mm  = \ReportedIP_Hive_Mode_Manager::get_instance();
		$ref = new \ReflectionProperty( $mm, 'cached_mode' );
		$ref->setValue( $mm, null );
	}

	public function test_free_tier_returns_smallest_caps() {
		$caps = \ReportedIP_Hive_Mode_Manager::get_instance()->default_api_rate_limits_for_tier( 'free' );

		$this->assertSame( 150, $caps['reputation'] );
		$this->assertSame( 10, $caps['submission'] );
		$this->assertSame( 30, $caps['meta'] );
	}

	public function test_professional_and_business_scale_up() {
		$mm = \ReportedIP_Hive_Mode_Manager::get_instance();

		$pro = $mm->default_api_rate_limits_for_tier( 'professional' );
		$biz = $mm->default_api_rate_limits_for_tier( 'business' );

		$this->assertSame( 3000, $pro['reputation'] );
		$this->assertSame( 150, $pro['submission'] );
		$this->assertSame( 12000, $biz['reputation'] );
		$this->assertSame( 600, $biz['submission'] );

		$this->assertGreaterThan( $pro['reputation'], $biz['reputation'] );
		$this->assertGreaterThan( $pro['submission'], $biz['submission'] );
	}

	public function test_enterprise_and_honeypot_are_unlimited() {
		$mm = \ReportedIP_Hive_Mode_Manager::get_instance();

		foreach ( array( 'enterprise', 'honeypot' ) as $tier ) {
			$caps = $mm->default_api_rate_limits_for_tier( $tier );
			$this->assertNull( $caps['reputation'], "tier {$tier} reputation should be unlimited" );
			$this->assertNull( $caps['submission'], "tier {$tier} submission should be unlimited" );
			$this->assertNull( $caps['meta'], "tier {$tier} meta should be unlimited" );
		}
	}

	public function test_unknown_tier_falls_back_to_free_caps() {
		$caps = \ReportedIP_Hive_Mode_Manager::get_instance()->default_api_rate_limits_for_tier( 'galactic_emperor' );

		$this->assertSame( 150, $caps['reputation'] );
		$this->assertSame( 10, $caps['submission'] );
		$this->assertSame( 30, $caps['meta'] );
	}

	public function test_snapshot_resolves_to_tier_defaults_when_option_is_zero() {
		$this->pretend_tier( 'professional' );
		$GLOBALS['wp_options']['reportedip_hive_max_api_calls_per_hour'] = 0;

		$snap = \ReportedIP_Hive_Mode_Manager::get_instance()->get_api_rate_limit_snapshot();

		$this->assertSame( 'professional', $snap['tier'] );
		$this->assertSame( 'auto', $snap['source'] );
		$this->assertSame( 3000, $snap['limits']['reputation'] );
		$this->assertSame( 150, $snap['limits']['submission'] );
		$this->assertSame( 100, $snap['limits']['meta'] );
	}

	public function test_snapshot_honours_manual_override_uniformly() {
		$this->pretend_tier( 'free' );
		$GLOBALS['wp_options']['reportedip_hive_max_api_calls_per_hour'] = 750;

		$snap = \ReportedIP_Hive_Mode_Manager::get_instance()->get_api_rate_limit_snapshot();

		$this->assertSame( 'manual', $snap['source'] );
		$this->assertSame( 750, $snap['limits']['reputation'] );
		$this->assertSame( 750, $snap['limits']['submission'] );
		$this->assertSame( 750, $snap['limits']['meta'] );
	}

	public function test_snapshot_reports_used_counts_per_bucket_independently() {
		$this->pretend_tier( 'free' );
		$GLOBALS['wp_transients']['reportedip_hive_hourly_api_calls_reputation'] = array(
			'value'   => 123,
			'expires' => time() + 3600,
		);
		$GLOBALS['wp_transients']['reportedip_hive_hourly_api_calls_submission'] = array(
			'value'   => 4,
			'expires' => time() + 3600,
		);

		$snap = \ReportedIP_Hive_Mode_Manager::get_instance()->get_api_rate_limit_snapshot();

		$this->assertSame( 123, $snap['used']['reputation'] );
		$this->assertSame( 4, $snap['used']['submission'] );
		$this->assertSame( 0, $snap['used']['meta'] );
	}

	public function test_is_community_layer_degraded_is_false_in_local_mode() {
		$this->pretend_mode( 'local' );
		$this->pretend_tier( 'free' );

		$GLOBALS['wp_transients']['reportedip_hive_hourly_api_calls_reputation'] = array(
			'value'   => 9999,
			'expires' => time() + 3600,
		);

		$this->assertFalse( \ReportedIP_Hive_Mode_Manager::get_instance()->is_community_layer_degraded() );
	}

	public function test_is_community_layer_degraded_triggers_at_eighty_percent() {
		$this->pretend_mode( 'community' );
		$this->pretend_tier( 'free' );

		$GLOBALS['wp_transients']['reportedip_hive_hourly_api_calls_reputation'] = array(
			'value'   => 119,
			'expires' => time() + 3600,
		);
		$this->assertFalse(
			\ReportedIP_Hive_Mode_Manager::get_instance()->is_community_layer_degraded(),
			'Below 80% the layer should still be considered healthy.'
		);

		\ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		$GLOBALS['wp_transients']['reportedip_hive_hourly_api_calls_reputation'] = array(
			'value'   => 120,
			'expires' => time() + 3600,
		);
		$this->assertTrue(
			\ReportedIP_Hive_Mode_Manager::get_instance()->is_community_layer_degraded(),
			'At 80% of the Free reputation cap (150) the layer is degraded.'
		);
	}

	public function test_is_community_layer_degraded_picks_up_server_429() {
		$this->pretend_mode( 'community' );
		$this->pretend_tier( 'enterprise' );

		$GLOBALS['wp_transients']['reportedip_hive_rate_limit_reset'] = array(
			'value'   => time() + 600,
			'expires' => time() + 600,
		);

		$this->assertTrue(
			\ReportedIP_Hive_Mode_Manager::get_instance()->is_community_layer_degraded(),
			'A pending server-side 429 reset must surface as degraded.'
		);
	}
}
