<?php
/**
 * Unit tests for Mode_Manager::feature_status() and the tier display helpers.
 *
 * Locks down the contract every future tier-gated feature relies on:
 * the four reason codes (ok / mode / tier / unknown), the min_tier carry,
 * the per-request tier memo, and the tier_changed flush hook.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.5.3
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class ModeManagerFeatureStatusTest extends TestCase {

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

	/**
	 * Helper: pretend the API has reported a specific user role.
	 */
	private function pretend_tier( string $tier ): void {
		$role_map                                                = array(
			'free'         => 'reportedip_free',
			'contributor'  => 'reportedip_contributor',
			'professional' => 'reportedip_professional',
			'business'     => 'reportedip_business',
			'enterprise'   => 'reportedip_enterprise',
		);
		$GLOBALS['wp_transients']['reportedip_hive_api_status'] = array(
			'value'   => array( 'userRole' => $role_map[ $tier ] ?? 'reportedip_free' ),
			'expires' => time() + 600,
		);
		\ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
	}

	/**
	 * Helper: switch operation mode and reset the singleton's mode cache.
	 */
	private function pretend_mode( string $mode ): void {
		$GLOBALS['wp_options']['reportedip_hive_operation_mode'] = $mode;
		$mm                                                      = \ReportedIP_Hive_Mode_Manager::get_instance();
		$ref                                                     = new \ReflectionProperty( $mm, 'cached_mode' );
		$ref->setValue( $mm, null );
	}

	public function test_feature_available_returns_ok_reason() {
		$this->pretend_mode( 'community' );
		$status = \ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'login_monitoring' );

		$this->assertTrue( $status['available'] );
		$this->assertSame( 'ok', $status['reason'] );
		$this->assertNull( $status['mode_required'] );
	}

	public function test_unknown_feature_returns_unknown_reason() {
		$status = \ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'never_existed' );

		$this->assertFalse( $status['available'] );
		$this->assertSame( 'unknown', $status['reason'] );
		$this->assertNull( $status['min_tier'] );
		$this->assertSame( '', $status['label'] );
	}

	public function test_local_mode_blocks_community_only_feature_with_mode_reason() {
		$this->pretend_mode( 'local' );
		$status = \ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'api_reputation_check' );

		$this->assertFalse( $status['available'] );
		$this->assertSame( 'mode', $status['reason'] );
		$this->assertSame( 'community', $status['mode_required'] );
	}

	public function test_free_tier_blocks_relay_with_tier_reason() {
		$this->pretend_mode( 'community' );
		$this->pretend_tier( 'free' );

		$status = \ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'sms_relay_via_api' );

		$this->assertFalse( $status['available'] );
		$this->assertSame( 'tier', $status['reason'] );
		$this->assertSame( 'professional', $status['min_tier'] );
	}

	public function test_professional_tier_unlocks_relay() {
		$this->pretend_mode( 'community' );
		$this->pretend_tier( 'professional' );

		$status = \ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'mail_relay_via_api' );

		$this->assertTrue( $status['available'] );
		$this->assertSame( 'ok', $status['reason'] );
	}

	public function test_local_mode_takes_precedence_over_tier_check() {
		$this->pretend_mode( 'local' );
		$this->pretend_tier( 'enterprise' );

		$status = \ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'mail_relay_via_api' );

		$this->assertFalse( $status['available'] );
		$this->assertSame( 'mode', $status['reason'] );
		$this->assertSame( 'community', $status['mode_required'] );
	}

	public function test_tier_at_least_walks_the_order() {
		$this->pretend_mode( 'community' );
		$this->pretend_tier( 'business' );

		$mm = \ReportedIP_Hive_Mode_Manager::get_instance();

		$this->assertTrue( $mm->tier_at_least( 'free' ) );
		$this->assertTrue( $mm->tier_at_least( 'professional' ) );
		$this->assertTrue( $mm->tier_at_least( 'business' ) );
		$this->assertFalse( $mm->tier_at_least( 'enterprise' ) );
	}

	public function test_get_tier_info_returns_display_tokens_for_known_tier() {
		$info = \ReportedIP_Hive_Mode_Manager::get_instance()->get_tier_info( 'professional' );

		$this->assertSame( 'professional', $info['key'] );
		$this->assertSame( 'PRO', $info['short_label'] );
		$this->assertSame( 'rip-tier-badge--professional', $info['badge_class'] );
		$this->assertStringContainsString( '<svg', $info['icon'] );
	}

	public function test_get_tier_info_falls_back_to_free_for_unknown_tier() {
		$info = \ReportedIP_Hive_Mode_Manager::get_instance()->get_tier_info( 'galactic_emperor' );

		$this->assertSame( 'free', $info['key'] );
	}

	public function test_relay_quota_snapshot_uses_tier_defaults_when_empty() {
		$this->pretend_tier( 'professional' );
		$snapshot = \ReportedIP_Hive_Mode_Manager::get_instance()->get_relay_quota_snapshot();

		$this->assertSame( 'professional', $snapshot['tier'] );
		$this->assertTrue( $snapshot['is_stale'] );
		$this->assertSame( 500, $snapshot['mail']['limit'] );
		$this->assertSame( 25, $snapshot['sms']['limit'] );
		$this->assertSame( 0, $snapshot['mail']['used'] );
	}

	public function test_relay_quota_snapshot_overlays_cached_payload() {
		$this->pretend_tier( 'business' );
		$GLOBALS['wp_transients']['reportedip_hive_relay_quota'] = array(
			'value'   => array(
				'tier'               => 'business',
				'mail'               => array(
					'used'  => 1100,
					'limit' => 2500,
				),
				'sms'                => array(
					'used'  => 12,
					'limit' => 75,
				),
				'sms_bundle_balance' => 50,
				'fetched_at'         => time(),
			),
			'expires' => time() + 3600,
		);

		$snapshot = \ReportedIP_Hive_Mode_Manager::get_instance()->get_relay_quota_snapshot();

		$this->assertFalse( $snapshot['is_stale'] );
		$this->assertSame( 1100, $snapshot['mail']['used'] );
		$this->assertSame( 50, $snapshot['sms_bundle_balance'] );
	}

	public function test_tier_changed_action_flushes_memo() {
		$this->pretend_mode( 'community' );
		$this->pretend_tier( 'free' );

		$mm = \ReportedIP_Hive_Mode_Manager::get_instance();
		$this->assertSame( 'free', $mm->get_current_tier() );

		$GLOBALS['wp_transients']['reportedip_hive_api_status']['value']['userRole'] = 'reportedip_business';
		\do_action( 'reportedip_hive_tier_changed', 'free', 'business' );

		$this->assertSame( 'business', $mm->get_current_tier() );
	}
}
