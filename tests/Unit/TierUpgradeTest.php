<?php
/**
 * Unit tests for ReportedIP_Hive_Tier_Upgrade.
 *
 * Locks down the post-upgrade soft-activation contract:
 *  - upgrade detection (Free/Contributor → PRO+ true; cross-paid, downgrade and
 *    same-tier transitions false),
 *  - SMS-provider prefill only when the option was empty,
 *  - email method auto-added to the allow-list without removing existing entries,
 *  - notice payload set on upgrade, dismissed flag cleared so a fresh upgrade
 *    re-shows the banner,
 *  - should_show_notice() lifecycle (open → done auto-hides without dismiss).
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.7.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

require_once dirname( __DIR__, 2 ) . '/includes/class-tier-upgrade.php';

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class TierUpgradeTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options']    = array();
		$GLOBALS['wp_transients'] = array();
		require_once dirname( __DIR__, 2 ) . '/includes/class-tier-upgrade.php';
	}

	public function test_is_upgrade_to_pro_free_to_professional() {
		$this->assertTrue( \ReportedIP_Hive_Tier_Upgrade::is_upgrade_to_pro( 'free', 'professional' ) );
	}

	public function test_is_upgrade_to_pro_contributor_to_business() {
		$this->assertTrue( \ReportedIP_Hive_Tier_Upgrade::is_upgrade_to_pro( 'contributor', 'business' ) );
	}

	public function test_is_upgrade_to_pro_free_to_enterprise() {
		$this->assertTrue( \ReportedIP_Hive_Tier_Upgrade::is_upgrade_to_pro( 'free', 'enterprise' ) );
	}

	public function test_is_upgrade_to_pro_cross_paid_is_false() {
		$this->assertFalse( \ReportedIP_Hive_Tier_Upgrade::is_upgrade_to_pro( 'professional', 'business' ) );
	}

	public function test_is_upgrade_to_pro_downgrade_is_false() {
		$this->assertFalse( \ReportedIP_Hive_Tier_Upgrade::is_upgrade_to_pro( 'business', 'free' ) );
		$this->assertFalse( \ReportedIP_Hive_Tier_Upgrade::is_upgrade_to_pro( 'professional', 'free' ) );
	}

	public function test_is_upgrade_to_pro_same_tier_is_false() {
		$this->assertFalse( \ReportedIP_Hive_Tier_Upgrade::is_upgrade_to_pro( 'free', 'free' ) );
		$this->assertFalse( \ReportedIP_Hive_Tier_Upgrade::is_upgrade_to_pro( 'professional', 'professional' ) );
	}

	public function test_on_tier_changed_prefills_empty_provider_with_relay() {
		\ReportedIP_Hive_Tier_Upgrade::on_tier_changed( 'free', 'professional' );
		$this->assertSame(
			'reportedip_relay',
			$GLOBALS['wp_options']['reportedip_hive_2fa_sms_provider'] ?? null
		);
	}

	public function test_on_tier_changed_respects_existing_provider() {
		$GLOBALS['wp_options']['reportedip_hive_2fa_sms_provider'] = 'sipgate';
		\ReportedIP_Hive_Tier_Upgrade::on_tier_changed( 'free', 'professional' );
		$this->assertSame( 'sipgate', $GLOBALS['wp_options']['reportedip_hive_2fa_sms_provider'] );
	}

	public function test_on_tier_changed_writes_notice_payload() {
		\ReportedIP_Hive_Tier_Upgrade::on_tier_changed( 'contributor', 'business' );

		$notice = $GLOBALS['wp_options']['reportedip_hive_tier_upgrade_notice'] ?? null;
		$this->assertIsArray( $notice );
		$this->assertSame( 'contributor', $notice['from'] );
		$this->assertSame( 'business', $notice['to'] );
		$this->assertGreaterThan( 0, (int) ( $notice['set_at'] ?? 0 ) );
	}

	public function test_on_tier_changed_clears_previous_dismiss_flag() {
		$GLOBALS['wp_options']['reportedip_hive_tier_upgrade_dismissed'] = true;
		\ReportedIP_Hive_Tier_Upgrade::on_tier_changed( 'free', 'professional' );
		$this->assertArrayNotHasKey( 'reportedip_hive_tier_upgrade_dismissed', $GLOBALS['wp_options'] );
	}

	public function test_on_tier_changed_skips_for_non_upgrade() {
		\ReportedIP_Hive_Tier_Upgrade::on_tier_changed( 'professional', 'business' );
		$this->assertArrayNotHasKey( 'reportedip_hive_tier_upgrade_notice', $GLOBALS['wp_options'] );
		$this->assertArrayNotHasKey( 'reportedip_hive_2fa_sms_provider', $GLOBALS['wp_options'] );
	}

	public function test_on_tier_changed_adds_email_to_allowed_methods_when_missing() {
		$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'] = '["totp","webauthn"]';
		\ReportedIP_Hive_Tier_Upgrade::on_tier_changed( 'free', 'professional' );

		$decoded = json_decode( (string) $GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'], true );
		$this->assertIsArray( $decoded );
		$this->assertContains( 'email', $decoded );
		$this->assertContains( 'totp', $decoded );
		$this->assertContains( 'webauthn', $decoded );
	}

	public function test_on_tier_changed_does_not_duplicate_email_when_already_present() {
		$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'] = '["totp","email"]';
		\ReportedIP_Hive_Tier_Upgrade::on_tier_changed( 'free', 'professional' );

		$decoded = json_decode( (string) $GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'], true );
		$this->assertSame( array( 'totp', 'email' ), $decoded );
	}

	public function test_should_show_notice_false_without_payload() {
		$this->assertFalse( \ReportedIP_Hive_Tier_Upgrade::should_show_notice() );
	}

	public function test_should_show_notice_false_when_dismissed() {
		\ReportedIP_Hive_Tier_Upgrade::on_tier_changed( 'free', 'professional' );
		$GLOBALS['wp_options']['reportedip_hive_tier_upgrade_dismissed'] = true;
		$this->assertFalse( \ReportedIP_Hive_Tier_Upgrade::should_show_notice() );
	}

	public function test_should_show_notice_false_when_all_steps_done() {
		\ReportedIP_Hive_Tier_Upgrade::on_tier_changed( 'free', 'professional' );
		$GLOBALS['wp_options']['reportedip_hive_2fa_sms_avv_confirmed']  = true;
		$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods']    = '["totp","email","sms"]';

		$this->assertFalse( \ReportedIP_Hive_Tier_Upgrade::should_show_notice() );
	}

	public function test_should_show_notice_true_when_avv_open() {
		\ReportedIP_Hive_Tier_Upgrade::on_tier_changed( 'free', 'professional' );
		$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'] = '["totp","email","sms"]';

		$this->assertTrue( \ReportedIP_Hive_Tier_Upgrade::should_show_notice() );
	}

	public function test_get_setup_checklist_marks_provider_done_when_relay_selected() {
		$GLOBALS['wp_options']['reportedip_hive_2fa_sms_provider'] = 'reportedip_relay';

		$items = \ReportedIP_Hive_Tier_Upgrade::get_setup_checklist();
		$by    = array();
		foreach ( $items as $item ) {
			$by[ $item['key'] ] = $item['done'];
		}

		$this->assertTrue( $by['provider'] );
		$this->assertFalse( $by['avv'] );
		$this->assertFalse( $by['method'] );
	}

	public function test_get_setup_checklist_marks_method_done_when_sms_in_allow_list() {
		$GLOBALS['wp_options']['reportedip_hive_2fa_allowed_methods'] = '["totp","sms"]';

		$items = \ReportedIP_Hive_Tier_Upgrade::get_setup_checklist();
		$by    = array();
		foreach ( $items as $item ) {
			$by[ $item['key'] ] = $item['done'];
		}

		$this->assertTrue( $by['method'] );
	}
}
