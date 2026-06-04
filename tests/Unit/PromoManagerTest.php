<?php
/**
 * Unit tests for {@see ReportedIP_Hive_Promo_Manager}.
 *
 * Locks down the three guard rails — killswitch, 90-day global cap, 60-day
 * per-feature cooldown — plus the permanent-opt-out path and the
 * reset-for-user lifecycle hook used by the tier-upgrade flow.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.16
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

require_once dirname( __DIR__, 2 ) . '/includes/class-promo-manager.php';

class PromoManagerTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options']     = array();
		$GLOBALS['wp_user_meta']   = array();
		$GLOBALS['wp_user_caps']   = array();
		$GLOBALS['wp_current_user_id'] = 42;
	}

	private function key(): string {
		return \ReportedIP_Hive_Promo_Manager::KEY_WC_FRONTEND_2FA;
	}

	public function test_can_show_returns_true_for_a_fresh_user_with_killswitch_default_on(): void {
		$this->assertTrue( \ReportedIP_Hive_Promo_Manager::can_show( $this->key(), 42 ) );
	}

	public function test_killswitch_off_blocks_all_promo_keys(): void {
		$GLOBALS['wp_options'][ \ReportedIP_Hive_Promo_Manager::OPT_ENABLED ] = false;
		$this->assertFalse( \ReportedIP_Hive_Promo_Manager::can_show( $this->key(), 42 ) );
		$this->assertFalse(
			\ReportedIP_Hive_Promo_Manager::can_show( \ReportedIP_Hive_Promo_Manager::KEY_MAIL_SMS_RELAY, 42 )
		);
	}

	public function test_mark_shown_blocks_global_cap_for_ninety_days(): void {
		\ReportedIP_Hive_Promo_Manager::mark_shown( $this->key(), 42 );

		// A different feature still hits the global cap.
		$this->assertFalse(
			\ReportedIP_Hive_Promo_Manager::can_show( \ReportedIP_Hive_Promo_Manager::KEY_MAIL_SMS_RELAY, 42 ),
			'A render of one promo key consumes a slot for ALL keys via the 90-day global cap.'
		);

		// Simulate 91 days passing — the global cap should release.
		$last = (int) get_user_meta( 42, \ReportedIP_Hive_Promo_Manager::META_LAST_SHOWN, true );
		$this->assertGreaterThan( 0, $last );
		update_user_meta(
			42,
			\ReportedIP_Hive_Promo_Manager::META_LAST_SHOWN,
			$last - ( \ReportedIP_Hive_Promo_Manager::GLOBAL_FREQUENCY_CAP_SECS + 60 )
		);
		// Also rewind the per-feature stamp so that path doesn't shadow the test.
		$map = get_user_meta( 42, \ReportedIP_Hive_Promo_Manager::META_DISMISSED_MAP, true );
		$map[ $this->key() ] = $last - ( \ReportedIP_Hive_Promo_Manager::PER_FEATURE_COOLDOWN_SECS + 60 );
		update_user_meta( 42, \ReportedIP_Hive_Promo_Manager::META_DISMISSED_MAP, $map );

		$this->assertTrue(
			\ReportedIP_Hive_Promo_Manager::can_show(
				\ReportedIP_Hive_Promo_Manager::KEY_MAIL_SMS_RELAY,
				42
			)
		);
	}

	public function test_per_feature_cooldown_blocks_only_that_feature(): void {
		// Manually set the per-feature timestamp without touching the global
		// last-shown timestamp, so we isolate the per-feature behaviour.
		$now = time();
		update_user_meta(
			42,
			\ReportedIP_Hive_Promo_Manager::META_DISMISSED_MAP,
			array( $this->key() => $now )
		);

		$this->assertFalse(
			\ReportedIP_Hive_Promo_Manager::can_show( $this->key(), 42 ),
			'Same key within the 60-day per-feature cooldown is blocked.'
		);
		$this->assertTrue(
			\ReportedIP_Hive_Promo_Manager::can_show(
				\ReportedIP_Hive_Promo_Manager::KEY_HARDENING_MODE,
				42
			),
			'A different key with no per-feature timestamp and no global last-shown remains visible.'
		);
	}

	public function test_permanent_optout_blocks_forever(): void {
		\ReportedIP_Hive_Promo_Manager::mark_permanently_dismissed( $this->key(), 42 );

		// Even with a fresh user-meta state for the cooldown caps, opt-out wins.
		$this->assertFalse( \ReportedIP_Hive_Promo_Manager::can_show( $this->key(), 42 ) );
	}

	public function test_reset_for_user_clears_caps_but_preserves_optout(): void {
		\ReportedIP_Hive_Promo_Manager::mark_shown( $this->key(), 42 );
		\ReportedIP_Hive_Promo_Manager::mark_permanently_dismissed(
			\ReportedIP_Hive_Promo_Manager::KEY_HARDENING_MODE,
			42
		);

		\ReportedIP_Hive_Promo_Manager::reset_for_user( 42 );

		// Cap is cleared — the key we just showed becomes visible again.
		$this->assertTrue( \ReportedIP_Hive_Promo_Manager::can_show( $this->key(), 42 ) );
		// Opt-out is explicit user intent and survives the reset.
		$this->assertFalse(
			\ReportedIP_Hive_Promo_Manager::can_show(
				\ReportedIP_Hive_Promo_Manager::KEY_HARDENING_MODE,
				42
			)
		);
	}

	public function test_unknown_user_id_returns_false(): void {
		$GLOBALS['wp_current_user_id'] = 0;
		$this->assertFalse( \ReportedIP_Hive_Promo_Manager::can_show( $this->key(), 0 ) );
	}

	public function test_empty_key_returns_false(): void {
		$this->assertFalse( \ReportedIP_Hive_Promo_Manager::can_show( '', 42 ) );
	}
}
