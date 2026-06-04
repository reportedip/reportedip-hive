<?php
/**
 * Unit tests for {@see ReportedIP_Hive_Two_Factor_WC_Notice}.
 *
 * Locks down the contract that frequency/dismiss state is delegated to
 * {@see ReportedIP_Hive_Promo_Manager} and that the gate-conditions
 * (WooCommerce active, tier-locked, manage_options) stay in place.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.7.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

class TwoFactorWcNoticeTest extends TestCase {

	private function source(): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-wc-notice.php' );
	}

	public function test_gate_requires_woocommerce_active(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			"class_exists( 'WooCommerce' )",
			$source,
			'should_show() must short-circuit when WC is not active — promoting a WC-only feature on a plain WP install is noise.'
		);
	}

	public function test_gate_requires_tier_reason(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			"'tier' !== ( \$status['reason'] ?? '' )",
			$source,
			'The promo must specifically target tier-locked sites. Mode-locked sites get a different banner from the operation-mode card.'
		);
	}

	public function test_gate_requires_manage_options_capability(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			"user_can( \$user_id, 'manage_options' )",
			$source,
			'Customer / Subscriber roles must never see the upgrade promo — only operators (manage_options) decide on plans.'
		);
	}

	public function test_gate_consults_promo_manager_can_show(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			'ReportedIP_Hive_Promo_Manager::can_show(',
			$source,
			'Frequency cap and killswitch must be delegated to Promo_Manager — every promo surface stays in lockstep through that single chokepoint.'
		);
		$this->assertStringContainsString(
			'ReportedIP_Hive_Promo_Manager::KEY_WC_FRONTEND_2FA',
			$source,
			'The WC-Frontend-2FA promo key must be the constant from Promo_Manager so a rename is one-shot.'
		);
	}

	public function test_render_marks_promo_shown(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			'ReportedIP_Hive_Promo_Manager::mark_shown(',
			$source,
			'maybe_render() must call mark_shown() after rendering so the global frequency cap is honoured.'
		);
	}

	public function test_dismiss_handler_calls_promo_manager(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			'ReportedIP_Hive_Promo_Manager::mark_dismissed(',
			$source,
			'The dismiss handler must route through Promo_Manager::mark_dismissed so the per-feature cooldown is set centrally.'
		);
	}

	public function test_dismiss_handler_verifies_nonce(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			"check_admin_referer( 'reportedip_hive_wc2fa_promo_dismiss' )",
			$source,
			'Dismiss must be CSRF-protected — otherwise an external link could silently mute the banner for the admin.'
		);
	}

	public function test_eligible_screens_kept_short(): void {
		$source = $this->source();
		foreach ( array( "'dashboard'", "'plugins'", "'reportedip-hive'" ) as $screen ) {
			$this->assertStringContainsString(
				$screen,
				$source,
				"Eligible screen '{$screen}' must remain in the allow-list — banner everywhere defeats the cooldown."
			);
		}
	}
}
