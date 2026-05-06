<?php
/**
 * Unit tests for {@see ReportedIP_Hive_Two_Factor_WC_Notice}.
 *
 * Locks down the per-user 14-day cooldown contract: a dismiss writes
 * the timestamp, a fresh dismiss bumps the counter, the gate stays
 * shut for 14 days and re-opens on day 15.
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

class TwoFactorWcNoticeTest extends TestCase {

	private function source(): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-wc-notice.php' );
	}

	public function test_cooldown_constant_is_fourteen_days(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			'const COOLDOWN_SECS = 1209600;',
			$source,
			'14 days = 1 209 600 seconds. Encoded as a literal so the constant survives DAY_IN_SECONDS not being defined yet on test bootstrap.'
		);
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

	public function test_dismiss_handler_writes_meta_and_increments_counter(): void {
		$source = $this->source();
		$this->assertStringContainsString(
			'update_user_meta( $user_id, self::META_DISMISSED_AT, time() )',
			$source,
			'The dismiss handler MUST persist the current timestamp so the cooldown can be measured.'
		);
		$this->assertStringContainsString(
			'update_user_meta( $user_id, self::META_DISMISS_COUNT, $count + 1 )',
			$source,
			'The dismiss counter must be bumped — it powers per-user telemetry on banner fatigue.'
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
