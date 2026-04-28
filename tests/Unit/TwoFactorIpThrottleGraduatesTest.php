<?php
/**
 * Unit tests for the 2FA per-IP throttle → escalation-block graduation.
 *
 * The 2FA per-IP throttle had its own LOCKOUT_THRESHOLDS array (3→30 s,
 * 5→300 s, 10→1800 s, 15→3600 s) that capped at one hour and forgot
 * because the transient TTL was HOUR_IN_SECONDS — a brute-forcer who
 * paced themselves around that hour was never promoted to a real
 * `wp_reportedip_hive_blocked` row, so the progressive-escalation
 * ladder + community-mode reporting never fired against them.
 *
 * 1.5.2 fix: when the per-IP failure count reaches the top threshold
 * (15), graduate to the central `auto_block_ip()` path. This test
 * locks down the contract via source-pattern matching — a refactor
 * that drops the graduation will fail the test.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.5.2
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class TwoFactorIpThrottleGraduatesTest extends TestCase {

		private function source(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor.php' );
		}

		public function test_lockout_thresholds_table_is_intact(): void {
			$source = $this->source();
			foreach ( array( '3  => 30,', '5  => 300,', '10 => 1800,', '15 => 3600,' ) as $rung ) {
				$this->assertStringContainsString(
					$rung,
					$source,
					"LOCKOUT_THRESHOLDS rung '{$rung}' was removed; the gentle pre-graduation ladder is intentional and must stay tuned for legitimate-user typos."
				);
			}
		}

		public function test_top_threshold_is_resolved_dynamically(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'max( array_keys( self::LOCKOUT_THRESHOLDS ) )',
				$source,
				'The graduation must read the top threshold from the LOCKOUT_THRESHOLDS array, not a hardcoded 15 — otherwise tuning the ladder later will silently break graduation.'
			);
		}

		public function test_graduation_calls_canonical_threshold_handler_with_brute_force_event(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'handle_threshold_exceeded(',
				$source,
				'increment_ip_failed_attempts() must escalate via the canonical handle_threshold_exceeded() entry point — auto_block_ip() alone bypasses community-mode API reporting and admin notification.'
			);
			$this->assertDoesNotMatchRegularExpression(
				'/->\s*auto_block_ip\s*\(/',
				$source,
				'2FA graduation must NOT call auto_block_ip() directly: that path skips report_security_event() and would silently drop community-mode reports for 2FA brute force.'
			);
			$this->assertStringContainsString(
				"'2fa_brute_force'",
				$source,
				"The graduation must use the '2fa_brute_force' event_type so dashboards and community-mode reports can attribute the block correctly."
			);
		}

		public function test_graduation_clears_the_transient(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'delete_transient( $key )',
				$source,
				'After graduating, the per-IP transient must be cleared so the block table is the new source of truth (otherwise both layers would race).'
			);
		}

		public function test_graduation_uses_the_security_monitor_service_locator(): void {
			$source = $this->source();
			$this->assertStringContainsString(
				'ReportedIP_Hive::get_instance()',
				$source,
				'Graduation must reuse the existing ReportedIP_Hive service locator.'
			);
			$this->assertStringContainsString(
				'get_security_monitor()',
				$source,
				'Graduation must obtain the security monitor through the service locator so the same instance handles the block (escalation history is per-instance state).'
			);
		}
	}
}
