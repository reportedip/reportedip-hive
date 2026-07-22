<?php
/**
 * Architecture invariant tests for the central never-block-a-good-bot guard.
 *
 * Every automatic IP block funnels through
 * `Security_Monitor::handle_threshold_exceeded()`; the guard must run there
 * FIRST — before the threshold log, the block, the community API report and
 * the admin mail — and again defensively inside `auto_block_ip()` for direct
 * callers. The full monitor depends on too many runtime singletons to mock
 * cheaply, so the contract is anchored via source inspection (the established
 * pattern, see RestMonitorBotAllowlistTest); the verdict-combination logic
 * itself is behaviourally covered in BotAllowlistExemptionTest.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.26
 */

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class SecurityMonitorBotGuardTest extends TestCase {

		private function source(): string {
			$path = dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php';
			$buf  = file_get_contents( $path );
			$this->assertNotFalse( $buf, 'security-monitor source must be readable' );
			return (string) $buf;
		}

		public function test_guard_consults_unified_crawler_exemption() {
			$this->assertStringContainsString(
				'ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler',
				$this->source(),
				'The central guard must use the unified crawler-exemption decision'
			);
		}

		public function test_guard_runs_first_in_handle_threshold_exceeded() {
			$source = $this->source();

			$handler_pos = strpos( $source, 'function handle_threshold_exceeded' );
			$this->assertNotFalse( $handler_pos );

			$body       = substr( $source, $handler_pos );
			$guard_pos  = strpos( $body, 'should_spare_verified_bot' );
			$log_pos    = strpos( $body, 'log_security_event' );
			$block_pos  = strpos( $body, 'auto_block_ip' );
			$report_pos = strpos( $body, 'report_security_event' );

			$this->assertNotFalse( $guard_pos );
			$this->assertLessThan( $log_pos, $guard_pos, 'Guard must run before the threshold-exceeded log entry' );
			$this->assertLessThan( $block_pos, $guard_pos, 'Guard must run before the auto-block' );
			$this->assertLessThan( $report_pos, $guard_pos, 'Guard must run before the community API report' );
		}

		public function test_auto_block_ip_has_defensive_recheck() {
			$source = $this->source();

			$block_fn_pos = strpos( $source, 'function auto_block_ip' );
			$this->assertNotFalse( $block_fn_pos );

			$body      = substr( $source, $block_fn_pos );
			$guard_pos = strpos( $body, 'should_spare_verified_bot' );
			$write_pos = strpos( $body, '->block_ip(' );

			$this->assertNotFalse( $guard_pos, 'auto_block_ip() must re-check the exemption for direct callers' );
			$this->assertNotFalse( $write_pos );
			$this->assertLessThan( $write_pos, $guard_pos, 'The re-check must precede the block write' );
		}

		public function test_averted_decisions_are_logged() {
			$this->assertStringContainsString(
				"'verified_bot_block_averted'",
				$this->source(),
				'Averted blocks must be visible to operators in the security log'
			);
		}

		public function test_guard_survives_missing_user_agent() {
			$source = $this->source();

			$guard_fn_pos = strpos( $source, 'function should_spare_verified_bot' );
			$this->assertNotFalse( $guard_fn_pos );

			$body = substr( $source, $guard_fn_pos, 1200 );
			$this->assertStringContainsString(
				"HTTP_USER_AGENT",
				$body,
				'Guard reads the UA from the request when present'
			);
			$this->assertStringContainsString(
				": ''",
				$body,
				'Guard must degrade to an empty UA (IP-only check) in cron/CLI contexts'
			);
		}
	}
}
