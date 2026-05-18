<?php
/**
 * Architecture invariant tests for the REST monitor bot allowlist.
 *
 * Confirms that ReportedIP_Hive_REST_Monitor consults
 * ReportedIP_Hive_Bot_Allowlist between the whitelist check and the call to
 * track_generic_attempt(). The full pre_dispatch flow depends on too many
 * runtime singletons to mock cheaply, so we anchor the contract via source
 * inspection — a refactor that breaks the ordering trips the test.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.5
 */

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class RestMonitorBotAllowlistTest extends TestCase {

		private function source(): string {
			$path = dirname( __DIR__, 2 ) . '/includes/class-rest-monitor.php';
			$buf  = file_get_contents( $path );
			$this->assertNotFalse( $buf, 'rest-monitor source must be readable' );
			return (string) $buf;
		}

		public function test_rest_monitor_consults_bot_allowlist() {
			$source = $this->source();
			$this->assertStringContainsString(
				'ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot',
				$source,
				'REST monitor must call the bot allowlist verifier'
			);
			$this->assertStringContainsString(
				"'reportedip_hive_bot_allowlist_enabled'",
				$source,
				'REST monitor must respect the master toggle option'
			);
		}

		public function test_bot_check_runs_before_track_generic_attempt() {
			$source = $this->source();

			$bot_check_pos  = strpos( $source, 'is_verified_search_or_ai_bot' );
			$track_call_pos = strpos( $source, 'track_generic_attempt' );

			$this->assertNotFalse( $bot_check_pos );
			$this->assertNotFalse( $track_call_pos );
			$this->assertLessThan(
				$track_call_pos,
				$bot_check_pos,
				'Bot allowlist check must run before track_generic_attempt() handoff'
			);
		}

		public function test_bot_check_runs_after_whitelist_check() {
			$source = $this->source();

			$whitelist_pos = strpos( $source, 'is_whitelisted' );
			$bot_check_pos = strpos( $source, 'is_verified_search_or_ai_bot' );

			$this->assertNotFalse( $whitelist_pos );
			$this->assertNotFalse( $bot_check_pos );
			$this->assertLessThan(
				$bot_check_pos,
				$whitelist_pos,
				'Explicit IP whitelist takes precedence over the UA-based bot allowlist'
			);
		}
	}
}
