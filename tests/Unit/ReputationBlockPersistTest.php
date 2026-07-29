<?php
/**
 * Architecture invariant tests for the persistent community-reputation block.
 *
 * A reputation verdict above the block threshold must not only fail the
 * current login — it must write a temporary `reputation` row into the
 * blocked table so the IP is blocked on every surface (front-end, XML-RPC,
 * REST) and is visible in the Blocked IPs list. The full plugin bootstrap
 * depends on too many runtime singletons to mock cheaply, so the contract
 * is anchored via source inspection (the established pattern, see
 * SecurityMonitorBotGuardTest).
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.28
 */

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class ReputationBlockPersistTest extends TestCase {

		private function pre_auth_body(): string {
			$path = dirname( __DIR__, 2 ) . '/reportedip-hive.php';
			$buf  = file_get_contents( $path );
			$this->assertNotFalse( $buf, 'main plugin source must be readable' );

			$start = strpos( (string) $buf, 'function pre_auth_check' );
			$this->assertNotFalse( $start, 'pre_auth_check must exist' );

			$body = substr( (string) $buf, $start );
			$end  = strpos( $body, 'public function handle_comment_post' );
			$this->assertNotFalse( $end, 'pre_auth_check body must be boundable' );

			return substr( $body, 0, $end );
		}

		public function test_reputation_hit_writes_a_reputation_block_row() {
			$body = $this->pre_auth_body();

			$block_pos = strpos( $body, '->block_ip(' );
			$this->assertNotFalse( $block_pos, 'A reputation hit must persist a block row' );
			$this->assertStringContainsString(
				"'reputation'",
				$body,
				'The persisted block must carry the reputation block type'
			);
		}

		public function test_block_row_is_written_before_the_login_is_rejected() {
			$body = $this->pre_auth_body();

			$block_pos = strpos( $body, '->block_ip(' );
			$error_pos = strpos( $body, "'ip_reputation_block'" );

			$this->assertNotFalse( $block_pos );
			$this->assertNotFalse( $error_pos );
			$this->assertLessThan(
				$error_pos,
				$block_pos,
				'The block row must be written before the WP_Error is returned'
			);
		}

		public function test_whitelisted_ips_are_never_reputation_blocked() {
			$body = $this->pre_auth_body();

			$guard_pos = strpos( $body, 'is_whitelisted' );
			$block_pos = strpos( $body, '->block_ip(' );

			$this->assertNotFalse( $guard_pos, 'The whitelist must be consulted' );
			$this->assertNotFalse( $block_pos );
			$this->assertLessThan(
				$block_pos,
				$guard_pos,
				'The whitelist guard must precede the block write'
			);
		}

		public function test_reputation_blocks_bump_the_daily_stat() {
			$this->assertStringContainsString(
				"update_daily_stats( 'reputation_blocks' )",
				$this->pre_auth_body(),
				'Persisted reputation blocks must be counted in the daily stats'
			);
		}

		public function test_block_duration_is_filterable_with_24h_default() {
			$body = $this->pre_auth_body();

			$this->assertStringContainsString(
				"'reportedip_hive_reputation_block_hours', 24",
				$body,
				'The block duration must default to 24 hours and stay filterable'
			);
		}

		public function test_request_level_block_cache_is_primed() {
			$this->assertStringContainsString(
				'mark_ip_blocked',
				$this->pre_auth_body(),
				'The request-level block cache must be primed so later hooks in the same request short-circuit'
			);
		}

		public function test_report_only_mode_does_not_persist_a_block() {
			$body = $this->pre_auth_body();

			$report_only_return = strpos( $body, 'return $user;' );
			$block_pos          = strpos( $body, '->block_ip(' );

			$this->assertNotFalse( $report_only_return, 'The report-only branch must return early' );
			$this->assertNotFalse( $block_pos );
			$this->assertLessThan(
				$block_pos,
				$report_only_return,
				'The block write must sit after the report-only early return'
			);
		}
	}
}
