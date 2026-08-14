<?php
/**
 * Regression tests for the own-server-IP guard (2.1.31).
 *
 * Cache-preload crawlers, WP-Cron loopbacks and REST self-requests connect
 * back through the site's public URL, so their REMOTE_ADDR is the server's
 * own public address — which passes is_public_ip(). Without a guard the
 * burst sensors auto-blocked that address (enforced by the pre-WordPress
 * drop-in before any path exception, answering every later preload with a
 * 403) and reported the server to the community API against its own
 * reputation. Observed in the field: a Multisite carried a seven-day
 * automatic block of its own IPv6.
 *
 * The heavy classes cannot be instantiated in the unit suite, so — like the
 * other main-file guards — these tests lock the critical source properties:
 *
 *  1. is_own_server_ip() exists and covers loopback, SERVER_ADDR and the
 *     addresses the site hostname resolves to, extensible via filter.
 *  2. handle_threshold_exceeded() stands down before any consequence fires.
 *  3. auto_block_ip() re-checks for direct callers.
 *  4. The reputation-block path in pre_auth_check() is exempt as well.
 *  5. A migration lifts self-blocks that are already active.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.31
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class SelfIpGuardTest extends TestCase {

		private function main_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
		}

		private function monitor_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php' );
		}

		private function migration_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-migration-manager.php' );
		}

		public function test_is_own_server_ip_helper_exists() {
			$src = $this->main_file();
			$this->assertStringContainsString( 'function is_own_server_ip(', $src, 'is_own_server_ip() must exist' );
			$this->assertMatchesRegularExpression(
				'/function get_own_server_ips\(.*?SERVER_ADDR/s',
				$src,
				'the own-server list must include the interface address of the current request'
			);
			$this->assertMatchesRegularExpression(
				'/function is_own_server_ip\(.*?::1/s',
				$src,
				'is_own_server_ip() must treat loopback as the server itself'
			);
			$this->assertMatchesRegularExpression(
				'/function resolve_site_host_ips\(.*?ReportedIP_Hive_Bot_Verifier::resolve_host_ips\(/s',
				$src,
				'the own-server list must include the addresses the site hostname resolves to, via the shared forward resolver'
			);
			$this->assertStringContainsString(
				"apply_filters( 'reportedip_hive_own_server_ips'",
				$src,
				'multi-node setups must be able to extend the own-server list'
			);
		}

		public function test_host_resolution_is_cached() {
			$this->assertMatchesRegularExpression(
				'/function resolve_site_host_ips\(.*?get_site_transient\(.*?set_site_transient\(/s',
				$this->main_file(),
				'the DNS lookup must be transient-cached, negative results included'
			);
		}

		public function test_threshold_pipeline_stands_down_for_own_server_ip() {
			$this->assertMatchesRegularExpression(
				'/function handle_threshold_exceeded\([^)]*\)\s*\{\s*if\s*\(\s*\$this->should_spare_own_server_ip\(.*?return;/s',
				$this->monitor_file(),
				'handle_threshold_exceeded() must stand down before any consequence fires'
			);
		}

		public function test_auto_block_ip_rechecks_own_server_ip() {
			$this->assertMatchesRegularExpression(
				'/function auto_block_ip\(.*?should_spare_own_server_ip\(.*?return false;/s',
				$this->monitor_file(),
				'auto_block_ip() must re-check the guard for direct callers'
			);
		}

		public function test_averted_decision_is_logged_but_rate_limited() {
			$this->assertMatchesRegularExpression(
				'/function should_spare_own_server_ip\(.*?get_transient\(.*?own_server_ip_block_averted.*?return true;/s',
				$this->monitor_file(),
				'the averted decision must be visible in the log without flooding it'
			);
		}

		public function test_reputation_block_skips_own_server_ip() {
			$this->assertMatchesRegularExpression(
				'/\$exceeds_threshold\s*&&[^{]*!\s*\$this->ip_manager->is_whitelisted\([^)]*\)\s*&&\s*!\s*self::is_own_server_ip\(/s',
				$this->main_file(),
				'the reputation-block path must never target the server itself'
			);
		}

		public function test_migration_lifts_existing_self_blocks() {
			$src = $this->migration_file();

			preg_match( '/CURRENT_VERSION\s*=\s*(\d+)/', $src, $matches );
			$this->assertGreaterThanOrEqual(
				12,
				(int) ( $matches[1] ?? 0 ),
				'CURRENT_VERSION must be at least 12 so the self-heal migration runs'
			);
			$this->assertMatchesRegularExpression(
				'/function migrate_to_v12\(.*?is_own_server_ip\(.*?unblock_ip\(/s',
				$src,
				'migrate_to_v12() must lift active self-blocks via unblock_ip()'
			);
		}
	}
}
