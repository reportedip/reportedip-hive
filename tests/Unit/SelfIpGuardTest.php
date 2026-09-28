<?php
/**
 * Regression tests for the own-server-IP guard (2.1.31).
 *
 * Cache-preload crawlers, WP-Cron loopbacks and REST self-requests connect
 * back through the site's public URL, so their REMOTE_ADDR is the server's
 * own public address, which passes is_public_ip(). Without a guard the
 * burst sensors auto-blocked that address (enforced by the pre-WordPress
 * drop-in before any path exception, answering every later preload with a
 * 403) and reported the server to the community API against its own
 * reputation. Observed in the field: a Multisite carried a seven-day
 * automatic block of its own IPv6.
 *
 * The heavy classes cannot be instantiated in the unit suite, so, like the
 * other main-file guards, these tests lock the critical source properties:
 *
 *  1. is_own_server_ip() exists and covers loopback, SERVER_ADDR and the
 *     addresses the site hostname resolves to, extensible via filter.
 *  2. handle_threshold_exceeded() stands down before any consequence fires.
 *  3. auto_block_ip() re-checks for direct callers.
 *  4. The reputation-block path in pre_auth_check() is exempt as well.
 *  5. A migration lifts self-blocks that are already active.
 *
 * Extended in 2.1.67 after live reports showed sites reporting the address of
 * the host they run on: five sensors call report_security_event() directly and
 * never pass handle_threshold_exceeded(), so the boundary now also sits in the
 * two funnels every decision goes through, the report queue and block_ip(),
 * and both address families of a dual-stacked host are recognised.
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

		private function database_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-database.php' );
		}

		private function manager_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-ip-manager.php' );
		}

		public function test_the_report_funnel_drops_the_own_server_address() {
			$src   = $this->database_file();
			$queue = substr( $src, strpos( $src, 'function queue_api_report(' ) );
			$queue = substr( $queue, 0, strpos( $queue, 'wp_cache_delete' ) ?: strlen( $queue ) );

			$this->assertStringContainsString(
				'ReportedIP_Hive::is_own_server_ip( $ip_address )',
				$queue,
				'queue_api_report() is the single funnel for every report and must drop the own address'
			);

			$guard  = strpos( $queue, 'is_own_server_ip( $ip_address )' );
			$insert = strpos( $queue, '$wpdb->insert' );
			if ( false !== $insert ) {
				$this->assertLessThan( $insert, $guard, 'the guard must run before the row is written' );
			}
		}

		public function test_the_guard_sits_beside_the_public_ip_gate_not_in_the_callers() {
			$queue = substr( $this->database_file(), strpos( $this->database_file(), 'function queue_api_report(' ) );

			$public = strpos( $queue, 'is_public_ip( $ip_address )' );
			$own    = strpos( $queue, 'is_own_server_ip( $ip_address )' );

			$this->assertNotFalse( $public );
			$this->assertNotFalse( $own );
			$this->assertLessThan(
				2000,
				abs( $own - $public ),
				'the own-server boundary belongs next to the existing public-IP gate, not as a second grid somewhere else'
			);
		}

		public function test_the_block_funnel_refuses_the_own_server_address_but_allows_a_manual_block() {
			$src   = $this->manager_file();
			$block = substr( $src, strpos( $src, 'function block_ip(' ) );
			$block = substr( $block, 0, strpos( $block, 'function unblock_ip(' ) ?: strlen( $block ) );

			$this->assertStringContainsString(
				"'manual' !== \$block_type && ReportedIP_Hive::is_own_server_ip( \$ip_address )",
				$block,
				'block_ip() must refuse an automatic self-block and still allow a deliberate manual one'
			);

			$guard     = strpos( $block, 'is_own_server_ip( $ip_address )' );
			$whitelist = strpos( $block, 'is_whitelisted( $ip_address )' );
			$write     = strpos( $block, '$this->database->block_ip(' );

			$this->assertNotFalse( $write );
			$this->assertLessThan( $write, $guard, 'the guard must run before the row is written' );
			$this->assertLessThan(
				2000,
				abs( $guard - $whitelist ),
				'the own-server boundary belongs at the same decision point as the whitelist gate'
			);
		}

		public function test_both_address_families_of_the_host_are_recognised() {
			$src = $this->main_file();

			$this->assertStringContainsString(
				'function remembered_server_addrs(',
				$src,
				'a host served over IPv4 must still recognise its own IPv6, which SERVER_ADDR alone never reveals'
			);
			$this->assertMatchesRegularExpression(
				'/function remembered_server_addrs\(.*?FILTER_FLAG_IPV6.*?\$known\[ \$family \] = \$current/s',
				$src,
				'the remembered list must be keyed per address family'
			);
			$this->assertMatchesRegularExpression(
				'/function get_own_server_ips\(.*?remembered_server_addrs\(\)/s',
				$src,
				'get_own_server_ips() must consult the remembered addresses'
			);
		}

		public function test_a_learned_address_is_written_once_and_then_only_read() {
			$this->assertMatchesRegularExpression(
				'/function remembered_server_addrs\(.*?!== \$current \).*?\$known\[ \$family \] = \$current.*?Option_Routing::set\(/s',
				$this->main_file(),
				'the option must only be written when the address is new, never on every request'
			);
		}

		public function test_the_cleanup_cron_lifts_a_self_block_learned_later() {
			$src = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-cron-handler.php' );

			$this->assertMatchesRegularExpression(
				'/function lift_own_server_blocks\(.*?is_own_server_ip\(.*?unblock_ip\(/s',
				$src,
				'the daily cleanup must lift self-blocks for addresses that only became known later'
			);
			$this->assertMatchesRegularExpression(
				'/function lift_own_server_blocks\(.*?manual. === \(string\) \( \$row->block_type/s',
				$src,
				'a manual block must survive the sweep'
			);
			$this->assertMatchesRegularExpression(
				'/function cron_cleanup\(.*?lift_own_server_blocks\(\)/s',
				$src,
				'the sweep must actually run from the cleanup cron'
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
