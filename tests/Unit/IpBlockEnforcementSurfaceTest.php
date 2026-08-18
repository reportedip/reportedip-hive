<?php
/**
 * Guards for the reach of the IP block gate and its verdict cache.
 *
 * Two defects this locks down, both found in the 2.1.43 audit:
 *
 *  1. `check_ip_access()` and `block_admin_access()` both bailed out on
 *     `wp_doing_ajax()`, so a blocked IP reached `admin-ajax.php` — and with
 *     it every `wp_ajax_nopriv_*` action on the site — without ever meeting
 *     the block gate. Only WP-Cron may stay exempt: its loopback comes from
 *     the server itself and must never be able to self-block the site.
 *  2. The 300-second `rip_access_*` verdict cache was invalidated in the
 *     auto-block path alone. A manual block kept letting the attacker in and
 *     a lifted block kept serving the 403, both for up to five minutes on
 *     sites with a persistent object cache.
 *
 * The main plugin file cannot be loaded in the unit harness (it terminates in
 * `exit` and boots WordPress), so — following the BlockedPageHooksTest idiom —
 * these contracts are anchored in the source text.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.44
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class IpBlockEnforcementSurfaceTest extends TestCase {

		/**
		 * Main plugin file source.
		 *
		 * @return string
		 */
		private function main_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
		}

		/**
		 * Body of one method in the main plugin file.
		 *
		 * @param string $signature Method signature to start at.
		 * @param int    $length    Characters to capture.
		 * @return string
		 */
		private function method_body( string $signature, int $length = 1200 ): string {
			$source = $this->main_file();
			$start  = strpos( $source, $signature );
			$this->assertNotFalse( $start, "$signature must exist" );

			return substr( $source, $start, $length );
		}

		public function test_block_gate_no_longer_exempts_ajax_requests() {
			$body = $this->method_body( 'private function check_ip_access()' );

			$this->assertStringNotContainsString(
				'wp_doing_ajax()',
				$body,
				'admin-ajax serves unauthenticated nopriv actions and must stay behind the block gate'
			);
			$this->assertStringContainsString(
				'wp_doing_cron()',
				$body,
				'WP-Cron must stay exempt so the server loopback cannot self-block the site'
			);
		}

		public function test_admin_gate_no_longer_exempts_ajax_requests() {
			$body = $this->method_body( 'public function block_admin_access()' );

			$this->assertStringNotContainsString( 'wp_doing_ajax()', $body );
		}

		public function test_blocked_ajax_requests_get_a_machine_readable_body() {
			$body = $this->method_body( 'public static function serve_blocked_page', 2000 );

			$this->assertStringContainsString( 'wp_send_json_error', $body, 'AJAX callers must not be handed the themed HTML page' );

			$status_pos = strpos( $body, 'status_header( 403 )' );
			$json_pos   = strpos( $body, 'wp_send_json_error' );
			$this->assertNotFalse( $status_pos );
			$this->assertNotFalse( $json_pos );
			$this->assertLessThan( $json_pos, $status_pos, 'The 403 status must be set before the JSON body is sent' );
		}

		public function test_verdict_cache_is_flushed_on_every_state_change() {
			$source = $this->main_file();

			foreach ( array( 'reportedip_hive_ip_blocked', 'reportedip_hive_ip_unblocked', 'reportedip_hive_whitelist_changed' ) as $hook ) {
				$this->assertStringContainsString(
					"add_action( '$hook', array( __CLASS__, 'flush_ip_verdict_cache' ) )",
					$source,
					"A change announced by $hook must retire the cached access verdicts"
				);
			}
		}

		public function test_verdict_cache_key_carries_an_epoch() {
			$key_body = $this->method_body( 'private static function ip_verdict_cache_key', 600 );

			$this->assertStringContainsString( 'OPTION_ACCESS_CACHE_EPOCH', $key_body, 'CIDR and whitelist verdicts can only be retired in bulk via an epoch' );
			$this->assertStringContainsString( 'md5(', $key_body );

			$flush_body = $this->method_body( 'public static function flush_ip_verdict_cache', 900 );

			$this->assertStringContainsString( 'wp_cache_delete', $flush_body, 'An exact IP must invalidate just its own entry' );
			$this->assertStringContainsString( "strpos( \$ip_address, '/' )", $flush_body, 'A CIDR range cannot enumerate its addresses and must bump the epoch' );
			$this->assertStringContainsString( '$epoch + 1', $flush_body );
		}

		public function test_auto_block_path_leaves_invalidation_to_the_hook() {
			$monitor = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-security-monitor.php' );

			$this->assertStringNotContainsString(
				"'rip_access_' . md5(",
				$monitor,
				'A hand-built key silently misses the epoch and deletes nothing'
			);
			$this->assertStringNotContainsString(
				'flush_ip_verdict_cache',
				$monitor,
				'block_ip() already announces the change; a second explicit flush is a copy that will drift'
			);
		}

		public function test_expiry_cleanup_rebakes_the_guard() {
			$manager = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-ip-manager.php' );
			$start   = strpos( $manager, 'public function cleanup_expired_entries()' );
			$this->assertNotFalse( $start );
			$body = substr( $manager, $start );

			$this->assertStringContainsString( 'flush_ip_state_caches()', $body, 'Expired rows must drop the CIDR and request caches' );
			$this->assertStringContainsString( "do_action( 'reportedip_hive_whitelist_changed'", $body, 'The guard bakes whitelist entries without an expiry and needs a rebake' );
		}

		public function test_cidr_unblock_rebakes_the_guard() {
			$dropin = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-waf-dropin-manager.php' );
			$start  = strpos( $dropin, 'public function on_ip_unblocked(' );
			$this->assertNotFalse( $start );
			$body = substr( $dropin, $start, 900 );

			$this->assertStringContainsString( "strpos( \$ip_address, '/' )", $body, 'A lifted CIDR block lives in the baked array, not the blocklist file' );
			$this->assertStringContainsString( 'queue_resync()', $body, 'Releasing a range requires a rebake, mirroring on_ip_blocked()' );
		}
	}
}
