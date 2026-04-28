<?php
/**
 * Unit tests for the cache-prevention contract of the front-end IP block.
 *
 * Locks down the 1.5.2 fix: a cached 403 "Access Denied" page would be
 * served to every legitimate visitor of the same URL until the cache
 * expired. The mitigation is a small static helper that defines the
 * `DONOTCACHE*` family of constants and emits explicit no-store /
 * no-cache headers — this test guards the helper's contract so a future
 * refactor cannot silently strip the cache-prevention.
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

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class BlockedPageCacheHeadersTest extends TestCase {

		public function test_show_blocked_page_source_calls_the_helper(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );

			$this->assertStringContainsString(
				'self::emit_block_response_headers();',
				$source,
				'show_blocked_page() must delegate header emission to emit_block_response_headers() so the contract is testable and cannot drift.'
			);
			$this->assertStringContainsString(
				'status_header( 403 )',
				$source,
				'The blocked page must respond with HTTP 403.'
			);
		}

		public function test_helper_source_emits_donotcache_constants(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );

			foreach ( array( 'DONOTCACHEPAGE', 'DONOTCACHEDB', 'DONOTCACHEOBJECT' ) as $constant ) {
				$this->assertStringContainsString(
					"define( '{$constant}', true );",
					$source,
					"The blocked-page response must define {$constant} so plugin caches refuse to store it."
				);
			}
		}

		public function test_helper_source_emits_no_store_cache_control(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );

			$this->assertStringContainsString(
				"'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'",
				$source,
				'CDNs that ignore DONOTCACHEPAGE need an explicit Cache-Control: no-store header on the blocked response.'
			);
			$this->assertStringContainsString(
				"'Pragma: no-cache'",
				$source,
				'HTTP/1.0 caches and a few legacy CDNs only honour Pragma: no-cache.'
			);
			$this->assertStringContainsString(
				'nocache_headers()',
				$source,
				'WordPress core nocache_headers() sets the standard cache-prevention header set; the helper must call it.'
			);
		}

		public function test_init_hook_uses_priority_one(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );

			$this->assertStringContainsString(
				"add_action( 'init', array( \$this, 'init' ), 1 )",
				$source,
				'The init hook for IP-access checking must run at priority 1 so the block decision happens before plugins that hook init at the default priority.'
			);
		}
	}
}
