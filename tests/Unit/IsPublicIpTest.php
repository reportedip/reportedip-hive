<?php
/**
 * Regression tests for the non-public-IP guards (hotfix 2.1.5).
 *
 * The full ReportedIP_Hive class cannot be instantiated in the unit suite
 * (heavy WordPress dependencies), so — like the other main-file guards — these
 * lock the critical source properties in place:
 *
 *  1. is_public_ip() rejects private/reserved ranges via the filter flags.
 *  2. get_client_ip() applies the same flags to the trusted proxy header, so a
 *     private hop never becomes the client IP.
 *  3. queue_api_report() drops non-public addresses before they reach the queue.
 *  4. the user-enumeration sensor exempts verified crawlers from the probe ladder.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.5
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	class IsPublicIpTest extends TestCase {

		private function main_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
		}

		private function database_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-database.php' );
		}

		private function user_enum_file(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-user-enumeration.php' );
		}

		public function test_is_public_ip_helper_exists_with_both_filter_flags() {
			$src = $this->main_file();
			$this->assertStringContainsString( 'function is_public_ip(', $src, 'is_public_ip() must exist' );
			$this->assertMatchesRegularExpression(
				'/is_public_ip\([^)]*\)\s*\{.*?FILTER_FLAG_NO_PRIV_RANGE\s*\|\s*FILTER_FLAG_NO_RES_RANGE.*?\}/s',
				$src,
				'is_public_ip() must reject private and reserved ranges'
			);
		}

		public function test_is_public_ip_rejects_the_unknown_sentinel() {
			$this->assertMatchesRegularExpression(
				"/is_public_ip\([^)]*\)\s*\{[^}]*'unknown'/s",
				$this->main_file(),
				'is_public_ip() must reject the unknown sentinel'
			);
		}

		public function test_trusted_header_path_filters_private_and_reserved() {
			$this->assertMatchesRegularExpression(
				'/trusted_header.*?filter_var\([^;]*FILTER_FLAG_NO_PRIV_RANGE\s*\|\s*FILTER_FLAG_NO_RES_RANGE/s',
				$this->main_file(),
				'get_client_ip() must apply the private/reserved filter to the proxy header'
			);
		}

		public function test_queue_api_report_drops_non_public_ips() {
			$this->assertMatchesRegularExpression(
				'/function queue_api_report\(.*?is_public_ip\(\s*\$ip_address\s*\).*?return false;/s',
				$this->database_file(),
				'queue_api_report() must drop non-public IPs before queueing'
			);
		}

		public function test_user_enumeration_exempts_verified_crawlers() {
			$this->assertMatchesRegularExpression(
				'/function record_probe\(.*?is_verified_search_or_ai_bot\(.*?return;/s',
				$this->user_enum_file(),
				'record_probe() must exempt verified crawlers from the probe ladder'
			);
		}
	}
}
