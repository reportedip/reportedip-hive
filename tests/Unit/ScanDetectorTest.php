<?php
/**
 * Unit Tests for the 404 Scanner pattern matcher.
 *
 * Exercises ReportedIP_Hive_Scan_Detector::is_known_scan_path() via reflection
 * — pure list-comparison, no WordPress, no DB. Locks down both the explicit
 * known paths (one-shot triggers) and the prefix-based detection.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.2.0
 */

namespace {

	if ( ! function_exists( 'add_action' ) ) {
		function add_action( $hook, $cb, $priority = 10, $args = 1 ) {} // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
	}
	if ( ! function_exists( 'apply_filters' ) ) {
		function apply_filters( $hook, $value, ...$args ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
			return $value;
		}
	}
	if ( ! function_exists( 'str_starts_with' ) ) {
		function str_starts_with( $haystack, $needle ) {
			return '' === $needle || 0 === strncmp( (string) $haystack, (string) $needle, strlen( (string) $needle ) );
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-scan-detector.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReflectionClass;
	use ReportedIP\Hive\Tests\TestCase;

	class ScanDetectorTest extends TestCase {

		private function call_is_known_scan_path( string $path ): bool {
			$instance = \ReportedIP_Hive_Scan_Detector::get_instance();
			$reflection = new ReflectionClass( $instance );
			$method     = $reflection->getMethod( 'is_known_scan_path' );
			return (bool) $method->invoke( $instance, $path );
		}

		/**
		 * @dataProvider known_scan_paths
		 */
		public function test_known_scan_paths_match( string $path ) {
			$this->assertTrue(
				$this->call_is_known_scan_path( $path ),
				"Path '$path' should be detected as a scanner signature"
			);
		}

		public function known_scan_paths(): array {
			return array(
				'/.env'                    => array( '/.env' ),
				'/.env.local'              => array( '/.env.local' ),
				'/.env.production'         => array( '/.env.production' ),
				'/wp-config.php.bak'       => array( '/wp-config.php.bak' ),
				'/wp-config.php.old'       => array( '/wp-config.php.old' ),
				'/wp-content/debug.log'    => array( '/wp-content/debug.log' ),
				'/phpmyadmin/'             => array( '/phpmyadmin/' ),
				'/.git/config'             => array( '/.git/config' ),
				'/.aws/credentials'        => array( '/.aws/credentials' ),
				'/.ssh/id_rsa'             => array( '/.ssh/id_rsa' ),
			);
		}

		/**
		 * @dataProvider known_scan_prefixes
		 */
		public function test_known_scan_prefixes_match( string $path ) {
			$this->assertTrue(
				$this->call_is_known_scan_path( $path ),
				"Path '$path' should be matched by the scan prefix list"
			);
		}

		public function known_scan_prefixes(): array {
			return array(
				'wp-file-manager'   => array( '/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php' ),
				'file-manager'      => array( '/wp-content/plugins/file-manager/something.php' ),
				'cgi-bin'           => array( '/cgi-bin/whatever' ),
				'ultimate-member'   => array( '/wp-content/plugins/ultimate-member/exploit.php' ),
			);
		}

		/**
		 * @dataProvider benign_paths
		 */
		public function test_benign_paths_do_not_match( string $path ) {
			$this->assertFalse(
				$this->call_is_known_scan_path( $path ),
				"Benign path '$path' must NOT be flagged as a scanner signature"
			);
		}

		public function benign_paths(): array {
			return array(
				'home'              => array( '/' ),
				'page'              => array( '/about' ),
				'feed'              => array( '/feed' ),
				'real plugin asset' => array( '/wp-content/plugins/jetpack/css/jetpack.css' ),
				'sitemap'           => array( '/sitemap.xml' ),
				'image'             => array( '/wp-content/uploads/2024/06/photo.jpg' ),
			);
		}

		/**
		 * Architecture invariant: the burst-trigger early-return for verified
		 * crawlers MUST be gated on `!$is_scan_hit`, otherwise a spoofed
		 * "Googlebot" UA hitting /.env would bypass the honeypot trigger.
		 * Verified by source-code inspection so a future refactor cannot
		 * silently drop the guard.
		 */
		public function test_bot_allowlist_check_is_gated_on_pattern_hit() {
			$source = file_get_contents(
				dirname( __DIR__, 2 ) . '/includes/class-scan-detector.php'
			);
			$this->assertNotFalse( $source );
			$this->assertStringContainsString(
				'! $is_scan_hit',
				$source,
				'Scan-Detector must gate the bot-allowlist bypass on !$is_scan_hit'
			);
			$this->assertStringContainsString(
				'ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot',
				$source,
				'Scan-Detector must consult the bot allowlist for the burst trigger'
			);

			$pattern_check_pos = strpos( $source, 'is_known_scan_path' );
			$bot_check_pos     = strpos( $source, 'is_verified_search_or_ai_bot' );
			$track_call_pos    = strpos( $source, 'track_generic_attempt' );

			$this->assertLessThan(
				$bot_check_pos,
				$pattern_check_pos,
				'Pattern detection must run before the bot allowlist check'
			);
			$this->assertLessThan(
				$track_call_pos,
				$bot_check_pos,
				'Bot allowlist check must run before the security-monitor handoff'
			);
		}

		/**
		 * Pattern-hit honeypot paths must keep firing regardless of the UA —
		 * a fake Googlebot crawling /.env IS the attack indicator.
		 *
		 * @dataProvider honeypot_paths_for_spoofing_test
		 */
		public function test_pattern_hit_paths_remain_armed_even_for_bot_uas( string $path ) {
			$this->assertTrue(
				$this->call_is_known_scan_path( $path ),
				"Honeypot path '$path' must stay matched — bot allowlist does not apply"
			);
		}

		public function honeypot_paths_for_spoofing_test(): array {
			return array(
				'/.env'                      => array( '/.env' ),
				'/wp-config.php.bak'         => array( '/wp-config.php.bak' ),
				'/wp-config.php~'            => array( '/wp-config.php~' ),
				'/.git/config'               => array( '/.git/config' ),
				'/phpmyadmin/'               => array( '/phpmyadmin/' ),
				'/.aws/credentials'          => array( '/.aws/credentials' ),
				'/.ssh/id_rsa'               => array( '/.ssh/id_rsa' ),
				'/wp-content/debug.log'      => array( '/wp-content/debug.log' ),
			);
		}
	}
}
