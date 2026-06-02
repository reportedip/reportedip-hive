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

		private function call_is_benign_404_path( string $path ): bool {
			$instance   = \ReportedIP_Hive_Scan_Detector::get_instance();
			$reflection = new ReflectionClass( $instance );
			$method     = $reflection->getMethod( 'is_benign_404_path' );
			return (bool) $method->invoke( $instance, $path );
		}

		/**
		 * Client / crawler auto-requests (icon families, manifests, well-known
		 * and courtesy files) must be excluded from the rate-based burst
		 * trigger so an iOS page view's apple-touch-icon volley cannot auto-block
		 * a real visitor. Size variants are covered by pattern.
		 *
		 * @dataProvider benign_404_paths
		 */
		public function test_benign_404_paths_are_ignored_by_rate_trigger( string $path ) {
			$this->assertTrue(
				$this->call_is_benign_404_path( $path ),
				"Benign auto-request '$path' must be ignored by the 404 burst trigger"
			);
		}

		public function benign_404_paths(): array {
			return array(
				'apple-touch-icon'             => array( '/apple-touch-icon.png' ),
				'apple-touch-icon precomposed' => array( '/apple-touch-icon-precomposed.png' ),
				'apple-touch-icon 120'         => array( '/apple-touch-icon-120x120.png' ),
				'apple-touch-icon 180 precomp' => array( '/apple-touch-icon-180x180-precomposed.png' ),
				'favicon.ico'                  => array( '/favicon.ico' ),
				'favicon 32'                   => array( '/favicon-32x32.png' ),
				'mstile'                       => array( '/mstile-150x150.png' ),
				'site.webmanifest'             => array( '/site.webmanifest' ),
				'manifest.json'                => array( '/manifest.json' ),
				'browserconfig'                => array( '/browserconfig.xml' ),
				'robots.txt'                   => array( '/robots.txt' ),
				'ads.txt'                      => array( '/ads.txt' ),
				'apple-app-site-association'   => array( '/.well-known/apple-app-site-association' ),
				'chrome devtools probe'        => array( '/.well-known/appspecific/com.chrome.devtools.json' ),
			);
		}

		/**
		 * Real content, broken site assets and honeypot paths must NOT be
		 * treated as benign — they still feed the trigger. The .php "icon"
		 * guards against a scanner disguising a probe with an icon-like name.
		 *
		 * @dataProvider non_benign_404_paths
		 */
		public function test_real_paths_still_count_toward_rate_trigger( string $path ) {
			$this->assertFalse(
				$this->call_is_benign_404_path( $path ),
				"Path '$path' must NOT be excluded from the 404 burst trigger"
			);
		}

		public function non_benign_404_paths(): array {
			return array(
				'home'                  => array( '/' ),
				'page'                  => array( '/about' ),
				'content path'          => array( '/team/jane-doe' ),
				'honeypot .env'         => array( '/.env' ),
				'honeypot wp-config'    => array( '/wp-config.php.bak' ),
				'backup probe'          => array( '/x/backup.zip' ),
				'fake-icon php'         => array( '/apple-touch-icon.php' ),
				'fake-favicon php'      => array( '/favicon.php' ),
			);
		}

		private function call_is_passive_asset_404( string $path ): bool {
			$instance   = \ReportedIP_Hive_Scan_Detector::get_instance();
			$reflection = new ReflectionClass( $instance );
			$method     = $reflection->getMethod( 'is_passive_asset_404' );
			return (bool) $method->invoke( $instance, $path );
		}

		/**
		 * A burst of missing render assets (images, fonts, media) from one IP is
		 * a broken page or a half-migrated site, not a path-walking scan, so
		 * these extensions are kept out of the rate trigger.
		 *
		 * @dataProvider passive_asset_paths
		 */
		public function test_passive_asset_404s_are_ignored_by_rate_trigger( string $path ) {
			$this->assertTrue(
				$this->call_is_passive_asset_404( $path ),
				"Render asset '$path' must be ignored by the 404 burst trigger"
			);
		}

		public function passive_asset_paths(): array {
			return array(
				'missing upload jpg' => array( '/wp-content/uploads/2024/06/photo.jpg' ),
				'theme webp'         => array( '/wp-content/themes/x/img/hero.webp' ),
				'apple icon png'     => array( '/apple-touch-icon.png' ),
				'font woff2'         => array( '/wp-content/themes/x/fonts/inter.woff2' ),
				'svg sprite'         => array( '/assets/icons.svg' ),
				'video mp4'          => array( '/media/promo.mp4' ),
			);
		}

		/**
		 * Scanner-relevant extensions and extension-less paths must NOT be
		 * treated as passive assets — the rate trigger must keep counting them.
		 *
		 * @dataProvider non_asset_paths
		 */
		public function test_scanner_relevant_paths_are_not_treated_as_assets( string $path ) {
			$this->assertFalse(
				$this->call_is_passive_asset_404( $path ),
				"Path '$path' must keep feeding the 404 burst trigger"
			);
		}

		public function non_asset_paths(): array {
			return array(
				'php probe'      => array( '/old/wp-login.php' ),
				'zip backup'     => array( '/backup.zip' ),
				'sql dump'       => array( '/db.sql' ),
				'bak file'       => array( '/config.bak' ),
				'log file'       => array( '/error.log' ),
				'no extension'   => array( '/wp-admin/network/' ),
				'content path'   => array( '/about' ),
			);
		}
	}
}
