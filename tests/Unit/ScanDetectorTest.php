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
			$method->setAccessible( true );
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
	}
}
