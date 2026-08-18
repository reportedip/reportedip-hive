<?php
/**
 * Guards that path-matching sensors see the path the web server resolves.
 *
 * `sanitize_text_field()` deletes every `%XX` sequence from its input. Three
 * sensors ran the request URI through it before parsing, so a percent-escaped
 * probe reached them stripped rather than decoded:
 *
 *  - `/wp-login%2Ephp` arrived as `/wp-loginphp`, missed the hidden-login
 *    comparison, and the login form was served anyway.
 *  - `/%2Eenv` arrived as `/env`, missed the `.env` honeypot signature, and
 *    the scan detector fell back to the generic burst threshold — while the
 *    server delivered the real file.
 *  - the same trick walked past the decoy bait paths.
 *
 * The engine always read the raw URI; these sensors now match it. Multiple
 * leading slashes are collapsed first, because `//wp-login.php` otherwise
 * parses as a protocol-relative URL with an empty path.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.44
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
	if ( ! function_exists( 'wp_unslash' ) ) {
		function wp_unslash( $value ) {
			return is_string( $value ) ? stripslashes( $value ) : $value;
		}
	}
	if ( ! function_exists( 'wp_parse_url' ) ) {
		function wp_parse_url( $url, $component = -1 ) {
			return -1 === $component ? parse_url( $url ) : parse_url( $url, $component );
		}
	}
	if ( ! function_exists( 'str_starts_with' ) ) {
		function str_starts_with( $haystack, $needle ) {
			return '' === $needle || 0 === strncmp( (string) $haystack, (string) $needle, strlen( (string) $needle ) );
		}
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-scan-detector.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-decoy-path-block.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReflectionClass;
	use ReportedIP\Hive\Tests\TestCase;

	class RequestPathDecodingTest extends TestCase {

		/**
		 * Resolve the scan detector's view of the current request path.
		 *
		 * @param string $uri Raw REQUEST_URI.
		 * @return string
		 */
		private function scan_detector_path( string $uri ): string {
			$_SERVER['REQUEST_URI'] = $uri;

			$instance   = \ReportedIP_Hive_Scan_Detector::get_instance();
			$reflection = new ReflectionClass( $instance );
			$method     = $reflection->getMethod( 'get_request_path' );

			return (string) $method->invoke( $instance );
		}

		protected function tearDown(): void {
			unset( $_SERVER['REQUEST_URI'] );
			parent::tearDown();
		}

		public function test_scan_detector_decodes_escaped_dot_probes() {
			$this->assertSame( '/.env', $this->scan_detector_path( '/%2Eenv' ) );
			$this->assertSame( '/.env', $this->scan_detector_path( '/.env' ) );
			$this->assertSame( '/.git/config', $this->scan_detector_path( '/%2Egit/config' ) );
		}

		public function test_scan_detector_still_strips_the_query_string() {
			$this->assertSame( '/wp-admin/admin.php', $this->scan_detector_path( '/wp-admin/admin.php?page=x&a=%2E' ) );
		}

		public function test_scan_detector_drops_control_characters() {
			$this->assertSame( '/.env', $this->scan_detector_path( "/%2Eenv%00" ) );
		}

		public function test_escaped_probe_matches_the_known_scan_signature() {
			$instance   = \ReportedIP_Hive_Scan_Detector::get_instance();
			$reflection = new ReflectionClass( $instance );
			$known      = $reflection->getMethod( 'is_known_scan_path' );

			$this->assertTrue(
				(bool) $known->invoke( $instance, $this->scan_detector_path( '/%2Eenv' ) ),
				'An escaped .env probe must trip the honeypot, not the generic burst threshold'
			);
		}

		public function test_decoy_paths_match_escaped_probes() {
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/%2Eenv.backup' ) );
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/wp-config%2Eold.php' ) );
		}

		public function test_decoy_paths_collapse_repeated_leading_slashes() {
			$this->assertTrue(
				\ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '//.env.backup' ),
				'A doubled leading slash parses as a host and would leave the path empty'
			);
		}

		public function test_decoy_matching_is_unchanged_for_plain_paths() {
			$this->assertTrue( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/.env.backup?foo=bar' ) );
			$this->assertFalse( \ReportedIP_Hive_Decoy_Path_Block::is_decoy_path( '/wp-login.php' ) );
		}

		public function test_hide_login_reads_the_raw_uri() {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-hide-login.php' );
			$start  = strpos( $source, 'private function get_request_path()' );
			$this->assertNotFalse( $start );
			$body = substr( $source, $start, 1200 );

			$this->assertStringNotContainsString(
				'sanitize_text_field',
				$body,
				'Sanitising the URI removes percent-encoding and reopens the /wp-login%2Ephp bypass'
			);
			$this->assertStringContainsString( 'rawurldecode', $body );
			$this->assertStringContainsString( "ltrim( \$raw, '/' )", $body, 'Repeated leading slashes must collapse before parsing' );
		}
	}
}
