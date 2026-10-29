<?php
/**
 * Unit tests for the site-wide security-header emitter.
 *
 * Locks the planned-header set against the option toggles: the basic trio
 * responds to its switches, the advanced set stays out without the add-on,
 * a listener on `reportedip_hive_planned_headers` can add a header but never
 * drop or rewrite the trio, and the Score contract helper reflects the
 * master switch.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.2
 */

namespace {
	if ( ! function_exists( 'wp_remote_retrieve_headers' ) ) {
		function wp_remote_retrieve_headers( $response ) {
			return is_array( $response ) ? ( $response['headers'] ?? array() ) : array();
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ArrayObject;
	use ReflectionMethod;
	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-option-routing.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-security-headers.php';

	/**
	 * @covers \ReportedIP_Hive_Security_Headers
	 */
	class SecurityHeadersTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options'] = array();
		}

		public function test_master_off_emits_nothing(): void {
			$this->assertSame( array(), \ReportedIP_Hive_Security_Headers::planned_headers() );
			$this->assertFalse( \ReportedIP_Hive_Security_Headers::basic_active() );
		}

		public function test_basic_headers_present_when_enabled(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			$h = \ReportedIP_Hive_Security_Headers::planned_headers();
			$this->assertSame( 'nosniff', $h['X-Content-Type-Options'] );
			$this->assertSame( 'SAMEORIGIN', $h['X-Frame-Options'] );
			$this->assertSame( 'strict-origin-when-cross-origin', $h['Referrer-Policy'] );
			$this->assertTrue( \ReportedIP_Hive_Security_Headers::basic_active() );
		}

		public function test_xfo_deny(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			update_option( 'reportedip_hive_header_xfo', 'DENY' );
			$h = \ReportedIP_Hive_Security_Headers::planned_headers();
			$this->assertSame( 'DENY', $h['X-Frame-Options'] );
		}

		public function test_xfo_off_omits_header(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			update_option( 'reportedip_hive_header_xfo', 'off' );
			$h = \ReportedIP_Hive_Security_Headers::planned_headers();
			$this->assertArrayNotHasKey( 'X-Frame-Options', $h );
		}

		public function test_xcto_off_omits_header(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			update_option( 'reportedip_hive_header_xcto', false );
			$h = \ReportedIP_Hive_Security_Headers::planned_headers();
			$this->assertArrayNotHasKey( 'X-Content-Type-Options', $h );
		}

		public function test_advanced_excluded_without_the_add_on(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			update_option( 'reportedip_hive_hsts_enabled', true );
			update_option( 'reportedip_hive_csp_mode', 'enforce' );
			update_option( 'reportedip_hive_csp_policy', "default-src 'self'" );
			$h = \ReportedIP_Hive_Security_Headers::planned_headers();
			$this->assertSame( array( 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy' ), array_keys( $h ) );
			$this->assertFalse( method_exists( 'ReportedIP_Hive_Security_Headers', 'advanced_active' ), 'the advanced set belongs to the add-on' );
		}

		public function test_a_listener_adds_headers_after_the_trio(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			$this->with_filter(
				static function ( $headers ) {
					$headers['Permissions-Policy'] = 'camera=()';
					return $headers;
				},
				function () {
					$h = \ReportedIP_Hive_Security_Headers::planned_headers();
					$this->assertSame( array( 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy', 'Permissions-Policy' ), array_keys( $h ) );
					$this->assertSame( 'camera=()', $h['Permissions-Policy'] );
				}
			);
		}

		public function test_a_listener_cannot_drop_or_rewrite_the_trio(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			$this->with_filter(
				static function () {
					return array(
						'X-Frame-Options' => 'ALLOWALL',
						'x-content-type-options' => 'sniff',
						'X-Evil'          => "a\r\nSet-Cookie: x=1",
						'Bad Name'        => 'x',
						'X-Ok'            => 'yes',
					);
				},
				function () {
					$h = \ReportedIP_Hive_Security_Headers::planned_headers();
					$this->assertSame( 'nosniff', $h['X-Content-Type-Options'] );
					$this->assertSame( 'SAMEORIGIN', $h['X-Frame-Options'] );
					$this->assertSame( 'strict-origin-when-cross-origin', $h['Referrer-Policy'] );
					$this->assertArrayNotHasKey( 'x-content-type-options', $h, 'a second casing would replace the header on the wire' );
					$this->assertArrayNotHasKey( 'X-Evil', $h, 'a line break would split the header' );
					$this->assertArrayNotHasKey( 'Bad Name', $h );
					$this->assertSame( 'yes', $h['X-Ok'] );
				}
			);
		}

		public function test_the_filter_does_not_run_with_the_master_switch_off(): void {
			$this->with_filter(
				static function ( $headers ) {
					$headers['X-Ok'] = 'yes';
					return $headers;
				},
				function () {
					$this->assertSame( array(), \ReportedIP_Hive_Security_Headers::planned_headers() );
				}
			);
		}

		public function test_server_snippets_are_empty_while_nothing_is_planned(): void {
			$this->assertSame(
				array(
					'nginx'  => '',
					'apache' => '',
				),
				\ReportedIP_Hive_Security_Headers::server_snippets()
			);
		}

		public function test_server_snippets_cover_error_pages_and_survive_a_missing_module(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			$this->with_filter(
				static function ( $headers ) {
					$headers['Strict-Transport-Security'] = 'max-age=31536000';
					$headers['X-Quote']                   = 'a "b" c\\d';
					return $headers;
				},
				function () {
					$s = \ReportedIP_Hive_Security_Headers::server_snippets();
					$this->assertStringContainsString( 'add_header X-Content-Type-Options "nosniff" always;', $s['nginx'] );
					$this->assertStringContainsString( 'add_header X-Quote "a \\"b\\" c\\\\d" always;', $s['nginx'] );
					$this->assertStringContainsString( '<IfModule mod_headers.c>', $s['apache'] );
					$this->assertStringEndsWith( '</IfModule>', $s['apache'] );
					$this->assertStringContainsString( "Header always set Strict-Transport-Security \"max-age=31536000\" \"expr=%{HTTPS} == 'on'\"", $s['apache'] );
					$this->assertStringContainsString( 'Header always set Referrer-Policy "strict-origin-when-cross-origin"' . "\n", $s['apache'] );
				}
			);
		}

		public function test_probe_judges_every_header_against_the_plan(): void {
			$rows = \ReportedIP_Hive_Security_Headers::evaluate_probe(
				array(
					'X-Content-Type-Options'  => 'nosniff',
					'X-Frame-Options'         => 'SAMEORIGIN',
					'Referrer-Policy'         => 'strict-origin-when-cross-origin',
					'Permissions-Policy'      => 'camera=()',
					'Content-Security-Policy' => "default-src 'self'",
				),
				array(
					'x-content-type-options'    => array( 'nosniff' ),
					'x-frame-options'           => array( 'SAMEORIGIN', 'SAMEORIGIN' ),
					'referrer-policy'           => array( 'no-referrer-when-downgrade' ),
					'strict-transport-security' => array( 'max-age=4838400' ),
				),
				array(
					'x-content-type-options'    => array( 'nosniff' ),
					'x-frame-options'           => array( 'SAMEORIGIN' ),
					'referrer-policy'           => array( 'no-referrer-when-downgrade' ),
					'permissions-policy'        => array( 'camera=()' ),
					'strict-transport-security' => array( 'max-age=4838400' ),
				)
			);

			$this->assertSame( 'ok', $rows['X-Content-Type-Options']['status'] );
			$this->assertSame( 'duplicate', $rows['X-Frame-Options']['status'] );
			$this->assertSame( 'other_value', $rows['Referrer-Policy']['status'] );
			$this->assertSame( 'missing_cached', $rows['Permissions-Policy']['status'] );
			$this->assertSame( 'missing', $rows['Content-Security-Policy']['status'] );
			$this->assertSame( 'server_only', $rows['Strict-Transport-Security']['status'] );
			$this->assertArrayNotHasKey( 'Cross-Origin-Opener-Policy', $rows, 'a header nobody sends and nobody plans is not listed' );
		}

		public function test_header_values_read_the_dictionary_the_http_api_returns(): void {
			$read = new ReflectionMethod( \ReportedIP_Hive_Security_Headers::class, 'header_values' );

			$dictionary = new ArrayObject(
				array(
					'referrer-policy' => array( 'no-referrer-when-downgrade', 'strict-origin-when-cross-origin' ),
					'x-frame-options' => 'SAMEORIGIN',
					'content-type'    => 'text/html',
				)
			);
			$this->assertSame(
				array(
					'x-frame-options' => array( 'SAMEORIGIN' ),
					'referrer-policy' => array( 'no-referrer-when-downgrade', 'strict-origin-when-cross-origin' ),
				),
				$read->invoke( null, array( 'headers' => $dictionary ) ),
				'an object with array access, duplicates as a list'
			);
			$this->assertSame(
				array( 'x-content-type-options' => array( 'nosniff' ) ),
				$read->invoke( null, array( 'headers' => array( 'X-Content-Type-Options' => ' nosniff ' ) ) ),
				'a plain array with any case'
			);
		}

		/**
		 * Run a body with one listener on the planned-headers filter.
		 *
		 * @param callable $listener Filter callback.
		 * @param callable $body     Assertions.
		 */
		private function with_filter( callable $listener, callable $body ): void {
			add_filter( 'reportedip_hive_planned_headers', $listener );
			try {
				$body();
			} finally {
				unset( $GLOBALS['wp_filters']['reportedip_hive_planned_headers'] );
			}
		}
	}
}
