<?php
/**
 * Unit tests for ReportedIP_Hive_IP_Cell.
 *
 * Locks down: hostile-input escaping in data-ip/aria-label/href, the
 * CIDR degradation path (no lookup, no external link), rawurlencode plus
 * filter application in external_url(), and the strong-wrap option.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

namespace {

	if ( ! defined( 'REPORTEDIP_HIVE_SITE_URL' ) ) {
		define( 'REPORTEDIP_HIVE_SITE_URL', 'https://reportedip.com' );
	}

	require_once dirname( __DIR__, 2 ) . '/admin/class-ip-cell.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_IP_Cell;

	/**
	 * Tests for the shared IP cell renderer.
	 *
	 * @since 2.1.41
	 */
	class IpCellTest extends TestCase {

		/**
		 * Drop any test filter registered on the external-url hook.
		 */
		protected function tear_down() {
			global $wp_filters;
			unset( $wp_filters['reportedip_hive_external_url'] );

			parent::tear_down();
		}

		/**
		 * A hostile IP string must never pass through unescaped.
		 */
		public function test_hostile_ip_is_escaped_everywhere() {
			$hostile = '"><script>alert(1)</script>';

			$html = ReportedIP_Hive_IP_Cell::render( $hostile );

			$this->assertStringNotContainsString( '<script>', $html );
			$this->assertStringNotContainsString( 'data-ip=""><script>', $html );
			$this->assertStringContainsString( '&lt;script&gt;', $html );
			$this->assertStringContainsString( 'data-ip="&quot;&gt;&lt;script&gt;', $html );
		}

		/**
		 * CIDR entries render code + copy but neither lookup nor external link.
		 */
		public function test_cidr_renders_without_lookup_and_external() {
			$html = ReportedIP_Hive_IP_Cell::render( '203.0.113.0/24' );

			$this->assertStringContainsString( '<code class="ip-address"', $html );
			$this->assertStringContainsString( '203.0.113.0/24', $html );
			$this->assertStringContainsString( 'copy-ip', $html );
			$this->assertStringNotContainsString( 'lookup-ip', $html );
			$this->assertStringNotContainsString( 'rip-ip-cell__external', $html );
		}

		/**
		 * external_url() rawurlencodes the IP and applies the filter with
		 * context 'ip_detail'.
		 */
		public function test_external_url_encodes_and_filters() {
			$seen_context = null;

			add_filter(
				'reportedip_hive_external_url',
				function ( $url, $context ) use ( &$seen_context ) {
					$seen_context = $context;
					return $url . '?filtered=1';
				},
				10,
				2
			);

			$url = ReportedIP_Hive_IP_Cell::external_url( '2001:db8::1' );

			$this->assertSame( 'ip_detail', $seen_context );
			$this->assertStringContainsString( '/ip/2001%3Adb8%3A%3A1/', $url );
			$this->assertStringContainsString( 'https://reportedip.com/ip/', $url );
			$this->assertStringEndsWith( '?filtered=1', $url );
		}

		/**
		 * The default markup carries the external link built from external_url().
		 */
		public function test_render_contains_external_link() {
			$html = ReportedIP_Hive_IP_Cell::render( '8.8.8.8' );

			$this->assertStringContainsString( 'rip-ip-cell__external', $html );
			$this->assertStringContainsString( 'https://reportedip.com/ip/8.8.8.8/', $html );
			$this->assertStringContainsString( 'target="_blank"', $html );
			$this->assertStringContainsString( 'rel="noopener noreferrer"', $html );
			$this->assertStringContainsString( 'lookup-ip', $html );
		}

		/**
		 * The strong option wraps the code element in a strong tag.
		 */
		public function test_strong_option_wraps_code() {
			$html = ReportedIP_Hive_IP_Cell::render( '8.8.8.8', array( 'strong' => true ) );

			$this->assertStringContainsString( '<strong><code class="ip-address"', $html );
			$this->assertStringContainsString( '</code></strong>', $html );
		}
	}
}
