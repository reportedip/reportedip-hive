<?php
/**
 * Unit tests for the site-wide security-header emitter.
 *
 * Locks the planned-header set against the option toggles: the basic trio
 * responds to its switches, the advanced set stays out while the tier gate is
 * unavailable (no Mode_Manager loaded in the unit context), and the Score
 * contract helpers reflect the master switch.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.2
 */

namespace ReportedIP\Hive\Tests\Unit {

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

		public function test_advanced_excluded_without_tier(): void {
			update_option( 'reportedip_hive_headers_enabled', true );
			update_option( 'reportedip_hive_hsts_enabled', true );
			update_option( 'reportedip_hive_csp_mode', 'enforce' );
			update_option( 'reportedip_hive_csp_policy', "default-src 'self'" );
			$h = \ReportedIP_Hive_Security_Headers::planned_headers();
			$this->assertArrayNotHasKey( 'Strict-Transport-Security', $h );
			$this->assertArrayNotHasKey( 'Content-Security-Policy', $h );
			$this->assertFalse( \ReportedIP_Hive_Security_Headers::advanced_available() );
			$this->assertFalse( \ReportedIP_Hive_Security_Headers::advanced_active() );
		}
	}
}
