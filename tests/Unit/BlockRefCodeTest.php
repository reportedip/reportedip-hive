<?php
/**
 * Unit tests for the block-page reference-code resolver.
 *
 * Locks down the contract of ReportedIP_Hive_Block_Ref: stable category codes
 * per reason, a lockout-duration suffix, and a deterministic-yet-non-reversible
 * incident token that never leaks the client IP. The token is what a wrongly
 * blocked visitor quotes, so a regression that made it reveal the IP — or made
 * it non-deterministic so the admin could not correlate it — must fail here.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.0
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-block-ref.php';

	/**
	 * @covers \ReportedIP_Hive_Block_Ref
	 */
	class BlockRefCodeTest extends TestCase {

		/**
		 * Every known reason resolves to its documented category code.
		 */
		public function test_category_maps_each_reason(): void {
			$expected = array(
				'ip_block'      => 'IP_BLOCK',
				'reputation'    => 'IP_REPUTATION',
				'hide_login'    => 'LOGIN_HIDDEN',
				'scan'          => 'SCAN_PROBE',
				'decoy'         => 'DECOY_HIT',
				'geo'           => 'GEO_ANOMALY',
				'rest_burst'    => 'REST_BURST',
				'user_enum'     => 'USER_ENUM',
				'xmlrpc'        => 'XMLRPC_ABUSE',
				'app_password'  => 'APP_PASSWORD',
				'waf_sqli'      => 'WAF_SQLI',
				'waf_xss'       => 'WAF_XSS',
				'waf_traversal' => 'WAF_TRAVERSAL',
				'waf_cmd'       => 'WAF_CMD',
				'waf_file'      => 'WAF_FILE',
				'waf_scanner'   => 'WAF_SCANNER',
			);

			foreach ( $expected as $reason => $code ) {
				$this->assertSame( $code, \ReportedIP_Hive_Block_Ref::category( $reason ), "Reason '{$reason}' must map to '{$code}'." );
			}
		}

		/**
		 * An unknown reason falls back to the generic category.
		 */
		public function test_unknown_reason_falls_back(): void {
			$this->assertSame( 'BLOCKED', \ReportedIP_Hive_Block_Ref::category( 'totally-unknown' ) );
			$this->assertSame( 'BLOCKED', \ReportedIP_Hive_Block_Ref::category( '' ) );
		}

		/**
		 * Reason matching is case-insensitive.
		 */
		public function test_category_is_case_insensitive(): void {
			$this->assertSame( 'WAF_SQLI', \ReportedIP_Hive_Block_Ref::category( 'WAF_SQLI' ) );
			$this->assertSame( 'WAF_SQLI', \ReportedIP_Hive_Block_Ref::category( 'Waf_Sqli' ) );
		}

		/**
		 * A lockout duration is appended to the category code.
		 */
		public function test_lockout_carries_minutes(): void {
			$this->assertSame( 'LOCKOUT_30M', \ReportedIP_Hive_Block_Ref::category( 'lockout', array( 'minutes' => 30 ) ) );
			$this->assertSame( 'LOGIN_LOCKOUT_5M', \ReportedIP_Hive_Block_Ref::category( 'login', array( 'minutes' => 5 ) ) );
			$this->assertSame( 'IP_BLOCK', \ReportedIP_Hive_Block_Ref::category( 'ip_block', array( 'minutes' => 30 ) ), 'Minutes only apply to lockout/login reasons.' );
			$this->assertSame( 'LOCKOUT', \ReportedIP_Hive_Block_Ref::category( 'lockout', array( 'minutes' => 0 ) ), 'A zero/absent duration must not add a suffix.' );
		}

		/**
		 * The token is a deterministic 8-char upper-case hex string within a window.
		 */
		public function test_token_is_deterministic_hex(): void {
			$a = \ReportedIP_Hive_Block_Ref::token( '203.0.113.7', 'waf_sqli', '2026-06-09-10' );
			$b = \ReportedIP_Hive_Block_Ref::token( '203.0.113.7', 'waf_sqli', '2026-06-09-10' );

			$this->assertSame( $a, $b, 'Same inputs must yield the same token so the admin can correlate.' );
			$this->assertMatchesRegularExpression( '/^[0-9A-F]{8}$/', $a );
		}

		/**
		 * Different IPs or windows yield different tokens.
		 */
		public function test_token_varies_by_ip_and_window(): void {
			$base  = \ReportedIP_Hive_Block_Ref::token( '203.0.113.7', 'waf_sqli', '2026-06-09-10' );
			$other = \ReportedIP_Hive_Block_Ref::token( '198.51.100.9', 'waf_sqli', '2026-06-09-10' );
			$later = \ReportedIP_Hive_Block_Ref::token( '203.0.113.7', 'waf_sqli', '2026-06-09-11' );

			$this->assertNotSame( $base, $other );
			$this->assertNotSame( $base, $later );
		}

		/**
		 * The token must never contain the client IP (no PII leak).
		 */
		public function test_token_does_not_leak_ip(): void {
			$ip    = '203.0.113.7';
			$token = \ReportedIP_Hive_Block_Ref::token( $ip, 'ip_block', '2026-06-09-10' );

			$this->assertStringNotContainsString( $ip, $token );
			$this->assertStringNotContainsString( '203', $token, 'No IP octet may survive into the token.' );
		}

		/**
		 * The full code is the category and token joined by a dash.
		 */
		public function test_code_combines_category_and_token(): void {
			$code = \ReportedIP_Hive_Block_Ref::code( 'waf_xss', '203.0.113.7', array( 'window' => '2026-06-09-10' ) );

			$this->assertStringStartsWith( 'WAF_XSS-', $code );
			$this->assertMatchesRegularExpression( '/^WAF_XSS-[0-9A-F]{8}$/', $code );
		}

		/**
		 * The lockout suffix flows through to the full code.
		 */
		public function test_code_includes_lockout_minutes(): void {
			$code = \ReportedIP_Hive_Block_Ref::code( 'lockout', '203.0.113.7', array( 'minutes' => 30, 'window' => '2026-06-09-10' ) );

			$this->assertMatchesRegularExpression( '/^LOCKOUT_30M-[0-9A-F]{8}$/', $code );
		}
	}
}
