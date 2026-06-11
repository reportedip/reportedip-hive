<?php
/**
 * Unit tests for the verified-bot detection sensor.
 *
 * Locks the SEO-critical core: a real crawler is confirmed (IP-range match or
 * forward-confirmed reverse DNS) and never flagged, while a user-agent spoofer
 * is classified fake. DNS is injected so the FCrDNS fallback is deterministic.
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

	require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-bot-verifier.php';

	/**
	 * @covers \ReportedIP_Hive_Bot_Verifier
	 */
	class BotVerifierTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options'] = array();
		}

		private function verifier(): \ReportedIP_Hive_Bot_Verifier {
			return \ReportedIP_Hive_Bot_Verifier::get_instance();
		}

		public function test_match_bot_finds_claimed_crawler(): void {
			$rules = array(
				array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() ),
				array( 'ua' => 'bingbot', 'domains' => array( '.search.msn.com' ), 'ranges' => array() ),
			);
			$hit = $this->verifier()->match_bot( $rules, 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' );
			$this->assertIsArray( $hit );
			$this->assertSame( 'googlebot', $hit['ua'] );
		}

		public function test_match_bot_ignores_ordinary_browser(): void {
			$rules = array(
				array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() ),
			);
			$this->assertNull( $this->verifier()->match_bot( $rules, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120' ) );
		}

		public function test_classify_verified_by_ip_range(): void {
			$bot = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array( '66.249.66.0/24' ) );
			$this->assertSame( 'verified', $this->verifier()->classify( $bot, '66.249.66.1' ) );
		}

		public function test_classify_fake_when_outside_published_range(): void {
			$bot = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array( '66.249.66.0/24' ) );
			$this->assertSame( 'fake', $this->verifier()->classify( $bot, '203.0.113.7' ) );
		}

		public function test_classify_verified_by_fcrdns(): void {
			$bot     = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() );
			$ptr     = static function ( $ip ) {
				return 'crawl-66-249-66-1.googlebot.com';
			};
			$forward = static function ( $host ) {
				return '66.249.66.1';
			};
			$this->assertSame( 'verified', $this->verifier()->classify( $bot, '66.249.66.1', $ptr, $forward ) );
		}

		public function test_classify_fake_when_no_ptr(): void {
			$bot = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() );
			$ptr = static function ( $ip ) {
				return $ip;
			};
			$this->assertSame( 'fake', $this->verifier()->classify( $bot, '203.0.113.7', $ptr ) );
		}

		public function test_classify_fake_when_ptr_domain_mismatch(): void {
			$bot = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() );
			$ptr = static function ( $ip ) {
				return 'host.evil.example.com';
			};
			$this->assertSame( 'fake', $this->verifier()->classify( $bot, '203.0.113.7', $ptr ) );
		}

		public function test_classify_fake_when_forward_does_not_confirm(): void {
			$bot     = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() );
			$ptr     = static function ( $ip ) {
				return 'crawl-1.googlebot.com';
			};
			$forward = static function ( $host ) {
				return '198.51.100.9';
			};
			$this->assertSame( 'fake', $this->verifier()->classify( $bot, '66.249.66.1', $ptr, $forward ) );
		}

		public function test_classify_verified_by_ipv6_range(): void {
			$bot = array( 'ua' => 'facebookexternalhit', 'domains' => array( '.fbsv.net' ), 'ranges' => array( '2a03:2880::/29' ) );
			$this->assertSame( 'verified', $this->verifier()->classify( $bot, '2a03:2880:10ff:12::1' ) );
		}

		public function test_classify_fcrdns_confirms_ipv6_client(): void {
			$bot     = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() );
			$ptr     = static function ( $ip ) {
				return 'crawl-v6.googlebot.com';
			};
			$forward = static function ( $host ) {
				return array( '203.0.113.5', '2001:4860:4801:10::1' );
			};
			$this->assertSame( 'verified', $this->verifier()->classify( $bot, '2001:4860:4801:0010:0:0:0:1', $ptr, $forward ) );
		}

		public function test_classify_fcrdns_ipv6_match_ignores_text_notation(): void {
			$bot     = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() );
			$ptr     = static function ( $ip ) {
				return 'crawl-v6.googlebot.com';
			};
			$forward = static function ( $host ) {
				return array( '2001:4860:4801:0010:0000:0000:0000:0001' );
			};
			$this->assertSame( 'verified', $this->verifier()->classify( $bot, '2001:4860:4801:10::1', $ptr, $forward ) );
		}

		public function test_classify_fcrdns_fake_when_no_address_confirms(): void {
			$bot     = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() );
			$ptr     = static function ( $ip ) {
				return 'crawl-v6.googlebot.com';
			};
			$forward = static function ( $host ) {
				return array( '203.0.113.5', '2001:4860:4801:10::99' );
			};
			$this->assertSame( 'fake', $this->verifier()->classify( $bot, '2001:4860:4801:10::1', $ptr, $forward ) );
		}

		public function test_action_defaults_to_flag(): void {
			$this->assertSame( 'flag', $this->verifier()->action() );
		}

		public function test_action_rejects_unknown_value(): void {
			\ReportedIP_Hive_Option_Routing::set( \ReportedIP_Hive_Bot_Verifier::OPT_ACTION, 'nonsense' );
			$this->assertSame( 'flag', $this->verifier()->action() );
		}
	}
}
