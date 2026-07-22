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

		public function test_classify_range_only_rule_fake_when_outside_range(): void {
			$bot = array( 'ua' => 'facebookexternalhit', 'domains' => array(), 'ranges' => array( '2a03:2880::/29' ) );
			$this->assertSame( 'fake', $this->verifier()->classify( $bot, '203.0.113.7' ) );
		}

		public function test_classify_reports_reason_for_log_diagnostics(): void {
			$reason = '';

			$bot = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array( '66.249.66.0/24' ) );
			$this->verifier()->classify( $bot, '66.249.66.1', null, null, $reason );
			$this->assertSame( 'ip_range_match', $reason, 'A range hit must record why it verified.' );

			$bot = array( 'ua' => 'facebookexternalhit', 'domains' => array(), 'ranges' => array( '2a03:2880::/29' ) );
			$this->verifier()->classify( $bot, '203.0.113.7', null, null, $reason );
			$this->assertSame( 'ip_not_in_official_range', $reason, 'A range-only miss must record the reason.' );

			$bot = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() );
			$ptr = static function ( $ip ) {
				return 'host.evil.example.com';
			};
			$this->verifier()->classify( $bot, '203.0.113.7', $ptr, null, $reason );
			$this->assertStringStartsWith( 'ptr_foreign_domain:', $reason, 'A foreign PTR must record the offending host.' );
		}

		public function test_classify_falls_back_to_fcrdns_when_outside_range(): void {
			// The real-world Bing case: a genuine crawler IP missing from the seed
			// range list must still verify via reverse DNS, not be flagged fake.
			$bot     = array( 'ua' => 'bingbot', 'domains' => array( '.search.msn.com' ), 'ranges' => array( '157.55.39.0/24' ) );
			$ptr     = static function ( $ip ) {
				return 'msnbot-52-167-144-158.search.msn.com';
			};
			$forward = static function ( $host ) {
				return '52.167.144.158';
			};
			$this->assertSame( 'verified', $this->verifier()->classify( $bot, '52.167.144.158', $ptr, $forward ) );
		}

		public function test_classify_unknown_when_outside_range_and_ptr_fails(): void {
			$bot = array( 'ua' => 'bingbot', 'domains' => array( '.search.msn.com' ), 'ranges' => array( '157.55.39.0/24' ) );
			$ptr = static function ( $ip ) {
				return $ip;
			};
			$this->assertSame( 'unknown', $this->verifier()->classify( $bot, '52.167.144.158', $ptr ) );
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

		public function test_classify_unknown_when_no_ptr(): void {
			// A failed reverse-DNS lookup is a resolver problem, not a spoofer.
			$bot = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() );
			$ptr = static function ( $ip ) {
				return $ip;
			};
			$this->assertSame( 'unknown', $this->verifier()->classify( $bot, '203.0.113.7', $ptr ) );
		}

		public function test_classify_unknown_when_forward_dns_unavailable(): void {
			$bot     = array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array() );
			$ptr     = static function ( $ip ) {
				return 'crawl-1.googlebot.com';
			};
			$forward = static function ( $host ) {
				return array();
			};
			$this->assertSame( 'unknown', $this->verifier()->classify( $bot, '66.249.66.1', $ptr, $forward ) );
		}

		public function test_classify_no_ranges_no_domains_is_unknown(): void {
			$bot = array( 'ua' => 'weirdbot', 'domains' => array(), 'ranges' => array() );
			$this->assertSame( 'unknown', $this->verifier()->classify( $bot, '203.0.113.7' ) );
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

		/**
		 * Seed a stored bot_signatures ruleset so verdict/range checks run against
		 * deterministic rules instead of the bundled baseline.
		 *
		 * @param array $rules   Bot rules.
		 * @param int   $version Ruleset version.
		 */
		private function seed_ruleset( array $rules, int $version = 7 ): void {
			\ReportedIP_Hive_Rule_Store::set(
				'bot_signatures',
				array(
					'key'     => 'bot_signatures',
					'version' => $version,
					'rules'   => $rules,
				)
			);
		}

		public function test_verdict_for_request_unmatched_for_browser_ua(): void {
			$this->assertSame(
				'unmatched',
				$this->verifier()->verdict_for_request( 'Mozilla/5.0 (Windows NT 10.0) Chrome/120', '203.0.113.9' )
			);
			$this->assertSame( 'no_signature_match', $this->verifier()->last_reason() );
		}

		public function test_verdict_for_request_verified_via_injected_dns(): void {
			$ptr     = static function ( $ip ) {
				return 'crawl-66-249-66-1.googlebot.com';
			};
			$forward = static function ( $host ) {
				return '66.249.66.1';
			};
			$this->assertSame(
				'verified',
				$this->verifier()->verdict_for_request( 'Mozilla/5.0 (compatible; Googlebot/2.1)', '66.249.66.1', $ptr, $forward )
			);
			$this->assertSame( 'fcrdns_confirmed', $this->verifier()->last_reason() );
		}

		public function test_verdict_for_request_fake_via_injected_dns(): void {
			$ptr = static function ( $ip ) {
				return 'vm.customer.cloud.example';
			};
			$this->assertSame(
				'fake',
				$this->verifier()->verdict_for_request( 'Mozilla/5.0 (compatible; Googlebot/2.1)', '203.0.113.9', $ptr )
			);
		}

		public function test_verdict_for_request_uses_transient_cache(): void {
			global $wp_transients;
			$wp_transients = array();

			$key                   = \ReportedIP_Hive_Bot_Verifier::CACHE_PREFIX . md5( '198.51.100.4|googlebot' );
			$wp_transients[ $key ] = array(
				'value'   => 'verified',
				'expires' => 0,
			);
			$this->assertSame(
				'verified',
				$this->verifier()->verdict_for_request( 'Mozilla/5.0 (compatible; Googlebot/2.1)', '198.51.100.4' )
			);
			$this->assertSame( 'cached', $this->verifier()->last_reason() );
		}

		public function test_matches_official_ranges_hit_and_miss(): void {
			global $wp_transients;
			$wp_transients = array();
			$this->seed_ruleset(
				array(
					array( 'ua' => 'googlebot', 'domains' => array( '.googlebot.com' ), 'ranges' => array( '66.249.64.0/19' ) ),
					array( 'ua' => 'applebot', 'domains' => array( '.applebot.apple.com' ), 'ranges' => array( '17.246.0.0/16' ) ),
				)
			);

			$this->assertTrue( $this->verifier()->matches_official_ranges( '17.246.23.10' ), 'Render-fleet IP inside official ranges must match without any UA.' );
			$this->assertFalse( $this->verifier()->matches_official_ranges( '203.0.113.9' ) );
		}

		public function test_matches_official_ranges_caches_by_ruleset_version(): void {
			global $wp_transients;
			$wp_transients = array();
			$this->seed_ruleset(
				array( array( 'ua' => 'googlebot', 'domains' => array(), 'ranges' => array( '66.249.64.0/19' ) ) ),
				7
			);

			$this->assertTrue( $this->verifier()->matches_official_ranges( '66.249.66.1' ) );
			$key = \ReportedIP_Hive_Bot_Verifier::CACHE_IP_PREFIX . md5( '66.249.66.1|7' );
			$this->assertArrayHasKey( $key, $wp_transients, 'Range verdict must be cached under the versioned key.' );
			$this->assertSame( '1', $wp_transients[ $key ]['value'] );

			$this->seed_ruleset(
				array( array( 'ua' => 'googlebot', 'domains' => array(), 'ranges' => array() ) ),
				8
			);
			$this->assertFalse(
				$this->verifier()->matches_official_ranges( '66.249.66.1' ),
				'A new ruleset version must bypass the verdict cached for the old version.'
			);
		}

		public function test_matches_official_ranges_false_on_baseline_without_ranges(): void {
			global $wp_transients;
			$wp_transients = array();
			$this->assertFalse(
				$this->verifier()->matches_official_ranges( '66.249.66.1' ),
				'The bundled baseline carries no ranges; the IP-only check must degrade to false.'
			);
		}
	}
}
