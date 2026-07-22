<?php
/**
 * Unit tests for the unified crawler-exemption decision.
 *
 * Locks the verdict-combination truth table of
 * `ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler()`: a verified or
 * DNS-undecidable crawler keeps its exemption (SEO fail-open), a confirmed
 * spoofer loses it, and an official-range IP earns it without any crawler
 * user-agent (render fleet). DNS is injected so every row is deterministic.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.26
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-bot-verifier.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-bot-allowlist.php';

	/**
	 * @covers \ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler
	 */
	class BotAllowlistExemptionTest extends TestCase {

		private const GOOGLEBOT_UA = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
			$GLOBALS['wp_filters']    = array();
			\ReportedIP_Hive_Bot_Allowlist::reset_cache();
			\ReportedIP_Hive_Rule_Store::flush_cache();
		}

		/**
		 * Seed a bot_signatures ruleset with a googlebot rule.
		 *
		 * @param array $ranges Official CIDR ranges for the rule.
		 */
		private function seed_googlebot_rule( array $ranges = array() ): void {
			\ReportedIP_Hive_Rule_Store::set(
				'bot_signatures',
				array(
					'key'     => 'bot_signatures',
					'version' => 3,
					'rules'   => array(
						array(
							'ua'      => 'googlebot',
							'domains' => array( '.googlebot.com' ),
							'ranges'  => $ranges,
						),
					),
				)
			);
		}

		/**
		 * Pre-fill the verifier's verdict cache for the googlebot rule token so
		 * no real DNS runs inside is_exempt_crawler().
		 *
		 * @param string $ip      Client IP.
		 * @param string $verdict Verdict to cache.
		 */
		private function cache_verdict( string $ip, string $verdict ): void {
			$key = \ReportedIP_Hive_Bot_Verifier::CACHE_PREFIX . md5( $ip . '|googlebot' );

			$GLOBALS['wp_transients'][ $key ] = array(
				'value'   => $verdict,
				'expires' => 0,
			);
		}

		public function test_verified_crawler_ua_is_exempt(): void {
			$this->seed_googlebot_rule();
			$this->cache_verdict( '66.249.66.1', 'verified' );
			$this->assertTrue( \ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler( self::GOOGLEBOT_UA, '66.249.66.1' ) );
		}

		public function test_unknown_verdict_fails_open(): void {
			$this->seed_googlebot_rule();
			$this->cache_verdict( '66.249.66.1', 'unknown' );
			$this->assertTrue(
				\ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler( self::GOOGLEBOT_UA, '66.249.66.1' ),
				'A DNS-undecidable crawler must keep its exemption (SEO priority).'
			);
		}

		public function test_fake_verdict_denies_exemption(): void {
			$this->seed_googlebot_rule();
			$this->cache_verdict( '203.0.113.9', 'fake' );
			$this->assertFalse(
				\ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler( self::GOOGLEBOT_UA, '203.0.113.9' ),
				'A confirmed spoofer must be counted like any other client.'
			);
		}

		public function test_allowlisted_ua_without_signature_rule_is_exempt(): void {
			$this->seed_googlebot_rule();
			$this->assertTrue(
				\ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler( 'Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)', '203.0.113.9' ),
				'An allowlisted UA with no verification signals stays exempt (unmatched ≙ unknown).'
			);
		}

		public function test_official_range_ip_is_exempt_without_crawler_ua(): void {
			$this->seed_googlebot_rule( array( '66.249.64.0/19' ) );
			$this->assertTrue(
				\ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler( 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/17.4 Safari/605.1.15', '66.249.66.1' ),
				'A render-fleet request from official ranges earns the exemption by IP alone.'
			);
		}

		public function test_browser_off_range_is_not_exempt(): void {
			$this->seed_googlebot_rule( array( '66.249.64.0/19' ) );
			$this->assertFalse( \ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler( 'Mozilla/5.0 (Windows NT 10.0) Chrome/120', '203.0.113.9' ) );
		}

		public function test_toggle_off_disables_exemption(): void {
			$this->seed_googlebot_rule();
			$this->cache_verdict( '66.249.66.1', 'verified' );
			\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_bot_allowlist_enabled', false );
			$this->assertFalse( \ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler( self::GOOGLEBOT_UA, '66.249.66.1' ) );
		}

		public function test_injected_verifier_is_consulted(): void {
			$this->seed_googlebot_rule();
			$verifier = \ReportedIP_Hive_Bot_Verifier::get_instance();
			$this->cache_verdict( '198.51.100.7', 'fake' );
			$this->assertFalse( \ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler( self::GOOGLEBOT_UA, '198.51.100.7', $verifier ) );
		}

		public function test_empty_ip_with_crawler_ua_falls_back_to_ua_match(): void {
			$this->seed_googlebot_rule();
			$this->assertTrue(
				\ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler( self::GOOGLEBOT_UA, '' ),
				'Without a client IP the decision degrades to the pure UA match.'
			);
		}

		public function test_filter_overrides_final_decision(): void {
			$this->seed_googlebot_rule();
			add_filter(
				'reportedip_hive_bot_exempt',
				static function ( $exempt, $ua, $ip ) {
					return '198.51.100.200' === $ip ? true : $exempt;
				},
				10,
				3
			);
			$this->assertTrue(
				\ReportedIP_Hive_Bot_Allowlist::is_exempt_crawler( 'CustomMonitor/1.0', '198.51.100.200' ),
				'The reportedip_hive_bot_exempt filter must be able to grant an exemption.'
			);
		}
	}
}
