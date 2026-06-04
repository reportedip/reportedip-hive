<?php
/**
 * Unit Tests for the verified-bot User-Agent allowlist.
 *
 * Pure UA pattern matching — no WordPress, no DB. Locks down the canonical
 * default patterns (search engines, social previews, AI crawlers), the
 * negative cases (browsers, empty UA), the filter extension point and the
 * per-request decision cache.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.0.5
 */

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}
	require_once dirname( __DIR__, 2 ) . '/includes/class-bot-allowlist.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Bot_Allowlist;

	class BotAllowlistTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			ReportedIP_Hive_Bot_Allowlist::reset_cache();
			$GLOBALS['wp_filters']['reportedip_hive_bot_allowlist_patterns'] = array();
		}

		protected function tear_down() {
			ReportedIP_Hive_Bot_Allowlist::reset_cache();
			$GLOBALS['wp_filters']['reportedip_hive_bot_allowlist_patterns'] = array();
			parent::tear_down();
		}

		/**
		 * @dataProvider verified_bot_user_agents
		 */
		public function test_known_bot_user_agents_are_verified( string $ua, string $label ) {
			$this->assertTrue(
				ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot( $ua ),
				"UA '$label' should be recognised as a verified crawler"
			);
		}

		public function verified_bot_user_agents(): array {
			return array(
				'googlebot'         => array(
					'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
					'Googlebot',
				),
				'googlebot-image'   => array(
					'Googlebot-Image/1.0',
					'Googlebot-Image',
				),
				'googlebot-mobile'  => array(
					'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.86 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
					'Googlebot-Mobile',
				),
				'bingbot'           => array(
					'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
					'Bingbot',
				),
				'duckduckbot'       => array(
					'Mozilla/5.0 (compatible; DuckDuckBot/1.1; +http://duckduckgo.com/duckduckbot.html)',
					'DuckDuckBot',
				),
				'yandexbot'         => array(
					'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
					'YandexBot',
				),
				'applebot'          => array(
					'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)',
					'Applebot',
				),
				'gptbot'            => array(
					'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)',
					'GPTBot',
				),
				'chatgpt-user'      => array(
					'Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)',
					'ChatGPT-User',
				),
				'oai-searchbot'     => array(
					'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)',
					'OAI-SearchBot',
				),
				'claudebot'         => array(
					'Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)',
					'ClaudeBot',
				),
				'perplexitybot'     => array(
					'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)',
					'PerplexityBot',
				),
				'amazonbot'         => array(
					'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)',
					'Amazonbot',
				),
				'ccbot'             => array(
					'CCBot/2.0 (https://commoncrawl.org/faq/)',
					'CCBot',
				),
				'meta-external'     => array(
					'meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)',
					'MetaExternalAgent',
				),
				'facebookexternal'  => array(
					'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
					'facebookexternalhit',
				),
				'twitterbot'        => array(
					'Twitterbot/1.0',
					'Twitterbot',
				),
			);
		}

		/**
		 * @dataProvider non_bot_user_agents
		 */
		public function test_browser_user_agents_are_not_verified( string $ua, string $label ) {
			$this->assertFalse(
				ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot( $ua ),
				"UA '$label' must NOT be flagged as a verified crawler"
			);
		}

		public function non_bot_user_agents(): array {
			return array(
				'chrome'        => array(
					'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
					'Chrome',
				),
				'firefox'       => array(
					'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
					'Firefox',
				),
				'safari'        => array(
					'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
					'Safari',
				),
				'curl'          => array(
					'curl/8.4.0',
					'curl',
				),
				'wget'          => array(
					'Wget/1.21.3',
					'wget',
				),
				'python'        => array(
					'python-requests/2.31.0',
					'python-requests',
				),
				'unknown'       => array(
					'Mozilla/5.0 (made-up generic ua string)',
					'generic',
				),
			);
		}

		public function test_empty_ua_is_not_verified() {
			$this->assertFalse( ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot( '' ) );
		}

		public function test_whitespace_only_ua_is_not_verified() {
			$this->assertFalse( ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot( "   \t\n" ) );
		}

		public function test_filter_can_add_custom_pattern() {
			$custom_ua = 'MyEnterpriseCrawler/1.0';

			$this->assertFalse(
				ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot( $custom_ua ),
				'Custom UA should not match before filter is registered'
			);

			ReportedIP_Hive_Bot_Allowlist::reset_cache();
			\add_filter(
				'reportedip_hive_bot_allowlist_patterns',
				static function ( array $patterns ): array {
					$patterns[] = 'MyEnterpriseCrawler';
					return $patterns;
				}
			);

			$this->assertTrue(
				ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot( $custom_ua ),
				'Filter must be able to add a custom UA pattern'
			);
		}

		public function test_filter_can_remove_default_pattern() {
			$googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

			$this->assertTrue(
				ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot( $googlebot )
			);

			ReportedIP_Hive_Bot_Allowlist::reset_cache();
			\add_filter(
				'reportedip_hive_bot_allowlist_patterns',
				static function ( array $patterns ): array {
					return array_values(
						array_filter(
							$patterns,
							static fn( string $p ): bool => ! str_starts_with( $p, 'Googlebot' )
								&& 'AdsBot-Google' !== $p
								&& 'Mediapartners-Google' !== $p
								&& 'APIs-Google' !== $p
						)
					);
				}
			);

			$this->assertFalse(
				ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot( $googlebot ),
				'Filter must be able to remove a default pattern'
			);
		}

		public function test_match_is_case_insensitive() {
			$lowercased = 'mozilla/5.0 (compatible; googlebot/2.1; +http://www.google.com/bot.html)';
			$this->assertTrue(
				ReportedIP_Hive_Bot_Allowlist::is_verified_search_or_ai_bot( $lowercased )
			);
		}

		public function test_default_patterns_listed_contain_known_bots() {
			$patterns = ReportedIP_Hive_Bot_Allowlist::default_patterns();
			$this->assertContains( 'Googlebot', $patterns );
			$this->assertContains( 'Bingbot', $patterns );
			$this->assertContains( 'GPTBot', $patterns );
			$this->assertContains( 'ClaudeBot', $patterns );
			$this->assertContains( 'PerplexityBot', $patterns );
		}
	}
}
