<?php
/**
 * Bot Allowlist for verified search engine and AI crawlers.
 *
 * Pure User-Agent pattern matcher with a per-request decision cache. Consumed
 * by the rate-based sensors (404 burst trigger, REST burst trigger) to skip
 * the per-IP threshold for traffic that obviously comes from a known crawler.
 *
 * Honeypot-path sensors (`.env`, `wp-config.php.bak`, `/phpmyadmin/`, …) and
 * user-enumeration sensors (`?author=`, `/wp-json/wp/v2/users`) intentionally
 * do NOT consult this class — legit crawlers never request those paths, so a
 * spoofed "Googlebot" UA on `/.env` is itself the attack indicator.
 *
 * No network I/O, no DB access. UA spoofing is accepted as a known limitation;
 * pattern-based sensors catch the cases where it would matter. Future phases
 * may add Forward-Confirmed Reverse DNS (FCrDNS) with a transient cache.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.5
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stateless verifier for known search engine and AI crawler User-Agents.
 *
 * @since 2.0.5
 */
final class ReportedIP_Hive_Bot_Allowlist {

	/**
	 * Substrings matched case-insensitively against the request User-Agent.
	 *
	 * Curated for low false-positive rate: each token is unique enough that a
	 * normal browser UA will not contain it. Order is irrelevant; lookup is
	 * O(n) over the (small) list.
	 *
	 * Maintenance: when adding a new bot, check that:
	 *  - the token is unique enough to not collide with a browser UA, and
	 *  - the bot publishes a stable UA across its crawl fleet.
	 *
	 * @var string[]
	 */
	private const DEFAULT_PATTERNS = array(
		'Googlebot',
		'Googlebot-Image',
		'Googlebot-Video',
		'Googlebot-News',
		'AdsBot-Google',
		'Mediapartners-Google',
		'APIs-Google',
		'Bingbot',
		'BingPreview',
		'Slurp',
		'DuckDuckBot',
		'DuckAssistBot',
		'YandexBot',
		'YandexImages',
		'Baiduspider',
		'Applebot',
		'Sogou',
		'Exabot',
		'facebookexternalhit',
		'Twitterbot',
		'LinkedInBot',
		'Pinterest',
		'Discordbot',
		'Slackbot',
		'WhatsApp',
		'TelegramBot',
		'GPTBot',
		'ChatGPT-User',
		'OAI-SearchBot',
		'ClaudeBot',
		'Claude-Web',
		'anthropic-ai',
		'PerplexityBot',
		'Perplexity-User',
		'Amazonbot',
		'Bytespider',
		'CCBot',
		'Diffbot',
		'MetaExternalAgent',
		'meta-externalagent',
		'FacebookBot',
		'cohere-ai',
		'YouBot',
		'DataForSeoBot',
		'AhrefsBot',
		'SemrushBot',
		'mj12bot',
		'WordPress',
		'UptimeRobot',
		'Pingdom',
		'Site24x7',
		'StatusCake',
		'BetterStack',
		'PetalBot',
		'SeznamBot',
		'Qwantify',
		'Mail.RU_Bot',
		'CocCocBot',
		'MojeekBot',
		'Yeti',
		'NaverBot',
		'Chrome-Lighthouse',
		'Google-Read-Aloud',
		'Google-Adwords-Instant',
		'HubSpot',
		'SkypeUriPreview',
		'Tumblr',
		'Mastodon',
		'Screaming Frog',
	);

	/**
	 * Per-request decision cache keyed by the User-Agent string. Bots hammer
	 * the same UA across thousands of requests inside a single PHP-FPM worker
	 * — caching the verdict avoids repeated pattern walks.
	 *
	 * @var array<string, bool>
	 */
	private static $cache = array();

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Bot_Allowlist|null
	 */
	private static $instance = null;

	/**
	 * Return the singleton instance.
	 *
	 * @return self
	 * @since  2.0.5
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Whether the given User-Agent matches a verified crawler pattern.
	 *
	 * Empty / whitespace-only UAs are never verified — bots send a UA.
	 *
	 * @param string $user_agent Raw User-Agent header value.
	 * @return bool              True when the UA matches an allowlist pattern.
	 * @since  2.0.5
	 */
	public static function is_verified_search_or_ai_bot( string $user_agent ): bool {
		$ua = trim( $user_agent );
		if ( '' === $ua ) {
			return false;
		}

		if ( isset( self::$cache[ $ua ] ) ) {
			return self::$cache[ $ua ];
		}

		$patterns = (array) apply_filters(
			'reportedip_hive_bot_allowlist_patterns',
			self::DEFAULT_PATTERNS
		);

		$verdict = false;
		foreach ( $patterns as $pattern ) {
			$needle = (string) $pattern;
			if ( '' === $needle ) {
				continue;
			}
			if ( false !== stripos( $ua, $needle ) ) {
				$verdict = true;
				break;
			}
		}

		self::$cache[ $ua ] = $verdict;
		return $verdict;
	}

	/**
	 * Default UA pattern list (read-only copy).
	 *
	 * Exposed so callers (settings UI, tests) can show the canonical list
	 * without depending on the private constant.
	 *
	 * @return string[]
	 * @since  2.0.5
	 */
	public static function default_patterns(): array {
		return self::DEFAULT_PATTERNS;
	}

	/**
	 * Reset the per-request decision cache.
	 *
	 * Intended for unit tests that need to re-evaluate a UA after applying a
	 * filter. Production code never calls this — the cache lifetime is the
	 * PHP request itself.
	 *
	 * @return void
	 * @since  2.0.5
	 */
	public static function reset_cache(): void {
		self::$cache = array();
	}
}
