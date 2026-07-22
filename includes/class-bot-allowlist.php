<?php
/**
 * Bot Allowlist for verified search engine and AI crawlers.
 *
 * Pure User-Agent pattern matcher with a per-request decision cache. Consumed
 * by the rate-based sensors (404 burst trigger, REST burst trigger) to skip
 * the per-IP threshold for traffic that obviously comes from a known crawler,
 * and by the author-archive arm of the user-enumeration sensor (genuine
 * crawlers index `/author/<slug>/` pages, so they must not trip the IP ladder).
 *
 * Honeypot-path sensors (`.env`, `wp-config.php.bak`, `/phpmyadmin/`, …) and
 * the REST `/wp-json/wp/v2/users` lockdown intentionally do NOT consult this
 * class — legit crawlers never request those paths, so a spoofed "Googlebot"
 * UA on `/.env` is itself the attack indicator.
 *
 * `is_verified_search_or_ai_bot()` is the pure UA matcher (no network I/O).
 * `is_exempt_crawler()` is the unified decision every rate sensor and the
 * central auto-block guard consume: it cross-checks a UA match against the
 * FCrDNS/IP-range verdict of {@see ReportedIP_Hive_Bot_Verifier}, so a spoofed
 * crawler UA no longer buys an exemption.
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
		'DotBot',
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

	/**
	 * Unified crawler-exemption decision for every rate sensor and the central
	 * never-block-a-good-bot guard. Combines the UA allowlist with the
	 * FCrDNS/IP-range verifier so a spoofed crawler UA no longer buys an
	 * exemption while DNS hiccups can never cost a genuine crawler its pass.
	 *
	 * Verdict combination:
	 *
	 * | UA in allowlist | UA matches bot_signatures rule | Verdict    | Exempt |
	 * |-----------------|--------------------------------|------------|--------|
	 * | yes             | yes                            | verified   | yes    |
	 * | yes             | yes                            | unknown    | yes    |
	 * | yes             | yes                            | fake       | NO     |
	 * | yes             | no rule (e.g. UptimeRobot)     | unmatched  | yes    |
	 * | no              | —                              | official range hit | yes |
	 * | no              | —                              | no range hit | no   |
	 * | verifier class unavailable                       | UA match only | UA verdict |
	 *
	 * The IP-only branch is the render-fleet catch: Applebot and Google render
	 * pages with browser-like user-agents from their official ranges, so the IP
	 * alone can earn the exemption (PRO rulesets; the free baseline carries no
	 * ranges and degrades to the UA path). `unknown` fails open by design —
	 * SEO priority, a resolver outage must never get a genuine crawler blocked.
	 *
	 * @param string                            $ua       Request User-Agent.
	 * @param string                            $ip       Client IP ('' when unavailable).
	 * @param ReportedIP_Hive_Bot_Verifier|null $verifier Verifier override (tests).
	 * @return bool True when the request must not be counted or auto-blocked.
	 * @since  2.1.26
	 */
	public static function is_exempt_crawler( string $ua, string $ip, ?ReportedIP_Hive_Bot_Verifier $verifier = null ): bool {
		$exempt = false;

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_bot_allowlist_enabled', true ) ) {
			if ( null === $verifier && class_exists( 'ReportedIP_Hive_Bot_Verifier' ) ) {
				$verifier = ReportedIP_Hive_Bot_Verifier::get_instance();
			}

			if ( self::is_verified_search_or_ai_bot( $ua ) ) {
				$exempt = null === $verifier || '' === $ip
					|| 'fake' !== $verifier->verdict_for_request( $ua, $ip );
			} elseif ( null !== $verifier && '' !== $ip ) {
				$exempt = $verifier->matches_official_ranges( $ip );
			}
		}

		/**
		 * Filters the final crawler-exemption decision.
		 *
		 * Escape hatch for operators with a custom monitoring fleet or an edge
		 * case the combined UA/FCrDNS logic cannot express.
		 *
		 * @param bool   $exempt Combined exemption decision.
		 * @param string $ua     Request User-Agent.
		 * @param string $ip     Client IP.
		 * @since 2.1.26
		 */
		return (bool) apply_filters( 'reportedip_hive_bot_exempt', $exempt, $ua, $ip );
	}
}
