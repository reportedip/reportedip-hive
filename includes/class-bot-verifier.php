<?php
/**
 * Verified-bot detection sensor.
 *
 * Confirms that a request claiming to be a search-engine crawler genuinely is
 * one. It matches the user-agent against the `bot_signatures` ruleset (bundled
 * baseline, free; the richer list with official Google/Bing IP-range feeds
 * arrives via Priority Sync) and then verifies in two stages: first a
 * DNS-free CIDR match against the crawler's published IP ranges, then a
 * forward-confirmed reverse-DNS (FCrDNS) fallback for crawlers without
 * published ranges. A genuine crawler is never blocked; a spoofer is logged
 * and — only when the operator opts into it — rejected. The default action is
 * `flag` (log only), so the sensor is SEO-safe out of the box.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two-stage verified-bot sensor (IP-range match first, FCrDNS fallback).
 *
 * @since 2.1.2
 */
class ReportedIP_Hive_Bot_Verifier {

	/**
	 * Master enable toggle option.
	 */
	const OPT_MONITOR = 'reportedip_hive_monitor_bot_verification';

	/**
	 * Action taken on a confirmed spoofer: off | flag | block.
	 */
	const OPT_ACTION = 'reportedip_hive_bot_action';

	/**
	 * Cache lifetime (seconds) for a verified result (24 h).
	 */
	const CACHE_VERIFIED = 86400;

	/**
	 * Cache lifetime (seconds) for a fake result (1 h).
	 */
	const CACHE_FAKE = 3600;

	/**
	 * Cache lifetime (seconds) for an `unknown` (DNS-undecidable) result. Kept
	 * short so a transient resolver failure re-checks soon instead of leaving a
	 * genuine crawler unverified for an hour.
	 */
	const CACHE_UNKNOWN = 900;

	/**
	 * Transient key prefix for cached verification verdicts.
	 */
	const CACHE_PREFIX = 'reportedip_hive_botverify_';

	/**
	 * Transient key prefix for cached IP-only official-range checks.
	 */
	const CACHE_IP_PREFIX = 'reportedip_hive_botip_';

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Bot_Verifier|null
	 */
	private static $instance = null;

	/**
	 * Why the most recent verdict was reached (e.g. `ptr_foreign_domain`,
	 * `ip_not_in_official_range`, `cached`). Surfaced in the spoofer log so an
	 * operator can tell a real spoof from a DNS/verification gap.
	 *
	 * @var string
	 */
	private $last_reason = '';

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Bot_Verifier
	 * @since  2.1.2
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire the inspection hook. Priority 4 runs after the IP-block gate and the
	 * WAF (both priority 1) so an already-blocked request never reaches the
	 * comparatively heavier verification path.
	 *
	 * @since 2.1.2
	 */
	private function __construct() {
		add_action( 'init', array( $this, 'inspect' ), 4 );
	}

	/**
	 * Inspect the current request: identify a claimed crawler, verify it and act
	 * on a spoofer according to the configured action.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function inspect() {
		if ( wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) || is_admin() ) {
			return;
		}
		if ( ! $this->is_enabled() ) {
			return;
		}
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}
		if ( is_user_logged_in() && current_user_can( 'edit_posts' ) ) {
			return;
		}

		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Matched as an opaque token, never stored or echoed.
		if ( '' === $ua ) {
			return;
		}

		$bot = $this->match_bot( $this->get_bot_rules(), $ua );
		if ( null === $bot ) {
			return;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( '' === $ip || 'unknown' === $ip ) {
			return;
		}

		$ip_manager = class_exists( 'ReportedIP_Hive_IP_Manager' )
			? ReportedIP_Hive_IP_Manager::get_instance()
			: null;
		if ( $ip_manager && method_exists( $ip_manager, 'is_whitelisted' ) && $ip_manager->is_whitelisted( $ip ) ) {
			return;
		}

		$verdict = $this->cached_verdict( $bot, $ip );
		if ( 'fake' === $verdict ) {
			$this->handle_fake( $bot, $ip );
		}
	}

	/**
	 * Whether the sensor is active (enabled, action not off, feature available).
	 *
	 * @return bool
	 * @since  2.1.2
	 */
	public function is_enabled() {
		if ( ! ReportedIP_Hive_Option_Routing::get( self::OPT_MONITOR, true ) ) {
			return false;
		}
		if ( 'off' === $this->action() ) {
			return false;
		}
		if ( class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'bot_verification' );
			if ( empty( $status['available'] ) ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * The configured action for a confirmed spoofer.
	 *
	 * @return string off | flag | block.
	 * @since  2.1.2
	 */
	public function action() {
		$action = (string) ReportedIP_Hive_Option_Routing::get( self::OPT_ACTION, 'flag' );
		return in_array( $action, array( 'off', 'flag', 'block' ), true ) ? $action : 'flag';
	}

	/**
	 * Resolve the active bot-signature rules from the synced ruleset (or the
	 * bundled baseline).
	 *
	 * @return array<int,array<string,mixed>>
	 * @since  2.1.2
	 */
	public function get_bot_rules() {
		if ( ! class_exists( 'ReportedIP_Hive_Rule_Sync' ) ) {
			return array();
		}
		$ruleset = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'bot_signatures' );
		return isset( $ruleset['rules'] ) && is_array( $ruleset['rules'] ) ? $ruleset['rules'] : array();
	}

	/**
	 * Why the most recent verdict was reached. Companion to
	 * {@see verdict_for_request()} so callers can log an explanation next to a
	 * verdict without re-running the classification.
	 *
	 * @return string
	 * @since  2.1.26
	 */
	public function last_reason(): string {
		return '' !== $this->last_reason ? $this->last_reason : 'unspecified';
	}

	/**
	 * Verdict for an arbitrary request, independent of the sensor's own
	 * enable/action options: those govern the spoofer *sensor*, while this
	 * method serves the protective never-block-a-good-bot guard and must keep
	 * working even when the operator switched the sensor off.
	 *
	 * Returns `unmatched` when the user-agent claims no known crawler,
	 * otherwise the (transient-cached) `verified` / `fake` / `unknown`
	 * classification. `$ptr` / `$forward` inject the DNS layer for tests and
	 * bypass the cache when provided.
	 *
	 * @param string        $ua      Request user-agent.
	 * @param string        $ip      Client IP.
	 * @param callable|null $ptr     PTR resolver override (tests only).
	 * @param callable|null $forward Forward resolver override (tests only).
	 * @return string `verified` | `fake` | `unknown` | `unmatched`.
	 * @since  2.1.26
	 */
	public function verdict_for_request( string $ua, string $ip, $ptr = null, $forward = null ): string {
		$bot = $this->match_bot( $this->get_bot_rules(), $ua );
		if ( null === $bot ) {
			$this->last_reason = 'no_signature_match';
			return 'unmatched';
		}
		if ( null !== $ptr || null !== $forward ) {
			$reason            = '';
			$verdict           = $this->classify( $bot, $ip, $ptr, $forward, $reason );
			$this->last_reason = '' !== $reason ? $reason : 'unspecified';
			return $verdict;
		}
		return $this->cached_verdict( $bot, $ip );
	}

	/**
	 * Whether the IP falls inside any crawler's published official ranges —
	 * Stage A only, no DNS ever. This is the render-fleet catch: Applebot and
	 * Google render pages with browser-like user-agents from their official
	 * ranges, so the IP alone must be able to earn the exemption. The result
	 * is cached per IP with the ruleset version baked into the key, so a
	 * ruleset sync self-invalidates the cache.
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 * @since  2.1.26
	 */
	public function matches_official_ranges( string $ip ): bool {
		if ( '' === $ip ) {
			return false;
		}

		$ruleset = class_exists( 'ReportedIP_Hive_Rule_Sync' )
			? ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'bot_signatures' )
			: array();
		$version = isset( $ruleset['version'] ) ? (int) $ruleset['version'] : 0;
		$rules   = isset( $ruleset['rules'] ) && is_array( $ruleset['rules'] ) ? $ruleset['rules'] : array();

		$key    = self::CACHE_IP_PREFIX . md5( $ip . '|' . $version );
		$cached = get_transient( $key );
		if ( '1' === $cached || '0' === $cached ) {
			return '1' === $cached;
		}

		$match = false;
		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['ranges'] ) || ! is_array( $rule['ranges'] ) ) {
				continue;
			}
			foreach ( $rule['ranges'] as $cidr ) {
				if ( ReportedIP_Hive_Database::ip_in_cidr( $ip, (string) $cidr ) ) {
					$match = true;
					break 2;
				}
			}
		}

		set_transient( $key, $match ? '1' : '0', $match ? self::CACHE_VERIFIED : self::CACHE_UNKNOWN );
		return $match;
	}

	/**
	 * Find the first bot rule whose token appears in the user-agent. Pure: takes
	 * the rules and the user-agent, touches no superglobal, so it is
	 * deterministically unit-testable.
	 *
	 * @param array<int,array<string,mixed>> $rules Bot-signature rules.
	 * @param string                         $ua    Request user-agent.
	 * @return array<string,mixed>|null The matched rule, or null.
	 * @since  2.1.2
	 */
	public function match_bot( array $rules, $ua ) {
		if ( '' === $ua ) {
			return null;
		}
		foreach ( $rules as $rule ) {
			if ( ! is_array( $rule ) || empty( $rule['ua'] ) ) {
				continue;
			}
			if ( false !== stripos( $ua, (string) $rule['ua'] ) ) {
				return $rule;
			}
		}
		return null;
	}

	/**
	 * Classify a claimed crawler as `verified` or `fake`. Pure: the DNS lookups
	 * are injectable so the FCrDNS fallback is testable without real DNS.
	 *
	 * Stage A — if the rule carries official IP ranges, a CIDR match is decisive
	 * (in-range = verified, out-of-range = fake) and no DNS is touched. Stage B —
	 * for range-less crawlers, the PTR record must resolve to one of the rule's
	 * valid domain suffixes and forward-confirm back to the same IP.
	 *
	 * The forward confirmation compares addresses by their packed binary form, so
	 * it works for IPv6 (where text notations differ but the address is the same)
	 * and the default resolver looks up both A and AAAA records — `gethostbyname()`
	 * only ever returned IPv4, which silently failed every IPv6 crawler.
	 *
	 * @param array<string,mixed> $bot     Matched bot rule (`ranges`, `domains`).
	 * @param string              $ip      Client IP.
	 * @param callable|null       $ptr     PTR resolver `fn(string $ip): string|false`.
	 * @param callable|null       $forward Forward resolver `fn(string $host): string|string[]|false` (one IP or a list of A/AAAA addresses).
	 * @return string `verified`, `fake`, or `unknown` when DNS cannot decide.
	 * @since  2.1.2
	 */
	public function classify( array $bot, $ip, $ptr = null, $forward = null, &$reason = null ) {
		$ranges  = isset( $bot['ranges'] ) && is_array( $bot['ranges'] ) ? $bot['ranges'] : array();
		$domains = isset( $bot['domains'] ) && is_array( $bot['domains'] ) ? $bot['domains'] : array();

		/*
		 * Stage A — an official IP-range match is a decisive positive and touches
		 * no DNS.
		 */
		foreach ( $ranges as $cidr ) {
			if ( ReportedIP_Hive_Database::ip_in_cidr( $ip, (string) $cidr ) ) {
				$reason = 'ip_range_match';
				return 'verified';
			}
		}

		/*
		 * A range list is a fast-path allowlist, not an exhaustive denylist:
		 * Bing/Google publish more crawler /24s than any seed carries, so an
		 * out-of-range IP must still get the FCrDNS check when the rule has
		 * domain suffixes. Treating out-of-range as an automatic spoofer is what
		 * flagged every genuine Bing crawler whose /24 was missing from the seed.
		 * Only a range-only rule (no domains) is decisive on the range miss.
		 */
		if ( empty( $domains ) ) {
			if ( empty( $ranges ) ) {
				$reason = 'no_verification_signals';
				return 'unknown';
			}
			$reason = 'ip_not_in_official_range';
			return 'fake';
		}

		$ptr     = is_callable( $ptr ) ? $ptr : 'gethostbyaddr';
		$forward = is_callable( $forward ) ? $forward : array( __CLASS__, 'resolve_host_ips' );

		$host = call_user_func( $ptr, $ip );
		/*
		 * A failed PTR lookup — gethostbyaddr() returns the IP unchanged on
		 * failure — is a DNS problem, NOT proof of a spoofer. Stay 'unknown' so a
		 * genuine crawler on a host with flaky or rate-limited reverse DNS is
		 * never flagged (the old code returned 'fake' here and mislabelled real
		 * crawlers whenever the server's resolver hiccuped).
		 */
		if ( ! is_string( $host ) || '' === $host || $host === $ip ) {
			$reason = 'ptr_unresolved';
			return 'unknown';
		}
		$host = strtolower( rtrim( $host, '.' ) );

		$suffix_ok = false;
		foreach ( $domains as $domain ) {
			$domain = strtolower( (string) $domain );
			if ( '' === $domain ) {
				continue;
			}
			if ( substr( $host, -strlen( $domain ) ) === $domain ) {
				$suffix_ok = true;
				break;
			}
		}
		/*
		 * The PTR resolved to a foreign domain — this is a confirmed spoofer.
		 */
		if ( ! $suffix_ok ) {
			$reason = 'ptr_foreign_domain:' . substr( $host, 0, 80 );
			return 'fake';
		}

		$resolved = call_user_func( $forward, $host );
		/*
		 * Right PTR suffix but forward DNS is unavailable — cannot confirm or
		 * deny, so stay 'unknown' rather than flag a probably-genuine crawler.
		 */
		if ( empty( $resolved ) ) {
			$reason = 'forward_dns_unresolved';
			return 'unknown';
		}
		$candidates = is_array( $resolved ) ? $resolved : array( $resolved );
		foreach ( $candidates as $candidate ) {
			$candidate = (string) $candidate;
			if ( '' !== $candidate && self::ip_equals( $candidate, $ip ) ) {
				$reason = 'fcrdns_confirmed';
				return 'verified';
			}
		}
		/*
		 * Right suffix but no forward address confirms the IP — a forged PTR.
		 */
		$reason = 'ptr_forward_mismatch:' . substr( $host, 0, 80 );
		return 'fake';
	}

	/**
	 * Compare two IP addresses by their packed binary form, so differing IPv6
	 * text notations (compressed vs expanded, leading zeros) for the same address
	 * still match and a plain string compare can never reject a valid IPv6 hit.
	 *
	 * @param string $a First address.
	 * @param string $b Second address.
	 * @return bool True when both parse to the same address.
	 * @since  2.1.3
	 */
	private static function ip_equals( $a, $b ) {
		if ( $a === $b ) {
			return true;
		}
		$pa = @inet_pton( $a ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton warns on a malformed address; the false return is handled.
		$pb = @inet_pton( $b ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton warns on a malformed address; the false return is handled.
		return false !== $pa && false !== $pb && $pa === $pb;
	}

	/**
	 * Default forward resolver: every A and AAAA address a host resolves to, so
	 * the FCrDNS confirmation can match an IPv6 client. Falls back to
	 * `gethostbyname()` (IPv4 only) when `dns_get_record()` is unavailable.
	 *
	 * @param string $host Hostname to resolve.
	 * @return string[] Resolved IP addresses (may be empty).
	 * @since  2.1.3
	 */
	public static function resolve_host_ips( $host ) {
		if ( ! is_string( $host ) || '' === $host ) {
			return array();
		}
		if ( function_exists( 'dns_get_record' ) ) {
			$records = @dns_get_record( $host, DNS_A | DNS_AAAA ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A failed DNS lookup must not surface a warning; the empty/false return is handled.
			if ( is_array( $records ) ) {
				$ips = array();
				foreach ( $records as $record ) {
					if ( isset( $record['ipv6'] ) && is_string( $record['ipv6'] ) ) {
						$ips[] = $record['ipv6'];
					} elseif ( isset( $record['ip'] ) && is_string( $record['ip'] ) ) {
						$ips[] = $record['ip'];
					}
				}
				if ( ! empty( $ips ) ) {
					return $ips;
				}
			}
		}
		$v4 = gethostbyname( $host );
		return ( '' !== $v4 && $v4 !== $host ) ? array( $v4 ) : array();
	}

	/**
	 * Return the cached verdict for the IP/bot pair, computing and caching it on
	 * a miss (verified 24 h, fake 1 h) so DNS is never hit twice for the same
	 * visitor inside the window.
	 *
	 * @param array<string,mixed> $bot Matched bot rule.
	 * @param string              $ip  Client IP.
	 * @return string `verified` or `fake`.
	 * @since  2.1.2
	 */
	private function cached_verdict( array $bot, $ip ) {
		$token = isset( $bot['ua'] ) ? (string) $bot['ua'] : 'bot';
		$key   = self::CACHE_PREFIX . md5( $ip . '|' . $token );

		$cached = get_transient( $key );
		if ( 'verified' === $cached || 'fake' === $cached || 'unknown' === $cached ) {
			$this->last_reason = 'cached';
			return $cached;
		}

		$reason            = '';
		$verdict           = $this->classify( $bot, $ip, null, null, $reason );
		$this->last_reason = '' !== $reason ? $reason : 'unspecified';
		if ( 'verified' === $verdict ) {
			$ttl = self::CACHE_VERIFIED;
		} elseif ( 'unknown' === $verdict ) {
			$ttl = self::CACHE_UNKNOWN;
		} else {
			$ttl = self::CACHE_FAKE;
		}
		set_transient( $key, $verdict, $ttl );
		return $verdict;
	}

	/**
	 * Act on a confirmed spoofer: always log, then block when the action is
	 * `block`. The `flag` action logs only, keeping the sensor SEO-safe.
	 *
	 * @param array<string,mixed> $bot Matched bot rule.
	 * @param string              $ip  Client IP.
	 * @return void
	 * @since  2.1.2
	 */
	private function handle_fake( array $bot, $ip ) {
		$action = $this->action();

		if ( class_exists( 'ReportedIP_Hive' ) ) {
			$logger = ReportedIP_Hive::get_instance()->get_logger();
			if ( $logger instanceof ReportedIP_Hive_Logger ) {
				$details = array(
					'claimed_bot' => isset( $bot['ua'] ) ? (string) $bot['ua'] : '',
					'action'      => $action,
					'reason'      => '' !== $this->last_reason ? $this->last_reason : 'unspecified',
				);
				$details = array_merge( $details, ReportedIP_Hive_Logger::request_snapshot() );

				$logger->log_security_event(
					'block' === $action ? 'fake_bot_blocked' : 'fake_bot',
					$ip,
					$details,
					'medium'
				);
			}
		}

		if ( 'block' === $action ) {
			ReportedIP_Hive::serve_blocked_page( 'fake_bot' );
		}
	}
}
