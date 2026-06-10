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
 * @since     2.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Two-stage verified-bot sensor (IP-range match first, FCrDNS fallback).
 *
 * @since 2.2.0
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
	 * Transient key prefix for cached verification verdicts.
	 */
	const CACHE_PREFIX = 'reportedip_hive_botverify_';

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Bot_Verifier|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Bot_Verifier
	 * @since  2.2.0
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
	 * @since 2.2.0
	 */
	private function __construct() {
		add_action( 'init', array( $this, 'inspect' ), 4 );
	}

	/**
	 * Inspect the current request: identify a claimed crawler, verify it and act
	 * on a spoofer according to the configured action.
	 *
	 * @return void
	 * @since  2.2.0
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
	 * @since  2.2.0
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
	 * @since  2.2.0
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
	 * @since  2.2.0
	 */
	public function get_bot_rules() {
		if ( ! class_exists( 'ReportedIP_Hive_Rule_Sync' ) ) {
			return array();
		}
		$ruleset = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'bot_signatures' );
		return isset( $ruleset['rules'] ) && is_array( $ruleset['rules'] ) ? $ruleset['rules'] : array();
	}

	/**
	 * Find the first bot rule whose token appears in the user-agent. Pure: takes
	 * the rules and the user-agent, touches no superglobal, so it is
	 * deterministically unit-testable.
	 *
	 * @param array<int,array<string,mixed>> $rules Bot-signature rules.
	 * @param string                         $ua    Request user-agent.
	 * @return array<string,mixed>|null The matched rule, or null.
	 * @since  2.2.0
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
	 * @param array<string,mixed> $bot     Matched bot rule (`ranges`, `domains`).
	 * @param string              $ip      Client IP.
	 * @param callable|null       $ptr     PTR resolver `fn(string $ip): string|false`.
	 * @param callable|null       $forward Forward resolver `fn(string $host): string|false`.
	 * @return string `verified` or `fake`.
	 * @since  2.2.0
	 */
	public function classify( array $bot, $ip, $ptr = null, $forward = null ) {
		$ranges = isset( $bot['ranges'] ) && is_array( $bot['ranges'] ) ? $bot['ranges'] : array();
		if ( ! empty( $ranges ) ) {
			foreach ( $ranges as $cidr ) {
				if ( ReportedIP_Hive_Database::ip_in_cidr( $ip, (string) $cidr ) ) {
					return 'verified';
				}
			}
			return 'fake';
		}

		$domains = isset( $bot['domains'] ) && is_array( $bot['domains'] ) ? $bot['domains'] : array();
		if ( empty( $domains ) ) {
			return 'fake';
		}

		$ptr     = is_callable( $ptr ) ? $ptr : 'gethostbyaddr';
		$forward = is_callable( $forward ) ? $forward : 'gethostbyname';

		$host = call_user_func( $ptr, $ip );
		if ( ! is_string( $host ) || '' === $host || $host === $ip ) {
			return 'fake';
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
		if ( ! $suffix_ok ) {
			return 'fake';
		}

		$resolved = call_user_func( $forward, $host );
		return ( is_string( $resolved ) && $resolved === $ip ) ? 'verified' : 'fake';
	}

	/**
	 * Return the cached verdict for the IP/bot pair, computing and caching it on
	 * a miss (verified 24 h, fake 1 h) so DNS is never hit twice for the same
	 * visitor inside the window.
	 *
	 * @param array<string,mixed> $bot Matched bot rule.
	 * @param string              $ip  Client IP.
	 * @return string `verified` or `fake`.
	 * @since  2.2.0
	 */
	private function cached_verdict( array $bot, $ip ) {
		$token = isset( $bot['ua'] ) ? (string) $bot['ua'] : 'bot';
		$key   = self::CACHE_PREFIX . md5( $ip . '|' . $token );

		$cached = get_transient( $key );
		if ( 'verified' === $cached || 'fake' === $cached ) {
			return $cached;
		}

		$verdict = $this->classify( $bot, $ip );
		set_transient( $key, $verdict, 'verified' === $verdict ? self::CACHE_VERIFIED : self::CACHE_FAKE );
		return $verdict;
	}

	/**
	 * Act on a confirmed spoofer: always log, then block when the action is
	 * `block`. The `flag` action logs only, keeping the sensor SEO-safe.
	 *
	 * @param array<string,mixed> $bot Matched bot rule.
	 * @param string              $ip  Client IP.
	 * @return void
	 * @since  2.2.0
	 */
	private function handle_fake( array $bot, $ip ) {
		$action = $this->action();

		if ( class_exists( 'ReportedIP_Hive' ) ) {
			$logger = ReportedIP_Hive::get_instance()->get_logger();
			if ( $logger instanceof ReportedIP_Hive_Logger ) {
				$logger->log_security_event(
					'block' === $action ? 'fake_bot_blocked' : 'fake_bot',
					$ip,
					array(
						'claimed_bot' => isset( $bot['ua'] ) ? (string) $bot['ua'] : '',
						'action'      => $action,
					),
					'medium'
				);
			}
		}

		if ( 'block' === $action ) {
			ReportedIP_Hive::serve_blocked_page( 'fake_bot' );
		}
	}
}
