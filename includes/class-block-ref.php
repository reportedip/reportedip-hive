<?php
/**
 * Block-page reference codes — maps a block reason to a stable category code
 * and a correlatable, non-reversible incident token (Cloudflare "Ray ID"
 * pattern). The category tells the admin *why* a request was blocked; the
 * token lets a wrongly-blocked visitor quote one short string that the admin
 * can match against the request without exposing any personal data.
 *
 * Pure, dependency-free and side-effect-free so it is trivially unit-testable
 * and so rendering a blocked page never writes to the database (which would
 * otherwise be a denial-of-service amplifier on a hammered URL).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reason-to-reference-code resolver for blocked-page responses.
 *
 * @since 2.1.0
 */
final class ReportedIP_Hive_Block_Ref {

	/**
	 * Canonical map of block reasons to human-readable category codes. The
	 * WAF entries are included ahead of the WAF sensor (Firewall phase) so a
	 * future caller only has to pass the matching reason key.
	 *
	 * @var array<string, string>
	 */
	const CATEGORY_MAP = array(
		'ip_block'       => 'IP_BLOCK',
		'reputation'     => 'IP_REPUTATION',
		'hide_login'     => 'LOGIN_HIDDEN',
		'login'          => 'LOGIN_LOCKOUT',
		'lockout'        => 'LOCKOUT',
		'scan'           => 'SCAN_PROBE',
		'decoy'          => 'DECOY_HIT',
		'geo'            => 'GEO_ANOMALY',
		'rest_burst'     => 'REST_BURST',
		'user_enum'      => 'USER_ENUM',
		'xmlrpc'         => 'XMLRPC_ABUSE',
		'app_password'   => 'APP_PASSWORD',
		'waf_sqli'       => 'WAF_SQLI',
		'waf_xss'        => 'WAF_XSS',
		'waf_traversal'  => 'WAF_TRAVERSAL',
		'waf_cmd'        => 'WAF_CMD',
		'waf_file'       => 'WAF_FILE',
		'waf_scanner'    => 'WAF_SCANNER',
		'waf_log4shell'  => 'WAF_LOG4SHELL',
		'waf_ssrf'       => 'WAF_SSRF',
		'waf_php'        => 'WAF_PHP_INJECTION',
		'waf_nosql'      => 'WAF_NOSQL',
		'waf_xxe'        => 'WAF_XXE',
		'waf_webshell'   => 'WAF_WEBSHELL',
		'waf_crlf'       => 'WAF_CRLF',
		'waf_ssti'       => 'WAF_SSTI',
		'waf_rest_abuse' => 'WAF_REST_ABUSE',
		'fake_bot'       => 'FAKE_BOT',
	);

	/**
	 * Category used when the reason is unknown.
	 */
	const FALLBACK_CATEGORY = 'BLOCKED';

	/**
	 * Resolve the category code for a block reason. A lockout duration in
	 * `$context['minutes']` is appended (e.g. `LOCKOUT_30M`) so the admin
	 * sees the active block length straight from the code.
	 *
	 * @param string               $reason  Reason key (see CATEGORY_MAP).
	 * @param array<string, mixed> $context Optional context; `minutes` is honoured for lockouts.
	 * @return string Upper-case category code.
	 * @since  2.1.0
	 */
	public static function category( $reason, array $context = array() ) {
		$key      = is_string( $reason ) ? strtolower( $reason ) : '';
		$category = isset( self::CATEGORY_MAP[ $key ] ) ? self::CATEGORY_MAP[ $key ] : self::FALLBACK_CATEGORY;

		$minutes = isset( $context['minutes'] ) ? (int) $context['minutes'] : 0;
		if ( $minutes > 0 && ( 'lockout' === $key || 'login' === $key ) ) {
			$category .= '_' . $minutes . 'M';
		}

		return $category;
	}

	/**
	 * Derive a short, non-reversible incident token from the client IP, the
	 * reason and an hourly time window. Deterministic within the window so the
	 * same visitor quoting the same code lets the admin correlate the event,
	 * yet the IP is never recoverable from the 8-hex digest (no PII leak).
	 *
	 * @param string      $ip     Client IP address (hashed, never emitted).
	 * @param string      $reason Reason key.
	 * @param string|null $window Optional explicit window key; defaults to the current UTC hour.
	 * @return string 8-character upper-case hex token.
	 * @since  2.1.0
	 */
	public static function token( $ip, $reason, $window = null ) {
		$window     = ( null !== $window && '' !== $window ) ? (string) $window : gmdate( 'Y-m-d-H' );
		$ip         = ( is_string( $ip ) && '' !== $ip ) ? $ip : 'unknown';
		$reason_key = is_string( $reason ) ? $reason : '';

		return strtoupper( substr( hash( 'sha256', $window . '|' . sha1( $ip . '|' . $reason_key ) ), 0, 8 ) );
	}

	/**
	 * Build the full reference code `CATEGORY-TOKEN` shown on the block page
	 * and emitted as the `X-RIP-Ref` header.
	 *
	 * @param string               $reason  Reason key (see CATEGORY_MAP).
	 * @param string               $ip      Client IP address.
	 * @param array<string, mixed> $context Optional context (`minutes`, `window`).
	 * @return string Reference code, e.g. `WAF_SQLI-3F9A2B71`.
	 * @since  2.1.0
	 */
	public static function code( $reason, $ip, array $context = array() ) {
		$window = isset( $context['window'] ) ? $context['window'] : null;

		return self::category( $reason, $context ) . '-' . self::token( $ip, $reason, $window );
	}
}
