<?php
/**
 * Canonical request-path resolution shared by every path-matching sensor.
 *
 * Each sensor used to parse `REQUEST_URI` itself, and they disagreed — which is
 * how a percent-escaped probe walked past the hidden login and the scanner
 * honeypot while the firewall engine saw it. Both traps this closes are subtle
 * enough that no sensor should re-derive them:
 *
 *  - `sanitize_text_field()` deletes every `%XX` sequence, so `/wp-login%2Ephp`
 *    became `/wp-loginphp` — a path the server never resolves and no rule ever
 *    matches. The URI has to be parsed raw and decoded exactly once.
 *  - `//host/path` is a protocol-relative URL: `parse_url()` reads `host` as the
 *    authority and returns only `/path`. A path-prefix comparison then matches
 *    a prefix the request never had, so leading slashes collapse *before*
 *    parsing, never after — re-collapsing post-decode would let `%2F%2F` fold
 *    into a prefix the web server keeps separate.
 *
 * The pre-WordPress guard cannot call this (it runs before WordPress loads) and
 * keeps its own copy by design; `WafGuardHelperParityTest` pins the two together.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.44
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Resolves the request path the way the web server does.
 *
 * @since 2.1.44
 */
class ReportedIP_Hive_Request_Path {

	/**
	 * Memoised path for the current request.
	 *
	 * @var string|null
	 */
	private static $current = null;

	/**
	 * Normalise a raw request URI to the path the server will resolve.
	 *
	 * @param string $raw Raw REQUEST_URI (or any URI-ish string).
	 * @return string Leading-slash path, decoded once, control characters removed.
	 * @since  2.1.44
	 */
	public static function normalize( $raw ) {
		$raw = (string) $raw;
		if ( '' === $raw ) {
			return '';
		}

		$path = (string) wp_parse_url( '/' . ltrim( $raw, '/' ), PHP_URL_PATH );
		if ( '' === $path ) {
			return '';
		}

		$path = rawurldecode( $path );

		return (string) preg_replace( '/[\x00-\x1F\x7F]/', '', $path );
	}

	/**
	 * The current request's path, resolved once per request.
	 *
	 * @return string Leading-slash path, or '' when there is no request URI.
	 * @since  2.1.44
	 */
	public static function current() {
		if ( null !== self::$current ) {
			return self::$current;
		}

		$raw = isset( $_SERVER['REQUEST_URI'] )
			? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitising strips percent-encoding and reopens the %2E bypass; normalize() decodes and removes control characters.
			: '';

		self::$current = self::normalize( $raw );

		return self::$current;
	}

	/**
	 * Drop the memoised path. Tests only.
	 *
	 * @return void
	 * @since  2.1.44
	 */
	public static function flush() {
		self::$current = null;
	}
}
