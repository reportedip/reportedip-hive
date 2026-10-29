<?php
/**
 * Site-wide HTTP security-header emitter.
 *
 * Sends a configurable set of response headers on front-end requests: the
 * low-risk basic trio (X-Content-Type-Options, X-Frame-Options,
 * Referrer-Policy) plus whatever an add-on appends through
 * `reportedip_hive_planned_headers`. Headers another plugin already queued
 * are detected via {@see headers_list()} and never overwritten. Headers the
 * web server adds itself are invisible to PHP; {@see probe()} finds them, and
 * {@see server_snippets()} moves the whole set to the web server, the route
 * that also covers cached pages and static files.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Emits and reports the site-wide security headers.
 *
 * @since 2.1.2
 */
class ReportedIP_Hive_Security_Headers {

	const OPT_ENABLED  = 'reportedip_hive_headers_enabled';
	const OPT_XCTO     = 'reportedip_hive_header_xcto';
	const OPT_XFO      = 'reportedip_hive_header_xfo';
	const OPT_REFERRER = 'reportedip_hive_header_referrer';

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Security_Headers|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton instance.
	 *
	 * @return ReportedIP_Hive_Security_Headers
	 * @since  2.1.2
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire the front-end header hook.
	 *
	 * @since 2.1.2
	 */
	private function __construct() {
		add_action( 'send_headers', array( $this, 'emit' ), 10 );
	}

	/**
	 * Send the configured headers, skipping any already present.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function emit() {
		if ( headers_sent() ) {
			return;
		}
		$planned = self::planned_headers();
		if ( empty( $planned ) ) {
			return;
		}
		$present = self::sent_header_names();
		foreach ( $planned as $name => $value ) {
			if ( in_array( strtolower( $name ), $present, true ) ) {
				continue;
			}
			header( $name . ': ' . $value );
		}
	}

	/**
	 * The header name/value map this site would emit under the current config.
	 *
	 * @return array<string,string>
	 * @since  2.1.2
	 */
	public static function planned_headers() {
		$headers = array();
		if ( ! self::is_enabled() ) {
			return $headers;
		}

		if ( (bool) self::opt( self::OPT_XCTO, true ) ) {
			$headers['X-Content-Type-Options'] = 'nosniff';
		}
		$xfo = self::xfo_value();
		if ( 'off' !== $xfo ) {
			$headers['X-Frame-Options'] = $xfo;
		}
		$referrer = trim( (string) self::opt( self::OPT_REFERRER, 'strict-origin-when-cross-origin' ) );
		if ( '' !== $referrer ) {
			$headers['Referrer-Policy'] = $referrer;
		}

		/**
		 * Extend the planned response headers.
		 *
		 * Runs only while the master switch is on, after the basic trio. A
		 * listener can add headers but never drop or rewrite the basic trio,
		 * and a name or value that would split the header line is ignored.
		 *
		 * @param array<string,string> $headers Header name to value.
		 * @since 3.0.0
		 */
		$extended = apply_filters( 'reportedip_hive_planned_headers', $headers );
		foreach ( is_array( $extended ) ? $extended : array() as $name => $value ) {
			if ( ! is_string( $name ) || ! is_scalar( $value ) || isset( array_change_key_case( $headers )[ strtolower( $name ) ] ) ) {
				continue;
			}
			$value = (string) $value;
			if ( ! preg_match( '/^[A-Za-z0-9-]+$/', $name ) || preg_match( '/[\r\n]/', $value ) ) {
				continue;
			}
			$headers[ $name ] = $value;
		}

		return $headers;
	}

	/**
	 * Planned headers that are already sent elsewhere (server/other plugin).
	 *
	 * @return string[] Conflicting header names (original casing).
	 * @since  2.1.2
	 */
	public static function conflicts() {
		$present = self::sent_header_names();
		$out     = array();
		foreach ( array_keys( self::planned_headers() ) as $name ) {
			if ( in_array( strtolower( $name ), $present, true ) ) {
				$out[] = $name;
			}
		}
		return $out;
	}

	/**
	 * Security headers the probe reports even when Hive does not plan them,
	 * so a header the web server sets on its own shows up as well.
	 *
	 * @var string[]
	 */
	const KNOWN = array(
		'X-Content-Type-Options',
		'X-Frame-Options',
		'Referrer-Policy',
		'Strict-Transport-Security',
		'Permissions-Policy',
		'Content-Security-Policy',
		'Content-Security-Policy-Report-Only',
		'Reporting-Endpoints',
		'Cross-Origin-Opener-Policy',
		'Cross-Origin-Resource-Policy',
		'Cross-Origin-Embedder-Policy',
	);

	/**
	 * Whether a page cache drop-in is active.
	 *
	 * A cache hit is delivered from `advanced-cache.php` before
	 * `send_headers` fires, so those pages go out without the headers
	 * WordPress would add.
	 *
	 * @return bool
	 * @since  3.0.5
	 */
	public static function page_cache_active() {
		return defined( 'WP_CACHE' ) && WP_CACHE && defined( 'WP_CONTENT_DIR' ) && file_exists( WP_CONTENT_DIR . '/advanced-cache.php' );
	}

	/**
	 * Web server configuration for the planned headers.
	 *
	 * The server route covers every response, cached pages and static files
	 * included, so it is the most compatible one. nginx lines carry `always`
	 * (error pages too); Apache lines sit inside `IfModule`, so a missing
	 * mod_headers never turns into a 500, and HSTS is limited to HTTPS.
	 *
	 * @return array{nginx:string,apache:string} Empty strings when nothing is planned.
	 * @since  3.0.5
	 */
	public static function server_snippets() {
		$planned = self::planned_headers();
		if ( empty( $planned ) ) {
			return array(
				'nginx'  => '',
				'apache' => '',
			);
		}

		$nginx  = array(
			'# ReportedIP Hive: security headers for nginx.',
			'# Paste into the server { } block that serves HTTPS, then run: nginx -t && systemctl reload nginx',
			'# A location { } block with its own add_header inherits none of these lines.',
			'# Repeat them there, or keep them in one file and include it in both places.',
			'# Afterwards switch off "Send security headers" in Hive, otherwise every header is sent twice.',
		);
		$apache = array(
			'# ReportedIP Hive: security headers for Apache (.htaccess or virtual host).',
			'# Afterwards switch off "Send security headers" in Hive, otherwise every header is sent twice.',
			'<IfModule mod_headers.c>',
		);
		foreach ( $planned as $name => $value ) {
			$quoted   = '"' . str_replace( array( '\\', '"' ), array( '\\\\', '\\"' ), $value ) . '"';
			$nginx[]  = 'add_header ' . $name . ' ' . $quoted . ' always;';
			$apache[] = "\tHeader always set " . $name . ' ' . $quoted . ( 'Strict-Transport-Security' === $name ? " \"expr=%{HTTPS} == 'on'\"" : '' );
		}
		$apache[] = '</IfModule>';

		return array(
			'nginx'  => implode( "\n", $nginx ),
			'apache' => implode( "\n", $apache ),
		);
	}

	/**
	 * Fetch the home page twice the way a visitor does (the second time a
	 * page cache answers) and once past the cache, then judge every header.
	 *
	 * Only the site's own address is requested.
	 *
	 * @return array{rows:array<string,array{status:string,planned:string,cached:string[],uncached:string[]}>,error:string}
	 * @since  3.0.5
	 */
	public static function probe() {
		$args = array(
			'timeout'     => 10,
			'redirection' => 3,
			'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core filter for loopback requests, the same one wp-cron uses.
			'headers'     => array( 'Cache-Control' => 'max-age=0' ),
		);
		$home = home_url( '/' );

		wp_remote_get( $home, $args );
		$cached   = wp_remote_get( $home, $args );
		$uncached = wp_remote_get( add_query_arg( 'rip-header-check', (string) time(), $home ), $args );

		foreach ( array( $cached, $uncached ) as $response ) {
			if ( is_wp_error( $response ) ) {
				return array(
					'rows'  => array(),
					'error' => $response->get_error_message(),
				);
			}
		}

		return array(
			'rows'  => self::evaluate_probe( self::planned_headers(), self::header_values( $cached ), self::header_values( $uncached ) ),
			'error' => '',
		);
	}

	/**
	 * Judge each header from two responses.
	 *
	 * Statuses: `ok` (once, with the planned value, on both paths),
	 * `missing` (planned, absent everywhere), `missing_cached` (planned,
	 * absent on the cached page), `duplicate` (sent more than once, usually
	 * by the server and Hive), `other_value` (one value, not the planned
	 * one, so something else sets it) and `server_only` (not planned, set by
	 * the server or another plugin).
	 *
	 * @param array<string,string>   $planned  Header name to planned value.
	 * @param array<string,string[]> $cached   Lower-cased name to values, cached path.
	 * @param array<string,string[]> $uncached Lower-cased name to values, uncached path.
	 * @return array<string,array{status:string,planned:string,cached:string[],uncached:string[]}>
	 * @since  3.0.5
	 */
	public static function evaluate_probe( array $planned, array $cached, array $uncached ) {
		$names = $planned;
		foreach ( self::KNOWN as $known ) {
			if ( ! isset( array_change_key_case( $names )[ strtolower( $known ) ] ) ) {
				$names[ $known ] = null;
			}
		}

		$rows = array();
		foreach ( $names as $name => $want ) {
			$key = strtolower( (string) $name );
			$c   = array_values( $cached[ $key ] ?? array() );
			$u   = array_values( $uncached[ $key ] ?? array() );
			if ( null === $want && array() === $c && array() === $u ) {
				continue;
			}
			if ( null === $want ) {
				$status = 'server_only';
			} elseif ( count( $c ) > 1 || count( $u ) > 1 ) {
				$status = 'duplicate';
			} elseif ( array() === $c && array() === $u ) {
				$status = 'missing';
			} elseif ( array() === $c ) {
				$status = 'missing_cached';
			} elseif ( $c[0] !== $want || ( array() !== $u && $u[0] !== $want ) ) {
				$status = 'other_value';
			} else {
				$status = 'ok';
			}
			$rows[ (string) $name ] = array(
				'status'   => $status,
				'planned'  => null === $want ? '' : (string) $want,
				'cached'   => $c,
				'uncached' => $u,
			);
		}
		return $rows;
	}

	/**
	 * Lower-cased header name to every value it was sent with.
	 *
	 * @param array|WP_Error $response HTTP API response.
	 * @return array<string,string[]>
	 * @since  3.0.5
	 */
	private static function header_values( $response ) {
		$headers = wp_remote_retrieve_headers( $response );
		$out     = array();
		if ( is_array( $headers ) ) {
			$headers = array_change_key_case( $headers );
		}
		if ( ! is_array( $headers ) && ! ( $headers instanceof ArrayAccess ) ) {
			return $out;
		}
		foreach ( self::KNOWN as $name ) {
			$key = strtolower( $name );
			if ( isset( $headers[ $key ] ) ) {
				$out[ $key ] = array_map( 'trim', array_map( 'strval', (array) $headers[ $key ] ) );
			}
		}
		return $out;
	}

	/**
	 * Whether the master toggle is on.
	 *
	 * @return bool
	 * @since  2.1.2
	 */
	public static function is_enabled() {
		return (bool) self::opt( self::OPT_ENABLED, false );
	}

	/**
	 * Whether at least one basic header is active (Score contract).
	 *
	 * @return bool
	 * @since  2.1.2
	 */
	public static function basic_active() {
		if ( ! self::is_enabled() ) {
			return false;
		}
		return (bool) self::opt( self::OPT_XCTO, true )
			|| 'off' !== self::xfo_value()
			|| '' !== trim( (string) self::opt( self::OPT_REFERRER, 'strict-origin-when-cross-origin' ) );
	}

	/**
	 * Sanitize a submitted X-Frame-Options value.
	 *
	 * The header value is case-sensitive in the wire format, so this key
	 * cannot use the registry's generic enum sanitizer: that one lower-cases
	 * through `sanitize_key()` and would reject `SAMEORIGIN`. Anything
	 * unrecognised falls back to the safe default rather than to `off`.
	 *
	 * @param mixed $value Raw input.
	 * @return string SAMEORIGIN | DENY | off.
	 * @since  2.1.51
	 */
	public static function sanitize_xfo( $value ) {
		$value = strtoupper( trim( is_scalar( $value ) ? (string) $value : '' ) );

		if ( 'DENY' === $value ) {
			return 'DENY';
		}
		if ( 'OFF' === $value || '' === $value ) {
			return 'off';
		}

		return 'SAMEORIGIN';
	}

	/**
	 * Normalised X-Frame-Options value: SAMEORIGIN | DENY | off.
	 *
	 * @return string
	 * @since  2.1.2
	 */
	private static function xfo_value() {
		return self::sanitize_xfo( self::opt( self::OPT_XFO, 'SAMEORIGIN' ) );
	}

	/**
	 * Lower-cased names of headers already queued for this response.
	 *
	 * @return string[]
	 * @since  2.1.2
	 */
	private static function sent_header_names() {
		if ( ! function_exists( 'headers_list' ) ) {
			return array();
		}
		$names = array();
		foreach ( headers_list() as $line ) {
			$pos = strpos( $line, ':' );
			if ( false !== $pos ) {
				$names[] = strtolower( trim( substr( $line, 0, $pos ) ) );
			}
		}
		return $names;
	}

	/**
	 * Read a plugin option through the multisite-aware routing layer.
	 *
	 * @param string $key      Option key.
	 * @param mixed  $fallback Value returned when the option is unset.
	 * @return mixed
	 * @since  2.1.2
	 */
	private static function opt( $key, $fallback ) {
		if ( ! class_exists( 'ReportedIP_Hive_Option_Routing' ) ) {
			return $fallback;
		}
		return ReportedIP_Hive_Option_Routing::get( $key, $fallback );
	}
}
