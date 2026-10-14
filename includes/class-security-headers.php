<?php
/**
 * Site-wide HTTP security-header emitter.
 *
 * Sends a configurable set of response headers on front-end requests: the
 * low-risk basic trio (X-Content-Type-Options, X-Frame-Options,
 * Referrer-Policy) plus whatever an add-on appends through
 * `reportedip_hive_planned_headers`. Headers already set by the server or
 * another plugin are detected via {@see headers_list()} and never
 * overwritten, the conflict is surfaced in the admin status instead.
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
