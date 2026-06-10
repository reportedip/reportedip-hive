<?php
/**
 * Site-wide HTTP security-header emitter.
 *
 * Sends a configurable set of response headers on front-end requests. The
 * basic trio (X-Content-Type-Options, X-Frame-Options, Referrer-Policy) is
 * free and low-risk; the advanced set (HSTS, Permissions-Policy, a
 * report-only-first Content-Security-Policy and the Cross-Origin trio) sits
 * behind the `security_headers_advanced` feature gate. Headers already set by
 * the server or another plugin are detected via {@see headers_list()} and
 * never overwritten — the conflict is surfaced in the admin status instead.
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
 * Emits and reports the site-wide security headers.
 *
 * @since 2.2.0
 */
class ReportedIP_Hive_Security_Headers {

	const OPT_ENABLED         = 'reportedip_hive_headers_enabled';
	const OPT_XCTO            = 'reportedip_hive_header_xcto';
	const OPT_XFO             = 'reportedip_hive_header_xfo';
	const OPT_REFERRER        = 'reportedip_hive_header_referrer';
	const OPT_HSTS_ENABLED    = 'reportedip_hive_hsts_enabled';
	const OPT_HSTS_MAX_AGE    = 'reportedip_hive_hsts_max_age';
	const OPT_HSTS_SUBDOMAINS = 'reportedip_hive_hsts_subdomains';
	const OPT_HSTS_PRELOAD    = 'reportedip_hive_hsts_preload';
	const OPT_PERMISSIONS     = 'reportedip_hive_permissions_policy';
	const OPT_CSP_MODE        = 'reportedip_hive_csp_mode';
	const OPT_CSP_POLICY      = 'reportedip_hive_csp_policy';
	const OPT_CSP_REPORT_URI  = 'reportedip_hive_csp_report_uri';
	const OPT_COOP            = 'reportedip_hive_coop';
	const OPT_CORP            = 'reportedip_hive_corp';
	const OPT_COEP            = 'reportedip_hive_coep';

	/**
	 * Feature key gating the advanced header set.
	 */
	const ADVANCED_FEATURE = 'security_headers_advanced';

	/**
	 * OWASP-aligned starter policy offered as the CSP textarea default.
	 */
	const CSP_BASELINE = "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

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
	 * @since  2.2.0
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
	 * @since 2.2.0
	 */
	private function __construct() {
		add_action( 'send_headers', array( $this, 'emit' ), 10 );
	}

	/**
	 * Send the configured headers, skipping any already present.
	 *
	 * @return void
	 * @since  2.2.0
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
	 * @since  2.2.0
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

		if ( ! self::advanced_available() ) {
			return $headers;
		}

		if ( (bool) self::opt( self::OPT_HSTS_ENABLED, false ) && is_ssl() ) {
			$max_age = max( 0, (int) self::opt( self::OPT_HSTS_MAX_AGE, 63072000 ) );
			$hsts    = 'max-age=' . $max_age;
			if ( (bool) self::opt( self::OPT_HSTS_SUBDOMAINS, false ) ) {
				$hsts .= '; includeSubDomains';
			}
			if ( (bool) self::opt( self::OPT_HSTS_PRELOAD, false ) ) {
				$hsts .= '; preload';
			}
			$headers['Strict-Transport-Security'] = $hsts;
		}

		$permissions = trim( (string) self::opt( self::OPT_PERMISSIONS, '' ) );
		if ( '' !== $permissions ) {
			$headers['Permissions-Policy'] = $permissions;
		}

		$csp_mode = (string) self::opt( self::OPT_CSP_MODE, 'off' );
		$policy   = trim( (string) self::opt( self::OPT_CSP_POLICY, '' ) );
		if ( in_array( $csp_mode, array( 'report_only', 'enforce' ), true ) && '' !== $policy ) {
			$report_uri = trim( (string) self::opt( self::OPT_CSP_REPORT_URI, '' ) );
			if ( '' !== $report_uri ) {
				$policy .= '; report-uri ' . $report_uri;
			}
			$name             = 'report_only' === $csp_mode ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy';
			$headers[ $name ] = $policy;
		}

		if ( 'same-origin' === self::opt( self::OPT_COOP, 'off' ) ) {
			$headers['Cross-Origin-Opener-Policy'] = 'same-origin';
		}
		if ( 'same-origin' === self::opt( self::OPT_CORP, 'off' ) ) {
			$headers['Cross-Origin-Resource-Policy'] = 'same-origin';
		}
		if ( 'require-corp' === self::opt( self::OPT_COEP, 'off' ) ) {
			$headers['Cross-Origin-Embedder-Policy'] = 'require-corp';
		}

		return $headers;
	}

	/**
	 * Planned headers that are already sent elsewhere (server/other plugin).
	 *
	 * @return string[] Conflicting header names (original casing).
	 * @since  2.2.0
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
	 * @since  2.2.0
	 */
	public static function is_enabled() {
		return (bool) self::opt( self::OPT_ENABLED, false );
	}

	/**
	 * Whether at least one basic header is active (Score contract).
	 *
	 * @return bool
	 * @since  2.2.0
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
	 * Whether at least one advanced header is active and available (Score contract).
	 *
	 * @return bool
	 * @since  2.2.0
	 */
	public static function advanced_active() {
		if ( ! self::is_enabled() || ! self::advanced_available() ) {
			return false;
		}
		return (bool) self::opt( self::OPT_HSTS_ENABLED, false )
			|| '' !== trim( (string) self::opt( self::OPT_PERMISSIONS, '' ) )
			|| 'off' !== (string) self::opt( self::OPT_CSP_MODE, 'off' )
			|| 'off' !== (string) self::opt( self::OPT_COOP, 'off' )
			|| 'off' !== (string) self::opt( self::OPT_CORP, 'off' )
			|| 'off' !== (string) self::opt( self::OPT_COEP, 'off' );
	}

	/**
	 * Whether the advanced header set is unlocked for the current tier/mode.
	 *
	 * @return bool
	 * @since  2.2.0
	 */
	public static function advanced_available() {
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			return false;
		}
		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( self::ADVANCED_FEATURE );
		return ! empty( $status['available'] );
	}

	/**
	 * Normalised X-Frame-Options value: SAMEORIGIN | DENY | off.
	 *
	 * @return string
	 * @since  2.2.0
	 */
	private static function xfo_value() {
		$value = strtoupper( trim( (string) self::opt( self::OPT_XFO, 'SAMEORIGIN' ) ) );
		if ( 'DENY' === $value ) {
			return 'DENY';
		}
		if ( 'OFF' === $value || '' === $value ) {
			return 'off';
		}
		return 'SAMEORIGIN';
	}

	/**
	 * Lower-cased names of headers already queued for this response.
	 *
	 * @return string[]
	 * @since  2.2.0
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
	 * @since  2.2.0
	 */
	private static function opt( $key, $fallback ) {
		if ( ! class_exists( 'ReportedIP_Hive_Option_Routing' ) ) {
			return $fallback;
		}
		return ReportedIP_Hive_Option_Routing::get( $key, $fallback );
	}
}
