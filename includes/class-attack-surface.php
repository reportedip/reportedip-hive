<?php
/**
 * Attack-surface switches, REST API access control, XML-RPC and feed
 * shut-off, and software-fingerprint removal. Every switch closes a WordPress
 * endpoint that most sites never use but every scanner tries first.
 *
 * The wp-admin guest block and the PHP-execution block in uploads belong to
 * the same settings section but live where their machinery already is
 * ({@see ReportedIP_Hive_Hide_Login}, {@see ReportedIP_Hive_Uploads_Htaccess_Writer}).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.51
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Runtime for the attack-surface switches.
 *
 * @since 2.1.51
 */
final class ReportedIP_Hive_Attack_Surface {

	/**
	 * REST access mode: open | logged_in | restricted.
	 */
	const OPT_REST_MODE = 'reportedip_hive_rest_access_mode';

	/**
	 * Namespace/route-prefix allowlist, one entry per line.
	 */
	const OPT_REST_NAMESPACES = 'reportedip_hive_rest_allowed_namespaces';

	/**
	 * Roles that keep REST access in `restricted` mode (JSON array).
	 */
	const OPT_REST_ROLES = 'reportedip_hive_rest_allowed_roles';

	/**
	 * Switch off XML-RPC entirely.
	 */
	const OPT_XMLRPC_OFF = 'reportedip_hive_disable_xmlrpc';

	/**
	 * Switch off RSS/Atom/comment feeds.
	 */
	const OPT_FEEDS_OFF = 'reportedip_hive_disable_feeds';

	/**
	 * Close wp-admin for logged-out visitors.
	 */
	const OPT_ADMIN_GUESTS = 'reportedip_hive_block_admin_guests';

	/**
	 * Refuse executable file types inside the uploads directory.
	 */
	const OPT_UPLOADS_PHP = 'reportedip_hive_block_uploads_php';

	/**
	 * Remove the generator tag and switch PHP error display off.
	 */
	const OPT_HIDE_SOFTWARE = 'reportedip_hive_hide_software_info';

	/**
	 * Every option key this feature owns, in registry order.
	 *
	 * @var string[]
	 */
	const OPTION_KEYS = array(
		self::OPT_REST_MODE,
		self::OPT_REST_NAMESPACES,
		self::OPT_REST_ROLES,
		self::OPT_XMLRPC_OFF,
		self::OPT_FEEDS_OFF,
		self::OPT_ADMIN_GUESTS,
		self::OPT_UPLOADS_PHP,
		self::OPT_HIDE_SOFTWARE,
	);

	/**
	 * REST is reachable by everyone (WordPress default).
	 */
	const REST_MODE_OPEN = 'open';

	/**
	 * REST is reachable by authenticated users only.
	 */
	const REST_MODE_LOGGED_IN = 'logged_in';

	/**
	 * REST is reachable by the listed roles (plus administrators) only.
	 */
	const REST_MODE_RESTRICTED = 'restricted';

	/**
	 * Namespaces that must never be gated: the plugin's own endpoints carry
	 * the 2FA challenge and the Cloud-Fleet remote-settings routes, both of
	 * which are anonymous from WordPress's point of view and both of which
	 * authenticate themselves.
	 *
	 * @var string[]
	 */
	const ALWAYS_ALLOWED_NAMESPACES = array( 'reportedip-hive/v1' );

	/**
	 * Application-password management route, WordPress's own app-password
	 * UI calls it for the authenticated user, so a role restriction must not
	 * lock a user out of their own credentials.
	 */
	const APP_PASSWORD_ROUTE_PATTERN = '#^/wp/v2/users/(?:\d+|me)/application-passwords#';

	/**
	 * Seconds a denial event is suppressed per IP and event type.
	 */
	const LOG_THROTTLE_SECONDS = 5;

	/**
	 * Event written when a REST request is refused.
	 */
	const EVENT_REST = 'rest_denied';

	/**
	 * Event written when an XML-RPC request is refused.
	 */
	const EVENT_XMLRPC = 'xmlrpc_denied';

	/**
	 * Event written when a feed request is refused.
	 */
	const EVENT_FEED = 'feed_denied';

	/**
	 * Event written when a logged-out wp-admin request is refused while Hide
	 * Login is off (with Hide Login on, its own probe ladder logs instead).
	 */
	const EVENT_ADMIN_GUEST = 'admin_guest_denied';

	/**
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * @return self
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor, registers hooks.
	 */
	private function __construct() {
		$this->register_hooks();
	}

	/**
	 * Whether a boolean switch of this feature is on. All switches are free
	 * and ungated, so this is a plain option read with the canonical default.
	 *
	 * @param string $option One of the OPT_* constants.
	 * @return bool
	 * @since  2.1.51
	 */
	public static function switch_on( $option ) {
		return (bool) ReportedIP_Hive_Option_Routing::get( $option, false );
	}

	/**
	 * Validated REST access mode.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	public static function rest_mode() {
		$mode = (string) ReportedIP_Hive_Option_Routing::get( self::OPT_REST_MODE, self::REST_MODE_OPEN );
		$all  = array( self::REST_MODE_OPEN, self::REST_MODE_LOGGED_IN, self::REST_MODE_RESTRICTED );
		return in_array( $mode, $all, true ) ? $mode : self::REST_MODE_OPEN;
	}

	/**
	 * Wire the runtime hooks and apply the fingerprint removals.
	 *
	 * `plugins_loaded` is late enough for both: WordPress's default filters
	 * are registered while `wp-includes/default-filters.php` loads, and
	 * `wp_debug_mode()` has already run.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function register_hooks() {
		add_filter( 'rest_authentication_errors', array( $this, 'filter_rest_authentication' ), 110 );
		add_action( 'init', array( $this, 'intercept_xmlrpc' ), 1 );
		add_action( 'init', array( $this, 'apply_passive_switches' ), 10 );
		add_action( 'template_redirect', array( $this, 'intercept_feeds' ), 1 );

		$this->apply_fingerprint_switches();
	}

	/**
	 * Remove the WordPress version fingerprints and switch PHP error display
	 * off.
	 *
	 * ponytail: `display_errors` only. Errors raised before this runs
	 * (mu-plugins, drop-ins, the core bootstrap) and the fatal-error handler's
	 * own page are out of reach, and a developer running `WP_DEBUG` with
	 * `WP_DEBUG_DISPLAY` keeps their error output, the wp-config constants
	 * win on purpose. Upgrade path if that is ever not enough: an
	 * `auto_prepend_file` directive, which the WAF drop-in already owns.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	private function apply_fingerprint_switches() {
		if ( ! self::switch_on( self::OPT_HIDE_SOFTWARE ) ) {
			return;
		}

		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );

		$debug_display = defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY;
		if ( ! $debug_display && function_exists( 'ini_set' ) ) {
			ini_set( 'display_errors', '0' ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Disallowed -- That is the entire point of the switch; the WP_DEBUG_DISPLAY guard above keeps a developer's error output intact.
		}
	}

	/**
	 * Register the passive switches: filters and `wp_head` removals that
	 * produce no output of their own.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function apply_passive_switches() {
		if ( self::REST_MODE_OPEN !== self::rest_mode() ) {
			remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
			remove_action( 'template_redirect', 'rest_output_link_header', 11 );
			remove_action( 'xmlrpc_rsd_apis', 'rest_output_rsd' );
		}

		if ( self::switch_on( self::OPT_XMLRPC_OFF ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', array( $this, 'strip_pingback_methods' ) );
			add_filter( 'pings_open', '__return_false', 99 );
			add_filter( 'bloginfo_url', array( $this, 'hide_pingback_url' ), 10, 2 );
			remove_action( 'wp_head', 'rsd_link' );
			remove_action( 'wp_head', 'wlwmanifest_link' );
		}

		if ( self::switch_on( self::OPT_FEEDS_OFF ) ) {
			remove_action( 'wp_head', 'feed_links', 2 );
			remove_action( 'wp_head', 'feed_links_extra', 3 );
		}
	}

	/**
	 * Drop the pingback methods from the XML-RPC method table.
	 *
	 * @param array<string,mixed>|mixed $methods Registered XML-RPC methods.
	 * @return array<string,mixed>
	 * @since  2.1.51
	 */
	public function strip_pingback_methods( $methods ) {
		$methods = is_array( $methods ) ? $methods : array();
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	/**
	 * Blank the advertised pingback URL.
	 *
	 * @param string|mixed $output Value about to be printed.
	 * @param string|mixed $show   Requested `bloginfo` key.
	 * @return string|mixed
	 * @since  2.1.51
	 */
	public function hide_pingback_url( $output, $show ) {
		return 'pingback_url' === $show ? '' : $output;
	}

	/**
	 * Refuse XML-RPC requests. Keyed on the `XMLRPC_REQUEST` constant, which
	 * WordPress defines in `xmlrpc.php` itself, so path tricks cannot dodge
	 * the check.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function intercept_xmlrpc() {
		if ( ! self::switch_on( self::OPT_XMLRPC_OFF ) ) {
			return;
		}
		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return;
		}

		self::log_denied( self::EVENT_XMLRPC, array( 'path' => ReportedIP_Hive_Request_Path::current() ) );
		ReportedIP_Hive_Hide_Login::render_response( ReportedIP_Hive_Hide_Login::response_mode() );
	}

	/**
	 * Answer feed requests with a 404. Feed readers stop polling on a 404;
	 * a 403 block page would just look like a malformed feed.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function intercept_feeds() {
		if ( ! self::switch_on( self::OPT_FEEDS_OFF ) || ! is_feed() ) {
			return;
		}

		self::log_denied( self::EVENT_FEED, array( 'path' => ReportedIP_Hive_Request_Path::current() ) );
		ReportedIP_Hive_Hide_Login::render_response( ReportedIP_Hive_Hide_Login::RESPONSE_MODE_404 );
	}

	/**
	 * Gate REST requests at authentication time, before `rest_pre_dispatch`,
	 * so neither the burst monitor nor the user-enumeration probe sensor sees
	 * a request that is refused here.
	 *
	 * @param WP_Error|bool|null|mixed $result Authentication verdict so far.
	 * @return WP_Error|bool|null|mixed
	 * @since  2.1.51
	 */
	public function filter_rest_authentication( $result ) {
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$mode = self::rest_mode();
		if ( self::REST_MODE_OPEN === $mode ) {
			return $result;
		}

		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || wp_doing_cron() ) {
			return $result;
		}

		$route = self::current_rest_route();
		$user  = wp_get_current_user();
		$roles = ( $user instanceof WP_User ) ? array_map( 'strval', (array) $user->roles ) : array();

		$decision = self::rest_decision(
			$mode,
			$route,
			is_user_logged_in(),
			$roles,
			current_user_can( 'manage_options' ) || is_super_admin(),
			self::allowed_namespaces(),
			self::allowed_roles()
		);

		if ( 'allow' === $decision ) {
			return $result;
		}

		if ( 'deny_guest' === $decision ) {
			self::log_denied(
				self::EVENT_REST,
				array(
					'route'  => $route,
					'reason' => 'anonymous',
				)
			);
			return new WP_Error(
				'rest_disabled_for_guests',
				__( 'The REST API is only available to authenticated users on this site.', 'reportedip-hive' ),
				array( 'status' => 401 )
			);
		}

		self::log_denied(
			self::EVENT_REST,
			array(
				'route'  => $route,
				'reason' => 'role',
				'roles'  => implode( ',', $roles ),
			)
		);
		return new WP_Error(
			'rest_disabled_for_role',
			__( 'Your account role is not allowed to use the REST API on this site.', 'reportedip-hive' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Pure access decision. No WordPress calls, so the whole table is unit
	 * testable.
	 *
	 * @param string   $mode          One of the REST_MODE_* constants.
	 * @param string   $route         Requested route with a leading slash.
	 * @param bool     $logged_in     Whether WordPress authenticated a user.
	 * @param string[] $roles         Roles of the authenticated user.
	 * @param bool     $is_admin      Whether the user may manage options or is a super admin.
	 * @param string[] $allowed_ns    Allowlisted namespaces/route prefixes.
	 * @param string[] $allowed_roles Roles allowed in `restricted` mode.
	 * @return string `allow` | `deny_guest` | `deny_role`
	 * @since  2.1.51
	 */
	public static function rest_decision( $mode, $route, $logged_in, array $roles, $is_admin, array $allowed_ns, array $allowed_roles ) {
		foreach ( $allowed_ns as $prefix ) {
			if ( self::route_matches( $route, (string) $prefix ) ) {
				return 'allow';
			}
		}

		if ( ! $logged_in ) {
			return 'deny_guest';
		}

		if ( self::REST_MODE_RESTRICTED !== $mode ) {
			return 'allow';
		}

		if ( $is_admin ) {
			return 'allow';
		}

		if ( preg_match( self::APP_PASSWORD_ROUTE_PATTERN, $route ) ) {
			return 'allow';
		}

		return array_intersect( $roles, $allowed_roles ) ? 'allow' : 'deny_role';
	}

	/**
	 * Whether a route belongs to a namespace/route prefix. Segment-aware, so
	 * `wc/store` never matches `/wc/storefront`.
	 *
	 * @param string $route  Route with a leading slash.
	 * @param string $prefix Namespace or route prefix without slashes.
	 * @return bool
	 * @since  2.1.51
	 */
	public static function route_matches( $route, $prefix ) {
		$prefix = trim( (string) $prefix, "/ \t\n\r\0\x0B" );
		if ( '' === $prefix ) {
			return false;
		}
		return '/' . $prefix === $route || str_starts_with( (string) $route, '/' . $prefix . '/' );
	}

	/**
	 * Allowlisted namespaces from the option, plus the ones that can never
	 * be gated.
	 *
	 * The fallback is the seeded list, not an empty string: `seed_missing()`
	 * runs on activation and on `admin_init`, so a site that switched the
	 * mode on remotely without ever loading wp-admin has no option row yet,
	 * and an empty fallback would silently refuse oEmbed, WooCommerce Store
	 * and every other namespace the seed opens.
	 *
	 * @return string[]
	 * @since  2.1.51
	 */
	public static function allowed_namespaces() {
		$raw   = (string) ReportedIP_Hive_Option_Routing::get( self::OPT_REST_NAMESPACES, ReportedIP_Hive_Defaults::all_option_defaults()[ self::OPT_REST_NAMESPACES ] );
		$lines = preg_split( '/[\r\n\s,]+/', $raw );
		$list  = array();

		foreach ( is_array( $lines ) ? $lines : array() as $line ) {
			$entry = trim( (string) $line, "/ \t\n\r\0\x0B" );
			if ( '' !== $entry ) {
				$list[] = $entry;
			}
		}

		return array_values( array_unique( array_merge( self::ALWAYS_ALLOWED_NAMESPACES, $list ) ) );
	}

	/**
	 * Roles allowed in `restricted` mode.
	 *
	 * @return string[]
	 * @since  2.1.51
	 */
	public static function allowed_roles() {
		$raw  = ReportedIP_Hive_Option_Routing::get( self::OPT_REST_ROLES, '["administrator"]' );
		$list = is_array( $raw ) ? $raw : json_decode( (string) $raw, true );

		if ( ! is_array( $list ) ) {
			return array( 'administrator' );
		}

		return array_values( array_filter( array_map( 'strval', $list ) ) );
	}

	/**
	 * The REST route of the current request.
	 *
	 * WordPress fills `rest_route` for both `/wp-json/...` and `?rest_route=`.
	 * ponytail: a plugin calling `WP_REST_Server::serve_request()` by hand
	 * without setting the query var lands on `/` and is treated as the index
	 * route, denied for guests, which is the safe direction.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	private static function current_rest_route() {
		$wp    = isset( $GLOBALS['wp'] ) ? $GLOBALS['wp'] : null;
		$route = ( $wp instanceof WP && isset( $wp->query_vars['rest_route'] ) )
			? (string) $wp->query_vars['rest_route']
			: '';

		return '/' . ltrim( $route, '/' );
	}

	/**
	 * Log a refused request. Denials are bookkeeping, not a threat verdict:
	 * severity `low`, no attempt counter, no escalation ladder and no
	 * community report, the operator switched the endpoint off, so a hit is
	 * expected traffic hitting a closed door.
	 *
	 * @param string              $event   One of the EVENT_* constants.
	 * @param array<string,mixed> $details Event details.
	 * @return void
	 * @since  2.1.51
	 */
	public static function log_denied( $event, array $details ) {
		if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
			return;
		}

		$ip = ReportedIP_Hive::get_client_ip();
		if ( '' === (string) $ip || 'unknown' === $ip ) {
			return;
		}

		if ( class_exists( 'ReportedIP_Hive_IP_Manager' ) ) {
			$ip_manager = ReportedIP_Hive_IP_Manager::get_instance();
			if ( method_exists( $ip_manager, 'is_whitelisted' ) && $ip_manager->is_whitelisted( $ip ) ) {
				return;
			}
		}

		$throttle_key = 'rip_as_' . $event . '_' . md5( (string) $ip );
		if ( get_transient( $throttle_key ) ) {
			return;
		}
		set_transient( $throttle_key, 1, self::LOG_THROTTLE_SECONDS );

		ReportedIP_Hive_Logger::get_instance()->log( $event, $ip, 'low', $details );
	}

	/**
	 * One sentence explaining that XML-RPC is off, reused by the notices on
	 * the Detection and Two-Factor settings tabs.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	public static function xmlrpc_off_notice() {
		return __( 'XML-RPC is switched off under Firewall → Hardening, so this setting has no effect right now.', 'reportedip-hive' );
	}
}
