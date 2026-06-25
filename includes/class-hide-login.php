<?php
/**
 * Hide Login — moves wp-login.php behind a custom slug and blocks the original URL.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Hide_Login
 *
 * Hooks at plugins_loaded so we run before pluggable.php and the WP routing.
 * The custom slug renders wp-login.php in place; direct hits on wp-login.php
 * are intercepted with a configurable response (Hive block page or soft 404).
 *
 * Bypassed for REST, cron, AJAX (logged-in), CLI, XMLRPC, password-protected
 * posts, password-reset links, interim re-auth, and when the wp-config kill
 * switch REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN is set.
 */
class ReportedIP_Hive_Hide_Login {

	public const RESPONSE_MODE_BLOCK_PAGE = 'block_page';
	public const RESPONSE_MODE_404        = '404';

	private const MIN_SLUG_LENGTH = 3;
	private const MAX_SLUG_LENGTH = 50;

	private const RECON_LOG_THROTTLE_SECONDS = 5;

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_Hide_Login|null
	 */
	private static $instance = null;

	/**
	 * Slugs we never let users pick — they collide with WP core or recognised
	 * platform paths and would either break the site or de-anonymise the install.
	 *
	 * @var string[]
	 */
	private const RESERVED_SLUGS = array(
		'wp-admin',
		'wp-login',
		'wp-content',
		'wp-includes',
		'wp-json',
		'wp-cron',
		'wp-config',
		'wp-signup',
		'wp-activate',
		'xmlrpc',
		'admin',
		'login',
		'dashboard',
		'wp',
		'feed',
		'comments',
		'trackback',
		'search',
		'page',
		'author',
		'category',
		'tag',
		'index',
		'test',
		'demo',
	);

	/**
	 * Cached request path (lower-case, leading-slash, no trailing slash).
	 *
	 * @var string|null
	 */
	private $request_path = null;

	/**
	 * True after we have intentionally served wp-login.php for the slug —
	 * blocks the login_init re-entry from triggering the block-page response.
	 *
	 * @var bool
	 */
	private $serving_login = false;

	/**
	 * Get singleton.
	 */
	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor — registers hooks. The class is instantiated during
	 * plugins_loaded:10, which is too early to load wp-login.php directly
	 * (AUTOSAVE_INTERVAL and other functionality constants are defined
	 * after plugins_loaded). Routing therefore runs on init:1 — late
	 * enough that all WP constants exist, early enough that the login
	 * form has not been rendered yet.
	 *
	 * login_init catches direct hits on wp-login.php (its own action), and
	 * admin_init catches /wp-admin requests so the auth-redirect leak is
	 * prevented.
	 */
	private function __construct() {
		add_action( 'init', array( $this, 'handle_request' ), 1 );
		add_action( 'login_init', array( $this, 'handle_request' ), 1 );
		add_action( 'wp_loaded', array( $this, 'remove_admin_locations_redirect' ) );
		add_action( 'admin_init', array( $this, 'block_wp_admin_for_logged_out' ), 1 );

		foreach ( array( 'site_url', 'network_site_url', 'admin_url', 'login_url', 'lostpassword_url', 'register_url', 'logout_url', 'wp_redirect' ) as $hook ) {
			add_filter( $hook, array( $this, 'filter_url' ), 100, 1 );
		}

		add_filter( 'rocket_cache_reject_uri', array( $this, 'exclude_login_from_cache_uri' ) );
	}

	/**
	 * Whether the feature is fully active (option enabled, slug set, no kill switch).
	 */
	public function is_active(): bool {
		if ( defined( 'REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN' ) && REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN ) {
			return false;
		}
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_enabled', false ) ) {
			return false;
		}
		$slug = $this->get_slug();
		return '' !== $slug;
	}

	/**
	 * Sanitised, lower-case slug from settings (or empty string).
	 */
	public function get_slug(): string {
		$slug = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_slug', '' );
		return strtolower( trim( $slug, "/ \t\n\r\0\x0B" ) );
	}

	/**
	 * Final, fully-qualified hidden login URL — used by settings UI / wizard summary.
	 */
	public function get_login_url(): string {
		$slug = $this->get_slug();
		if ( '' === $slug ) {
			return '';
		}
		return trailingslashit( home_url() ) . $slug;
	}

	/**
	 * Decide whether the current request should be left alone.
	 *
	 * Bypass conditions are intentionally permissive — false negatives here
	 * just mean the feature is silently inactive for that request, but a
	 * false positive (blocking a REST or cron request) breaks the site.
	 */
	private function should_bypass(): bool {
		if ( ! $this->is_active() ) {
			return true;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}
		if ( wp_doing_cron() ) {
			return true;
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return true;
		}

		$path = $this->get_request_path();

		if ( str_starts_with( $path, '/wp-json' ) ) {
			return true;
		}
		if ( '/wp-cron.php' === $path ) {
			return true;
		}
		if ( '/xmlrpc.php' === $path ) {
			return true;
		}
		if ( '/wp-admin/admin-ajax.php' === $path && is_user_logged_in() ) {
			return true;
		}
		if ( '/wp-admin/admin-post.php' === $path && is_user_logged_in() ) {
			return true;
		}

		if ( class_exists( 'ReportedIP_Hive_Two_Factor_Frontend' ) ) {
			$rip_2fa_slugs = array(
				ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug(),
				ReportedIP_Hive_Two_Factor_Frontend::get_setup_slug(),
			);
			foreach ( $rip_2fa_slugs as $rip_slug ) {
				if ( '' === (string) $rip_slug ) {
					continue;
				}
				if ( '/' . $rip_slug === $path || str_starts_with( $path, '/' . $rip_slug . '/' ) ) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Lower-cased, query-stripped request path with leading slash, no trailing slash.
	 */
	private function get_request_path(): string {
		if ( null !== $this->request_path ) {
			return $this->request_path;
		}

		$raw = isset( $_SERVER['REQUEST_URI'] )
			? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_URI'] ) )
			: '';

		$path = (string) wp_parse_url( $raw, PHP_URL_PATH );

		$home = (string) wp_parse_url( home_url(), PHP_URL_PATH );
		if ( '' !== $home && '/' !== $home && str_starts_with( $path, $home ) ) {
			$path = substr( $path, strlen( $home ) );
		}
		if ( '' === $path || '/' !== $path[0] ) {
			$path = '/' . $path;
		}
		$path = rtrim( $path, '/' );
		if ( '' === $path ) {
			$path = '/';
		}

		$this->request_path = strtolower( $path );
		return $this->request_path;
	}

	/**
	 * The "is this a wp-login page request" check used by several action hooks
	 * that fire only on the actual /wp-login.php endpoint after WP routes the
	 * request — kept separate from get_request_path() to handle pretty-permalink
	 * edge cases (rewrite rules pointing /wp-login -> wp-login.php).
	 */
	private function is_wp_login_request(): bool {
		$path = $this->get_request_path();
		return '/wp-login.php' === $path || '/wp-login' === $path;
	}

	/**
	 * Whitelist of wp-login.php actions that must always go through, even when
	 * the feature is active — otherwise password-resets, logouts and the
	 * post-password form break.
	 *
	 * @return string[]
	 */
	private function bypass_actions(): array {
		return array(
			'postpass',
			'logout',
			'rp',
			'resetpass',
			'confirm_admin_email',
			'confirmaction',
			'jetpack-sso',
			'jetpack_json_api_authorization',
		);
	}

	/**
	 * Main entry point — runs once on plugins_loaded.
	 */
	public function handle_request(): void {
		if ( $this->serving_login ) {
			return;
		}
		if ( $this->should_bypass() ) {
			return;
		}

		$path = $this->get_request_path();
		$slug = $this->get_slug();

		if ( '/' . $slug === $path ) {
			$this->serve_wp_login();
			return;
		}

		if ( $this->is_wp_login_request() ) {
			if ( $this->is_action_whitelisted() ) {
				return;
			}
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only check; the value is never trusted, just used to skip our block on the WP "interim-login" iframe flow.
			if ( isset( $_GET['interim-login'] ) ) {
				return;
			}
			$this->log_recon_attempt();
			$this->render_block_response();
			return;
		}

		if ( $this->is_wp_admin_request( $path ) && ! is_user_logged_in() ) {
			$this->log_recon_attempt();
			$this->render_block_response();
		}
	}

	/**
	 * Detect a wp-admin request that we should intercept before WP's own
	 * auth_redirect kicks in. Excludes admin-ajax/admin-post (already
	 * handled by the bypass matrix for logged-in users).
	 */
	private function is_wp_admin_request( string $path ): bool {
		if ( '/wp-admin/admin-ajax.php' === $path || '/wp-admin/admin-post.php' === $path ) {
			return false;
		}
		return '/wp-admin' === $path || str_starts_with( $path, '/wp-admin/' );
	}

	/**
	 * Whether the current request carries a wp-login action we always allow.
	 */
	private function is_action_whitelisted(): bool {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only allow-listing; the action value is sanitised and only compared to a hardcoded bypass list.
		$action = isset( $_REQUEST['action'] )
			? sanitize_key( wp_unslash( (string) $_REQUEST['action'] ) )
			: '';
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
		if ( '' === $action ) {
			return false;
		}
		return in_array( $action, $this->bypass_actions(), true );
	}

	/**
	 * Render the configured response when wp-login.php is hit directly.
	 *
	 * Default mode: Hive block page (403, same look as IP-blocked page).
	 * Optional 404 mode: theme's 404 template — gives no plugin fingerprint.
	 */
	private function render_block_response(): void {
		$mode = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_response_mode', self::RESPONSE_MODE_BLOCK_PAGE );

		if ( self::RESPONSE_MODE_404 === $mode ) {
			global $wp_query;
			if ( $wp_query instanceof WP_Query ) {
				$wp_query->set_404();
			}
			status_header( 404 );
			nocache_headers();
			$template = get_404_template();
			if ( $template && file_exists( $template ) ) {
				include $template;
				exit;
			}
			wp_die( esc_html__( 'Not found.', 'reportedip-hive' ), '', array( 'response' => 404 ) );
		}

		status_header( 403 );
		nocache_headers();
		$reportedip_hive_block_context = 'hide_login';
		include REPORTEDIP_HIVE_PLUGIN_DIR . 'templates/blocked.php';
		exit;
	}

	/**
	 * Load wp-login.php in place — the custom slug behaves like the original
	 * URL, query-string and POST data flow through unchanged. We rewrite
	 * REQUEST_URI so wp-login's own self-referencing form actions stay valid.
	 *
	 * wp-login.php's "case 'login'" block initialises some variables only
	 * conditionally (e.g. `$user_login` is only set when `$_POST['log']`
	 * exists, even though the form template always reads it). When the file
	 * is included from a method scope under WP_DEBUG, those reads emit
	 * "Undefined variable" warnings into the rendered HTML. Pre-declaring
	 * them here lifts that risk.
	 */
	private function serve_wp_login(): void {
		$this->serving_login = true;
		$this->request_path  = '/wp-login.php';

		$this->emit_login_no_cache_headers();

		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- QUERY_STRING is forwarded verbatim into REQUEST_URI so wp-login.php sees the original request; sanitize_text_field() above strips control chars, no SQL/HTML context here.
		$query = isset( $_SERVER['QUERY_STRING'] ) && '' !== (string) $_SERVER['QUERY_STRING']
			? '?' . sanitize_text_field( wp_unslash( (string) $_SERVER['QUERY_STRING'] ) )
			: '';
		// phpcs:enable WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$_SERVER['REQUEST_URI'] = '/wp-login.php' . $query;
		$_SERVER['SCRIPT_NAME'] = '/wp-login.php';
		$_SERVER['PHP_SELF']    = '/wp-login.php';

		// phpcs:disable VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable, WordPress.Security.NonceVerification.Recommended -- Pre-declared so wp-login.php (loaded via require) sees defined variables under WP_DEBUG; the interim-login flag is consumed by core.
		$user_login    = '';
		$error         = '';
		$interim_login = isset( $_REQUEST['interim-login'] );
		// phpcs:enable

		require_once ABSPATH . 'wp-login.php';
		exit;
	}

	/**
	 * Stop every known page-cache layer from storing the hidden login page.
	 *
	 * A cached login page is served as static HTML without PHP running, so
	 * wp-login.php never gets to set the `wordpress_test_cookie`. The next
	 * POST then fails the cookie handshake with "Cookies are blocked…" and
	 * the user can never sign in — the login simply appears to do nothing.
	 * Because the slug is an ordinary URL (not `/wp-login.php`), cache plugins
	 * do not exclude it automatically, so we have to opt out explicitly.
	 *
	 * The DONOTCACHE* constants and no-store headers are honoured by WP Rocket,
	 * W3 Total Cache, WP Super Cache, WP Fastest Cache, Comet Cache, Cache
	 * Enabler and Hummingbird; the LiteSpeed header plus its control action
	 * cover LiteSpeed Cache. The matching URL-level WP Rocket exclusion lives
	 * in {@see self::exclude_login_from_cache_uri()}.
	 */
	private function emit_login_no_cache_headers(): void {
		if ( class_exists( 'ReportedIP_Hive' ) ) {
			ReportedIP_Hive::emit_block_response_headers();
		}

		if ( ! headers_sent() ) {
			header( 'Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0' );
			header( 'Vary: Cookie' );
			header( 'X-LiteSpeed-Cache-Control: no-cache' );
		}

		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- LiteSpeed Cache's own documented control hook; the name is fixed by that plugin and cannot be prefixed.
		do_action( 'litespeed_control_set_nocache', 'reportedip-hive hidden login page' );
	}

	/**
	 * Add the hidden login slug to WP Rocket's never-cache URI list.
	 *
	 * WP Rocket can serve a previously cached copy from `advanced-cache.php`
	 * before our `serve_wp_login()` ever runs, so the constant-based opt-out
	 * is not enough on its own — the URL has to be rejected at WP Rocket's own
	 * cache layer. The pattern is anchored to the slug with an optional
	 * trailing slash and query string.
	 *
	 * @param string[]|mixed $uris Existing rejected URIs.
	 * @return string[]            URIs with the login slug appended.
	 */
	public function exclude_login_from_cache_uri( $uris ): array {
		$uris = is_array( $uris ) ? $uris : array();

		if ( ! $this->is_active() ) {
			return $uris;
		}

		$slug = $this->get_slug();
		if ( '' === $slug ) {
			return $uris;
		}

		$uris[] = '/' . $slug . '(/.*)?';

		return $uris;
	}

	/**
	 * Block /wp-admin for unauthenticated requests so they never see the
	 * "you must log in" redirect (which would leak the real wp-login URL).
	 */
	public function block_wp_admin_for_logged_out(): void {
		if ( $this->should_bypass() ) {
			return;
		}
		if ( wp_doing_ajax() ) {
			return;
		}
		if ( is_user_logged_in() ) {
			return;
		}
		$this->log_recon_attempt();
		$this->render_block_response();
	}

	/**
	 * WordPress core has a polite redirect that sends visitors of "/login"
	 * or "/dashboard" to wp-admin — defeats the whole feature. Drop it.
	 */
	public function remove_admin_locations_redirect(): void {
		if ( ! $this->is_active() ) {
			return;
		}
		remove_action( 'template_redirect', 'wp_redirect_admin_locations', 1000 );
	}

	/**
	 * Replace wp-login.php in any URL with the hidden slug. Registered for
	 * site_url, network_site_url, admin_url, login_url, lostpassword_url,
	 * register_url, logout_url and wp_redirect.
	 *
	 * The strpos guard runs before is_active() so that requests on disabled
	 * installs short-circuit without an option lookup, and so do all the
	 * URL filter calls that don't reference wp-login.php in the first place.
	 */
	public function filter_url( string $url ): string {
		if ( false === strpos( $url, 'wp-login.php' ) ) {
			return $url;
		}
		if ( ! $this->is_active() ) {
			return $url;
		}

		$slug = $this->get_slug();
		$new  = str_replace( 'wp-login.php', $slug, $url );
		$new  = $this->apply_login_trailing_slash( $new, $slug );

		return $this->maybe_add_token( $new, $slug );
	}

	/**
	 * Normalise the rewritten login URL's trailing slash to the site's
	 * permalink convention.
	 *
	 * `str_replace()` inherits wp-login.php's slash-less form, so the login
	 * form action comes out as `…/<slug>` with no trailing slash. On a site
	 * whose permalinks use trailing slashes — and whose web server enforces
	 * them — a POST to `/<slug>` is answered with a 301 redirect to `/<slug>/`,
	 * which the browser replays as a GET, silently dropping the POST body. The
	 * sign-in then appears to do nothing. Routing the URL through
	 * user_trailingslashit() makes the form post straight to `/<slug>/`, so no
	 * redirect happens.
	 *
	 * Only the bare slug path is adjusted; the query string and fragment are
	 * preserved, and installs that do not use trailing-slash permalinks are
	 * left untouched.
	 *
	 * @param string $url  Rewritten login URL.
	 * @param string $slug Hidden login slug.
	 * @return string
	 */
	private function apply_login_trailing_slash( string $url, string $slug ): string {
		if ( '' === $slug || ! function_exists( 'user_trailingslashit' ) ) {
			return $url;
		}

		$fragment = '';
		$hash_pos = strpos( $url, '#' );
		if ( false !== $hash_pos ) {
			$fragment = substr( $url, $hash_pos );
			$url      = substr( $url, 0, $hash_pos );
		}

		$query = '';
		$q_pos = strpos( $url, '?' );
		if ( false !== $q_pos ) {
			$query = substr( $url, $q_pos );
			$url   = substr( $url, 0, $q_pos );
		}

		if ( preg_match( '#/' . preg_quote( $slug, '#' ) . '/?$#', $url ) ) {
			$url = user_trailingslashit( untrailingslashit( $url ) );
		}

		return $url . $query . $fragment;
	}

	/**
	 * Append `?<slug>` token to URLs we generate, if enabled. Skipped when the
	 * URL already carries the token or has its own query string we shouldn't
	 * disturb (login_url generates with redirect_to=… which is fine to keep).
	 */
	private function maybe_add_token( string $url, string $slug ): string {
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_token_in_urls', true ) ) {
			return $url;
		}
		if ( '' === $slug ) {
			return $url;
		}
		$query = (string) wp_parse_url( $url, PHP_URL_QUERY );
		if ( '' !== $query && false !== strpos( $query, $slug . '=' ) ) {
			return $url;
		}
		if ( '' !== $query && false !== strpos( '&' . $query . '&', '&' . $slug . '&' ) ) {
			return $url;
		}
		return add_query_arg( $slug, '', $url );
	}

	/**
	 * Sanitise a posted slug. Returns empty string if the submission cannot
	 * be salvaged; surfaces a settings error explaining why.
	 *
	 * Called from the Settings API and the wizard AJAX validator.
	 */
	public function sanitize_slug( $value ): string {
		$current = $this->get_slug();
		$raw     = is_string( $value ) ? sanitize_title( wp_unslash( $value ) ) : '';

		if ( '' === $raw ) {
			return $current;
		}

		$inner_min = self::MIN_SLUG_LENGTH - 2;
		$inner_max = self::MAX_SLUG_LENGTH - 2;
		$pattern   = '/^[a-z0-9][a-z0-9_-]{' . $inner_min . ',' . $inner_max . '}[a-z0-9]$/';

		if ( ! preg_match( $pattern, $raw ) ) {
			add_settings_error(
				'reportedip_hive_hide_login_slug',
				'reportedip_hive_hide_login_slug_invalid',
				sprintf(
					/* translators: 1: minimum slug length, 2: maximum slug length */
					__( 'The login slug must be %1$d–%2$d characters of lowercase letters, digits, dashes or underscores, and may not start or end with a dash.', 'reportedip-hive' ),
					self::MIN_SLUG_LENGTH,
					self::MAX_SLUG_LENGTH
				)
			);
			return $current;
		}

		if ( in_array( $raw, self::RESERVED_SLUGS, true ) ) {
			add_settings_error(
				'reportedip_hive_hide_login_slug',
				'reportedip_hive_hide_login_slug_reserved',
				/* translators: %s: rejected slug */
				sprintf( __( 'The slug "%s" is reserved by WordPress and cannot be used.', 'reportedip-hive' ), esc_html( $raw ) )
			);
			return $current;
		}

		$collision = $this->detect_permalink_collision( $raw );
		if ( '' !== $collision ) {
			add_settings_error(
				'reportedip_hive_hide_login_slug',
				'reportedip_hive_hide_login_slug_collision',
				/* translators: 1: rejected slug, 2: where it already exists */
				sprintf( __( 'The slug "%1$s" already exists as %2$s. Pick a different slug.', 'reportedip-hive' ), esc_html( $raw ), esc_html( $collision ) )
			);
			return $current;
		}

		return $raw;
	}

	/**
	 * Detect a permalink collision; returns a human-readable label of the
	 * conflicting object or empty string if no collision.
	 */
	public function detect_permalink_collision( string $slug ): string {
		if ( '' === $slug ) {
			return '';
		}

		$page = get_page_by_path( $slug, OBJECT, 'page' );
		if ( $page instanceof WP_Post ) {
			return __( 'a published page', 'reportedip-hive' );
		}

		$post = get_page_by_path( $slug, OBJECT, 'post' );
		if ( $post instanceof WP_Post ) {
			return __( 'a published post', 'reportedip-hive' );
		}

		$user = get_user_by( 'slug', $slug );
		if ( $user instanceof WP_User ) {
			return __( 'a user/author archive', 'reportedip-hive' );
		}

		foreach ( get_taxonomies( array( 'public' => true ), 'names' ) as $taxonomy ) {
			$term = get_term_by( 'slug', $slug, $taxonomy );
			if ( $term instanceof WP_Term ) {
				/* translators: %s: taxonomy name */
				return sprintf( __( 'a %s archive', 'reportedip-hive' ), $taxonomy );
			}
		}

		return '';
	}

	/**
	 * Sanitise the response-mode option (enum allowlist).
	 */
	public function sanitize_response_mode( $value ): string {
		$value = is_string( $value ) ? sanitize_key( $value ) : '';
		$valid = array( self::RESPONSE_MODE_BLOCK_PAGE, self::RESPONSE_MODE_404 );
		return in_array( $value, $valid, true ) ? $value : self::RESPONSE_MODE_BLOCK_PAGE;
	}

	/**
	 * Suggest a default slug a user can copy when they enable the feature for
	 * the first time without a value yet.
	 */
	public static function suggest_default_slug(): string {
		return 'wp-secure-' . strtolower( wp_generate_password( 6, false, false ) );
	}

	/**
	 * Whether the hidden-login probe sensor is armed. The sensor runs only on
	 * the direct-hit path (Hide-Login already active) and behind its own
	 * monitor toggle, so operators can keep the passive recon log without the
	 * escalating IP block.
	 */
	private function probe_sensor_enabled(): bool {
		return (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_hide_login_probe', true );
	}

	/**
	 * Number of direct hits within the timeframe that promote a prober from
	 * "logged" to "blocked". Floored at 1 so a misconfigured 0 cannot silently
	 * disable the block.
	 */
	private function get_probe_threshold(): int {
		return max( 1, (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_probe_threshold', 5 ) );
	}

	/**
	 * Rolling window in minutes the probe count is measured over.
	 */
	private function get_probe_timeframe(): int {
		return max( 1, (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_hide_login_probe_timeframe', 10 ) );
	}

	/**
	 * Feed a direct hit on the hidden login URL into the shared attempt counter.
	 *
	 * Delegates to the Security-Monitor so the probe reuses the exact escalation
	 * ladder and community-report path the other sensors use: nothing happens
	 * below the threshold; a confirmed scanner pattern is blocked and reported.
	 *
	 * @param string $ip Client IP — already non-empty and non-whitelisted.
	 */
	private function maybe_track_probe( string $ip ): void {
		if ( ! $this->probe_sensor_enabled() ) {
			return;
		}
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
			return;
		}
		$monitor = ReportedIP_Hive::get_instance()->get_security_monitor();
		if ( ! ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) ) {
			return;
		}
		$monitor->track_generic_attempt(
			$ip,
			'hide_login_probe',
			'hide_login_probe',
			$this->get_probe_threshold(),
			$this->get_probe_timeframe(),
			array( 'path' => $this->get_request_path() )
		);
	}

	/**
	 * Light recon log + threshold sensor on a direct hit of the hidden login URL.
	 *
	 * The low-severity `hide_login_block` log is throttled per IP so a hammering
	 * scanner cannot flood the log. The threshold sensor (maybe_track_probe) runs
	 * BEFORE that throttle so every hit is counted toward the escalation ladder.
	 * Whitelisted IPs are skipped entirely so legitimate admin testing is never
	 * blocked or logged.
	 */
	private function log_recon_attempt(): void {
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

		$this->maybe_track_probe( $ip );

		if ( ! class_exists( 'ReportedIP_Hive_Logger' ) ) {
			return;
		}

		$throttle_key = 'rip_hl_recon_' . md5( $ip );
		if ( get_transient( $throttle_key ) ) {
			return;
		}
		set_transient( $throttle_key, 1, self::RECON_LOG_THROTTLE_SECONDS );

		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->log(
			'hide_login_block',
			$ip,
			'low',
			array(
				'path' => $this->get_request_path(),
			)
		);
	}
}
