<?php
/**
 * Frontend renderer for the WooCommerce-aware 2FA challenge.
 *
 * This class owns the public, themed surface of two-factor authentication.
 * Whereas {@see ReportedIP_Hive_Two_Factor} handles the wp-login.php-bound
 * interstitial used for backend logins, this module hijacks two dedicated
 * front-end slugs (`reportedip-hive-2fa` and `reportedip-hive-2fa-setup`)
 * and renders the challenge / onboarding inside the active theme via
 * `get_header()` / `get_footer()` so customers never get bounced out of
 * the My-Account / Checkout context.
 *
 * The whole module is gated by the `frontend_2fa` feature flag in
 * {@see ReportedIP_Hive_Mode_Manager} (PRO+ tier required). When the gate
 * is closed the rewrites are still registered so a downgrade does not
 * 404 stale links, but {@see self::route_request()} simply yields and
 * lets WordPress fall through to its standard 404, while the legacy
 * wp-login.php challenge keeps working for everyone.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.7.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Routes, gating, cache-headers and conflict-detection for the frontend
 * 2FA module. The public surface is fully static, there is no
 * per-request state, only WordPress hooks and one tier-gate memo.
 *
 * @since 1.7.0
 */
class ReportedIP_Hive_Two_Factor_Frontend {

	/**
	 * Query var that the rewrite layer tags onto matching requests.
	 */
	const QUERY_VAR = 'reportedip_hive_2fa_frontend';

	/**
	 * Challenge context of the themed slug, see
	 * {@see ReportedIP_Hive_Two_Factor::handle_2fa_challenge()}. Also the
	 * context of `reportedip_hive_2fa_verified` for a storefront sign-in.
	 */
	const CONTEXT = 'theme_frame';

	/**
	 * Site-option master toggle for the frontend module.
	 */
	const OPT_ENABLED = 'reportedip_hive_2fa_frontend_enabled';

	/**
	 * Unix-timestamp written when a tier-downgrade soft-disabled the module.
	 * Zero means the module is in normal operation.
	 */
	const OPT_SOFT_DISABLED = 'reportedip_hive_2fa_frontend_soft_disabled';

	/**
	 * Default slugs, if you change these in code, also update the
	 * corresponding entries in {@see ReportedIP_Hive_Defaults}.
	 */
	const DEFAULT_CHALLENGE_SLUG = 'reportedip-hive-2fa';
	const DEFAULT_SETUP_SLUG     = 'reportedip-hive-2fa-setup';

	/**
	 * Slugs that would either collide with WordPress core paths, leak
	 * the host platform or break the rewrite layer outright. Reused
	 * by the settings-validation path so admins cannot save them.
	 *
	 * @var string[]
	 */
	const RESERVED_SLUGS = array(
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
		'cart',
		'checkout',
		'shop',
		'my-account',
		'product',
	);

	/**
	 * Per-request memo for {@see self::is_available()}. Reset on
	 * `reportedip_hive_tier_changed`.
	 *
	 * @var bool|null
	 */
	private static $available_memo = null;

	/**
	 * Per-request memo for the resolved slugs. Read on every Hide-Login
	 * bypass check, so caching them once spares two `get_option()` round-
	 * trips per request on the frontend hot path.
	 *
	 * @var array{challenge:string,setup:string}|null
	 */
	private static $slug_memo = null;

	/**
	 * Wire the WordPress hooks. Idempotent, calling twice is safe.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'register_routes' ), 5 );
		add_filter( 'query_vars', array( __CLASS__, 'register_query_var' ) );
		add_action( 'template_redirect', array( __CLASS__, 'route_request' ), 5 );
		add_action( 'reportedip_hive_tier_changed', array( __CLASS__, 'on_tier_changed' ), 30, 2 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'maybe_enqueue_blocks_redirect' ) );
		add_filter( 'pre_get_document_title', array( __CLASS__, 'filter_document_title' ) );
		add_filter( 'wp_robots', array( __CLASS__, 'filter_robots' ) );
		add_filter( 'reportedip_hive_2fa_challenge_payload', array( __CLASS__, 'challenge_payload' ) );
		add_filter( 'reportedip_hive_2fa_challenge_url', array( __CLASS__, 'filter_challenge_url' ), 10, 2 );
		add_filter( 'reportedip_hive_2fa_redirect_url', array( __CLASS__, 'filter_redirect_url' ), 10, 4 );
		add_action( 'reportedip_hive_2fa_render_challenge_' . self::CONTEXT, array( __CLASS__, 'render_challenge_view' ), 10, 2 );
		add_action( 'reportedip_hive_2fa_render_expired_' . self::CONTEXT, array( __CLASS__, 'render_expired_view' ), 10, 2 );
		add_filter( 'reportedip_hive_2fa_onboarding_url', array( __CLASS__, 'filter_onboarding_url' ), 10, 2 );
		add_filter( 'reportedip_hive_2fa_post_skip_url', array( __CLASS__, 'filter_post_skip_url' ), 10, 2 );
		add_filter( 'reportedip_2fa_skip_onboarding_redirect', array( __CLASS__, 'skip_onboarding_redirect' ), 10, 2 );
		add_filter( 'reportedip_hive_hide_login_bypass_paths', array( __CLASS__, 'bypass_paths' ) );
		add_action( 'reportedip_hive_settings_effect_flush_2fa_frontend_memo', array( __CLASS__, 'flush_memo' ) );
	}

	/**
	 * Override the document title on our themed slugs so the storefront
	 * tab/window shows "Verification required" / "Set up Two-Factor"
	 * instead of the generic theme default. Yields when the request is
	 * not on one of our slugs.
	 *
	 * @param string $title Theme-provided title.
	 * @return string
	 */
	public static function filter_document_title( $title ) {
		$mode = get_query_var( self::QUERY_VAR );
		if ( 'challenge' === $mode ) {
			return __( 'Verification required', 'reportedip-hive' );
		}
		if ( 'setup' === $mode ) {
			return __( 'Set up Two-Factor', 'reportedip-hive' );
		}
		return $title;
	}

	/**
	 * Mark our themed slugs as `noindex,nofollow,noarchive` so search
	 * engines never crawl the challenge/setup pages.
	 *
	 * @param array<string,bool|string> $rules
	 * @return array<string,bool|string>
	 */
	public static function filter_robots( $rules ) {
		$mode = get_query_var( self::QUERY_VAR );
		if ( 'challenge' === $mode || 'setup' === $mode ) {
			$rules['noindex']   = true;
			$rules['nofollow']  = true;
			$rules['noarchive'] = true;
		}
		return $rules;
	}

	/**
	 * Enqueue the small Block-Checkout error listener that converts a
	 * `reportedip_2fa_required` REST error into a `window.location`
	 * redirect to the themed challenge slug. Loaded only on pages that
	 * actually carry a Cart or Checkout block to keep the regular
	 * storefront free of unused JS.
	 *
	 * @return void
	 */
	public static function maybe_enqueue_blocks_redirect() {
		if ( ! self::is_available() ) {
			return;
		}
		if ( ! is_singular() ) {
			return;
		}
		if ( ! function_exists( 'has_block' ) ) {
			return;
		}
		if ( ! has_block( 'woocommerce/checkout' ) && ! has_block( 'woocommerce/cart' ) ) {
			return;
		}
		wp_enqueue_script(
			'reportedip-hive-wc-blocks-2fa-redirect',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/wc-blocks-2fa-redirect.js',
			array( 'wp-hooks' ),
			REPORTEDIP_HIVE_VERSION,
			true
		);
	}

	/**
	 * Whether the frontend module should serve traffic right now.
	 *
	 * Three gates have to be open:
	 *  - the master toggle option,
	 *  - the {@see ReportedIP_Hive_Mode_Manager} feature flag (PRO+ tier),
	 *  - the soft-disable marker that downgrades flip on (a downgrade
	 *    parks the module without deleting customer 2FA secrets).
	 *
	 * @return bool
	 */
	public static function is_available() {
		if ( null !== self::$available_memo ) {
			return self::$available_memo;
		}

		if ( ! ReportedIP_Hive_Option_Routing::get( self::OPT_ENABLED, false ) ) {
			self::$available_memo = false;
			return false;
		}

		if ( (int) ReportedIP_Hive_Option_Routing::get( self::OPT_SOFT_DISABLED, 0 ) > 0 ) {
			self::$available_memo = false;
			return false;
		}

		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			self::$available_memo = false;
			return false;
		}

		$status               = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'frontend_2fa' );
		self::$available_memo = ! empty( $status['available'] );
		return self::$available_memo;
	}

	/**
	 * Reset the per-request memo. Called by the test suite and by
	 * {@see self::on_tier_changed()}.
	 *
	 * @return void
	 */
	public static function flush_memo() {
		self::$available_memo = null;
		self::$slug_memo      = null;
	}

	/**
	 * Resolve the current configured challenge slug, falling back to
	 * the default when the option is empty or invalid.
	 *
	 * @return string
	 */
	public static function get_challenge_slug() {
		return self::resolve_slugs()['challenge'];
	}

	/**
	 * Resolve the current configured setup / onboarding slug.
	 *
	 * @return string
	 */
	public static function get_setup_slug() {
		return self::resolve_slugs()['setup'];
	}

	/**
	 * Resolve and memoise both slugs in one go. Hide-Login bypass and
	 * URL helpers hit this on every frontend request, so the round-trip
	 * to `get_option()` × 2 plus two `sanitize_slug()` calls is folded
	 * into a single per-request lookup.
	 *
	 * @return array{challenge:string,setup:string}
	 */
	private static function resolve_slugs() {
		if ( null !== self::$slug_memo ) {
			return self::$slug_memo;
		}
		self::$slug_memo = array(
			'challenge' => self::sanitize_slug( ReportedIP_Hive_Option_Routing::resolve_2fa_frontend_slug(), self::DEFAULT_CHALLENGE_SLUG ),
			'setup'     => self::sanitize_slug( ReportedIP_Hive_Option_Routing::resolve_2fa_frontend_setup_slug(), self::DEFAULT_SETUP_SLUG ),
		);
		return self::$slug_memo;
	}

	/**
	 * Drop the per-request slug memo. Called from the Site-2FA save
	 * handler so a freshly saved override is reflected immediately on
	 * the same request.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public static function flush_slug_memo() {
		self::$slug_memo = null;
	}

	/**
	 * Public absolute URL of the themed challenge page.
	 *
	 * @return string
	 */
	public static function challenge_url() {
		return home_url( '/' . self::get_challenge_slug() . '/' );
	}

	/**
	 * Public absolute URL of the themed setup / onboarding page.
	 *
	 * @return string
	 */
	public static function setup_url() {
		return home_url( '/' . self::get_setup_slug() . '/' );
	}

	/**
	 * Validate a candidate slug against the reserved list and the
	 * shape rules (3-50 chars, lowercase ascii + dash). Returns the
	 * cleaned value or the supplied fallback.
	 *
	 * @param mixed  $candidate Raw user input.
	 * @param string $fallback  Returned when the candidate is invalid.
	 * @return string
	 */
	/**
	 * Registry sanitizer for the challenge slug.
	 *
	 * The registry hands its sanitizers one argument, so the two slugs get a
	 * thin wrapper each rather than a second copy of the slug rules.
	 *
	 * @param mixed $value Raw input.
	 * @return string
	 * @since  2.1.51
	 */
	public static function sanitize_challenge_slug( $value ) {
		return self::sanitize_slug( $value, self::DEFAULT_CHALLENGE_SLUG );
	}

	/**
	 * Registry sanitizer for the setup slug.
	 *
	 * @param mixed $value Raw input.
	 * @return string
	 * @since  2.1.51
	 */
	public static function sanitize_setup_slug( $value ) {
		return self::sanitize_slug( $value, self::DEFAULT_SETUP_SLUG );
	}

	public static function sanitize_slug( $candidate, $fallback ) {
		$candidate = is_string( $candidate ) ? strtolower( trim( $candidate, "/ \t\n\r\0\x0B" ) ) : '';
		$candidate = preg_replace( '/[^a-z0-9-]/', '', $candidate );
		if ( '' === (string) $candidate ) {
			return $fallback;
		}
		if ( strlen( $candidate ) < 3 || strlen( $candidate ) > 50 ) {
			return $fallback;
		}
		if ( in_array( $candidate, self::RESERVED_SLUGS, true ) ) {
			return $fallback;
		}
		return $candidate;
	}

	/**
	 * Register the rewrite rules that point both slugs at this
	 * module's query var. Idempotent, `add_rewrite_rule()` is a
	 * no-op when the rule already exists in the rules array.
	 *
	 * @return void
	 */
	public static function register_routes() {
		$challenge = self::get_challenge_slug();
		$setup     = self::get_setup_slug();

		add_rewrite_tag( '%' . self::QUERY_VAR . '%', '([^/]+)' );

		add_rewrite_rule(
			'^' . preg_quote( $challenge, '/' ) . '/?$',
			'index.php?' . self::QUERY_VAR . '=challenge',
			'top'
		);
		add_rewrite_rule(
			'^' . preg_quote( $setup, '/' ) . '/?$',
			'index.php?' . self::QUERY_VAR . '=setup',
			'top'
		);
	}

	/**
	 * Whitelist the query var so WordPress preserves it through the
	 * parse-request stage.
	 *
	 * @param string[] $vars
	 * @return string[]
	 */
	public static function register_query_var( $vars ) {
		$vars[] = self::QUERY_VAR;
		return $vars;
	}

	/**
	 * `template_redirect` callback. Inspects the resolved query var,
	 * gates on the tier feature flag, then dispatches to the matching
	 * renderer. Yields silently when the request is unrelated, so
	 * other plugins keep working as expected.
	 *
	 * @return void
	 */
	public static function route_request() {
		$mode = get_query_var( self::QUERY_VAR );
		if ( 'challenge' !== $mode && 'setup' !== $mode ) {
			return;
		}

		if ( ! self::is_available() ) {
			return;
		}

		self::emit_no_cache_headers();

		if ( 'challenge' === $mode ) {
			self::render_challenge();
			exit;
		}

		self::render_setup();
		exit;
	}

	/**
	 * Run the challenge on the themed slug. The engine verifies the code
	 * and hands the page back through
	 * {@see self::render_challenge_view()} and {@see self::render_expired_view()}.
	 *
	 * @return void
	 */
	public static function render_challenge() {
		if ( class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
			ReportedIP_Hive_Two_Factor::get_instance()->handle_2fa_challenge( self::CONTEXT );
			return;
		}
		wp_safe_redirect( wp_login_url() );
	}

	/**
	 * Render the themed setup / onboarding page. Same fallback rule
	 * as {@see self::render_challenge()}.
	 *
	 * @return void
	 */
	public static function render_setup() {
		if ( ! is_user_logged_in() ) {
			$account_url = function_exists( 'wc_get_page_permalink' )
				? (string) wc_get_page_permalink( 'myaccount' )
				: wp_login_url();
			wp_safe_redirect( $account_url );
			return;
		}

		if ( class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) ) {
			$has_wc     = function_exists( 'wc_get_page_permalink' );
			$onboarding = new ReportedIP_Hive_Two_Factor_Onboarding();
			$onboarding->render_page(
				'frontend',
				array(
					'optional'   => (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_frontend_customer_optional', true ),
					'exit_url'   => $has_wc ? (string) wc_get_page_permalink( 'myaccount' ) : '',
					'exit_label' => $has_wc ? __( 'Back to My Account', 'reportedip-hive' ) : '',
				)
			);
			return;
		}

		wp_safe_redirect( is_network_admin() ? network_admin_url( 'admin.php?page=reportedip-hive-2fa-onboarding' ) : admin_url( 'admin.php?page=reportedip-hive-2fa-onboarding' ) );
	}

	/**
	 * Emit no-cache headers for both the challenge and onboarding
	 * pages. Reuses {@see ReportedIP_Hive::emit_block_response_headers()}
	 * for the DONOTCACHE* and HTTP-cache-control basics, then layers on
	 * the LiteSpeed and Vary-Cookie headers that the upstream helper
	 * does not need to set on a generic block page.
	 *
	 * @return void
	 */
	public static function emit_no_cache_headers() {
		ReportedIP_Hive::emit_block_response_headers();

		if ( ! headers_sent() ) {
			header( 'Cache-Control: private, no-store, no-cache, max-age=0' );
			header( 'Vary: Cookie' );
			header( 'X-LiteSpeed-Cache-Control: no-cache' );
		}
	}

	/**
	 * `reportedip_hive_tier_changed` callback. Soft-disables the
	 * module when the customer drops below the PRO requirement so
	 * existing customer 2FA stays valid but new onboardings stop
	 * - full implementation lives in Phase 10. For Phase 3 we only
	 * flush the memo so {@see self::is_available()} re-evaluates on
	 * the next request.
	 *
	 * @param string $prev Previous tier slug.
	 * @param string $next New tier slug.
	 * @return void
	 */
	public static function on_tier_changed( $prev, $next ) {
		self::flush_memo();

		$prev_was_paid = self::tier_was_paid( (string) $prev );
		$next_is_paid  = self::tier_was_paid( (string) $next );

		if ( $prev_was_paid && ! $next_is_paid ) {
			ReportedIP_Hive_Option_Routing::set( self::OPT_SOFT_DISABLED, time() );
			return;
		}

		if ( $next_is_paid && (int) ReportedIP_Hive_Option_Routing::get( self::OPT_SOFT_DISABLED, 0 ) > 0 ) {
			ReportedIP_Hive_Option_Routing::delete( self::OPT_SOFT_DISABLED );
		}
	}

	/**
	 * Whether a tier slug grants access to the frontend module. Used by
	 * the soft-disable bookkeeping in {@see self::on_tier_changed()} so
	 * the bookkeeping stays consistent even if the tier ladder grows in
	 * the future.
	 *
	 * @param string $tier Tier slug from {@see ReportedIP_Hive_Mode_Manager::TIER_ORDER}.
	 * @return bool
	 */
	private static function tier_was_paid( $tier ) {
		return in_array( $tier, array( 'professional', 'business', 'enterprise' ), true );
	}

	/**
	 * Detect whether the current login attempt came from a WooCommerce
	 * frontend form (My Account / classic checkout) or from the WC Store
	 * REST API used by the checkout block.
	 *
	 * @return string One of `wc`, `wc-block`, or empty string when the
	 *                 login originated from `wp-login.php` or some other
	 *                 non-WooCommerce surface.
	 * @since  1.7.0
	 */
	public static function detect_login_origin() {
		if ( ! function_exists( 'WC' ) && ! class_exists( 'WooCommerce' ) ) {
			return '';
		}

		$rest_route = '';
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			$raw = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			if ( false !== strpos( $raw, '/wc/store/' ) ) {
				return 'wc-block';
			}
			$rest_route = isset( $GLOBALS['wp']->query_vars['rest_route'] ) ? (string) $GLOBALS['wp']->query_vars['rest_route'] : '';
			if ( $rest_route && 0 === strpos( $rest_route, '/wc/store' ) ) {
				return 'wc-block';
			}
		}

		if ( ! empty( $_POST['woocommerce-login-nonce'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Sniffing only, never authenticating with this value.
			return 'wc';
		}

		if ( did_action( 'woocommerce_login_form_start' ) ) {
			return 'wc';
		}
		if ( did_action( 'woocommerce_checkout_login_form' ) ) {
			return 'wc';
		}

		$referer = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';
		if ( $referer && function_exists( 'wc_get_page_permalink' ) ) {
			$account_url  = (string) wc_get_page_permalink( 'myaccount' );
			$checkout_url = (string) wc_get_page_permalink( 'checkout' );
			if ( $account_url && 0 === strpos( $referer, $account_url ) ) {
				return 'wc';
			}
			if ( $checkout_url && 0 === strpos( $referer, $checkout_url ) ) {
				return 'wc';
			}
		}

		return '';
	}

	/**
	 * Capture the current WooCommerce session customer-id so the cart can
	 * survive the 2FA redirect roundtrip. Returns an empty string when WC is
	 * not loaded, when the customer has no session yet, or when WC bootstraps
	 * later than the authenticate filter (REST app-passwords path).
	 *
	 * @return string
	 * @since  1.7.0
	 */
	public static function collect_wc_session_hash() {
		if ( ! function_exists( 'WC' ) ) {
			return '';
		}
		$wc = WC();
		if ( ! is_object( $wc ) || empty( $wc->session ) || ! is_object( $wc->session ) ) {
			return '';
		}
		if ( ! method_exists( $wc->session, 'get_customer_id' ) ) {
			return '';
		}
		$cid = (string) $wc->session->get_customer_id();
		return $cid;
	}

	/**
	 * Listener on `reportedip_hive_2fa_challenge_payload`: store where the
	 * sign-in came from, so the challenge URL and the redirect after the
	 * second factor can lead back into the shop.
	 *
	 * @param array<string,mixed> $extra Extra fields so far.
	 * @return array<string,mixed>
	 * @since  3.0.0
	 */
	public static function challenge_payload( $extra ) {
		$extra                    = (array) $extra;
		$extra['origin']          = self::detect_login_origin();
		$extra['origin_url']      = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';
		$extra['wc_session_hash'] = self::collect_wc_session_hash();
		return $extra;
	}

	/**
	 * Listener on `reportedip_hive_2fa_challenge_url`: a WooCommerce sign-in
	 * goes to the themed slug while the module is available; everything
	 * else keeps the wp-login.php interstitial.
	 *
	 * @param string $url    Challenge URL so far.
	 * @param string $origin Origin token from {@see self::challenge_payload()}.
	 * @return string
	 * @since  3.0.0
	 */
	public static function filter_challenge_url( $url, $origin ) {
		if ( '' === (string) $origin || ! self::is_available() ) {
			return (string) $url;
		}
		return self::challenge_url();
	}

	/**
	 * Listener on `reportedip_hive_2fa_redirect_url`: the targets of the
	 * themed challenge. Other contexts pass through unchanged.
	 *
	 * @param string              $url        Target so far (the wp-login target).
	 * @param string              $event      `verified`, `locked` or `signed_in`.
	 * @param string              $context    Challenge context.
	 * @param array<string,mixed> $nonce_data Stored challenge payload.
	 * @return string
	 * @since  3.0.0
	 */
	public static function filter_redirect_url( $url, $event, $context, $nonce_data ) {
		if ( self::CONTEXT !== $context ) {
			return (string) $url;
		}
		switch ( $event ) {
			case 'locked':
				return add_query_arg( 'reportedip_2fa_locked', '1', self::challenge_url() );
			case 'signed_in':
				return self::account_url();
			case 'verified':
				return self::post_verify_url( (array) $nonce_data, (string) $url );
		}
		return (string) $url;
	}

	/**
	 * Target after a passed themed challenge. A stored `redirect_to` wins;
	 * otherwise customers who signed in from `/checkout/` or `/my-account/`
	 * land back there, not on the WP dashboard which they cannot reach.
	 *
	 * @param array<string,mixed> $nonce_data Stored challenge payload.
	 * @param string              $url        Target so far (the stored `redirect_to` when set).
	 * @return string Absolute URL.
	 * @since  1.7.0
	 */
	public static function post_verify_url( array $nonce_data, $url ) {
		$redirect_to = isset( $nonce_data['redirect_to'] ) ? (string) $nonce_data['redirect_to'] : '';
		if ( '' !== $redirect_to ) {
			return (string) $url;
		}
		$origin     = isset( $nonce_data['origin'] ) ? (string) $nonce_data['origin'] : '';
		$origin_url = isset( $nonce_data['origin_url'] ) ? (string) $nonce_data['origin_url'] : '';

		if ( function_exists( 'wc_get_page_permalink' ) ) {
			$home = home_url();
			if ( '' !== $origin_url && 0 === strpos( $origin_url, $home ) ) {
				$path = wp_parse_url( $origin_url, PHP_URL_PATH );
				if ( is_string( $path ) && false !== strpos( $path, '/checkout/' ) && function_exists( 'wc_get_checkout_url' ) ) {
					return (string) wc_get_checkout_url();
				}
				if ( is_string( $path ) && false !== strpos( $path, '/my-account/' ) ) {
					return (string) wc_get_page_permalink( 'myaccount' );
				}
			}
			if ( 'wc' === $origin || 'wc-block' === $origin ) {
				return (string) wc_get_page_permalink( 'myaccount' );
			}
		}
		if ( '' !== $origin_url ) {
			return $origin_url;
		}
		return home_url( '/' );
	}

	/**
	 * The storefront sign-in page: My Account, or the home page without
	 * WooCommerce.
	 *
	 * @return string
	 * @since  3.0.0
	 */
	private static function account_url() {
		return function_exists( 'wc_get_page_permalink' )
			? (string) wc_get_page_permalink( 'myaccount' )
			: home_url( '/' );
	}

	/**
	 * Listener on `reportedip_hive_2fa_render_challenge_theme_frame`: render
	 * the challenge inside the active theme frame instead of the wp-login.php
	 * interstitial, so WooCommerce customers stay on the storefront
	 * throughout the second factor and never get bounced into the WordPress
	 * backend chrome.
	 *
	 * The HTML lives in `templates/frontend-2fa-challenge.php`.
	 *
	 * @param int                 $user_id       The challenged user (the template reads it from the view).
	 * @param array<string,mixed> $template_data Same payload that the
	 *                                            wp-login renderer receives.
	 * @return void
	 * @since 1.7.0
	 */
	public static function render_challenge_view( $user_id, $template_data ) {
		unset( $user_id );
		$challenge_url = self::challenge_url();

		wp_enqueue_style(
			'reportedip-hive-design-system',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/design-system.css',
			array(),
			REPORTEDIP_HIVE_VERSION
		);
		wp_enqueue_style(
			'reportedip-hive-two-factor',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/two-factor.css',
			array( 'reportedip-hive-design-system' ),
			REPORTEDIP_HIVE_VERSION
		);
		wp_enqueue_style(
			'reportedip-hive-two-factor-frontend',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/two-factor-frontend.css',
			array( 'reportedip-hive-two-factor' ),
			REPORTEDIP_HIVE_VERSION
		);

		wp_enqueue_script(
			'reportedip-hive-two-factor-login',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/two-factor-login.js',
			array(),
			REPORTEDIP_HIVE_VERSION,
			true
		);
		wp_localize_script(
			'reportedip-hive-two-factor-login',
			'reportedip2fa',
			array(
				'resendUrl' => add_query_arg( 'resend_email', '1', $challenge_url ),
				'ajaxUrl'   => admin_url( 'admin-ajax.php' ),
				'strings'   => array(
					'newCodeSent'          => __( 'New code sent.', 'reportedip-hive' ),
					'sendingFailed'        => __( 'Sending failed.', 'reportedip-hive' ),
					'sessionExpired'       => __( 'Your session has expired. Please sign in again.', 'reportedip-hive' ),
					'passkeyRequesting'    => __( 'Passkey request in progress...', 'reportedip-hive' ),
					'enterCodeFirst'       => __( 'Please enter the verification code first. If you touched your security key, switch to the passkey tab and use its button instead.', 'reportedip-hive' ),
					'enterCodeFirstPlain'  => __( 'Please enter the verification code first.', 'reportedip-hive' ),
					'passkeyWaiting'       => __( 'Waiting for your security key. Insert and touch it now, or approve the passkey prompt.', 'reportedip-hive' ),
					'passkeyTimeout'       => __( 'The request timed out or was cancelled. Insert your key and touch it (on a phone, hold the key flat against the back for NFC), then try again.', 'reportedip-hive' ),
					'passkeySecurityError' => __( 'The domain of this page does not match the key registration.', 'reportedip-hive' ),
					'passkeyOptionsFailed' => __( 'Failed to fetch passkey options.', 'reportedip-hive' ),
					'passkeyVerifyFailed'  => __( 'Verification failed.', 'reportedip-hive' ),
					'passkeyCancelled'     => __( 'Passkey login cancelled.', 'reportedip-hive' ),
				),
			)
		);

		$template = REPORTEDIP_HIVE_PLUGIN_DIR . 'templates/frontend-2fa-challenge.php';
		if ( ! file_exists( $template ) ) {
			wp_safe_redirect( wp_login_url() . '?action=' . ReportedIP_Hive_Two_Factor::ACTION_CHALLENGE );
			return;
		}

		$rip_2fa = (array) $template_data;
		self::open_theme_frame();
		include $template;
		self::close_theme_frame();
	}

	/**
	 * Open a minimal HTML frame that loads the active theme's stylesheet
	 * and emits `wp_head()` so design tokens, fonts and analytics keep
	 * working, without calling `get_header()`.
	 *
	 * Using `get_header()` triggers a deprecation notice on Block Themes
	 * (twentytwentyfive, twentytwentyfour, ...) because they ship template
	 * parts under `templates/` instead of a classic `header.php`. Block
	 * themes also render their full chrome through `block_template_part`
	 * which is not appropriate for a self-contained interstitial like
	 * the 2FA challenge. The custom frame keeps the visual identity of
	 * the storefront (body class, theme styles) without dragging in the
	 * navigation, breadcrumbs and footer widgets the customer does not
	 * need at this step.
	 *
	 * @return void
	 * @since 1.7.0
	 */
	public static function open_theme_frame() {
		$body_classes = array( 'rip-frontend-2fa-page' );
		if ( function_exists( 'wp_is_block_theme' ) && wp_is_block_theme() ) {
			$body_classes[] = 'wp-block-theme';
		}
		?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
<meta charset="<?php bloginfo( 'charset' ); ?>">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex,nofollow,noarchive">
<title><?php echo esc_html( wp_get_document_title() ); ?></title>
		<?php wp_head(); ?>
</head>
<body <?php body_class( $body_classes ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>>
		<?php wp_body_open(); ?>
<div class="rip-frontend-2fa-frame">
		<?php
	}

	/**
	 * Close the minimal theme-frame opened by {@see self::open_theme_frame()}.
	 *
	 * @return void
	 * @since 1.7.0
	 */
	public static function close_theme_frame() {
		?>
</div>
		<?php wp_footer(); ?>
</body>
</html>
		<?php
	}

	/**
	 * Listener on `reportedip_hive_2fa_render_expired_theme_frame`: the
	 * "session expired" page inside the theme frame, with a way back to the
	 * storefront sign-in.
	 *
	 * @param string $message Explanation for the visitor.
	 * @param string $reason  `expired` or `unknown_user`.
	 * @return void
	 * @since 1.7.0
	 */
	public static function render_expired_view( $message, $reason ) {
		unset( $reason );
		$retry_url = self::account_url();

		self::open_theme_frame();
		?>
		<main class="rip-frontend-2fa rip-frontend-2fa--session-expired" id="rip-frontend-2fa">
			<div class="rip-frontend-2fa__panel">
				<h1 class="rip-frontend-2fa__title"><?php esc_html_e( 'Two-Factor session expired', 'reportedip-hive' ); ?></h1>
				<p class="rip-frontend-2fa__lede"><?php echo esc_html( (string) $message ); ?></p>
				<p>
					<a class="rip-button rip-button--primary" href="<?php echo esc_url( $retry_url ); ?>" rel="noopener">
						<?php esc_html_e( 'Back to sign in', 'reportedip-hive' ); ?>
					</a>
				</p>
			</div>
		</main>
		<?php
		self::close_theme_frame();
	}

	/**
	 * Listener on `reportedip_hive_2fa_onboarding_url`. While the module is
	 * available, a frontend request and a user who cannot reach wp-admin
	 * (neither `manage_options` nor `edit_posts`) get the themed setup slug,
	 * so an administrator who signed in via My Account stays on the
	 * storefront too. Everything else keeps the wp-admin wizard.
	 *
	 * @param string $url     Wizard URL so far.
	 * @param int    $user_id Current user.
	 * @return string
	 * @since  3.0.0
	 */
	public static function filter_onboarding_url( $url, $user_id ) {
		unset( $user_id );
		if ( ! self::is_available() ) {
			return (string) $url;
		}
		if ( self::is_frontend_request() ) {
			return self::setup_url();
		}
		if ( ! current_user_can( 'manage_options' ) && ! current_user_can( 'edit_posts' ) ) {
			return self::setup_url();
		}
		return (string) $url;
	}

	/**
	 * Listener on `reportedip_hive_2fa_post_skip_url`. Customers and
	 * Subscribers cannot reach `wp-admin/`, so a hard dashboard target lands
	 * them on a 403/redirect loop; on a WooCommerce site they go back to My
	 * Account.
	 *
	 * @param string $url     Dashboard URL.
	 * @param int    $user_id User who skipped.
	 * @return string
	 * @since  1.7.0
	 */
	public static function filter_post_skip_url( $url, $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id > 0
			&& ! user_can( $user_id, 'manage_options' )
			&& ! user_can( $user_id, 'edit_posts' )
			&& function_exists( 'wc_get_page_permalink' ) ) {
			$account_url = (string) wc_get_page_permalink( 'myaccount' );
			if ( '' !== $account_url ) {
				return $account_url;
			}
		}
		return (string) $url;
	}

	/**
	 * Listener on `reportedip_2fa_skip_onboarding_redirect`: outside
	 * wp-admin the setting "Send storefront users to themed onboarding"
	 * (default on) decides whether a user who still has to enrol is sent to
	 * the wizard from the frontend.
	 *
	 * @param bool $skip    Skip so far.
	 * @param int  $user_id User.
	 * @return bool
	 * @since  3.0.0
	 */
	public static function skip_onboarding_redirect( $skip, $user_id ) {
		unset( $user_id );
		if ( $skip || is_admin() ) {
			return (bool) $skip;
		}
		return ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_frontend_onboarding', true );
	}

	/**
	 * Whether the current request is a frontend (theme) request, as
	 * opposed to wp-admin, REST, AJAX, cron or CLI.
	 *
	 * @return bool
	 */
	private static function is_frontend_request() {
		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return false;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return false;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return false;
		}
		if ( function_exists( 'is_admin' ) && is_admin() ) {
			return false;
		}
		return true;
	}

	/**
	 * Listener on `reportedip_hive_hide_login_bypass_paths`: both themed
	 * slugs stay reachable while Hide Login is on, otherwise enabling Hide
	 * Login on a customer-facing site silently breaks the second factor
	 * for every WooCommerce user.
	 *
	 * @param string[] $paths Paths so far.
	 * @return string[]
	 * @since  3.0.0
	 */
	public static function bypass_paths( $paths ) {
		$paths   = (array) $paths;
		$paths[] = '/' . self::get_challenge_slug();
		$paths[] = '/' . self::get_setup_slug();
		return $paths;
	}

	/**
	 * Detect known competing 2FA / login-hardening plugins. Returns
	 * the array of conflict descriptors that the settings page can
	 * render as warning banners. Phase 9 wires this into the admin
	 * UI; the static helper is exposed early so the unit tests can
	 * lock the contract down without waiting for that phase.
	 *
	 * @return array<int,array{slug:string,label:string,message:string}>
	 */
	public static function detect_conflicts() {
		$conflicts = array();

		if ( class_exists( 'ITSEC_Core' ) ) {
			$conflicts[] = array(
				'slug'    => 'solid-security',
				'label'   => __( 'Solid Security (formerly iThemes Security)', 'reportedip-hive' ),
				'message' => __( 'Solid Security is active. Hive Frontend 2FA runs alongside it, but to avoid double prompts disable the second factor in one of the two plugins.', 'reportedip-hive' ),
			);
		}
		if ( class_exists( 'Two_Factor_Core' ) ) {
			$conflicts[] = array(
				'slug'    => 'wp-two-factor',
				'label'   => __( 'WordPress Two-Factor', 'reportedip-hive' ),
				'message' => __( 'The WordPress.org "Two Factor" plugin is active. Pick one provider, running both will prompt customers twice.', 'reportedip-hive' ),
			);
		}
		if ( function_exists( 'wfConfig' ) ) {
			$conflicts[] = array(
				'slug'    => 'wordfence',
				'label'   => __( 'Wordfence', 'reportedip-hive' ),
				'message' => __( 'Wordfence offers its own 2FA injection, disable it for any role that should be served by Hive Frontend 2FA.', 'reportedip-hive' ),
			);
		}
		if ( class_exists( 'WC_Subscriptions' ) || class_exists( 'WC_Memberships' ) ) {
			$conflicts[] = array(
				'slug'    => 'wc-subscriptions',
				'label'   => __( 'WooCommerce Subscriptions / Memberships', 'reportedip-hive' ),
				'message' => __( 'Magic-login links sent by Subscriptions and Memberships intentionally bypass 2FA so renewals do not break, keep the subscription audit log enabled.', 'reportedip-hive' ),
			);
		}

		return $conflicts;
	}
}
