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
 * 404 stale links — but {@see self::route_request()} simply yields and
 * lets WordPress fall through to its standard 404, while the legacy
 * wp-login.php challenge keeps working for everyone.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
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
 * 2FA module. The public surface is fully static — there is no
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
	 * Site-option holding the public slug of the challenge page.
	 */
	const OPT_CHALLENGE_SLUG = 'reportedip_hive_2fa_frontend_slug';

	/**
	 * Site-option holding the public slug of the setup / onboarding page.
	 */
	const OPT_SETUP_SLUG = 'reportedip_hive_2fa_frontend_setup_slug';

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
	 * Default slugs — if you change these in code, also update the
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
	 * Wire the WordPress hooks. Idempotent — calling twice is safe.
	 *
	 * @return void
	 */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'register_routes' ), 5 );
		add_filter( 'query_vars', array( __CLASS__, 'register_query_var' ) );
		add_action( 'template_redirect', array( __CLASS__, 'route_request' ), 5 );
		add_action( 'reportedip_hive_tier_changed', array( __CLASS__, 'on_tier_changed' ), 30, 2 );
		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'maybe_enqueue_blocks_redirect' ) );
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

		if ( ! get_option( self::OPT_ENABLED, false ) ) {
			self::$available_memo = false;
			return false;
		}

		if ( (int) get_option( self::OPT_SOFT_DISABLED, 0 ) > 0 ) {
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
	}

	/**
	 * Resolve the current configured challenge slug, falling back to
	 * the default when the option is empty or invalid.
	 *
	 * @return string
	 */
	public static function get_challenge_slug() {
		return self::sanitize_slug( get_option( self::OPT_CHALLENGE_SLUG, self::DEFAULT_CHALLENGE_SLUG ), self::DEFAULT_CHALLENGE_SLUG );
	}

	/**
	 * Resolve the current configured setup / onboarding slug.
	 *
	 * @return string
	 */
	public static function get_setup_slug() {
		return self::sanitize_slug( get_option( self::OPT_SETUP_SLUG, self::DEFAULT_SETUP_SLUG ), self::DEFAULT_SETUP_SLUG );
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
	 * module's query var. Idempotent — `add_rewrite_rule()` is a
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

		if ( 'setup' === $mode ) {
			self::render_setup();
			exit;
		}
	}

	/**
	 * Render the themed challenge page. The actual HTML lives in a
	 * template under `templates/frontend-2fa-challenge.php` and is
	 * delivered in Phase 4. Until that template is in place the
	 * method falls through to the legacy `wp-login.php?action=...`
	 * URL so we never serve an empty page.
	 *
	 * @return void
	 */
	public static function render_challenge() {
		if ( class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
			ReportedIP_Hive_Two_Factor::get_instance()->handle_2fa_challenge( 'theme_frame' );
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
			$onboarding = new ReportedIP_Hive_Two_Factor_Onboarding();
			$onboarding->render_page();
			return;
		}

		wp_safe_redirect( admin_url( 'admin.php?page=reportedip-hive-2fa-onboarding' ) );
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
		if ( class_exists( 'ReportedIP_Hive' ) && method_exists( 'ReportedIP_Hive', 'emit_block_response_headers' ) ) {
			ReportedIP_Hive::emit_block_response_headers();
		} elseif ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}

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
	 * — full implementation lives in Phase 10. For Phase 3 we only
	 * flush the memo so {@see self::is_available()} re-evaluates on
	 * the next request.
	 *
	 * @param string $prev Previous tier slug.
	 * @param string $new  New tier slug.
	 * @return void
	 */
	public static function on_tier_changed( $prev, $new ) {
		self::flush_memo();

		$prev_was_paid = self::tier_was_paid( (string) $prev );
		$new_is_paid   = self::tier_was_paid( (string) $new );

		if ( $prev_was_paid && ! $new_is_paid ) {
			update_option( self::OPT_SOFT_DISABLED, time() );
			return;
		}

		if ( $new_is_paid && (int) get_option( self::OPT_SOFT_DISABLED, 0 ) > 0 ) {
			delete_option( self::OPT_SOFT_DISABLED );
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
				'message' => __( 'The WordPress.org "Two Factor" plugin is active. Pick one provider — running both will prompt customers twice.', 'reportedip-hive' ),
			);
		}
		if ( function_exists( 'wfConfig' ) ) {
			$conflicts[] = array(
				'slug'    => 'wordfence',
				'label'   => __( 'Wordfence', 'reportedip-hive' ),
				'message' => __( 'Wordfence offers its own 2FA injection — disable it for any role that should be served by Hive Frontend 2FA.', 'reportedip-hive' ),
			);
		}
		if ( class_exists( 'WC_Subscriptions' ) || class_exists( 'WC_Memberships' ) ) {
			$conflicts[] = array(
				'slug'    => 'wc-subscriptions',
				'label'   => __( 'WooCommerce Subscriptions / Memberships', 'reportedip-hive' ),
				'message' => __( 'Magic-login links sent by Subscriptions and Memberships intentionally bypass 2FA so renewals do not break — keep the subscription audit log enabled.', 'reportedip-hive' ),
			);
		}

		return $conflicts;
	}
}
