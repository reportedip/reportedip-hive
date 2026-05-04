<?php
/**
 * User Enumeration Defence.
 *
 * Closes the four classic WordPress username-leak vectors and rate-limits
 * the bots that probe them:
 *
 *  1. `?author=<n>` permalink redirect → 404 (or block).
 *  2. `/wp-json/wp/v2/users` and `/wp-json/wp/v2/users/<id>` for unauth users.
 *  3. `/wp-json/oembed/1.0/embed?url=<post>` author leak.
 *  4. Generic login-error message so "user not found" and "wrong password"
 *     are indistinguishable.
 *
 * Every block-event also feeds the security monitor as `user_enumeration`
 * — repeated probes from the same IP escalate to a real block + report.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.2.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_User_Enumeration {

	/**
	 * `?action=` slugs that bypass the "Invalid credentials." mask. Adding
	 * an action here lets its login-error text reach the user verbatim
	 * (used by the 2FA login challenge and the password-reset gate).
	 *
	 * @var string[]
	 */
	private const PASSTHROUGH_ACTIONS = array( 'reportedip_2fa', 'reportedip_2fa_reset' );

	/**
	 * Substrings that — when an error message contains one of them on the
	 * `rp` / `resetpass` actions — let the message pass through unmasked.
	 * The reset-gate phrasing is stable English; translations should keep
	 * one of these tokens in place. (The gate itself prefers wp_die() for
	 * unmask-able lockouts, but the WP_Error path still needs a
	 * pass-through for the "verification required" case.)
	 *
	 * @var string[]
	 */
	private const PASSTHROUGH_NEEDLES_RESET = array( 'two-factor', 'reset blocked' );

	/**
	 * Singleton instance.
	 *
	 * @var ReportedIP_Hive_User_Enumeration|null
	 */
	private static $instance = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'template_redirect', array( $this, 'block_author_param' ), 1 );
		add_filter( 'rest_endpoints', array( $this, 'restrict_users_endpoint' ) );
		add_filter( 'rest_pre_dispatch', array( $this, 'detect_rest_users_probe' ), 4, 3 );
		add_filter( 'oembed_response_data', array( $this, 'strip_author_from_oembed' ), 99 );
		add_filter( 'login_errors', array( $this, 'normalize_login_errors' ), 99 );
		add_filter( 'authenticate', array( $this, 'unify_login_error_codes' ), 99, 3 );
	}

	/**
	 * Detect probes against the `/wp/v2/users` endpoint family on the actual
	 * request route — rest_endpoints fires on every REST request and would
	 * otherwise log a probe against unrelated routes too. Runs at priority 4
	 * so the global REST monitor (priority 5) still sees the request.
	 *
	 * @param mixed           $result  Existing dispatch result.
	 * @param WP_REST_Server  $server  Server instance.
	 * @param WP_REST_Request $request Incoming request.
	 * @return mixed                   Original $result, untouched.
	 */
	public function detect_rest_users_probe( $result, $server, $request ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		unset( $server );
		if ( ! get_option( 'reportedip_hive_block_user_enumeration', true ) ) {
			return $result;
		}
		if ( ! ( $request instanceof WP_REST_Request ) ) {
			return $result;
		}
		if ( is_user_logged_in() ) {
			return $result;
		}
		$route = (string) $request->get_route();
		if ( '/wp/v2/users' === $route || str_starts_with( $route, '/wp/v2/users/' ) ) {
			$this->record_probe( 'rest_users' );
		}
		return $result;
	}

	/**
	 * Trap requests that probe `?author=<n>` (or the pretty `/author/<slug>`)
	 * before WordPress can redirect to the slug-based archive (which leaks
	 * the username). Bots that hammer this endpoint accumulate
	 * `user_enumeration` attempts and eventually trip the threshold.
	 */
	public function block_author_param(): void {
		if ( ! get_option( 'reportedip_hive_block_user_enumeration', true ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only probe detection on a public route; presence-only check, no value used.
		$author_param    = isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( (string) $_GET['author'] ) ) : '';
		$is_author_query = '' !== $author_param;

		if ( ! $is_author_query && ! ( is_author() && ! is_user_logged_in() ) ) {
			return;
		}

		$this->record_probe( 'author_param' );

		status_header( 404 );
		nocache_headers();
		global $wp_query;
		if ( $wp_query instanceof WP_Query ) {
			$wp_query->set_404();
		}
		$template = get_404_template();
		if ( $template && file_exists( $template ) ) {
			include $template;
			exit;
		}
		wp_die( esc_html__( 'Not found.', 'reportedip-hive' ), '', array( 'response' => 404 ) );
	}

	/**
	 * Lock down `/wp-json/wp/v2/users` for unauthenticated callers. We
	 * leave the endpoint registered for logged-in users (so the block-editor
	 * keeps working), but drop all routes that would otherwise list users.
	 *
	 * Probes still flow through rest_pre_dispatch and the REST monitor —
	 * here we additionally short-circuit the response so the data leak is
	 * gone even if the IP threshold has not yet fired.
	 *
	 * @param array $endpoints REST endpoint registry.
	 * @return array
	 */
	public function restrict_users_endpoint( $endpoints ) {
		if ( ! get_option( 'reportedip_hive_block_user_enumeration', true ) ) {
			return $endpoints;
		}
		if ( is_user_logged_in() ) {
			return $endpoints;
		}

		unset( $endpoints['/wp/v2/users'] );
		foreach ( $endpoints as $route => $_handlers ) {
			if ( str_starts_with( (string) $route, '/wp/v2/users/' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	/**
	 * Strip `author_name` and `author_url` from the oEmbed JSON payload so
	 * `?embed=true` cannot reveal the post author's display name.
	 *
	 * @param array $data oEmbed response payload.
	 * @return array
	 */
	public function strip_author_from_oembed( $data ) {
		if ( ! get_option( 'reportedip_hive_block_user_enumeration', true ) ) {
			return $data;
		}
		if ( ! is_array( $data ) ) {
			return $data;
		}
		unset( $data['author_name'], $data['author_url'] );
		return $data;
	}

	/**
	 * Replace the verbose default login error (which leaks whether the
	 * username exists) with a single generic message.
	 *
	 * Recognises the plugin's own 2FA-flow query flags
	 * (`?reportedip_2fa_locked=1`, `?reportedip_2fa_expired=1`) and lets
	 * those messages through unmasked — they reveal nothing about user
	 * existence and would otherwise be replaced with the misleading
	 * "Invalid credentials." text.
	 */
	public function normalize_login_errors( $error ) {
		if ( ! get_option( 'reportedip_hive_block_user_enumeration', true ) ) {
			return $error;
		}
		if ( '' === (string) $error ) {
			return $error;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only flag inspection; no state change.
		$action       = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : '';
		$flag_locked  = isset( $_GET['reportedip_2fa_locked'] ) && '1' === sanitize_text_field( wp_unslash( $_GET['reportedip_2fa_locked'] ) );
		$flag_expired = isset( $_GET['reportedip_2fa_expired'] ) && '1' === sanitize_text_field( wp_unslash( $_GET['reportedip_2fa_expired'] ) );
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$is_reset_passthrough = is_string( $error )
			&& in_array( $action, array( 'rp', 'resetpass' ), true )
			&& self::contains_any( $error, self::PASSTHROUGH_NEEDLES_RESET );

		if ( $flag_locked
			|| $flag_expired
			|| in_array( $action, self::PASSTHROUGH_ACTIONS, true )
			|| $is_reset_passthrough ) {
			return $error;
		}

		return __( 'Invalid credentials.', 'reportedip-hive' );
	}

	/**
	 * Case-insensitive haystack-contains-any-needle check.
	 *
	 * @param string   $haystack
	 * @param string[] $needles
	 * @return bool
	 */
	private static function contains_any( string $haystack, array $needles ): bool {
		foreach ( $needles as $needle ) {
			if ( '' !== $needle && false !== stripos( $haystack, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Mask the WP_Error code so plugins / themes that surface the raw code
	 * (rather than the message) cannot leak whether the username existed.
	 *
	 * @param WP_User|WP_Error|null $user     Current authentication result.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password (unused).
	 */
	public function unify_login_error_codes( $user, $username, $password ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		unset( $password );

		if ( ! get_option( 'reportedip_hive_block_user_enumeration', true ) ) {
			return $user;
		}
		if ( ! ( $user instanceof WP_Error ) ) {
			return $user;
		}

		$leaky_codes = array( 'invalid_username', 'invalid_email', 'incorrect_password' );
		foreach ( $leaky_codes as $code ) {
			if ( $user->get_error_code() === $code ) {
				return new WP_Error( 'invalid_credentials', __( 'Invalid credentials.', 'reportedip-hive' ) );
			}
		}
		return $user;
	}

	/**
	 * Record a probe attempt and let the security monitor decide whether to
	 * block. Whitelisted IPs are exempt so admins can use the WP CLI or
	 * the REST users endpoint from a known IP without tripping the sensor.
	 */
	private function record_probe( string $vector ): void {
		if ( ! class_exists( 'ReportedIP_Hive' ) ) {
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

		$client  = ReportedIP_Hive::get_instance();
		$monitor = $client->get_security_monitor();
		if ( ! ( $monitor instanceof ReportedIP_Hive_Security_Monitor ) ) {
			return;
		}

		$threshold = (int) get_option( 'reportedip_hive_user_enum_threshold', 5 );
		$timeframe = (int) get_option( 'reportedip_hive_user_enum_timeframe', 5 );

		$monitor->track_generic_attempt(
			$ip,
			'user_enumeration',
			'user_enumeration',
			$threshold,
			$timeframe,
			array( 'vector' => $vector )
		);
	}
}
