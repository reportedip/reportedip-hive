<?php
/**
 * The single reader for active WordPress sessions.
 *
 * Core's `WP_Session_Tokens::get_all()` returns `array_values()` and therefore
 * drops the verifier keys, without them a specific session cannot be ended,
 * because nobody but the browser holds the raw token. This class reads the
 * `session_tokens` user meta directly, keeps the verifiers, and is the only
 * place in the plugin that does so.
 *
 * It also attaches the proxy-aware client IP to every new session: core
 * overwrites the `ip` field with `REMOTE_ADDR` after the filter has run, which
 * behind Cloudflare or any reverse proxy records the proxy, not the visitor.
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
 * Session inventory and termination.
 *
 * @since 2.1.51
 */
final class ReportedIP_Hive_User_Sessions {

	/**
	 * Core user-meta key holding the session map.
	 */
	const META = 'session_tokens';

	/**
	 * Extra per-session field carrying the proxy-aware client IP.
	 */
	const IP_KEY = 'rip_ip';

	/**
	 * Columns a session listing may be ordered by.
	 *
	 * @var string[]
	 */
	const ORDERBY_ALLOWED = array( 'user_login', 'display_name' );

	/**
	 * Memo for {@see uses_usermeta_store()}.
	 *
	 * @var bool|null
	 */
	private static $usermeta_store = null;

	/**
	 * Register the always-on session-information filter.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public static function register_hooks() {
		add_filter( 'attach_session_information', array( __CLASS__, 'attach_client_ip' ), 10, 2 );
	}

	/**
	 * Record the real client IP alongside core's `REMOTE_ADDR`.
	 *
	 * @param array $session Session payload being created.
	 * @param int   $user_id Owner of the session.
	 * @return array
	 * @since  2.1.51
	 */
	public static function attach_client_ip( $session, $user_id = 0 ) {
		unset( $user_id );

		$session = is_array( $session ) ? $session : array();
		$ip      = ReportedIP_Hive::get_client_ip();
		if ( '' !== $ip && 'unknown' !== $ip ) {
			$session[ self::IP_KEY ] = $ip;
		}

		return $session;
	}

	/**
	 * Hash a raw session token into its stored verifier. Pure.
	 *
	 * Mirrors the private `WP_Session_Tokens::hash_token()`.
	 *
	 * @param string $token Raw session token.
	 * @return string
	 * @since  2.1.51
	 */
	public static function hash_verifier( $token ) {
		$token = (string) $token;
		if ( '' === $token ) {
			return '';
		}
		return function_exists( 'hash' ) ? hash( 'sha256', $token ) : sha1( $token );
	}

	/**
	 * Verifier of the session the current request is authenticated with.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	public static function current_verifier() {
		return self::hash_verifier( (string) wp_get_session_token() );
	}

	/**
	 * Keep only sessions that have not expired, verifier keys intact. Pure.
	 *
	 * @param array $sessions Raw `session_tokens` map.
	 * @param int   $now      Current UNIX timestamp.
	 * @return array<string,array<string,mixed>>
	 * @since  2.1.51
	 */
	public static function live( array $sessions, $now ) {
		$live = array();
		foreach ( $sessions as $verifier => $session ) {
			if ( is_int( $session ) ) {
				$session = array( 'expiration' => $session );
			}
			if ( ! is_array( $session ) || empty( $session['expiration'] ) ) {
				continue;
			}
			if ( (int) $session['expiration'] <= (int) $now ) {
				continue;
			}
			$live[ (string) $verifier ] = $session;
		}

		return $live;
	}

	/**
	 * Live sessions of one user, keyed by verifier.
	 *
	 * @param int $user_id User id.
	 * @return array<string,array<string,mixed>>
	 * @since  2.1.51
	 */
	public static function for_user( $user_id ) {
		$raw = get_user_meta( (int) $user_id, self::META, true );
		return self::live( is_array( $raw ) ? $raw : array(), time() );
	}

	/**
	 * Best available IP for one session. Pure.
	 *
	 * @param array $session Session payload.
	 * @return string
	 * @since  2.1.51
	 */
	public static function display_ip( array $session ) {
		if ( ! empty( $session[ self::IP_KEY ] ) ) {
			return (string) $session[ self::IP_KEY ];
		}
		return isset( $session['ip'] ) ? (string) $session['ip'] : '';
	}

	/**
	 * LIKE needle matching an IP inside the serialised session blob. Pure.
	 *
	 * Returned bare: `WP_Meta_Query` wraps a LIKE value in
	 * `'%' . $wpdb->esc_like( $value ) . '%'` itself, so pre-wrapped wildcards
	 * would be escaped into literal percent signs and never match.
	 *
	 * ponytail: exact-string LIKE over the serialised meta value. Good enough
	 * for a filter box on an admin screen; if session volume ever makes this
	 * hurt, the sessions need their own index table.
	 *
	 * @param string $ip IP address to look for.
	 * @return string
	 * @since  2.1.51
	 */
	public static function ip_like_pattern( $ip ) {
		return '"' . (string) $ip . '"';
	}

	/**
	 * Build the `WP_User_Query` arguments for one page of session owners. Pure.
	 *
	 * Pagination is by user, not by session: a user with three browsers open
	 * counts once towards the page size and contributes three rows.
	 *
	 * @param array $filters  Optional `search` and `ip` filters.
	 * @param int   $per_page Users per page.
	 * @param int   $page     1-based page number.
	 * @param int   $blog_id  Blog id, 0 for the whole network.
	 * @return array<string,mixed>
	 * @since  2.1.51
	 */
	public static function users_query_args( array $filters, $per_page, $page, $blog_id ) {
		$per_page = max( 1, (int) $per_page );
		$page     = max( 1, (int) $page );

		$orderby = isset( $filters['orderby'] ) ? (string) $filters['orderby'] : '';
		if ( ! in_array( $orderby, self::ORDERBY_ALLOWED, true ) ) {
			$orderby = 'user_login';
		}
		$order = ( isset( $filters['order'] ) && 'desc' === strtolower( (string) $filters['order'] ) ) ? 'DESC' : 'ASC';

		$args = array(
			'blog_id'     => (int) $blog_id,
			'meta_key'    => self::META, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Existence probe over the core session meta; there is no other index of who is signed in.
			'number'      => $per_page,
			'offset'      => ( $page - 1 ) * $per_page,
			'orderby'     => $orderby,
			'order'       => $order,
			'count_total' => true,
		);

		$ip = isset( $filters['ip'] ) ? trim( (string) $filters['ip'] ) : '';
		if ( '' !== $ip ) {
			$args['meta_value']   = self::ip_like_pattern( $ip ); // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- Admin-only filter box; see ip_like_pattern().
			$args['meta_compare'] = 'LIKE';
		} else {
			$args['meta_compare'] = 'EXISTS';
		}

		$search = isset( $filters['search'] ) ? trim( (string) $filters['search'] ) : '';
		if ( '' !== $search ) {
			$args['search']         = '*' . $search . '*';
			$args['search_columns'] = array( 'user_login', 'user_email', 'display_name' );
		}

		return $args;
	}

	/**
	 * Whether sessions live in user meta and can be edited per session.
	 *
	 * Object-cache backed session managers (Redis and friends) swap the store
	 * through the `session_token_manager` filter; there the per-session
	 * controls have nothing to act on and are hidden.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	public static function uses_usermeta_store() {
		if ( null === self::$usermeta_store ) {
			self::$usermeta_store = WP_Session_Tokens::get_instance( 0 ) instanceof WP_User_Meta_Session_Tokens;
		}
		return self::$usermeta_store;
	}

	/**
	 * End one specific session. Refuses the caller's own current session.
	 *
	 * @param int    $user_id  Session owner.
	 * @param string $verifier Session verifier.
	 * @return bool True when a session was removed.
	 * @since  2.1.51
	 */
	public static function terminate( $user_id, $verifier ) {
		$user_id  = (int) $user_id;
		$verifier = (string) $verifier;

		if ( $user_id <= 0 || '' === $verifier || ! self::uses_usermeta_store() ) {
			return false;
		}
		if ( get_current_user_id() === $user_id && self::current_verifier() === $verifier ) {
			return false;
		}

		$sessions = get_user_meta( $user_id, self::META, true );
		$sessions = is_array( $sessions ) ? $sessions : array();
		if ( ! isset( $sessions[ $verifier ] ) ) {
			return false;
		}

		unset( $sessions[ $verifier ] );
		if ( empty( $sessions ) ) {
			delete_user_meta( $user_id, self::META );
		} else {
			update_user_meta( $user_id, self::META, $sessions );
		}

		return true;
	}

	/**
	 * End every session of a user; for the caller's own account every session
	 * but the current one.
	 *
	 * @param int $user_id Session owner.
	 * @return int Number of sessions ended.
	 * @since  2.1.51
	 */
	public static function terminate_all( $user_id ) {
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return 0;
		}

		$count = count( self::for_user( $user_id ) );

		if ( get_current_user_id() === $user_id ) {
			wp_destroy_other_sessions();
			return max( 0, $count - 1 );
		}

		WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		return $count;
	}
}
