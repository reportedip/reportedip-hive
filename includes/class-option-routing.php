<?php
/**
 * Option-Routing service: routes plugin options to network or per-site storage.
 *
 * On Multisite installs the plugin needs to distinguish between
 *   - network-wide options (single source of truth across all sites: API key,
 *     mode, tier, thresholds, sensor toggles, …)
 *   - site-specific options (currently only two: per-site WooCommerce
 *     Frontend-2FA slug override and per-site additional 2FA enforcement
 *     roles, both of which strictly extend the network defaults).
 *
 * On single-site installs `get_site_option()` falls through to `get_option()`,
 * so the routing is a no-op and behaviour is identical to v1.x.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Routes plugin options to the correct storage scope (network vs. per-site).
 *
 * @since 2.0.0
 */
final class ReportedIP_Hive_Option_Routing {

	/**
	 * Options that live in per-site storage (`wp_options` per blog).
	 *
	 * Every key NOT in this map is treated as a network option. Stored as
	 * a flipped lookup map (key => true) so {@see is_site_option()} is an
	 * O(1) `isset()` rather than an O(N) `in_array()` — at 350+ call
	 * sites per request the difference is measurable.
	 *
	 * @var array<string, true>
	 */
	private const SITE_OPTION_LOOKUP = array(
		'reportedip_hive_2fa_frontend_slug_site_override' => true,
		'reportedip_hive_2fa_frontend_setup_slug_site_override' => true,
		'reportedip_hive_2fa_enforce_roles_extra'         => true,
	);

	/**
	 * Default for `2fa_frontend_slug` when neither network nor site value is set.
	 */
	public const DEFAULT_FRONTEND_SLUG = 'reportedip-hive-2fa';

	/**
	 * Upper value-size bound for {@see prime_cache()}. Large payloads (the
	 * synced disposable-domains ruleset can exceed 500 KB) are deliberately
	 * NOT primed — they stay lazy-loaded by their single consumer instead of
	 * being unserialised into memory on every request.
	 */
	private const PRIME_MAX_BYTES = 65536;

	/**
	 * Per-request cache for the resolve_* helpers. Cleared by `flush()`
	 * (called from the `update_option_*` / `update_site_option_*` action
	 * hooks). Hot-path callers (Two_Factor login filter, Password_Strength)
	 * read these values multiple times per request.
	 *
	 * @var array<string, mixed>
	 */
	private static $resolve_cache = array();

	/**
	 * Pre-load every small plugin option into the request-level object cache
	 * with a single query.
	 *
	 * Background: on single-site WordPress `update_network_option()` always
	 * writes with `autoload=no`, so none of the ~150 plugin options ever land
	 * in `alloptions`. Without a persistent object cache every distinct
	 * `Option_Routing::get()` key therefore costs one `SELECT option_value …
	 * LIMIT 1` — measured at 30+ plugin-option queries on a single anonymous
	 * front-end request. On Multisite the same applies to sitemeta lookups.
	 *
	 * This helper replaces those with ONE query per request. Values are stored
	 * via `wp_cache_add()` in the exact raw form core caches itself, so
	 * `get_option()` / `get_site_option()` become cache hits and any value the
	 * current request already cached wins. With a persistent external object
	 * cache the per-key lookups are already cheap and cross-request, so the
	 * helper is a no-op there.
	 *
	 * @return void
	 * @since  2.1.32
	 */
	public static function prime_cache() {
		global $wpdb;

		if ( function_exists( 'wp_using_ext_object_cache' ) && wp_using_ext_object_cache() ) {
			return;
		}

		$prefix_like = $wpdb->esc_like( 'reportedip_hive_' ) . '%';

		if ( is_multisite() ) {
			$network_id = function_exists( 'get_current_network_id' ) ? get_current_network_id() : 1;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bulk cache prime; the per-key core path would issue one query per option.
			$rows = (array) $wpdb->get_results(
				$wpdb->prepare(
					"SELECT meta_key, meta_value FROM {$wpdb->sitemeta}
					 WHERE site_id = %d AND meta_key LIKE %s
					   AND LENGTH(meta_value) <= %d",
					$network_id,
					$prefix_like,
					self::PRIME_MAX_BYTES
				)
			);
			foreach ( $rows as $row ) {
				/*
				 * Core's get_network_option() unserializes BEFORE caching and
				 * trusts a cache hit verbatim, so the primed value must already
				 * be unserialized — a raw serialized string here poisons every
				 * array-valued network option until the cache expires (fatal
				 * TypeError in consumers such as the cache-stats counters).
				 */
				wp_cache_add( $network_id . ':' . $row->meta_key, maybe_unserialize( $row->meta_value ), 'site-options' );
			}
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Bulk cache prime; the per-key core path would issue one query per option.
		$rows = (array) $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options}
				 WHERE option_name LIKE %s
				   AND LENGTH(option_value) <= %d",
				$prefix_like,
				self::PRIME_MAX_BYTES
			)
		);
		foreach ( $rows as $row ) {
			wp_cache_add( $row->option_name, $row->option_value, 'options' );
		}
	}

	/**
	 * Get an option, routed to the correct storage.
	 *
	 * @param string $key      Option name (must include `reportedip_hive_` prefix).
	 * @param mixed  $fallback Default value if the option is not set.
	 * @return mixed Option value or $fallback.
	 * @since  2.0.0
	 */
	public static function get( $key, $fallback = false ) {
		$key = (string) $key;
		if ( self::is_site_option( $key ) ) {
			return get_option( $key, $fallback );
		}
		return get_site_option( $key, $fallback );
	}

	/**
	 * Set an option in the correct storage.
	 *
	 * @param string $key   Option name.
	 * @param mixed  $value Option value.
	 * @return bool True if the value was changed (or written), false otherwise.
	 * @since  2.0.0
	 */
	public static function set( $key, $value ) {
		$key = (string) $key;
		if ( self::is_site_option( $key ) ) {
			return update_option( $key, $value );
		}
		return update_site_option( $key, $value );
	}

	/**
	 * Delete an option from the correct storage.
	 *
	 * @param string $key Option name.
	 * @return bool True on success.
	 * @since  2.0.0
	 */
	public static function delete( $key ) {
		$key = (string) $key;
		if ( self::is_site_option( $key ) ) {
			return delete_option( $key );
		}
		return delete_site_option( $key );
	}

	/**
	 * Whether an option key is per-site (override / additive) instead of network-wide.
	 *
	 * @param string $key Option name.
	 * @return bool
	 * @since  2.0.0
	 */
	public static function is_site_option( $key ) {
		return isset( self::SITE_OPTION_LOOKUP[ (string) $key ] );
	}

	/**
	 * Drop the per-request resolve cache.
	 *
	 * Called from `update_option_*` / `update_site_option_*` hooks so a
	 * settings save in the same request is reflected immediately.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public static function flush_resolve_cache() {
		self::$resolve_cache = array();
	}

	/**
	 * Resolve the effective WooCommerce Frontend-2FA slug for the current request.
	 *
	 * Per-site override (if non-empty) wins over the network default. On
	 * single-site installs both calls hit the same storage so behaviour is
	 * unchanged.
	 *
	 * @return string Slug suitable for `sanitize_title()` consumers (3–50 chars).
	 * @since  2.0.0
	 */
	public static function resolve_2fa_frontend_slug() {
		$key = self::cache_key( 'frontend_slug' );
		if ( isset( self::$resolve_cache[ $key ] ) ) {
			return self::$resolve_cache[ $key ];
		}
		$override = (string) get_option( 'reportedip_hive_2fa_frontend_slug_site_override', '' );
		if ( '' !== trim( $override ) ) {
			self::$resolve_cache[ $key ] = $override;
			return $override;
		}
		$network                     = (string) get_site_option( 'reportedip_hive_2fa_frontend_slug', self::DEFAULT_FRONTEND_SLUG );
		$slug                        = '' !== trim( $network ) ? $network : self::DEFAULT_FRONTEND_SLUG;
		self::$resolve_cache[ $key ] = $slug;
		return $slug;
	}

	/**
	 * Build a per-blog cache key for the resolve_* helpers so cached
	 * values do not leak across `switch_to_blog()` boundaries.
	 *
	 * @param string $bucket Logical bucket (e.g. 'frontend_slug').
	 * @return string
	 * @since  2.0.0
	 */
	private static function cache_key( $bucket ) {
		$blog_id = function_exists( 'get_current_blog_id' ) ? (int) get_current_blog_id() : 0;
		return $bucket . ':' . $blog_id;
	}

	/**
	 * Resolve the WooCommerce Frontend-2FA setup (onboarding) slug.
	 *
	 * Per-site override wins over the network default. Used by
	 * {@see ReportedIP_Hive_Two_Factor_Frontend::get_setup_slug()} so the
	 * customer-self-service onboarding URL can be tuned per sub-site if
	 * the network default collides with an existing path.
	 *
	 * @return string
	 * @since  2.0.0
	 */
	public static function resolve_2fa_frontend_setup_slug() {
		$key = self::cache_key( 'frontend_setup_slug' );
		if ( isset( self::$resolve_cache[ $key ] ) ) {
			return self::$resolve_cache[ $key ];
		}
		$override = (string) get_option( 'reportedip_hive_2fa_frontend_setup_slug_site_override', '' );
		if ( '' !== trim( $override ) ) {
			self::$resolve_cache[ $key ] = $override;
			return $override;
		}
		$network                     = (string) get_site_option( 'reportedip_hive_2fa_frontend_setup_slug', 'reportedip-hive-2fa-setup' );
		$slug                        = '' !== trim( $network ) ? $network : 'reportedip-hive-2fa-setup';
		self::$resolve_cache[ $key ] = $slug;
		return $slug;
	}

	/**
	 * Resolve the effective 2FA enforcement role list for the current site.
	 *
	 * Site can ONLY extend the network list (additive). Removing a role
	 * network-wide is the prerogative of the Network Admin — Site Admins
	 * cannot drop roles that the Super Admin requires.
	 *
	 * @return string[] Sorted, de-duplicated list of role slugs.
	 * @since  2.0.0
	 */
	public static function resolve_2fa_enforce_roles() {
		$key = self::cache_key( 'enforce_roles' );
		if ( isset( self::$resolve_cache[ $key ] ) ) {
			return self::$resolve_cache[ $key ];
		}
		$network = self::get_network_enforce_roles();
		$extra   = self::get_site_enforce_roles_extra();

		$merged = array_unique( array_merge( $network, $extra ) );
		$merged = array_values( array_filter( $merged, 'is_string' ) );
		sort( $merged );
		self::$resolve_cache[ $key ] = $merged;
		return $merged;
	}

	/**
	 * Network-only 2FA enforce-roles list (no site-extra merge).
	 *
	 * Use this when you need to know which roles are *network-required*
	 * — e.g. in the Site Admin UI to render the read-only "always
	 * enforced by network" markers. {@see resolve_2fa_enforce_roles()}
	 * is the right call when you need the *effective* enforced list for
	 * the current site.
	 *
	 * @return string[]
	 * @since  2.0.0
	 */
	public static function get_network_enforce_roles() {
		return self::coerce_role_list( get_site_option( 'reportedip_hive_2fa_enforce_roles', array() ) );
	}

	/**
	 * Per-site additive 2FA enforce-roles list.
	 *
	 * Returns only the roles the Site Admin marked extra on top of the
	 * network list. Network roles are NOT in here.
	 *
	 * @return string[]
	 * @since  2.0.0
	 */
	public static function get_site_enforce_roles_extra() {
		return self::coerce_role_list( get_option( 'reportedip_hive_2fa_enforce_roles_extra', array() ) );
	}

	/**
	 * Normalises a stored option value to a flat array.
	 *
	 * Accepts both the legacy JSON-string representation (`'["totp","email"]'`)
	 * and the modern array form (`['totp','email']`) so call sites can read the
	 * value either way without ad-hoc decoding — calling `json_decode()` on a
	 * value that is already an array is a fatal `TypeError` on PHP 8.
	 *
	 * @param mixed              $raw     Stored option value (array or JSON string).
	 * @param array<int, string> $default Returned when $raw is neither a usable array nor decodable JSON.
	 * @return array<int, string>
	 * @since  2.0.18
	 */
	public static function to_array( $raw, array $default = array() ) {
		if ( is_string( $raw ) ) {
			$decoded = json_decode( $raw, true );
			return is_array( $decoded ) ? array_values( $decoded ) : $default;
		}
		return is_array( $raw ) ? array_values( $raw ) : $default;
	}

	/**
	 * Normalises a stored 2FA-enforce-roles value to a flat array.
	 *
	 * Thin wrapper over {@see to_array()} kept for call-site readability.
	 *
	 * @param mixed $raw Stored option value.
	 * @return array<int, string>
	 * @since  2.0.0
	 */
	private static function coerce_role_list( $raw ) {
		return self::to_array( $raw );
	}

	/**
	 * Returns the list of plugin keys that live in network storage.
	 *
	 * Used by Migration_Manager during the v4→v5 promotion step on Multisite
	 * installs that previously had Hive activated per site. The list is the
	 * inverse of SITE_OPTIONS; we return all keys discovered in `wp_options`
	 * starting with `reportedip_hive_` minus the explicit site keys.
	 *
	 * @return string[]
	 * @since  2.0.0
	 */
	public static function discover_network_keys_for_promotion() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- One-shot migration discovery query; caching would defeat the purpose.
		$keys = (array) $wpdb->get_col(
			"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE 'reportedip\\_hive\\_%'"
		);
		return array_values(
			array_filter(
				$keys,
				static function ( $key ) {
					return ! self::is_site_option( $key );
				}
			)
		);
	}

	/**
	 * Delete every plugin option from both network and per-site storage.
	 *
	 * Used by uninstall.php when the user opted in to data deletion.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public static function delete_all_plugin_options() {
		global $wpdb;

		if ( is_multisite() ) {
			$site_ids = (array) get_sites( array( 'fields' => 'ids' ) );
			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );
				self::delete_all_options_on_current_site();
				restore_current_blog();
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Uninstall path: enumerate every plugin-prefixed sitemeta key for explicit deletion.
			$network_keys = (array) $wpdb->get_col(
				"SELECT meta_key FROM {$wpdb->sitemeta}
				 WHERE meta_key LIKE 'reportedip\\_hive\\_%'
				    OR meta_key LIKE '\\_site\\_transient\\_reportedip\\_hive\\_%'
				    OR meta_key LIKE '\\_site\\_transient\\_timeout\\_reportedip\\_hive\\_%'"
			);
			foreach ( $network_keys as $key ) {
				if ( 0 === strpos( $key, '_site_transient_timeout_' ) ) {
					$transient_name = substr( $key, strlen( '_site_transient_timeout_' ) );
					delete_site_transient( $transient_name );
				} elseif ( 0 === strpos( $key, '_site_transient_' ) ) {
					$transient_name = substr( $key, strlen( '_site_transient_' ) );
					delete_site_transient( $transient_name );
				} else {
					delete_site_option( $key );
				}
			}
			return;
		}

		self::delete_all_options_on_current_site();
	}

	/**
	 * Delete all plugin options and transients from the current site's `wp_options` table.
	 *
	 * The base `LIKE 'reportedip\_hive\_%'` does NOT match transient rows
	 * (`_transient_…` / `_transient_timeout_…`) — they need their own
	 * predicates. Without this every Hive transient — including the new
	 * `reportedip_hive_hardening_seen_*` and `reportedip_hive_relay_bo_*`
	 * payloads — survived deactivate/uninstall and could come back to
	 * haunt a fresh re-install.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	private static function delete_all_options_on_current_site() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Uninstall path: enumerate every plugin-prefixed wp_options key for explicit deletion.
		$keys = (array) $wpdb->get_col(
			"SELECT option_name FROM {$wpdb->options}
			 WHERE option_name LIKE 'reportedip\\_hive\\_%'
			    OR option_name LIKE '\\_transient\\_reportedip\\_hive\\_%'
			    OR option_name LIKE '\\_transient\\_timeout\\_reportedip\\_hive\\_%'"
		);
		foreach ( $keys as $key ) {
			if ( 0 === strpos( $key, '_transient_timeout_' ) ) {
				$transient_name = substr( $key, strlen( '_transient_timeout_' ) );
				delete_transient( $transient_name );
			} elseif ( 0 === strpos( $key, '_transient_' ) ) {
				$transient_name = substr( $key, strlen( '_transient_' ) );
				delete_transient( $transient_name );
			} else {
				delete_option( $key );
			}
		}
	}
}
