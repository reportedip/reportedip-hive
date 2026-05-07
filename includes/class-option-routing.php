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
 * @author    Patrick Schlesinger <ps@cms-admins.de>
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
		'reportedip_hive_2fa_enforce_roles_extra'         => true,
	);

	/**
	 * Default for `2fa_frontend_slug` when neither network nor site value is set.
	 */
	public const DEFAULT_FRONTEND_SLUG = '2fa-login';

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
	 * Get an option, routed to the correct storage.
	 *
	 * @param string $key     Option name (must include `reportedip_hive_` prefix).
	 * @param mixed  $default Default value if the option is not set.
	 * @return mixed Option value or $default.
	 * @since  2.0.0
	 */
	public static function get( $key, $default = false ) {
		$key = (string) $key;
		if ( self::is_site_option( $key ) ) {
			return get_option( $key, $default );
		}
		return get_site_option( $key, $default );
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
		if ( isset( self::$resolve_cache['frontend_slug'] ) ) {
			return self::$resolve_cache['frontend_slug'];
		}
		$override = (string) get_option( 'reportedip_hive_2fa_frontend_slug_site_override', '' );
		if ( '' !== trim( $override ) ) {
			self::$resolve_cache['frontend_slug'] = $override;
			return $override;
		}
		$network = (string) get_site_option( 'reportedip_hive_2fa_frontend_slug', self::DEFAULT_FRONTEND_SLUG );
		$slug    = '' !== trim( $network ) ? $network : self::DEFAULT_FRONTEND_SLUG;
		self::$resolve_cache['frontend_slug'] = $slug;
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
		if ( isset( self::$resolve_cache['enforce_roles'] ) ) {
			return self::$resolve_cache['enforce_roles'];
		}
		$network = self::coerce_role_list( get_site_option( 'reportedip_hive_2fa_enforce_roles', array() ) );
		$extra   = self::coerce_role_list( get_option( 'reportedip_hive_2fa_enforce_roles_extra', array() ) );

		$merged = array_unique( array_merge( $network, $extra ) );
		$merged = array_values( array_filter( $merged, 'is_string' ) );
		sort( $merged );
		self::$resolve_cache['enforce_roles'] = $merged;
		return $merged;
	}

	/**
	 * Normalises a stored 2FA-enforce-roles value to a flat array.
	 *
	 * Accepts both the legacy JSON-string representation (`'["administrator"]'`)
	 * and the modern array form (`['administrator']`) so call sites can read
	 * the value either way without ad-hoc decoding.
	 *
	 * @param mixed $raw Stored option value.
	 * @return array<int, string>
	 * @since  2.0.0
	 */
	private static function coerce_role_list( $raw ) {
		if ( is_string( $raw ) ) {
			$decoded = json_decode( $raw, true );
			$raw     = is_array( $decoded ) ? $decoded : array();
		}
		return is_array( $raw ) ? array_values( $raw ) : array();
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

			$network_keys = (array) $wpdb->get_col(
				"SELECT meta_key FROM {$wpdb->sitemeta} WHERE meta_key LIKE 'reportedip\\_hive\\_%'"
			);
			foreach ( $network_keys as $key ) {
				delete_site_option( $key );
			}
			return;
		}

		self::delete_all_options_on_current_site();
	}

	/**
	 * Delete all plugin options from the current site's `wp_options` table.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	private static function delete_all_options_on_current_site() {
		global $wpdb;
		$keys = (array) $wpdb->get_col(
			"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE 'reportedip\\_hive\\_%'"
		);
		foreach ( $keys as $key ) {
			delete_option( $key );
		}
	}
}
