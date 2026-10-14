<?php
/**
 * Persistence layer for synced rulesets.
 *
 * Reads and writes the active ruleset for each key as a network-wide option
 * (routed to sitemeta on Multisite via {@see ReportedIP_Hive_Option_Routing}),
 * with a per-request static cache so repeated reads in one request do not
 * re-decode the JSON. The bundled baseline fallback lives in
 * {@see ReportedIP_Hive_Rule_Sync}; this class only owns the stored copy.
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
 * Stores and retrieves the active (synced) ruleset per key.
 *
 * @since 2.1.2
 */
final class ReportedIP_Hive_Rule_Store {

	/**
	 * Option-key prefix for stored rulesets.
	 */
	const OPTION_PREFIX = 'reportedip_hive_ruleset_';

	/**
	 * The ruleset keys the free plugin ships a baseline for. An add-on
	 * registers more through {@see self::keys()}.
	 *
	 * @var string[]
	 */
	const VALID_KEYS = array( 'waf', 'bot_signatures', 'disposable_domains', 'scan_paths' );

	/**
	 * Per-request decode cache, keyed by ruleset key.
	 *
	 * @var array<string, array<string, mixed>|null>
	 */
	private static $cache = array();

	/**
	 * True when the key is a recognised ruleset key.
	 *
	 * @param string $key Ruleset key.
	 * @return bool
	 * @since  2.1.2
	 */
	public static function is_valid_key( $key ) {
		return is_string( $key ) && in_array( $key, self::keys(), true );
	}

	/**
	 * The ruleset keys this site syncs, stores and reads: the free keys
	 * first, then the keys an add-on registers.
	 *
	 * @return string[]
	 * @since  3.0.0
	 */
	public static function keys() {
		/**
		 * Register additional ruleset keys.
		 *
		 * A listener can add keys but never drop a free one: the free keys
		 * stay in the list whatever the filter returns, and an entry that is
		 * not a lowercase slug is ignored.
		 *
		 * @param string[] $keys Ruleset keys.
		 * @since 3.0.0
		 */
		$filtered = apply_filters( 'reportedip_hive_ruleset_keys', self::VALID_KEYS );
		$keys     = self::VALID_KEYS;
		foreach ( is_array( $filtered ) ? $filtered : array() as $key ) {
			if ( is_string( $key ) && preg_match( '/^[a-z0-9_]{1,64}$/', $key ) && ! in_array( $key, $keys, true ) ) {
				$keys[] = $key;
			}
		}
		return $keys;
	}

	/**
	 * Full option key for a ruleset key.
	 *
	 * @param string $key Ruleset key.
	 * @return string
	 * @since  2.1.2
	 */
	public static function option_key( $key ) {
		return self::OPTION_PREFIX . $key;
	}

	/**
	 * Return the stored ruleset for a key, or null when none is stored / invalid.
	 *
	 * @param string $key Ruleset key.
	 * @return array<string, mixed>|null
	 * @since  2.1.2
	 */
	public static function get( $key ) {
		if ( ! self::is_valid_key( $key ) ) {
			return null;
		}
		if ( array_key_exists( $key, self::$cache ) ) {
			return self::$cache[ $key ];
		}

		$raw = ReportedIP_Hive_Option_Routing::get( self::option_key( $key ), '' );
		$out = null;
		if ( is_string( $raw ) && '' !== $raw ) {
			$decoded = json_decode( $raw, true );
			if ( is_array( $decoded ) && isset( $decoded['rules'] ) && is_array( $decoded['rules'] ) ) {
				$out = $decoded;
			}
		}

		self::$cache[ $key ] = $out;
		return $out;
	}

	/**
	 * Store a validated ruleset for a key.
	 *
	 * @param string               $key     Ruleset key.
	 * @param array<string, mixed> $ruleset Ruleset array (must contain a `rules` array).
	 * @return bool True on success.
	 * @since  2.1.2
	 */
	public static function set( $key, array $ruleset ) {
		if ( ! self::is_valid_key( $key ) || ! isset( $ruleset['rules'] ) || ! is_array( $ruleset['rules'] ) ) {
			return false;
		}
		unset( self::$cache[ $key ] );
		return (bool) ReportedIP_Hive_Option_Routing::set( self::option_key( $key ), wp_json_encode( $ruleset ) );
	}

	/**
	 * Delete the stored ruleset for a key.
	 *
	 * @param string $key Ruleset key.
	 * @return bool
	 * @since  2.1.2
	 */
	public static function delete( $key ) {
		if ( ! self::is_valid_key( $key ) ) {
			return false;
		}
		unset( self::$cache[ $key ] );
		return (bool) ReportedIP_Hive_Option_Routing::delete( self::option_key( $key ) );
	}

	/**
	 * Drop the per-request cache. Test/seam helper.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public static function flush_cache() {
		self::$cache = array();
	}
}
