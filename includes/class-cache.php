<?php
/**
 * Cache Management Class for ReportedIP Hive.
 *
 * Response cache for ReportedIP Hive API calls with ETag support
 * and batched hit/miss counter persistence.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.0.0
 *
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
 * @phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table names are safe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_Cache {

	/**
	 * Single instance of the class
	 */
	private static $instance = null;

	/**
	 * In-memory counters for batch DB updates
	 */
	private static $pending_hits        = 0;
	private static $pending_misses      = 0;
	private static $pending_sets        = 0;
	private static $shutdown_registered = false;

	private $cache_prefix       = 'reportedip_';
	private $default_ttl        = 86400;
	private $negative_cache_ttl = 7200;
	private $logger;

	/**
	 * Get single instance
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor
	 */
	private function __construct() {
		$this->logger             = ReportedIP_Hive_Logger::get_instance();
		$this->default_ttl        = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_cache_duration', 24 ) * 3600;
		$this->negative_cache_ttl = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_negative_cache_duration', 2 ) * 3600;

		if ( ! self::$shutdown_registered ) {
			register_shutdown_function( array( __CLASS__, 'flush_pending_stats' ) );
			self::$shutdown_registered = true;
		}
	}

	/**
	 * Flush pending statistics to database
	 *
	 * This is called at request shutdown to batch all counter updates into a single DB write.
	 */
	public static function flush_pending_stats() {
		if ( self::$pending_hits === 0 && self::$pending_misses === 0 && self::$pending_sets === 0 ) {
			return;
		}

		$stats = ReportedIP_Hive_Option_Routing::get(
			'reportedip_hive_cache_stats',
			array(
				'hits'       => 0,
				'misses'     => 0,
				'sets'       => 0,
				'clears'     => 0,
				'last_reset' => current_time( 'mysql', true ),
			)
		);

		$stats['hits']   += self::$pending_hits;
		$stats['misses'] += self::$pending_misses;
		$stats['sets']   += self::$pending_sets;

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_cache_stats', $stats );

		self::$pending_hits   = 0;
		self::$pending_misses = 0;
		self::$pending_sets   = 0;
	}

	/**
	 * Get cached reputation data.
	 *
	 * A verbose request must not be satisfied by a non-verbose envelope: the
	 * verbose API response carries fields (ISP, usage type, Tor flag, …) a
	 * non-verbose check never fetched. Envelopes written before the marker
	 * existed carry no `verbose` key and are treated as non-verbose. An
	 * insufficient envelope is reported as a miss but left in place so
	 * subsequent non-verbose reads can still use it.
	 *
	 * @param string $ip_address      IP address to look up.
	 * @param bool   $require_verbose Whether only a verbose envelope satisfies the read.
	 * @return array|false Cache envelope or false on miss.
	 */
	public function get_reputation( $ip_address, $require_verbose = false ) {
		if ( ! $this->is_caching_enabled() ) {
			return false;
		}

		$cache_key   = $this->get_reputation_cache_key( $ip_address );
		$cached_data = get_transient( $cache_key );

		if ( $cached_data !== false && $require_verbose && empty( $cached_data['verbose'] ) ) {
			$this->increment_cache_misses();
			return false;
		}

		if ( $cached_data !== false ) {
			$this->increment_cache_hits();

			if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_detailed_logging', false ) ) {
				$this->logger->log_security_event(
					'cache_hit',
					$ip_address,
					array(
						'cache_key'     => $cache_key,
						'cached_at'     => $cached_data['cached_at'] ?? 'unknown',
						'ttl_remaining' => $this->get_ttl_remaining( $cache_key ),
					),
					'low'
				);
			}

			return $cached_data;
		}

		$this->increment_cache_misses();
		return false;
	}

	/**
	 * Cache reputation data.
	 *
	 * @param string      $ip_address         IP address the data belongs to.
	 * @param array|false $data               Reputation payload, or false for a negative result.
	 * @param bool        $is_negative_result Whether this is a negative-cache entry (shorter TTL).
	 * @param bool        $verbose            Whether the payload came from a verbose API response.
	 * @return bool True when the transient was written.
	 */
	public function set_reputation( $ip_address, $data, $is_negative_result = false, $verbose = false ) {
		if ( ! $this->is_caching_enabled() ) {
			return false;
		}

		$cache_key = $this->get_reputation_cache_key( $ip_address );
		$ttl       = $is_negative_result ? $this->negative_cache_ttl : $this->default_ttl;

		$cache_data = array(
			'data'        => $data,
			'cached_at'   => current_time( 'mysql', true ),
			'ip_address'  => $ip_address,
			'is_negative' => $is_negative_result,
			'verbose'     => (bool) $verbose,
			'ttl'         => $ttl,
		);

		$result = set_transient( $cache_key, $cache_data, $ttl );

		if ( $result ) {
			if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_detailed_logging', false ) ) {
				$this->logger->log_security_event(
					'cache_set',
					$ip_address,
					array(
						'cache_key'   => $cache_key,
						'ttl'         => $ttl,
						'is_negative' => $is_negative_result,
						'data_size'   => strlen( wp_json_encode( $data ) ?: '' ),
					),
					'low'
				);
			}

			$this->update_cache_statistics( 'set' );
		}

		return $result;
	}

	/**
	 * Clear cache for specific IP
	 */
	public function clear_ip_cache( $ip_address ) {
		$cache_key = $this->get_reputation_cache_key( $ip_address );
		$result    = delete_transient( $cache_key );

		if ( $result ) {
			$this->logger->log_security_event(
				'cache_cleared',
				$ip_address,
				array(
					'cache_key' => $cache_key,
					'reason'    => 'manual_clear',
				),
				'low'
			);
		}

		return $result;
	}

	/**
	 * Clear all reputation cache
	 */
	public function clear_all_cache() {
		global $wpdb;

		$cache_prefix = '_transient_' . $this->cache_prefix . 'reputation_';
		$deleted      = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
				$cache_prefix . '%',
				'_transient_timeout_' . $this->cache_prefix . 'reputation_%'
			)
		);

		if ( $deleted > 0 ) {
			$this->logger->log_security_event(
				'cache_flush_all',
				'system',
				array(
					'deleted_entries' => $deleted,
					'reason'          => 'manual_flush',
				),
				'low'
			);

			$this->reset_cache_statistics();
		}

		return $deleted;
	}

	/**
	 * Get cache statistics
	 */
	public function get_cache_statistics() {
		$stats = ReportedIP_Hive_Option_Routing::get(
			'reportedip_hive_cache_stats',
			array(
				'hits'       => 0,
				'misses'     => 0,
				'sets'       => 0,
				'clears'     => 0,
				'last_reset' => current_time( 'mysql', true ),
			)
		);

		if ( ! isset( $stats['last_reset'] ) || empty( $stats['last_reset'] ) ) {
			$stats['last_reset'] = current_time( 'mysql', true );
			ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_cache_stats', $stats );
		}

		$hits           = (int) ( $stats['hits'] ?? 0 );
		$misses         = (int) ( $stats['misses'] ?? 0 );
		$total_requests = $hits + $misses;
		$hit_rate       = $total_requests > 0 ? ( $hits / $total_requests ) * 100 : 0;

		$stats['hit_rate']       = round( $hit_rate, 2 );
		$stats['total_requests'] = $total_requests;

		return $stats;
	}

	/**
	 * Estimate monthly API calls saved by caching
	 */
	public function estimate_monthly_savings() {
		$stats = $this->get_cache_statistics();

		if ( $stats['total_requests'] === 0 ) {
			return array(
				'estimated_monthly_calls_saved' => 0,
				'estimated_monthly_calls_total' => 0,
				'cache_efficiency'              => 0,
			);
		}

		$last_reset      = $stats['last_reset'] ?? current_time( 'mysql', true );
		$reset_timestamp = strtotime( $last_reset );

		if ( $reset_timestamp === false ) {
			$reset_timestamp = time() - 86400;
		}

		$days_since_reset = max( 1, ( time() - $reset_timestamp ) / 86400 );
		$daily_hits       = $stats['hits'] / $days_since_reset;
		$daily_total      = $stats['total_requests'] / $days_since_reset;

		$monthly_calls_saved = $daily_hits * 30;
		$monthly_calls_total = $daily_total * 30;

		return array(
			'estimated_monthly_calls_saved' => round( $monthly_calls_saved ),
			'estimated_monthly_calls_total' => round( $monthly_calls_total ),
			'cache_efficiency'              => $stats['hit_rate'],
		);
	}

	/**
	 * Get cache size and entry count.
	 *
	 * Two prefix-indexed queries instead of the previous self-join whose ON
	 * clause (`CONCAT`/`SUBSTRING`) could never use an index and scanned
	 * `wp_options` on both sides. LIKE prefixes are `esc_like()`-escaped —
	 * an unescaped `_transient_…` pattern treats every underscore as a
	 * single-char wildcard, which also defeated the `option_name` index.
	 * Memoised per request: the settings page asks twice per render.
	 */
	public function get_cache_info() {
		global $wpdb;

		static $request_memo = null;
		if ( null !== $request_memo ) {
			return $request_memo;
		}

		$cache_prefix = $this->cache_prefix . 'reputation_';

		$totals = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT COUNT(option_id) AS entry_count, COALESCE(SUM(LENGTH(option_value)), 0) AS total_size
                 FROM {$wpdb->options}
                 WHERE option_name LIKE %s",
				$wpdb->esc_like( '_transient_' . $cache_prefix ) . '%'
			)
		);

		$expired_count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(option_id) FROM {$wpdb->options}
                 WHERE option_name LIKE %s AND option_value < %d",
				$wpdb->esc_like( '_transient_timeout_' . $cache_prefix ) . '%',
				time()
			)
		);

		$entry_count = $totals ? (int) $totals->entry_count : 0;
		$total_size  = $totals ? (int) $totals->total_size : 0;

		$request_memo = array(
			'entry_count'      => $entry_count,
			'total_size_bytes' => $total_size,
			'total_size_mb'    => round( $total_size / 1024 / 1024, 2 ),
			'expired_count'    => $expired_count,
			'active_count'     => max( 0, $entry_count - $expired_count ),
		);

		return $request_memo;
	}

	/**
	 * Clean up expired cache entries.
	 *
	 * Covers the reputation cache AND the ETag response cache — the latter
	 * (`reportedip_etag_*` + `…_body`) was written by the API client but never
	 * matched by the old reputation-only prefix, so expired ETag rows
	 * accumulated in `wp_options` indefinitely. Deletes run as chunked
	 * `IN (…)` batches instead of two single-row DELETEs per entry.
	 */
	public function cleanup_expired_cache() {
		global $wpdb;

		$prefixes = array(
			$this->cache_prefix . 'reputation_',
			$this->cache_prefix . 'etag_',
		);

		$expired_timeouts = array();
		foreach ( $prefixes as $prefix ) {
			$expired_timeouts = array_merge(
				$expired_timeouts,
				(array) $wpdb->get_col(
					$wpdb->prepare(
						"SELECT option_name FROM {$wpdb->options}
	                 WHERE option_name LIKE %s
	                 AND option_value < %d",
						$wpdb->esc_like( '_transient_timeout_' . $prefix ) . '%',
						time()
					)
				)
			);
		}

		$cleaned    = 0;
		$delete_all = array();
		foreach ( $expired_timeouts as $timeout_key ) {
			$delete_all[] = $timeout_key;
			$delete_all[] = str_replace( '_transient_timeout_', '_transient_', $timeout_key );
			++$cleaned;
		}
		foreach ( array_chunk( $delete_all, 200 ) as $chunk ) {
			$placeholders = implode( ',', array_fill( 0, count( $chunk ), '%s' ) );
			// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $placeholders is a "%s,%s,…" list bound via $chunk.
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name IN ($placeholders)", $chunk ) );
		}

		if ( $cleaned > 0 ) {
			$this->logger->log_security_event(
				'cache_cleanup',
				'system',
				array(
					'cleaned_entries' => $cleaned,
					'reason'          => 'expired_cleanup',
				),
				'low'
			);
		}

		return $cleaned;
	}

	/**
	 * Check if caching is enabled
	 */
	private function is_caching_enabled() {
		return ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_enable_caching', true );
	}

	/**
	 * Generate cache key for IP reputation
	 */
	private function get_reputation_cache_key( $ip_address ) {
		return $this->cache_prefix . 'reputation_' . hash( 'sha256', $ip_address );
	}

	/**
	 * Get remaining TTL for cache key
	 */
	private function get_ttl_remaining( $cache_key ) {
		$timeout_key = '_transient_timeout_' . $cache_key;
		$timeout     = get_option( $timeout_key );

		if ( ! $timeout ) {
			return 0;
		}

		return max( 0, $timeout - time() );
	}

	/**
	 * Increment cache hits counter
	 *
	 * Uses in-memory counter that is flushed at request shutdown.
	 */
	private function increment_cache_hits() {
		++self::$pending_hits;
	}

	/**
	 * Increment cache misses counter
	 *
	 * Uses in-memory counter that is flushed at request shutdown.
	 */
	private function increment_cache_misses() {
		++self::$pending_misses;
	}

	/**
	 * Update cache statistics
	 *
	 * Uses in-memory counters for hits/misses/sets.
	 * Only 'clears' is written immediately (as it's a rare operation).
	 *
	 * @param string $action The action type (hits, misses, sets, clears)
	 */
	private function update_cache_statistics( $action ) {
		switch ( $action ) {
			case 'hits':
				++self::$pending_hits;
				break;
			case 'misses':
				++self::$pending_misses;
				break;
			case 'sets':
			case 'set':
				++self::$pending_sets;
				break;
			case 'clears':
			case 'clear':
				$stats = ReportedIP_Hive_Option_Routing::get(
					'reportedip_hive_cache_stats',
					array(
						'hits'       => 0,
						'misses'     => 0,
						'sets'       => 0,
						'clears'     => 0,
						'last_reset' => current_time( 'mysql', true ),
					)
				);
				++$stats['clears'];
				ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_cache_stats', $stats );
				break;
		}
	}

	/**
	 * Reset cache statistics
	 */
	private function reset_cache_statistics() {
		$stats = array(
			'hits'       => 0,
			'misses'     => 0,
			'sets'       => 0,
			'clears'     => 0,
			'last_reset' => current_time( 'mysql', true ),
		);

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_cache_stats', $stats );
	}
}
