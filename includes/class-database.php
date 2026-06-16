<?php
/**
 * Database Management Class for ReportedIP Hive.
 *
 * This class provides database abstraction for the ReportedIP Hive plugin.
 * Direct database queries are intentional as this is the database layer.
 * Table names are constructed safely using $wpdb->base_prefix and cannot use placeholders.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.0.0
 *
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
 * @phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
 * @phpcs:disable WordPress.DB.PreparedSQL.NotPrepared
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.SchemaChange
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter -- Database layer: all table names are composed from $wpdb->base_prefix with hardcoded suffixes and cannot be parameterised. Dynamic SQL fragments are built with $wpdb->prepare(), validated allowlists, or cast integers.

class ReportedIP_Hive_Database {

	/**
	 * Single instance of the class
	 */
	private static $instance = null;

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
	public function __construct() {
	}

	/**
	 * Check if all plugin tables exist
	 *
	 * @return bool True if all tables exist
	 */
	public function tables_exist() {
		global $wpdb;

		$required_tables = array(
			$wpdb->base_prefix . 'reportedip_hive_logs',
			$wpdb->base_prefix . 'reportedip_hive_whitelist',
			$wpdb->base_prefix . 'reportedip_hive_blocked',
			$wpdb->base_prefix . 'reportedip_hive_attempts',
			$wpdb->base_prefix . 'reportedip_hive_api_queue',
			$wpdb->base_prefix . 'reportedip_hive_stats',
		);

		foreach ( $required_tables as $table ) {
			$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
			if ( ! $exists ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Check if a specific table exists
	 *
	 * @param string $table_name Full table name including prefix
	 * @return bool
	 */
	public function table_exists( $table_name ) {
		global $wpdb;

		return (bool) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) );
	}

	/**
	 * Ensure tables exist and schema is up to date.
	 *
	 * Delegated to the dedicated {@see ReportedIP_Hive_Migration_Manager}.
	 * The manager owns the lock, version tracking and step-by-step migration
	 * methods so this entry point stays a thin compatibility shim for code
	 * paths that still call into the database layer directly.
	 */
	public function maybe_update_schema() {
		ReportedIP_Hive_Migration_Manager::maybe_run();
	}

	/**
	 * Create all database tables.
	 *
	 * Thin shim around {@see ReportedIP_Hive_Schema::ensure_tables()}. Kept
	 * for compatibility with the activation hook and any external caller
	 * that still reaches into this class.
	 */
	public function create_tables() {
		ReportedIP_Hive_Schema::ensure_tables();
	}

	/**
	 * Drop all plugin tables.
	 *
	 * Thin shim around {@see ReportedIP_Hive_Schema::drop_all_tables()}.
	 */
	public function drop_tables() {
		ReportedIP_Hive_Schema::drop_all_tables();
	}

	/**
	 * Log security event
	 */
	public function log_security_event( $event_type, $ip_address, $details = array(), $severity = 'medium' ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_logs';

		return $wpdb->insert(
			$table_name,
			array(
				'blog_id'    => (int) get_current_blog_id(),
				'event_type' => $event_type,
				'ip_address' => $ip_address,
				'details'    => wp_json_encode( $details ),
				'severity'   => $severity,
			),
			array( '%d', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Get security logs
	 */
	public function get_logs( $days = 30, $limit = 1000, $event_type = null ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_logs';

		$where_clause = 'WHERE created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)';
		$params       = array( $days );

		if ( $event_type ) {
			$where_clause .= ' AND event_type = %s';
			$params[]      = $event_type;
		}

		$sql      = "SELECT * FROM $table_name $where_clause ORDER BY created_at DESC LIMIT %d";
		$params[] = $limit;

		return $wpdb->get_results( $wpdb->prepare( $sql, ...$params ) );
	}

	/**
	 * Add IP to whitelist
	 */
	public function add_to_whitelist( $ip_address, $reason = '', $added_by = null, $expires_at = null ) {
		global $wpdb;

		if ( ! is_string( $ip_address ) || $ip_address === '' ) {
			return false;
		}

		$table_name = $wpdb->base_prefix . 'reportedip_hive_whitelist';

		if ( ! $added_by ) {
			$added_by = get_current_user_id();
		}

		$ip_type = 'ipv4';
		if ( strpos( $ip_address, '/' ) !== false ) {
			$ip_type = 'cidr';
		} elseif ( strpos( $ip_address, ':' ) !== false ) {
			$ip_type = 'ipv6';
		}

		$result = $wpdb->insert(
			$table_name,
			array(
				'ip_address' => $ip_address,
				'ip_type'    => $ip_type,
				'reason'     => $reason,
				'added_by'   => $added_by,
				'expires_at' => $expires_at,
			),
			array( '%s', '%s', '%s', '%d', '%s' )
		);

		wp_cache_delete( 'rip_whitelist_cidrs', 'reportedip' );

		if ( false !== $result ) {
			/**
			 * Fires after an IP/CIDR entry was added to the whitelist.
			 *
			 * The WAF drop-in listens here to rebake the guard file so the new
			 * entry is honoured by the pre-WordPress layer immediately.
			 *
			 * @param string $ip_address Whitelisted IP or CIDR range.
			 * @since 2.1.2
			 */
			do_action( 'reportedip_hive_whitelist_changed', $ip_address );
		}

		return $result;
	}

	/**
	 * Check if IP is whitelisted
	 */
	public function is_whitelisted( $ip_address ) {
		global $wpdb;

		/*
		 * Per-request memo keyed by IP. Both the init-priority-1 IP-block gate
		 * and the WAF engine check the same client IP on every request; without
		 * this memo each visitor would cost two identical whitelist queries on
		 * the hot path. The result is stable within a request, so a function-
		 * static cache is safe (whitelist edits take effect on the next request).
		 */
		static $request_cache = array();
		if ( isset( $request_cache[ $ip_address ] ) ) {
			return $request_cache[ $ip_address ];
		}

		$table_name = $wpdb->base_prefix . 'reportedip_hive_whitelist';

		$exact_match = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $table_name
                 WHERE ip_address = %s
                 AND is_active = 1
                 AND (expires_at IS NULL OR expires_at > NOW())",
				$ip_address
			)
		);

		if ( $exact_match > 0 ) {
			$request_cache[ $ip_address ] = true;
			return true;
		}

		$cidr_ranges = wp_cache_get( 'rip_whitelist_cidrs', 'reportedip' );
		if ( false === $cidr_ranges ) {
			$cidr_ranges = $wpdb->get_col(
				"SELECT ip_address FROM $table_name
				 WHERE ip_type = 'cidr'
				 AND is_active = 1
				 AND (expires_at IS NULL OR expires_at > NOW())"
			);
			wp_cache_set( 'rip_whitelist_cidrs', $cidr_ranges, 'reportedip', 300 );
		}

		foreach ( $cidr_ranges as $cidr ) {
			if ( self::ip_in_cidr( $ip_address, $cidr ) ) {
				$request_cache[ $ip_address ] = true;
				return true;
			}
		}

		$request_cache[ $ip_address ] = false;
		return false;
	}

	/**
	 * Get whitelist entries
	 */
	public function get_whitelist( $active_only = true ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_whitelist';

		$where_clause = '';
		if ( $active_only ) {
			$where_clause = 'WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > NOW())';
		}

		return $wpdb->get_results( "SELECT * FROM $table_name $where_clause ORDER BY created_at DESC" );
	}

	/**
	 * Remove from whitelist
	 */
	public function remove_from_whitelist( $ip_address ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_whitelist';

		$exists = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM $table_name WHERE ip_address = %s AND is_active = 1",
				$ip_address
			)
		);

		if ( ! $exists ) {
			return false;
		}

		$result = $wpdb->update(
			$table_name,
			array( 'is_active' => 0 ),
			array( 'ip_address' => $ip_address ),
			array( '%d' ),
			array( '%s' )
		) !== false;

		wp_cache_delete( 'rip_whitelist_cidrs', 'reportedip' );

		if ( $result ) {
			/** This action is documented in includes/class-database.php (add_to_whitelist). */
			do_action( 'reportedip_hive_whitelist_changed', $ip_address );
		}

		return $result;
	}

	/**
	 * Fetch the active WAF exceptions (allowlist), cached network-wide.
	 *
	 * The WAF engine reads this on every front-end request, so the active set
	 * is cached for 300 seconds; {@see self::add_waf_exception()} and
	 * {@see self::remove_waf_exception()} invalidate it on write.
	 *
	 * @return array<int,object> Active exception rows ordered newest first.
	 * @since  2.1.9
	 */
	public function get_active_waf_exceptions() {
		global $wpdb;

		/*
		 * Hot-path guard: the WAF reads this on every front-end request. A count
		 * marker (default 0, so it also short-circuits before the v10 migration
		 * creates the table) skips the query entirely on the overwhelming
		 * majority of installs that hold no exceptions.
		 */
		if ( class_exists( 'ReportedIP_Hive_Option_Routing' )
			&& 0 === (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_waf_exceptions_active', 0 ) ) {
			return array();
		}

		$cached = wp_cache_get( 'rip_waf_exceptions', 'reportedip' );
		if ( false !== $cached ) {
			return $cached;
		}

		$table_name = $wpdb->base_prefix . 'reportedip_hive_waf_exceptions';
		$rows       = $wpdb->get_results( "SELECT * FROM $table_name WHERE is_active = 1 ORDER BY created_at DESC" );
		$rows       = is_array( $rows ) ? $rows : array();

		wp_cache_set( 'rip_waf_exceptions', $rows, 'reportedip', 300 );

		return $rows;
	}

	/**
	 * List WAF exceptions for the admin surface.
	 *
	 * @param bool $active_only Only active rows when true.
	 * @return array<int,object> Exception rows ordered newest first.
	 * @since  2.1.9
	 */
	public function get_waf_exceptions( $active_only = true ) {
		global $wpdb;

		$table_name   = $wpdb->base_prefix . 'reportedip_hive_waf_exceptions';
		$where_clause = $active_only ? 'WHERE is_active = 1' : '';

		$rows = $wpdb->get_results( "SELECT * FROM $table_name $where_clause ORDER BY created_at DESC" );

		return is_array( $rows ) ? $rows : array();
	}

	/**
	 * Add a WAF exception to the backend allowlist.
	 *
	 * A `scope='all'` exception with neither a path prefix nor an IP scope is
	 * rejected — it would disable the whole engine. Duplicate active rows
	 * (same scope, rule, path and IP) are not inserted twice.
	 *
	 * @param array<string,mixed> $args {
	 *     @type string      $scope       'rule', 'group' or 'all'.
	 *     @type string|null $rule_id     Rule id (scope=rule) or group name (scope=group).
	 *     @type string|null $path_prefix Optional leading-slash path prefix.
	 *     @type string|null $ip_address  Optional IP or CIDR scope.
	 *     @type string      $reason      Free-text reason.
	 *     @type int|null    $created_from_log_id Originating log row id.
	 *     @type string      $source      'manual', 'log' or 'filter'.
	 *     @type int|null    $added_by    User id; defaults to current user.
	 * }
	 * @return int|WP_Error Inserted row id, or a WP_Error on invalid input.
	 * @since  2.1.9
	 */
	public function add_waf_exception( array $args ) {
		global $wpdb;

		$scope = isset( $args['scope'] ) ? (string) $args['scope'] : 'rule';
		if ( ! in_array( $scope, array( 'rule', 'group', 'all' ), true ) ) {
			return new WP_Error( 'rip_waf_exception_scope', __( 'Invalid exception scope.', 'reportedip-hive' ) );
		}

		$rule_id     = isset( $args['rule_id'] ) ? trim( (string) $args['rule_id'] ) : '';
		$path_prefix = isset( $args['path_prefix'] ) ? trim( (string) $args['path_prefix'] ) : '';
		$ip_address  = isset( $args['ip_address'] ) ? trim( (string) $args['ip_address'] ) : '';

		if ( 'all' === $scope && '' === $path_prefix && '' === $ip_address ) {
			return new WP_Error(
				'rip_waf_exception_too_broad',
				__( 'A whole-engine exception must be scoped to at least a path or an IP address.', 'reportedip-hive' )
			);
		}

		if ( in_array( $scope, array( 'rule', 'group' ), true ) && '' === $rule_id ) {
			return new WP_Error(
				'rip_waf_exception_rule_required',
				__( 'A rule or group identifier is required for this exception scope.', 'reportedip-hive' )
			);
		}

		if ( '' !== $path_prefix && '/' !== $path_prefix[0] ) {
			$path_prefix = '/' . $path_prefix;
		}

		$ip_type = null;
		if ( '' !== $ip_address ) {
			if ( false !== strpos( $ip_address, '/' ) ) {
				$ip_type = 'cidr';
			} elseif ( false !== strpos( $ip_address, ':' ) ) {
				$ip_type = 'ipv6';
			} else {
				$ip_type = 'ipv4';
			}
			if ( 'cidr' !== $ip_type && ! filter_var( $ip_address, FILTER_VALIDATE_IP ) ) {
				return new WP_Error( 'rip_waf_exception_ip', __( 'Invalid IP address.', 'reportedip-hive' ) );
			}
		}

		$source   = isset( $args['source'] ) && in_array( $args['source'], array( 'manual', 'log', 'filter' ), true )
			? (string) $args['source']
			: 'manual';
		$added_by = isset( $args['added_by'] ) ? (int) $args['added_by'] : get_current_user_id();
		$log_id   = isset( $args['created_from_log_id'] ) && $args['created_from_log_id'] ? (int) $args['created_from_log_id'] : null;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_waf_exceptions';

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM $table_name
				 WHERE is_active = 1 AND scope = %s
				 AND COALESCE(rule_id,'') = %s
				 AND COALESCE(path_prefix,'') = %s
				 AND COALESCE(ip_address,'') = %s",
				$scope,
				$rule_id,
				$path_prefix,
				$ip_address
			)
		);
		if ( $existing ) {
			return (int) $existing;
		}

		$result = $wpdb->insert(
			$table_name,
			array(
				'scope'               => $scope,
				'rule_id'             => '' === $rule_id ? null : $rule_id,
				'path_prefix'         => '' === $path_prefix ? null : $path_prefix,
				'ip_address'          => '' === $ip_address ? null : $ip_address,
				'ip_type'             => $ip_type,
				'reason'              => isset( $args['reason'] ) ? (string) $args['reason'] : null,
				'created_from_log_id' => $log_id,
				'source'              => $source,
				'added_by'            => $added_by,
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s', '%d' )
		);

		if ( false === $result ) {
			return new WP_Error( 'rip_waf_exception_insert', __( 'Could not store the exception.', 'reportedip-hive' ) );
		}

		wp_cache_delete( 'rip_waf_exceptions', 'reportedip' );
		$this->refresh_waf_exception_count();

		/**
		 * Fires after a WAF exception was added or removed.
		 *
		 * The WAF drop-in listens here to rebake its guard file so the change
		 * is honoured by the pre-WordPress layer immediately.
		 *
		 * @since 2.1.9
		 */
		do_action( 'reportedip_hive_waf_exceptions_changed' );

		return (int) $wpdb->insert_id;
	}

	/**
	 * Soft-delete a WAF exception by id.
	 *
	 * @param int $id Exception row id.
	 * @return bool True when a row was deactivated.
	 * @since  2.1.9
	 */
	public function remove_waf_exception( $id ) {
		global $wpdb;

		$id = (int) $id;
		if ( $id <= 0 ) {
			return false;
		}

		$table_name = $wpdb->base_prefix . 'reportedip_hive_waf_exceptions';

		$result = $wpdb->update(
			$table_name,
			array( 'is_active' => 0 ),
			array( 'id' => $id ),
			array( '%d' ),
			array( '%d' )
		);

		if ( false === $result ) {
			return false;
		}

		wp_cache_delete( 'rip_waf_exceptions', 'reportedip' );
		$this->refresh_waf_exception_count();

		/** This action is documented in includes/class-database.php (add_waf_exception). */
		do_action( 'reportedip_hive_waf_exceptions_changed' );

		return $result > 0;
	}

	/**
	 * Recompute and persist the active WAF-exception count marker used by
	 * {@see self::get_active_waf_exceptions()} to skip the hot-path query when
	 * no exceptions exist.
	 *
	 * @return void
	 * @since  2.1.9
	 */
	private function refresh_waf_exception_count() {
		global $wpdb;

		if ( ! class_exists( 'ReportedIP_Hive_Option_Routing' ) ) {
			return;
		}

		$table_name = $wpdb->base_prefix . 'reportedip_hive_waf_exceptions';
		$count      = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_name WHERE is_active = 1" );

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_waf_exceptions_active', $count );
	}

	/**
	 * Block IP address
	 */
	public function block_ip( $ip_address, $reason, $block_type = 'automatic', $duration_hours = 24 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_blocked';

		$duration_hours = absint( $duration_hours );

		$blocked_until = null;
		if ( $duration_hours > 0 ) {
			$blocked_until = gmdate( 'Y-m-d H:i:s', time() + ( $duration_hours * 3600 ) );
		}

		return $wpdb->replace(
			$table_name,
			array(
				'ip_address'    => $ip_address,
				'reason'        => $reason,
				'block_type'    => $block_type,
				'blocked_until' => $blocked_until,
				'is_active'     => 1,
			),
			array( '%s', '%s', '%s', '%s', '%d' )
		);
	}

	/**
	 * Block an IP for a sub-hour duration. Used by the progressive-escalation
	 * ladder where the first ladder step is typically 5 minutes — too short
	 * to express via `block_ip( …, $duration_hours )` without losing precision.
	 *
	 * @param string $ip_address      IP to block.
	 * @param string $reason          Human-readable reason.
	 * @param string $block_type      Block source: 'automatic' | 'manual' | 'reputation'.
	 * @param int    $duration_minutes Block duration in minutes (>=1; 0 = permanent).
	 * @return int|false Number of rows affected, or false on error.
	 * @since  1.5.0
	 */
	public function block_ip_for_minutes( $ip_address, $reason, $block_type = 'automatic', $duration_minutes = 1440 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_blocked';

		$duration_minutes = absint( $duration_minutes );

		$blocked_until = null;
		if ( $duration_minutes > 0 ) {
			$blocked_until = gmdate( 'Y-m-d H:i:s', time() + ( $duration_minutes * 60 ) );
		}

		return $wpdb->replace(
			$table_name,
			array(
				'ip_address'    => $ip_address,
				'reason'        => $reason,
				'block_type'    => $block_type,
				'blocked_until' => $blocked_until,
				'is_active'     => 1,
			),
			array( '%s', '%s', '%s', '%s', '%d' )
		);
	}

	/**
	 * Check if IP is blocked
	 */
	public function is_blocked( $ip_address ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_blocked';

		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $table_name 
                 WHERE ip_address = %s 
                 AND is_active = 1 
                 AND (blocked_until IS NULL OR blocked_until > NOW())",
				$ip_address
			)
		);

		return $count > 0;
	}

	/**
	 * Get blocked IPs
	 */
	public function get_blocked_ips( $active_only = true ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_blocked';

		$where_clause = '';
		if ( $active_only ) {
			$where_clause = 'WHERE is_active = 1 AND (blocked_until IS NULL OR blocked_until > NOW())';
		}

		return $wpdb->get_results( "SELECT * FROM $table_name $where_clause ORDER BY created_at DESC" );
	}

	/**
	 * Count blocked IPs
	 *
	 * @param bool $active_only Only count active blocks
	 * @return int Number of blocked IPs
	 */
	public function count_blocked_ips( $active_only = true ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_blocked';

		$where_clause = '';
		if ( $active_only ) {
			$where_clause = 'WHERE is_active = 1 AND (blocked_until IS NULL OR blocked_until > NOW())';
		}

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_name $where_clause" );
	}

	/**
	 * Count whitelisted IPs
	 *
	 * @param bool $active_only Only count active whitelist entries
	 * @return int Number of whitelisted IPs
	 */
	public function count_whitelisted_ips( $active_only = true ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_whitelist';

		$where_clause = '';
		if ( $active_only ) {
			$where_clause = 'WHERE is_active = 1';
		}

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_name $where_clause" );
	}

	/**
	 * Unblock IP address
	 */
	public function unblock_ip( $ip_address ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_blocked';

		return $wpdb->update(
			$table_name,
			array( 'is_active' => 0 ),
			array( 'ip_address' => $ip_address ),
			array( '%d' ),
			array( '%s' )
		);
	}

	/**
	 * Track failed attempt
	 */
	public function track_attempt( $ip_address, $attempt_type, $username = null, $user_agent = null ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_attempts';

		$existing = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM $table_name 
                 WHERE ip_address = %s 
                 AND attempt_type = %s 
                 AND last_attempt > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
				$ip_address,
				$attempt_type
			)
		);

		if ( $existing ) {
			return $wpdb->update(
				$table_name,
				array(
					'attempt_count' => $existing->attempt_count + 1,
					'username'      => $username ?: $existing->username,
					'user_agent'    => $user_agent ?: $existing->user_agent,
					'last_attempt'  => current_time( 'mysql' ),
				),
				array( 'id' => $existing->id ),
				array( '%d', '%s', '%s', '%s' ),
				array( '%d' )
			);
		} else {
			return $wpdb->insert(
				$table_name,
				array(
					'ip_address'    => $ip_address,
					'attempt_type'  => $attempt_type,
					'username'      => $username,
					'user_agent'    => $user_agent,
					'attempt_count' => 1,
				),
				array( '%s', '%s', '%s', '%s', '%d' )
			);
		}
	}

	/**
	 * Get attempt count for IP and type within timeframe
	 */
	public function get_attempt_count( $ip_address, $attempt_type, $minutes = 15 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_attempts';

		$result = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COALESCE(SUM(attempt_count), 0) FROM $table_name 
                 WHERE ip_address = %s 
                 AND attempt_type = %s 
                 AND last_attempt > DATE_SUB(NOW(), INTERVAL %d MINUTE)",
				$ip_address,
				$attempt_type,
				$minutes
			)
		);

		return intval( $result );
	}

	/**
	 * Reset attempt counter for IP
	 */
	public function reset_attempt_counter( $ip_address, $attempt_type = null ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_attempts';

		$where        = array( 'ip_address' => $ip_address );
		$where_format = array( '%s' );

		if ( $attempt_type ) {
			$where['attempt_type'] = $attempt_type;
			$where_format[]        = '%s';
		}

		return $wpdb->delete( $table_name, $where, $where_format );
	}

	/**
	 * Check if IP was recently processed (blocked or reported)
	 */
	public function is_recently_processed( $ip_address, $hours = 24 ) {
		global $wpdb;

		$queue_table = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		$recently_reported = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $queue_table
                 WHERE ip_address = %s
                 AND report_type = 'negative'
                 AND status = 'completed'
                 AND created_at > DATE_SUB(NOW(), INTERVAL %d HOUR)",
				$ip_address,
				$hours
			)
		);

		if ( $recently_reported > 0 ) {
			return array(
				'processed' => true,
				'reason'    => 'recently_reported',
				'details'   => 'IP was successfully reported to API within the last ' . $hours . ' hours',
			);
		}

		return array(
			'processed' => false,
			'reason'    => null,
			'details'   => null,
		);
	}

	/**
	 * Add to API report queue
	 */
	public function queue_api_report( $ip_address, $category_ids, $comment, $report_type = 'negative', $priority = 'normal' ) {
		global $wpdb;

		/*
		 * Never queue a non-public address. An `unknown`, loopback or private
		 * IP cannot be a community threat — the remote API rejects it ("invalid
		 * ip" / "whitelisted local") after three wasted retries. Drop it here so
		 * a mis-detected internal request never reaches the queue at all.
		 */
		if ( class_exists( 'ReportedIP_Hive' ) && ! ReportedIP_Hive::is_public_ip( $ip_address ) ) {
			return false;
		}

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		$cooldown_hours = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_cooldown_hours', 24 );

		$recent_check = $this->is_recently_processed( $ip_address, $cooldown_hours );
		if ( $recent_check['processed'] ) {
			return false;
		}

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $table_name
                 WHERE ip_address = %s
                 AND report_type = %s
                 AND (
                     ( status IN ('pending', 'processing') AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR) )
                     OR
                     ( status = 'failed' AND last_attempt IS NOT NULL AND last_attempt > DATE_SUB(NOW(), INTERVAL 15 MINUTE) )
                 )",
				$ip_address,
				$report_type
			)
		);

		if ( $existing > 0 ) {
			return false;
		}

		return $wpdb->insert(
			$table_name,
			array(
				'blog_id'      => (int) get_current_blog_id(),
				'ip_address'   => $ip_address,
				'category_ids' => is_array( $category_ids ) ? implode( ',', $category_ids ) : $category_ids,
				'comment'      => $comment,
				'report_type'  => $report_type,
				'priority'     => $priority,
			),
			array( '%d', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Get pending API reports (includes failed reports that haven't exceeded max_attempts)
	 */
	public function get_pending_api_reports( $limit = 10 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM $table_name
                 WHERE status IN ('pending', 'failed')
                 AND attempts < max_attempts
                 ORDER BY
                    CASE status
                        WHEN 'pending' THEN 0
                        WHEN 'failed' THEN 1
                    END,
                    priority DESC,
                    created_at ASC
                 LIMIT %d",
				$limit
			)
		);
	}

	/**
	 * Update API report status
	 */
	public function update_api_report_status( $report_id, $status, $error_message = null ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		$data = array(
			'status'       => $status,
			'last_attempt' => current_time( 'mysql' ),
		);

		if ( $error_message ) {
			$data['error_message'] = $error_message;
		}

		if ( $status === 'processing' ) {
			return $wpdb->query(
				$wpdb->prepare(
					"UPDATE $table_name
                     SET status = %s, attempts = attempts + 1, last_attempt = %s, error_message = %s
                     WHERE id = %d",
					$status,
					$data['last_attempt'],
					$error_message,
					$report_id
				)
			);
		} else {
			return $wpdb->update(
				$table_name,
				$data,
				array( 'id' => $report_id ),
				array( '%s', '%s', '%s' ),
				array( '%d' )
			);
		}
	}

	/**
	 * Stamp `submitted_at` immediately before the HTTP call so the recovery
	 * sweep can tell rows that are legitimately in flight from rows whose
	 * worker crashed mid-request.
	 *
	 * @param int $report_id Queue row id.
	 * @return int|false Number of rows updated, or false on error.
	 * @since 1.5.3
	 */
	public function mark_report_submitted( $report_id ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		return $wpdb->update(
			$table_name,
			array( 'submitted_at' => current_time( 'mysql' ) ),
			array( 'id' => (int) $report_id ),
			array( '%s' ),
			array( '%d' )
		);
	}

	/**
	 * Recover queue rows that transitioned to `processing` but never finished.
	 *
	 * A worker that crashes between `update_api_report_status('processing')`
	 * and the terminal `completed`/`failed` update leaves its row stranded:
	 * `get_pending_api_reports()` filters on `IN ('pending','failed')` so the
	 * stuck row is invisible to every subsequent cron run, and the cleanup
	 * cron only deletes `pending|failed`. Combined with `is_recently_processed()`
	 * counting `processing` toward the cooldown, a single crashed row can
	 * silently suppress all reports for that IP for 24 h+.
	 *
	 * Rows whose `submitted_at` is recent are assumed to still be in flight
	 * and are skipped — only rows older than `processing_timeout_minutes`
	 * (or with NULL `submitted_at` and a similarly aged `last_attempt`) are
	 * recovered.
	 *
	 * `attempts` is NOT incremented here: the counter was already bumped at
	 * the original transition into `processing` (see `update_api_report_status`).
	 * Re-incrementing would double-charge a single legitimate crash.
	 *
	 * @param int $timeout_minutes Minutes after which a `processing` row is
	 *                             treated as crashed. Default 10.
	 * @return array{reset:int, failed:int} Counts of rows reset to `pending`
	 *                                      and rows marked `failed` (retries
	 *                                      exhausted).
	 * @since 1.5.3
	 */
	public function recover_stuck_processing( $timeout_minutes = 10 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';
		$timeout    = max( 1, (int) $timeout_minutes );

		$reset = $wpdb->query(
			$wpdb->prepare(
				"UPDATE $table_name
                 SET status = 'pending', error_message = 'recovered: stuck processing'
                 WHERE status = 'processing'
                   AND attempts < max_attempts
                   AND (
                     ( submitted_at IS NOT NULL AND submitted_at < DATE_SUB(NOW(), INTERVAL %d MINUTE) )
                     OR
                     ( submitted_at IS NULL AND ( last_attempt IS NULL OR last_attempt < DATE_SUB(NOW(), INTERVAL %d MINUTE) ) )
                   )",
				$timeout,
				$timeout
			)
		);

		$failed = $wpdb->query(
			$wpdb->prepare(
				"UPDATE $table_name
                 SET status = 'failed', error_message = 'recovered: stuck processing, retries exhausted'
                 WHERE status = 'processing'
                   AND attempts >= max_attempts
                   AND (
                     ( submitted_at IS NOT NULL AND submitted_at < DATE_SUB(NOW(), INTERVAL %d MINUTE) )
                     OR
                     ( submitted_at IS NULL AND ( last_attempt IS NULL OR last_attempt < DATE_SUB(NOW(), INTERVAL %d MINUTE) ) )
                   )",
				$timeout,
				$timeout
			)
		);

		return array(
			'reset'  => false === $reset ? 0 : (int) $reset,
			'failed' => false === $failed ? 0 : (int) $failed,
		);
	}

	/**
	 * Update daily statistics
	 */
	public function update_daily_stats( $stat_type, $increment = 1 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_stats';
		$today      = gmdate( 'Y-m-d' );

		$valid_stats = array( 'failed_logins', 'blocked_ips', 'comment_spam', 'xmlrpc_calls', 'api_reports_sent', 'reputation_blocks' );

		if ( ! in_array( $stat_type, $valid_stats ) ) {
			return false;
		}

		$blog_id = (int) get_current_blog_id();

		return $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO $table_name (blog_id, stat_date, $stat_type) VALUES (%d, %s, %d)
                 ON DUPLICATE KEY UPDATE $stat_type = $stat_type + %d",
				$blog_id,
				$today,
				$increment,
				$increment
			)
		);
	}

	/**
	 * Get statistics for date range
	 */
	public function get_statistics( $days = 30 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_stats';

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM $table_name 
                 WHERE stat_date >= DATE_SUB(CURDATE(), INTERVAL %d DAY) 
                 ORDER BY stat_date DESC",
				$days
			)
		);
	}

	/**
	 * Anonymize old data for GDPR compliance
	 */
	public function anonymize_old_data( $days = 7 ) {
		global $wpdb;

		$anonymized = 0;

		$logs_table = $wpdb->base_prefix . 'reportedip_hive_logs';

		$old_logs = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, details FROM $logs_table 
                 WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)
                 AND created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days,
				ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_data_retention_days', 30 )
			)
		);

		foreach ( $old_logs as $log ) {
			$details = json_decode( $log->details, true );
			if ( is_array( $details ) ) {
				$personal_fields    = array( 'username', 'username_hash', 'author', 'author_hash', 'user_agent', 'referer', 'referer_domain' );
				$anonymized_details = array_diff_key( $details, array_flip( $personal_fields ) );

				$anonymized_details['anonymized']    = true;
				$anonymized_details['anonymized_at'] = current_time( 'mysql' );

				$wpdb->update(
					$logs_table,
					array( 'details' => wp_json_encode( $anonymized_details ) ),
					array( 'id' => $log->id ),
					array( '%s' ),
					array( '%d' )
				);

				++$anonymized;
			}
		}

		$attempts_table      = $wpdb->base_prefix . 'reportedip_hive_attempts';
		$anonymized_attempts = $wpdb->query(
			$wpdb->prepare(
				"UPDATE $attempts_table 
                 SET username = NULL, user_agent = NULL 
                 WHERE last_attempt < DATE_SUB(NOW(), INTERVAL %d DAY)
                 AND (username IS NOT NULL OR user_agent IS NOT NULL)",
				$days
			)
		);

		if ( $anonymized_attempts !== false ) {
			$anonymized += $anonymized_attempts;
		}

		return $anonymized;
	}

	/**
	 * Clean up old data
	 */
	public function cleanup_old_data( $days = 30 ) {
		global $wpdb;

		$deleted = 0;

		$tables_to_clean = array(
			$wpdb->base_prefix . 'reportedip_hive_logs' => 'created_at',
			$wpdb->base_prefix . 'reportedip_hive_attempts' => 'last_attempt',
			$wpdb->base_prefix . 'reportedip_hive_api_queue' => 'created_at',
		);

		foreach ( $tables_to_clean as $table => $date_column ) {
			$result = $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM $table WHERE $date_column < DATE_SUB(NOW(), INTERVAL %d DAY)",
					$days
				)
			);
			if ( $result !== false ) {
				$deleted += $result;
			}
		}

		$completed_reports = $wpdb->query(
			"DELETE FROM {$wpdb->base_prefix}reportedip_hive_api_queue
             WHERE status = 'completed'
             AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)"
		);

		if ( $completed_reports !== false ) {
			$deleted += $completed_reports;
		}

		$failed_reports = $wpdb->query(
			"DELETE FROM {$wpdb->base_prefix}reportedip_hive_api_queue
             WHERE status = 'failed'
             AND attempts >= max_attempts
             AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)"
		);

		if ( $failed_reports !== false ) {
			$deleted += $failed_reports;
		}

		$queue_max_age = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_queue_max_age_days', 7 );
		$old_pending   = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->base_prefix}reportedip_hive_api_queue
				 WHERE status IN ('pending', 'failed')
				 AND created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
				$queue_max_age
			)
		);

		if ( $old_pending !== false ) {
			$deleted += $old_pending;
		}

		return $deleted;
	}

	/**
	 * Get failed API reports
	 *
	 * @param int $limit Maximum number of reports to return
	 * @return array Failed API reports
	 */
	public function get_failed_api_reports( $limit = 50 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM $table_name
                 WHERE status = 'failed'
                 ORDER BY created_at DESC
                 LIMIT %d",
				$limit
			)
		);
	}

	/**
	 * Get API queue statistics
	 *
	 * @return array Queue statistics by status
	 */
	public function get_queue_statistics() {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		$results = $wpdb->get_results(
			"SELECT status, COUNT(*) as count
             FROM $table_name
             GROUP BY status",
			OBJECT_K
		);

		$stats = array(
			'pending'    => 0,
			'processing' => 0,
			'completed'  => 0,
			'failed'     => 0,
			'total'      => 0,
		);

		foreach ( $results as $status => $row ) {
			$stats[ $status ] = (int) $row->count;
			$stats['total']  += (int) $row->count;
		}

		$retryable          = $wpdb->get_var(
			"SELECT COUNT(*) FROM $table_name
             WHERE status = 'failed'
             AND attempts < max_attempts"
		);
		$stats['retryable'] = (int) $retryable;

		$stats['permanently_failed'] = $stats['failed'] - $stats['retryable'];

		$last_success          = $wpdb->get_var(
			"SELECT MAX(last_attempt) FROM $table_name
             WHERE status = 'completed'"
		);
		$stats['last_success'] = $last_success;

		$oldest_pending          = $wpdb->get_var(
			"SELECT MIN(created_at) FROM $table_name
             WHERE status = 'pending'"
		);
		$stats['oldest_pending'] = $oldest_pending;

		return $stats;
	}

	/**
	 * Get current queue size (pending and retryable failed items)
	 *
	 * @return int Number of pending reports in queue
	 */
	public function get_queue_size() {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		return (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM $table_name
			 WHERE status IN ('pending', 'failed')
			 AND attempts < max_attempts"
		);
	}

	/**
	 * Get queue age (oldest pending item)
	 *
	 * @return string|null Datetime of oldest item or null
	 */
	public function get_oldest_queue_item_date() {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		return $wpdb->get_var(
			"SELECT MIN(created_at) FROM $table_name
			 WHERE status IN ('pending', 'failed')
			 AND attempts < max_attempts"
		);
	}

	/**
	 * Get queue age in days
	 *
	 * @return int|null Days since oldest item or null if queue empty
	 */
	public function get_queue_age_days() {
		$oldest = $this->get_oldest_queue_item_date();

		if ( ! $oldest ) {
			return null;
		}

		$oldest_timestamp = strtotime( $oldest );
		$diff_seconds     = time() - $oldest_timestamp;

		return (int) floor( $diff_seconds / DAY_IN_SECONDS );
	}

	/**
	 * Get queue summary for admin display
	 *
	 * @return array Queue summary with size, age, and status breakdown
	 */
	public function get_queue_summary() {
		$stats = $this->get_queue_statistics();

		return array(
			'total_pending' => $stats['pending'] + $stats['retryable'],
			'pending'       => $stats['pending'],
			'failed'        => $stats['failed'],
			'retryable'     => $stats['retryable'],
			'completed'     => $stats['completed'],
			'oldest_date'   => $this->get_oldest_queue_item_date(),
			'age_days'      => $this->get_queue_age_days(),
			'last_success'  => $stats['last_success'],
		);
	}

	/**
	 * Get all API queue items for display
	 *
	 * @param array $args Query arguments (status, limit, offset, orderby, order)
	 * @return array Queue items
	 */
	public function get_api_queue_items( $args = array() ) {
		global $wpdb;

		$defaults = array(
			'status'  => '',
			'limit'   => 20,
			'offset'  => 0,
			'orderby' => 'created_at',
			'order'   => 'DESC',
			'search'  => '',
		);

		$args       = wp_parse_args( $args, $defaults );
		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		$where = array( '1=1' );

		if ( ! empty( $args['status'] ) ) {
			$where[] = $wpdb->prepare( 'status = %s', $args['status'] );
		}

		if ( ! empty( $args['search'] ) ) {
			$search  = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where[] = $wpdb->prepare( '(ip_address LIKE %s OR comment LIKE %s)', $search, $search );
		}

		$where_clause = implode( ' AND ', $where );

		$allowed_orderby = array( 'id', 'ip_address', 'status', 'priority', 'attempts', 'created_at', 'last_attempt' );
		$orderby         = in_array( $args['orderby'] ?? '', $allowed_orderby ) ? $args['orderby'] : 'created_at';
		$order           = strtoupper( $args['order'] ?? 'DESC' ) === 'ASC' ? 'ASC' : 'DESC';

		$sql = $wpdb->prepare(
			"SELECT * FROM $table_name
             WHERE $where_clause
             ORDER BY $orderby $order
             LIMIT %d OFFSET %d",
			$args['limit'],
			$args['offset']
		);

		return $wpdb->get_results( $sql );
	}

	/**
	 * Count API queue items
	 *
	 * @param string $status Filter by status (optional)
	 * @param string $search Search term (optional)
	 * @return int Count
	 */
	public function count_api_queue_items( $status = '', $search = '' ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		$where = array( '1=1' );

		if ( ! empty( $status ) ) {
			$where[] = $wpdb->prepare( 'status = %s', $status );
		}

		if ( ! empty( $search ) ) {
			$search_term = '%' . $wpdb->esc_like( $search ) . '%';
			$where[]     = $wpdb->prepare( '(ip_address LIKE %s OR comment LIKE %s)', $search_term, $search_term );
		}

		$where_clause = implode( ' AND ', $where );

		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_name WHERE $where_clause" );
	}

	/**
	 * Reset report for retry
	 *
	 * @param int $report_id Report ID
	 * @return bool Success
	 */
	public function reset_report_for_retry( $report_id ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		return $wpdb->update(
			$table_name,
			array(
				'status'        => 'pending',
				'attempts'      => 0,
				'error_message' => null,
				'last_attempt'  => null,
			),
			array( 'id' => $report_id ),
			array( '%s', '%d', '%s', '%s' ),
			array( '%d' )
		) !== false;
	}

	/**
	 * Reset all failed reports for retry
	 *
	 * Resets every failed row, including ones that already exhausted
	 * max_attempts: this is a manual, admin-initiated action that
	 * deliberately overrides the automatic retry ceiling enforced by cron.
	 *
	 * @return int Number of reports reset
	 */
	public function reset_all_failed_reports() {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		$result = $wpdb->query(
			"UPDATE $table_name
             SET status = 'pending', attempts = 0, error_message = NULL, last_attempt = NULL
             WHERE status = 'failed'"
		);

		return $result !== false ? $result : 0;
	}

	/**
	 * Delete API queue item
	 *
	 * @param int $report_id Report ID
	 * @return bool Success
	 */
	public function delete_api_queue_item( $report_id ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		return $wpdb->delete(
			$table_name,
			array( 'id' => $report_id ),
			array( '%d' )
		) !== false;
	}

	/**
	 * Delete all failed reports that exceeded max_attempts
	 *
	 * @return int Number of reports deleted
	 */
	public function delete_permanently_failed_reports() {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_api_queue';

		$result = $wpdb->query(
			"DELETE FROM $table_name
             WHERE status = 'failed'
             AND attempts >= max_attempts"
		);

		return $result !== false ? $result : 0;
	}

	/**
	 * Check whether an IP falls inside a CIDR range (or equals a bare IP).
	 *
	 * Pure, dependency-free and side-effect-free so sensors that need a
	 * request-path CIDR test (e.g. the verified-bot IP-range match) can reuse
	 * one canonical IPv4/IPv6 implementation instead of duplicating it.
	 *
	 * @param string $ip   Candidate IP address.
	 * @param string $cidr CIDR range (`192.0.2.0/24`, `2001:db8::/32`) or a bare IP.
	 * @return bool True when the IP is inside the range.
	 * @since  2.1.2
	 */
	public static function ip_in_cidr( $ip, $cidr ) {
		if ( ! is_string( $ip ) || ! is_string( $cidr ) || $ip === '' || $cidr === '' ) {
			return false;
		}

		if ( strpos( $cidr, '/' ) === false ) {
			return $ip === $cidr;
		}

		list($subnet, $mask) = explode( '/', $cidr, 2 );
		if ( ! is_numeric( $mask ) ) {
			return false;
		}
		$mask = (int) $mask;

		$ip_is_v4     = (bool) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
		$subnet_is_v4 = (bool) filter_var( $subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );

		/*
		 * The IP and the CIDR must be the same family. A v4 address can never
		 * fall inside a v6 range (or vice-versa), and — critically — testing a
		 * v4 IP against a v6 CIDR is exactly what fed a /33..128 mask into the
		 * 32-bit shift below and raised "bit shift by negative number". Reject
		 * the mismatch instead of crashing the request.
		 */
		if ( $ip_is_v4 !== $subnet_is_v4 ) {
			return false;
		}

		if ( $ip_is_v4 ) {
			if ( $mask < 0 || $mask > 32 ) {
				return false;
			}
			$ip_long     = ip2long( $ip );
			$subnet_long = ip2long( $subnet );
			if ( false === $ip_long || false === $subnet_long ) {
				return false;
			}
			$mask_long = ( 0 === $mask ) ? 0 : ( -1 << ( 32 - $mask ) );
			return ( $ip_long & $mask_long ) === ( $subnet_long & $mask_long );
		}

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) || $mask < 0 || $mask > 128 ) {
			return false;
		}

		$ip_bin     = inet_pton( $ip );
		$subnet_bin = inet_pton( $subnet );
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$bytes = intdiv( $mask, 8 );
		$bits  = $mask % 8;

		for ( $i = 0; $i < $bytes; $i++ ) {
			if ( $ip_bin[ $i ] !== $subnet_bin[ $i ] ) {
				return false;
			}
		}

		if ( $bits > 0 ) {
			$mask_byte = ( 0xFF << ( 8 - $bits ) ) & 0xFF;
			return ( ord( $ip_bin[ $bytes ] ) & $mask_byte ) === ( ord( $subnet_bin[ $bytes ] ) & $mask_byte );
		}

		return true;
	}

	/**
	 * Get log statistics for debugging
	 */
	public function get_log_statistics( $days = 7 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_logs';

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT event_type, severity, COUNT(*) as count, COUNT(DISTINCT ip_address) as unique_ips
                 FROM $table_name 
                 WHERE created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
                 GROUP BY event_type, severity
                 ORDER BY count DESC",
				$days
			)
		);
	}

	/**
	 * Get recent critical events for dashboard.
	 *
	 * The `details` field is stored as JSON; we decode it here so callers
	 * (Admin dashboard) get an array directly.
	 *
	 * @param int $hours Lookback window in hours.
	 * @param int $limit Maximum rows.
	 * @return array Event rows with `details` decoded to array.
	 */
	public function get_recent_critical_events( $hours = 24, $limit = 10 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_logs';
		$cutoff_utc = gmdate( 'Y-m-d H:i:s', time() - max( 1, (int) $hours ) * HOUR_IN_SECONDS );

		$events = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM $table_name
                 WHERE severity IN ('high', 'critical')
                   AND ( created_at >= %s OR created_at >= DATE_SUB(NOW(), INTERVAL %d HOUR) )
                 ORDER BY created_at DESC
                 LIMIT %d",
				$cutoff_utc,
				$hours,
				$limit
			)
		);

		foreach ( $events as $event ) {
			if ( is_string( $event->details ) ) {
				$event->details = json_decode( $event->details, true );
			}
		}

		return $events;
	}

	/**
	 * Get recent events for the dashboard activity feed (any severity).
	 *
	 * Counterpart to {@see get_recent_critical_events()} for the
	 * "Recent Activity" widget which should surface the full event stream,
	 * not just high/critical entries. Uses a PHP-computed UTC cutoff OR'd
	 * with the MySQL relative cutoff so a misaligned MySQL session timezone
	 * cannot make the list collapse to zero rows.
	 *
	 * @param int $hours Lookback window in hours.
	 * @param int $limit Maximum rows.
	 * @return array Event rows with `details` decoded to array.
	 */
	public function get_recent_events( $hours = 24, $limit = 10 ) {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_logs';
		$cutoff_utc = gmdate( 'Y-m-d H:i:s', time() - max( 1, (int) $hours ) * HOUR_IN_SECONDS );

		$events = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM $table_name
                 WHERE created_at >= %s OR created_at >= DATE_SUB(NOW(), INTERVAL %d HOUR)
                 ORDER BY created_at DESC
                 LIMIT %d",
				$cutoff_utc,
				$hours,
				$limit
			)
		);

		foreach ( $events as $event ) {
			if ( is_string( $event->details ) ) {
				$event->details = json_decode( $event->details, true );
			}
		}

		return $events;
	}

	/**
	 * Get recent events restricted to a set of event types (firewall overview).
	 *
	 * Mirrors {@see get_recent_events()} including the dual UTC/MySQL cutoff,
	 * but filters on an explicit event-type whitelist so a surface can show only
	 * its own sensors' stream.
	 *
	 * @param string[] $event_types Event types to include.
	 * @param int      $hours       Lookback window in hours.
	 * @param int      $limit       Maximum rows.
	 * @return array Event rows with `details` decoded to array.
	 */
	public function get_recent_events_by_types( array $event_types, $hours = 24, $limit = 10 ) {
		global $wpdb;

		$event_types = array_values( array_filter( array_map( 'strval', $event_types ) ) );
		if ( empty( $event_types ) ) {
			return array();
		}

		$table_name   = $wpdb->base_prefix . 'reportedip_hive_logs';
		$cutoff_utc   = gmdate( 'Y-m-d H:i:s', time() - max( 1, (int) $hours ) * HOUR_IN_SECONDS );
		$placeholders = implode( ',', array_fill( 0, count( $event_types ), '%s' ) );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $placeholders is a generated %s list; values are bound below.
		$events = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM $table_name
                 WHERE event_type IN ($placeholders)
                   AND (created_at >= %s OR created_at >= DATE_SUB(NOW(), INTERVAL %d HOUR))
                 ORDER BY created_at DESC
                 LIMIT %d",
				array_merge( $event_types, array( $cutoff_utc, $hours, $limit ) )
			)
		);

		foreach ( $events as $event ) {
			if ( is_string( $event->details ) ) {
				$event->details = json_decode( $event->details, true );
			}
		}

		return $events;
	}

	/**
	 * Count events per event type within a lookback window (firewall overview).
	 *
	 * @param string[] $event_types Event types to count.
	 * @param int      $hours       Lookback window in hours.
	 * @return array<string,int> Map of event type to count (missing types are 0).
	 */
	public function get_event_type_counts( array $event_types, $hours = 24 ) {
		global $wpdb;

		$event_types = array_values( array_filter( array_map( 'strval', $event_types ) ) );
		$counts      = array_fill_keys( $event_types, 0 );
		if ( empty( $event_types ) ) {
			return $counts;
		}

		$table_name   = $wpdb->base_prefix . 'reportedip_hive_logs';
		$cutoff_utc   = gmdate( 'Y-m-d H:i:s', time() - max( 1, (int) $hours ) * HOUR_IN_SECONDS );
		$placeholders = implode( ',', array_fill( 0, count( $event_types ), '%s' ) );

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $placeholders is a generated %s list; values are bound below.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT event_type, COUNT(*) AS cnt FROM $table_name
                 WHERE event_type IN ($placeholders)
                   AND (created_at >= %s OR created_at >= DATE_SUB(NOW(), INTERVAL %d HOUR))
                 GROUP BY event_type",
				array_merge( $event_types, array( $cutoff_utc, $hours ) )
			)
		);

		foreach ( (array) $rows as $row ) {
			if ( isset( $counts[ $row->event_type ] ) ) {
				$counts[ $row->event_type ] = (int) $row->cnt;
			}
		}

		return $counts;
	}

	/**
	 * Get IP management statistics
	 */
	public function get_ip_management_stats() {
		global $wpdb;

		$blocked_table   = $wpdb->base_prefix . 'reportedip_hive_blocked';
		$whitelist_table = $wpdb->base_prefix . 'reportedip_hive_whitelist';

		$stats = array();

		$stats['active_blocked'] = $wpdb->get_var(
			"SELECT COUNT(*) FROM $blocked_table 
             WHERE is_active = 1 
             AND (blocked_until IS NULL OR blocked_until > NOW())"
		);

		$stats['expired_blocked'] = $wpdb->get_var(
			"SELECT COUNT(*) FROM $blocked_table 
             WHERE is_active = 1 
             AND blocked_until IS NOT NULL 
             AND blocked_until <= NOW()"
		);

		$stats['active_whitelist'] = $wpdb->get_var(
			"SELECT COUNT(*) FROM $whitelist_table 
             WHERE is_active = 1 
             AND (expires_at IS NULL OR expires_at > NOW())"
		);

		$stats['expired_whitelist'] = $wpdb->get_var(
			"SELECT COUNT(*) FROM $whitelist_table 
             WHERE is_active = 1 
             AND expires_at IS NOT NULL 
             AND expires_at <= NOW()"
		);

		$stats['expired_entries'] = $stats['expired_blocked'] + $stats['expired_whitelist'];

		return $stats;
	}

	/**
	 * Get security summary for reports
	 */
	public function get_security_summary( $days = 30 ) {
		global $wpdb;

		$logs_table  = $wpdb->base_prefix . 'reportedip_hive_logs';
		$stats_table = $wpdb->base_prefix . 'reportedip_hive_stats';

		$event_counts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT event_type, COUNT(*) as count
                 FROM $logs_table 
                 WHERE created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
                 GROUP BY event_type",
				$days
			)
		);

		$aggregated_stats = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT 
                    SUM(failed_logins) as total_failed_logins,
                    SUM(blocked_ips) as total_blocked_ips,
                    SUM(comment_spam) as total_comment_spam,
                    SUM(xmlrpc_calls) as total_xmlrpc_calls,
                    SUM(api_reports_sent) as total_api_reports,
                    SUM(reputation_blocks) as total_reputation_blocks
                 FROM $stats_table 
                 WHERE stat_date >= DATE_SUB(CURDATE(), INTERVAL %d DAY)",
				$days
			)
		);

		return array(
			'event_counts' => $event_counts,
			'summary'      => $aggregated_stats ?: (object) array(
				'total_failed_logins'     => 0,
				'total_blocked_ips'       => 0,
				'total_comment_spam'      => 0,
				'total_xmlrpc_calls'      => 0,
				'total_api_reports'       => 0,
				'total_reputation_blocks' => 0,
			),
		);
	}

	/**
	 * Aggregate threat telemetry for the Security Dashboard.
	 *
	 * A single pass over the logs table, folded through
	 * {@see ReportedIP_Hive_Event_Taxonomy} into per-day family time series plus
	 * family/severity totals, a WAF rule-group breakdown, period/today totals and
	 * the most active attacker IPs. Network-wide (base_prefix); on single site
	 * identical to the local scope. The window guard OR's a PHP-computed UTC
	 * cutoff with the MySQL relative cutoff so a skewed DB session timezone cannot
	 * collapse the result to zero (mirrors {@see get_recent_events()}).
	 *
	 * @param int $days Lookback window in days (clamped 1..90).
	 * @return array{
	 *     days:int,
	 *     labels:array<int,string>,
	 *     families:array<int,array{key:string,label:string,data:array<int,int>}>,
	 *     by_family:array<string,int>,
	 *     by_severity:array{critical:int,high:int,medium:int,low:int},
	 *     waf_groups:array<string,int>,
	 *     totals:array{period:int,today:int},
	 *     top_ips:array<int,array{ip:string,count:int,last_seen:string,blocked:bool}>
	 * }
	 * @since 2.1.13
	 */
	public function get_threat_analytics( $days = 7 ) {
		global $wpdb;

		$days       = max( 1, min( 90, (int) $days ) );
		$logs_table = $wpdb->base_prefix . 'reportedip_hive_logs';
		$cutoff_utc = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );

		$labels_map  = ReportedIP_Hive_Event_Taxonomy::labels();
		$family_keys = array_keys( $labels_map );

		$labels   = array();
		$date_pos = array();
		$now      = time();
		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$day_ts            = $now - $i * DAY_IN_SECONDS;
			$date              = gmdate( 'Y-m-d', $day_ts );
			$date_pos[ $date ] = count( $labels );
			$labels[]          = date_i18n( 'M j', $day_ts );
		}

		$series    = array();
		$by_family = array();
		foreach ( $family_keys as $fkey ) {
			$series[ $fkey ]    = array_fill( 0, $days, 0 );
			$by_family[ $fkey ] = 0;
		}
		$by_severity = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
		);

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE(created_at) AS d, event_type, severity, COUNT(*) AS c
				 FROM $logs_table
				 WHERE created_at >= %s OR created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
				 GROUP BY DATE(created_at), event_type, severity",
				$cutoff_utc,
				$days
			)
		);

		foreach ( (array) $rows as $row ) {
			$family = ReportedIP_Hive_Event_Taxonomy::classify( $row->event_type );
			if ( null === $family ) {
				continue;
			}
			$count                 = (int) $row->c;
			$by_family[ $family ] += $count;

			$severity = (string) $row->severity;
			if ( isset( $by_severity[ $severity ] ) ) {
				$by_severity[ $severity ] += $count;
			}

			if ( isset( $date_pos[ $row->d ] ) ) {
				$series[ $family ][ $date_pos[ $row->d ] ] += $count;
			}
		}

		$families = array();
		foreach ( $family_keys as $fkey ) {
			$families[] = array(
				'key'   => $fkey,
				'label' => $labels_map[ $fkey ],
				'data'  => $series[ $fkey ],
			);
		}

		$period_total = array_sum( $by_family );
		$today_total  = 0;
		$last_pos     = $days - 1;
		foreach ( $family_keys as $fkey ) {
			$today_total += $series[ $fkey ][ $last_pos ];
		}

		$waf_rows   = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT details FROM $logs_table
				 WHERE event_type IN ('waf_block','waf_would_block')
				   AND ( created_at >= %s OR created_at >= DATE_SUB(NOW(), INTERVAL %d DAY) )
				 ORDER BY created_at DESC
				 LIMIT 5000",
				$cutoff_utc,
				$days
			)
		);
		$waf_groups = array();
		foreach ( (array) $waf_rows as $row ) {
			$decoded              = json_decode( (string) $row->details, true );
			$group                = ( is_array( $decoded ) && ! empty( $decoded['group'] ) )
				? (string) $decoded['group']
				: 'other';
			$waf_groups[ $group ] = ( $waf_groups[ $group ] ?? 0 ) + 1;
		}
		arsort( $waf_groups );

		$top_ips      = array();
		$threat_types = ReportedIP_Hive_Event_Taxonomy::threat_event_types();
		if ( ! empty( $threat_types ) ) {
			$placeholders = implode( ',', array_fill( 0, count( $threat_types ), '%s' ) );
			$top_rows     = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT ip_address, COUNT(*) AS c, MAX(created_at) AS last_seen
					 FROM $logs_table
					 WHERE event_type IN ($placeholders)
					   AND ip_address <> ''
					   AND ( created_at >= %s OR created_at >= DATE_SUB(NOW(), INTERVAL %d DAY) )
					 GROUP BY ip_address
					 ORDER BY c DESC
					 LIMIT 10",
					array_merge( $threat_types, array( $cutoff_utc, $days ) )
				)
			);

			$ips = array();
			foreach ( (array) $top_rows as $row ) {
				$ips[] = (string) $row->ip_address;
			}

			$active_blocks = array();
			if ( ! empty( $ips ) ) {
				$blocked_table = $wpdb->base_prefix . 'reportedip_hive_blocked';
				$ip_ph         = implode( ',', array_fill( 0, count( $ips ), '%s' ) );
				$blocked_rows  = $wpdb->get_col(
					$wpdb->prepare(
						"SELECT ip_address FROM $blocked_table
						 WHERE is_active = 1
						   AND ip_address IN ($ip_ph)
						   AND ( blocked_until IS NULL OR blocked_until > NOW() )",
						$ips
					)
				);
				$active_blocks = array_flip( array_map( 'strval', (array) $blocked_rows ) );
			}

			foreach ( (array) $top_rows as $row ) {
				$top_ips[] = array(
					'ip'        => (string) $row->ip_address,
					'count'     => (int) $row->c,
					'last_seen' => (string) $row->last_seen,
					'blocked'   => isset( $active_blocks[ (string) $row->ip_address ] ),
				);
			}
		}

		return array(
			'days'        => $days,
			'labels'      => $labels,
			'families'    => $families,
			'by_family'   => $by_family,
			'by_severity' => $by_severity,
			'waf_groups'  => $waf_groups,
			'totals'      => array(
				'period' => $period_total,
				'today'  => $today_total,
			),
			'top_ips'     => $top_ips,
		);
	}
}
