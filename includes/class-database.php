<?php
/**
 * Database Management Class for ReportedIP Hive.
 *
 * This class provides database abstraction for the ReportedIP Hive plugin.
 * Direct database queries are intentional as this is the database layer.
 * Table names are constructed safely using $wpdb->prefix and cannot use placeholders.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
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

// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter -- Database layer: all table names are composed from $wpdb->prefix with hardcoded suffixes and cannot be parameterised. Dynamic SQL fragments are built with $wpdb->prepare(), validated allowlists, or cast integers.

class ReportedIP_Hive_Database {

	/**
	 * Current database schema version.
	 * Increment this when adding migrations.
	 */
	const DB_VERSION = 3;

	/**
	 * Option key for stored DB version
	 */
	const DB_VERSION_OPTION = 'reportedip_hive_db_version';

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
			$wpdb->prefix . 'reportedip_hive_logs',
			$wpdb->prefix . 'reportedip_hive_whitelist',
			$wpdb->prefix . 'reportedip_hive_blocked',
			$wpdb->prefix . 'reportedip_hive_attempts',
			$wpdb->prefix . 'reportedip_hive_api_queue',
			$wpdb->prefix . 'reportedip_hive_stats',
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
	 * Called on every admin page load to catch missed activations and updates.
	 */
	public function maybe_update_schema() {
		$installed_version = get_option( self::DB_VERSION_OPTION, 0 );

		if ( (int) $installed_version >= self::DB_VERSION ) {
			return;
		}

		$this->create_tables();
		$this->run_migrations();

		update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Run incremental migrations between schema versions.
	 *
	 * dbDelta does not change ENUM definitions on existing tables, so the
	 * VARCHAR(32) widening on `attempts.attempt_type` introduced in v3
	 * needs an explicit ALTER. Idempotent: re-running is a no-op.
	 */
	private function run_migrations() {
		global $wpdb;

		$table_attempts = $wpdb->prefix . 'reportedip_hive_attempts';

		$column = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT DATA_TYPE AS data_type, COLUMN_TYPE AS column_type FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s',
				$table_attempts,
				'attempt_type'
			)
		);

		if ( $column && strtolower( (string) $column->data_type ) === 'enum' ) {
			$wpdb->query( "ALTER TABLE $table_attempts MODIFY attempt_type VARCHAR(32) NOT NULL DEFAULT 'login'" );
		}
	}

	/**
	 * Create all database tables
	 */
	public function create_tables() {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$table_logs = $wpdb->prefix . 'reportedip_hive_logs';
		$sql_logs   = "CREATE TABLE $table_logs (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            event_type varchar(50) NOT NULL,
            ip_address varchar(45) NOT NULL,
            details longtext DEFAULT NULL,
            severity enum('low','medium','high','critical') DEFAULT 'medium',
            reported_to_api tinyint(1) DEFAULT 0,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_event_type (event_type),
            KEY idx_ip_address (ip_address),
            KEY idx_created_at (created_at),
            KEY idx_severity (severity),
            KEY idx_reported_to_api (reported_to_api)
        ) $charset_collate;";

		$table_whitelist = $wpdb->prefix . 'reportedip_hive_whitelist';
		$sql_whitelist   = "CREATE TABLE $table_whitelist (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            ip_type enum('ipv4','ipv6','cidr') DEFAULT 'ipv4',
            reason text DEFAULT NULL,
            added_by bigint(20) unsigned NOT NULL,
            expires_at datetime DEFAULT NULL,
            is_active tinyint(1) DEFAULT 1,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY unique_ip (ip_address),
            KEY idx_ip_type (ip_type),
            KEY idx_is_active (is_active),
            KEY idx_expires_at (expires_at)
        ) $charset_collate;";

		$table_blocked = $wpdb->prefix . 'reportedip_hive_blocked';
		$sql_blocked   = "CREATE TABLE $table_blocked (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            reason varchar(255) NOT NULL,
            block_type enum('manual','automatic','reputation') DEFAULT 'automatic',
            blocked_until datetime DEFAULT NULL,
            failed_attempts int(11) DEFAULT 0,
            last_attempt datetime DEFAULT NULL,
            is_active tinyint(1) DEFAULT 1,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY unique_ip (ip_address),
            KEY idx_block_type (block_type),
            KEY idx_blocked_until (blocked_until),
            KEY idx_is_active (is_active),
            KEY idx_last_attempt (last_attempt)
        ) $charset_collate;";

		$table_attempts = $wpdb->prefix . 'reportedip_hive_attempts';
		$sql_attempts   = "CREATE TABLE $table_attempts (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            attempt_type varchar(32) NOT NULL DEFAULT 'login',
            username varchar(60) DEFAULT NULL,
            user_agent text DEFAULT NULL,
            attempt_count int(11) DEFAULT 1,
            first_attempt datetime DEFAULT CURRENT_TIMESTAMP,
            last_attempt datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_ip_address (ip_address),
            KEY idx_attempt_type (attempt_type),
            KEY idx_last_attempt (last_attempt),
            KEY composite_ip_type (ip_address, attempt_type)
        ) $charset_collate;";

		$table_queue = $wpdb->prefix . 'reportedip_hive_api_queue';
		$sql_queue   = "CREATE TABLE $table_queue (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            category_ids text NOT NULL,
            comment text DEFAULT NULL,
            report_type enum('negative','positive') DEFAULT 'negative',
            priority enum('low','normal','high') DEFAULT 'normal',
            attempts int(11) DEFAULT 0,
            max_attempts int(11) DEFAULT 3,
            last_attempt datetime DEFAULT NULL,
            status enum('pending','processing','completed','failed') DEFAULT 'pending',
            error_message text DEFAULT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_status (status),
            KEY idx_priority (priority),
            KEY idx_report_type (report_type),
            KEY idx_created_at (created_at)
        ) $charset_collate;";

		$table_stats = $wpdb->prefix . 'reportedip_hive_stats';
		$sql_stats   = "CREATE TABLE $table_stats (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            stat_date date NOT NULL,
            failed_logins int(11) DEFAULT 0,
            blocked_ips int(11) DEFAULT 0,
            comment_spam int(11) DEFAULT 0,
            xmlrpc_calls int(11) DEFAULT 0,
            api_reports_sent int(11) DEFAULT 0,
            reputation_blocks int(11) DEFAULT 0,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY unique_date (stat_date),
            KEY idx_stat_date (stat_date)
        ) $charset_collate;";

		$table_trusted = $wpdb->prefix . 'reportedip_hive_trusted_devices';
		$sql_trusted   = "CREATE TABLE $table_trusted (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            user_id bigint(20) unsigned NOT NULL,
            token_hash varchar(64) NOT NULL,
            device_name varchar(255) DEFAULT '',
            ip_address varchar(45) DEFAULT '',
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            expires_at datetime NOT NULL,
            last_used_at datetime DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY unique_token (token_hash),
            KEY idx_user_id (user_id),
            KEY idx_expires_at (expires_at)
        ) $charset_collate;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta( $sql_logs );
		dbDelta( $sql_whitelist );
		dbDelta( $sql_blocked );
		dbDelta( $sql_attempts );
		dbDelta( $sql_queue );
		dbDelta( $sql_stats );
		dbDelta( $sql_trusted );

		$this->create_additional_indexes();
	}

	/**
	 * Create additional indexes for performance (idempotent)
	 */
	private function create_additional_indexes() {
		global $wpdb;

		$indexes = array(
			array(
				'table' => $wpdb->prefix . 'reportedip_hive_logs',
				'name'  => 'idx_logs_composite',
				'sql'   => "CREATE INDEX idx_logs_composite ON {$wpdb->prefix}reportedip_hive_logs (ip_address, event_type, created_at DESC)",
			),
			array(
				'table' => $wpdb->prefix . 'reportedip_hive_attempts',
				'name'  => 'idx_attempts_timeframe',
				'sql'   => "CREATE INDEX idx_attempts_timeframe ON {$wpdb->prefix}reportedip_hive_attempts (ip_address, last_attempt DESC)",
			),
			array(
				'table' => $wpdb->prefix . 'reportedip_hive_api_queue',
				'name'  => 'idx_queue_processing',
				'sql'   => "CREATE INDEX idx_queue_processing ON {$wpdb->prefix}reportedip_hive_api_queue (status, priority, created_at ASC)",
			),
		);

		foreach ( $indexes as $index ) {
			$existing = $wpdb->get_var(
				$wpdb->prepare(
					'SELECT COUNT(*) FROM information_schema.STATISTICS WHERE table_schema = DATABASE() AND table_name = %s AND index_name = %s',
					$index['table'],
					$index['name']
				)
			);
			if ( ! $existing ) {
				$wpdb->query( $index['sql'] );
			}
		}
	}

	/**
	 * Drop all tables
	 */
	public function drop_tables() {
		global $wpdb;

		$tables = array(
			$wpdb->prefix . 'reportedip_hive_trusted_devices',
			$wpdb->prefix . 'reportedip_hive_stats',
			$wpdb->prefix . 'reportedip_hive_api_queue',
			$wpdb->prefix . 'reportedip_hive_attempts',
			$wpdb->prefix . 'reportedip_hive_blocked',
			$wpdb->prefix . 'reportedip_hive_whitelist',
			$wpdb->prefix . 'reportedip_hive_logs',
		);

		foreach ( $tables as $table ) {
			$wpdb->query( "DROP TABLE IF EXISTS $table" );
		}
	}

	/**
	 * Log security event
	 */
	public function log_security_event( $event_type, $ip_address, $details = array(), $severity = 'medium' ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_logs';

		return $wpdb->insert(
			$table_name,
			array(
				'event_type' => $event_type,
				'ip_address' => $ip_address,
				'details'    => wp_json_encode( $details ),
				'severity'   => $severity,
			),
			array( '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Get security logs
	 */
	public function get_logs( $days = 30, $limit = 1000, $event_type = null ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_logs';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_whitelist';

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

		return $result;
	}

	/**
	 * Check if IP is whitelisted
	 */
	public function is_whitelisted( $ip_address ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_whitelist';

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
			if ( $this->ip_in_range( $ip_address, $cidr ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Get whitelist entries
	 */
	public function get_whitelist( $active_only = true ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_whitelist';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_whitelist';

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

		return $result;
	}

	/**
	 * Block IP address
	 */
	public function block_ip( $ip_address, $reason, $block_type = 'automatic', $duration_hours = 24 ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_blocked';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_blocked';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_blocked';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_blocked';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_blocked';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_whitelist';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_blocked';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_attempts';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_attempts';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_attempts';

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

		$blocked_table = $wpdb->prefix . 'reportedip_hive_blocked';
		$queue_table   = $wpdb->prefix . 'reportedip_hive_api_queue';
		$logs_table    = $wpdb->prefix . 'reportedip_hive_logs';

		$recently_blocked = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $blocked_table 
                 WHERE ip_address = %s 
                 AND created_at > DATE_SUB(NOW(), INTERVAL %d HOUR)",
				$ip_address,
				$hours
			)
		);

		if ( $recently_blocked > 0 ) {
			return array(
				'processed' => true,
				'reason'    => 'recently_blocked',
				'details'   => 'IP was blocked within the last ' . $hours . ' hours',
			);
		}

		$recently_reported = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $queue_table 
                 WHERE ip_address = %s 
                 AND report_type = 'negative'
                 AND status IN ('completed', 'pending', 'processing')
                 AND created_at > DATE_SUB(NOW(), INTERVAL %d HOUR)",
				$ip_address,
				$hours
			)
		);

		if ( $recently_reported > 0 ) {
			return array(
				'processed' => true,
				'reason'    => 'recently_reported',
				'details'   => 'IP was reported to API within the last ' . $hours . ' hours',
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

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

		$cooldown_hours = get_option( 'reportedip_hive_report_cooldown_hours', 24 );

		$recent_check = $this->is_recently_processed( $ip_address, $cooldown_hours );
		if ( $recent_check['processed'] ) {
			return false;
		}

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $table_name 
                 WHERE ip_address = %s 
                 AND report_type = %s 
                 AND status IN ('pending', 'processing') 
                 AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
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
				'ip_address'   => $ip_address,
				'category_ids' => is_array( $category_ids ) ? implode( ',', $category_ids ) : $category_ids,
				'comment'      => $comment,
				'report_type'  => $report_type,
				'priority'     => $priority,
			),
			array( '%s', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Get pending API reports (includes failed reports that haven't exceeded max_attempts)
	 */
	public function get_pending_api_reports( $limit = 10 ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

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
	 * Update daily statistics
	 */
	public function update_daily_stats( $stat_type, $increment = 1 ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_stats';
		$today      = gmdate( 'Y-m-d' );

		$valid_stats = array( 'failed_logins', 'blocked_ips', 'comment_spam', 'xmlrpc_calls', 'api_reports_sent', 'reputation_blocks' );

		if ( ! in_array( $stat_type, $valid_stats ) ) {
			return false;
		}

		return $wpdb->query(
			$wpdb->prepare(
				"INSERT INTO $table_name (stat_date, $stat_type) VALUES (%s, %d) 
                 ON DUPLICATE KEY UPDATE $stat_type = $stat_type + %d",
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

		$table_name = $wpdb->prefix . 'reportedip_hive_stats';

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

		$logs_table = $wpdb->prefix . 'reportedip_hive_logs';

		$old_logs = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT id, details FROM $logs_table 
                 WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)
                 AND created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)",
				$days,
				get_option( 'reportedip_hive_data_retention_days', 30 )
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

		$attempts_table      = $wpdb->prefix . 'reportedip_hive_attempts';
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
			$wpdb->prefix . 'reportedip_hive_logs'      => 'created_at',
			$wpdb->prefix . 'reportedip_hive_attempts'  => 'last_attempt',
			$wpdb->prefix . 'reportedip_hive_api_queue' => 'created_at',
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
			"DELETE FROM {$wpdb->prefix}reportedip_hive_api_queue
             WHERE status = 'completed'
             AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)"
		);

		if ( $completed_reports !== false ) {
			$deleted += $completed_reports;
		}

		$failed_reports = $wpdb->query(
			"DELETE FROM {$wpdb->prefix}reportedip_hive_api_queue
             WHERE status = 'failed'
             AND attempts >= max_attempts
             AND created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)"
		);

		if ( $failed_reports !== false ) {
			$deleted += $failed_reports;
		}

		$queue_max_age = get_option( 'reportedip_hive_queue_max_age_days', 7 );
		$old_pending   = $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}reportedip_hive_api_queue
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

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

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
		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

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
	 * @return int Number of reports reset
	 */
	public function reset_all_failed_reports() {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

		$result = $wpdb->query(
			"UPDATE $table_name
             SET status = 'pending', attempts = 0, error_message = NULL, last_attempt = NULL
             WHERE status = 'failed'
             AND attempts < max_attempts"
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

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_api_queue';

		$result = $wpdb->query(
			"DELETE FROM $table_name
             WHERE status = 'failed'
             AND attempts >= max_attempts"
		);

		return $result !== false ? $result : 0;
	}

	/**
	 * Check if IP is in CIDR range
	 */
	private function ip_in_range( $ip, $cidr ) {
		if ( ! is_string( $ip ) || ! is_string( $cidr ) || $ip === '' || $cidr === '' ) {
			return false;
		}

		if ( strpos( $cidr, '/' ) === false ) {
			return $ip === $cidr;
		}

		list($subnet, $mask) = explode( '/', $cidr, 2 );
		$mask                = (int) $mask;

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$ip_long     = ip2long( $ip );
			$subnet_long = ip2long( $subnet );
			$mask_long   = -1 << ( 32 - $mask );

			return ( $ip_long & $mask_long ) === ( $subnet_long & $mask_long );
		} elseif ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$ip_bin     = inet_pton( $ip );
			$subnet_bin = inet_pton( $subnet );

			if ( $ip_bin === false || $subnet_bin === false ) {
				return false;
			}

			$bytes = intval( $mask / 8 );
			$bits  = $mask % 8;

			for ( $i = 0; $i < $bytes; $i++ ) {
				if ( $ip_bin[ $i ] !== $subnet_bin[ $i ] ) {
					return false;
				}
			}

			if ( $bits > 0 ) {
				$mask_byte = 0xFF << ( 8 - $bits );
				return ( ord( $ip_bin[ $bytes ] ) & $mask_byte ) === ( ord( $subnet_bin[ $bytes ] ) & $mask_byte );
			}

			return true;
		}

		return false;
	}

	/**
	 * Get log statistics for debugging
	 */
	public function get_log_statistics( $days = 7 ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_logs';

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

		$table_name = $wpdb->prefix . 'reportedip_hive_logs';
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

		$table_name = $wpdb->prefix . 'reportedip_hive_logs';
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
	 * Get IP management statistics
	 */
	public function get_ip_management_stats() {
		global $wpdb;

		$blocked_table   = $wpdb->prefix . 'reportedip_hive_blocked';
		$whitelist_table = $wpdb->prefix . 'reportedip_hive_whitelist';

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

		$logs_table  = $wpdb->prefix . 'reportedip_hive_logs';
		$stats_table = $wpdb->prefix . 'reportedip_hive_stats';

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
}
