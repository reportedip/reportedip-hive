<?php
/**
 * Schema service: owns the central plugin tables.
 *
 * All seven plugin tables live under `$wpdb->base_prefix`, i.e. they are
 * shared across the entire WordPress Multisite network. On single-site
 * installs `base_prefix === prefix`, so the storage is unchanged from v1.x.
 *
 * Tables that record where an event happened carry an explicit `blog_id`
 * column (`logs`, `api_queue`, `stats`). Tables that are inherently
 * IP-centric (`whitelist`, `blocked`, `attempts`) or user-global
 * (`trusted_devices`) intentionally have no `blog_id` so that a single
 * threat decision applies network-wide.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.0
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

// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter -- Database layer: table names are composed from $wpdb->base_prefix with hardcoded suffixes and cannot be parameterised.

/**
 * Owns the plugin's central database schema.
 *
 * @since 2.0.0
 */
final class ReportedIP_Hive_Schema {

	/**
	 * Plugin table suffixes (without prefix).
	 *
	 * Used for both creation and teardown. Order matters for `drop_all_tables()`:
	 * we drop in reverse FK-affinity order even though the schema doesn't use
	 * formal foreign keys (defensive).
	 *
	 * @var string[]
	 */
	private const TABLE_SUFFIXES = array(
		'reportedip_hive_logs',
		'reportedip_hive_whitelist',
		'reportedip_hive_blocked',
		'reportedip_hive_attempts',
		'reportedip_hive_api_queue',
		'reportedip_hive_stats',
		'reportedip_hive_trusted_devices',
	);

	/**
	 * Returns the fully-qualified table name (with `base_prefix`) for a suffix.
	 *
	 * @param string $suffix Plugin-internal suffix, e.g. `reportedip_hive_logs`.
	 * @return string
	 * @since  2.0.0
	 */
	public static function table( $suffix ) {
		global $wpdb;
		return $wpdb->base_prefix . (string) $suffix;
	}

	/**
	 * Whether all required plugin tables exist.
	 *
	 * @return bool
	 * @since  2.0.0
	 */
	public static function tables_exist() {
		global $wpdb;
		foreach ( self::TABLE_SUFFIXES as $suffix ) {
			$table  = self::table( $suffix );
			$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
			if ( ! $exists ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Create or update all plugin tables via dbDelta. Idempotent.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public static function ensure_tables() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset_collate = $wpdb->get_charset_collate();
		$prefix          = $wpdb->base_prefix;

		$table_logs = $prefix . 'reportedip_hive_logs';
		$sql_logs   = "CREATE TABLE $table_logs (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			blog_id int(11) unsigned NOT NULL DEFAULT 0,
			event_type varchar(50) NOT NULL,
			ip_address varchar(45) NOT NULL,
			details longtext DEFAULT NULL,
			severity enum('low','medium','high','critical') DEFAULT 'medium',
			reported_to_api tinyint(1) DEFAULT 0,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY idx_blog_id (blog_id),
			KEY idx_event_type (event_type),
			KEY idx_ip_address (ip_address),
			KEY idx_created_at (created_at),
			KEY idx_severity (severity),
			KEY idx_reported_to_api (reported_to_api),
			KEY idx_logs_site_time (blog_id, created_at)
		) $charset_collate;";

		$table_whitelist = $prefix . 'reportedip_hive_whitelist';
		$sql_whitelist   = "CREATE TABLE $table_whitelist (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL,
			ip_type enum('ipv4','ipv6','cidr') DEFAULT 'ipv4',
			reason text DEFAULT NULL,
			added_by bigint(20) unsigned NOT NULL,
			expires_at datetime DEFAULT NULL,
			is_active tinyint(1) DEFAULT 1,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY unique_ip (ip_address),
			KEY idx_ip_type (ip_type),
			KEY idx_is_active (is_active),
			KEY idx_expires_at (expires_at)
		) $charset_collate;";

		$table_blocked = $prefix . 'reportedip_hive_blocked';
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
			PRIMARY KEY  (id),
			UNIQUE KEY unique_ip (ip_address),
			KEY idx_block_type (block_type),
			KEY idx_blocked_until (blocked_until),
			KEY idx_is_active (is_active),
			KEY idx_last_attempt (last_attempt)
		) $charset_collate;";

		$table_attempts = $prefix . 'reportedip_hive_attempts';
		$sql_attempts   = "CREATE TABLE $table_attempts (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL,
			attempt_type varchar(32) NOT NULL DEFAULT 'login',
			username varchar(60) DEFAULT NULL,
			user_agent text DEFAULT NULL,
			attempt_count int(11) DEFAULT 1,
			first_attempt datetime DEFAULT CURRENT_TIMESTAMP,
			last_attempt datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY idx_ip_address (ip_address),
			KEY idx_attempt_type (attempt_type),
			KEY idx_last_attempt (last_attempt),
			KEY composite_ip_type (ip_address, attempt_type)
		) $charset_collate;";

		$table_queue = $prefix . 'reportedip_hive_api_queue';
		$sql_queue   = "CREATE TABLE $table_queue (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			blog_id int(11) unsigned NOT NULL DEFAULT 0,
			ip_address varchar(45) NOT NULL,
			category_ids text NOT NULL,
			comment text DEFAULT NULL,
			report_type enum('negative','positive') DEFAULT 'negative',
			priority enum('low','normal','high') DEFAULT 'normal',
			attempts int(11) DEFAULT 0,
			max_attempts int(11) DEFAULT 3,
			last_attempt datetime DEFAULT NULL,
			submitted_at datetime DEFAULT NULL,
			status enum('pending','processing','completed','failed') DEFAULT 'pending',
			error_message text DEFAULT NULL,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY idx_blog_id (blog_id),
			KEY idx_status (status),
			KEY idx_priority (priority),
			KEY idx_report_type (report_type),
			KEY idx_created_at (created_at),
			KEY idx_submitted_at (submitted_at),
			KEY idx_queue_site_status (blog_id, status, priority)
		) $charset_collate;";

		$table_stats = $prefix . 'reportedip_hive_stats';
		$sql_stats   = "CREATE TABLE $table_stats (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			blog_id int(11) unsigned NOT NULL DEFAULT 0,
			stat_date date NOT NULL,
			failed_logins int(11) DEFAULT 0,
			blocked_ips int(11) DEFAULT 0,
			comment_spam int(11) DEFAULT 0,
			xmlrpc_calls int(11) DEFAULT 0,
			api_reports_sent int(11) DEFAULT 0,
			reputation_blocks int(11) DEFAULT 0,
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			UNIQUE KEY unique_site_date (blog_id, stat_date),
			KEY idx_stat_date (stat_date),
			KEY idx_blog_id (blog_id)
		) $charset_collate;";

		$table_trusted = $prefix . 'reportedip_hive_trusted_devices';
		$sql_trusted   = "CREATE TABLE $table_trusted (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			user_id bigint(20) unsigned NOT NULL,
			token_hash varchar(64) NOT NULL,
			device_name varchar(255) DEFAULT '',
			ip_address varchar(45) DEFAULT '',
			created_at datetime DEFAULT CURRENT_TIMESTAMP,
			expires_at datetime NOT NULL,
			last_used_at datetime DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY unique_token (token_hash),
			KEY idx_user_id (user_id),
			KEY idx_expires_at (expires_at)
		) $charset_collate;";

		dbDelta( $sql_logs );
		dbDelta( $sql_whitelist );
		dbDelta( $sql_blocked );
		dbDelta( $sql_attempts );
		dbDelta( $sql_queue );
		dbDelta( $sql_stats );
		dbDelta( $sql_trusted );

		self::ensure_additional_indexes();
	}

	/**
	 * Adds additional composite indexes that dbDelta cannot manage idempotently.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	private static function ensure_additional_indexes() {
		global $wpdb;
		$prefix = $wpdb->base_prefix;

		$indexes = array(
			array(
				'table' => $prefix . 'reportedip_hive_logs',
				'name'  => 'idx_logs_composite',
				'sql'   => "CREATE INDEX idx_logs_composite ON {$prefix}reportedip_hive_logs (ip_address, event_type, created_at DESC)",
			),
			array(
				'table' => $prefix . 'reportedip_hive_attempts',
				'name'  => 'idx_attempts_timeframe',
				'sql'   => "CREATE INDEX idx_attempts_timeframe ON {$prefix}reportedip_hive_attempts (ip_address, last_attempt DESC)",
			),
			array(
				'table' => $prefix . 'reportedip_hive_api_queue',
				'name'  => 'idx_queue_processing',
				'sql'   => "CREATE INDEX idx_queue_processing ON {$prefix}reportedip_hive_api_queue (status, priority, created_at ASC)",
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
	 * Drop all plugin tables. Used by uninstall when data deletion was requested.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public static function drop_all_tables() {
		global $wpdb;
		foreach ( array_reverse( self::TABLE_SUFFIXES ) as $suffix ) {
			$table = self::table( $suffix );
			$wpdb->query( "DROP TABLE IF EXISTS $table" );
		}
	}

	/**
	 * Remove all data belonging to a specific blog from `blog_id`-scoped tables.
	 *
	 * Hooked from `wp_delete_site`. Network-wide tables (whitelist, blocked,
	 * attempts, trusted_devices) are intentionally NOT touched — they live
	 * above the site boundary and a deleted site does not invalidate the
	 * threat data accumulated against an attacker's IP.
	 *
	 * @param int $blog_id Site ID being deleted.
	 * @return void
	 * @since  2.0.0
	 */
	public static function cleanup_blog_data( $blog_id ) {
		global $wpdb;
		$blog_id = (int) $blog_id;
		if ( $blog_id <= 0 ) {
			return;
		}

		$tables = array(
			self::table( 'reportedip_hive_logs' ),
			self::table( 'reportedip_hive_api_queue' ),
			self::table( 'reportedip_hive_stats' ),
		);

		foreach ( $tables as $table ) {
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM $table WHERE blog_id = %d",
					$blog_id
				)
			);
		}
	}

	/**
	 * Whether a given column already exists on a plugin table.
	 *
	 * Used by Migration_Manager to keep `migrate_to_v5()` idempotent (re-runs
	 * must not throw on existing columns).
	 *
	 * @param string $table_suffix Plugin-internal suffix.
	 * @param string $column       Column name.
	 * @return bool
	 * @since  2.0.0
	 */
	public static function column_exists( $table_suffix, $column ) {
		global $wpdb;
		$table  = self::table( $table_suffix );
		$result = $wpdb->get_var(
			$wpdb->prepare(
				'SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s',
				$table,
				$column
			)
		);
		return (int) $result > 0;
	}
}
