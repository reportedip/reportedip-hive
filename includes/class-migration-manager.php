<?php
/**
 * Migration-Manager: numbered, idempotent schema migrations.
 *
 * Each schema bump implements a `migrate_to_v{N}()` method. `maybe_run()`
 * advances `db_version` step by step until it matches `CURRENT_VERSION`,
 * persisting after each successful step. Re-entry is safe, every step
 * checks for already-applied state before touching the schema.
 *
 * Concurrency: `acquire_lock()` takes a row in the main site's options
 * table with `INSERT IGNORE` ({@see take_lock()}); `option_name` is UNIQUE
 * there, so exactly one request wins. `add_site_option()` is not atomic on
 * Multisite (sitemeta has no unique key). Stale locks expire after
 * `LOCK_TTL` seconds.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
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

// phpcs:disable PluginCheck.Security.DirectDB.UnescapedDBParameter -- Migration layer: composes table names from $wpdb->base_prefix with hardcoded suffixes.

/**
 * Runs versioned schema migrations.
 *
 * @since 2.0.0
 */
final class ReportedIP_Hive_Migration_Manager {

	/**
	 * Highest schema version this build of the plugin understands.
	 */
	public const CURRENT_VERSION = 24;

	/**
	 * Network option name storing the currently-applied schema version.
	 */
	public const VERSION_OPTION = 'reportedip_hive_db_version';

	/**
	 * Network option name used as an atomic lock during migration.
	 */
	public const LOCK_OPTION = 'reportedip_hive_migration_lock';

	/**
	 * Whether the running migration started from ReportedIP Hive Light.
	 *
	 * Light (the wordpress.org plugin on the same slug up to 1.3.x) stored
	 * its schema version as a dotted string such as `1.2.0`; every Hive
	 * release stored an integer. The integer cast reads `1.2.0` as 1, so the
	 * whole 2.x chain runs, which is right for the tables; the flag lets the
	 * steps that only make sense for a 2.x install leave Light data alone.
	 *
	 * @var bool
	 */
	private static $from_light = false;

	/**
	 * Values of the locks this request holds, keyed by lock name.
	 *
	 * @var array<string,string>
	 */
	private static $held_locks = array();

	/**
	 * Lock TTL in seconds. Stale locks beyond this window are force-released.
	 */
	public const LOCK_TTL = 300;

	/**
	 * Run any outstanding migrations.
	 *
	 * Safe to call from `admin_init`, `wp_initialize_site` and activation.
	 * Returns early when the version is already current or when the lock
	 * is held by another request.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public static function maybe_run() {
		$current = (int) get_site_option( self::VERSION_OPTION, 0 );
		if ( $current >= self::CURRENT_VERSION ) {
			return;
		}

		if ( ! self::acquire_lock() ) {
			return;
		}

		$raw = get_site_option( self::VERSION_OPTION, 0 );
		if ( ! self::is_light_version( $raw ) && is_multisite() ) {
			$raw = get_option( self::VERSION_OPTION, 0 );
		}
		self::$from_light = self::is_light_version( $raw );

		try {
			for ( $v = $current + 1; $v <= self::CURRENT_VERSION; $v++ ) {
				$method = "migrate_to_v{$v}";
				if ( method_exists( __CLASS__, $method ) ) {
					self::$method();
				}
				update_site_option( self::VERSION_OPTION, $v );
			}
		} finally {
			self::$from_light = false;
			self::release_lock();
		}
	}

	/**
	 * Whether a stored schema version comes from ReportedIP Hive Light.
	 *
	 * @param mixed $raw Stored `reportedip_hive_db_version`.
	 * @return bool True for a dotted version string such as `1.2.0`.
	 * @since  3.0.0
	 */
	public static function is_light_version( $raw ) {
		return is_string( $raw ) && 1 === preg_match( '/^\d+\.\d+(\.\d+)?$/D', $raw );
	}

	/**
	 * Atomically acquire the migration lock.
	 *
	 * @return bool True if the lock was acquired, false otherwise.
	 * @since  2.0.0
	 */
	private static function acquire_lock() {
		return self::take_lock( self::LOCK_OPTION, self::LOCK_TTL );
	}

	/**
	 * Release the migration lock unconditionally.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	private static function release_lock() {
		self::drop_lock( self::LOCK_OPTION );
	}

	/**
	 * Take a network-wide mutex, or report that another request holds it.
	 *
	 * The lock is a row in the main site's options table, inserted with
	 * `INSERT IGNORE`: `option_name` is UNIQUE, so of two parallel requests
	 * exactly one inserts it. A lock older than `$ttl` seconds is taken
	 * over, so a crashed holder does not block forever. Without a real
	 * database handle (unit test doubles) the option API stands in.
	 *
	 * @param string $name Lock name, an option name.
	 * @param int    $ttl  Seconds after which a held lock counts as stale.
	 * @return bool True when this request holds the lock now.
	 * @since  3.0.0
	 */
	public static function take_lock( $name, $ttl ) {
		global $wpdb;
		if ( ! ( $wpdb instanceof wpdb ) ) {
			$held = (int) get_site_option( $name, 0 );
			if ( $held > 0 ) {
				if ( time() - $held < $ttl ) {
					return false;
				}
				delete_site_option( $name );
			}
			$value = time();
			if ( ! add_site_option( $name, $value ) ) {
				return false;
			}
			self::$held_locks[ $name ] = (string) $value;
			return true;
		}

		$table = $wpdb->base_prefix . 'options';
		$held  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$table} WHERE option_name = %s", $name ) );
		if ( $held > 0 ) {
			if ( time() - $held < (int) $ttl ) {
				return false;
			}
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE option_name = %s AND option_value = %s", $name, (string) $held ) );
		}
		$value = (string) time();
		if ( 1 !== (int) $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$table} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $name, $value ) ) ) {
			return false;
		}
		self::$held_locks[ $name ] = $value;
		return true;
	}

	/**
	 * Release a mutex this request took with {@see take_lock()}.
	 *
	 * Only the row carrying the value this request inserted is deleted. A
	 * holder that outlived the TTL finds its lock taken over by another
	 * request and must not release that request's lock; a request that never
	 * took the lock releases nothing.
	 *
	 * @param string $name Lock name.
	 * @return void
	 * @since  3.0.0
	 */
	public static function drop_lock( $name ) {
		global $wpdb;
		if ( ! isset( self::$held_locks[ $name ] ) ) {
			return;
		}
		$value = self::$held_locks[ $name ];
		unset( self::$held_locks[ $name ] );
		if ( ! ( $wpdb instanceof wpdb ) ) {
			if ( (string) get_site_option( $name, '' ) === $value ) {
				delete_site_option( $name );
			}
			return;
		}
		$table = $wpdb->base_prefix . 'options';
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE option_name = %s AND option_value = %s", $name, $value ) );
	}

	/**
	 * Migrate from v4 to v5: Multisite-aware central schema.
	 *
	 * Steps (all idempotent):
	 *   1. Create / upgrade tables under `$wpdb->base_prefix` via Schema::ensure_tables().
	 *   2. Add `blog_id` columns to logs/api_queue/stats if missing.
	 *      Default `1` so single-site rows keep their natural blog id.
	 *   3. Widen `attempts.attempt_type` from ENUM to VARCHAR(32) if needed.
	 *   4. Promote per-site network-class options to sitemeta (Multisite only,
	 *      Pfad B from the spec, installs that previously had Hive activated
	 *      on individual sites without `Network: true`).
	 *   5. Shorten existing `trusted_devices.expires_at` to NOW()+24h so users
	 *      get a smooth re-trust window after the cookie path widens to
	 *      `SITECOOKIEPATH`.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	private static function migrate_to_v5() {
		global $wpdb;

		ReportedIP_Hive_Schema::ensure_tables();

		$blog_id_targets = array( 'reportedip_hive_logs', 'reportedip_hive_api_queue', 'reportedip_hive_stats' );
		foreach ( $blog_id_targets as $suffix ) {
			if ( ! ReportedIP_Hive_Schema::column_exists( $suffix, 'blog_id' ) ) {
				$table = ReportedIP_Hive_Schema::table( $suffix );
				$wpdb->query( "ALTER TABLE $table ADD COLUMN blog_id INT(11) UNSIGNED NOT NULL DEFAULT 1" );
			}
		}

		$attempts_table = ReportedIP_Hive_Schema::table( 'reportedip_hive_attempts' );
		$column         = $wpdb->get_row(
			$wpdb->prepare(
				'SELECT DATA_TYPE AS data_type FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s',
				$attempts_table,
				'attempt_type'
			)
		);
		if ( $column && strtolower( (string) $column->data_type ) === 'enum' ) {
			$wpdb->query( "ALTER TABLE $attempts_table MODIFY attempt_type VARCHAR(32) NOT NULL DEFAULT 'login'" );
		}

		if ( is_multisite() ) {
			self::promote_per_site_options_to_network();
		}

		$trusted_table = ReportedIP_Hive_Schema::table( 'reportedip_hive_trusted_devices' );
		if ( ReportedIP_Hive_Schema::tables_exist() ) {
			$wpdb->query(
				"UPDATE $trusted_table SET expires_at = LEAST( expires_at, DATE_ADD( UTC_TIMESTAMP(), INTERVAL 1 DAY ) )"
			);
		}
	}

	/**
	 * v5 → v6: switch hourly-API-call limit to "auto / tier-bound".
	 *
	 * Before 2.0.7 the option `reportedip_hive_max_api_calls_per_hour` carried
	 * a hard default of 100/h that gated *all* outgoing API calls, reputation
	 * lookups, report submissions, quota sync. From 2.0.7 the value `0` means
	 * "auto: derive caps per bucket from the current tier", which is the
	 * intended behaviour for every install. Per the upgrade brief this resets
	 * the option for every installation, including manual overrides.
	 *
	 * Also drops the legacy single-counter transient so the new per-bucket
	 * counters start from a clean slate.
	 *
	 * Hive Light had no field for the option, so its 100 is the untouched
	 * Light default and becomes the free default 0 as well; kept as 100 it
	 * would cap every paid plan at 100 lookups an hour. Any other value on
	 * a Light install was set on purpose (WP-CLI) and stays.
	 *
	 * @return void
	 * @since  2.0.7
	 */
	private static function migrate_to_v6() {
		$key = 'reportedip_hive_max_api_calls_per_hour';
		if ( ! self::$from_light || 100 === (int) ReportedIP_Hive_Option_Routing::get( $key, 100 ) ) {
			ReportedIP_Hive_Option_Routing::set( $key, 0 );
		}
		delete_site_transient( 'reportedip_hive_hourly_api_calls' );
		delete_transient( 'reportedip_hive_hourly_api_calls' );
	}

	/**
	 * v7:remove the 2.0.9-era local IP blocks set by the decoy-path sensor,
	 * and drop the now-defunct `reportedip_hive_decoy_block_hours` option.
	 *
	 * From 2.0.11 onwards the sensor only logs + community-reports; it no
	 * longer touches the local block table. Stale entries left behind by
	 * earlier versions would still expire on their own clock, but cleaning
	 * them up here keeps the admin UI honest after the upgrade.
	 *
	 * @return void
	 * @since  2.0.11
	 */
	private static function migrate_to_v7() {
		global $wpdb;
		$table = $wpdb->base_prefix . 'reportedip_hive_blocked';
		$wpdb->query( $wpdb->prepare( "DELETE FROM `{$table}` WHERE reason LIKE %s", $wpdb->esc_like( 'decoy_pathblock:' ) . '%' ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name built from $wpdb->base_prefix, LIKE pattern is parameterised.

		delete_site_option( 'reportedip_hive_decoy_block_hours' );

		if ( is_multisite() ) {
			$site_ids = (array) get_sites( array( 'fields' => 'ids' ) );
			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );
				delete_option( 'reportedip_hive_decoy_block_hours' );
				restore_current_blog();
			}
		} else {
			delete_option( 'reportedip_hive_decoy_block_hours' );
		}
	}

	/**
	 * v8:drop the self-hosted SMS-provider settings. From 2.0.25 SMS-2FA is a
	 * Professional feature delivered exclusively through the managed
	 * reportedip.com relay; the third-party provider adapters (Sipgate,
	 * MessageBird, seven.io), the provider selector, the per-provider
	 * credentials store and the per-provider AVV flag no longer exist.
	 *
	 * Removes the now-orphaned options on both single-site (option storage) and
	 * Multisite (network + per-site option storage). Idempotent.
	 *
	 * @return void
	 * @since  2.0.25
	 */
	private static function migrate_to_v8() {
		$keys = array(
			'reportedip_hive_2fa_sms_provider',
			'reportedip_hive_2fa_sms_avv_confirmed',
			'reportedip_hive_2fa_sms_provider_config',
			'reportedip_hive_2fa_sms_from',
		);

		foreach ( $keys as $key ) {
			delete_site_option( $key );
		}

		if ( is_multisite() ) {
			$site_ids = (array) get_sites( array( 'fields' => 'ids' ) );
			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );
				foreach ( $keys as $key ) {
					delete_option( $key );
				}
				restore_current_blog();
			}
		}
	}

	/**
	 * Schema v9: created the audit-log table (2.1.2).
	 *
	 * The add-on owns that table since 3.0.0 and creates it itself. The step
	 * still delegates to the idempotent
	 * {@see ReportedIP_Hive_Schema::ensure_tables()}, so a re-run is a no-op.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	private static function migrate_to_v9() {
		ReportedIP_Hive_Schema::ensure_tables();
	}

	/**
	 * Adds the network-wide `waf_exceptions` table backing the backend-managed
	 * WAF allowlist (rule/group/whole-path exceptions). Created under
	 * `base_prefix` so a single decision applies across the network, like the
	 * whitelist. Delegates to the idempotent
	 * {@see ReportedIP_Hive_Schema::ensure_tables()}, so a re-run is a no-op.
	 *
	 * @return void
	 * @since  2.1.9
	 */
	private static function migrate_to_v10() {
		ReportedIP_Hive_Schema::ensure_tables();
	}

	/**
	 * Clears a poisoned API-statistics counter.
	 *
	 * Before 2.1.18 `reportedip_hive_api_stats` was a lifetime cumulative
	 * counter with no reset, so a single outage could pin `success_rate` low
	 * forever and brand the install "API health degraded" indefinitely. The
	 * rolling health window introduced in 2.1.18 fixes this going forward; this
	 * migration removes the legacy stuck value so the dashboard recovers on
	 * upgrade. Only installs that actually look poisoned (enough calls, low
	 * lifetime rate) are reset, healthy installs keep their usage history.
	 *
	 * @return void
	 * @since  2.1.18
	 */
	private static function migrate_to_v11() {
		$stats = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_stats', array() );

		if ( ! is_array( $stats ) || empty( $stats ) ) {
			return;
		}

		$total        = (int) ( $stats['total_calls'] ?? 0 );
		$success_rate = (float) ( $stats['success_rate'] ?? 100 );

		if ( $total < 10 || $success_rate >= 80 ) {
			return;
		}

		ReportedIP_Hive_Option_Routing::set(
			'reportedip_hive_api_stats',
			array(
				'total_calls'         => 0,
				'successful_calls'    => 0,
				'failed_calls'        => 0,
				'total_response_time' => 0,
				'last_reset'          => current_time( 'mysql', true ),
				'error_types'         => array(),
				'recent'              => array(),
				'recent_total'        => 0,
				'recent_success_rate' => 100.0,
				'success_rate'        => 0,
				'avg_response_time'   => 0,
			)
		);

		delete_transient( 'reportedip_hive_health_warning_logged' );
	}

	/**
	 * Lifts automatic and reputation blocks that target the server itself.
	 *
	 * Until 2.1.31 the burst sensors could auto-block the site's own address:
	 * cache-preload crawlers and WP-Cron loopbacks arrive with the server's
	 * public IP as REMOTE_ADDR and look exactly like an attacker to a
	 * windowed counter. The runtime guard now prevents new self-blocks; this
	 * migration heals installs already carrying one so the fix does not wait
	 * for the block to expire. Lifting the block through
	 * {@see ReportedIP_Hive_Database::unblock_ip()} also rewrites the
	 * pre-WordPress blocklist file via the `reportedip_hive_ip_unblocked`
	 * action.
	 *
	 * @return void
	 * @since  2.1.31
	 */
	private static function migrate_to_v12() {
		$database = ReportedIP_Hive_Database::get_instance();

		foreach ( (array) $database->get_blocked_ips( true ) as $row ) {
			if ( ! in_array( (string) $row->block_type, array( 'automatic', 'reputation' ), true ) ) {
				continue;
			}
			if ( ReportedIP_Hive::is_own_server_ip( (string) $row->ip_address ) ) {
				$database->unblock_ip( (string) $row->ip_address );
			}
		}
	}

	/**
	 * Migrate to v13: rebalance the logs/api_queue index set for the hot paths.
	 *
	 * Adds (idempotent via {@see ReportedIP_Hive_Schema::index_exists()}):
	 *   - `logs (event_type, created_at, ip_address)`, carries the
	 *     coordinated-attack window aggregate (index-only, measured 50 ms →
	 *     34 ms at 20k rows in-window) and `get_event_type_counts()`, both of
	 *     which had no usable composite before and fell back to scans.
	 *   - `api_queue (ip_address)`, carries `is_recently_processed()` and the
	 *     duplicate-report check, which fire on every threshold trip.
	 *
	 * Drops dead weight on `logs`: `idx_severity` and `idx_reported_to_api`
	 * (ultra-low-cardinality, no reader) and `idx_event_type` (fully covered
	 * by the new composite's leftmost prefix). Every security event pays each
	 * index tree on INSERT, so the swap is net-neutral at three-for-two.
	 *
	 * @return void
	 * @since  2.1.32
	 */
	private static function migrate_to_v13() {
		global $wpdb;

		$logs  = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_LOGS );
		$queue = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_API_QUEUE );

		if ( ! ReportedIP_Hive_Schema::index_exists( ReportedIP_Hive_Schema::TABLE_LOGS, 'idx_logs_event_time' ) ) {
			$wpdb->query( "ALTER TABLE $logs ADD INDEX idx_logs_event_time (event_type, created_at, ip_address)" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Schema migration.
		}
		if ( ! ReportedIP_Hive_Schema::index_exists( ReportedIP_Hive_Schema::TABLE_API_QUEUE, 'idx_ip_address' ) ) {
			$wpdb->query( "ALTER TABLE $queue ADD INDEX idx_ip_address (ip_address)" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Schema migration.
		}

		foreach ( array( 'idx_severity', 'idx_reported_to_api', 'idx_event_type' ) as $dead_index ) {
			if ( ReportedIP_Hive_Schema::index_exists( ReportedIP_Hive_Schema::TABLE_LOGS, $dead_index ) ) {
				$wpdb->query( "ALTER TABLE $logs DROP INDEX $dead_index" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Schema migration.
			}
		}
	}

	/**
	 * Migrate to v14: point the stored API endpoint at reportedip.com.
	 *
	 * The service moved from reportedip.de to reportedip.com. Installs that
	 * still carry the old default endpoint in `reportedip_hive_api_endpoint`
	 * are rewritten to the new default; custom endpoints (self-hosted proxies,
	 * staging targets) are left untouched. The old domain keeps a permanent
	 * redirect, so unmigrated installs continue to work either way, this
	 * just removes the extra hop. Idempotent, no schema change.
	 *
	 * @return void
	 * @since  2.1.37
	 */
	private static function migrate_to_v14() {
		$stored = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_endpoint', '' );

		if ( '' === $stored ) {
			return;
		}

		if ( rtrim( $stored, '/' ) === 'https://reportedip.de/wp-json/reportedip/v2' ) {
			ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_api_endpoint', 'https://reportedip.com/wp-json/reportedip/v2/' );
		}
	}

	/**
	 * Migrate to v15: make the attempts counter race-safe.
	 *
	 * `track_attempt()` used to read-then-update, which loses increments under
	 * exactly the burst load the sensors exist for, and its "new row after one
	 * idle hour" behavior produced duplicate rows per (ip, attempt_type) by
	 * design. This migration:
	 *
	 *   1. Deduplicates through
	 *      {@see ReportedIP_Hive_Schema::merge_duplicate_attempts()}: one row
	 *      per (ip_address, attempt_type) carrying the summed counters (until
	 *      3.0.0 the stale rows were dropped and their counts lost).
	 *   2. Adds `UNIQUE KEY unique_ip_type (ip_address, attempt_type)` so the
	 *      rewritten `track_attempt()` upsert (`INSERT ... ON DUPLICATE KEY
	 *      UPDATE` with a conditional one-hour window reset) is atomic.
	 *   3. Drops the now-redundant non-unique `composite_ip_type` index.
	 *
	 * @return void
	 * @since  2.1.41
	 */
	private static function migrate_to_v15() {
		global $wpdb;

		$attempts = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_ATTEMPTS );

		if ( ! ReportedIP_Hive_Schema::index_exists( ReportedIP_Hive_Schema::TABLE_ATTEMPTS, 'unique_ip_type' ) ) {
			ReportedIP_Hive_Schema::merge_duplicate_attempts();

			$wpdb->query( "ALTER TABLE $attempts ADD UNIQUE KEY unique_ip_type (ip_address, attempt_type)" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Schema migration.
		}

		if ( ReportedIP_Hive_Schema::index_exists( ReportedIP_Hive_Schema::TABLE_ATTEMPTS, 'composite_ip_type' ) ) {
			$wpdb->query( "ALTER TABLE $attempts DROP INDEX composite_ip_type" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Schema migration.
		}
	}

	/**
	 * Lifts stored reputation-block thresholds onto the new floor.
	 *
	 * 2.1.50 introduced `ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD` after
	 * legitimate visitors were blocked by sites running sub-floor thresholds.
	 * Enforcement clamps at read time regardless; this normalisation keeps
	 * the value shown in the settings UI equal to the value that is actually
	 * enforced.
	 *
	 * @return void
	 * @since  2.1.50
	 */
	private static function migrate_to_v16() {
		$floor = ReportedIP_Hive_Defaults::MIN_BLOCK_THRESHOLD;

		foreach ( array( 'reportedip_hive_block_threshold', 'reportedip_hive_hardening_block_threshold' ) as $option ) {
			$stored = (int) ReportedIP_Hive_Option_Routing::get( $option, $floor );
			if ( $stored < $floor ) {
				ReportedIP_Hive_Option_Routing::set( $option, $floor );
			}
		}
	}

	/**
	 * Added the object columns to the audit trail (2.1.62).
	 *
	 * Moved to the add-on in 3.0.0, kept so the counter stays linear: the
	 * audit table belongs to the add-on, whose own schema adds the columns
	 * to a table that lacks them.
	 *
	 * @return void
	 * @since  2.1.62
	 */
	private static function migrate_to_v17() {
	}

	/**
	 * Lowers the comment spam counter from five offences an hour to three a
	 * day, on installs that never changed it.
	 *
	 * Five rejected comments inside sixty minutes is a burst almost no
	 * spammer produces: measured over thirteen days on a live magazine, 56
	 * per cent of the spamming addresses posted exactly one comment and only
	 * five addresses out of 104 could ever have reached the old threshold.
	 * A stored value that differs from the old default is the operator's own
	 * decision and stays untouched.
	 *
	 * @return void
	 * @since  2.1.63
	 */
	private static function migrate_to_v18() {
		$pairs = array(
			'reportedip_hive_comment_spam_threshold' => array( 5, 3 ),
			'reportedip_hive_comment_spam_timeframe' => array( 60, 1440 ),
		);

		foreach ( $pairs as $option => $values ) {
			list( $old, $new ) = $values;
			if ( (int) ReportedIP_Hive_Option_Routing::get( $option, $old ) === $old ) {
				ReportedIP_Hive_Option_Routing::set( $option, $new );
			}
		}
	}

	/**
	 * Migrate to v19: the `group` block type for the shared group ban list.
	 *
	 * `ensure_tables()` carries the widened `blocked.block_type` enum and
	 * dbDelta alters the column in place; on a strict-mode server an insert
	 * with the new type would otherwise be refused.
	 *
	 * @return void
	 * @since  2.1.67
	 */
	private static function migrate_to_v19() {
		ReportedIP_Hive_Schema::ensure_tables();
	}

	/**
	 * Migrate to v20: `whitelist.source` tells a group entry from a manual one.
	 *
	 * The group sync writes whitelist rows with `source = group` and only
	 * ever removes rows of that source; every existing row keeps the column
	 * default `manual`, so nothing an operator entered changes hands.
	 *
	 * @return void
	 * @since  2.1.67
	 */
	private static function migrate_to_v20() {
		ReportedIP_Hive_Schema::ensure_tables();
	}

	/**
	 * Created `group_entries`, the group list as the service sent it (2.1.67).
	 *
	 * Moved to the add-on in 3.0.0, kept so the counter stays linear: the
	 * group table belongs to the add-on, whose own schema creates it or
	 * adopts the one a 2.x release left.
	 *
	 * @return void
	 * @since  2.1.67
	 */
	private static function migrate_to_v21() {
	}

	/**
	 * Migrate to v22: drop what the update checker of 2.x left behind.
	 *
	 * 2.x shipped an update checker that polled GitHub releases. The
	 * wordpress.org build has none, so nothing listens to its cron event or
	 * reads its state option any more; both are removed here. The checker
	 * scheduled its event on every site of a network that loaded it, so a
	 * network clears the hook site by site. Idempotent: a second run finds
	 * nothing to remove.
	 *
	 * @return void
	 * @since  3.0.0
	 */
	private static function migrate_to_v22() {
		$hook = 'puc_cron_check_updates-reportedip-hive';
		if ( is_multisite() ) {
			foreach ( (array) get_sites(
				array(
					'fields' => 'ids',
					'number' => 0,
				)
			) as $site_id ) {
				switch_to_blog( (int) $site_id );
				wp_clear_scheduled_hook( $hook );
				delete_option( 'external_updates-reportedip-hive' );
				restore_current_blog();
			}
		} else {
			wp_clear_scheduled_hook( $hook );
		}
		delete_option( 'external_updates-reportedip-hive' );
		delete_site_option( 'external_updates-reportedip-hive' );
	}

	/**
	 * Notice ids whose dismissal rows carried a date or a hash up to 3.0.0.
	 * Since then each id is fixed and the row holds the time of the click,
	 * see {@see ReportedIP_Hive_Admin_Notice::DISMISS_TTL}.
	 */
	public const DATED_DISMISS_IDS = array( 'rate_limited', 'twofa_recommend', 'no_api_key', 'domain_limit', 'queue_warning', 'queue_critical', 'readiness' );

	/**
	 * Migrate to v23: drop the dated notice-dismissal rows.
	 *
	 * Each dismissal used to write a new user-meta row per day (per hour for
	 * the rate-limit notice, per issue set for the readiness notice). The
	 * rows are inert now; one `LIKE` delete per old id removes them. The
	 * fixed rows of 3.0.0 carry no suffix and do not match. Idempotent.
	 *
	 * @return void
	 * @since  3.0.0
	 */
	private static function migrate_to_v23() {
		global $wpdb;
		if ( ! isset( $wpdb->usermeta ) ) {
			return;
		}
		foreach ( self::DATED_DISMISS_IDS as $id ) {
			$like = $wpdb->esc_like( 'reportedip_dismissed_' . $id . '_' ) . '%';
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $like ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- One-time cleanup of inert rows; no cache holds them.
		}
	}

	/**
	 * Migrate to v24: make data stored by ReportedIP Hive Light behave.
	 *
	 * All three steps are data-driven and idempotent, so they also run on a
	 * 2.x install, where they find nothing to change:
	 *
	 *   1. Whitelist entries without an expiry: Light bound `null` through
	 *      `prepare( '%s' )`, which stores the zero date. A NOW() comparison
	 *      is false for it, so the entries stopped working. NULL is the free
	 *      plugin's "never expires".
	 *   2. Whitelist `ip_type`: Light had no such column, dbDelta filled the
	 *      default `ipv4` in, and range entries are only matched with
	 *      `ip_type = 'cidr'`. The type follows from the address.
	 *   3. `attempts.window_start`: a Light column, NOT NULL without a default.
	 *      The free plugin never writes it, so a strict SQL mode would refuse
	 *      every new counter row. It becomes nullable; the values stay.
	 *
	 * @return void
	 * @since  3.0.0
	 */
	private static function migrate_to_v24() {
		global $wpdb;

		$whitelist = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_WHITELIST );
		if ( ReportedIP_Hive_Schema::column_exists( ReportedIP_Hive_Schema::TABLE_WHITELIST, 'expires_at' ) ) {
			$wpdb->query( "UPDATE $whitelist SET expires_at = NULL WHERE expires_at = '0000-00-00 00:00:00'" );
		}
		if ( ReportedIP_Hive_Schema::column_exists( ReportedIP_Hive_Schema::TABLE_WHITELIST, 'ip_type' ) ) {
			$wpdb->query( "UPDATE $whitelist SET ip_type = 'cidr' WHERE ip_address LIKE '%/%' AND ( ip_type IS NULL OR ip_type <> 'cidr' )" );
			$wpdb->query( "UPDATE $whitelist SET ip_type = 'ipv6' WHERE ip_address LIKE '%:%' AND ip_address NOT LIKE '%/%' AND ( ip_type IS NULL OR ip_type <> 'ipv6' )" );
		}
		ReportedIP_Hive_Database::flush_ip_state_caches();

		if ( ReportedIP_Hive_Schema::column_exists( ReportedIP_Hive_Schema::TABLE_ATTEMPTS, 'window_start' ) ) {
			$attempts = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_ATTEMPTS );
			$wpdb->query( "ALTER TABLE $attempts MODIFY window_start datetime NULL DEFAULT NULL" );
		}
	}

	/**
	 * On Multisite installs that previously ran Hive on individual sites,
	 * promote network-class options out of `wp_X_options` into the network
	 * `sitemeta` storage. The first site in `get_sites()` order to have a
	 * value wins (no overwrites). The original per-site row is left intact
	 * so a downgrade to v1.x is non-destructive.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	private static function promote_per_site_options_to_network() {
		$site_ids = (array) get_sites( array( 'fields' => 'ids' ) );
		foreach ( $site_ids as $site_id ) {
			switch_to_blog( (int) $site_id );

			$keys = ReportedIP_Hive_Option_Routing::discover_network_keys_for_promotion();
			foreach ( $keys as $key ) {
				$value = get_option( $key, '__rip_hive_unset__' );
				if ( '__rip_hive_unset__' === $value ) {
					continue;
				}
				if ( false === get_site_option( $key, false ) ) {
					update_site_option( $key, $value );
				}
			}

			restore_current_blog();
		}
	}
}
