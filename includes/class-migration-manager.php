<?php
/**
 * Migration-Manager: numbered, idempotent schema migrations.
 *
 * Each schema bump implements a `migrate_to_v{N}()` method. `maybe_run()`
 * advances `db_version` step by step until it matches `CURRENT_VERSION`,
 * persisting after each successful step. Re-entry is safe — every step
 * checks for already-applied state before touching the schema.
 *
 * Concurrency: `acquire_lock()` uses `add_site_option()` which is atomic on
 * Multisite (sitemeta `meta_key` is UNIQUE) and on single-site
 * (`wp_options.option_name` is UNIQUE). Stale locks expire after `LOCK_TTL`
 * seconds.
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
	public const CURRENT_VERSION = 5;

	/**
	 * Network option name storing the currently-applied schema version.
	 */
	public const VERSION_OPTION = 'reportedip_hive_db_version';

	/**
	 * Network option name used as an atomic lock during migration.
	 */
	public const LOCK_OPTION = 'reportedip_hive_migration_lock';

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

		try {
			for ( $v = $current + 1; $v <= self::CURRENT_VERSION; $v++ ) {
				$method = "migrate_to_v{$v}";
				if ( method_exists( __CLASS__, $method ) ) {
					self::$method();
				}
				update_site_option( self::VERSION_OPTION, $v );
			}
		} finally {
			self::release_lock();
		}
	}

	/**
	 * Atomically acquire the migration lock.
	 *
	 * Uses `add_site_option()` which fails (returns false) when the option
	 * already exists. A stale lock older than LOCK_TTL is force-released
	 * before the second attempt so a crashed migration does not block
	 * future updates indefinitely.
	 *
	 * @return bool True if the lock was acquired, false otherwise.
	 * @since  2.0.0
	 */
	private static function acquire_lock() {
		$existing = get_site_option( self::LOCK_OPTION, 0 );
		if ( $existing ) {
			$age = time() - (int) $existing;
			if ( $age < self::LOCK_TTL ) {
				return false;
			}
			delete_site_option( self::LOCK_OPTION );
		}
		return (bool) add_site_option( self::LOCK_OPTION, time() );
	}

	/**
	 * Release the migration lock unconditionally.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	private static function release_lock() {
		delete_site_option( self::LOCK_OPTION );
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
	 *      Pfad B from the spec — installs that previously had Hive activated
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
				"UPDATE $trusted_table SET expires_at = LEAST( expires_at, DATE_ADD( NOW(), INTERVAL 1 DAY ) )"
			);
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
