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
 * @author    Patrick Schlesinger <1@reportedip.de>
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
	public const CURRENT_VERSION = 11;

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
				"UPDATE $trusted_table SET expires_at = LEAST( expires_at, DATE_ADD( UTC_TIMESTAMP(), INTERVAL 1 DAY ) )"
			);
		}
	}

	/**
	 * v5 → v6: switch hourly-API-call limit to "auto / tier-bound".
	 *
	 * Before 2.0.7 the option `reportedip_hive_max_api_calls_per_hour` carried
	 * a hard default of 100/h that gated *all* outgoing API calls — reputation
	 * lookups, report submissions, quota sync. From 2.0.7 the value `0` means
	 * "auto: derive caps per bucket from the current tier", which is the
	 * intended behaviour for every install. Per the upgrade brief this resets
	 * the option for every installation, including manual overrides.
	 *
	 * Also drops the legacy single-counter transient so the new per-bucket
	 * counters start from a clean slate.
	 *
	 * @return void
	 * @since  2.0.7
	 */
	private static function migrate_to_v6() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_max_api_calls_per_hour', 0 );
		delete_site_transient( 'reportedip_hive_hourly_api_calls' );
		delete_transient( 'reportedip_hive_hourly_api_calls' );
	}

	/**
	 * v7 — remove the 2.0.9-era local IP blocks set by the decoy-path sensor,
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
	 * v8 — drop the self-hosted SMS-provider settings. From 2.0.25 SMS-2FA is a
	 * Professional feature delivered exclusively through the managed
	 * reportedip.de relay; the third-party provider adapters (Sipgate,
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
	 * Schema v9: create the audit-log table.
	 *
	 * Backs the Business-tier audit event trail. Created network-wide (under
	 * `base_prefix`) so a site that later upgrades captures immediately.
	 * Delegates to the idempotent {@see ReportedIP_Hive_Schema::ensure_tables()},
	 * so a re-run is a no-op.
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
	 * lifetime rate) are reset — healthy installs keep their usage history.
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
