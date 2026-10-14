<?php
/**
 * Personal data a 2.x release stored in a table that an add-on owns since 3.0.0.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     3.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table names from base_prefix and the legacy suffix list; every value bound through prepare().

/**
 * Retention, export and erasure for a legacy table no add-on claims.
 *
 * A site that used the audit trail under 2.x keeps its rows (addresses,
 * user names, old and new values) when it runs the free plugin alone. 2.x
 * cleaned them by retention whatever the plan, listed them in the personal
 * data export and erased them on request. The free plugin keeps exactly
 * these duties for the tables of {@see ReportedIP_Hive_Schema::LEGACY_SUFFIXES}
 * while no add-on lists them through `reportedip_hive_schema_tables`
 * ({@see ReportedIP_Hive_Schema::unclaimed_legacy_tables()}); while one does,
 * the add-on does the work and this class stays out. Uninstall and the
 * per-site cleanup run through the schema's table list. It never writes a
 * row and renders nothing.
 *
 * @since 3.0.0
 */
final class ReportedIP_Hive_Legacy_Data {

	/**
	 * The audit trail table of 2.x.
	 */
	const AUDIT_LOG = 'reportedip_hive_audit_log';

	/**
	 * Retention per legacy table: stored option, 2.x default in days and the
	 * UTC datetime column the age is read from.
	 *
	 * @var array<string, array{0:string, 1:int, 2:string}>
	 */
	const RETENTION = array(
		self::AUDIT_LOG => array( 'reportedip_hive_audit_retention_days', 90, 'created_at' ),
	);

	/**
	 * Whether a legacy table exists and no add-on claims it.
	 *
	 * @param string $suffix Table suffix.
	 * @return bool
	 */
	public static function orphaned( $suffix ) {
		if ( ! in_array( $suffix, ReportedIP_Hive_Schema::unclaimed_legacy_tables(), true ) ) {
			return false;
		}
		global $wpdb;
		$table = ReportedIP_Hive_Schema::table( $suffix );
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) ) === $table;
	}

	/**
	 * Delete the rows of every orphaned legacy table that are older than its
	 * stored retention, chunked under the shared cleanup time budget like the
	 * free tables. Called from the daily cleanup.
	 *
	 * @return int Rows deleted.
	 */
	public static function cleanup() {
		$deleted = 0;
		foreach ( self::RETENTION as $suffix => $rule ) {
			if ( ! self::orphaned( $suffix ) ) {
				continue;
			}
			list( $option, $default, $column ) = $rule;
			$deleted                          += ReportedIP_Hive_Database::delete_older_than(
				ReportedIP_Hive_Schema::table( $suffix ),
				$column,
				(int) ReportedIP_Hive_Option_Routing::get( $option, $default ),
				time() + ReportedIP_Hive_Database::CLEANUP_TIME_BUDGET
			);
		}
		return $deleted;
	}

	/**
	 * Export items of the orphaned audit trail for one user: the rows the
	 * user acted in and the rows about the user's account, as in 2.x. A
	 * table from before 2.1.62 has no object columns and only the first.
	 *
	 * @param WP_User $user User.
	 * @return array<int, array<string, mixed>>
	 */
	public static function export_items( $user ) {
		if ( ! self::orphaned( self::AUDIT_LOG ) ) {
			return array();
		}
		global $wpdb;
		$table = ReportedIP_Hive_Schema::table( self::AUDIT_LOG );
		$rows  = ReportedIP_Hive_Schema::column_exists( self::AUDIT_LOG, 'object_type' )
			? $wpdb->get_results( $wpdb->prepare( "SELECT id, created_at, ip, event_type, event_action, event_data FROM {$table} WHERE user_id = %d OR (object_type = 'user' AND object_id = %d)", $user->ID, $user->ID ) )
			: $wpdb->get_results( $wpdb->prepare( "SELECT id, created_at, ip, event_type, event_action, event_data FROM {$table} WHERE user_id = %d", $user->ID ) );
		$items = array();
		foreach ( (array) $rows as $row ) {
			$items[] = array(
				'group_id'    => 'reportedip-hive-audit',
				'group_label' => __( 'ReportedIP Hive: audit trail', 'reportedip-hive' ),
				'item_id'     => 'rip-hive-audit-' . (int) $row->id,
				'data'        => array(
					array(
						'name'  => __( 'Time', 'reportedip-hive' ),
						'value' => $row->created_at,
					),
					array(
						'name'  => __( 'Event', 'reportedip-hive' ),
						'value' => $row->event_type,
					),
					array(
						'name'  => __( 'Action', 'reportedip-hive' ),
						'value' => $row->event_action,
					),
					array(
						'name'  => __( 'IP address', 'reportedip-hive' ),
						'value' => $row->ip,
					),
					array(
						'name'  => __( 'Details', 'reportedip-hive' ),
						'value' => $row->event_data,
					),
				),
			);
		}
		return $items;
	}

	/**
	 * Erase one user from the orphaned audit trail as 2.x did: the rows the
	 * user acted in lose name, address, id and details, the rows about the
	 * account lose label and details (a table from before 2.1.62 has no
	 * such rows). The rows themselves stay, so the trail keeps its shape.
	 *
	 * @param WP_User $user User.
	 * @return int Rows changed.
	 */
	public static function erase( $user ) {
		if ( ! self::orphaned( self::AUDIT_LOG ) ) {
			return 0;
		}
		global $wpdb;
		$table   = ReportedIP_Hive_Schema::table( self::AUDIT_LOG );
		$changed = (int) $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET username = '', ip = '', user_id = NULL, event_data = NULL WHERE user_id = %d", $user->ID ) );
		if ( ! ReportedIP_Hive_Schema::column_exists( self::AUDIT_LOG, 'object_type' ) ) {
			return $changed;
		}
		return $changed + (int) $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET object_label = NULL, event_data = NULL WHERE object_type = 'user' AND object_id = %d", $user->ID ) );
	}
}
