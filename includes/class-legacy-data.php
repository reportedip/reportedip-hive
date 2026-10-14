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
 * The group ban list of 2.x left more than a table: blocks of type `group`
 * and whitelist entries of source `group` in the free tables, kept current
 * by a sync that ran every fifteen minutes. Without the add-on nothing
 * refreshes them, and a group whitelist entry the group later dropped
 * would trust an address forever (it cannot even be removed by hand, see
 * {@see ReportedIP_Hive_IP_Manager::remove_from_whitelist()}). 2.x dropped
 * everything the sync placed as soon as groups were no longer available
 * (plan without groups, no key, Local Shield); {@see release_groups()} does
 * the same while no add-on claims the group table, through the IP manager,
 * so both firewall layers learn about every lifted block and every removed
 * whitelist entry.
 *
 * @since 3.0.0
 */
final class ReportedIP_Hive_Legacy_Data {

	/**
	 * The audit trail table of 2.x.
	 */
	const AUDIT_LOG = 'reportedip_hive_audit_log';

	/**
	 * The group list table of 2.x.
	 */
	const GROUP_ENTRIES = 'reportedip_hive_group_entries';

	/**
	 * Cron hook of the 2.x group sync. An update from 2.x leaves the event
	 * scheduled; while no add-on claims the group table, its next run
	 * releases the group state and unschedules it.
	 */
	const GROUP_SYNC_HOOK = 'reportedip_hive_sync_group';

	/**
	 * Block type and whitelist source the 2.x group sync wrote.
	 */
	const GROUP_SOURCE = 'group';

	/**
	 * Free schema version from which both group columns exist
	 * (`blocked.block_type` value `group` in v19, `whitelist.source` in v20).
	 */
	const GROUP_MIN_DB_VERSION = 20;

	/**
	 * Runtime options of the 2.x group sync that a release clears, as 2.x
	 * did: the group, the ETag, the plan refusal marker and the wait of a
	 * key without a group.
	 *
	 * @var string[]
	 */
	const GROUP_OPTIONS = array( 'reportedip_hive_group', 'reportedip_hive_group_etag', 'reportedip_hive_group_error', 'reportedip_hive_group_idle_until' );

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
	 * Whether an add-on claims a legacy table right now.
	 *
	 * @param string $suffix Table suffix.
	 * @return bool
	 */
	private static function claimed( $suffix ) {
		return ! in_array( $suffix, ReportedIP_Hive_Schema::unclaimed_legacy_tables(), true );
	}

	/**
	 * Lift every group block, remove every group whitelist entry and empty
	 * the group list while no add-on claims the group table. Called from the
	 * daily cleanup and from the left-over cron event of the 2.x sync.
	 *
	 * Each row goes through the IP manager, which fires
	 * `reportedip_hive_ip_unblocked` and `reportedip_hive_whitelist_changed`,
	 * so the pre-WordPress guard drops the block from its list and is rebaked
	 * without the whitelist entry. Manual and automatic rows are never
	 * touched. Idempotent: a second run finds nothing.
	 *
	 * @return int Blocks lifted plus whitelist entries removed.
	 */
	public static function release_groups() {
		if ( self::claimed( self::GROUP_ENTRIES ) ) {
			return 0;
		}
		if ( (int) get_site_option( ReportedIP_Hive_Migration_Manager::VERSION_OPTION, 0 ) < self::GROUP_MIN_DB_VERSION ) {
			return 0;
		}

		global $wpdb;
		$ip_manager = ReportedIP_Hive_IP_Manager::get_instance();
		$whitelist  = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_WHITELIST );
		$blocked    = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_BLOCKED );
		$released   = 0;

		foreach ( (array) $wpdb->get_col( $wpdb->prepare( "SELECT ip_address FROM {$whitelist} WHERE source = %s AND is_active = 1", self::GROUP_SOURCE ) ) as $address ) {
			$result = $ip_manager->remove_from_whitelist( (string) $address, self::GROUP_SOURCE );
			if ( ! empty( $result['success'] ) ) {
				++$released;
			}
		}
		foreach ( (array) $wpdb->get_col( $wpdb->prepare( "SELECT ip_address FROM {$blocked} WHERE block_type = %s AND is_active = 1", self::GROUP_SOURCE ) ) as $address ) {
			$result = $ip_manager->unblock_ip( (string) $address );
			if ( ! empty( $result['success'] ) ) {
				++$released;
			}
		}

		if ( self::orphaned( self::GROUP_ENTRIES ) ) {
			$entries = ReportedIP_Hive_Schema::table( self::GROUP_ENTRIES );
			$wpdb->query( "DELETE FROM {$entries}" );
		}
		foreach ( self::GROUP_OPTIONS as $option ) {
			ReportedIP_Hive_Option_Routing::delete( $option );
		}

		return $released;
	}

	/**
	 * Listener on the 2.x cron hook of the group sync: release the group
	 * state and unschedule the event while no add-on claims the group table.
	 * With an add-on that does, the add-on's sync answers the event and this
	 * listener does nothing.
	 *
	 * @return void
	 */
	public static function on_group_sync_event() {
		if ( self::claimed( self::GROUP_ENTRIES ) ) {
			return;
		}
		self::release_groups();
		wp_clear_scheduled_hook( self::GROUP_SYNC_HOOK );
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
