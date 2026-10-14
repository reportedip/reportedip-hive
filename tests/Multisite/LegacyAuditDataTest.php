<?php
/**
 * Multisite tests for the audit rows a 2.x release left behind: without the
 * add-on the free plugin still expires them, exports and erases them and
 * removes a deleted site's rows; with the add-on it keeps out.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Legacy_Audit_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Fully qualified audit table name.
	 *
	 * @var string
	 */
	private $table = '';

	/**
	 * The user the rows are about.
	 *
	 * @var int
	 */
	private $user_id = 0;

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		remove_filter( 'query', array( $this, '_create_temporary_tables' ) );
		remove_filter( 'query', array( $this, '_drop_temporary_tables' ) );
		$this->table   = ReportedIP_Hive_Schema::table( 'reportedip_hive_audit_log' );
		$this->user_id = self::factory()->user->create( array( 'user_email' => 'legacy-audit@example.org' ) );
		ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_audit_retention_days' );
	}

	public function tear_down() {
		global $wpdb;
		$wpdb->query( "DROP TABLE IF EXISTS {$this->table}" );
		ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_audit_retention_days' );
		parent::tear_down();
	}

	/**
	 * Create the table as 2.1.74 (with the object columns) or 2.1.61 left it,
	 * with four rows: an old one of the user on blog 99, a fresh one of the
	 * user, a fresh one about the user's account and one of somebody else.
	 *
	 * @param bool $with_objects Whether the 2.1.62 object columns exist.
	 * @return void
	 */
	private function seed( $with_objects = true ) {
		global $wpdb;
		$objects = $with_objects ? ', object_type varchar(32) DEFAULT NULL, object_id bigint(20) unsigned DEFAULT NULL, object_label varchar(200) DEFAULT NULL' : '';
		$wpdb->query( "DROP TABLE IF EXISTS {$this->table}" );
		$wpdb->query( "CREATE TABLE {$this->table} ( id bigint(20) unsigned NOT NULL AUTO_INCREMENT, blog_id int(11) unsigned NOT NULL DEFAULT 0, created_at datetime DEFAULT CURRENT_TIMESTAMP, ip varchar(64) DEFAULT NULL, user_id bigint(20) unsigned DEFAULT NULL, username varchar(60) DEFAULT NULL, event_type varchar(32) NOT NULL, event_action varchar(64) NOT NULL, event_data text DEFAULT NULL{$objects}, PRIMARY KEY  (id) )" );

		$old   = gmdate( 'Y-m-d H:i:s', time() - 200 * DAY_IN_SECONDS );
		$fresh = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$rows  = array(
			array( 99, $old, '198.51.100.1', $this->user_id, 'legacy', 'settings', 'updated' ),
			array( 1, $fresh, '198.51.100.2', $this->user_id, 'legacy', 'content', 'trashed' ),
			array( 1, $fresh, '198.51.100.3', 1, 'admin', 'users', 'role_changed' ),
			array( 1, $fresh, '198.51.100.4', 1, 'admin', 'installer', 'activated' ),
		);
		foreach ( $rows as $i => $row ) {
			$data = array(
				'blog_id'      => $row[0],
				'created_at'   => $row[1],
				'ip'           => $row[2],
				'user_id'      => $row[3],
				'username'     => $row[4],
				'event_type'   => $row[5],
				'event_action' => $row[6],
				'event_data'   => '{"n":' . $i . '}',
			);
			if ( $with_objects && 2 === $i ) {
				$data['object_type']  = 'user';
				$data['object_id']    = $this->user_id;
				$data['object_label'] = 'legacy';
			}
			$wpdb->insert( $this->table, $data );
		}
	}

	/**
	 * Let the add-on claim the table.
	 *
	 * @return void
	 */
	private function claim() {
		add_filter(
			'reportedip_hive_schema_tables',
			static function ( $suffixes ) {
				return array_merge( $suffixes, array( 'reportedip_hive_audit_log' ) );
			}
		);
	}

	/**
	 * Row count.
	 *
	 * @return int
	 */
	private function count() {
		global $wpdb;
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$this->table}" );
	}

	public function test_the_free_plugin_neither_creates_nor_claims_the_table() {
		global $wpdb;
		$wpdb->query( "DROP TABLE IF EXISTS {$this->table}" );
		ReportedIP_Hive_Schema::ensure_tables();
		$this->assertNull( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $this->table ) ) );
		$this->assertNotContains( 'reportedip_hive_audit_log', ReportedIP_Hive_Schema::tables() );
		$this->assertFalse( ReportedIP_Hive_Legacy_Data::orphaned( 'reportedip_hive_audit_log' ), 'No table, nothing to look after.' );
	}

	public function test_retention_uses_the_stored_value_or_the_2_x_default() {
		$this->seed();
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_audit_retention_days', 365 );
		$this->assertSame( 0, ReportedIP_Hive_Legacy_Data::cleanup() );

		ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_audit_retention_days' );
		$this->assertSame( 1, ReportedIP_Hive_Legacy_Data::cleanup(), 'Ninety days by default: the 200-day row goes.' );
		$this->assertSame( 3, $this->count() );
	}

	public function test_export_and_erase_cover_the_actor_and_the_account_rows() {
		global $wpdb;
		$this->seed();
		$user = get_userdata( $this->user_id );

		$ids = wp_list_pluck( ReportedIP_Hive_Legacy_Data::export_items( $user ), 'item_id' );
		$this->assertCount( 3, $ids );

		$this->assertSame( 3, ReportedIP_Hive_Legacy_Data::erase( $user ) );
		$this->assertSame( 0, (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$this->table} WHERE user_id = %d OR username = 'legacy' OR object_label IS NOT NULL", $this->user_id ) ) );
		$this->assertSame( 4, $this->count(), 'The rows stay, only the personal fields go.' );
	}

	public function test_the_wordpress_exporter_and_eraser_include_the_legacy_rows() {
		global $wpdb;
		$this->seed();
		$privacy = ReportedIP_Hive_Privacy::get_instance();

		$export = $privacy->export_personal_data( 'legacy-audit@example.org' );
		$audit  = wp_list_filter( $export['data'], array( 'group_id' => 'reportedip-hive-audit' ) );
		$this->assertCount( 3, $audit );

		$erase = $privacy->erase_personal_data( 'legacy-audit@example.org' );
		$this->assertGreaterThanOrEqual( 3, $erase['items_removed'] );
		$this->assertSame( 0, (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$this->table} WHERE user_id = %d", $this->user_id ) ) );
	}

	public function test_a_2_1_61_table_is_exported_and_erased_by_its_user_column() {
		$this->seed( false );
		$user = get_userdata( $this->user_id );
		$this->assertCount( 2, ReportedIP_Hive_Legacy_Data::export_items( $user ) );
		$this->assertSame( 2, ReportedIP_Hive_Legacy_Data::erase( $user ) );
	}

	public function test_a_deleted_site_loses_its_legacy_rows() {
		global $wpdb;
		$this->seed();
		ReportedIP_Hive_Schema::cleanup_blog_data( 99 );
		$this->assertSame( 0, (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$this->table} WHERE blog_id = 99" ) );
		$this->assertSame( 3, $this->count() );
	}

	public function test_a_claimed_table_is_left_to_the_add_on() {
		$this->seed();
		$this->claim();
		$user = get_userdata( $this->user_id );
		$this->assertSame( 0, ReportedIP_Hive_Legacy_Data::cleanup() );
		$this->assertSame( array(), ReportedIP_Hive_Legacy_Data::export_items( $user ) );
		$this->assertSame( 0, ReportedIP_Hive_Legacy_Data::erase( $user ) );
		$this->assertSame( 4, $this->count() );
	}
}
