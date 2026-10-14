<?php
/**
 * Multisite tests for the audit rows a 2.x release left behind: without the
 * add-on the free plugin still expires them, exports and erases them and
 * removes a deleted site's rows; with an add-on claiming the table it keeps
 * out.
 *
 * The table is created once per class (DDL commits the test transaction, so
 * it must not run inside a test); every test seeds its rows inside the
 * transaction, which the test case rolls back.
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
 * Shared fixture: an audit table as 2.1.74 (or 2.1.61) left it and four
 * rows: an old one of the user on blog 99, a fresh one of the user, a fresh
 * one about the user's account (only with the object columns) and one of
 * somebody else.
 */
abstract class ReportedIP_Hive_Legacy_Audit_Fixture extends WP_UnitTestCase {

	/**
	 * Whether the table carries the 2.1.62 object columns.
	 *
	 * @var bool
	 */
	const WITH_OBJECTS = true;

	/**
	 * The user the rows are about.
	 *
	 * @var int
	 */
	protected $user_id = 0;

	/**
	 * Fully qualified table name.
	 *
	 * @return string
	 */
	protected static function audit_table() {
		return ReportedIP_Hive_Schema::table( 'reportedip_hive_audit_log' );
	}

	public static function wpSetUpBeforeClass() {
		global $wpdb;
		$table   = self::audit_table();
		$objects = static::WITH_OBJECTS ? ', object_type varchar(32) DEFAULT NULL, object_id bigint(20) unsigned DEFAULT NULL, object_label varchar(200) DEFAULT NULL' : '';
		$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		$wpdb->query( "CREATE TABLE {$table} ( id bigint(20) unsigned NOT NULL AUTO_INCREMENT, blog_id int(11) unsigned NOT NULL DEFAULT 0, created_at datetime DEFAULT CURRENT_TIMESTAMP, ip varchar(64) DEFAULT NULL, user_id bigint(20) unsigned DEFAULT NULL, username varchar(60) DEFAULT NULL, event_type varchar(32) NOT NULL, event_action varchar(64) NOT NULL, event_data text DEFAULT NULL{$objects}, PRIMARY KEY  (id) )" );
	}

	public static function wpTearDownAfterClass() {
		global $wpdb;
		$wpdb->query( 'DROP TABLE IF EXISTS ' . self::audit_table() );
	}

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		global $wpdb;
		$this->user_id = self::factory()->user->create( array( 'user_email' => 'legacy-audit@example.org' ) );
		ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_audit_retention_days' );

		$table = self::audit_table();
		$wpdb->query( "DELETE FROM {$table}" );
		$old   = gmdate( 'Y-m-d H:i:s', time() - 200 * DAY_IN_SECONDS );
		$fresh = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );
		$rows  = array(
			array( 99, $old, $this->user_id, 'legacy', 'settings', 'updated' ),
			array( 1, $fresh, $this->user_id, 'legacy', 'content', 'trashed' ),
			array( 1, $fresh, 1, 'admin', 'users', 'role_changed' ),
			array( 1, $fresh, 1, 'admin', 'installer', 'activated' ),
		);
		foreach ( $rows as $i => $row ) {
			$data = array(
				'blog_id'      => $row[0],
				'created_at'   => $row[1],
				'ip'           => '198.51.100.' . ( $i + 1 ),
				'user_id'      => $row[2],
				'username'     => $row[3],
				'event_type'   => $row[4],
				'event_action' => $row[5],
				'event_data'   => '{"n":' . $i . '}',
			);
			if ( static::WITH_OBJECTS && 2 === $i ) {
				$data['object_type']  = 'user';
				$data['object_id']    = $this->user_id;
				$data['object_label'] = 'legacy';
			}
			$wpdb->insert( $table, $data );
		}
	}

	/**
	 * Row count.
	 *
	 * @return int
	 */
	protected function row_count() {
		global $wpdb;
		return (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::audit_table() );
	}
}

/**
 * @group ms-required
 */
class ReportedIP_Hive_Legacy_Audit_Multisite_Test extends ReportedIP_Hive_Legacy_Audit_Fixture {

	public function test_the_free_plugin_does_not_claim_the_table() {
		$this->assertNotContains( 'reportedip_hive_audit_log', ReportedIP_Hive_Schema::tables() );
		$this->assertSame( array( 'reportedip_hive_audit_log' ), ReportedIP_Hive_Schema::unclaimed_legacy_tables() );
		$this->assertTrue( ReportedIP_Hive_Legacy_Data::orphaned( 'reportedip_hive_audit_log' ) );
	}

	public function test_retention_uses_the_stored_value_or_the_2_x_default() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_audit_retention_days', 365 );
		$this->assertSame( 0, ReportedIP_Hive_Legacy_Data::cleanup() );

		ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_audit_retention_days' );
		$this->assertSame( 1, ReportedIP_Hive_Legacy_Data::cleanup(), 'Ninety days by default: the 200-day row goes.' );
		$this->assertSame( 3, $this->row_count() );
	}

	public function test_export_and_erase_cover_the_actor_and_the_account_rows() {
		global $wpdb;
		$user = get_userdata( $this->user_id );

		$this->assertCount( 3, ReportedIP_Hive_Legacy_Data::export_items( $user ) );

		$this->assertSame( 3, ReportedIP_Hive_Legacy_Data::erase( $user ) );
		$this->assertSame( 0, (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . self::audit_table() . " WHERE user_id = %d OR username = 'legacy' OR object_label IS NOT NULL", $this->user_id ) ) );
		$this->assertSame( 4, $this->row_count(), 'The rows stay, only the personal fields go.' );
	}

	public function test_the_wordpress_exporter_and_eraser_include_the_legacy_rows() {
		global $wpdb;
		$privacy = ReportedIP_Hive_Privacy::get_instance();

		$export = $privacy->export_personal_data( 'legacy-audit@example.org' );
		$this->assertCount( 3, wp_list_filter( $export['data'], array( 'group_id' => 'reportedip-hive-audit' ) ) );

		$erase = $privacy->erase_personal_data( 'legacy-audit@example.org' );
		$this->assertGreaterThanOrEqual( 3, $erase['items_removed'] );
		$this->assertSame( 0, (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . self::audit_table() . ' WHERE user_id = %d', $this->user_id ) ) );
	}

	public function test_a_deleted_site_loses_its_legacy_rows() {
		global $wpdb;
		ReportedIP_Hive_Schema::cleanup_blog_data( 99 );
		$this->assertSame( 0, (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . self::audit_table() . ' WHERE blog_id = 99' ) );
		$this->assertSame( 3, $this->row_count() );
	}

	public function test_a_claimed_table_is_left_to_the_add_on() {
		add_filter(
			'reportedip_hive_schema_tables',
			static function ( $suffixes ) {
				return array_merge( $suffixes, array( 'reportedip_hive_audit_log' ) );
			}
		);
		$user = get_userdata( $this->user_id );
		$this->assertSame( 0, ReportedIP_Hive_Legacy_Data::cleanup() );
		$this->assertSame( array(), ReportedIP_Hive_Legacy_Data::export_items( $user ) );
		$this->assertSame( 0, ReportedIP_Hive_Legacy_Data::erase( $user ) );
		$this->assertSame( 4, $this->row_count() );
	}
}

/**
 * @group ms-required
 */
class ReportedIP_Hive_Legacy_Audit_2161_Multisite_Test extends ReportedIP_Hive_Legacy_Audit_Fixture {

	const WITH_OBJECTS = false;

	public function test_a_2_1_61_table_is_exported_and_erased_by_its_user_column() {
		$user = get_userdata( $this->user_id );
		$this->assertCount( 2, ReportedIP_Hive_Legacy_Data::export_items( $user ) );
		$this->assertSame( 2, ReportedIP_Hive_Legacy_Data::erase( $user ) );
	}
}
