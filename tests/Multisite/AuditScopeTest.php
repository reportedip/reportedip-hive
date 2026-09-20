<?php
/**
 * Multisite tests for the audit trail's scope and trigger groups.
 *
 * Network rows carry `blog_id = 0`, site rows the site they happened on, a
 * switched-off trigger group writes nothing, and the network group is only
 * enabled on a network.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.62
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Audit_Scope_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Acting administrator.
	 *
	 * @var int
	 */
	private $actor;

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
		update_site_option( ReportedIP_Hive_Migration_Manager::VERSION_OPTION, ReportedIP_Hive_Migration_Manager::CURRENT_VERSION );

		$this->actor = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $this->actor );

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_known_tier', 'business' );
		delete_site_transient( 'reportedip_hive_api_status' );
		delete_transient( 'reportedip_hive_api_status' );
		delete_site_transient( 'reportedip_hive_relay_quota' );
		delete_transient( 'reportedip_hive_relay_quota' );
		ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_audit_enabled', 1 );
		ReportedIP_Hive_Option_Routing::set( ReportedIP_Hive_Audit_Registry::OPTION_TRIGGERS, wp_json_encode( ReportedIP_Hive_Audit_Registry::default_groups() ) );
		$this->truncate();
	}

	public function tear_down() {
		ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_known_tier' );
		ReportedIP_Hive_Option_Routing::delete( ReportedIP_Hive_Audit_Registry::OPTION_TRIGGERS );
		ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
		wp_set_current_user( 0 );
		$this->truncate();
		parent::tear_down();
	}

	/**
	 * Empty the audit table. DELETE, not TRUNCATE: TRUNCATE is DDL and would
	 * commit the test transaction, leaking rows into the next test.
	 */
	private function truncate() {
		global $wpdb;
		$wpdb->query( 'DELETE FROM ' . ReportedIP_Hive_Schema::table( 'reportedip_hive_audit_log' ) );
	}

	/**
	 * All rows, newest first.
	 *
	 * @return object[]
	 */
	private function rows() {
		global $wpdb;
		return (array) $wpdb->get_results( 'SELECT * FROM ' . ReportedIP_Hive_Schema::table( 'reportedip_hive_audit_log' ) . ' ORDER BY id DESC' );
	}

	public function test_network_group_is_enabled_on_a_network() {
		$this->assertContains( 'multisite', ReportedIP_Hive_Audit_Registry::enabled_groups() );
	}

	public function test_explicit_scope_and_current_site_are_stored() {
		$logger = ReportedIP_Hive_Audit_Logger::get_instance();
		$logger->record( 'plugin', 'deactivated', array(), $this->actor, 'admin', array( 'type' => 'plugin', 'id' => 0, 'label' => 'Akismet' ), 0 );

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		$logger->record( 'content', 'trashed', array(), $this->actor, 'admin', array( 'type' => 'post', 'id' => 5, 'label' => 'Imprint' ) );
		restore_current_blog();

		$rows = $this->rows();
		$this->assertCount( 2, $rows );
		$this->assertSame( $blog_id, (int) $rows[0]->blog_id );
		$this->assertSame( 'Imprint', $rows[0]->object_label );
		$this->assertSame( 5, (int) $rows[0]->object_id );
		$this->assertSame( 0, (int) $rows[1]->blog_id );
		$this->assertSame( 'plugin', $rows[1]->object_type );
		$this->assertSame( $this->actor, (int) $rows[1]->user_id );
	}

	public function test_a_switched_off_group_writes_nothing() {
		ReportedIP_Hive_Option_Routing::set( ReportedIP_Hive_Audit_Registry::OPTION_TRIGGERS, wp_json_encode( array( 'users' ) ) );

		$logger = ReportedIP_Hive_Audit_Logger::get_instance();
		$logger->record( 'plugin', 'deactivated', array(), $this->actor, 'admin', array( 'type' => 'plugin', 'id' => 0, 'label' => 'Akismet' ), 0 );
		$logger->record( 'user_block', 'blocked', array(), $this->actor, 'admin', array( 'type' => 'user', 'id' => 9, 'label' => 'someone' ) );

		$rows = $this->rows();
		$this->assertCount( 1, $rows );
		$this->assertSame( 'user_block', $rows[0]->event_type );
	}

	public function test_site_deletion_row_survives_the_per_site_cleanup() {
		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		ReportedIP_Hive_Audit_Logger::get_instance()->record( 'content', 'trashed', array(), $this->actor, 'admin', array( 'type' => 'post', 'id' => 5, 'label' => 'Imprint' ) );
		restore_current_blog();

		ReportedIP_Hive_Audit_Logger::load_connectors();
		( new ReportedIP_Hive_Audit_Connector_Multisite() )->register();
		wp_delete_site( $blog_id );

		$rows = $this->rows();
		$this->assertCount( 1, $rows, 'the site row is gone, the network row stays' );
		$this->assertSame( 'site', $rows[0]->event_type );
		$this->assertSame( 'deleted', $rows[0]->event_action );
		$this->assertSame( 0, (int) $rows[0]->blog_id );
		$this->assertSame( $blog_id, (int) $rows[0]->object_id );
	}
}
