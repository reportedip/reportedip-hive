<?php
/**
 * Multisite test: deleting a site cleans its plugin rows without a
 * database error. `wp_delete_site` fires after core dropped the site's
 * tables, so the handler must not touch per-site options any more.
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
class ReportedIP_Hive_Site_Delete_Multisite_Test extends WP_UnitTestCase {

	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
	}

	public function test_site_delete_cleans_rows_without_db_error() {
		global $wpdb, $EZSQL_ERROR;

		$site = (int) self::factory()->blog->create();
		update_blog_option( $site, 'reportedip_hive_2fa_enforce_roles_extra', array( 'editor' ) );
		$logs = ReportedIP_Hive_Schema::table( ReportedIP_Hive_Schema::TABLE_LOGS );
		$wpdb->insert(
			$logs,
			array(
				'blog_id'    => $site,
				'event_type' => 'failed_login',
				'ip_address' => '203.0.113.9',
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
			)
		);

		$errors_before = is_array( $EZSQL_ERROR ) ? count( $EZSQL_ERROR ) : 0;
		$suppress      = $wpdb->suppress_errors( true );
		$last_error    = 'not reached';
		$capture       = static function () use ( &$last_error ) {
			global $wpdb;
			$last_error = $wpdb->last_error;
		};
		add_action( 'wp_delete_site', $capture, 11 );

		$deleted = wp_delete_site( $site );

		remove_action( 'wp_delete_site', $capture, 11 );
		$wpdb->suppress_errors( $suppress );
		$new_errors = array_slice( is_array( $EZSQL_ERROR ) ? $EZSQL_ERROR : array(), $errors_before );

		$this->assertInstanceOf( WP_Site::class, $deleted );
		$this->assertSame( '', $last_error );
		$this->assertSame( array(), $new_errors );
		$this->assertSame(
			'0',
			$wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $logs WHERE blog_id = %d", $site ) )
		);
	}
}
