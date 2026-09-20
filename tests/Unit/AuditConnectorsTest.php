<?php
/**
 * Pure decision helpers of the audit connectors.
 *
 * The connectors' hook callbacks need WordPress; their decisions do not. This
 * pins the noise rules (which status transitions are rows, which post types
 * never are), the diffs (sidebars, menu locations, roles, sites), the upgrader
 * context normalisation and the value storage rules.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.62
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/includes/class-audit-registry.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-audit-logger.php';
	require_once dirname( __DIR__, 2 ) . '/includes/audit/class-audit-connector.php';
	require_once dirname( __DIR__, 2 ) . '/includes/audit/class-audit-connector-content.php';
	require_once dirname( __DIR__, 2 ) . '/includes/audit/class-audit-connector-installer.php';
	require_once dirname( __DIR__, 2 ) . '/includes/audit/class-audit-connector-settings.php';
	require_once dirname( __DIR__, 2 ) . '/includes/audit/class-audit-connector-menus.php';
	require_once dirname( __DIR__, 2 ) . '/includes/audit/class-audit-connector-multisite.php';

	/**
	 * @covers \ReportedIP_Hive_Audit_Connector
	 * @covers \ReportedIP_Hive_Audit_Connector_Content
	 * @covers \ReportedIP_Hive_Audit_Connector_Installer
	 * @covers \ReportedIP_Hive_Audit_Connector_Settings
	 * @covers \ReportedIP_Hive_Audit_Connector_Menus
	 * @covers \ReportedIP_Hive_Audit_Connector_Multisite
	 */
	class AuditConnectorsTest extends TestCase {

		public function test_content_classify_only_reports_visible_changes(): void {
			$c = '\ReportedIP_Hive_Audit_Connector_Content';
			$this->assertSame( 'published', $c::classify( 'draft', 'publish', 'page' ) );
			$this->assertSame( 'published', $c::classify( 'auto-draft', 'publish', 'post' ) );
			$this->assertSame( 'published', $c::classify( 'pending', 'future', 'post' ) );
			$this->assertSame( 'unpublished', $c::classify( 'publish', 'draft', 'page' ) );
			$this->assertSame( 'unpublished', $c::classify( 'private', 'pending', 'page' ) );
			$this->assertNull( $c::classify( 'publish', 'publish', 'page' ), 'an ordinary edit is not a row' );
			$this->assertNull( $c::classify( 'draft', 'pending', 'page' ), 'invisible either way' );
			$this->assertNull( $c::classify( 'publish', 'trash', 'page' ), 'the trash hook owns the trash' );
			$this->assertNull( $c::classify( 'trash', 'publish', 'page' ), 'the untrash hook owns the restore' );
			$this->assertNull( $c::classify( 'publish', 'private', 'page' ), 'still visible to someone' );
			$this->assertNull( $c::classify( 'draft', 'publish', 'revision' ) );
			$this->assertNull( $c::classify( 'draft', 'publish', 'customize_changeset' ) );
			$this->assertNull( $c::classify( 'draft', 'publish', 'nav_menu_item' ) );
		}

		public function test_installer_normalises_single_bulk_and_other_types(): void {
			$i = '\ReportedIP_Hive_Audit_Connector_Installer';
			$this->assertSame(
				array(
					array(
						'type'   => 'plugin',
						'action' => 'updated',
						'slug'   => 'akismet/akismet.php',
					),
				),
				$i::from_hook_extra(
					array(
						'action' => 'update',
						'type'   => 'plugin',
						'plugin' => 'akismet/akismet.php',
						'bulk'   => false,
					)
				)
			);

			$bulk = $i::from_hook_extra(
				array(
					'action'  => 'update',
					'type'    => 'theme',
					'themes'  => array( 'twentytwentyfive', 'astra' ),
					'bulk'    => true,
				)
			);
			$this->assertCount( 2, $bulk );
			$this->assertSame( 'theme', $bulk[0]['type'] );
			$this->assertSame( 'updated', $bulk[1]['action'] );
			$this->assertSame( 'astra', $bulk[1]['slug'] );

			$this->assertSame( array(), $i::from_hook_extra( array( 'action' => 'update', 'type' => 'translation' ) ) );
			$this->assertSame( array(), $i::from_hook_extra( array( 'action' => 'update', 'type' => 'core' ) ) );
			$this->assertSame( array(), $i::from_hook_extra( array( 'action' => 'install', 'type' => 'plugin' ) ), 'an install without an upgrader has no slug' );
		}

		public function test_sidebar_diff_names_added_and_removed_widgets(): void {
			$old = array(
				'array_version'       => 3,
				'wp_inactive_widgets' => array( 'text-9' ),
				'sidebar-1'           => array( 'search-2', 'recent-posts-2' ),
				'footer'              => array( 'text-3' ),
			);
			$new = array(
				'array_version'       => 3,
				'wp_inactive_widgets' => array( 'text-9', 'recent-posts-2' ),
				'sidebar-1'           => array( 'search-2', 'calendar-1' ),
				'footer'              => array( 'text-3' ),
			);
			$this->assertSame(
				array(
					array( 'sidebar' => 'sidebar-1', 'widget' => 'calendar-1', 'action' => 'added' ),
					array( 'sidebar' => 'sidebar-1', 'widget' => 'recent-posts-2', 'action' => 'removed' ),
				),
				\ReportedIP_Hive_Audit_Connector_Menus::diff_sidebars( $old, $new )
			);
			$this->assertSame( array(), \ReportedIP_Hive_Audit_Connector_Menus::diff_sidebars( $old, $old ) );
		}

		public function test_menu_location_diff_reads_nav_menu_locations_only(): void {
			$old = array( 'nav_menu_locations' => array( 'primary' => 3, 'footer' => 5 ), 'custom_logo' => 12 );
			$new = array( 'nav_menu_locations' => array( 'primary' => 7, 'footer' => 5, 'social' => 9 ), 'custom_logo' => 13 );
			$this->assertSame(
				array(
					'primary' => array( 'old' => 3, 'new' => 7 ),
					'social'  => array( 'old' => 0, 'new' => 9 ),
				),
				\ReportedIP_Hive_Audit_Connector_Menus::diff_locations( $old, $new )
			);
			$this->assertSame( array(), \ReportedIP_Hive_Audit_Connector_Menus::diff_locations( array( 'custom_logo' => 1 ), array( 'custom_logo' => 2 ) ) );
		}

		public function test_role_diff_reports_added_removed_and_changed_capabilities(): void {
			$old = array(
				'administrator' => array( 'name' => 'Administrator', 'capabilities' => array( 'read' => true, 'edit_posts' => true ) ),
				'shop_manager'  => array( 'name' => 'Shop Manager', 'capabilities' => array( 'read' => true ) ),
			);
			$new = array(
				'administrator' => array( 'name' => 'Administrator', 'capabilities' => array( 'edit_posts' => true, 'read' => true ) ),
				'auditor'       => array( 'name' => 'Auditor', 'capabilities' => array( 'read' => true ) ),
			);
			$this->assertSame(
				array( 'added' => array( 'auditor' ), 'removed' => array( 'shop_manager' ), 'caps_changed' => array() ),
				\ReportedIP_Hive_Audit_Connector_Settings::diff_roles( $old, $new ),
				'key order inside the capability map is not a change'
			);

			$new['administrator']['capabilities']['unfiltered_html'] = true;
			$this->assertSame( array( 'administrator' ), \ReportedIP_Hive_Audit_Connector_Settings::diff_roles( $old, $new )['caps_changed'] );
		}

		public function test_secret_option_names_are_recognised(): void {
			$this->assertTrue( \ReportedIP_Hive_Audit_Connector_Settings::is_secret( 'reportedip_hive_api_key' ) );
			$this->assertTrue( \ReportedIP_Hive_Audit_Connector_Settings::is_secret( 'mailserver_pass' ) );
			$this->assertFalse( \ReportedIP_Hive_Audit_Connector_Settings::is_secret( 'permalink_structure' ) );
			$this->assertFalse( \ReportedIP_Hive_Audit_Connector_Settings::is_secret( 'reportedip_hive_waf_enabled' ) );
		}

		public function test_site_diff_covers_the_watched_fields_only(): void {
			$old = (object) array( 'domain' => 'a.example', 'path' => '/', 'public' => '1', 'archived' => '0', 'spam' => '0', 'deleted' => '0', 'mature' => '0', 'last_updated' => '2026-01-01' );
			$new = (object) array( 'domain' => 'a.example', 'path' => '/', 'public' => '0', 'archived' => '1', 'spam' => '0', 'deleted' => '0', 'mature' => '0', 'last_updated' => '2026-02-01' );
			$this->assertSame(
				array(
					'public'   => array( 'old' => '1', 'new' => '0' ),
					'archived' => array( 'old' => '0', 'new' => '1' ),
				),
				\ReportedIP_Hive_Audit_Connector_Multisite::diff_site( $old, $new )
			);
		}

		public function test_value_for_row_truncates_scalars_and_diffs_lists(): void {
			$long = str_repeat( 'x', 900 );
			$this->assertSame( 500, strlen( \ReportedIP_Hive_Audit_Connector::value_for_row( $long ) ) );
			$this->assertSame( '1', \ReportedIP_Hive_Audit_Connector::value_for_row( true ) );
			$this->assertSame( '', \ReportedIP_Hive_Audit_Connector::value_for_row( false ), 'an unset option reads as empty' );
			$this->assertSame( '', \ReportedIP_Hive_Audit_Connector::value_for_row( null ) );
			$this->assertSame( '0', \ReportedIP_Hive_Audit_Connector::value_for_row( 0 ) );

			$diff = \ReportedIP_Hive_Audit_Connector::value_for_row( array( 'a/a.php', 'c/c.php' ), array( 'a/a.php', 'b/b.php' ) );
			$this->assertSame( array( 'added' => array( '1=c/c.php' ), 'removed' => array( '1=b/b.php' ) ), $diff );
		}

		public function test_agent_is_web_outside_cli_cron_rest_and_ajax(): void {
			$this->assertSame( 'web', \ReportedIP_Hive_Audit_Connector::agent() );
		}

		public function test_seen_and_suppress_are_request_scoped(): void {
			\ReportedIP_Hive_Audit_Connector::reset_request_state();
			$probe = new class() extends \ReportedIP_Hive_Audit_Connector {
				protected function hooks() {
					return array();
				}
				public static function probe( $key ) {
					return self::seen( $key );
				}
			};
			$this->assertFalse( $probe::probe( 'x' ) );
			$this->assertTrue( $probe::probe( 'x' ) );
			$this->assertFalse( $probe::probe( 'y' ) );

			$this->assertFalse( \ReportedIP_Hive_Audit_Connector::suppressed( 'set_user_role' ) );
			\ReportedIP_Hive_Audit_Connector::suppress( 'set_user_role' );
			$this->assertTrue( \ReportedIP_Hive_Audit_Connector::suppressed( 'set_user_role' ) );
			\ReportedIP_Hive_Audit_Connector::reset_request_state();
			$this->assertFalse( \ReportedIP_Hive_Audit_Connector::suppressed( 'set_user_role' ) );
		}
	}
}
