<?php
/**
 * Multisite tests for the attack-surface switches.
 *
 * The switches are network state, and the uploads block is a single file at
 * the main site's basedir, sub-sites inherit it through the directory tree.
 * Both properties break silently on a network, so they run against a real
 * WordPress rather than a mock.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.51
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Attack_Surface_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Option keys the tests write, reset before and after each case.
	 *
	 * @var string[]
	 */
	private $touched = array(
		'reportedip_hive_rest_access_mode',
		'reportedip_hive_rest_allowed_namespaces',
		'reportedip_hive_rest_allowed_roles',
		'reportedip_hive_disable_xmlrpc',
		'reportedip_hive_block_uploads_php',
	);

	/**
	 * Skip on single-site runs and start from a clean state.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}

		$this->reset_options();
		wp_set_current_user( 0 );
	}

	/**
	 * Drop every option the case wrote.
	 */
	public function tear_down() {
		$this->reset_options();
		parent::tear_down();
	}

	/**
	 * Remove the touched options from sitemeta and from the current blog.
	 */
	private function reset_options() {
		foreach ( $this->touched as $key ) {
			ReportedIP_Hive_Option_Routing::delete( $key );
			delete_option( $key );
		}
	}

	public function test_switch_options_are_network_wide() {
		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_disable_xmlrpc', 1 );
		$local = get_option( 'reportedip_hive_disable_xmlrpc' );
		restore_current_blog();

		$this->assertFalse( $local, 'A switch written from a sub-site must not land in that blog options table.' );
		$this->assertTrue( (bool) get_site_option( 'reportedip_hive_disable_xmlrpc' ), 'The switch belongs to the network.' );
		$this->assertTrue( ReportedIP_Hive_Attack_Surface::switch_on( ReportedIP_Hive_Attack_Surface::OPT_XMLRPC_OFF ) );
	}

	public function test_uploads_writer_targets_the_main_site_basedir() {
		$main    = wp_get_upload_dir();
		$blog_id = self::factory()->blog->create();

		switch_to_blog( $blog_id );
		$target = ReportedIP_Hive_Uploads_Htaccess_Writer::get_instance()->get_target_path();
		restore_current_blog();

		$this->assertSame(
			rtrim( (string) $main['basedir'], '/\\' ) . '/.htaccess',
			$target,
			'One file at the main-site basedir covers sites/N/ through directory inheritance.'
		);
		$this->assertStringNotContainsString( '/sites/', $target );
	}

	public function test_uploads_writer_roundtrip_leaves_no_skeleton() {
		$writer = ReportedIP_Hive_Uploads_Htaccess_Writer::get_instance();
		$file   = $writer->get_target_path();
		$this->assertNotSame( '', $file );

		$existed  = file_exists( $file );
		$original = $existed ? (string) file_get_contents( $file ) : '';

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_block_uploads_php', 1 );
		$this->assertTrue( $writer->sync() );
		$this->assertTrue( $writer->is_block_present() );
		$this->assertStringContainsString( 'Require all denied', (string) file_get_contents( $file ) );

		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_block_uploads_php', 0 );
		$this->assertTrue( $writer->sync() );
		$this->assertFalse( $writer->is_block_present() );

		$after = file_exists( $file ) ? (string) file_get_contents( $file ) : '';
		$this->assertStringNotContainsString( '# BEGIN ' . ReportedIP_Hive_Uploads_Htaccess_Writer::MARKER, $after );
		$this->assertStringNotContainsString( '# END ' . ReportedIP_Hive_Uploads_Htaccess_Writer::MARKER, $after );

		if ( $existed ) {
			file_put_contents( $file, $original );
		} elseif ( file_exists( $file ) ) {
			unlink( $file );
		}
	}

	public function test_super_admin_keeps_rest_access_in_restricted_mode() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_rest_access_mode', 'restricted' );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_rest_allowed_roles', wp_json_encode( array( 'administrator' ) ) );

		$blog_id = self::factory()->blog->create();
		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		grant_super_admin( $user_id );

		switch_to_blog( $blog_id );
		wp_set_current_user( $user_id );

		$previous                              = isset( $GLOBALS['wp']->query_vars['rest_route'] ) ? $GLOBALS['wp']->query_vars['rest_route'] : null;
		$GLOBALS['wp']->query_vars['rest_route'] = '/wp/v2/posts';

		$result = ReportedIP_Hive_Attack_Surface::get_instance()->filter_rest_authentication( null );

		if ( null === $previous ) {
			unset( $GLOBALS['wp']->query_vars['rest_route'] );
		} else {
			$GLOBALS['wp']->query_vars['rest_route'] = $previous;
		}
		wp_set_current_user( 0 );
		restore_current_blog();

		$this->assertNull( $result, 'A super admin must never be locked out of the REST API on a sub-site.' );

		revoke_super_admin( $user_id );
	}

	public function test_anonymous_request_is_denied_on_a_sub_site() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_rest_access_mode', 'logged_in' );

		$blog_id = self::factory()->blog->create();
		switch_to_blog( $blog_id );

		$previous                                = isset( $GLOBALS['wp']->query_vars['rest_route'] ) ? $GLOBALS['wp']->query_vars['rest_route'] : null;
		$GLOBALS['wp']->query_vars['rest_route'] = '/wp/v2/posts';

		$result = ReportedIP_Hive_Attack_Surface::get_instance()->filter_rest_authentication( null );

		if ( null === $previous ) {
			unset( $GLOBALS['wp']->query_vars['rest_route'] );
		} else {
			$GLOBALS['wp']->query_vars['rest_route'] = $previous;
		}
		restore_current_blog();

		$this->assertInstanceOf( 'WP_Error', $result );
		$this->assertSame( 'rest_disabled_for_guests', $result->get_error_code() );
	}
}
