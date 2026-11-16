<?php
/**
 * Multisite tests for the remote settings apply path.
 *
 * A remote apply arriving at any connected sub-site must write network
 * options (sitemeta) so the whole network converges, and the settings hash
 * must be identical no matter which sub-site reports it.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.47
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Settings_Remote_Apply_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Skip the entire class on single-site test runs.
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
	}

	/**
	 * Applying from a sub-site context writes the network option.
	 */
	public function test_apply_from_sub_site_writes_network_option() {
		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );

		$result = ReportedIP_Hive_Settings_Apply::apply(
			array( 'reportedip_hive_failed_login_threshold' => 42 ),
			'test'
		);

		restore_current_blog();

		$this->assertSame( 'applied', $result['results']['reportedip_hive_failed_login_threshold']['status'] );
		$this->assertSame( 42, (int) get_site_option( 'reportedip_hive_failed_login_threshold' ) );
	}

	/**
	 * The settings hash is network-scoped: every sub-site reports the same
	 * fingerprint, so a dashboard can recognise sibling sub-sites.
	 */
	public function test_settings_hash_is_identical_across_sub_sites() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_failed_login_threshold', 23 );

		$main_hash = ReportedIP_Hive_Settings_Registry::settings_hash();

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		$sub_hash = ReportedIP_Hive_Settings_Registry::settings_hash();
		restore_current_blog();

		$this->assertSame( $main_hash, $sub_hash );
	}

	/**
	 * The cloud transport uses the same apply pipeline: an apply with the
	 * `cloud` origin arriving at a sub-site converges the whole network.
	 */
	public function test_cloud_origin_apply_from_sub_site_writes_network_option() {
		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );

		$result = ReportedIP_Hive_Settings_Apply::apply(
			array( 'reportedip_hive_failed_login_threshold' => 17 ),
			'cloud'
		);

		restore_current_blog();

		$this->assertSame( 'applied', $result['results']['reportedip_hive_failed_login_threshold']['status'] );
		$this->assertSame( 17, (int) get_site_option( 'reportedip_hive_failed_login_threshold' ) );
	}

	/**
	 * The shared values envelope flags multisite so dashboards can warn that
	 * an apply acts network-wide.
	 */
	public function test_values_envelope_flags_network_wide_on_multisite() {
		$envelope = ReportedIP_Hive_Settings_Registry::values_envelope();

		$this->assertTrue( $envelope['network_wide'] );
		$this->assertSame( ReportedIP_Hive_Settings_Registry::settings_hash(), $envelope['hash'] );
	}

	/**
	 * The per-site override keys must never be remote-manageable.
	 */
	public function test_per_site_override_keys_are_not_remote() {
		$result = ReportedIP_Hive_Settings_Apply::apply(
			array( 'reportedip_hive_2fa_frontend_slug_site_override' => 'evil-slug' ),
			'test'
		);

		$this->assertSame(
			'unknown_key',
			$result['results']['reportedip_hive_2fa_frontend_slug_site_override']['status']
		);
	}

	/**
	 * The WP-CLI channel writes the network option from a sub-site, reads it
	 * back and hands the refusal of the pipeline through.
	 */
	public function test_cli_channel_writes_the_network_option_and_reports_refusals() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-cli.php';
		$key     = 'reportedip_hive_failed_login_threshold';
		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		$written = ReportedIP_Hive_Settings_CLI::write( $key, '17' );
		$again   = ReportedIP_Hive_Settings_CLI::write( $key, '17' );
		$row     = ReportedIP_Hive_Settings_CLI::rows( $key );
		restore_current_blog();

		$this->assertSame( 'applied', $written['status'] );
		$this->assertSame( 'unchanged', $again['status'] );
		$this->assertSame( 17, (int) get_site_option( $key ) );
		$this->assertSame( array( array( 'key' => $key, 'kind' => 'int', 'value' => '17' ) ), $row );

		$this->assertSame( 'unknown_key', ReportedIP_Hive_Settings_CLI::write( 'reportedip_hive_no_such_key', '1' )['status'] );
		$this->assertSame( array(), ReportedIP_Hive_Settings_CLI::rows( 'reportedip_hive_no_such_key' ) );

		$invalid = ReportedIP_Hive_Settings_CLI::write( 'reportedip_hive_rest_access_mode', 'bogus' );
		$this->assertSame( 'invalid', $invalid['status'] );
		$this->assertNotSame( '', $invalid['message'], 'the reason travels to the shell' );

		$this->assertSame(
			array_keys( ReportedIP_Hive_Settings_Registry::remote_spec() ),
			array_column( ReportedIP_Hive_Settings_CLI::rows(), 'key' ),
			'list shows every key the pipeline accepts'
		);
	}
}
