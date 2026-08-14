<?php
/**
 * Multisite tests for {@see ReportedIP_Hive_Whats_New} state routing.
 *
 * The What's-new state markers are network-class options, so they must land
 * in sitemeta and be visible from every blog in the network.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.41
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Whats_New_Multisite_Test extends WP_UnitTestCase {

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
	 * The seen-version marker is stored network-wide in sitemeta.
	 */
	public function test_seen_version_lands_in_sitemeta() {
		ReportedIP_Hive_Option_Routing::set( ReportedIP_Hive_Whats_New::OPT_SEEN_VERSION, '9.9.9' );

		$this->assertSame( '9.9.9', get_site_option( ReportedIP_Hive_Whats_New::OPT_SEEN_VERSION ) );
	}

	/**
	 * The payload cache is stored network-wide in sitemeta.
	 */
	public function test_payload_lands_in_sitemeta() {
		$payload = array(
			'version'    => '9.9.9',
			'highlights' => array( 'Network highlight' ),
			'notes_url'  => 'https://reportedip.com/news/release/',
		);

		ReportedIP_Hive_Option_Routing::set( ReportedIP_Hive_Whats_New::OPT_PAYLOAD, $payload );

		$this->assertSame( $payload, get_site_option( ReportedIP_Hive_Whats_New::OPT_PAYLOAD ) );
	}

	/**
	 * The state survives switch_to_blog() so every network screen sees it.
	 */
	public function test_state_survives_switch_to_blog() {
		ReportedIP_Hive_Option_Routing::set( ReportedIP_Hive_Whats_New::OPT_SEEN_VERSION, '8.8.8' );

		$site_id = self::factory()->blog->create();
		switch_to_blog( $site_id );
		$this->assertSame(
			'8.8.8',
			ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_Whats_New::OPT_SEEN_VERSION )
		);
		restore_current_blog();
	}
}
