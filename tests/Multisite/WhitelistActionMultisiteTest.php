<?php
/**
 * Multisite tests for the whitelist-changed announcement.
 *
 * The pre-WordPress WAF drop-in bakes the IP whitelist into its guard file, so
 * every whitelist mutation must announce itself via
 * `reportedip_hive_whitelist_changed` — otherwise a freshly whitelisted client
 * would stay blocked by the stale guard until the hourly self-heal. These
 * tests run against a real WordPress + database.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.2
 */

/**
 * @group ms-required
 */
class ReportedIP_Hive_Whitelist_Action_Multisite_Test extends WP_UnitTestCase {

	/**
	 * Skip the entire class on single-site test runs and make sure the plugin
	 * tables exist (idempotent).
	 */
	public function set_up() {
		parent::set_up();
		if ( ! is_multisite() ) {
			$this->markTestSkipped( 'Multisite required.' );
		}
		ReportedIP_Hive_Schema::ensure_tables();
	}

	/**
	 * Adding and removing a whitelist entry each fire the changed action once.
	 */
	public function test_whitelist_add_and_remove_fire_changed_action() {
		$db     = ReportedIP_Hive_Database::get_instance();
		$before = did_action( 'reportedip_hive_whitelist_changed' );

		$this->assertNotFalse( $db->add_to_whitelist( '203.0.113.77', 'finalisation test' ) );
		$this->assertSame( $before + 1, did_action( 'reportedip_hive_whitelist_changed' ), 'Adding a whitelist entry must announce the change.' );

		$this->assertTrue( $db->remove_from_whitelist( '203.0.113.77' ) );
		$this->assertSame( $before + 2, did_action( 'reportedip_hive_whitelist_changed' ), 'Removing a whitelist entry must announce the change.' );
	}

	/**
	 * The drop-in manager listens for whitelist changes and ruleset applies so
	 * the guard is rebaked without waiting for the self-heal.
	 */
	public function test_dropin_manager_listens_for_freshness_triggers() {
		$manager = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();

		$this->assertNotFalse(
			has_action( 'reportedip_hive_whitelist_changed', array( $manager, 'queue_resync' ) ),
			'Drop-in manager must rebake on whitelist changes.'
		);
		$this->assertNotFalse(
			has_action( 'reportedip_hive_ruleset_applied', array( $manager, 'on_ruleset_applied' ) ),
			'Drop-in manager must rebake when the waf ruleset is re-applied.'
		);
	}
}
