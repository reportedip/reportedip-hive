<?php
/**
 * A plugin update rebakes the pre-WordPress guard on the next admin request.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Multisite
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.1
 */

/**
 * The guard carries the rules of the version that wrote it. After an update
 * it ran with the old rules until the hourly self-heal came around; the
 * upgrade seed now clears the self-heal lock, so the next admin request on
 * the main site rewrites it.
 */
class ReportedIP_Hive_Upgrade_Rebake_Test extends WP_UnitTestCase {

	public function test_a_version_change_releases_the_self_heal_lock() {
		set_site_transient( ReportedIP_Hive_WAF_Dropin_Manager::HEAL_LOCK_TRANSIENT, 1, HOUR_IN_SECONDS );
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_seeded_version', '3.0.0-old' );

		ReportedIP_Hive::maybe_seed_on_upgrade();

		$this->assertFalse( get_site_transient( ReportedIP_Hive_WAF_Dropin_Manager::HEAL_LOCK_TRANSIENT ) );
	}

	public function test_the_same_version_keeps_the_lock() {
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_seeded_version', REPORTEDIP_HIVE_VERSION );
		set_site_transient( ReportedIP_Hive_WAF_Dropin_Manager::HEAL_LOCK_TRANSIENT, 1, HOUR_IN_SECONDS );

		ReportedIP_Hive::maybe_seed_on_upgrade();

		$this->assertSame( 1, (int) get_site_transient( ReportedIP_Hive_WAF_Dropin_Manager::HEAL_LOCK_TRANSIENT ) );
	}
}
