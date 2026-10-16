<?php
/**
 * Unit tests for the recommendation delta the free plugin applies on a plan change.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.1
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * @covers \ReportedIP_Hive_Defaults::on_tier_changed
 * @covers \ReportedIP_Hive_Defaults::select_upgrade_values
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class TierChangeDeltaTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options']    = array();
		$GLOBALS['wp_transients'] = array();
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-defaults.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-registry.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-apply.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-addon-notice.php';
	}

	public function test_a_rank_increase_without_the_add_on_applies_the_delta() {
		\ReportedIP_Hive_Defaults::on_tier_changed( 'free', 'professional' );
		$this->assertSame( 90, (int) $GLOBALS['wp_options']['reportedip_hive_data_retention_days'] );

		\ReportedIP_Hive_Defaults::on_tier_changed( 'professional', 'business' );
		$this->assertSame( 365, (int) $GLOBALS['wp_options']['reportedip_hive_data_retention_days'] );
	}

	public function test_an_admin_value_survives_the_plan_change() {
		$GLOBALS['wp_options']['reportedip_hive_data_retention_days'] = 14;
		\ReportedIP_Hive_Defaults::on_tier_changed( 'free', 'professional' );
		$this->assertSame( 14, (int) $GLOBALS['wp_options']['reportedip_hive_data_retention_days'] );
	}

	public function test_a_downgrade_writes_nothing() {
		\ReportedIP_Hive_Defaults::on_tier_changed( 'business', 'free' );
		$this->assertArrayNotHasKey( 'reportedip_hive_data_retention_days', $GLOBALS['wp_options'] );
	}

	public function test_a_running_add_on_owns_the_delta() {
		add_filter( 'reportedip_hive_feature_matrix', '__return_empty_array' );
		\ReportedIP_Hive_Defaults::on_tier_changed( 'free', 'professional' );
		$this->assertArrayNotHasKey( 'reportedip_hive_data_retention_days', $GLOBALS['wp_options'] );
	}

	public function test_the_free_plugin_listens_on_the_plan_change() {
		$source = (string) file_get_contents( REPORTEDIP_HIVE_PLUGIN_FILE );
		$this->assertTrue( false !== strpos( $source, "add_action( 'reportedip_hive_tier_changed', array( 'ReportedIP_Hive_Defaults', 'on_tier_changed' ), 20, 2 );" ), 'the listener is wired in the main file' );
	}
}
