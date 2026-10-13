<?php
/**
 * The extension points the add-on consumes, each proven with a filter.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * Filter-driven extension points.
 */
class ExtensionApiTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-defaults.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-mode-manager.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-registry.php';
		global $wp_filters;
		$wp_filters               = array();
		$GLOBALS['wp_options']    = array();
		$GLOBALS['wp_transients'] = array();
		\ReportedIP_Hive_Mode_Manager::get_instance()->flush_cached_tier();
	}

	protected function tear_down() {
		global $wp_filters;
		$wp_filters = array();
		\ReportedIP_Hive_Mode_Manager::get_instance()->flush_feature_matrix();
		\ReportedIP_Hive_Settings_Registry::flush_spec_cache();
		parent::tear_down();
	}

	public function test_feature_matrix_accepts_injected_rows() {
		add_filter(
			'reportedip_hive_feature_matrix',
			static function ( array $matrix ) {
				$matrix['demo_pro_feature'] = array(
					'local'         => true,
					'community'     => true,
					'requires_tier' => 'professional',
				);
				return $matrix;
			}
		);
		$manager = \ReportedIP_Hive_Mode_Manager::get_instance();
		$manager->flush_feature_matrix();
		$manager->set_mode( 'local' );

		$status = $manager->feature_status( 'demo_pro_feature' );

		$this->assertFalse( $status['available'] );
		$this->assertSame( 'tier', $status['reason'] );
		$this->assertSame( 'professional', $status['min_tier'] );
	}

	public function test_unknown_feature_stays_unknown_without_filter() {
		$manager = \ReportedIP_Hive_Mode_Manager::get_instance();
		$manager->flush_feature_matrix();

		$status = $manager->feature_status( 'demo_pro_feature' );

		$this->assertFalse( $status['available'] );
		$this->assertSame( 'unknown', $status['reason'] );
	}

	public function test_settings_spec_accepts_injected_entries() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-registry.php';
		add_filter(
			'reportedip_hive_settings_spec',
			static function ( array $spec ) {
				$spec['reportedip_hive_demo_switch'] = array(
					'section'     => 'detection',
					'kind'        => 'bool',
					'remote'      => true,
					'label'       => 'Demo',
					'description' => 'Demo switch.',
				);
				return $spec;
			}
		);
		\ReportedIP_Hive_Settings_Registry::flush_spec_cache();

		$spec = \ReportedIP_Hive_Settings_Registry::spec();

		$this->assertArrayHasKey( 'reportedip_hive_demo_switch', $spec );
		$this->assertArrayHasKey( 'reportedip_hive_trusted_ip_header', $spec );
	}

	public function test_settings_sections_accept_injected_sections() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-registry.php';
		add_filter(
			'reportedip_hive_settings_sections',
			static function ( array $sections ) {
				$sections['demo'] = array(
					'label'       => 'Demo',
					'description' => 'Demo section.',
				);
				return $sections;
			}
		);

		$this->assertArrayHasKey( 'demo', \ReportedIP_Hive_Settings_Registry::sections() );
	}
}
