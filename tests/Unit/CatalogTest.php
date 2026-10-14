<?php
/**
 * The pro catalog: every row carries the fields the UI renders.
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
 * Catalog assertions.
 */
class CatalogTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-settings-registry.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-catalog.php';
	}

	public function test_every_row_is_complete() {
		$sections = array_merge( array_keys( \ReportedIP_Hive_Settings_Registry::sections() ), array_keys( \ReportedIP_Hive_Catalog::sections() ) );
		foreach ( \ReportedIP_Hive_Catalog::features() as $key => $row ) {
			foreach ( array( 'label', 'description', 'tier', 'section', 'docs_url' ) as $field ) {
				$this->assertNotEmpty( $row[ $field ], "{$key}.{$field}" );
			}
			$this->assertContains( $row['tier'], array( 'professional', 'business' ), $key );
			$this->assertContains( $row['section'], $sections, $key );
			$this->assertStringStartsWith( \ReportedIP_Hive_Catalog::PRODUCT_URL . '#hive-', $row['docs_url'], $key );
		}
	}

	public function test_rows_by_section_groups_keys() {
		$by_section = \ReportedIP_Hive_Catalog::by_section();
		$this->assertArrayHasKey( 'account_security', $by_section );
		$this->assertContains( 'frontend_2fa', array_keys( $by_section['account_security'] ) );
	}

	public function test_add_on_sections_sit_where_the_features_lived_in_2_1_74() {
		$by_section = \ReportedIP_Hive_Catalog::by_section();
		$this->assertSame( array( 'hardening_mode' ), array_keys( $by_section['hardening_mode'] ) );
		$this->assertSame( array( '2fa_policies' ), array_keys( $by_section['twofa_policies'] ) );
	}

	public function test_add_on_sections_are_not_free_registry_sections() {
		$free = array_keys( \ReportedIP_Hive_Settings_Registry::sections() );
		foreach ( \ReportedIP_Hive_Catalog::sections() as $id => $section ) {
			$this->assertNotContains( $id, $free, $id );
			$this->assertNotEmpty( $section['label'], $id );
			$this->assertSame( 'advanced', $section['tab'], $id );
		}
	}
}
