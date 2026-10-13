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
		if ( ! function_exists( '__' ) ) {
			/**
			 * Translation stub, the unit stubs do not define it on every path.
			 *
			 * @param string $text   Text.
			 * @param string $domain Domain.
			 * @return string
			 */
			function __( $text, $domain = 'default' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
				return $text;
			}
		}
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-catalog.php';
	}

	public function test_every_row_is_complete() {
		foreach ( \ReportedIP_Hive_Catalog::features() as $key => $row ) {
			foreach ( array( 'label', 'description', 'tier', 'section', 'docs_url' ) as $field ) {
				$this->assertNotEmpty( $row[ $field ], "{$key}.{$field}" );
			}
			$this->assertContains( $row['tier'], array( 'professional', 'business' ), $key );
		}
	}

	public function test_rows_by_section_groups_keys() {
		$by_section = \ReportedIP_Hive_Catalog::by_section();
		$this->assertArrayHasKey( 'account_security', $by_section );
		$this->assertContains( 'frontend_2fa', array_keys( $by_section['account_security'] ) );
	}

	public function test_fourteen_features() {
		$this->assertCount( 14, \ReportedIP_Hive_Catalog::features() );
	}
}
