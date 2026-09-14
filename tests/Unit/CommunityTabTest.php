<?php
/**
 * The Community page resolves its three tabs from the request and maps the
 * legacy backlink-tools sub-tab onto the badges tab.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.57
 */

declare(strict_types=1);

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		define( 'ABSPATH', __DIR__ . '/' );
	}
	require_once dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Admin_Settings;

	/**
	 * @covers ReportedIP_Hive_Admin_Settings::community_tab
	 * @covers ReportedIP_Hive_Admin_Settings::community_tabs
	 */
	final class CommunityTabTest extends TestCase {

		/**
		 * @dataProvider requests
		 */
		public function test_tab_resolves_from_tab_then_legacy_subtab( $tab, $subtab, string $expected ): void {
			$this->assertSame( $expected, ReportedIP_Hive_Admin_Settings::community_tab( $tab, $subtab ) );
		}

		/**
		 * @return array<string,array{0:mixed,1:mixed,2:string}>
		 */
		public static function requests(): array {
			return array(
				'no parameters open the settings' => array( '', '', 'settings' ),
				'settings'                        => array( 'settings', '', 'settings' ),
				'community'                       => array( 'community', '', 'community' ),
				'badges'                          => array( 'badges', '', 'badges' ),
				'legacy promote lands on badges'  => array( '', 'promote', 'badges' ),
				'legacy main opens the settings'  => array( '', 'main', 'settings' ),
				'tab wins over legacy subtab'     => array( 'community', 'promote', 'community' ),
				'unknown tab falls back'          => array( 'nonsense', '', 'settings' ),
				'array input is ignored'          => array( array( 'badges' ), array( 'promote' ), 'settings' ),
			);
		}

		public function test_settings_is_the_first_of_three_tabs(): void {
			$this->assertSame( array( 'settings', 'community', 'badges' ), array_keys( ReportedIP_Hive_Admin_Settings::community_tabs() ) );
		}
	}
}
