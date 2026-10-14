<?php
/**
 * The dashboard keeps the "Licensed domains" card where 2.1.74 showed it
 * (Community site, Professional plan and up) without the add-on, and leaves
 * the place to the add-on's relay section while that is hooked.
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

require_once dirname( __DIR__, 2 ) . '/includes/class-defaults.php';

/**
 * Source and rank assertions.
 */
class DashboardDomainsCardTest extends TestCase {

	/**
	 * Body of `dashboard_page()`.
	 *
	 * @return string
	 */
	private function dashboard_source(): string {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php' );
		$start  = (int) strpos( $source, 'public function dashboard_page()' );
		return substr( $source, $start, (int) strpos( $source, "\n\t}\n", $start ) - $start );
	}

	public function test_the_dashboard_shows_the_domains_section_without_a_listener(): void {
		$body  = $this->dashboard_source();
		$guard = strpos( $body, "! has_action( 'reportedip_hive_dashboard_after_next_steps' ) && \$mode_manager->is_community_mode() && ReportedIP_Hive_Defaults::recommendation_rank( \$mode_manager->get_current_tier() ) > 0" );
		$this->assertNotFalse( $guard );
		$this->assertNotFalse( strpos( $body, '$this->render_domains_section( $mode_manager );', (int) $guard ) );
		$this->assertLessThan( strpos( $body, "do_action( 'reportedip_hive_dashboard_after_next_steps' );" ), $guard, 'Same place as the 2.1.74 relay section.' );
	}

	public function test_the_rank_opens_from_professional_up(): void {
		$this->assertSame( 0, \ReportedIP_Hive_Defaults::recommendation_rank( 'free' ) );
		$this->assertSame( 0, \ReportedIP_Hive_Defaults::recommendation_rank( 'contributor' ) );
		foreach ( array( 'professional', 'business', 'enterprise' ) as $tier ) {
			$this->assertGreaterThan( 0, \ReportedIP_Hive_Defaults::recommendation_rank( $tier ), $tier );
		}
	}
}
