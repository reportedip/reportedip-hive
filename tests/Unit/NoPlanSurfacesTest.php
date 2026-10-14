<?php
/**
 * The free plugin names no price, books no plan and links no plan badge
 * (wordpress.org rules 5 and 11). It offers slots; the add-on fills them.
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
 * Source assertions over the admin pages and the bootstrap.
 */
class NoPlanSurfacesTest extends TestCase {

	/**
	 * Source of one free file.
	 *
	 * @param string $relative Path below the plugin directory.
	 * @return string
	 */
	private function source( string $relative ): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
	}

	public function test_no_admin_page_names_a_price_or_books_a_plan(): void {
		foreach ( array( 'admin/class-admin-settings.php', 'admin/class-dashboard-next-steps.php', 'admin/class-quickstart.php', 'reportedip-hive.php' ) as $file ) {
			$source = $this->source( $file );
			foreach ( array( '€', 'EUR each', 'get_tier_definitions', 'Upgrade now', 'Upgrade API tier', 'Upgrade tier for higher caps', "'utm_campaign' => 'upgrade'", 'REPORTEDIP_HIVE_UPGRADE_URL', 'render_tier_upgrade_banner', 'Promo_Manager', 'Whats_New' ) as $needle ) {
				$this->assertStringNotContainsString( $needle, $source, "{$file}: {$needle}" );
			}
		}
	}

	public function test_the_header_badge_links_only_through_the_filter(): void {
		$source = $this->source( 'admin/class-admin-settings.php' );
		$this->assertStringContainsString( "\$tier_opts = apply_filters( 'reportedip_hive_header_badge', array(), \$tier_key );", $source );
		$this->assertStringNotContainsString( "'href'  => self::pricing_url()", $source );
	}

	public function test_the_community_tab_offers_its_slot_where_the_plan_overview_was(): void {
		$source = $this->source( 'admin/class-admin-settings.php' );
		$slot   = strpos( $source, "'reportedip_hive_community_tab_after_status'," );
		$this->assertNotFalse( $slot );
		$this->assertGreaterThan( strpos( $source, 'Learn more about the honeypot program' ), $slot );
		$this->assertLessThan( strpos( $source, '$this->render_backlink_booster();' ), $slot );
	}

	public function test_the_api_notices_stay_off_the_wordpress_dashboard(): void {
		$source = $this->source( 'reportedip-hive.php' );
		$this->assertStringContainsString( "\$show_on_screens = array( 'toplevel_page_reportedip-hive', 'reportedip-hive_page_reportedip-hive-logs' );", $source );
	}
}
