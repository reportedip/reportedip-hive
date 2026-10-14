<?php
/**
 * The add-on hint: due on a paid plan without the add-on, once per plan and
 * user, never with the add-on, never on a free plan.
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

if ( ! defined( 'REPORTEDIP_HIVE_SITE_URL' ) ) {
	define( 'REPORTEDIP_HIVE_SITE_URL', 'https://reportedip.com' );
}
require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
require_once dirname( __DIR__, 2 ) . '/includes/class-addon-notice.php';

/**
 * @covers \ReportedIP_Hive_Addon_Notice
 */
class AddonNoticeTest extends TestCase {

	public function test_the_hint_is_due_on_a_paid_plan_without_the_add_on(): void {
		foreach ( array( 'professional', 'business', 'enterprise' ) as $tier ) {
			$body = \ReportedIP_Hive_Addon_Notice::message_for( $tier, false, false );
			$this->assertStringContainsString( 'ReportedIP Hive Pro add-on', $body, $tier );
			$this->assertStringContainsString( 'https://reportedip.com/dashboard/', $body, $tier );
			$this->assertStringNotContainsString( 'utm_', $body, $tier );
		}
		$this->assertStringContainsString( 'Business', \ReportedIP_Hive_Addon_Notice::message_for( 'business', false, false ) );
	}

	public function test_the_hint_stays_away_with_the_add_on_a_dismissal_or_a_free_plan(): void {
		$this->assertSame( '', \ReportedIP_Hive_Addon_Notice::message_for( 'professional', true, false ), 'add-on runs' );
		$this->assertSame( '', \ReportedIP_Hive_Addon_Notice::message_for( 'professional', false, true ), 'dismissed' );
		foreach ( array( 'free', 'contributor', 'honeypot', '' ) as $tier ) {
			$this->assertSame( '', \ReportedIP_Hive_Addon_Notice::message_for( $tier, false, false ), $tier );
		}
	}

	public function test_the_add_on_is_detected_through_its_matrix_rows(): void {
		$filters_before = $GLOBALS['wp_filters'] ?? array();
		try {
			unset( $GLOBALS['wp_filters']['reportedip_hive_feature_matrix'] );
			$this->assertFalse( \ReportedIP_Hive_Addon_Notice::addon_running() );
			add_filter( 'reportedip_hive_feature_matrix', 'array_values' );
			$this->assertTrue( \ReportedIP_Hive_Addon_Notice::addon_running() );
		} finally {
			$GLOBALS['wp_filters'] = $filters_before;
		}
	}

	public function test_each_plan_has_its_own_dismissal(): void {
		$this->assertSame( 'reportedip_hive_addon_available_professional', \ReportedIP_Hive_Addon_Notice::notice_id( 'professional' ) );
		$this->assertNotSame( \ReportedIP_Hive_Addon_Notice::notice_id( 'professional' ), \ReportedIP_Hive_Addon_Notice::notice_id( 'business' ) );
	}

	public function test_the_notice_shows_on_the_plugin_pages_only(): void {
		$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-admin-settings.php' );
		$this->assertSame( 1, substr_count( $source, 'ReportedIP_Hive_Addon_Notice::render();' ) );
		$inline = strpos( $source, 'public static function render_inline_notices()' );
		$this->assertGreaterThan( $inline, strpos( $source, 'ReportedIP_Hive_Addon_Notice::render();' ) );
	}
}
