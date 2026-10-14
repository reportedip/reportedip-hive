<?php
/**
 * Unit tests for the Hide-Login bypass that protects the frontend 2FA
 * challenge / setup slugs.
 *
 * Hide-Login's `is_environment_bypassed()` is the choke-point that decides
 * whether the request gets rewritten or rendered as a fake 404 / block-page.
 * The frontend 2FA module hands both of its public slugs (challenge and
 * setup) to `reportedip_hive_hide_login_bypass_paths`, otherwise enabling
 * Hide-Login on a customer-facing site silently breaks the second factor for
 * every WooCommerce user.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.7.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class HideLoginFrontend2faBypassTest extends TestCase {

	protected function set_up() {
		parent::set_up();
		$GLOBALS['wp_options'] = array();
		require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
		require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-frontend.php';
		\ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
	}

	public function test_both_default_slugs_are_bypassed(): void {
		$this->assertSame(
			array( '/kept', '/reportedip-hive-2fa', '/reportedip-hive-2fa-setup' ),
			\ReportedIP_Hive_Two_Factor_Frontend::bypass_paths( array( '/kept' ) )
		);
	}

	public function test_configured_slugs_are_bypassed(): void {
		$GLOBALS['wp_options']['reportedip_hive_2fa_frontend_slug']       = 'shop-verify';
		$GLOBALS['wp_options']['reportedip_hive_2fa_frontend_setup_slug'] = 'shop-verify-setup';
		\ReportedIP_Hive_Two_Factor_Frontend::flush_memo();

		$this->assertSame(
			array( '/shop-verify', '/shop-verify-setup' ),
			\ReportedIP_Hive_Two_Factor_Frontend::bypass_paths( array() ),
			'Admins who customised the slugs must not lock their customers out.'
		);
	}

	public function test_bypass_does_not_depend_on_the_plan(): void {
		$this->assertFalse( \ReportedIP_Hive_Two_Factor_Frontend::is_available() );
		$this->assertCount( 2, \ReportedIP_Hive_Two_Factor_Frontend::bypass_paths( array() ), 'Like 2.1.x the slugs stay reachable while the module is parked, so a stale link is not answered by the Hide Login block page.' );
	}

	public function test_listener_is_wired_in_init(): void {
		$this->assertStringContainsString(
			"add_filter( 'reportedip_hive_hide_login_bypass_paths', array( __CLASS__, 'bypass_paths' ) );",
			(string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-frontend.php' )
		);
	}
}
