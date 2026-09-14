<?php
/**
 * Readiness advisory detectors that feed the dashboard's next steps.
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
	require_once dirname( __DIR__, 2 ) . '/includes/class-readiness.php';
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;
	use ReportedIP_Hive_Readiness;

	/**
	 * @covers ReportedIP_Hive_Readiness
	 */
	final class ReadinessAdvisoryTest extends TestCase {

		public function test_hide_login_off_raises_only_while_the_slug_is_off(): void {
			$issue = ReportedIP_Hive_Readiness::hide_login_off( false );
			$this->assertSame( 'hide_login_off', $issue['key'] );
			$this->assertSame( ReportedIP_Hive_Readiness::SEV_ADVISORY, $issue['severity'] );
			$this->assertNull( ReportedIP_Hive_Readiness::hide_login_off( true ) );
		}

		public function test_frontend_2fa_available_needs_woocommerce_and_the_plan_and_an_off_switch(): void {
			$this->assertNotNull( ReportedIP_Hive_Readiness::frontend_2fa_available( true, true, false ) );
			$this->assertNull( ReportedIP_Hive_Readiness::frontend_2fa_available( false, true, false ), 'no WooCommerce' );
			$this->assertNull( ReportedIP_Hive_Readiness::frontend_2fa_available( true, false, false ), 'not on the plan: that is the upsell card' );
			$this->assertNull( ReportedIP_Hive_Readiness::frontend_2fa_available( true, true, true ), 'already on' );
		}

		public function test_badge_off_and_community_pending(): void {
			$this->assertSame( 'badge_off', ReportedIP_Hive_Readiness::badge_off( false )['key'] );
			$this->assertNull( ReportedIP_Hive_Readiness::badge_off( true ) );
			$this->assertSame( 'community_pending', ReportedIP_Hive_Readiness::community_pending( 'local' )['key'] );
			$this->assertNull( ReportedIP_Hive_Readiness::community_pending( 'community' ) );
		}

		public function test_dropin_not_running_only_where_the_server_could_run_it(): void {
			$this->assertNotNull( ReportedIP_Hive_Readiness::dropin_not_running( true, false ) );
			$this->assertNull( ReportedIP_Hive_Readiness::dropin_not_running( true, true ), 'running' );
			$this->assertNull( ReportedIP_Hive_Readiness::dropin_not_running( false, false ), 'no supported server' );
		}

		public function test_own_2fa_missing_is_a_user_issue(): void {
			$issue = ReportedIP_Hive_Readiness::own_2fa_missing( true, array() );
			$this->assertSame( 'own_2fa_missing', $issue['key'] );
			$this->assertNull( ReportedIP_Hive_Readiness::own_2fa_missing( true, array( 'totp' ) ) );
			$this->assertNull( ReportedIP_Hive_Readiness::own_2fa_missing( false, array() ), '2FA globally off' );
		}
	}
}
