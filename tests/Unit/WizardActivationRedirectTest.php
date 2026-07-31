<?php
/**
 * Unit tests for the one-shot activation redirect into the setup wizard.
 *
 * The activation marker is consumed exactly once, so it must never be spent on
 * a request no browser follows. `admin-ajax.php` fires `admin_init` just like a
 * real admin page, and a WooCommerce store keeps that endpoint busy around the
 * clock (Action Scheduler, Heartbeat) — which is why the wizard silently failed
 * to open on those installs.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.30
 */

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	require_once dirname( __DIR__, 2 ) . '/admin/class-setup-wizard.php';

	/**
	 * @covers \ReportedIP_Hive_Setup_Wizard
	 */
	class WizardActivationRedirectTest extends TestCase {

		protected function setUp(): void {
			parent::setUp();
			$GLOBALS['rip_test_doing_ajax'] = false;
			$GLOBALS['rip_test_doing_cron'] = false;
			$_SERVER['REQUEST_METHOD']      = 'GET';
		}

		protected function tearDown(): void {
			unset( $GLOBALS['rip_test_doing_ajax'], $GLOBALS['rip_test_doing_cron'] );
			$_SERVER['REQUEST_METHOD'] = 'GET';
			parent::tearDown();
		}

		private function can_redirect(): bool {
			$wizard = ( new \ReflectionClass( \ReportedIP_Hive_Setup_Wizard::class ) )->newInstanceWithoutConstructor();
			$method = new \ReflectionMethod( \ReportedIP_Hive_Setup_Wizard::class, 'request_can_redirect' );
			return (bool) $method->invoke( $wizard );
		}

		public function test_plain_admin_page_view_may_redirect(): void {
			$this->assertTrue( $this->can_redirect(), 'A normal admin GET is exactly the request the wizard redirect is meant for.' );
		}

		public function test_ajax_request_may_not_redirect(): void {
			$GLOBALS['rip_test_doing_ajax'] = true;
			$this->assertFalse( $this->can_redirect(), 'An admin-ajax background request must not consume the one-shot marker.' );
		}

		public function test_cron_request_may_not_redirect(): void {
			$GLOBALS['rip_test_doing_cron'] = true;
			$this->assertFalse( $this->can_redirect() );
		}

		public function test_post_request_may_not_redirect(): void {
			$_SERVER['REQUEST_METHOD'] = 'POST';
			$this->assertFalse( $this->can_redirect(), 'A form submission is not a navigation.' );
		}

		/**
		 * Order matters more than the check itself: the marker is deleted
		 * unconditionally, so a context check placed after the delete would still
		 * burn the redirect on a background request.
		 */
		public function test_context_check_runs_before_the_marker_is_consumed(): void {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/admin/class-setup-wizard.php' );
			$start  = strpos( $source, 'public function maybe_redirect_to_wizard()' );
			$this->assertNotFalse( $start );
			$body = substr( $source, $start, 900 );

			$guard    = strpos( $body, 'request_can_redirect' );
			$consumed = strpos( $body, 'delete_site_transient' );

			$this->assertNotFalse( $guard, 'maybe_redirect_to_wizard() must check the request context.' );
			$this->assertNotFalse( $consumed );
			$this->assertLessThan( $consumed, $guard, 'The context check must run before the activation marker is deleted.' );
		}
	}
}
