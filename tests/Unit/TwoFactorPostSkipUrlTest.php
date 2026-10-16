<?php
/**
 * Target after a skipped 2FA enrolment: the dashboard, My Account for a
 * customer on a WooCommerce site (as in 2.1.74, no plan needed), and the
 * filter for an add-on surface.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      3.0.0
 */

namespace {

	if ( ! function_exists( 'wc_get_page_permalink' ) ) {
		/**
		 * WooCommerce double: the My Account page from a global.
		 *
		 * @param string $page Page key.
		 * @return string
		 */
		function wc_get_page_permalink( $page ) {
			return 'myaccount' === $page ? (string) ( $GLOBALS['rip_test_myaccount'] ?? '' ) : '';
		}
	}
	if ( ! function_exists( 'is_network_admin' ) ) {
		/**
		 * @return bool
		 */
		function is_network_admin() {
			return false;
		}
	}
	if ( ! function_exists( 'network_admin_url' ) ) {
		/**
		 * @param string $path Path.
		 * @return string
		 */
		function network_admin_url( $path = '' ) {
			return 'https://example.org/wp-admin/network/' . ltrim( (string) $path, '/' );
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorPostSkipUrlTest extends TestCase {

		private const CUSTOMER = 21;

		protected function set_up() {
			parent::set_up();
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'tests/stubs/two-factor-runtime-stubs.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-onboarding.php';
			$GLOBALS['wp_filters']         = array();
			$GLOBALS['wp_user_caps']       = array(
				self::CUSTOMER . '|manage_options' => false,
				self::CUSTOMER . '|edit_posts'     => false,
			);
			$GLOBALS['rip_test_myaccount'] = 'https://example.org/my-account/';
		}

		/**
		 * @param int $user_id User who skipped.
		 * @return string
		 */
		private function target( int $user_id ): string {
			$method = new \ReflectionMethod( \ReportedIP_Hive_Two_Factor_Onboarding::class, 'default_post_skip_url' );
			return (string) $method->invoke( null, $user_id );
		}

		public function test_a_customer_on_a_woocommerce_site_goes_to_my_account() {
			$this->assertSame( 'https://example.org/my-account/', $this->target( self::CUSTOMER ) );
		}

		/**
		 * "Set up later" from the Hive setup leads an administrator back to
		 * the Hive dashboard, not to the WordPress start page.
		 */
		public function test_an_administrator_goes_to_the_hive_dashboard() {
			$this->assertSame( admin_url( 'admin.php?page=reportedip-hive' ), $this->target( 5 ) );
		}

		public function test_staff_and_a_missing_account_page_keep_the_dashboard() {
			$GLOBALS['wp_user_caps']['6|manage_options'] = false;
			$this->assertSame( admin_url(), $this->target( 6 ), 'A user who can edit posts reaches wp-admin.' );
			$this->assertSame( admin_url(), $this->target( 0 ) );

			$GLOBALS['rip_test_myaccount'] = '';
			$this->assertSame( admin_url(), $this->target( self::CUSTOMER ), 'Without a My Account page the dashboard stays.' );
		}

		public function test_the_filter_sees_the_default_and_the_user() {
			$seen = array();
			add_filter(
				'reportedip_hive_2fa_post_skip_url',
				static function ( $url, $user_id ) use ( &$seen ) {
					$seen = array( $url, $user_id );
					return 'https://example.org/shop/';
				},
				10,
				2
			);
			$this->assertSame( 'https://example.org/shop/', $this->target( self::CUSTOMER ) );
			$this->assertSame( array( 'https://example.org/my-account/', self::CUSTOMER ), $seen );
		}
	}
}
