<?php
/**
 * Unit tests for the tier-downgrade soft-disable pathway in
 * {@see ReportedIP_Hive_Two_Factor_Frontend::on_tier_changed()}.
 *
 * The soft-disable contract is the safety net for
 * Free / Contributor → … sequences: customer 2FA secrets are NEVER
 * deleted on a downgrade, the module merely parks itself so new
 * onboardings cannot start. A subsequent upgrade automatically
 * clears the marker.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.7.0
 */

namespace {

	if ( ! function_exists( 'home_url' ) ) {
		function home_url( $path = '' ) { return 'https://example.test' . $path; }
	}
	if ( ! function_exists( 'admin_url' ) ) {
		function admin_url( $path = '' ) { return 'https://example.test/wp-admin/' . ltrim( (string) $path, '/' ); }
	}
	if ( ! function_exists( 'wp_login_url' ) ) {
		function wp_login_url( $redirect = '', $force_reauth = false ) { return 'https://example.test/wp-login.php'; }
	}
	if ( ! function_exists( 'add_action' ) ) {
		function add_action( ...$args ) {}
	}
	if ( ! function_exists( 'add_filter' ) ) {
		function add_filter( ...$args ) {}
	}
	if ( ! function_exists( 'add_rewrite_rule' ) ) {
		function add_rewrite_rule( ...$args ) {}
	}
	if ( ! function_exists( 'add_rewrite_tag' ) ) {
		function add_rewrite_tag( ...$args ) {}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorFrontendSoftDisableTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
			require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-frontend.php';
		}

		public function test_pro_to_free_writes_soft_disable_timestamp(): void {
			$this->assertSame( 0, (int) get_option( \ReportedIP_Hive_Two_Factor_Frontend::OPT_SOFT_DISABLED, 0 ) );

			\ReportedIP_Hive_Two_Factor_Frontend::on_tier_changed( 'professional', 'free' );

			$marker = (int) get_option( \ReportedIP_Hive_Two_Factor_Frontend::OPT_SOFT_DISABLED, 0 );
			$this->assertGreaterThan( 0, $marker, 'A downgrade from a paid tier must persist a soft-disable timestamp.' );
		}

		public function test_free_to_pro_clears_soft_disable_timestamp(): void {
			$GLOBALS['wp_options'][ \ReportedIP_Hive_Two_Factor_Frontend::OPT_SOFT_DISABLED ] = 999;

			\ReportedIP_Hive_Two_Factor_Frontend::on_tier_changed( 'free', 'professional' );

			$this->assertSame(
				0,
				(int) get_option( \ReportedIP_Hive_Two_Factor_Frontend::OPT_SOFT_DISABLED, 0 ),
				'An upgrade after a downgrade must clear the marker so the module reactivates on the next request.'
			);
		}

		public function test_pro_to_business_does_not_touch_marker(): void {
			\ReportedIP_Hive_Two_Factor_Frontend::on_tier_changed( 'professional', 'business' );

			$this->assertSame(
				0,
				(int) get_option( \ReportedIP_Hive_Two_Factor_Frontend::OPT_SOFT_DISABLED, 0 ),
				'Cross-paid-tier moves must not flip the soft-disable bookkeeping.'
			);
		}

		public function test_free_to_contributor_does_not_create_marker(): void {
			\ReportedIP_Hive_Two_Factor_Frontend::on_tier_changed( 'free', 'contributor' );

			$this->assertSame(
				0,
				(int) get_option( \ReportedIP_Hive_Two_Factor_Frontend::OPT_SOFT_DISABLED, 0 ),
				'Free → Contributor never had access in the first place; nothing to soft-disable.'
			);
		}
	}
}
