<?php
/**
 * Unit tests for the rewrite / routing surface of
 * {@see ReportedIP_Hive_Two_Factor_Frontend}.
 *
 * Validates the slug sanitiser, the reserved-slug list, and the
 * tier-gate memo. The full hook wiring is exercised in the E2E
 * suite; here we focus on the deterministic helpers.
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
		function home_url( $path = '' ) {
			return 'https://example.org' . $path;
		}
	}

	if ( ! function_exists( 'admin_url' ) ) {
		function admin_url( $path = '' ) {
			return 'https://example.org/wp-admin/' . ltrim( (string) $path, '/' );
		}
	}

	if ( ! function_exists( 'wp_login_url' ) ) {
		function wp_login_url( $redirect = '', $force_reauth = false ) {
			return 'https://example.org/wp-login.php';
		}
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
	if ( ! function_exists( 'wp_safe_redirect' ) ) {
		function wp_safe_redirect( $url, $status = 302 ) { return true; }
	}
	if ( ! function_exists( 'is_user_logged_in' ) ) {
		function is_user_logged_in() { return false; }
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorFrontendRoutingTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options']    = array();
			$GLOBALS['wp_transients'] = array();
			require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-frontend.php';
			\ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
		}

		public function test_sanitize_slug_strips_invalid_characters(): void {
			$result = \ReportedIP_Hive_Two_Factor_Frontend::sanitize_slug(
				'My-Slug 2026!', 'fallback'
			);
			$this->assertSame( 'my-slug2026', $result );
		}

		public function test_sanitize_slug_preserves_dashes_and_lowercase(): void {
			$result = \ReportedIP_Hive_Two_Factor_Frontend::sanitize_slug( 'My-Slug-2026', 'fallback' );
			$this->assertSame( 'my-slug-2026', $result );
		}

		public function test_sanitize_slug_returns_fallback_when_empty(): void {
			$result = \ReportedIP_Hive_Two_Factor_Frontend::sanitize_slug( '', 'reportedip-hive-2fa' );
			$this->assertSame( 'reportedip-hive-2fa', $result );
		}

		public function test_sanitize_slug_rejects_reserved_slugs(): void {
			foreach ( array( 'wp-admin', 'wp-login', 'my-account', 'checkout' ) as $reserved ) {
				$result = \ReportedIP_Hive_Two_Factor_Frontend::sanitize_slug( $reserved, 'safe' );
				$this->assertSame( 'safe', $result, "Reserved slug '{$reserved}' must be rejected — collision with WC or core paths." );
			}
		}

		public function test_sanitize_slug_rejects_too_short_or_too_long(): void {
			$this->assertSame( 'fb', \ReportedIP_Hive_Two_Factor_Frontend::sanitize_slug( 'ab', 'fb' ) );
			$too_long = str_repeat( 'a', 60 );
			$this->assertSame( 'fb', \ReportedIP_Hive_Two_Factor_Frontend::sanitize_slug( $too_long, 'fb' ) );
		}

		public function test_is_available_false_when_master_toggle_off(): void {
			\ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
			$this->assertFalse( \ReportedIP_Hive_Two_Factor_Frontend::is_available() );
		}

		public function test_is_available_false_when_soft_disabled(): void {
			$GLOBALS['wp_options'][ \ReportedIP_Hive_Two_Factor_Frontend::OPT_ENABLED ]       = '1';
			$GLOBALS['wp_options'][ \ReportedIP_Hive_Two_Factor_Frontend::OPT_SOFT_DISABLED ] = time();
			\ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
			$this->assertFalse(
				\ReportedIP_Hive_Two_Factor_Frontend::is_available(),
				'A soft-disable timestamp must keep the module dormant even with the master toggle on.'
			);
		}

		public function test_default_slugs_compose_expected_urls(): void {
			$this->assertSame(
				'https://example.org/reportedip-hive-2fa/',
				\ReportedIP_Hive_Two_Factor_Frontend::challenge_url()
			);
			$this->assertSame(
				'https://example.org/reportedip-hive-2fa-setup/',
				\ReportedIP_Hive_Two_Factor_Frontend::setup_url()
			);
		}
	}
}
