<?php
/**
 * Unit tests for the WooCommerce-aware origin tracking of the storefront
 * challenge in {@see ReportedIP_Hive_Two_Factor_Frontend}.
 *
 * The 2FA challenge URL has to differentiate between WordPress backend
 * logins (wp-login.php) and WooCommerce frontend logins (My Account /
 * checkout / blocks). The contract locked in here:
 *
 *  - `detect_login_origin()` returns `'wc'`, `'wc-block'`, or `''`.
 *  - The challenge payload carries `origin`, `origin_url`, and
 *    `wc_session_hash` so the challenge page can preserve the cart and
 *    redirect back to the right WC endpoint.
 *  - The challenge URL listener keeps wp-login for a sign-in without an
 *    origin and while the module is unavailable.
 *  - The redirect listener leaves every other challenge context alone.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
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
	if ( ! function_exists( 'add_action' ) ) {
		function add_action( ...$args ) {}
	}
	if ( ! function_exists( 'add_filter' ) ) {
		function add_filter( ...$args ) {}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @runTestsInSeparateProcesses
	 * @preserveGlobalState disabled
	 */
	class TwoFactorOriginTrackingTest extends TestCase {

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options'] = array();
			require_once dirname( __DIR__, 2 ) . '/includes/class-mode-manager.php';
			require_once dirname( __DIR__, 2 ) . '/includes/class-two-factor-frontend.php';
			\ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
		}

		protected function tear_down() {
			unset( $_SERVER['HTTP_REFERER'] );
			parent::tear_down();
		}

		private function source(): string {
			return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor-frontend.php' );
		}

		public function test_payload_carries_origin_origin_url_and_session_hash(): void {
			$_SERVER['HTTP_REFERER'] = 'https://example.org/my-account/';

			$payload = \ReportedIP_Hive_Two_Factor_Frontend::challenge_payload( array( 'kept' => 1 ) );

			$this->assertSame( '', $payload['origin'], 'Without WooCommerce the sign-in has no storefront origin.' );
			$this->assertSame( 'https://example.org/my-account/', $payload['origin_url'], 'The login referrer rides along so the customer is bounced back to the page they came from.' );
			$this->assertSame( '', $payload['wc_session_hash'], 'collect_wc_session_hash() must short-circuit when WC() is not defined.' );
			$this->assertSame( 1, $payload['kept'], 'Fields of earlier listeners survive.' );
		}

		public function test_challenge_url_stays_on_wp_login_without_origin_or_module(): void {
			$this->assertSame( 'https://example.org/wp-login.php?action=reportedip_2fa', \ReportedIP_Hive_Two_Factor_Frontend::filter_challenge_url( 'https://example.org/wp-login.php?action=reportedip_2fa', '' ) );
			$this->assertSame(
				'https://example.org/wp-login.php?action=reportedip_2fa',
				\ReportedIP_Hive_Two_Factor_Frontend::filter_challenge_url( 'https://example.org/wp-login.php?action=reportedip_2fa', 'wc' ),
				'A WooCommerce sign-in keeps wp-login while the module is switched off, a downgrade must never strand a customer on a dead slug.'
			);
		}

		public function test_redirect_listener_ignores_other_contexts(): void {
			foreach ( array( 'verified', 'locked', 'signed_in' ) as $event ) {
				$this->assertSame( 'https://example.org/wp-admin/', \ReportedIP_Hive_Two_Factor_Frontend::filter_redirect_url( 'https://example.org/wp-admin/', $event, 'wp_login', array() ), $event );
			}
		}

		public function test_redirect_listener_keeps_a_stored_redirect_to(): void {
			$nonce = array(
				'redirect_to' => 'https://example.org/cart/',
				'origin'      => 'wc',
			);
			$this->assertSame( 'https://example.org/cart/', \ReportedIP_Hive_Two_Factor_Frontend::filter_redirect_url( 'https://example.org/cart/', 'verified', 'theme_frame', $nonce ) );
		}

		public function test_redirect_listener_falls_back_to_origin_url_then_home(): void {
			$this->assertSame(
				'https://example.org/shop/',
				\ReportedIP_Hive_Two_Factor_Frontend::filter_redirect_url( 'https://example.org/wp-admin/', 'verified', 'theme_frame', array( 'origin_url' => 'https://example.org/shop/' ) )
			);
			$this->assertSame( 'https://example.org/', \ReportedIP_Hive_Two_Factor_Frontend::filter_redirect_url( 'https://example.org/wp-admin/', 'verified', 'theme_frame', array() ) );
			$this->assertSame( 'https://example.org/', \ReportedIP_Hive_Two_Factor_Frontend::filter_redirect_url( 'https://example.org/wp-admin/', 'signed_in', 'theme_frame', array() ), 'Without WooCommerce a signed-in visitor goes home.' );
		}

		public function test_detect_login_origin_returns_wc_block_for_store_api_routes(): void {
			$source = $this->source();

			$this->assertStringContainsString(
				"return 'wc-block';",
				$source,
				'WC Store-API REST requests (Cart and Checkout blocks) must be tagged as `wc-block` so we can hand back a JSON redirect instead of trying to redirect-and-exit.'
			);
			$this->assertStringContainsString(
				"'/wc/store/'",
				$source,
				'The `/wc/store/` route prefix is the canonical marker for the WC blocks REST namespace.'
			);
		}

		public function test_detect_login_origin_recognises_classic_wc_form_marker(): void {
			$source = $this->source();

			$this->assertStringContainsString(
				'woocommerce-login-nonce',
				$source,
				'The classic `woocommerce-login-nonce` POST field is the cheapest reliable signal that this submit came from `[woocommerce_my_account]`.'
			);
			$this->assertStringContainsString(
				"did_action( 'woocommerce_login_form_start' )",
				$source,
				'`woocommerce_login_form_start` is dispatched by every WC login template, make sure we honour it so themes that override the form still get tagged.'
			);
		}

		public function test_listeners_are_wired_in_init(): void {
			$source = $this->source();

			foreach ( array(
				"add_filter( 'reportedip_hive_2fa_challenge_payload', array( __CLASS__, 'challenge_payload' ) );",
				"add_filter( 'reportedip_hive_2fa_challenge_url', array( __CLASS__, 'filter_challenge_url' ), 10, 2 );",
				"add_filter( 'reportedip_hive_2fa_redirect_url', array( __CLASS__, 'filter_redirect_url' ), 10, 4 );",
				"add_action( 'reportedip_hive_2fa_render_challenge_' . self::CONTEXT, array( __CLASS__, 'render_challenge_view' ), 10, 2 );",
				"add_action( 'reportedip_hive_2fa_render_expired_' . self::CONTEXT, array( __CLASS__, 'render_expired_view' ), 10, 2 );",
			) as $line ) {
				$this->assertStringContainsString( $line, $source );
			}
			$this->assertSame( 'theme_frame', \ReportedIP_Hive_Two_Factor_Frontend::CONTEXT, 'The context of reportedip_hive_2fa_verified stays as in 2.1.x.' );
		}
	}
}
