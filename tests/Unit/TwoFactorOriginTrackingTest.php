<?php
/**
 * Unit tests for the WooCommerce-aware origin tracking added to
 * {@see ReportedIP_Hive_Two_Factor::filter_authenticate()} in 1.7.0.
 *
 * The 2FA challenge URL has to differentiate between WordPress backend
 * logins (wp-login.php) and WooCommerce frontend logins (My Account /
 * checkout / blocks). Earlier releases hard-wired the challenge to
 * wp-login.php, so any customer using `[woocommerce_my_account]` got
 * thrown out of the theme frame on the second factor. The contract
 * locked in here:
 *
 *  - `detect_login_origin()` returns `'wc'`, `'wc-block'`, or `''`.
 *  - The persisted nonce payload carries `origin`, `origin_url`, and
 *    `wc_session_hash` so the challenge page can preserve the cart and
 *    redirect back to the right WC endpoint.
 *  - `resolve_challenge_url()` falls back to wp-login when the Frontend
 *    Two-Factor module is not yet loaded (Phase 3 dependency) — so
 *    activating the tracking in isolation never breaks the existing
 *    backend flow.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <ps@cms-admins.de>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      1.7.0
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

class TwoFactorOriginTrackingTest extends TestCase {

	private function source(): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-two-factor.php' );
	}

	public function test_nonce_data_carries_origin_origin_url_and_session_hash(): void {
		$source = $this->source();

		$this->assertStringContainsString(
			"'origin'          => \$origin,",
			$source,
			'filter_authenticate() must persist the origin token in the challenge nonce so the challenge page can pick the right post-verify redirect.'
		);
		$this->assertStringContainsString(
			"'origin_url'      => \$referer,",
			$source,
			'The login referrer has to ride along with the nonce so the customer is bounced back to the page they came from after a successful 2FA verify.'
		);
		$this->assertStringContainsString(
			"'wc_session_hash' => \$wc_session,",
			$source,
			'The WooCommerce session customer-id must be captured before the redirect — otherwise the cart silently empties on the way to the challenge.'
		);
	}

	public function test_filter_authenticate_picks_origin_aware_challenge_url(): void {
		$source = $this->source();

		$this->assertStringContainsString(
			'$challenge_url = self::resolve_challenge_url( $origin );',
			$source,
			'The challenge URL must be resolved through the origin-aware helper, not the legacy `wp_login_url() . action=...` literal — otherwise WC frontend logins keep bouncing to wp-login.php.'
		);
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
			"woocommerce-login-nonce",
			$source,
			'The classic `woocommerce-login-nonce` POST field is the cheapest reliable signal that this submit came from `[woocommerce_my_account]`.'
		);
		$this->assertStringContainsString(
			"did_action( 'woocommerce_login_form_start' )",
			$source,
			'`woocommerce_login_form_start` is dispatched by every WC login template — make sure we honour it so themes that override the form still get tagged.'
		);
	}

	public function test_resolve_challenge_url_falls_back_to_wp_login_without_frontend_module(): void {
		$source = $this->source();

		$this->assertMatchesRegularExpression(
			'/\$default\s*=\s*wp_login_url\(\)\s*\.\s*\'\?action=\'\s*\.\s*self::ACTION_CHALLENGE;/',
			$source,
			'When the Frontend Two-Factor module is not loaded yet (Phase 3 dep) the helper must hand back the legacy wp-login URL — otherwise enabling Phase 2 alone would 404 every login.'
		);
		$this->assertStringContainsString(
			"if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_Frontend' ) ) {",
			$source,
			'The class-existence guard is critical: the Frontend module is gated by the PRO tier and may not be present on every install.'
		);
		$this->assertStringContainsString(
			'ReportedIP_Hive_Two_Factor_Frontend::is_available()',
			$source,
			'Even when the Frontend class is loaded, the tier-gate has to be re-checked — otherwise a downgrade leaves customers stranded on a slug that the rewrite layer has stopped serving.'
		);
	}

	public function test_collect_wc_session_hash_is_safe_when_wc_is_absent(): void {
		$source = $this->source();

		$this->assertStringContainsString(
			"if ( ! function_exists( 'WC' ) ) {",
			$source,
			'collect_wc_session_hash() must short-circuit when WC() is not defined — otherwise the helper triggers a fatal on plain WP installs.'
		);
		$this->assertStringContainsString(
			"return '';",
			$source,
			'collect_wc_session_hash() must always return a string so the transient payload stays JSON-serialisable.'
		);
	}
}
