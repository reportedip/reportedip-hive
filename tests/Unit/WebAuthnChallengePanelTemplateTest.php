<?php
/**
 * Source-pattern guards for the shared WebAuthn challenge panel.
 *
 * Before 2.1.33 the WooCommerce frontend challenge rendered a "Passkey"
 * tab with no matching panel (aria-controls pointed into the void), and
 * the password-reset gate offered webauthn with nothing but a text input
 * — both surfaces silently locked passkey-only users out. These tests pin
 * every challenge surface to the single shared partial so the panels can
 * never drift apart again.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.33
 */

namespace ReportedIP\Hive\Tests\Unit;

use ReportedIP\Hive\Tests\TestCase;

class WebAuthnChallengePanelTemplateTest extends TestCase {

	private const PARTIAL = 'templates/partials/webauthn-challenge-panel.php';

	/**
	 * Read a plugin file relative to the plugin root.
	 *
	 * @param string $relative Relative path.
	 * @return string
	 */
	private function source( string $relative ): string {
		return (string) file_get_contents( dirname( __DIR__, 2 ) . '/' . $relative );
	}

	public function test_partial_carries_the_full_js_dom_contract(): void {
		$partial = $this->source( self::PARTIAL );
		$this->assertStringContainsString( 'id="rip-2fa-webauthn-login"', $partial );
		$this->assertStringContainsString( 'id="rip-2fa-code-webauthn"', $partial );
		$this->assertStringContainsString( 'id="rip-2fa-webauthn-status"', $partial );
		$this->assertStringContainsString( 'id="rip-2fa-panel-webauthn"', $partial );
		$this->assertStringContainsString(
			'reportedip_2fa_reset_code',
			$partial,
			'The reset context must rename the hidden input to the reset gate POST contract.'
		);
	}

	public function test_wp_login_challenge_includes_the_partial(): void {
		$this->assertStringContainsString(
			self::PARTIAL,
			$this->source( 'templates/two-factor-challenge.php' )
		);
	}

	public function test_frontend_challenge_includes_the_partial(): void {
		$template = $this->source( 'templates/frontend-2fa-challenge.php' );
		$this->assertStringContainsString(
			self::PARTIAL,
			$template,
			'The WooCommerce frontend challenge must render the webauthn panel — it shipped a dead tab without one before 2.1.33.'
		);
		$this->assertStringContainsString(
			'$has_webauthn',
			$template,
			'The webauthn tab and its panel must be gated on the same flag.'
		);
	}

	public function test_reset_gate_includes_the_partial_and_the_token_bridge(): void {
		$gate = $this->source( 'includes/class-two-factor-reset-gate.php' );
		$this->assertStringContainsString(
			self::PARTIAL,
			$gate,
			'The reset gate must render the ceremony panel for webauthn instead of a text input.'
		);
		$this->assertStringContainsString(
			'mint_login_token',
			$gate,
			'The gate must mint the ceremony token — without it the nopriv AJAX endpoints cannot resolve the user (no login-nonce cookie exists on this surface).'
		);
		$this->assertStringContainsString( 'id="rip-2fa-form"', $gate );
		$this->assertStringContainsString( 'id="rip-2fa-method-input"', $gate );
	}

	public function test_login_js_forwards_the_ceremony_token(): void {
		$js = $this->source( 'assets/js/two-factor-login.js' );
		$this->assertStringContainsString( 'config.loginToken', $js );
		$this->assertStringContainsString( "formData.append( 'login_token', config.loginToken )", $js );
	}
}
