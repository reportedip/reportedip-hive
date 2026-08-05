<?php
/**
 * Shared WebAuthn / security-key challenge panel.
 *
 * Single DOM contract consumed by `assets/js/two-factor-login.js`
 * (initWebAuthnLogin binds to #rip-2fa-webauthn-login). Included by the
 * wp-login challenge, the WooCommerce frontend challenge and the
 * password-reset gate so the three surfaces cannot drift apart.
 *
 * Expects `$rip_webauthn_panel` to be set by the including template:
 *   array(
 *       'is_active' => (bool)   whether webauthn is the active method,
 *       'context'   => (string) 'login' | 'frontend' | 'reset',
 *   )
 *
 * In the 'reset' context the hidden code input is named
 * `reportedip_2fa_reset_code` (the reset gate's POST contract) and the
 * tablist ARIA wiring is omitted because that page renders one method at
 * a time via links instead of tabs.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.33
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

$rip_wa_active  = ! empty( $rip_webauthn_panel['is_active'] );
$rip_wa_context = isset( $rip_webauthn_panel['context'] ) ? (string) $rip_webauthn_panel['context'] : 'login';
$rip_wa_reset   = ( 'reset' === $rip_wa_context );
$rip_wa_name    = $rip_wa_reset ? 'reportedip_2fa_reset_code' : 'reportedip_2fa_code';
?>
<section class="rip-2fa-challenge__panel<?php echo $rip_wa_active ? ' rip-2fa-challenge__panel--active' : ''; ?>"
	<?php if ( ! $rip_wa_reset ) : ?>
	role="tabpanel"
	aria-labelledby="rip-2fa-tab-webauthn"
	<?php endif; ?>
	id="rip-2fa-panel-webauthn"
	data-panel="webauthn"
	tabindex="0"
	<?php echo $rip_wa_active ? '' : 'hidden'; ?>>
	<p class="rip-2fa-challenge__instruction">
		<?php esc_html_e( 'Use your passkey or security key: Face ID, Touch ID, Windows Hello, or a hardware key such as a YubiKey. Insert the key and touch it, or hold it to the back of your phone (NFC).', 'reportedip-hive' ); ?>
	</p>
	<input type="hidden" name="<?php echo esc_attr( $rip_wa_name ); ?>" id="rip-2fa-code-webauthn" value="" <?php echo $rip_wa_active ? '' : 'disabled'; ?> />
	<button type="button" class="rip-button rip-button--primary rip-button--full-width" id="rip-2fa-webauthn-login">
		<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18" aria-hidden="true" style="vertical-align:-3px;margin-right:6px;"><path d="M12 11c1.7 0 3-1.3 3-3s-1.3-3-3-3-3 1.3-3 3 1.3 3 3 3z"/><path d="M6 21v-2c0-2.2 1.8-4 4-4h4c2.2 0 4 1.8 4 4v2"/></svg>
		<?php esc_html_e( 'Use passkey or security key', 'reportedip-hive' ); ?>
	</button>
	<p class="rip-2fa-challenge__hint" id="rip-2fa-webauthn-status" role="status" aria-live="polite"></p>
</section>
<?php
unset( $rip_webauthn_panel, $rip_wa_active, $rip_wa_context, $rip_wa_reset, $rip_wa_name );
