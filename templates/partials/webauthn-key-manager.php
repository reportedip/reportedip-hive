<?php
/**
 * Security-key / passkey manager card.
 *
 * Lists a user's WebAuthn credentials with rename/delete controls and an
 * inline "add key" flow (name first, then the ceremony with an optional
 * authenticator hint). All behaviour lives in `assets/js/two-factor-keys.js`
 * which binds to the ids below; the list itself is loaded via AJAX so this
 * partial stays render-context-free.
 *
 * Expects `$rip_webauthn_manager` to be set by the including template:
 *   array(
 *       'user_id' => (int) user whose keys are managed,
 *   )
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.34
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

$rip_wa_mgr_user = isset( $rip_webauthn_manager['user_id'] ) ? (int) $rip_webauthn_manager['user_id'] : get_current_user_id();
?>
<div class="rip-webauthn-keys" id="rip-webauthn-key-manager" data-user-id="<?php echo esc_attr( (string) $rip_wa_mgr_user ); ?>">
	<div class="rip-webauthn-keys__header">
		<h3 class="rip-webauthn-keys__title"><?php esc_html_e( 'Security keys & passkeys', 'reportedip-hive' ); ?></h3>
		<button type="button" class="rip-button rip-button--secondary" id="rip-webauthn-add-toggle">
			<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" aria-hidden="true"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
			<?php esc_html_e( 'Add security key', 'reportedip-hive' ); ?>
		</button>
	</div>

	<p class="description"><?php esc_html_e( 'Register more than one key so a lost or broken key never locks you out — keep a backup key in a safe place.', 'reportedip-hive' ); ?></p>

	<div class="rip-webauthn-keys__add" id="rip-webauthn-add-form" hidden>
		<div class="rip-form-group">
			<label class="rip-label" for="rip-webauthn-key-name"><?php esc_html_e( 'Key name', 'reportedip-hive' ); ?></label>
			<input type="text" id="rip-webauthn-key-name" class="rip-input" maxlength="64" placeholder="<?php esc_attr_e( 'e.g. YubiKey office', 'reportedip-hive' ); ?>" />
		</div>
		<div class="rip-webauthn-keys__add-actions">
			<button type="button" class="rip-button rip-button--primary rip-webauthn-add-run" data-hint="security-key">
				<?php esc_html_e( 'Security key (USB / NFC)', 'reportedip-hive' ); ?>
			</button>
			<button type="button" class="rip-button rip-button--secondary rip-webauthn-add-run" data-hint="client-device">
				<?php esc_html_e( 'This device (Face ID / Windows Hello)', 'reportedip-hive' ); ?>
			</button>
		</div>
		<p class="rip-2fa-inline-status" id="rip-webauthn-add-status" role="status" aria-live="polite"></p>
	</div>

	<table class="rip-table rip-webauthn-keys__table" id="rip-webauthn-keys-table" hidden>
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Name', 'reportedip-hive' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Type', 'reportedip-hive' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Added', 'reportedip-hive' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Last used', 'reportedip-hive' ); ?></th>
				<th scope="col"><span class="screen-reader-text"><?php esc_html_e( 'Actions', 'reportedip-hive' ); ?></span></th>
			</tr>
		</thead>
		<tbody></tbody>
	</table>

	<div class="rip-alert rip-alert--info" id="rip-webauthn-keys-empty" hidden>
		<?php esc_html_e( 'No security key registered yet. Add a hardware key (e.g. YubiKey) or a passkey on this device.', 'reportedip-hive' ); ?>
	</div>

	<p class="rip-2fa-inline-status" id="rip-webauthn-keys-status" role="status" aria-live="polite"></p>
</div>
<?php
unset( $rip_webauthn_manager, $rip_wa_mgr_user );
