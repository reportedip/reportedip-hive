<?php
/**
 * Two-Factor Authentication Challenge Template
 *
 * Rendered on wp-login.php when a user needs to pass their second factor.
 * Uses the ReportedIP design system and progressively enhances with JS:
 *   – resend-code buttons hit an AJAX endpoint so the user never loses the
 *     challenge session
 *   – tab navigation follows WAI-ARIA Authoring Practices (arrow keys,
 *     aria-controls/labelledby, roving tabindex)
 *   – when the user has only one method configured the tabs collapse and the
 *     method panel is shown immediately
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.4.0
 *
 * @var WP_User $user            Current user being authenticated.
 * @var string  $method          Primary / initially-selected 2FA method.
 * @var string  $error           Error message to display (empty if none).
 * @var string  $form_nonce      CSRF protection nonce.
 * @var array   $allowed_methods Methods the user has actively configured.
 * @var bool    $trust_enabled   Whether trusted-device option is available.
 * @var int     $resend_wait     Seconds until email can be resent (0 = now).
 * @var int     $recovery_count  Remaining recovery codes.
 * @var bool    $email_code_sent True if an email OTP transient is pending.
 * @var bool    $sms_code_sent   True if an SMS OTP transient is pending.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

login_header(
	__( 'Two-Factor Verification', 'reportedip-hive' ),
	'',
	$error ? new WP_Error( 'reportedip_2fa_error', $error ) : null
);

$has_totp     = in_array( ReportedIP_Hive_Two_Factor::METHOD_TOTP, $allowed_methods, true );
$has_webauthn = in_array( ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN, $allowed_methods, true );
$has_email    = in_array( ReportedIP_Hive_Two_Factor::METHOD_EMAIL, $allowed_methods, true );
$has_sms      = in_array( ReportedIP_Hive_Two_Factor::METHOD_SMS, $allowed_methods, true );
$has_recovery = $recovery_count > 0;

$tab_count   = (int) $has_totp + (int) $has_webauthn + (int) $has_email + (int) $has_sms + (int) $has_recovery;
$show_tabs   = $tab_count > 1;
$masked_mail = ReportedIP_Hive_Two_Factor::mask_email( $user->user_email );
$sms_masked  = '';
if ( $has_sms && class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
	$sms_phone  = ReportedIP_Hive_Two_Factor_SMS::get_user_phone( $user->ID );
	$sms_masked = $sms_phone ? ReportedIP_Hive_Two_Factor_SMS::mask_phone( $sms_phone ) : '';
}
?>

<main class="rip-2fa-challenge<?php echo $show_tabs ? ' rip-2fa-challenge--multi' : ''; ?>" role="main" aria-labelledby="rip-2fa-title">
	<header class="rip-2fa-challenge__header">
		<div class="rip-2fa-challenge__icon" aria-hidden="true">
			<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
				<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4z" fill="currentColor" opacity="0.15"/>
				<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4zm0 4.2l12 6v10c0 8.4-6 16.3-12 18.5-6-2.2-12-10.1-12-18.5v-10l12-6z" fill="currentColor"/>
				<path d="M21 28l-5-5 1.8-1.8 3.2 3.2 7.2-7.2L30 19l-9 9z" fill="currentColor"/>
			</svg>
		</div>
		<h1 class="rip-2fa-challenge__title" id="rip-2fa-title">
			<?php esc_html_e( 'Verification required', 'reportedip-hive' ); ?>
		</h1>
		<p class="rip-2fa-challenge__subtitle">
			<?php
			printf(
				/* translators: %s: user display name */
				esc_html__( 'Hello %s, please confirm your identity.', 'reportedip-hive' ),
				'<strong>' . esc_html( $user->display_name ) . '</strong>' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			);
			?>
		</p>
	</header>

	<?php if ( $show_tabs ) : ?>
		<div class="rip-2fa-challenge__methods" role="tablist" aria-label="<?php esc_attr_e( 'Choose verification method', 'reportedip-hive' ); ?>">
			<?php
			$tab_definitions = array();
			if ( $has_totp ) {
				$tab_definitions[] = array(
					'method'   => ReportedIP_Hive_Two_Factor::METHOD_TOTP,
					'label'    => __( 'Authenticator', 'reportedip-hive' ),
					'aria_tip' => __( '6-digit code from your authenticator app', 'reportedip-hive' ),
					'icon'     => '<rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12" y2="18"/>',
				);
			}
			if ( $has_webauthn ) {
				$tab_definitions[] = array(
					'method'   => ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN,
					'label'    => __( 'Passkey', 'reportedip-hive' ),
					'aria_tip' => __( 'Sign in with passkey, Touch ID, Face ID or a hardware key', 'reportedip-hive' ),
					'icon'     => '<path d="M12 15v2m0 0v2m0-2h2m-2 0h-2M5 7h14l1 3v9a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-9l1-3z"/><circle cx="12" cy="11" r="3"/>',
				);
			}
			if ( $has_email ) {
				$tab_definitions[] = array(
					'method'   => ReportedIP_Hive_Two_Factor::METHOD_EMAIL,
					'label'    => __( 'Email', 'reportedip-hive' ),
					'aria_tip' => __( 'One-time code by email', 'reportedip-hive' ),
					'icon'     => '<path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/>',
				);
			}
			if ( $has_sms ) {
				$tab_definitions[] = array(
					'method'   => ReportedIP_Hive_Two_Factor::METHOD_SMS,
					'label'    => __( 'SMS', 'reportedip-hive' ),
					'aria_tip' => __( 'One-time code by SMS', 'reportedip-hive' ),
					'icon'     => '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
				);
			}
			if ( $has_recovery ) {
				$tab_definitions[] = array(
					'method'   => 'recovery',
					'label'    => __( 'Recovery', 'reportedip-hive' ),
					'aria_tip' => __( 'Use recovery code', 'reportedip-hive' ),
					'icon'     => '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>',
				);
			}

			foreach ( $tab_definitions as $rip_tab ) :
				$is_active = ( $rip_tab['method'] === $method );
				?>
				<button type="button"
					class="rip-2fa-challenge__method-tab<?php echo $is_active ? ' rip-2fa-challenge__method-tab--active' : ''; ?>"
					role="tab"
					id="rip-2fa-tab-<?php echo esc_attr( $rip_tab['method'] ); ?>"
					data-method="<?php echo esc_attr( $rip_tab['method'] ); ?>"
					aria-controls="rip-2fa-panel-<?php echo esc_attr( $rip_tab['method'] ); ?>"
					aria-selected="<?php echo $is_active ? 'true' : 'false'; ?>"
					tabindex="<?php echo $is_active ? '0' : '-1'; ?>"
					aria-label="<?php echo esc_attr( $rip_tab['label'] . ' — ' . $rip_tab['aria_tip'] ); ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" aria-hidden="true"><?php echo $rip_tab['icon']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></svg>
					<span class="rip-2fa-challenge__method-tab-label"><?php echo esc_html( $rip_tab['label'] ); ?></span>
				</button>
				<?php
			endforeach;
			?>
		</div>
	<?php endif; ?>

	<form method="post" action="<?php echo esc_url( wp_login_url() . '?action=reportedip_2fa' ); ?>" class="rip-2fa-challenge__form" id="rip-2fa-form" novalidate>
		<input type="hidden" name="_reportedip_2fa_nonce" value="<?php echo esc_attr( $form_nonce ); ?>" />
		<input type="hidden" name="reportedip_2fa_method" id="rip-2fa-method-input" value="<?php echo esc_attr( $method ); ?>" />

		<?php /* -------- TOTP panel ----------------------------------------- */ ?>
		<?php
		if ( $has_totp ) :
			$is_active = ( ReportedIP_Hive_Two_Factor::METHOD_TOTP === $method );
			?>
			<section class="rip-2fa-challenge__panel<?php echo $is_active ? ' rip-2fa-challenge__panel--active' : ''; ?>"
				role="tabpanel"
				id="rip-2fa-panel-totp"
				aria-labelledby="rip-2fa-tab-totp"
				data-panel="totp"
				tabindex="0"
				<?php echo $is_active ? '' : 'hidden'; ?>>
				<p class="rip-2fa-challenge__instruction">
					<?php esc_html_e( 'Enter the 6-digit code from your authenticator app.', 'reportedip-hive' ); ?>
				</p>
				<div class="rip-2fa-challenge__input-wrapper">
					<label class="screen-reader-text" for="rip-2fa-code-totp"><?php esc_html_e( 'Authenticator code', 'reportedip-hive' ); ?></label>
					<input type="text"
						name="reportedip_2fa_code"
						class="rip-2fa-challenge__input"
						id="rip-2fa-code-totp"
						inputmode="numeric"
						pattern="[0-9]{6}"
						maxlength="6"
						autocomplete="one-time-code"
						<?php echo $is_active ? 'autofocus' : 'disabled'; ?>
						placeholder="000000"
						aria-describedby="rip-2fa-hint-totp" />
				</div>
				<p class="rip-2fa-challenge__hint" id="rip-2fa-hint-totp">
					<?php esc_html_e( 'The code changes every 30 seconds.', 'reportedip-hive' ); ?>
				</p>
			</section>
		<?php endif; ?>

		<?php /* -------- Email panel ---------------------------------------- */ ?>
		<?php
		if ( $has_email ) :
			$is_active = ( ReportedIP_Hive_Two_Factor::METHOD_EMAIL === $method );
			?>
			<section class="rip-2fa-challenge__panel<?php echo $is_active ? ' rip-2fa-challenge__panel--active' : ''; ?>"
				role="tabpanel"
				id="rip-2fa-panel-email"
				aria-labelledby="rip-2fa-tab-email"
				data-panel="email"
				data-code-sent="<?php echo $email_code_sent ? '1' : '0'; ?>"
				tabindex="0"
				<?php echo $is_active ? '' : 'hidden'; ?>>

				<div class="rip-2fa-challenge__phase rip-2fa-challenge__phase--request" data-phase="request"<?php echo $email_code_sent ? ' hidden' : ''; ?>>
					<p class="rip-2fa-challenge__instruction">
						<?php
						printf(
							/* translators: %s: masked email */
							esc_html__( 'We will send a one-time code to %s.', 'reportedip-hive' ),
							'<strong>' . esc_html( $masked_mail ) . '</strong>'
						);
						?>
					</p>
					<button type="button"
						class="rip-button rip-button--primary rip-2fa-challenge__resend-btn"
						data-resend-method="email"
						data-fallback-url="<?php echo esc_url( wp_login_url() . '?action=reportedip_2fa&resend_email=1' ); ?>">
						<?php esc_html_e( 'Send code by email', 'reportedip-hive' ); ?>
					</button>
				</div>

				<div class="rip-2fa-challenge__phase rip-2fa-challenge__phase--code" data-phase="code"<?php echo $email_code_sent ? '' : ' hidden'; ?>>
					<p class="rip-2fa-challenge__instruction">
						<?php
						printf(
							/* translators: %s: masked email */
							esc_html__( 'We sent a 6-digit code to %s.', 'reportedip-hive' ),
							'<strong class="rip-2fa-challenge__destination" data-destination-email>' . esc_html( $masked_mail ) . '</strong>'
						);
						?>
					</p>
					<div class="rip-2fa-challenge__input-wrapper">
						<label class="screen-reader-text" for="rip-2fa-code-email"><?php esc_html_e( 'Email code', 'reportedip-hive' ); ?></label>
						<input type="text"
							name="reportedip_2fa_code"
							class="rip-2fa-challenge__input"
							id="rip-2fa-code-email"
							inputmode="numeric"
							pattern="[0-9]{6}"
							maxlength="6"
							autocomplete="one-time-code"
							<?php
							if ( $is_active && $email_code_sent ) {
								echo 'autofocus';
							} elseif ( ! $is_active ) {
								echo 'disabled';
							}
							?>
							placeholder="000000" />
					</div>
					<p class="rip-2fa-challenge__resend">						<?php esc_html_e( 'Didn\'t get the email?', 'reportedip-hive' ); ?>
						<button type="button"
							class="rip-2fa-challenge__resend-link"
							data-resend-method="email"
							data-fallback-url="<?php echo esc_url( wp_login_url() . '?action=reportedip_2fa&resend_email=1' ); ?>"
							data-cooldown="<?php echo esc_attr( (string) $resend_wait ); ?>">
							<?php esc_html_e( 'Resend code', 'reportedip-hive' ); ?>
						</button>
						<span class="rip-2fa-challenge__timer" aria-hidden="true"></span>
					</p>
				</div>
			</section>
		<?php endif; ?>

		<?php /* -------- SMS panel ------------------------------------------ */ ?>
		<?php
		if ( $has_sms ) :
			$is_active = ( ReportedIP_Hive_Two_Factor::METHOD_SMS === $method );
			?>
			<section class="rip-2fa-challenge__panel<?php echo $is_active ? ' rip-2fa-challenge__panel--active' : ''; ?>"
				role="tabpanel"
				id="rip-2fa-panel-sms"
				aria-labelledby="rip-2fa-tab-sms"
				data-panel="sms"
				data-code-sent="<?php echo $sms_code_sent ? '1' : '0'; ?>"
				tabindex="0"
				<?php echo $is_active ? '' : 'hidden'; ?>>

				<?php if ( ! $sms_masked ) : ?>
					<p class="rip-2fa-challenge__instruction">
						<?php esc_html_e( 'No phone number is stored for this user.', 'reportedip-hive' ); ?>
					</p>
				<?php else : ?>
					<div class="rip-2fa-challenge__phase rip-2fa-challenge__phase--request" data-phase="request"<?php echo $sms_code_sent ? ' hidden' : ''; ?>>
						<p class="rip-2fa-challenge__instruction">
							<?php
							printf(
								/* translators: %s: masked phone */
								esc_html__( 'We will send a one-time code by SMS to %s.', 'reportedip-hive' ),
								'<strong>' . esc_html( $sms_masked ) . '</strong>'
							);
							?>
						</p>
						<button type="button"
							class="rip-button rip-button--primary rip-2fa-challenge__resend-btn"
							data-resend-method="sms"
							data-fallback-url="<?php echo esc_url( wp_login_url() . '?action=reportedip_2fa&resend_sms=1' ); ?>">
							<?php esc_html_e( 'Send code by SMS', 'reportedip-hive' ); ?>
						</button>
					</div>

					<div class="rip-2fa-challenge__phase rip-2fa-challenge__phase--code" data-phase="code"<?php echo $sms_code_sent ? '' : ' hidden'; ?>>
						<p class="rip-2fa-challenge__instruction">
							<?php
							printf(
								/* translators: %s: masked phone */
								esc_html__( 'We sent a 6-digit SMS code to %s.', 'reportedip-hive' ),
								'<strong class="rip-2fa-challenge__destination" data-destination-sms>' . esc_html( $sms_masked ) . '</strong>'
							);
							?>
						</p>
						<div class="rip-2fa-challenge__input-wrapper">
							<label class="screen-reader-text" for="rip-2fa-code-sms"><?php esc_html_e( 'SMS code', 'reportedip-hive' ); ?></label>
							<input type="text"
								name="reportedip_2fa_code"
								class="rip-2fa-challenge__input"
								id="rip-2fa-code-sms"
								inputmode="numeric"
								pattern="[0-9]{6}"
								maxlength="6"
								autocomplete="one-time-code"
								<?php
								if ( $is_active && $sms_code_sent ) {
									echo 'autofocus';
								} elseif ( ! $is_active ) {
									echo 'disabled';
								}
								?>
								placeholder="000000" />
						</div>
						<p class="rip-2fa-challenge__resend">
							<?php esc_html_e( 'Didn\'t get the SMS?', 'reportedip-hive' ); ?>
							<button type="button"
								class="rip-2fa-challenge__resend-link"
								data-resend-method="sms"
								data-fallback-url="<?php echo esc_url( wp_login_url() . '?action=reportedip_2fa&resend_sms=1' ); ?>">
								<?php esc_html_e( 'Resend SMS', 'reportedip-hive' ); ?>
							</button>
							<span class="rip-2fa-challenge__timer" aria-hidden="true"></span>
						</p>
					</div>
				<?php endif; ?>
			</section>
		<?php endif; ?>

		<?php /* -------- Passkey panel --------------------------------------- */ ?>
		<?php
		if ( $has_webauthn ) :
			$is_active = ( ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN === $method );
			?>
			<section class="rip-2fa-challenge__panel<?php echo $is_active ? ' rip-2fa-challenge__panel--active' : ''; ?>"
				role="tabpanel"
				id="rip-2fa-panel-webauthn"
				aria-labelledby="rip-2fa-tab-webauthn"
				data-panel="webauthn"
				tabindex="0"
				<?php echo $is_active ? '' : 'hidden'; ?>>
				<p class="rip-2fa-challenge__instruction">
					<?php esc_html_e( 'Sign in with your passkey — Face ID, Touch ID, Windows Hello or hardware key.', 'reportedip-hive' ); ?>
				</p>
				<input type="hidden" name="reportedip_2fa_code" id="rip-2fa-code-webauthn" value="" <?php echo $is_active ? '' : 'disabled'; ?> />
				<button type="button" class="rip-button rip-button--primary rip-button--full-width" id="rip-2fa-webauthn-login">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18" aria-hidden="true" style="vertical-align:-3px;margin-right:6px;"><path d="M12 11c1.7 0 3-1.3 3-3s-1.3-3-3-3-3 1.3-3 3 1.3 3 3 3z"/><path d="M6 21v-2c0-2.2 1.8-4 4-4h4c2.2 0 4 1.8 4 4v2"/></svg>
					<?php esc_html_e( 'Sign in with passkey', 'reportedip-hive' ); ?>
				</button>
				<p class="rip-2fa-challenge__hint" id="rip-2fa-webauthn-status" role="status" aria-live="polite"></p>
			</section>
		<?php endif; ?>

		<?php /* -------- Recovery panel -------------------------------------- */ ?>
		<?php if ( $has_recovery ) : ?>
			<section class="rip-2fa-challenge__panel"
				role="tabpanel"
				id="rip-2fa-panel-recovery"
				aria-labelledby="rip-2fa-tab-recovery"
				data-panel="recovery"
				tabindex="0"
				hidden>
				<p class="rip-2fa-challenge__instruction">
					<?php
					printf(
						/* translators: %d: remaining codes */
						esc_html__( 'Enter one of your recovery codes. (%d remaining)', 'reportedip-hive' ),
						(int) $recovery_count
					);
					?>
				</p>
				<div class="rip-2fa-challenge__input-wrapper">
					<label class="screen-reader-text" for="rip-2fa-code-recovery"><?php esc_html_e( 'Recovery code', 'reportedip-hive' ); ?></label>
					<input type="text"
						name="reportedip_2fa_code"
						class="rip-2fa-challenge__input rip-2fa-challenge__input--recovery"
						id="rip-2fa-code-recovery"
						maxlength="9"
						autocomplete="off"
						placeholder="xxxx-xxxx"
						disabled />
				</div>
				<p class="rip-2fa-challenge__hint">
					<?php esc_html_e( 'Each recovery code can be used only once.', 'reportedip-hive' ); ?>
				</p>
			</section>
		<?php endif; ?>

		<p class="rip-2fa-challenge__live" id="rip-2fa-live" role="status" aria-live="polite"></p>

		<?php if ( $trust_enabled ) : ?>
			<div class="rip-2fa-challenge__trust">
				<label class="rip-2fa-challenge__trust-label">
					<input type="checkbox" name="reportedip_2fa_trust_device" value="1" />
					<span>
						<?php
						$trust_days = (int) get_option( 'reportedip_hive_2fa_trusted_device_days', 30 );
						printf(
							/* translators: %d: number of days */
							esc_html__( 'Trust this device for %d days', 'reportedip-hive' ),
							(int) $trust_days
						);
						?>
					</span>
				</label>
			</div>
		<?php endif; ?>

		<div class="rip-2fa-challenge__actions">
			<button type="submit" class="rip-button rip-button--primary rip-button--full-width rip-2fa-challenge__submit">
				<?php esc_html_e( 'Verify', 'reportedip-hive' ); ?>
			</button>
		</div>

		<p class="rip-2fa-challenge__back">
			<a href="<?php echo esc_url( wp_login_url() ); ?>">
				<?php esc_html_e( '← Back to sign-in', 'reportedip-hive' ); ?>
			</a>
		</p>
	</form>
</main>

<?php
login_footer();
