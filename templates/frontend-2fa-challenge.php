<?php
/**
 * Two-Factor Authentication Challenge Template — Theme-frame variant.
 *
 * Rendered by {@see ReportedIP_Hive_Two_Factor::render_frontend_challenge_page()}
 * inside the active theme via `get_header()` / `get_footer()`. Used when the
 * customer kicked off the login from a WooCommerce frontend surface
 * (My Account / Checkout / WC Blocks) so the second factor stays inside the
 * storefront chrome instead of bouncing them to wp-login.php.
 *
 * The HTML is intentionally close to `templates/two-factor-challenge.php`
 * so behavior parity is obvious. The differences are scoped:
 *   - no `login_header()` / `login_footer()` — the wrapper supplies the
 *     theme frame.
 *   - all action URLs target the dedicated frontend slug rather than
 *     `wp-login.php?action=reportedip_2fa`.
 *   - "Back to sign-in" returns to `wc_get_page_permalink('myaccount')`
 *     when WooCommerce is loaded; otherwise to `home_url('/')`.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.7.0
 *
 * @var array<string,mixed> $rip_2fa Template payload assembled by
 *                                    {@see ReportedIP_Hive_Two_Factor::handle_2fa_challenge()}.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound

/** @var WP_User $user */
$user             = $rip_2fa['user'];
$method           = (string) $rip_2fa['method'];
$rip_render_error = (string) $rip_2fa['error'];
$form_nonce       = (string) $rip_2fa['form_nonce'];
$allowed_methods  = (array) $rip_2fa['allowed_methods'];
$trust_enabled    = (bool) $rip_2fa['trust_enabled'];
$resend_wait      = (int) $rip_2fa['resend_wait'];
$recovery_count   = (int) $rip_2fa['recovery_count'];
$email_code_sent  = (bool) $rip_2fa['email_code_sent'];
$sms_code_sent    = (bool) $rip_2fa['sms_code_sent'];

$challenge_action = ReportedIP_Hive_Two_Factor_Frontend::challenge_url();
$back_url         = function_exists( 'wc_get_page_permalink' )
	? (string) wc_get_page_permalink( 'myaccount' )
	: home_url( '/' );

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

<main class="rip-frontend-2fa rip-2fa-challenge<?php echo $show_tabs ? ' rip-2fa-challenge--multi' : ''; ?>" id="rip-frontend-2fa" role="main" aria-labelledby="rip-2fa-title">
	<div class="rip-frontend-2fa__panel">
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

		<?php if ( '' !== $rip_render_error ) : ?>
			<div class="rip-alert rip-alert--error" role="alert">
				<?php echo esc_html( $rip_render_error ); ?>
			</div>
		<?php endif; ?>

		<?php if ( $show_tabs ) : ?>
			<div class="rip-2fa-challenge__methods" role="tablist" aria-label="<?php esc_attr_e( 'Choose verification method', 'reportedip-hive' ); ?>">
				<?php
				$tab_definitions = array();
				if ( $has_totp ) {
					$tab_definitions[] = array(
						'method' => ReportedIP_Hive_Two_Factor::METHOD_TOTP,
						'label'  => __( 'Authenticator', 'reportedip-hive' ),
					);
				}
				if ( $has_webauthn ) {
					$tab_definitions[] = array(
						'method' => ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN,
						'label'  => __( 'Passkey', 'reportedip-hive' ),
					);
				}
				if ( $has_email ) {
					$tab_definitions[] = array(
						'method' => ReportedIP_Hive_Two_Factor::METHOD_EMAIL,
						'label'  => __( 'Email', 'reportedip-hive' ),
					);
				}
				if ( $has_sms ) {
					$tab_definitions[] = array(
						'method' => ReportedIP_Hive_Two_Factor::METHOD_SMS,
						'label'  => __( 'SMS', 'reportedip-hive' ),
					);
				}
				if ( $has_recovery ) {
					$tab_definitions[] = array(
						'method' => 'recovery',
						'label'  => __( 'Recovery', 'reportedip-hive' ),
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
						tabindex="<?php echo $is_active ? '0' : '-1'; ?>">
						<span class="rip-2fa-challenge__method-tab-label"><?php echo esc_html( $rip_tab['label'] ); ?></span>
					</button>
					<?php
				endforeach;
				?>
			</div>
		<?php endif; ?>

		<form method="post" action="<?php echo esc_url( $challenge_action ); ?>" class="rip-2fa-challenge__form" id="rip-2fa-form" novalidate>
			<input type="hidden" name="_reportedip_2fa_nonce" value="<?php echo esc_attr( $form_nonce ); ?>" />
			<input type="hidden" name="reportedip_2fa_method" id="rip-2fa-method-input" value="<?php echo esc_attr( $method ); ?>" />

			<?php
			if ( $has_totp ) :
				$is_active = ( ReportedIP_Hive_Two_Factor::METHOD_TOTP === $method );
				?>
				<section class="rip-2fa-challenge__panel<?php echo $is_active ? ' rip-2fa-challenge__panel--active' : ''; ?>"
					role="tabpanel" id="rip-2fa-panel-totp" aria-labelledby="rip-2fa-tab-totp" data-panel="totp" tabindex="0"
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
							placeholder="000000" />
					</div>
				</section>
			<?php endif; ?>

			<?php
			if ( $has_email ) :
				$is_active = ( ReportedIP_Hive_Two_Factor::METHOD_EMAIL === $method );
				?>
				<section class="rip-2fa-challenge__panel<?php echo $is_active ? ' rip-2fa-challenge__panel--active' : ''; ?>"
					role="tabpanel" id="rip-2fa-panel-email" aria-labelledby="rip-2fa-tab-email" data-panel="email"
					data-code-sent="<?php echo $email_code_sent ? '1' : '0'; ?>" tabindex="0"
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
							data-fallback-url="<?php echo esc_url( add_query_arg( 'resend_email', '1', $challenge_action ) ); ?>">
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
						<p class="rip-2fa-challenge__resend">
							<?php esc_html_e( 'Did not receive the email?', 'reportedip-hive' ); ?>
							<button type="button"
								class="rip-2fa-challenge__resend-link"
								data-resend-method="email"
								data-fallback-url="<?php echo esc_url( add_query_arg( 'resend_email', '1', $challenge_action ) ); ?>"
								data-cooldown="<?php echo esc_attr( (string) $resend_wait ); ?>">
								<?php esc_html_e( 'Resend code', 'reportedip-hive' ); ?>
							</button>
							<span class="rip-2fa-challenge__timer" aria-hidden="true"></span>
						</p>
					</div>
				</section>
			<?php endif; ?>

			<?php
			if ( $has_sms ) :
				$is_active = ( ReportedIP_Hive_Two_Factor::METHOD_SMS === $method );
				?>
				<section class="rip-2fa-challenge__panel<?php echo $is_active ? ' rip-2fa-challenge__panel--active' : ''; ?>"
					role="tabpanel" id="rip-2fa-panel-sms" aria-labelledby="rip-2fa-tab-sms" data-panel="sms"
					data-code-sent="<?php echo $sms_code_sent ? '1' : '0'; ?>" tabindex="0"
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
								data-fallback-url="<?php echo esc_url( add_query_arg( 'resend_sms', '1', $challenge_action ) ); ?>">
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
								<?php esc_html_e( 'Did not receive the SMS?', 'reportedip-hive' ); ?>
								<button type="button"
									class="rip-2fa-challenge__resend-link"
									data-resend-method="sms"
									data-fallback-url="<?php echo esc_url( add_query_arg( 'resend_sms', '1', $challenge_action ) ); ?>">
									<?php esc_html_e( 'Resend SMS', 'reportedip-hive' ); ?>
								</button>
								<span class="rip-2fa-challenge__timer" aria-hidden="true"></span>
							</p>
						</div>
					<?php endif; ?>
				</section>
			<?php endif; ?>

			<?php if ( $has_recovery ) : ?>
				<section class="rip-2fa-challenge__panel"
					role="tabpanel" id="rip-2fa-panel-recovery" aria-labelledby="rip-2fa-tab-recovery" data-panel="recovery" tabindex="0" hidden>
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
				<a href="<?php echo esc_url( $back_url ); ?>" rel="noopener">
					<?php esc_html_e( 'Back to sign in', 'reportedip-hive' ); ?>
				</a>
			</p>
		</form>
	</div>
</main>
