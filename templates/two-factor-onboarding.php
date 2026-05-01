<?php
/**
 * Two-Factor Onboarding Template (standalone, 5-step wizard).
 *
 * Variables available (see class-two-factor-onboarding.php):
 *   - $user            WP_User object
 *   - $allowed_methods string[] globally allowed methods (totp|email|webauthn|sms)
 *   - $skips_left      float   remaining skips (INF during grace)
 *   - $grace_deadline  int     Unix timestamp, 0 if no/expired grace
 *   - $in_grace        bool    true if in grace period
 *   - $dashboard_url   string  fallback redirect URL
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.4.0
 *
 * @var \WP_User       $user            WordPress user object.
 * @var array<string>  $allowed_methods Globally allowed 2FA method keys.
 * @var float          $skips_left      Remaining skips (INF during grace period).
 * @var int            $grace_deadline  Unix timestamp; 0 if no/expired grace.
 * @var bool           $in_grace        Whether the user is in the grace period.
 * @var string         $dashboard_url   Fallback redirect URL.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound -- Template-scoped locals, not globals; the file is included from ReportedIP_Hive_Two_Factor_Onboarding with the listed $-vars already in scope. Disabled for the whole file.
$unlimited_skip     = $in_grace;
$skip_allowed       = $unlimited_skip || $skips_left > 0;
$last_skip          = ! $unlimited_skip && 1 === (int) $skips_left;
$method_totp_ok     = in_array( ReportedIP_Hive_Two_Factor::METHOD_TOTP, $allowed_methods, true );
$method_email_ok    = in_array( ReportedIP_Hive_Two_Factor::METHOD_EMAIL, $allowed_methods, true );
$method_webauthn_ok = in_array( ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN, $allowed_methods, true );
$method_sms_ok      = in_array( ReportedIP_Hive_Two_Factor::METHOD_SMS, $allowed_methods, true );

$grace_deadline_str = '';
if ( $grace_deadline > 0 ) {
	$grace_deadline_str = wp_date( get_option( 'date_format', 'd.m.Y' ), $grace_deadline );
}
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title><?php esc_html_e( 'Set Up Two-Factor Authentication', 'reportedip-hive' ); ?></title>
	<?php wp_head(); ?>
</head>
<body class="rip-wizard-page rip-2fa-onboarding">
<div class="rip-wizard">

	<header class="rip-wizard__header">
		<div class="rip-wizard__logo">
			<svg class="rip-wizard__logo-icon" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
				<path d="M20 4L6 10v10c0 9.2 6.4 17.8 14 20 7.6-2.2 14-10.8 14-20V10L20 4z" fill="currentColor" opacity="0.2"/>
				<path d="M20 4L6 10v10c0 9.2 6.4 17.8 14 20 7.6-2.2 14-10.8 14-20V10L20 4zm0 3.5L31 12v8c0 7.5-5.2 14.5-11 16.5-5.8-2-11-9-11-16.5v-8L20 7.5z" fill="currentColor"/>
				<path d="M18 24l-4-4 1.4-1.4L18 21.2l6.6-6.6L26 16l-8 8z" fill="currentColor"/>
			</svg>
			<span class="rip-wizard__logo-text"><?php esc_html_e( 'Two-Factor Authentication', 'reportedip-hive' ); ?></span>
		</div>
		<?php if ( $skip_allowed ) : ?>
			<a href="#" class="rip-wizard__skip-link" id="rip-2fa-skip"
				data-confirm="<?php echo esc_attr( $last_skip ? __( 'This is your final skip. You must set up 2FA on your next sign-in. Continue?', 'reportedip-hive' ) : __( 'Set up later?', 'reportedip-hive' ) ); ?>">
				<?php esc_html_e( 'Set up later', 'reportedip-hive' ); ?>
				<?php if ( ! $unlimited_skip ) : ?>
					<span class="rip-skip-counter" id="rip-skip-counter-label">
						<?php
						printf(
							/* translators: %d: remaining skips */
							esc_html( _n( '(%d skip remaining)', '(%d skips remaining)', (int) $skips_left, 'reportedip-hive' ) ),
							(int) $skips_left
						);
						?>
					</span>
				<?php endif; ?>
				→
			</a>
		<?php endif; ?>
	</header>

	<div class="rip-wizard__site-context">
		<span class="rip-wizard__site-name">
			<?php
			printf(
				/* translators: %s: blog name */
				wp_kses_post( __( 'for %s', 'reportedip-hive' ) ),
				'<strong>' . esc_html( get_bloginfo( 'name' ) ) . '</strong>'
			);
			?>
		</span>
		<span class="rip-wizard__site-domain">
			<?php esc_html_e( 'Domain:', 'reportedip-hive' ); ?>
			<code><?php echo esc_html( (string) wp_parse_url( home_url(), PHP_URL_HOST ) ); ?></code>
		</span>
	</div>

	<div class="rip-wizard__content">

		<?php if ( $unlimited_skip && $grace_deadline_str ) : ?>
			<div class="rip-alert rip-alert--info" role="status" style="margin-bottom: var(--rip-space-6);">
				<strong><?php esc_html_e( 'Grace period active.', 'reportedip-hive' ); ?></strong>
				<?php
				printf(
					/* translators: %s: grace period end date */
					esc_html__( 'You can skip unlimited times until %s. After that you must set up 2FA.', 'reportedip-hive' ),
					'<strong>' . esc_html( $grace_deadline_str ) . '</strong>'
				);
				?>
			</div>
		<?php elseif ( $last_skip ) : ?>
			<div class="rip-alert rip-alert--warning" role="alert" style="margin-bottom: var(--rip-space-6);">
				<strong><?php esc_html_e( 'Final skip.', 'reportedip-hive' ); ?></strong>
				<?php esc_html_e( 'You must set up 2FA on your next sign-in, otherwise login will be blocked.', 'reportedip-hive' ); ?>
			</div>
		<?php endif; ?>

		<!-- Step indicator -->
		<div class="rip-wizard__steps" role="list">
			<?php
			$steps = array(
				1 => __( 'Welcome', 'reportedip-hive' ),
				2 => __( 'Method', 'reportedip-hive' ),
				3 => __( 'Setup', 'reportedip-hive' ),
				4 => __( 'Recovery', 'reportedip-hive' ),
				5 => __( 'Done', 'reportedip-hive' ),
			);
			foreach ( $steps as $num => $label ) :
				?>
				<div class="rip-wizard__step <?php echo 1 === $num ? 'rip-wizard__step--active' : ''; ?>" data-step="<?php echo esc_attr( (string) $num ); ?>" role="listitem">
					<div class="rip-wizard__step-number"><?php echo esc_html( (string) $num ); ?></div>
					<span class="rip-wizard__step-label"><?php echo esc_html( $label ); ?></span>
				</div>
				<?php if ( $num < 5 ) : ?>
					<div class="rip-wizard__step-connector"></div>
				<?php endif; ?>
			<?php endforeach; ?>
		</div>

		<!-- ==================== STEP 1 – Welcome ==================== -->
		<section class="rip-wizard__step-content rip-2fa-step" data-step="1" aria-labelledby="rip-2fa-step1-title">
			<h1 id="rip-2fa-step1-title" class="rip-wizard__title">
				<?php
				printf(
					/* translators: %s: blog name */
					esc_html__( 'Welcome to Two-Factor Authentication for %s', 'reportedip-hive' ),
					esc_html( get_bloginfo( 'name' ) )
				);
				?>
			</h1>
			<p class="rip-wizard__subtitle">
				<?php esc_html_e( 'Let\'s make your WordPress account even more secure — in just 2 minutes.', 'reportedip-hive' ); ?>
			</p>

			<div class="rip-wizard__welcome">
				<div class="rip-wizard__features">
					<div class="rip-wizard__feature">
						<div class="rip-wizard__feature-icon" aria-hidden="true">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
						</div>
						<div class="rip-wizard__feature-text">
							<h3><?php esc_html_e( 'What is 2FA?', 'reportedip-hive' ); ?></h3>
							<p><?php esc_html_e( 'In addition to your password, you confirm who you are with a second factor — for example a code on your smartphone. Even if someone knows your password, they can\'t get into your account without that second factor.', 'reportedip-hive' ); ?></p>
						</div>
					</div>

					<div class="rip-wizard__feature">
						<div class="rip-wizard__feature-icon" aria-hidden="true">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
						</div>
						<div class="rip-wizard__feature-text">
							<h3><?php esc_html_e( 'How long does it take?', 'reportedip-hive' ); ?></h3>
							<p><?php esc_html_e( 'About 2 minutes. You can resume this process anytime if you get interrupted.', 'reportedip-hive' ); ?></p>
						</div>
					</div>

					<div class="rip-wizard__feature">
						<div class="rip-wizard__feature-icon" aria-hidden="true">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18"/></svg>
						</div>
						<div class="rip-wizard__feature-text">
							<h3><?php esc_html_e( 'What do you need?', 'reportedip-hive' ); ?></h3>
							<p><?php esc_html_e( 'Depending on the method you choose: a smartphone with an authenticator app, a passkey-capable browser (Face ID / Windows Hello / Touch ID), or just access to your email inbox.', 'reportedip-hive' ); ?></p>
						</div>
					</div>

					<div class="rip-wizard__feature">
						<div class="rip-wizard__feature-icon" aria-hidden="true">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
						</div>
						<div class="rip-wizard__feature-text">
							<h3><?php esc_html_e( 'Why am I seeing this now?', 'reportedip-hive' ); ?></h3>
							<p><?php esc_html_e( 'Your administrator has made 2FA mandatory for your role. You can enable multiple methods at the same time so you won\'t be locked out if you lose a device.', 'reportedip-hive' ); ?></p>
						</div>
					</div>
				</div>
			</div>

			<div class="rip-wizard__actions">
				<button type="button" class="rip-button rip-button--primary rip-button--lg" data-goto-step="2">
					<?php esc_html_e( 'Let\'s start', 'reportedip-hive' ); ?>
				</button>
			</div>
		</section>

		<!-- ==================== STEP 2 – Choose Method ==================== -->
		<section class="rip-wizard__step-content rip-2fa-step" data-step="2" hidden aria-labelledby="rip-2fa-step2-title">
			<h1 id="rip-2fa-step2-title" class="rip-wizard__title"><?php esc_html_e( 'Choose your method', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle">
				<?php esc_html_e( 'Which second factor would you like to use when you sign in?', 'reportedip-hive' ); ?>
			</p>

			<div class="rip-wizard__mode-cards rip-2fa-methods" data-hint="<?php esc_attr_e( 'Multi-select — click one or more cards', 'reportedip-hive' ); ?>">
				<?php if ( $method_webauthn_ok ) : ?>
					<label class="rip-mode-card rip-mode-card--recommended" data-method="webauthn">
						<input type="checkbox" class="rip-2fa-method-check" value="webauthn" hidden>
						<span class="rip-mode-card__ribbon"><?php esc_html_e( 'Recommended', 'reportedip-hive' ); ?></span>
						<div class="rip-mode-card__icon" aria-hidden="true">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
								<path d="M2 12C2 6.5 6.5 2 12 2a9.96 9.96 0 0 1 8 4"/>
								<path d="M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2"/>
								<path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/>
								<path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/>
								<path d="M8.65 22c.21-.66.45-1.32.57-2"/>
								<path d="M14 13.12c0 2.38 0 6.38-1 8.88"/>
								<path d="M2 16h.01"/>
								<path d="M21.8 16c.2-2 .131-5.354 0-6"/>
								<path d="M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.44-.025 2"/>
							</svg>
						</div>
						<h3 class="rip-mode-card__title"><?php esc_html_e( 'Passkey / biometrics', 'reportedip-hive' ); ?></h3>
						<p class="rip-mode-card__description">
							<?php esc_html_e( 'Face ID, Touch ID, Windows Hello or a hardware key. Phishing-resistant, no app needed.', 'reportedip-hive' ); ?>
						</p>
						<ul class="rip-mode-card__features">
							<li>✓ <?php esc_html_e( 'Most secure method', 'reportedip-hive' ); ?></li>
							<li>✓ <?php esc_html_e( 'Biometric, no code entry', 'reportedip-hive' ); ?></li>
							<li>✓ <?php esc_html_e( 'Phishing-resistant', 'reportedip-hive' ); ?></li>
						</ul>
					</label>
				<?php endif; ?>

				<?php if ( $method_totp_ok ) : ?>
					<label class="rip-mode-card" data-method="totp">
						<input type="checkbox" class="rip-2fa-method-check" value="totp" hidden>
						<div class="rip-mode-card__icon" aria-hidden="true">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12" y2="18"/></svg>
						</div>
						<h3 class="rip-mode-card__title"><?php esc_html_e( 'Authenticator app (TOTP)', 'reportedip-hive' ); ?></h3>
						<p class="rip-mode-card__description">
							<?php esc_html_e( 'Google Authenticator, Microsoft Authenticator, Authy, 1Password, Bitwarden. Works offline.', 'reportedip-hive' ); ?>
						</p>
						<ul class="rip-mode-card__features">
							<li>✓ <?php esc_html_e( 'Usable offline', 'reportedip-hive' ); ?></li>
							<li>✓ <?php esc_html_e( 'Very secure', 'reportedip-hive' ); ?></li>
							<li>✓ <?php esc_html_e( 'No dependency on SMS or email', 'reportedip-hive' ); ?></li>
						</ul>
					</label>
				<?php endif; ?>

				<?php if ( $method_email_ok ) : ?>
					<label class="rip-mode-card" data-method="email">
						<input type="checkbox" class="rip-2fa-method-check" value="email" hidden>
						<div class="rip-mode-card__icon" aria-hidden="true">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
						</div>
						<h3 class="rip-mode-card__title"><?php esc_html_e( 'Email code', 'reportedip-hive' ); ?></h3>
						<p class="rip-mode-card__description">
							<?php
							printf(
								/* translators: %s: masked email */
								esc_html__( 'We will send a 6-digit code to %s.', 'reportedip-hive' ),
								'<strong>' . esc_html( ReportedIP_Hive_Two_Factor::mask_email( $user->user_email ) ) . '</strong>'
							);
							?>
						</p>
						<ul class="rip-mode-card__features">
							<li>✓ <?php esc_html_e( 'No app needed', 'reportedip-hive' ); ?></li>
							<li>✓ <?php esc_html_e( 'Easy to get started', 'reportedip-hive' ); ?></li>
							<li>⚠ <?php esc_html_e( 'Only as secure as your email account', 'reportedip-hive' ); ?></li>
						</ul>
					</label>
				<?php endif; ?>

				<?php if ( $method_sms_ok ) : ?>
					<label class="rip-mode-card" data-method="sms">
						<input type="checkbox" class="rip-2fa-method-check" value="sms" hidden>
						<div class="rip-mode-card__icon" aria-hidden="true">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
						</div>
						<h3 class="rip-mode-card__title"><?php esc_html_e( 'SMS (GDPR-compliant)', 'reportedip-hive' ); ?></h3>
						<p class="rip-mode-card__description">
							<?php esc_html_e( 'Code by SMS to your mobile number. Processed only by EU providers. Less secure than the other methods (SIM-swapping risk).', 'reportedip-hive' ); ?>
						</p>
						<ul class="rip-mode-card__features">
							<li>⚠ <?php esc_html_e( 'Less secure than TOTP/passkey', 'reportedip-hive' ); ?></li>
							<li>✓ <?php esc_html_e( 'EU provider, DPA', 'reportedip-hive' ); ?></li>
						</ul>
					</label>
				<?php endif; ?>
			</div>

			<p class="rip-help-text" style="margin-top: var(--rip-space-6); text-align: center;">
				<?php esc_html_e( 'Tip: alongside your main method, pick a fallback method (e.g. passkey + email) to avoid being locked out if you lose a device.', 'reportedip-hive' ); ?>
			</p>

			<div class="rip-wizard__actions">
				<button type="button" class="rip-button rip-button--ghost" data-goto-step="1">← <?php esc_html_e( 'Back', 'reportedip-hive' ); ?></button>
				<button type="button" class="rip-button rip-button--primary rip-button--lg" id="rip-2fa-methods-continue" disabled>
					<?php esc_html_e( 'Next', 'reportedip-hive' ); ?>
				</button>
			</div>
		</section>

		<!-- ==================== STEP 3 – Setup per Method ==================== -->
		<section class="rip-wizard__step-content rip-2fa-step" data-step="3" hidden aria-labelledby="rip-2fa-step3-title">
			<h1 id="rip-2fa-step3-title" class="rip-wizard__title" data-default-title="<?php esc_attr_e( 'Set up methods', 'reportedip-hive' ); ?>" data-done-title="<?php esc_attr_e( 'All methods set up successfully!', 'reportedip-hive' ); ?>">
				<?php esc_html_e( 'Set up methods', 'reportedip-hive' ); ?>
			</h1>
			<p class="rip-wizard__subtitle" data-default-subtitle="<?php esc_attr_e( 'Follow the instructions for each selected method. After successful verification, the next method is set up.', 'reportedip-hive' ); ?>" data-done-subtitle="<?php esc_attr_e( 'Well done! In the next step you save your recovery codes.', 'reportedip-hive' ); ?>">
				<?php esc_html_e( 'Follow the instructions for each selected method. After successful verification, the next method is set up.', 'reportedip-hive' ); ?>
			</p>

			<div class="rip-2fa-setup-done" id="rip-2fa-setup-done" hidden>
				<div class="rip-2fa-setup-done__icon" aria-hidden="true">
					<svg class="rip-success-circle" viewBox="0 0 52 52"><circle cx="26" cy="26" r="25" fill="none"/><path fill="none" d="M14 27l7 7 16-16"/></svg>
				</div>
				<h2 class="rip-2fa-setup-done__title"><?php esc_html_e( 'Setup complete', 'reportedip-hive' ); ?></h2>
				<p class="rip-2fa-setup-done__methods" id="rip-2fa-setup-done-methods"></p>
				<p class="rip-2fa-setup-done__hint"><?php esc_html_e( 'Click "Next: recovery codes" to save your one-time codes.', 'reportedip-hive' ); ?></p>
			</div>

			<!-- TOTP-Setup-Panel -->
			<div class="rip-2fa-setup-panel" data-method-panel="totp" hidden>
				<h2><?php esc_html_e( 'Set up authenticator app', 'reportedip-hive' ); ?></h2>
				<ol class="rip-2fa-steps">
					<li><?php esc_html_e( 'Install an authenticator app on your smartphone if you don\'t have one yet.', 'reportedip-hive' ); ?>
						<div class="rip-2fa-apps">
							<a href="https://www.microsoft.com/security/mobile-authenticator-app" target="_blank" rel="noopener">Microsoft Authenticator</a> ·
							<a href="https://apps.apple.com/us/app/google-authenticator/id388497605" target="_blank" rel="noopener">Google Authenticator</a> ·
							<a href="https://authy.com/download/" target="_blank" rel="noopener">Authy</a> ·
							<a href="https://1password.com/downloads/" target="_blank" rel="noopener">1Password</a> ·
							<a href="https://bitwarden.com/download/" target="_blank" rel="noopener">Bitwarden</a>
						</div>
					</li>
					<li><?php esc_html_e( 'Scan the QR code with the app (or enter the secret key manually).', 'reportedip-hive' ); ?>
						<div class="rip-2fa-qr-container">
							<div id="rip-2fa-qr-canvas" class="rip-2fa-qr" aria-label="<?php esc_attr_e( 'QR code to scan', 'reportedip-hive' ); ?>"></div>
							<div class="rip-2fa-secret-box">
								<label for="rip-2fa-secret-display" class="rip-label"><?php esc_html_e( 'Or enter manually:', 'reportedip-hive' ); ?></label>
								<div class="rip-2fa-secret-row">
									<input type="text" id="rip-2fa-secret-display" class="rip-input" readonly>
									<button type="button" class="rip-button rip-button--ghost" id="rip-2fa-secret-copy"><?php esc_html_e( 'Copy', 'reportedip-hive' ); ?></button>
								</div>
							</div>
						</div>
					</li>
					<li><?php esc_html_e( 'Enter the 6-digit code from your app to finish setup.', 'reportedip-hive' ); ?>
						<div class="rip-2fa-code-confirm">
							<input type="text" id="rip-2fa-totp-verify" class="rip-input rip-2fa-code-input" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" placeholder="000000" aria-label="<?php esc_attr_e( 'TOTP code', 'reportedip-hive' ); ?>">
							<button type="button" class="rip-button rip-button--primary" id="rip-2fa-totp-confirm"><?php esc_html_e( 'Confirm', 'reportedip-hive' ); ?></button>
						</div>
						<p class="rip-2fa-inline-status" id="rip-2fa-totp-status" role="status"></p>
					</li>
				</ol>
			</div>

			<!-- E-Mail-Setup-Panel -->
			<div class="rip-2fa-setup-panel" data-method-panel="email" hidden>
				<h2><?php esc_html_e( 'Set up email code', 'reportedip-hive' ); ?></h2>
				<p>
					<?php
					printf(
						/* translators: %s: email address */
						esc_html__( 'We will send a confirmation code to %s.', 'reportedip-hive' ),
						'<strong>' . esc_html( ReportedIP_Hive_Two_Factor::mask_email( $user->user_email ) ) . '</strong>'
					);
					?>
				</p>
				<div class="rip-2fa-substep">
					<span class="rip-2fa-substep__num" aria-hidden="true">1</span>
					<div class="rip-2fa-substep__body">
						<h3 class="rip-2fa-substep__title"><?php esc_html_e( 'Send confirmation code to my email', 'reportedip-hive' ); ?></h3>
						<button type="button" class="rip-button rip-button--primary" id="rip-2fa-email-send" data-default-label="<?php esc_attr_e( 'Send confirmation code to my email', 'reportedip-hive' ); ?>"><?php esc_html_e( 'Send confirmation code to my email', 'reportedip-hive' ); ?></button>
						<p class="rip-2fa-inline-status" id="rip-2fa-email-send-status" role="status"></p>
					</div>
				</div>
				<div class="rip-2fa-substep">
					<span class="rip-2fa-substep__num" aria-hidden="true">2</span>
					<div class="rip-2fa-substep__body">
						<h3 class="rip-2fa-substep__title"><?php esc_html_e( 'Enter the 6-digit code from the email', 'reportedip-hive' ); ?></h3>
						<div class="rip-2fa-code-confirm">
							<input type="text" id="rip-2fa-email-verify" class="rip-input rip-2fa-code-input" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" placeholder="000000" aria-label="<?php esc_attr_e( 'Email code', 'reportedip-hive' ); ?>">
							<button type="button" class="rip-button rip-button--primary" id="rip-2fa-email-confirm"><?php esc_html_e( 'Confirm', 'reportedip-hive' ); ?></button>
						</div>
						<p class="rip-2fa-inline-status" id="rip-2fa-email-verify-status" role="status"></p>
					</div>
				</div>
				<p class="rip-help-text">
					<?php esc_html_e( 'Security note: email-based 2FA is only as secure as your email account. Protect it with 2FA as well if possible.', 'reportedip-hive' ); ?>
				</p>
			</div>

			<!-- Passkey-Setup-Panel -->
			<div class="rip-2fa-setup-panel" data-method-panel="webauthn" hidden>
				<h2><?php esc_html_e( 'Set up passkey', 'reportedip-hive' ); ?></h2>
				<p>
					<?php esc_html_e( 'Use Face ID, Touch ID, Windows Hello or a hardware key (e.g. YubiKey). A passkey stays on your device — we do not store any biometric data.', 'reportedip-hive' ); ?>
				</p>
				<div class="rip-2fa-webauthn-status" id="rip-2fa-webauthn-status" role="status"></div>
				<button type="button" class="rip-button rip-button--primary rip-button--lg" id="rip-2fa-webauthn-register">
					<?php esc_html_e( 'Create passkey with this device', 'reportedip-hive' ); ?>
				</button>
				<p class="rip-help-text">
					<?php esc_html_e( 'Note: if your browser doesn\'t support passkeys, please pick another method (go back).', 'reportedip-hive' ); ?>
				</p>
			</div>

			<!-- SMS-Setup-Panel -->
			<div class="rip-2fa-setup-panel" data-method-panel="sms" hidden>
				<h2><?php esc_html_e( 'Set up SMS', 'reportedip-hive' ); ?></h2>

				<div class="rip-privacy-notice" role="note">
					<svg class="rip-privacy-notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
						<rect x="3" y="11" width="18" height="11" rx="2"/>
						<path d="M7 11V7a5 5 0 0110 0v4"/>
					</svg>
					<div>
						<strong><?php esc_html_e( 'Privacy notice', 'reportedip-hive' ); ?></strong>
						<p><?php esc_html_e( 'Your phone number is stored encrypted and only shared with our EU SMS provider for delivery. SIM-swapping can compromise SMS 2FA — prefer passkey or TOTP as your main method.', 'reportedip-hive' ); ?></p>
					</div>
				</div>

				<div class="rip-2fa-substep">
					<span class="rip-2fa-substep__num" aria-hidden="true">1</span>
					<div class="rip-2fa-substep__body">
						<h3 class="rip-2fa-substep__title"><?php esc_html_e( 'Enter your mobile number', 'reportedip-hive' ); ?></h3>

						<div class="rip-form-group">
							<label for="rip-2fa-sms-number" class="rip-label"><?php esc_html_e( 'Mobile number (international, e.g. +49 151 12345678)', 'reportedip-hive' ); ?></label>
							<div class="rip-input-wrap">
								<input type="tel" id="rip-2fa-sms-number" class="rip-input" autocomplete="tel" placeholder="+49 151 12345678" aria-describedby="rip-2fa-sms-number-hint" inputmode="tel">
								<span class="rip-input-validity" aria-hidden="true"></span>
							</div>
							<p id="rip-2fa-sms-number-hint" class="rip-help-text">
								<?php esc_html_e( 'Country code is mandatory — for example +49 151 12345678. Numbers starting with 0 (like 0176…) are not accepted.', 'reportedip-hive' ); ?>
							</p>
						</div>

						<label class="rip-checkbox">
							<input type="checkbox" id="rip-2fa-sms-consent">
							<?php esc_html_e( 'I consent to processing of my phone number by the configured EU SMS provider for authentication.', 'reportedip-hive' ); ?>
						</label>

						<button type="button" class="rip-button rip-button--primary" id="rip-2fa-sms-send" disabled data-default-label="<?php esc_attr_e( 'Send confirmation code by SMS', 'reportedip-hive' ); ?>">
							<?php esc_html_e( 'Send confirmation code by SMS', 'reportedip-hive' ); ?>
						</button>
						<p class="rip-2fa-inline-status" id="rip-2fa-sms-send-status" role="status"></p>
						<p class="rip-2fa-challenge__timer" id="rip-2fa-sms-delivery-timer" role="status" hidden></p>
					</div>
				</div>

				<div class="rip-2fa-substep">
					<span class="rip-2fa-substep__num" aria-hidden="true">2</span>
					<div class="rip-2fa-substep__body">
						<h3 class="rip-2fa-substep__title"><?php esc_html_e( 'Enter the 6-digit code from the SMS', 'reportedip-hive' ); ?></h3>
						<div class="rip-2fa-code-confirm">
							<input type="text" id="rip-2fa-sms-verify" class="rip-input rip-2fa-code-input" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="one-time-code" placeholder="000000" aria-label="<?php esc_attr_e( 'SMS code', 'reportedip-hive' ); ?>">
							<button type="button" class="rip-button rip-button--primary" id="rip-2fa-sms-confirm"><?php esc_html_e( 'Confirm', 'reportedip-hive' ); ?></button>
						</div>
						<p class="rip-2fa-inline-status" id="rip-2fa-sms-status" role="status"></p>
					</div>
				</div>
			</div>

			<div class="rip-wizard__actions">
				<button type="button" class="rip-button rip-button--ghost" data-goto-step="2">← <?php esc_html_e( 'Back', 'reportedip-hive' ); ?></button>
				<button type="button" class="rip-button rip-button--primary rip-button--lg" id="rip-2fa-setup-continue" disabled>
					<?php esc_html_e( 'Next: recovery codes', 'reportedip-hive' ); ?>
				</button>
			</div>
		</section>

		<!-- ==================== STEP 4 – Recovery Codes ==================== -->
		<section class="rip-wizard__step-content rip-2fa-step" data-step="4" hidden aria-labelledby="rip-2fa-step4-title">
			<h1 id="rip-2fa-step4-title" class="rip-wizard__title"><?php esc_html_e( 'Save recovery codes', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle">
				<?php esc_html_e( 'If you lose your device or can\'t access your chosen methods, you can sign in with one of these one-time codes.', 'reportedip-hive' ); ?>
			</p>

			<div class="rip-privacy-notice rip-privacy-notice--warning" role="note">
				<svg class="rip-privacy-notice__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
					<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
					<line x1="12" y1="9" x2="12" y2="13"/>
					<line x1="12" y1="17" x2="12.01" y2="17"/>
				</svg>
				<div>
					<strong><?php esc_html_e( 'Important — these codes are your fallback.', 'reportedip-hive' ); ?></strong>
					<p><?php esc_html_e( 'Each code can be used only once. Store them safely — password manager, safe, or printed. Do NOT store them in the same password manager as your WordPress password.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-2fa-recovery-grid" id="rip-2fa-recovery-codes" aria-label="<?php esc_attr_e( 'Recovery codes', 'reportedip-hive' ); ?>">
				<!-- populated via JS -->
			</div>

			<div class="rip-wizard__actions rip-2fa-recovery-actions">
				<button type="button" class="rip-button rip-button--secondary" id="rip-2fa-recovery-copy">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
					<?php esc_html_e( 'Copy', 'reportedip-hive' ); ?>
				</button>
				<button type="button" class="rip-button rip-button--secondary" id="rip-2fa-recovery-download">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
					<?php esc_html_e( 'Download as .txt', 'reportedip-hive' ); ?>
				</button>
				<button type="button" class="rip-button rip-button--secondary" id="rip-2fa-recovery-print">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16" aria-hidden="true"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
					<?php esc_html_e( 'Print', 'reportedip-hive' ); ?>
				</button>
			</div>

			<div class="rip-2fa-recovery-ack">
				<label class="rip-checkbox">
					<input type="checkbox" id="rip-2fa-recovery-acknowledged">
					<?php esc_html_e( 'I have stored my recovery codes safely.', 'reportedip-hive' ); ?>
				</label>
				<button type="button" class="rip-button rip-button--primary rip-button--lg" id="rip-2fa-recovery-continue" disabled>
					<?php esc_html_e( 'Finish', 'reportedip-hive' ); ?>
				</button>
			</div>

			<div class="rip-wizard__actions rip-wizard__actions--secondary">
				<button type="button" class="rip-button rip-button--ghost" data-goto-step="3">← <?php esc_html_e( 'Back', 'reportedip-hive' ); ?></button>
			</div>
		</section>

		<!-- ==================== STEP 5 – Done ==================== -->
		<section class="rip-wizard__step-content rip-2fa-step" data-step="5" hidden aria-labelledby="rip-2fa-step5-title">
			<div class="rip-wizard__complete rip-2fa-celebrate">
				<div class="rip-2fa-confetti" aria-hidden="true">
					<span></span><span></span><span></span><span></span><span></span>
					<span></span><span></span><span></span><span></span><span></span>
					<span></span><span></span>
				</div>

				<div class="rip-2fa-celebrate__badge" aria-hidden="true">
					<svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
						<circle cx="40" cy="40" r="38" fill="url(#rip-celebrate-grad)" opacity="0.12"/>
						<path d="M40 10L16 20v16c0 14 10 26 24 30 14-4 24-16 24-30V20L40 10z" fill="url(#rip-celebrate-grad)"/>
						<path d="M32 42l5 5 12-14" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
						<defs>
							<linearGradient id="rip-celebrate-grad" x1="0" y1="0" x2="80" y2="80" gradientUnits="userSpaceOnUse">
								<stop offset="0" stop-color="#4F46E5"/>
								<stop offset="1" stop-color="#10B981"/>
							</linearGradient>
						</defs>
					</svg>
				</div>

				<h1 id="rip-2fa-step5-title" class="rip-wizard__title"><?php esc_html_e( 'Done — your account is now doubly secure!', 'reportedip-hive' ); ?></h1>
				<p class="rip-wizard__subtitle">
					<?php esc_html_e( 'From now on you\'ll need your second factor in addition to your password on sign-in. Thanks for taking the time!', 'reportedip-hive' ); ?>
				</p>

				<div class="rip-2fa-celebrate__stats">
					<div class="rip-2fa-celebrate__stat">
						<div class="rip-2fa-celebrate__stat-value" id="rip-2fa-summary-methods">—</div>
						<div class="rip-2fa-celebrate__stat-label"><?php esc_html_e( 'Enabled methods', 'reportedip-hive' ); ?></div>
					</div>
					<div class="rip-2fa-celebrate__stat">
						<div class="rip-2fa-celebrate__stat-value" id="rip-2fa-summary-recovery">—</div>
						<div class="rip-2fa-celebrate__stat-label"><?php esc_html_e( 'Recovery codes', 'reportedip-hive' ); ?></div>
					</div>
					<div class="rip-2fa-celebrate__stat">
						<div class="rip-2fa-celebrate__stat-value">∞</div>
						<div class="rip-2fa-celebrate__stat-label"><?php esc_html_e( 'fewer sleepless nights', 'reportedip-hive' ); ?></div>
					</div>
				</div>

				<div class="rip-2fa-celebrate__tips">
					<h3><?php esc_html_e( 'What else to know', 'reportedip-hive' ); ?></h3>
					<ul>
						<li>
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
							<?php esc_html_e( 'You will be asked for your second factor on your next sign-in.', 'reportedip-hive' ); ?>
						</li>
						<li>
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
							<?php esc_html_e( 'You can remember trusted devices so you don\'t need to enter a code on every sign-in.', 'reportedip-hive' ); ?>
						</li>
						<li>
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
							<?php esc_html_e( 'Under Profile → Security you can add or remove methods any time.', 'reportedip-hive' ); ?>
						</li>
					</ul>
				</div>

				<div class="rip-wizard__actions">
					<a href="<?php echo esc_url( $dashboard_url ); ?>" class="rip-button rip-button--primary rip-button--lg">
						<?php esc_html_e( 'Go to dashboard', 'reportedip-hive' ); ?> →
					</a>
				</div>

				<p class="rip-2fa-celebrate__attribution">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
					<?php
					printf(
						/* translators: 1: opening link tag, 2: closing link tag */
						esc_html__( 'This page is protected by %1$sReportedIP%2$s — Open Threat Intelligence for a Safer Internet.', 'reportedip-hive' ),
						'<a href="https://reportedip.de/" target="_blank" rel="noopener">',
						'</a>'
					);
					?>
				</p>
			</div>
		</section>

	</div><!-- /.rip-wizard__content -->

	<footer class="rip-wizard__footer">
		<div class="rip-wizard__footer-badges">
			<span class="rip-wizard__badge">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
				<?php esc_html_e( 'Security Focused', 'reportedip-hive' ); ?>
			</span>
			<span class="rip-wizard__badge">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
				<?php esc_html_e( 'GDPR Compliant', 'reportedip-hive' ); ?>
			</span>
			<span class="rip-wizard__badge">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
				<?php esc_html_e( 'Made in Germany', 'reportedip-hive' ); ?>
			</span>
		</div>
		<div class="rip-wizard__version"><?php echo esc_html( 'v' . REPORTEDIP_HIVE_VERSION ); ?></div>
	</footer>

</div><!-- /.rip-wizard -->

<?php wp_footer(); ?>
</body>
</html>
