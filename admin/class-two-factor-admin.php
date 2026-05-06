<?php
/**
 * Two-Factor Admin Class for ReportedIP Hive.
 *
 * Handles admin settings UI, per-user 2FA profile section,
 * and AJAX endpoints for 2FA setup/management.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.3.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Two_Factor_Admin
 *
 * Admin interface for Two-Factor Authentication configuration.
 */
class ReportedIP_Hive_Two_Factor_Admin {

	/**
	 * Constructor — registers admin hooks.
	 */
	public function __construct() {
		add_action( 'show_user_profile', array( $this, 'render_user_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_user_profile_section' ) );

		add_action( 'wp_ajax_reportedip_hive_2fa_setup_totp', array( $this, 'ajax_setup_totp' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_confirm_totp', array( $this, 'ajax_confirm_totp' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_setup_email', array( $this, 'ajax_setup_email' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_setup_sms', array( $this, 'ajax_setup_sms' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_disable', array( $this, 'ajax_disable' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_disable_method', array( $this, 'ajax_disable_method' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_test_sms', array( $this, 'ajax_admin_test_sms' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_regenerate_recovery', array( $this, 'ajax_regenerate_recovery' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_revoke_device', array( $this, 'ajax_revoke_device' ) );
		add_action( 'wp_ajax_reportedip_hive_2fa_revoke_all_devices', array( $this, 'ajax_revoke_all_devices' ) );

		add_filter( 'wp_privacy_personal_data_exporters', array( $this, 'register_data_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( $this, 'register_data_eraser' ) );

		add_filter( 'user_row_actions', array( $this, 'add_reset_row_action' ), 10, 2 );
		add_action( 'admin_post_reportedip_hive_2fa_admin_reset', array( $this, 'handle_admin_reset' ) );
		add_action( 'admin_notices', array( $this, 'show_admin_reset_notice' ) );
	}

	/**
	 * Add a "Reset 2FA" row action on the Users screen.
	 *
	 * @param array   $actions Existing actions.
	 * @param WP_User $user    Row user.
	 * @return array
	 */
	public function add_reset_row_action( $actions, $user ) {
		if ( ! ReportedIP_Hive_Two_Factor::is_globally_enabled() ) {
			return $actions;
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return $actions;
		}
		if ( ! ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID ) ) {
			return $actions;
		}

		$nonce   = wp_create_nonce( 'reportedip_hive_2fa_admin_reset_' . (int) $user->ID );
		$confirm = esc_attr__( 'Really reset 2FA for this user? The user will be able to sign in without 2FA and will be sent back to onboarding on the next login (if their role requires 2FA).', 'reportedip-hive' );

		$actions['reportedip_reset_2fa'] = sprintf(
			'<a href="#" class="rip-2fa-admin-reset" data-user="%d" data-nonce="%s" data-confirm="%s" style="color:#b32d2e;">%s</a>',
			(int) $user->ID,
			esc_attr( $nonce ),
			$confirm,
			esc_html__( 'Reset 2FA', 'reportedip-hive' )
		);

		if ( ! did_action( 'admin_print_footer_scripts' ) ) {
			add_action( 'admin_print_footer_scripts', array( __CLASS__, 'print_reset_row_action_script' ) );
		}

		return $actions;
	}

	/**
	 * Tiny footer script that converts the reset link into a POST to
	 * admin-post.php on click. Keeps the destructive action off the GET surface
	 * while still working inside WP's row-actions HTML model.
	 */
	public static function print_reset_row_action_script() {
		?>
		<script>
		(function(){
			document.addEventListener('click', function(e){
				var a = e.target.closest('.rip-2fa-admin-reset');
				if (!a) return;
				e.preventDefault();
				if (!window.confirm(a.getAttribute('data-confirm'))) return;
				var f = document.createElement('form');
				f.method = 'post';
				f.action = <?php echo wp_json_encode( admin_url( 'admin-post.php' ) ); ?>;
				f.style.display = 'none';
				['action:reportedip_hive_2fa_admin_reset','user_id:'+a.getAttribute('data-user'),'_wpnonce:'+a.getAttribute('data-nonce')].forEach(function(p){
					var i = document.createElement('input'); var kv = p.split(':'); i.type='hidden'; i.name=kv[0]; i.value=kv.slice(1).join(':'); f.appendChild(i);
				});
				document.body.appendChild(f); f.submit();
			});
		})();
		</script>
		<?php
	}

	/**
	 * admin-post handler for the reset row action.
	 */
	public function handle_admin_reset() {
		$user_id = isset( $_POST['user_id'] ) ? absint( wp_unslash( $_POST['user_id'] ) ) : 0;
		if ( ! $user_id ) {
			wp_die( esc_html__( 'Invalid user ID.', 'reportedip-hive' ) );
		}
		check_admin_referer( 'reportedip_hive_2fa_admin_reset_' . $user_id );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission.', 'reportedip-hive' ) );
		}

		$target = get_userdata( $user_id );
		if ( ! $target ) {
			wp_die( esc_html__( 'User not found.', 'reportedip-hive' ) );
		}

		ReportedIP_Hive_Two_Factor::disable_for_user( $user_id );

		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->warning(
			'2FA admin-reset performed',
			ReportedIP_Hive::get_client_ip(),
			array(
				'admin_id'       => get_current_user_id(),
				'target_user_id' => $user_id,
			)
		);

		$site_name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$timestamp = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );

		ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => $target->user_email,
				'subject'         => sprintf(
					/* translators: %s: site name */
					__( '[%s] Your two-factor authentication was reset', 'reportedip-hive' ),
					$site_name
				),
				'greeting'        => sprintf(
					/* translators: %s: user display name */
					__( 'Hello %s,', 'reportedip-hive' ),
					$target->display_name
				),
				'intro_text'      => __( 'An administrator has reset two-factor authentication on your account. You can sign in without 2FA for now.', 'reportedip-hive' ),
				'main_block_html' => '<p style="margin:0 0 24px;font-size:14px;color:#374151;line-height:1.6;">'
					. esc_html__( 'When you are ready, please set up 2FA again to keep your account protected. It only takes a couple of minutes.', 'reportedip-hive' )
					. '</p>',
				'main_block_text' => __( 'When you are ready, please set up 2FA again to keep your account protected. It only takes a couple of minutes.', 'reportedip-hive' ),
				'cta'             => array(
					'label' => __( 'Set up 2FA again', 'reportedip-hive' ),
					'url'   => admin_url( 'profile.php' ),
				),
				'security_notice' => array(
					'ip'        => ReportedIP_Hive::get_client_ip(),
					'timestamp' => $timestamp,
				),
				'disclaimer'      => __( 'If you did not request this reset, please reach out to your administrator.', 'reportedip-hive' ),
				'context'         => array(
					'type'    => '2fa_admin_reset',
					'user_id' => $user_id,
				),
			)
		);

		wp_safe_redirect( add_query_arg( 'reportedip_2fa_reset', (int) $user_id, admin_url( 'users.php' ) ) );
		exit;
	}

	/**
	 * Show a success notice after an admin reset.
	 */
	public function show_admin_reset_notice() {
		if ( ! isset( $_GET['reportedip_2fa_reset'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}
		$user_id = absint( $_GET['reportedip_2fa_reset'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$user    = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		printf(
			'<div class="notice notice-success is-dismissible"><p>%s</p></div>',
			esc_html(
				sprintf(
					/* translators: %s: user display name */
					__( '2FA for %s has been reset. The user has been notified by email.', 'reportedip-hive' ),
					$user->display_name
				)
			)
		);
	}

	/**
	 * Render the global 2FA settings tab content.
	 *
	 * Called from class-admin-settings.php when the 'two_factor' tab is active.
	 */
	public static function render_global_settings() {
		$enabled         = get_option( 'reportedip_hive_2fa_enabled_global', false );
		$allowed_methods = json_decode( get_option( 'reportedip_hive_2fa_allowed_methods', '["totp","email"]' ), true );
		$enforce_roles   = json_decode( get_option( 'reportedip_hive_2fa_enforce_roles', '[]' ), true );
		$grace_days      = get_option( 'reportedip_hive_2fa_enforce_grace_days', 7 );
		$trust_enabled   = get_option( 'reportedip_hive_2fa_trusted_devices', true );
		$trust_days      = get_option( 'reportedip_hive_2fa_trusted_device_days', 30 );

		if ( ! is_array( $allowed_methods ) ) {
			$allowed_methods = array( ReportedIP_Hive_Two_Factor::METHOD_TOTP, ReportedIP_Hive_Two_Factor::METHOD_EMAIL );
		}
		if ( ! is_array( $enforce_roles ) ) {
			$enforce_roles = array();
		}

		$crypto_available = ReportedIP_Hive_Two_Factor_Crypto::is_available();
		$crypto_method    = ReportedIP_Hive_Two_Factor_Crypto::get_active_method();
		?>
		<form method="post" action="options.php">
			<?php settings_fields( 'reportedip_hive_2fa_settings' ); ?>

			<?php
			/*
				Hidden fallbacks: WordPress' options.php only invokes the
				sanitize callback for fields present in $_POST. For boolean
				checkboxes this means an unchecked box silently keeps the
				old value. Each hidden input below pre-fills the option name
				with "0" / "" so a subsequent checked checkbox overrides it,
				and an unchecked one leaves the explicit "off" value. The
				`reportedip_hive_2fa_allowed_methods` and
				`reportedip_hive_2fa_enforce_roles` hidden fields ensure their
				sanitize callbacks always run, even when no method/role
				checkbox is selected.
			*/
			?>
			<input type="hidden" name="reportedip_hive_2fa_enabled_global" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_allowed_methods" value="" />
			<input type="hidden" name="reportedip_hive_2fa_enforce_roles" value="" />
			<input type="hidden" name="reportedip_hive_2fa_reminder_enabled" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_reminder_hard_roles" value="" />
			<input type="hidden" name="reportedip_hive_2fa_frontend_onboarding" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_xmlrpc_app_password_only" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_trusted_devices" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_extended_remember" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_branded_login" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_sms_avv_confirmed" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_require_on_password_reset" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_password_reset_block_email_only" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_frontend_enabled" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_frontend_customer_optional" value="0" />
			<input type="hidden" name="reportedip_hive_2fa_frontend_slug" value="" />
			<input type="hidden" name="reportedip_hive_2fa_frontend_setup_slug" value="" />

			<!-- Status Banner -->
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<?php esc_html_e( 'Two-Factor Authentication', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc">
					<?php esc_html_e( 'Protect WordPress accounts with an additional verification step at sign-in.', 'reportedip-hive' ); ?>
				</p>

				<?php if ( ! $crypto_available ) : ?>
					<div class="rip-alert rip-alert--error">
						<?php esc_html_e( 'Encryption is not available. Make sure libsodium or OpenSSL is installed and AUTH_KEY is set in wp-config.php.', 'reportedip-hive' ); ?>
					</div>
				<?php else : ?>
					<div class="rip-alert rip-alert--info" style="margin-bottom: var(--rip-space-4);">
						<?php
						printf(
							/* translators: %s: encryption method name */
							esc_html__( 'Encryption active: %s', 'reportedip-hive' ),
							'<strong>' . esc_html( strtoupper( $crypto_method ) ) . '</strong>'
						);
						?>
					</div>
				<?php endif; ?>

				<!-- Master Toggle -->
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							id="rip-2fa-enabled-global"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_enabled_global"
							value="1"
							<?php checked( $enabled ); ?>
							<?php disabled( ! $crypto_available ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Enable 2FA feature', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Activates the 2FA feature. Users must set up 2FA individually in their profile. When off, all 2FA configuration below is disabled.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div id="rip-2fa-dependent-fields"<?php echo $enabled ? '' : ' class="rip-is-disabled"'; ?>>

			<!-- Methods -->
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12" y2="18"/></svg>
					<?php esc_html_e( 'Verification methods', 'reportedip-hive' ); ?>
				</h2>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_method_totp"
							value="1"
							<?php checked( in_array( ReportedIP_Hive_Two_Factor::METHOD_TOTP, $allowed_methods, true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Authenticator App (TOTP)', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Google Authenticator, Microsoft Authenticator, Authy, etc.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_method_email"
							value="1"
							<?php checked( in_array( ReportedIP_Hive_Two_Factor::METHOD_EMAIL, $allowed_methods, true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Email code', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text">
						<?php esc_html_e( 'Sends a 6-digit code to the user\'s email address.', 'reportedip-hive' ); ?>
						<?php
						$mail_relay_status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'mail_relay_via_api' );
						if ( $mail_relay_status['available'] ) {
							echo ' ';
							esc_html_e( 'Delivered via the managed reportedip.de relay (clean SPF / DKIM / DMARC).', 'reportedip-hive' );
						} else {
							echo ' ';
							esc_html_e( 'Delivered via wp_mail() on this server.', 'reportedip-hive' );
							if ( 'tier' === ( $mail_relay_status['reason'] ?? '' ) ) {
								echo ' ';
								ReportedIP_Hive_Admin_Settings::render_tier_lock(
									$mail_relay_status,
									array( 'label' => __( 'Upgrade for managed delivery', 'reportedip-hive' ) )
								);
							}
						}
						?>
					</p>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_method_webauthn"
							value="1"
							<?php checked( in_array( ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN, $allowed_methods, true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Passkey / WebAuthn / FIDO2', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Phishing-resistant sign-in via Face ID, Touch ID, Windows Hello or a hardware key (YubiKey).', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_method_sms"
							value="1"
							<?php checked( in_array( ReportedIP_Hive_Two_Factor::METHOD_SMS, $allowed_methods, true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'SMS (GDPR — EU providers only)', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text">
						<?php esc_html_e( 'Only available with a configured EU SMS provider (seven.io, sipgate, MessageBird) and a confirmed DPA. Less secure than TOTP/Passkey — recommended only as a fallback.', 'reportedip-hive' ); ?>
					</p>
				</div>
			</div>

			<!-- Enforcement -->
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
					<?php esc_html_e( 'Enforcement', 'reportedip-hive' ); ?>
				</h2>

				<div class="rip-form-group">
					<label class="rip-label"><?php esc_html_e( '2FA required for roles', 'reportedip-hive' ); ?></label>
					<?php
					$all_roles = wp_roles()->get_names();
					foreach ( $all_roles as $role_slug => $role_name ) :
						?>
						<label style="display: block; margin-bottom: 4px;">
							<input type="checkbox"
								name="reportedip_hive_2fa_enforce_roles[]"
								value="<?php echo esc_attr( $role_slug ); ?>"
								<?php checked( in_array( $role_slug, $enforce_roles, true ) ); ?> />
							<?php echo esc_html( translate_user_role( $role_name ) ); ?>
						</label>
					<?php endforeach; ?>
					<p class="rip-help-text"><?php esc_html_e( 'Users with these roles must set up 2FA, otherwise sign-in is blocked.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_2fa_grace_days"><?php esc_html_e( 'Grace period (days)', 'reportedip-hive' ); ?></label>
					<input type="number"
						id="reportedip_2fa_grace_days"
						class="rip-input"
						name="reportedip_hive_2fa_enforce_grace_days"
						value="<?php echo esc_attr( $grace_days ); ?>"
						min="0"
						max="90"
						style="width: 80px;" />
					<p class="rip-help-text"><?php esc_html_e( 'Required users see the onboarding after sign-in. During the grace period the "Later" button is unlimited. Afterwards the skip cap applies. 0 = immediate.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_2fa_max_skips"><?php esc_html_e( 'Max. skips after the grace period', 'reportedip-hive' ); ?></label>
					<input type="number"
						id="reportedip_2fa_max_skips"
						class="rip-input"
						name="reportedip_hive_2fa_max_skips"
						value="<?php echo esc_attr( (string) (int) get_option( 'reportedip_hive_2fa_max_skips', 3 ) ); ?>"
						min="0"
						max="20"
						style="width: 80px;" />
					<p class="rip-help-text"><?php esc_html_e( 'How many times required users may skip the onboarding after the grace period ends. 0 = enforced immediately.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_frontend_onboarding"
							value="1"
							<?php checked( (bool) get_option( 'reportedip_hive_2fa_frontend_onboarding', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Enforce onboarding on the frontend too', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Also redirects required users to onboarding when they land on frontend pages after sign-in (e.g. WooCommerce account).', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<?php
			$rip_wc_active           = class_exists( 'WooCommerce' );
			$rip_frontend_enabled    = (bool) get_option( ReportedIP_Hive_Two_Factor_Frontend::OPT_ENABLED, false );
			$rip_customer_optional   = (bool) get_option( 'reportedip_hive_2fa_frontend_customer_optional', true );
			$rip_frontend_status     = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'frontend_2fa' );
			$rip_frontend_locked     = ! $rip_frontend_status['available'];
			$rip_frontend_soft_off   = (int) get_option( ReportedIP_Hive_Two_Factor_Frontend::OPT_SOFT_DISABLED, 0 ) > 0;
			$rip_frontend_disabled   = $rip_frontend_locked ? ' disabled' : '';
			$rip_challenge_slug      = ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug();
			$rip_setup_slug          = ReportedIP_Hive_Two_Factor_Frontend::get_setup_slug();
			$rip_challenge_url_label = ReportedIP_Hive_Two_Factor_Frontend::challenge_url();
			$rip_setup_url_label     = ReportedIP_Hive_Two_Factor_Frontend::setup_url();
			$rip_home_prefix         = trailingslashit( home_url( '/' ) );
			?>
			<div class="rip-settings-section <?php echo $rip_frontend_locked ? 'rip-settings-section--locked' : ''; ?>" id="rip-2fa-frontend-section" data-rip-2fa-frontend>
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
					<?php esc_html_e( 'Frontend login for WooCommerce', 'reportedip-hive' ); ?>
					<?php if ( $rip_frontend_locked && 'tier' === $rip_frontend_status['reason'] ) : ?>
						&nbsp;<?php ReportedIP_Hive_Admin_Settings::render_tier_lock( $rip_frontend_status, array( 'label' => __( 'Unlock with Professional', 'reportedip-hive' ) ) ); ?>
					<?php endif; ?>
				</h2>
				<p class="rip-settings-section__desc">
					<?php esc_html_e( 'Renders the second factor inside the active storefront theme when customers sign in via My Account, classic checkout or the WooCommerce blocks — instead of bouncing them to wp-login.php.', 'reportedip-hive' ); ?>
				</p>

				<?php if ( $rip_frontend_locked && 'tier' === $rip_frontend_status['reason'] ) : ?>
					<div class="rip-alert rip-alert--info rip-2fa-frontend-pro-card">
						<p style="margin:0 0 var(--rip-space-2);font-weight:600;">
							<?php esc_html_e( 'Available with the Professional plan and higher', 'reportedip-hive' ); ?>
						</p>
						<ul style="margin:0 0 var(--rip-space-3);padding-left:1.25em;">
							<li><?php esc_html_e( 'Themed challenge page on the My Account / Checkout slug', 'reportedip-hive' ); ?></li>
							<li><?php esc_html_e( 'Themed onboarding wizard for Customer / Subscriber roles', 'reportedip-hive' ); ?></li>
							<li><?php esc_html_e( 'Cart and checkout state survive the redirect roundtrip', 'reportedip-hive' ); ?></li>
							<li><?php esc_html_e( 'WC Blocks Cart / Checkout error redirect listener', 'reportedip-hive' ); ?></li>
							<li><?php esc_html_e( 'Trusted-device cookie shared with the wp-login flow', 'reportedip-hive' ); ?></li>
							<li><?php esc_html_e( 'Hide-Login bypass + cache-plugin-safe headers', 'reportedip-hive' ); ?></li>
						</ul>
						<p style="margin:0;">
							<a class="rip-button rip-button--primary" href="<?php echo esc_url( defined( 'REPORTEDIP_UPGRADE_URL' ) ? REPORTEDIP_UPGRADE_URL : 'https://reportedip.de/pricing/' ); ?>" target="_blank" rel="noopener noreferrer">
								<?php esc_html_e( 'Compare plans', 'reportedip-hive' ); ?>
							</a>
						</p>
					</div>
				<?php endif; ?>

				<?php if ( ! $rip_wc_active ) : ?>
					<div class="rip-alert rip-alert--info">
						<?php esc_html_e( 'WooCommerce is not active on this site. Activate WooCommerce to use frontend login 2FA.', 'reportedip-hive' ); ?>
					</div>
				<?php elseif ( $rip_frontend_soft_off ) : ?>
					<div class="rip-alert rip-alert--warning">
						<?php esc_html_e( 'Frontend 2FA is paused because the current ReportedIP plan no longer includes it. Existing customer secrets stay valid; new onboardings are blocked until the plan is restored.', 'reportedip-hive' ); ?>
					</div>
				<?php endif; ?>

				<?php
				$rip_2fa_conflicts = ReportedIP_Hive_Two_Factor_Frontend::detect_conflicts();
				if ( ! empty( $rip_2fa_conflicts ) ) :
					?>
					<div class="rip-alert rip-alert--warning rip-2fa-conflicts">
						<p style="margin:0 0 var(--rip-space-2);font-weight:600;">
							<?php esc_html_e( 'Other 2FA / login plugins detected', 'reportedip-hive' ); ?>
						</p>
						<ul style="margin:0;padding-left:1.25em;">
							<?php foreach ( $rip_2fa_conflicts as $rip_conflict ) : ?>
								<li>
									<strong><?php echo esc_html( $rip_conflict['label'] ); ?></strong>
									— <?php echo esc_html( $rip_conflict['message'] ); ?>
								</li>
							<?php endforeach; ?>
						</ul>
					</div>
				<?php endif; ?>

				<fieldset class="rip-fieldset" <?php echo $rip_frontend_locked ? 'disabled' : ''; ?>>
					<legend class="screen-reader-text"><?php esc_html_e( 'Frontend 2FA configuration', 'reportedip-hive' ); ?></legend>

					<div class="rip-form-group">
						<label class="rip-toggle">
							<input type="checkbox"
								class="rip-toggle__input"
								name="reportedip_hive_2fa_frontend_enabled"
								value="1"
								<?php checked( $rip_frontend_enabled ); ?> />
							<span class="rip-toggle__slider"></span>
							<span class="rip-toggle__label">
								<?php esc_html_e( 'Render the 2FA challenge inside the storefront theme', 'reportedip-hive' ); ?>
							</span>
						</label>
						<p class="rip-help-text">
							<?php esc_html_e( 'When off, WooCommerce frontend logins still get challenged — but the challenge falls back to wp-login.php.', 'reportedip-hive' ); ?>
						</p>
					</div>

					<div class="rip-form-group">
						<label class="rip-toggle">
							<input type="checkbox"
								class="rip-toggle__input"
								name="reportedip_hive_2fa_frontend_customer_optional"
								value="1"
								<?php checked( $rip_customer_optional ); ?> />
							<span class="rip-toggle__slider"></span>
							<span class="rip-toggle__label">
								<?php esc_html_e( 'Let customers opt in to 2FA from My Account', 'reportedip-hive' ); ?>
							</span>
						</label>
						<p class="rip-help-text">
							<?php esc_html_e( 'When enabled, Customer / Subscriber roles see the same self-service setup wizard as administrators. Role-based enforcement above still applies on top.', 'reportedip-hive' ); ?>
						</p>
					</div>

					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_2fa_frontend_slug"><?php esc_html_e( 'Challenge page slug', 'reportedip-hive' ); ?></label>
						<div class="rip-input-prefix">
							<span class="rip-input-prefix__prefix"><?php echo esc_html( $rip_home_prefix ); ?></span>
							<input type="text"
								id="reportedip_hive_2fa_frontend_slug"
								name="reportedip_hive_2fa_frontend_slug"
								class="rip-input"
								value="<?php echo esc_attr( $rip_challenge_slug ); ?>"
								pattern="[a-z0-9][a-z0-9-]{1,48}[a-z0-9]"
								maxlength="50"
								spellcheck="false"
								autocomplete="off" />
							<span class="rip-input-prefix__suffix">/</span>
						</div>
						<p class="rip-help-text">
							<?php
							printf(
								/* translators: %s: absolute URL of the configured challenge slug */
								esc_html__( 'Where logged-in customers land for the second factor. Current URL: %s', 'reportedip-hive' ),
								'<code>' . esc_html( $rip_challenge_url_label ) . '</code>'
							);
							?>
						</p>
					</div>

					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_2fa_frontend_setup_slug"><?php esc_html_e( 'Setup page slug (onboarding)', 'reportedip-hive' ); ?></label>
						<div class="rip-input-prefix">
							<span class="rip-input-prefix__prefix"><?php echo esc_html( $rip_home_prefix ); ?></span>
							<input type="text"
								id="reportedip_hive_2fa_frontend_setup_slug"
								name="reportedip_hive_2fa_frontend_setup_slug"
								class="rip-input"
								value="<?php echo esc_attr( $rip_setup_slug ); ?>"
								pattern="[a-z0-9][a-z0-9-]{1,48}[a-z0-9]"
								maxlength="50"
								spellcheck="false"
								autocomplete="off" />
							<span class="rip-input-prefix__suffix">/</span>
						</div>
						<p class="rip-help-text">
							<?php
							printf(
								/* translators: %s: absolute URL of the setup slug */
								esc_html__( 'Customer onboarding wizard. Current URL: %s', 'reportedip-hive' ),
								'<code>' . esc_html( $rip_setup_url_label ) . '</code>'
							);
							?>
						</p>
					</div>
				</fieldset>
			</div>

			<!-- Login reminder for users without 2FA -->
			<?php
			$reminder_enabled   = (bool) get_option( ReportedIP_Hive_Two_Factor_Recommend::OPT_ENABLED, true );
			$reminder_threshold = (int) get_option( ReportedIP_Hive_Two_Factor_Recommend::OPT_HARD_THRESHOLD, ReportedIP_Hive_Two_Factor_Recommend::DEFAULT_THRESHOLD );
			$reminder_hard_raw  = get_option( ReportedIP_Hive_Two_Factor_Recommend::OPT_HARD_ROLES, ReportedIP_Hive_Two_Factor_Recommend::DEFAULT_HARD_ROLES );
			if ( is_string( $reminder_hard_raw ) ) {
				$decoded           = json_decode( $reminder_hard_raw, true );
				$reminder_hard_raw = is_array( $decoded ) ? $decoded : ReportedIP_Hive_Two_Factor_Recommend::DEFAULT_HARD_ROLES;
			}
			if ( ! is_array( $reminder_hard_raw ) ) {
				$reminder_hard_raw = ReportedIP_Hive_Two_Factor_Recommend::DEFAULT_HARD_ROLES;
			}
			?>
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
					<?php esc_html_e( 'Login reminder for users without 2FA', 'reportedip-hive' ); ?>
				</h2>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_reminder_enabled"
							value="1"
							<?php checked( $reminder_enabled ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Show a reminder banner at login until 2FA is set up', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'On every login of a user without any 2FA method, a banner appears across all admin pages. The banner is dismissable per session but reappears on the next login.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_2fa_reminder_threshold">
						<?php esc_html_e( 'Hard-block threshold', 'reportedip-hive' ); ?>
					</label>
					<input type="number"
						id="reportedip_2fa_reminder_threshold"
						class="rip-input"
						name="reportedip_hive_2fa_reminder_hard_threshold"
						value="<?php echo esc_attr( (string) $reminder_threshold ); ?>"
						min="1"
						max="10"
						style="width: 80px;" />
					<p class="rip-help-text"><?php esc_html_e( 'After this many login reminders, users in the roles selected below are forced into the 2FA onboarding wizard before they can continue. Recommended: 5.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-label"><?php esc_html_e( 'Hard-block roles', 'reportedip-hive' ); ?></label>
					<?php
					$all_roles_for_reminder = wp_roles()->get_names();
					foreach ( $all_roles_for_reminder as $role_slug => $role_name ) :
						?>
						<label style="display: block; margin-bottom: 4px;">
							<input type="checkbox"
								name="reportedip_hive_2fa_reminder_hard_roles[]"
								value="<?php echo esc_attr( $role_slug ); ?>"
								<?php checked( in_array( $role_slug, $reminder_hard_raw, true ) ); ?> />
							<?php echo esc_html( translate_user_role( $role_name ) ); ?>
						</label>
					<?php endforeach; ?>
					<p class="rip-help-text"><?php esc_html_e( 'Users in these roles get hard-blocked once the threshold is reached. All other roles only see the reminder banner — no lock-out (recommended for Customer / Subscriber / Author so a missing phone never breaks WooCommerce).', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<!-- IP Allowlist -->
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/></svg>
					<?php esc_html_e( 'IP allowlist (2FA bypass)', 'reportedip-hive' ); ?>
				</h2>
				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_2fa_ip_allowlist"><?php esc_html_e( 'Trusted IPs / CIDR ranges', 'reportedip-hive' ); ?></label>
					<textarea
						id="reportedip_2fa_ip_allowlist"
						name="reportedip_hive_2fa_ip_allowlist"
						class="rip-input"
						rows="5"
						style="width: 100%; font-family: var(--rip-font-mono); font-size: var(--rip-text-sm);"
						placeholder="# One IP or CIDR per line&#10;192.168.1.0/24&#10;203.0.113.42&#10;2001:db8::/32"><?php echo esc_textarea( (string) get_option( 'reportedip_hive_2fa_ip_allowlist', '' ) ); ?></textarea>
					<?php
					$current_ip = class_exists( 'ReportedIP_Hive' ) ? (string) ReportedIP_Hive::get_client_ip() : '';
					if ( '' !== $current_ip ) :
						?>
						<div style="margin-top: var(--rip-space-2); display: flex; align-items: center; gap: var(--rip-space-2);">
							<button type="button"
								class="rip-button rip-button--secondary rip-button--small"
								id="rip-2fa-ip-add-mine"
								data-target="reportedip_2fa_ip_allowlist"
								data-ip="<?php echo esc_attr( $current_ip ); ?>">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width: 14px; height: 14px;"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
								<?php esc_html_e( 'Add my IP', 'reportedip-hive' ); ?>
							</button>
							<span class="rip-help-text" style="margin: 0;">
								<?php
								printf(
									/* translators: %s: detected client IP address */
									esc_html__( 'Detected: %s', 'reportedip-hive' ),
									'<code>' . esc_html( $current_ip ) . '</code>'
								);
								?>
							</span>
						</div>
					<?php endif; ?>
					<p class="rip-help-text">
						<?php esc_html_e( 'Users from these IPs sign in without 2FA. Enable only on trusted networks (office VPN, corporate network), NOT on co-working spaces or open Wi-Fi. Lines starting with # are treated as comments.', 'reportedip-hive' ); ?>
					</p>
					<script>
					(function () {
						var btn = document.getElementById('rip-2fa-ip-add-mine');
						if (!btn) { return; }
						btn.addEventListener('click', function () {
							var ip = btn.getAttribute('data-ip') || '';
							var ta = document.getElementById(btn.getAttribute('data-target'));
							if (!ta || !ip) { return; }
							var lines = ta.value.split(/\r?\n/);
							for (var i = 0; i < lines.length; i++) {
								if (lines[i].trim() === ip) {
									ta.focus();
									return;
								}
							}
							var current = ta.value.replace(/\s+$/, '');
							ta.value = current + (current ? '\n' : '') + ip + '\n';
							ta.focus();
							ta.scrollTop = ta.scrollHeight;
						});
					})();
					</script>
				</div>
			</div>

			<!-- SMS provider (GDPR-compliant, EU providers) -->
			<?php self::render_sms_provider_section(); ?>

			<!-- XMLRPC protection -->
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 12V8H6a2 2 0 0 1-2-2c0-1.1.9-2 2-2h12v4"/><path d="M4 6v12c0 1.1.9 2 2 2h14v-4"/><path d="M18 12a2 2 0 0 0-2 2c0 1.1.9 2 2 2h4v-4h-4z"/></svg>
					<?php esc_html_e( 'XMLRPC protection', 'reportedip-hive' ); ?>
				</h2>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_xmlrpc_app_password_only"
							value="1"
							<?php checked( (bool) get_option( 'reportedip_hive_2fa_xmlrpc_app_password_only', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Allow XMLRPC only with application passwords', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Blocks basic auth over XMLRPC (commonly used by bot attacks) but still allows application passwords. No 2FA prompt on XMLRPC — the API client must use a separate application password.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<!-- Trusted Devices -->
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
					<?php esc_html_e( 'Trusted devices', 'reportedip-hive' ); ?>
				</h2>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_trusted_devices"
							value="1"
							<?php checked( $trust_enabled ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Enable "remember device"', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Users can skip 2FA on trusted devices.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_2fa_trust_days"><?php esc_html_e( 'Trust duration (days)', 'reportedip-hive' ); ?></label>
					<input type="number"
						id="reportedip_2fa_trust_days"
						class="rip-input"
						name="reportedip_hive_2fa_trusted_device_days"
						value="<?php echo esc_attr( $trust_days ); ?>"
						min="1"
						max="365"
						style="width: 80px;" />
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_extended_remember"
							value="1"
							<?php checked( (bool) get_option( 'reportedip_hive_2fa_extended_remember', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Extended session duration (30 days) when "Remember me" is used with verified 2FA', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Extends the auth cookie from 14 to 30 days when a user signs in with 2FA + "Remember me". Stronger authentication justifies the longer session.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_branded_login"
							value="1"
							<?php checked( (bool) get_option( 'reportedip_hive_2fa_branded_login', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Branded login screen (show the plugin logo on the 2FA challenge)', 'reportedip-hive' ); ?>
						</span>
					</label>
				</div>
			</div>

			<!-- Password reset gate -->
			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
					<?php esc_html_e( 'Password reset gate', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc">
					<?php esc_html_e( 'Require a second factor before a user can set a new password through the WordPress "lost password" flow. This closes the bypass where someone with access to a mailbox could reset the password and receive the email-based 2FA code in the same inbox.', 'reportedip-hive' ); ?>
				</p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_require_on_password_reset"
							value="1"
							<?php checked( (bool) get_option( 'reportedip_hive_2fa_require_on_password_reset', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Require 2FA verification before password reset', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Users who have any 2FA method configured must verify a non-email factor (Authenticator, SMS, security key, or recovery code) before the new password is accepted. The email channel is excluded by design — it is the channel that delivered the reset link in the first place.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox"
							class="rip-toggle__input"
							name="reportedip_hive_2fa_password_reset_block_email_only"
							value="1"
							<?php checked( (bool) get_option( 'reportedip_hive_2fa_password_reset_block_email_only', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label">
							<?php esc_html_e( 'Block resets for accounts that only have email 2FA and no recovery codes', 'reportedip-hive' ); ?>
						</span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'When the only configured factor is email and no recovery codes exist, the password reset is rejected and an alert is sent to all administrators. Unblock manually via WP-CLI: wp user reset-password &lt;id&gt; --skip-email.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			</div>

			<script>
			(function () {
				var toggle = document.getElementById('rip-2fa-enabled-global');
				var deps   = document.getElementById('rip-2fa-dependent-fields');
				if (!toggle || !deps) { return; }
				toggle.addEventListener('change', function () {
					deps.classList.toggle('rip-is-disabled', !toggle.checked);
				});
			})();
			</script>

			<?php submit_button( __( 'Save settings', 'reportedip-hive' ) ); ?>
		</form>
		<?php
	}

	/**
	 * Register 2FA settings for the WordPress Settings API.
	 *
	 * Intentionally does NOT pass a `'default'` to `register_setting()`. Core
	 * has a long-standing footgun in `update_option()`:
	 *
	 *     if ( apply_filters( "default_option_{$option}", false, $option, false ) === $old_value ) {
	 *         return add_option( $option, $value, '', $autoload );
	 *     }
	 *
	 * When the stored value happens to equal the registered default,
	 * `update_option()` reroutes to `add_option()`, which returns false (and
	 * silently does nothing) because the row already exists. The toggle on the
	 * settings page then "reverts" on reload. We supply explicit defaults at
	 * every call site (`get_option( $key, $fallback )`) instead.
	 */
	public static function register_settings() {
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_enabled_global',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_enforce_grace_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_max_skips',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( __CLASS__, 'sanitize_max_skips' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_trusted_devices',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_trusted_device_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_frontend_onboarding',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_frontend_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( __CLASS__, 'sanitize_frontend_enabled' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_frontend_customer_optional',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_frontend_slug',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( __CLASS__, 'sanitize_frontend_challenge_slug' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_frontend_setup_slug',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( __CLASS__, 'sanitize_frontend_setup_slug' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_xmlrpc_app_password_only',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_ip_allowlist',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( __CLASS__, 'sanitize_ip_allowlist' ),
			)
		);

		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_sms_provider',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( __CLASS__, 'sanitize_sms_provider' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_sms_avv_confirmed',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_sms_provider_config_raw',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( __CLASS__, 'sanitize_sms_provider_config' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_extended_remember',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_branded_login',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);

		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_allowed_methods',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( __CLASS__, 'sanitize_allowed_methods' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_enforce_roles',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( __CLASS__, 'sanitize_enforce_roles' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_reminder_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_reminder_hard_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( __CLASS__, 'sanitize_reminder_threshold' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_reminder_hard_roles',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( __CLASS__, 'sanitize_reminder_hard_roles' ),
			)
		);

		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_require_on_password_reset',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_password_reset_block_email_only',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
			)
		);
	}

	/**
	 * Clamp the reminder threshold to a sane range.
	 *
	 * @param mixed $input
	 * @return int 1..10
	 */
	public static function sanitize_reminder_threshold( $input ) {
		$value = (int) $input;
		if ( $value < 1 ) {
			$value = 1;
		}
		if ( $value > 10 ) {
			$value = 10;
		}
		return $value;
	}

	/**
	 * Sanitize the hard-block role list and persist it as a JSON array string,
	 * mirroring the storage pattern used for `reportedip_hive_2fa_enforce_roles`.
	 *
	 * @param mixed $input Either an array of role slugs (POST) or a string.
	 * @return string JSON-encoded list of sanitised role slugs.
	 */
	public static function sanitize_reminder_hard_roles( $input ) {
		if ( is_string( $input ) ) {
			$decoded = json_decode( $input, true );
			$input   = is_array( $decoded ) ? $decoded : array();
		}
		if ( ! is_array( $input ) ) {
			$input = array();
		}
		$valid = array_keys( wp_roles()->get_names() );
		$clean = array();
		foreach ( $input as $role ) {
			$role = sanitize_key( (string) $role );
			if ( '' !== $role && in_array( $role, $valid, true ) ) {
				$clean[] = $role;
			}
		}
		return wp_json_encode( array_values( array_unique( $clean ) ) );
	}

	/**
	 * Render the SMS-provider admin section (DSGVO gate, provider selector,
	 * per-provider credentials form, test-dispatch button).
	 */
	public static function render_sms_provider_section() {
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
			return;
		}
		$providers     = ReportedIP_Hive_Two_Factor_SMS::providers();
		$active_id     = (string) get_option( ReportedIP_Hive_Two_Factor_SMS::OPT_PROVIDER, '' );
		$avv_confirmed = (bool) get_option( ReportedIP_Hive_Two_Factor_SMS::OPT_AVV_CONFIRMED, false );
		$active_config = ReportedIP_Hive_Two_Factor_SMS::get_provider_config();

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$relay_status = $mode_manager->feature_status( 'sms_relay_via_api' );
		?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
				<?php esc_html_e( 'SMS provider (GDPR — EU only)', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc">
				<?php esc_html_e( 'An EU SMS provider is used to send SMS OTPs. The plugin operator must sign a DPA with the selected provider. Phone numbers are stored encrypted; the SMS body contains only the code and a minimal note (no site, no user data, no IP).', 'reportedip-hive' ); ?>
			</p>

			<?php if ( $relay_status['available'] ) : ?>
				<div class="rip-alert rip-alert--success">
					<strong><?php esc_html_e( 'Managed SMS relay active', 'reportedip-hive' ); ?>:</strong>
					<?php esc_html_e( 'SMS-2FA flows through reportedip.de — included with your plan, no third-party SMS contract needed.', 'reportedip-hive' ); ?>
					<?php
					$allowed_methods_for_hint = class_exists( 'ReportedIP_Hive_Two_Factor' )
						? ReportedIP_Hive_Two_Factor::get_allowed_methods()
						: array();
					if ( ! in_array( 'sms', $allowed_methods_for_hint, true ) ) :
						?>
						<br>
						<em><?php esc_html_e( 'Final step: enable “SMS code” in the methods list above to roll it out to your users.', 'reportedip-hive' ); ?></em>
					<?php endif; ?>
				</div>
			<?php elseif ( 'tier' === ( $relay_status['reason'] ?? '' ) ) : ?>
				<p class="rip-help-text">
					<?php esc_html_e( 'Tip: Professional and Business plans include SMS-2FA via our managed EU gateway — no separate provider contract required.', 'reportedip-hive' ); ?>
					<?php ReportedIP_Hive_Admin_Settings::render_tier_lock( $relay_status ); ?>
				</p>
			<?php endif; ?>

			<div class="rip-form-group">
				<label class="rip-label" for="reportedip_2fa_sms_provider"><?php esc_html_e( 'SMS provider', 'reportedip-hive' ); ?></label>
				<select id="reportedip_2fa_sms_provider" name="reportedip_hive_2fa_sms_provider" class="rip-select">
					<option value=""><?php esc_html_e( '— not configured —', 'reportedip-hive' ); ?></option>
					<?php
					foreach ( $providers as $pid => $class ) :
						if ( ! class_exists( $class ) ) {
							continue;
						}
						$is_relay     = ( 'reportedip_relay' === $pid );
						$relay_locked = ( $is_relay && ! $relay_status['available'] );
						?>
						<option
							value="<?php echo esc_attr( $pid ); ?>"
							<?php selected( $active_id, $pid ); ?>
							<?php disabled( $relay_locked ); ?>
						>
							<?php
							$display_name = call_user_func( array( $class, 'display_name' ) );
							$region       = call_user_func( array( $class, 'region' ) );

							if ( $is_relay ) {
								$min_tier   = $relay_status['min_tier'] ?? 'professional';
								$tier_short = $mode_manager->get_tier_info( (string) $min_tier )['short_label'];
								$suffix     = $relay_status['available']
									? __( '(managed, included)', 'reportedip-hive' )
									: sprintf(
										/* translators: %s = required tier short label, e.g. PRO */
										__( '(requires %s+)', 'reportedip-hive' ),
										$tier_short
									);
								printf( '%s — %s %s', esc_html( $display_name ), esc_html( $region ), esc_html( $suffix ) );
							} else {
								printf( '%s — %s', esc_html( $display_name ), esc_html( $region ) );
							}
							?>
						</option>
					<?php endforeach; ?>
				</select>
			</div>

			<?php
			foreach ( $providers as $pid => $class ) :
				if ( ! class_exists( $class ) ) {
					continue;
				}
				$is_active = ( $pid === $active_id );
				$fields    = call_user_func( array( $class, 'config_fields' ) );
				$avv       = call_user_func( array( $class, 'avv_url' ) );
				?>
				<fieldset class="rip-sms-provider-config" data-provider="<?php echo esc_attr( $pid ); ?>" <?php echo $is_active ? '' : 'style="display:none;"'; ?>>
					<legend>
						<?php
						printf(
							/* translators: %s: provider name */
							esc_html__( 'Credentials: %s', 'reportedip-hive' ),
							esc_html( call_user_func( array( $class, 'display_name' ) ) )
						);
						?>
					</legend>
					<p class="rip-help-text">
						<?php
						printf(
							/* translators: %s: URL */
							wp_kses_post( __( 'Provider DPA: <a href="%s" target="_blank" rel="noopener">Open terms</a>', 'reportedip-hive' ) ),
							esc_url( $avv )
						);
						?>
					</p>
					<?php
					foreach ( $fields as $field_key => $field_spec ) :
						$value = ( $is_active && isset( $active_config[ $field_key ] ) ) ? $active_config[ $field_key ] : '';
						?>
						<div class="rip-form-group">
							<label class="rip-label" for="rip-sms-<?php echo esc_attr( $pid . '-' . $field_key ); ?>">
								<?php echo esc_html( $field_spec['label'] ); ?>
								<?php
								if ( ! empty( $field_spec['required'] ) ) :
									?>
									<span aria-hidden="true">*</span><?php endif; ?>
							</label>
							<input
								type="<?php echo esc_attr( $field_spec['type'] ?? 'text' ); ?>"
								id="rip-sms-<?php echo esc_attr( $pid . '-' . $field_key ); ?>"
								name="reportedip_hive_2fa_sms_provider_config_raw[<?php echo esc_attr( $pid ); ?>][<?php echo esc_attr( $field_key ); ?>]"
								value="<?php echo esc_attr( $value ); ?>"
								class="rip-input"
								autocomplete="off"
							/>
							<?php if ( ! empty( $field_spec['help'] ) ) : ?>
								<p class="rip-help-text"><?php echo esc_html( $field_spec['help'] ); ?></p>
							<?php endif; ?>
						</div>
					<?php endforeach; ?>
				</fieldset>
			<?php endforeach; ?>

			<?php
			$is_relay_active = ( 'reportedip_relay' === $active_id && ! empty( $relay_status['available'] ) );
			$avv_label       = $is_relay_active
				? __( 'I have accepted the ReportedIP AVV (signed with my plan subscription).', 'reportedip-hive' )
				: __( 'I confirm that a DPA with the selected SMS provider is in place.', 'reportedip-hive' );
			$avv_help        = $is_relay_active
				? __( 'The AVV is part of your active plan and is automatically in force — no separate provider contract needed.', 'reportedip-hive' )
				: __( 'Without this confirmation no SMS is ever sent — privacy hard gate.', 'reportedip-hive' );
			?>
			<div class="rip-form-group">
				<label class="rip-toggle">
					<input type="checkbox"
						class="rip-toggle__input"
						name="reportedip_hive_2fa_sms_avv_confirmed"
						value="1"
						<?php checked( $avv_confirmed || $is_relay_active ); ?> />
					<span class="rip-toggle__slider"></span>
					<span class="rip-toggle__label">
						<?php echo esc_html( $avv_label ); ?>
					</span>
				</label>
				<p class="rip-help-text"><?php echo esc_html( $avv_help ); ?></p>
			</div>

			<?php $sms_ready = ReportedIP_Hive_Two_Factor_SMS::is_ready(); ?>
			<div class="rip-form-group" data-ready="<?php echo $sms_ready ? '1' : '0'; ?>">
				<label class="rip-label" for="rip-sms-test-number"><?php esc_html_e( 'Test SMS to (E.164):', 'reportedip-hive' ); ?></label>
				<input type="tel" id="rip-sms-test-number" class="rip-input" placeholder="+491511234567" style="width: 220px;" <?php disabled( ! $sms_ready ); ?> />
				<button type="button" class="rip-button rip-button--secondary" id="rip-sms-test-btn" <?php disabled( ! $sms_ready ); ?>><?php esc_html_e( 'Send test SMS', 'reportedip-hive' ); ?></button>
				<p class="rip-help-text" id="rip-sms-test-status" role="status">
					<?php if ( ! $sms_ready ) : ?>
						<?php esc_html_e( 'Pick a provider, save the AVV checkbox and store your provider credentials before testing.', 'reportedip-hive' ); ?>
					<?php endif; ?>
				</p>
			</div>

			<script>
			(function(){
				var sel = document.getElementById('reportedip_2fa_sms_provider');
				if (sel) {
					sel.addEventListener('change', function(){
						var val = this.value;
						document.querySelectorAll('.rip-sms-provider-config').forEach(function(fs){
							fs.style.display = (fs.getAttribute('data-provider') === val) ? '' : 'none';
						});
					});
				}
				var btn = document.getElementById('rip-sms-test-btn');
				if (btn && !btn.disabled) {
					btn.addEventListener('click', function(){
						var phone = (document.getElementById('rip-sms-test-number') || {}).value || '';
						var status = document.getElementById('rip-sms-test-status');
						if (!phone) {
							if (status) status.textContent = '<?php echo esc_js( __( 'Please enter a phone number.', 'reportedip-hive' ) ); ?>';
							return;
						}
						btn.disabled = true;
						if (status) status.textContent = '<?php echo esc_js( __( 'Sende…', 'reportedip-hive' ) ); ?>';
						var data = new FormData();
						data.append('action', 'reportedip_hive_2fa_test_sms');
						data.append('nonce', '<?php echo esc_js( wp_create_nonce( 'reportedip_hive_nonce' ) ); ?>');
						data.append('phone', phone);
						fetch('<?php echo esc_js( admin_url( 'admin-ajax.php' ) ); ?>', { method: 'POST', body: data, credentials: 'same-origin' })
							.then(function(r){
								return r.text().then(function(t){
									try {
										return { ok: r.ok, status: r.status, body: JSON.parse(t) };
									} catch (e) {
										return { ok: r.ok, status: r.status, body: null, raw: t };
									}
								});
							})
							.then(function(res){
								btn.disabled = false;
								if (!status) return;
								if (res.body && res.body.success) {
									status.textContent = (res.body.data && res.body.data.message) || '<?php echo esc_js( __( 'Test SMS sent.', 'reportedip-hive' ) ); ?>';
								} else if (res.body && res.body.data && res.body.data.message) {
									status.textContent = res.body.data.message;
								} else {
									status.textContent = '<?php echo esc_js( __( 'Request failed (HTTP', 'reportedip-hive' ) ); ?> ' + res.status + ').';
								}
							})
							.catch(function(){
								btn.disabled = false;
								if (status) status.textContent = '<?php echo esc_js( __( 'Network error — could not reach admin-ajax.php.', 'reportedip-hive' ) ); ?>';
							});
					});
				}
			})();
			</script>
		</div>
		<?php
	}

	/**
	 * Clamp the max-skips option to a safe range.
	 *
	 * @param mixed $input Raw input.
	 * @return int
	 */
	public static function sanitize_max_skips( $input ) {
		$n = absint( $input );
		return max( 0, min( 20, $n ) );
	}

	/**
	 * Sanitize the SMS-provider identifier against the registered providers.
	 *
	 * @param mixed $input
	 * @return string
	 */
	public static function sanitize_sms_provider( $input ) {
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
			return '';
		}
		$input    = sanitize_key( (string) $input );
		$registry = ReportedIP_Hive_Two_Factor_SMS::providers();
		$value    = isset( $registry[ $input ] ) ? $input : '';

		if ( 'reportedip_relay' === $value && class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			$relay_status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'sms_relay_via_api' );
			if ( ! empty( $relay_status['available'] ) ) {
				update_option( ReportedIP_Hive_Two_Factor_SMS::OPT_AVV_CONFIRMED, true );
			}
		}

		return $value;
	}

	/**
	 * Sanitize the provider-config payload and persist it encrypted.
	 *
	 * The per-field raw inputs arrive under `reportedip_hive_2fa_sms_provider_config_raw`
	 * as a nested array keyed by provider id. We pick the currently active
	 * provider's fields, validate against its schema, and store the whole thing
	 * via ReportedIP_Hive_Two_Factor_SMS::save_provider_config() (which
	 * encrypts the JSON). This routine returns an empty placeholder string
	 * because we never want the raw secrets sitting in `wp_options`.
	 *
	 * @param mixed $input
	 * @return string Always empty — the real config lives in OPT_PROVIDER_CONF encrypted.
	 */
	// phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Required by register_setting() sanitize_callback signature; the real config is read from $_POST['reportedip_hive_2fa_sms_provider_config_raw'] and stored encrypted via save_provider_config().
	public static function sanitize_sms_provider_config( $input ) {
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
			return '';
		}
		// phpcs:disable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Settings API verifies the options-page nonce before invoking sanitize_callback. The raw array is recursively sanitized field-by-field below via sanitize_text_field().
		$raw = isset( $_POST['reportedip_hive_2fa_sms_provider_config_raw'] ) && is_array( $_POST['reportedip_hive_2fa_sms_provider_config_raw'] )
			? wp_unslash( $_POST['reportedip_hive_2fa_sms_provider_config_raw'] )
			: array();

		$provider = isset( $_POST['reportedip_hive_2fa_sms_provider'] )
			? sanitize_key( wp_unslash( $_POST['reportedip_hive_2fa_sms_provider'] ) )
			: '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		if ( '' === $provider || empty( $raw[ $provider ] ) ) {
			ReportedIP_Hive_Two_Factor_SMS::save_provider_config( array() );
			return '';
		}

		$registry = ReportedIP_Hive_Two_Factor_SMS::providers();
		if ( empty( $registry[ $provider ] ) ) {
			return '';
		}
		$class  = $registry[ $provider ];
		$fields = call_user_func( array( $class, 'config_fields' ) );

		$clean = array();
		foreach ( $fields as $key => $spec ) {
			$value         = isset( $raw[ $provider ][ $key ] ) ? (string) $raw[ $provider ][ $key ] : '';
			$clean[ $key ] = sanitize_text_field( $value );
		}

		ReportedIP_Hive_Two_Factor_SMS::save_provider_config( $clean );
		return '';
	}

	/**
	 * Sanitize the IP allowlist textarea.
	 *
	 * Keeps comments (# …), drops invalid entries, normalises line breaks.
	 * Blocks the allowlist from being used to bypass 2FA via spoofed IPs by
	 * validating each entry against filter_var + CIDR parsing.
	 *
	 * @param mixed $input Raw textarea input.
	 * @return string Cleaned, newline-joined allowlist.
	 */
	/**
	 * Sanitize the frontend-2FA master toggle.
	 *
	 * Refuses to flip the toggle on when the current ReportedIP plan does
	 * not include `frontend_2fa`, and surfaces a settings error so the
	 * admin sees why the box snapped back to off. When the toggle changes
	 * value, flush the rewrite rules so the configured slugs become
	 * routable / un-routable on the very next page load.
	 *
	 * @param mixed $input Raw form value.
	 * @return string '1' or ''.
	 * @since  1.7.0
	 */
	public static function sanitize_frontend_enabled( $input ) {
		$desired = (bool) rest_sanitize_boolean( $input );
		$current = (bool) get_option( ReportedIP_Hive_Two_Factor_Frontend::OPT_ENABLED, false );

		if ( $desired ) {
			$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'frontend_2fa' );
			if ( empty( $status['available'] ) ) {
				if ( function_exists( 'add_settings_error' ) ) {
					add_settings_error(
						'reportedip_hive_2fa_settings',
						'reportedip_hive_2fa_frontend_tier_locked',
						__( 'Frontend 2FA requires the Professional plan or higher. Toggle reverted.', 'reportedip-hive' ),
						'error'
					);
				}
				$desired = false;
			}
		}

		if ( $desired !== $current ) {
			ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
			if ( function_exists( 'flush_rewrite_rules' ) ) {
				flush_rewrite_rules( false );
			}
		}

		return $desired ? '1' : '';
	}

	/**
	 * Sanitize the configurable challenge slug.
	 *
	 * Reuses {@see ReportedIP_Hive_Two_Factor_Frontend::sanitize_slug()}
	 * so the same reserved-list / shape rules that protect the rewrite
	 * layer also protect the settings save. Empty / invalid input falls
	 * back to the existing value rather than the hardcoded default — a
	 * site that already personalised the slug should not silently revert
	 * to `reportedip-hive-2fa` when the admin saves something invalid.
	 *
	 * Flushes the rewrite rules and the slug memo when the value
	 * changes so the new URL becomes routable on the next request.
	 *
	 * @param mixed $input Raw form value.
	 * @return string
	 * @since  1.7.0
	 */
	public static function sanitize_frontend_challenge_slug( $input ) {
		$current = ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug();
		$clean   = ReportedIP_Hive_Two_Factor_Frontend::sanitize_slug( $input, $current );

		$other = ReportedIP_Hive_Two_Factor_Frontend::get_setup_slug();
		if ( $clean === $other ) {
			if ( function_exists( 'add_settings_error' ) ) {
				add_settings_error(
					'reportedip_hive_2fa_settings',
					'reportedip_hive_2fa_frontend_slug_clash',
					__( 'The challenge and setup slugs must differ. Reverted to the previous value.', 'reportedip-hive' ),
					'error'
				);
			}
			$clean = $current;
		}

		if ( $clean !== $current ) {
			ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
			if ( function_exists( 'flush_rewrite_rules' ) ) {
				flush_rewrite_rules( false );
			}
		}
		return $clean;
	}

	/**
	 * Sanitize the configurable setup / onboarding slug. Mirror of
	 * {@see self::sanitize_frontend_challenge_slug()}.
	 *
	 * @param mixed $input Raw form value.
	 * @return string
	 * @since  1.7.0
	 */
	public static function sanitize_frontend_setup_slug( $input ) {
		$current = ReportedIP_Hive_Two_Factor_Frontend::get_setup_slug();
		$clean   = ReportedIP_Hive_Two_Factor_Frontend::sanitize_slug( $input, $current );

		$other = ReportedIP_Hive_Two_Factor_Frontend::get_challenge_slug();
		if ( $clean === $other ) {
			if ( function_exists( 'add_settings_error' ) ) {
				add_settings_error(
					'reportedip_hive_2fa_settings',
					'reportedip_hive_2fa_frontend_setup_slug_clash',
					__( 'The setup and challenge slugs must differ. Reverted to the previous value.', 'reportedip-hive' ),
					'error'
				);
			}
			$clean = $current;
		}

		if ( $clean !== $current ) {
			ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
			if ( function_exists( 'flush_rewrite_rules' ) ) {
				flush_rewrite_rules( false );
			}
		}
		return $clean;
	}

	public static function sanitize_ip_allowlist( $input ) {
		if ( ! is_string( $input ) ) {
			return '';
		}
		$ip_mgr = ReportedIP_Hive_IP_Manager::get_instance();
		$output = array();

		foreach ( preg_split( '/\r\n|\r|\n/', $input ) as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			if ( 0 === strpos( $line, '#' ) ) {
				$output[] = $line;
				continue;
			}
			if ( $ip_mgr->validate_ip_address( $line ) ) {
				$output[] = $line;
			}
		}

		return implode( "\n", $output );
	}

	/**
	 * Sanitize allowed methods from checkbox inputs into JSON.
	 *
	 * @param mixed $input Raw input (not used, we read from $_POST).
	 * @return string JSON array of methods.
	 */
	public static function sanitize_allowed_methods( $input ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		$methods = array();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Handled by Settings API
		if ( ! empty( $_POST['reportedip_hive_2fa_method_totp'] ) ) {
			$methods[] = ReportedIP_Hive_Two_Factor::METHOD_TOTP;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Handled by Settings API
		if ( ! empty( $_POST['reportedip_hive_2fa_method_email'] ) ) {
			$methods[] = ReportedIP_Hive_Two_Factor::METHOD_EMAIL;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Handled by Settings API
		if ( ! empty( $_POST['reportedip_hive_2fa_method_webauthn'] ) ) {
			$methods[] = ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Handled by Settings API
		if ( ! empty( $_POST['reportedip_hive_2fa_method_sms'] ) ) {
			$methods[] = ReportedIP_Hive_Two_Factor::METHOD_SMS;
		}
		if ( empty( $methods ) ) {
			$methods = array( ReportedIP_Hive_Two_Factor::METHOD_TOTP );
		}
		return wp_json_encode( $methods );
	}

	/**
	 * Sanitize enforced roles from checkbox inputs into JSON.
	 *
	 * @param mixed $input Raw input from form.
	 * @return string JSON array of role slugs.
	 */
	public static function sanitize_enforce_roles( $input ) {
		if ( ! is_array( $input ) ) {
			return '[]';
		}
		$valid_roles = array_keys( wp_roles()->get_names() );
		$roles       = array_filter(
			$input,
			function ( $role ) use ( $valid_roles ) {
				return in_array( $role, $valid_roles, true );
			}
		);
		return wp_json_encode( array_values( $roles ) );
	}

	/**
	 * Render the 2FA section on the user profile page.
	 *
	 * @param WP_User $user The user being edited.
	 */
	public function render_user_profile_section( $user ) {
		if ( ! ReportedIP_Hive_Two_Factor::is_globally_enabled() ) {
			return;
		}

		$is_enabled     = ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID );
		$method         = ReportedIP_Hive_Two_Factor::get_user_method( $user->ID );
		$recovery_count = ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user->ID );
		$devices        = ReportedIP_Hive_Two_Factor::get_trusted_devices( $user->ID );
		$can_edit       = current_user_can( 'edit_user', $user->ID );

		wp_enqueue_style( 'reportedip-hive-two-factor', REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/two-factor.css', array(), REPORTEDIP_HIVE_VERSION );

		$js_deps = array( 'jquery', 'wp-a11y' );
		if ( ! $is_enabled ) {
			wp_enqueue_script( 'reportedip-hive-qrcode', REPORTEDIP_HIVE_PLUGIN_URL . 'assets/vendor/qrcode.min.js', array(), '1.0.0', true );
			$js_deps[] = 'reportedip-hive-qrcode';
		}
		wp_enqueue_script( 'reportedip-hive-two-factor-admin', REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/two-factor-admin.js', $js_deps, REPORTEDIP_HIVE_VERSION, true );
		wp_localize_script(
			'reportedip-hive-two-factor-admin',
			'reportedip2faAdmin',
			array(
				'ajaxUrl' => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'reportedip_hive_nonce' ),
				'userId'  => $user->ID,
				'strings' => array(
					'confirmDisable'    => __( 'Are you sure? This removes all 2FA settings for this account.', 'reportedip-hive' ),
					'confirmRegenerate' => __( 'Existing recovery codes will be invalidated. Continue?', 'reportedip-hive' ),
					'confirmRevokeAll'  => __( 'Revoke all trusted devices?', 'reportedip-hive' ),
					'confirmEmailSetup' => __( 'Enable email-based 2FA? We will send a test code to your registered email address.', 'reportedip-hive' ),
					'copied'            => __( 'Copied!', 'reportedip-hive' ),
					'scanQrCode'        => __( 'Scan this QR code with your authenticator app:', 'reportedip-hive' ),
					'enterCode'         => __( 'Enter the 6-digit code to confirm setup:', 'reportedip-hive' ),
					'setupComplete'     => __( '2FA has been set up successfully!', 'reportedip-hive' ),
					'saveRecoveryCodes' => __( 'Save these recovery codes in a secure place:', 'reportedip-hive' ),
					'error'             => __( 'Error', 'reportedip-hive' ),
					'confirm'           => __( 'Confirm', 'reportedip-hive' ),
					'cancel'            => __( 'Cancel', 'reportedip-hive' ),
					'qrLibMissing'      => __( 'QR code library not loaded.', 'reportedip-hive' ),
					'emailSetupIntro'   => __( 'We will send you a code. Check your inbox…', 'reportedip-hive' ),
					'codePlaceholder'   => __( '000000', 'reportedip-hive' ),
					'copy'              => __( 'Copy', 'reportedip-hive' ),
					'download'          => __( 'Download', 'reportedip-hive' ),
					'recoveryShownOnce' => __( 'These codes are shown only once!', 'reportedip-hive' ),
					'recoveryOneUse'    => __( 'Each code can be used only once.', 'reportedip-hive' ),
				),
			)
		);

		wp_set_script_translations(
			'reportedip-hive-two-factor-admin',
			'reportedip-hive',
			REPORTEDIP_HIVE_LANGUAGES_DIR
		);
		?>
		<h2 id="reportedip-hive-2fa"><?php esc_html_e( 'Two-Factor Authentication', 'reportedip-hive' ); ?></h2>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( 'Status', 'reportedip-hive' ); ?></th>
				<td>
					<?php if ( $is_enabled ) : ?>
						<?php
						$method_labels   = array(
							ReportedIP_Hive_Two_Factor::METHOD_TOTP     => __( 'Authenticator app', 'reportedip-hive' ),
							ReportedIP_Hive_Two_Factor::METHOD_EMAIL    => __( 'Email code', 'reportedip-hive' ),
							ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN => __( 'Passkey', 'reportedip-hive' ),
							ReportedIP_Hive_Two_Factor::METHOD_SMS      => __( 'SMS', 'reportedip-hive' ),
						);
						$enabled_methods = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user->ID );
						$primary_label   = isset( $method_labels[ $method ] ) ? $method_labels[ $method ] : $method;
						$labels_rendered = array();
						foreach ( $enabled_methods as $m ) {
							$label = isset( $method_labels[ $m ] ) ? $method_labels[ $m ] : $m;
							if ( $m === $method ) {
								$label .= ' (' . __( 'primary', 'reportedip-hive' ) . ')';
							}
							$labels_rendered[] = $label;
						}
						if ( empty( $labels_rendered ) ) {
							$labels_rendered[] = $primary_label;
						}
						?>
						<span class="rip-2fa-setup__status rip-2fa-setup__status--enabled">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
							<?php
							printf(
								/* translators: %d: method count */
								esc_html( _n( 'Active — %d method', 'Active — %d methods', count( $labels_rendered ), 'reportedip-hive' ) ),
								count( $labels_rendered )
							);
							?>
						</span>
						<p class="description" style="margin-top:6px;">
							<?php echo esc_html( implode( ' · ', $labels_rendered ) ); ?>
						</p>
					<?php else : ?>
						<span class="rip-2fa-setup__status rip-2fa-setup__status--disabled">
							<?php esc_html_e( 'Not set up', 'reportedip-hive' ); ?>
						</span>
					<?php endif; ?>
				</td>
			</tr>

			<?php if ( $can_edit && ! $is_enabled ) : ?>
				<tr>
					<th scope="row"><?php esc_html_e( 'Set up', 'reportedip-hive' ); ?></th>
					<td>
						<div id="rip-2fa-setup-container">
							<button type="button" class="button" id="rip-2fa-setup-totp">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="vertical-align: text-bottom;"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12" y2="18"/></svg>
								<?php esc_html_e( 'Set up authenticator app', 'reportedip-hive' ); ?>
							</button>
							<button type="button" class="button" id="rip-2fa-setup-email" style="margin-left: 8px;">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16" style="vertical-align: text-bottom;"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
								<?php esc_html_e( 'Set up email code', 'reportedip-hive' ); ?>
							</button>
						</div>
						<div id="rip-2fa-setup-flow" style="display: none;"></div>
					</td>
				</tr>
			<?php endif; ?>

			<?php if ( $can_edit && $is_enabled ) : ?>
				<!-- Recovery Codes -->
				<tr>
					<th scope="row"><?php esc_html_e( 'Recovery Codes', 'reportedip-hive' ); ?></th>
					<td>
						<?php if ( ReportedIP_Hive_Two_Factor_Recovery::is_exhausted( $user->ID ) ) : ?>
							<span class="rip-badge rip-badge--danger"><?php esc_html_e( 'All codes used — generate new', 'reportedip-hive' ); ?></span>
						<?php elseif ( ReportedIP_Hive_Two_Factor_Recovery::is_low( $user->ID ) ) : ?>
							<span class="rip-badge rip-badge--warning">
								<?php
								printf(
									/* translators: %d: remaining codes */
									esc_html__( '%d left — generate new', 'reportedip-hive' ),
									(int) $recovery_count
								);
								?>
							</span>
						<?php else : ?>
							<span class="rip-badge rip-badge--neutral">
								<?php
								printf(
									/* translators: %d: remaining codes */
									esc_html__( '%d available', 'reportedip-hive' ),
									(int) $recovery_count
								);
								?>
							</span>
						<?php endif; ?>
						<br>
						<button type="button" class="button" id="rip-2fa-regenerate-recovery" style="margin-top: 8px;">
							<?php esc_html_e( 'Generate new recovery codes', 'reportedip-hive' ); ?>
						</button>
						<div id="rip-2fa-recovery-display" style="display: none;"></div>
					</td>
				</tr>

				<!-- Trusted Devices -->
				<?php if ( get_option( 'reportedip_hive_2fa_trusted_devices', true ) && ! empty( $devices ) ) : ?>
					<tr>
						<th scope="row"><?php esc_html_e( 'Trusted devices', 'reportedip-hive' ); ?></th>
						<td>
							<ul class="rip-2fa-device-list">
								<?php foreach ( $devices as $device ) : ?>
									<li class="rip-2fa-device-list__item" data-device-id="<?php echo esc_attr( $device->id ); ?>">
										<div class="rip-2fa-device-list__info">
											<div class="rip-2fa-device-list__name"><?php echo esc_html( $device->device_name ?: __( 'Unknown device', 'reportedip-hive' ) ); ?></div>
											<div class="rip-2fa-device-list__meta">
												<?php echo esc_html( $device->ip_address ); ?> &middot;
												<?php
												printf(
													/* translators: %s: date */
													esc_html__( 'Added: %s', 'reportedip-hive' ),
													esc_html( date_i18n( get_option( 'date_format' ), strtotime( $device->created_at ) ) )
												);
												?>
												<?php if ( $device->last_used_at ) : ?>
													&middot;
													<?php
													printf(
														/* translators: %s: date */
														esc_html__( 'Last used: %s', 'reportedip-hive' ),
														esc_html( date_i18n( get_option( 'date_format' ), strtotime( $device->last_used_at ) ) )
													);
													?>
												<?php endif; ?>
											</div>
										</div>
										<button type="button" class="button button-small rip-2fa-revoke-device" data-device-id="<?php echo esc_attr( $device->id ); ?>">
											<?php esc_html_e( 'Revoke', 'reportedip-hive' ); ?>
										</button>
									</li>
								<?php endforeach; ?>
							</ul>
							<button type="button" class="button" id="rip-2fa-revoke-all" style="margin-top: 8px;">
								<?php esc_html_e( 'Revoke all devices', 'reportedip-hive' ); ?>
							</button>
						</td>
					</tr>
				<?php endif; ?>

				<!-- Disable -->
				<tr>
					<th scope="row"><?php esc_html_e( 'Disable', 'reportedip-hive' ); ?></th>
					<td>
						<button type="button" class="button button-link-delete" id="rip-2fa-disable">
							<?php esc_html_e( 'Disable 2FA', 'reportedip-hive' ); ?>
						</button>
					</td>
				</tr>
			<?php endif; ?>
		</table>
		<?php
	}

	/**
	 * Validate AJAX request and return authorized user ID.
	 *
	 * Checks nonce and edit_user capability. Sends JSON error and exits on failure.
	 *
	 * @return int Validated user ID.
	 */
	private function validate_ajax_user() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		$user_id = isset( $_POST['user_id'] ) ? absint( $_POST['user_id'] ) : get_current_user_id();
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission.', 'reportedip-hive' ) ) );
		}

		return $user_id;
	}

	/**
	 * AJAX: Begin TOTP setup — generate secret and return otpauth URI.
	 */
	public function ajax_setup_totp() {
		$user_id = $this->validate_ajax_user();

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			wp_send_json_error( array( 'message' => __( 'Invalid user.', 'reportedip-hive' ) ) );
		}

		$secret = ReportedIP_Hive_Two_Factor_TOTP::generate_secret();
		$uri    = ReportedIP_Hive_Two_Factor_TOTP::generate_qr_uri( $secret, $user->user_login );

		$encrypted = ReportedIP_Hive_Two_Factor_Crypto::encrypt( $secret );
		if ( false === $encrypted ) {
			wp_send_json_error( array( 'message' => __( 'Encryption failed.', 'reportedip-hive' ) ) );
		}

		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET, $encrypted );
		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_CONFIRMED, '0' );

		wp_send_json_success(
			array(
				'uri'    => $uri,
				'secret' => $secret,
			)
		);
	}

	/**
	 * AJAX: Confirm TOTP setup by verifying a code.
	 */
	public function ajax_confirm_totp() {
		$user_id = $this->validate_ajax_user();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_user() above.
		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';

		$encrypted_secret = get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET, true );
		if ( empty( $encrypted_secret ) ) {
			wp_send_json_error( array( 'message' => __( 'No TOTP setup found. Please start again.', 'reportedip-hive' ) ) );
		}

		$secret = ReportedIP_Hive_Two_Factor_Crypto::decrypt( $encrypted_secret );
		if ( false === $secret ) {
			wp_send_json_error( array( 'message' => __( 'Decryption failed.', 'reportedip-hive' ) ) );
		}

		if ( ! ReportedIP_Hive_Two_Factor_TOTP::verify_code( $secret, $code ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid code. Please check your device clock.', 'reportedip-hive' ) ) );
		}

		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_CONFIRMED, '1' );
		ReportedIP_Hive_Two_Factor::enable_for_user( $user_id, ReportedIP_Hive_Two_Factor::METHOD_TOTP );

		$recovery_codes = ReportedIP_Hive_Two_Factor_Recovery::regenerate_codes( $user_id );

		wp_send_json_success(
			array(
				'message'        => __( '2FA with authenticator app enabled!', 'reportedip-hive' ),
				'recovery_codes' => $recovery_codes,
			)
		);
	}

	/**
	 * AJAX: Set up email-based 2FA with mandatory two-step verification.
	 *
	 * step=send   → dispatches a one-time code to the user's address
	 * step=verify → verifies the submitted code, activates Email-2FA on success
	 */
	public function ajax_setup_email() {
		$user_id = $this->validate_ajax_user();

		$user = get_userdata( $user_id );
		if ( ! $user || empty( $user->user_email ) ) {
			wp_send_json_error( array( 'message' => __( 'User has no email address.', 'reportedip-hive' ) ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_user() above.
		$step = isset( $_POST['step'] ) ? sanitize_key( wp_unslash( $_POST['step'] ) ) : '';

		if ( 'send' === $step ) {
			$result = ReportedIP_Hive_Two_Factor_Email::send_code( $user_id );
			if ( is_wp_error( $result ) ) {
				wp_send_json_error( array( 'message' => $result->get_error_message() ) );
			}
			wp_send_json_success(
				array(
					'message' => __( 'Code sent. Please check your inbox.', 'reportedip-hive' ),
					'masked'  => ReportedIP_Hive_Two_Factor::mask_email( $user->user_email ),
				)
			);
		}

		if ( 'verify' === $step ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_user() above.
			$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
			if ( ! ReportedIP_Hive_Two_Factor_Email::verify_code( $user_id, $code ) ) {
				wp_send_json_error( array( 'message' => __( 'Invalid or expired code.', 'reportedip-hive' ) ) );
			}

			update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_EMAIL_ENABLED, '1' );

			if ( ! ReportedIP_Hive_Two_Factor::is_user_enabled( $user_id ) ) {
				ReportedIP_Hive_Two_Factor::enable_for_user( $user_id, ReportedIP_Hive_Two_Factor::METHOD_EMAIL );
			}

			if ( 0 === ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user_id ) ) {
				ReportedIP_Hive_Two_Factor_Recovery::regenerate_codes( $user_id );
			}

			wp_send_json_success(
				array(
					'message' => __( 'Email code enabled!', 'reportedip-hive' ),
				)
			);
		}

		wp_send_json_error(
			array(
				'message' => __( 'Invalid setup step. Email 2FA requires code verification.', 'reportedip-hive' ),
			)
		);
	}

	/**
	 * AJAX: SMS-2FA setup (register number → send test → verify).
	 *
	 * Steps:
	 *   register  — stores encrypted phone number + user consent, dispatches first code
	 *   verify    — checks the submitted code and activates SMS-2FA
	 */
	public function ajax_setup_sms() {
		$user_id = $this->validate_ajax_user();

		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
			wp_send_json_error( array( 'message' => __( 'SMS module is not loaded.', 'reportedip-hive' ) ) );
		}
		if ( ! ReportedIP_Hive_Two_Factor_SMS::is_ready() ) {
			wp_send_json_error( array( 'message' => __( 'SMS sending is not configured. Please contact an administrator.', 'reportedip-hive' ) ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_user() above.
		$step = isset( $_POST['step'] ) ? sanitize_key( wp_unslash( $_POST['step'] ) ) : '';

		if ( 'register' === $step ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_user() above.
			$consent = ! empty( $_POST['consent'] );
			if ( ! $consent ) {
				wp_send_json_error( array( 'message' => __( 'Please confirm processing of your phone number by the EU SMS provider.', 'reportedip-hive' ) ) );
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce verified in validate_ajax_user() above; raw value is normalized/validated by ReportedIP_Hive_Two_Factor_SMS::normalise_phone() (E.164 strict regex) on the next line.
			$phone_raw = isset( $_POST['phone'] ) ? wp_unslash( $_POST['phone'] ) : '';
			$phone     = ReportedIP_Hive_Two_Factor_SMS::normalise_phone( $phone_raw );
			if ( is_wp_error( $phone ) ) {
				wp_send_json_error( array( 'message' => $phone->get_error_message() ) );
			}

			if ( ! ReportedIP_Hive_Two_Factor_SMS::set_user_phone( $user_id, $phone ) ) {
				wp_send_json_error( array( 'message' => __( 'Could not store phone number securely.', 'reportedip-hive' ) ) );
			}

			$result = ReportedIP_Hive_Two_Factor_SMS::send_code( $user_id );
			if ( is_wp_error( $result ) ) {
				wp_send_json_error( array( 'message' => $result->get_error_message() ) );
			}

			wp_send_json_success(
				array(
					'message' => __( 'SMS sent. Please enter the code.', 'reportedip-hive' ),
					'masked'  => ReportedIP_Hive_Two_Factor_SMS::mask_phone( $phone ),
				)
			);
		}

		if ( 'verify' === $step ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_user() above.
			$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
			if ( ! ReportedIP_Hive_Two_Factor_SMS::verify_code( $user_id, $code ) ) {
				wp_send_json_error( array( 'message' => __( 'Invalid or expired code.', 'reportedip-hive' ) ) );
			}

			update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_SMS_ENABLED, '1' );

			if ( ! ReportedIP_Hive_Two_Factor::is_user_enabled( $user_id ) ) {
				ReportedIP_Hive_Two_Factor::enable_for_user( $user_id, ReportedIP_Hive_Two_Factor::METHOD_SMS );
			}

			if ( 0 === ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user_id ) ) {
				ReportedIP_Hive_Two_Factor_Recovery::regenerate_codes( $user_id );
			}

			wp_send_json_success(
				array(
					'message' => __( 'SMS 2FA enabled!', 'reportedip-hive' ),
				)
			);
		}

		wp_send_json_error(
			array(
				'message' => __( 'Invalid setup step.', 'reportedip-hive' ),
			)
		);
	}

	/**
	 * AJAX: Disable a single 2FA method.
	 */
	public function ajax_disable_method() {
		$user_id = $this->validate_ajax_user();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_user() above.
		$method = isset( $_POST['method'] ) ? sanitize_key( wp_unslash( $_POST['method'] ) ) : '';

		if ( ! ReportedIP_Hive_Two_Factor::get_method_meta_key( $method ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid method.', 'reportedip-hive' ) ) );
		}
		if ( ! ReportedIP_Hive_Two_Factor::disable_method( $user_id, $method ) ) {
			wp_send_json_error( array( 'message' => __( 'Could not disable method.', 'reportedip-hive' ) ) );
		}

		wp_send_json_success(
			array(
				'message'       => __( 'Method disabled.', 'reportedip-hive' ),
				'remaining'     => ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id ),
				'still_enabled' => ReportedIP_Hive_Two_Factor::is_user_enabled( $user_id ),
			)
		);
	}

	/**
	 * AJAX: Admin-only test dispatch of an SMS to an arbitrary number to
	 * confirm provider credentials work before rolling 2FA to users.
	 */
	public function ajax_admin_test_sms() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission.', 'reportedip-hive' ) ) );
		}
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) || ! ReportedIP_Hive_Two_Factor_SMS::is_ready() ) {
			wp_send_json_error( array( 'message' => __( 'SMS sending is not configured (provider/DPA/keys).', 'reportedip-hive' ) ) );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce verified by check_ajax_referer() above; raw value is normalized/validated by ReportedIP_Hive_Two_Factor_SMS::normalise_phone() (E.164 strict regex) on the next line.
		$phone_raw = isset( $_POST['phone'] ) ? wp_unslash( $_POST['phone'] ) : '';
		$phone     = ReportedIP_Hive_Two_Factor_SMS::normalise_phone( $phone_raw );
		if ( is_wp_error( $phone ) ) {
			wp_send_json_error( array( 'message' => $phone->get_error_message() ) );
		}

		$class  = ReportedIP_Hive_Two_Factor_SMS::get_active_provider_class();
		$config = ReportedIP_Hive_Two_Factor_SMS::get_provider_config();
		$result = call_user_func( array( $class, 'send' ), $phone, __( 'ReportedIP Hive: Test SMS. Setup was successful.', 'reportedip-hive' ), $config );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ) );
		}
		wp_send_json_success( array( 'message' => __( 'Test SMS sent.', 'reportedip-hive' ) ) );
	}

	/**
	 * AJAX: Disable 2FA for a user.
	 */
	public function ajax_disable() {
		$user_id = $this->validate_ajax_user();

		ReportedIP_Hive_Two_Factor::disable_for_user( $user_id );

		wp_send_json_success(
			array(
				'message' => __( '2FA has been disabled.', 'reportedip-hive' ),
			)
		);
	}

	/**
	 * AJAX: Regenerate recovery codes.
	 */
	public function ajax_regenerate_recovery() {
		$user_id = $this->validate_ajax_user();

		$codes = ReportedIP_Hive_Two_Factor_Recovery::regenerate_codes( $user_id );

		wp_send_json_success(
			array(
				'message' => __( 'New recovery codes generated.', 'reportedip-hive' ),
				'codes'   => $codes,
			)
		);
	}

	/**
	 * AJAX: Revoke a specific trusted device.
	 */
	public function ajax_revoke_device() {
		$user_id = $this->validate_ajax_user();
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_user() above.
		$device_id = isset( $_POST['device_id'] ) ? absint( $_POST['device_id'] ) : 0;

		$revoked = ReportedIP_Hive_Two_Factor::revoke_trusted_device( $device_id, $user_id );

		if ( $revoked ) {
			wp_send_json_success( array( 'message' => __( 'Device revoked.', 'reportedip-hive' ) ) );
		} else {
			wp_send_json_error( array( 'message' => __( 'Device not found.', 'reportedip-hive' ) ) );
		}
	}

	/**
	 * AJAX: Revoke all trusted devices.
	 */
	public function ajax_revoke_all_devices() {
		$user_id = $this->validate_ajax_user();

		$count = ReportedIP_Hive_Two_Factor::revoke_all_trusted_devices( $user_id );

		wp_send_json_success(
			array(
				'message' => sprintf(
				/* translators: %d: number of revoked devices */
					_n( '%d device revoked.', '%d devices revoked.', $count, 'reportedip-hive' ),
					$count
				),
			)
		);
	}

	/**
	 * Register GDPR personal data exporter.
	 *
	 * @param array $exporters Existing exporters.
	 * @return array Modified exporters.
	 */
	public function register_data_exporter( $exporters ) {
		$exporters['reportedip-hive-2fa'] = array(
			'exporter_friendly_name' => __( 'ReportedIP Hive 2FA-Daten', 'reportedip-hive' ),
			'callback'               => array( $this, 'export_personal_data' ),
		);
		return $exporters;
	}

	/**
	 * Register GDPR personal data eraser.
	 *
	 * @param array $erasers Existing erasers.
	 * @return array Modified erasers.
	 */
	public function register_data_eraser( $erasers ) {
		$erasers['reportedip-hive-2fa'] = array(
			'eraser_friendly_name' => __( 'ReportedIP Hive 2FA-Daten', 'reportedip-hive' ),
			'callback'             => array( $this, 'erase_personal_data' ),
		);
		return $erasers;
	}

	/**
	 * Export 2FA personal data for GDPR.
	 *
	 * @param string $email_address User email.
	 * @param int    $page          Page number.
	 * @return array Export data.
	 */
	public function export_personal_data( $email_address, $page = 1 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$user = get_user_by( 'email', $email_address );
		if ( ! $user ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}

		$data = array();

		if ( ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID ) ) {
			$data[] = array(
				'group_id'    => 'reportedip-hive-2fa',
				'group_label' => __( 'ReportedIP 2FA', 'reportedip-hive' ),
				'item_id'     => 'reportedip-2fa-' . $user->ID,
				'data'        => array(
					array(
						'name'  => __( '2FA Status', 'reportedip-hive' ),
						'value' => __( 'Active', 'reportedip-hive' ),
					),
					array(
						'name'  => __( 'Method', 'reportedip-hive' ),
						'value' => ReportedIP_Hive_Two_Factor::get_user_method( $user->ID ),
					),
					array(
						'name'  => __( 'Recovery codes remaining', 'reportedip-hive' ),
						'value' => ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user->ID ),
					),
				),
			);
		}

		return array(
			'data' => $data,
			'done' => true,
		);
	}

	/**
	 * Erase 2FA personal data for GDPR.
	 *
	 * @param string $email_address User email.
	 * @param int    $page          Page number.
	 * @return array Erase result.
	 */
	public function erase_personal_data( $email_address, $page = 1 ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$user = get_user_by( 'email', $email_address );
		if ( ! $user ) {
			return array(
				'items_removed'  => 0,
				'items_retained' => 0,
				'messages'       => array(),
				'done'           => true,
			);
		}

		$was_enabled = ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID );

		if ( $was_enabled ) {
			ReportedIP_Hive_Two_Factor::disable_for_user( $user->ID );
		}

		return array(
			'items_removed'  => $was_enabled ? 1 : 0,
			'items_retained' => 0,
			'messages'       => array(),
			'done'           => true,
		);
	}
}
