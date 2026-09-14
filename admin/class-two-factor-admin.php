<?php
/**
 * Two-Factor Admin Class for ReportedIP Hive.
 *
 * Handles admin settings UI, per-user 2FA profile section,
 * and AJAX endpoints for 2FA setup/management.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
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
	 * Constructor, registers admin hooks.
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
		add_action( 'wp_ajax_reportedip_hive_2fa_set_primary_method', array( $this, 'ajax_set_primary_method' ) );
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
				f.action = <?php echo wp_json_encode( is_network_admin() ? network_admin_url( 'admin-post.php' ) : admin_url( 'admin-post.php' ) ); ?>;
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

		wp_safe_redirect( add_query_arg( 'reportedip_2fa_reset', (int) $user_id, is_network_admin() ? network_admin_url( 'users.php' ) : admin_url( 'users.php' ) ) );
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
		ReportedIP_Hive_Admin_Notice::render(
			array(
				'variant'     => 'success',
				'dismissible' => true,
				'body'        => sprintf(
					/* translators: %s: user display name */
					__( '2FA for %s has been reset. The user has been notified by email.', 'reportedip-hive' ),
					esc_html( $user->display_name )
				),
			)
		);
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
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_enabled_global' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_enforce_grace_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_enforce_grace_days' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_max_skips',
			array(
				'type'              => 'integer',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_max_skips' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_enforce_action',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_enforce_action' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_enforce_super_admins',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_enforce_super_admins' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_trusted_devices',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_trusted_devices' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_trusted_device_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_trusted_device_days' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_frontend_onboarding',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_frontend_onboarding' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_frontend_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_frontend_enabled' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_frontend_customer_optional',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_frontend_customer_optional' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_frontend_slug',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_frontend_slug' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_frontend_setup_slug',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_frontend_setup_slug' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_xmlrpc_app_password_only',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_xmlrpc_app_password_only' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_ip_allowlist',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_ip_allowlist' ),
			)
		);

		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_extended_remember',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_extended_remember' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_branded_login',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_branded_login' ),
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
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_reminder_enabled' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_reminder_hard_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_reminder_hard_threshold' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_reminder_hard_roles',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_reminder_hard_roles' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_email_subject',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_email_subject' ),
			)
		);

		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_require_on_password_reset',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_require_on_password_reset' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_password_reset_block_email_only',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_password_reset_block_email_only' ),
			)
		);

		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_policy_new_country',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_policy_new_country' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_policy_new_ip',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_policy_new_ip' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_policy_new_subnet',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_policy_new_subnet' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_policy_new_device',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_policy_new_device' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_policy_every_n_days',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_policy_every_n_days' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_policy_every_n_logins',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_policy_every_n_logins' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_policy_sessions_above_n',
			array(
				'type'              => 'string',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_policy_sessions_above_n' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_policy_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_policy_days' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_policy_logins',
			array(
				'type'              => 'integer',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_policy_logins' ),
			)
		);
		register_setting(
			'reportedip_hive_2fa_settings',
			'reportedip_hive_2fa_policy_sessions',
			array(
				'type'              => 'integer',
				'sanitize_callback' => ReportedIP_Hive_Settings_Registry::settings_api_callback( 'reportedip_hive_2fa_policy_sessions' ),
			)
		);
	}

	/**
	 * Render the SMS section. SMS-2FA is a Professional-tier feature delivered
	 * exclusively through the managed reportedip.com relay; this renders either
	 * the active-relay status with a test-dispatch button, or a tier-lock card.
	 */
	public static function render_sms_provider_section() {
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) ) {
			return;
		}

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$relay_status = $mode_manager->feature_status( 'sms_relay_via_api' );
		?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
				<?php esc_html_e( 'SMS code (Professional)', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc">
				<?php esc_html_e( 'SMS-2FA is delivered through the managed reportedip.com relay, included with Professional and Business plans. Phone numbers are stored encrypted and the SMS contains only the code, no site or user data.', 'reportedip-hive' ); ?>
			</p>

			<?php if ( ! empty( $relay_status['available'] ) ) : ?>
				<div class="rip-alert rip-alert--success">
					<strong><?php esc_html_e( 'Managed SMS relay active', 'reportedip-hive' ); ?>:</strong>
					<?php esc_html_e( 'SMS-2FA flows through reportedip.com, included with your plan, no separate SMS contract needed.', 'reportedip-hive' ); ?>
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

				<?php $sms_ready = ReportedIP_Hive_Two_Factor_SMS::is_ready(); ?>
				<div class="rip-form-group" data-ready="<?php echo $sms_ready ? '1' : '0'; ?>">
					<label class="rip-label" for="rip-sms-test-number"><?php esc_html_e( 'Test SMS to (E.164):', 'reportedip-hive' ); ?></label>
					<input type="tel" id="rip-sms-test-number" class="rip-input" placeholder="+491511234567" style="width: 220px;" <?php disabled( ! $sms_ready ); ?> />
					<button type="button" class="rip-button rip-button--secondary" id="rip-sms-test-btn" <?php disabled( ! $sms_ready ); ?>><?php esc_html_e( 'Send test SMS', 'reportedip-hive' ); ?></button>
					<p class="rip-help-text" id="rip-sms-test-status" role="status"></p>
				</div>
			<?php else : ?>
				<div class="rip-alert rip-alert--info">
					<strong><?php esc_html_e( 'SMS code is a Professional feature', 'reportedip-hive' ); ?>:</strong>
					<?php esc_html_e( 'Professional and Business plans include SMS-2FA via our managed EU gateway, no separate provider contract required. TOTP, Email and Passkeys remain available on every plan.', 'reportedip-hive' ); ?>
					<?php
					if ( 'tier' === ( $relay_status['reason'] ?? '' ) ) {
						ReportedIP_Hive_Admin_Settings::render_tier_lock( $relay_status, array( 'label' => __( 'Included in Professional', 'reportedip-hive' ) ) );
					}
					?>
				</div>
			<?php endif; ?>

			<script>
			(function(){
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
						if (status) status.textContent = '<?php echo esc_js( __( 'Sende...', 'reportedip-hive' ) ); ?>';
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
								if (status) status.textContent = '<?php echo esc_js( __( 'Network error, could not reach admin-ajax.php.', 'reportedip-hive' ) ); ?>';
							});
					});
				}
			})();
			</script>
		</div>
		<?php
	}

	/**
	 * Sanitize the IP allowlist textarea.
	 *
	 * Keeps comments (# ...), drops invalid entries, normalises line breaks.
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

		return $desired ? '1' : '';
	}

	/**
	 * Sanitize the configurable challenge slug.
	 *
	 * Reuses {@see ReportedIP_Hive_Two_Factor_Frontend::sanitize_slug()}
	 * so the same reserved-list / shape rules that protect the rewrite
	 * layer also protect the settings save. Empty / invalid input falls
	 * back to the existing value rather than the hardcoded default, a
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
	 * Sanitize the allowed-methods option into a JSON array.
	 *
	 * This sanitiser runs for every write to `reportedip_hive_2fa_allowed_methods`
	 * via the `sanitize_option_*` filter that {@see register_setting()} installs.
	 * not only the settings form. Two write shapes therefore reach it:
	 *
	 *  - The settings form posts one checkbox per method
	 *    (`reportedip_hive_2fa_method_totp` ...); the option field itself is an
	 *    empty hidden input, so the value lives in those per-method keys.
	 *  - Every other writer (setup wizard, tier-upgrade, settings import,
	 *    WP-CLI) passes the value directly as a JSON array string or array.
	 *
	 * Detecting the form by the presence of any per-method checkbox key keeps the
	 * checkbox path authoritative for the form while letting a direct value pass
	 * through untouched, previously the direct value was discarded and the option
	 * collapsed to TOTP only (the wizard "only TOTP gets saved" bug).
	 *
	 * @param mixed $input JSON array string / array of method slugs (direct writers).
	 * @return string JSON array of methods.
	 */
	public static function sanitize_allowed_methods( $input ) {
		$checkboxes = array(
			'reportedip_hive_2fa_method_totp'     => ReportedIP_Hive_Two_Factor::METHOD_TOTP,
			'reportedip_hive_2fa_method_email'    => ReportedIP_Hive_Two_Factor::METHOD_EMAIL,
			'reportedip_hive_2fa_method_webauthn' => ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN,
			'reportedip_hive_2fa_method_sms'      => ReportedIP_Hive_Two_Factor::METHOD_SMS,
		);

		$is_settings_form = false;
		foreach ( array_keys( $checkboxes ) as $checkbox_key ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Handled by Settings API; this only detects the form shape.
			if ( isset( $_POST[ $checkbox_key ] ) ) {
				$is_settings_form = true;
				break;
			}
		}

		if ( $is_settings_form ) {
			$methods = array();
			foreach ( $checkboxes as $checkbox_key => $method ) {
				// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Handled by Settings API.
				if ( ! empty( $_POST[ $checkbox_key ] ) ) {
					$methods[] = $method;
				}
			}
		} else {
			$methods = ReportedIP_Hive_Two_Factor::filter_valid_methods( ReportedIP_Hive_Option_Routing::to_array( $input ) );
		}

		if ( empty( $methods ) ) {
			$methods = array( ReportedIP_Hive_Two_Factor::METHOD_TOTP );
		}
		return wp_json_encode( $methods );
	}

	/**
	 * Sanitize the enforce-roles option into a JSON array.
	 *
	 * Like {@see sanitize_allowed_methods()} this runs for every write to
	 * `reportedip_hive_2fa_enforce_roles`. The settings form submits an array
	 * (`reportedip_hive_2fa_enforce_roles[]`); the setup wizard, import and
	 * WP-CLI pass a JSON array string. {@see ReportedIP_Hive_Option_Routing::to_array()}
	 * normalises both shapes, the previous `is_array()` guard rejected the JSON
	 * string and silently wiped the wizard's enforced roles to an empty list.
	 *
	 * @param mixed $input Array (settings form) or JSON array string (other writers).
	 * @return string JSON array of role slugs.
	 */
	public static function sanitize_enforce_roles( $input ) {
		return wp_json_encode( ReportedIP_Hive_Two_Factor::filter_valid_roles( ReportedIP_Hive_Option_Routing::to_array( $input ) ) );
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

		wp_enqueue_style( 'reportedip-hive-design-system', REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/design-system.css', array(), REPORTEDIP_HIVE_VERSION );
		wp_enqueue_style( 'reportedip-hive-two-factor', REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/two-factor.css', array( 'reportedip-hive-design-system' ), REPORTEDIP_HIVE_VERSION );

		$allowed_methods = ReportedIP_Hive_Two_Factor::get_allowed_methods();

		$js_deps = array( 'jquery', 'wp-a11y' );
		if ( $can_edit && in_array( ReportedIP_Hive_Two_Factor::METHOD_TOTP, $allowed_methods, true ) ) {
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
					'confirmDisable'      => __( 'Turn off two-factor authentication completely? Afterwards your account is protected by your password alone.', 'reportedip-hive' ),
					'confirmRegenerate'   => __( 'Your existing recovery codes will stop working and you will receive a new set. Continue?', 'reportedip-hive' ),
					'confirmRevokeAll'    => __( 'Sign out all trusted devices? Every device will be asked for a code on the next sign-in again.', 'reportedip-hive' ),
					'confirmRemoveMethod' => __( 'Remove this sign-in method? You will no longer be able to use it to confirm your sign-in.', 'reportedip-hive' ),
					'confirmRemoveLast'   => __( 'This is your last active method. Removing it turns off two-factor authentication for this account completely. Continue?', 'reportedip-hive' ),
					'confirmReplaceTotp'  => __( 'Set up the authenticator app again? The existing app connection stops working as soon as you finish the new setup.', 'reportedip-hive' ),
					'copied'              => __( 'Copied!', 'reportedip-hive' ),
					'setupComplete'       => __( '2FA has been set up successfully!', 'reportedip-hive' ),
					'saveRecoveryCodes'   => __( 'Save these recovery codes in a secure place:', 'reportedip-hive' ),
					'error'               => __( 'Error', 'reportedip-hive' ),
					'qrLibMissing'        => __( 'QR code library not loaded.', 'reportedip-hive' ),
					'copy'                => __( 'Copy', 'reportedip-hive' ),
					'download'            => __( 'Download', 'reportedip-hive' ),
					'recoveryShownOnce'   => __( 'These codes are shown only once!', 'reportedip-hive' ),
					'recoveryOneUse'      => __( 'Each code can be used only once.', 'reportedip-hive' ),
					'codesSaved'          => __( 'I have saved my codes', 'reportedip-hive' ),
					'phoneRequired'       => __( 'Please enter your mobile number in international format (for example +49 151 23456789).', 'reportedip-hive' ),
					'consentRequired'     => __( 'Please confirm the processing of your phone number first.', 'reportedip-hive' ),
					'working'             => __( 'Please wait', 'reportedip-hive' ),
				),
			)
		);

		wp_set_script_translations(
			'reportedip-hive-two-factor-admin',
			'reportedip-hive',
			REPORTEDIP_HIVE_LANGUAGES_DIR
		);

		$webauthn_allowed = in_array( ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN, $allowed_methods, true );
		if ( $can_edit && $webauthn_allowed ) {
			wp_enqueue_script(
				'reportedip-hive-two-factor-keys',
				REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/two-factor-keys.js',
				array(),
				REPORTEDIP_HIVE_VERSION,
				true
			);
			wp_localize_script(
				'reportedip-hive-two-factor-keys',
				'reportedip2faKeys',
				array(
					'ajaxUrl' => admin_url( 'admin-ajax.php' ),
					'nonce'   => wp_create_nonce( 'reportedip_hive_nonce' ),
					'userId'  => $user->ID,
					'keys'    => ReportedIP_Hive_Two_Factor_WebAuthn::keys_for_display( $user->ID ),
					'strings' => array(
						'typeSecurityKey'    => __( 'Security key', 'reportedip-hive' ),
						'typePasskey'        => __( 'Passkey', 'reportedip-hive' ),
						'never'              => __( 'Never', 'reportedip-hive' ),
						'rename'             => __( 'Rename', 'reportedip-hive' ),
						'remove'             => __( 'Remove', 'reportedip-hive' ),
						'save'               => __( 'Save', 'reportedip-hive' ),
						'renamed'            => __( 'Key renamed.', 'reportedip-hive' ),
						'removed'            => __( 'Key removed.', 'reportedip-hive' ),
						'methodDisabled'     => __( 'Last key removed. The passkey method is now disabled for this account.', 'reportedip-hive' ),
						'confirmRemove'      => __( 'Remove this security key? You will no longer be able to sign in with it.', 'reportedip-hive' ),
						'unsupported'        => __( 'This browser does not support security keys.', 'reportedip-hive' ),
						'waitingForKey'      => __( 'Waiting for your security key. Insert and touch it now.', 'reportedip-hive' ),
						'alreadyRegistered'  => __( 'This key is already registered on this account.', 'reportedip-hive' ),
						'cancelled'          => __( 'The request timed out or was cancelled. Insert your key and touch it (on a phone, hold it against the back for NFC).', 'reportedip-hive' ),
						'otpDetected'        => __( 'That long string was your YubiKey typing its one-time password. That happens when the key is touched while no browser dialog is waiting for it. The field was cleared; click the register button first and touch the key only when the browser asks.', 'reportedip-hive' ),
						'defaultKeyName'     => __( 'Security key', 'reportedip-hive' ),
						'defaultPasskeyName' => __( 'This device', 'reportedip-hive' ),
						'error'              => __( 'Something went wrong.', 'reportedip-hive' ),
						'networkError'       => __( 'Network error.', 'reportedip-hive' ),
					),
				)
			);
		}
		?>
		<?php
		$enabled_methods = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user->ID );

		$sms_allowed = in_array( ReportedIP_Hive_Two_Factor::METHOD_SMS, $allowed_methods, true ) && class_exists( 'ReportedIP_Hive_Two_Factor_SMS' );
		$sms_ready   = $sms_allowed && ReportedIP_Hive_Two_Factor_SMS::is_ready();
		$sms_lock    = null;
		if ( $sms_allowed && ! $sms_ready && class_exists( 'ReportedIP_Hive_Mode_Manager' ) && class_exists( 'ReportedIP_Hive_Admin_Settings' ) ) {
			$sms_lock = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'sms_relay_via_api' );
		}
		$sms_masked = '';
		if ( $sms_allowed && in_array( ReportedIP_Hive_Two_Factor::METHOD_SMS, $enabled_methods, true ) ) {
			$sms_masked = ReportedIP_Hive_Two_Factor_SMS::mask_phone( ReportedIP_Hive_Two_Factor_SMS::get_user_phone( $user->ID ) );
		}

		$method_rows = array();
		if ( in_array( ReportedIP_Hive_Two_Factor::METHOD_TOTP, $allowed_methods, true ) ) {
			$method_rows[ ReportedIP_Hive_Two_Factor::METHOD_TOTP ] = array(
				'label'       => __( 'Authenticator app', 'reportedip-hive' ),
				'description' => __( 'An app on your phone, such as Google Authenticator or Microsoft Authenticator, shows a new 6-digit code every 30 seconds. Works even without mobile signal.', 'reportedip-hive' ),
				'setup'       => true,
			);
		}
		if ( in_array( ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN, $allowed_methods, true ) ) {
			$method_rows[ ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN ] = array(
				'label'       => __( 'Passkey or security key', 'reportedip-hive' ),
				'description' => __( 'Confirm your sign-in with your fingerprint, your face, or a hardware security key such as a YubiKey. This is the most secure option, because it only works on the real sign-in page.', 'reportedip-hive' ),
				'setup'       => false,
				'manager'     => true,
			);
		}
		if ( in_array( ReportedIP_Hive_Two_Factor::METHOD_EMAIL, $allowed_methods, true ) && ! empty( $user->user_email ) ) {
			$method_rows[ ReportedIP_Hive_Two_Factor::METHOD_EMAIL ] = array(
				'label'       => __( 'Email code', 'reportedip-hive' ),
				'description' => sprintf(
					/* translators: %s: masked email address */
					__( 'We send a 6-digit code to %s every time you sign in.', 'reportedip-hive' ),
					ReportedIP_Hive_Two_Factor::mask_email( $user->user_email )
				),
				'setup'       => true,
			);
		}
		if ( $sms_allowed ) {
			$method_rows[ ReportedIP_Hive_Two_Factor::METHOD_SMS ] = array(
				'label'       => __( 'Text message (SMS)', 'reportedip-hive' ),
				'description' => __( 'We send a 6-digit code as a text message to your mobile phone every time you sign in.', 'reportedip-hive' ),
				'setup'       => $sms_ready,
				'lock'        => $sms_lock,
				'meta'        => $sms_masked,
			);
		}
		?>
		<h2 id="reportedip-hive-2fa"><?php esc_html_e( 'Two-Factor Authentication', 'reportedip-hive' ); ?></h2>

		<table class="form-table" role="presentation">
			<tr>
				<td colspan="2" class="rip-2fa-profile__cell">
					<div class="rip-2fa-profile">
						<div class="rip-2fa-setup__section rip-2fa-profile__card">
							<div class="rip-2fa-profile__status-row">
								<?php if ( $is_enabled ) : ?>
									<span class="rip-2fa-setup__status rip-2fa-setup__status--enabled">
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
										<?php
										printf(
											/* translators: %d: method count */
											esc_html( _n( 'Active (%d method)', 'Active (%d methods)', count( $enabled_methods ), 'reportedip-hive' ) ),
											count( $enabled_methods )
										);
										?>
									</span>
								<?php else : ?>
									<span class="rip-2fa-setup__status rip-2fa-setup__status--disabled">
										<?php esc_html_e( 'Not set up', 'reportedip-hive' ); ?>
									</span>
								<?php endif; ?>
							</div>
							<p class="rip-2fa-profile__lead">
								<?php esc_html_e( 'Two-factor authentication adds a second check when you sign in. Even if someone finds out your password, they still cannot get into your account without this second step.', 'reportedip-hive' ); ?>
							</p>
							<?php if ( $can_edit && ! $is_enabled && class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' ) ) : ?>
								<p class="description">
									<?php
									printf(
										/* translators: 1: opening link tag, 2: closing link tag */
										esc_html__( 'Prefer a step-by-step walkthrough? %1$sSet up 2FA in the guided wizard%2$s.', 'reportedip-hive' ),
										'<a href="' . esc_url( ReportedIP_Hive_Two_Factor_Onboarding::get_onboarding_url() ) . '">',
										'</a>'
									);
									?>
								</p>
							<?php endif; ?>
						</div>

						<div class="rip-2fa-setup__section rip-2fa-profile__card">
							<h3 class="rip-2fa-setup__section-title"><?php esc_html_e( 'Your sign-in methods', 'reportedip-hive' ); ?></h3>
							<p class="description rip-2fa-profile__hint">
								<?php esc_html_e( 'You can set up more than one method. Your default method is asked for first when you sign in; every other active method stays available as an alternative on the sign-in screen.', 'reportedip-hive' ); ?>
							</p>
							<ul class="rip-2fa-methods">
								<?php
								foreach ( $method_rows as $row_slug => $row_args ) {
									$row_args['active']   = in_array( $row_slug, $enabled_methods, true );
									$row_args['default']  = $row_args['active'] && $row_slug === $method;
									$row_args['can_edit'] = $can_edit;
									$this->render_profile_method_row( $user, $row_slug, $row_args );
								}
								?>
							</ul>
							<div id="rip-2fa-method-recovery" class="rip-2fa-profile__recovery-display" hidden></div>
						</div>

			<?php if ( $can_edit && $is_enabled ) : ?>
						<div class="rip-2fa-setup__section rip-2fa-profile__card">
							<h3 class="rip-2fa-setup__section-title"><?php esc_html_e( 'Recovery codes', 'reportedip-hive' ); ?></h3>
							<p class="description rip-2fa-profile__hint">
								<?php esc_html_e( 'Recovery codes are one-time emergency codes for the case that your phone or security key is lost. Store them in a safe place, for example a password manager. Each code works exactly once.', 'reportedip-hive' ); ?>
							</p>
							<div class="rip-2fa-profile__recovery-status">
								<?php if ( ReportedIP_Hive_Two_Factor_Recovery::is_exhausted( $user->ID ) ) : ?>
									<span class="rip-badge rip-badge--danger"><?php esc_html_e( 'All codes used. Generate new codes now.', 'reportedip-hive' ); ?></span>
								<?php elseif ( ReportedIP_Hive_Two_Factor_Recovery::is_low( $user->ID ) ) : ?>
									<span class="rip-badge rip-badge--warning">
										<?php
										printf(
											/* translators: %d: remaining codes */
											esc_html__( '%d left. Generate new codes soon.', 'reportedip-hive' ),
											(int) $recovery_count
										);
										?>
									</span>
								<?php else : ?>
									<span class="rip-badge rip-badge--info">
										<?php
										printf(
											/* translators: %d: remaining codes */
											esc_html__( '%d available', 'reportedip-hive' ),
											(int) $recovery_count
										);
										?>
									</span>
								<?php endif; ?>
							</div>
							<button type="button" class="rip-button rip-button--secondary rip-button--sm" id="rip-2fa-regenerate-recovery">
								<?php esc_html_e( 'Generate new recovery codes', 'reportedip-hive' ); ?>
							</button>
							<div id="rip-2fa-recovery-display" class="rip-2fa-profile__recovery-display" hidden></div>
						</div>

						<?php if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_2fa_trusted_devices', true ) && ! empty( $devices ) ) : ?>
							<div class="rip-2fa-setup__section rip-2fa-profile__card">
								<h3 class="rip-2fa-setup__section-title"><?php esc_html_e( 'Trusted devices', 'reportedip-hive' ); ?></h3>
								<p class="description rip-2fa-profile__hint">
									<?php esc_html_e( 'On these devices you chose to skip the second check for a while. Remove a device here if you no longer use it or do not recognise it.', 'reportedip-hive' ); ?>
								</p>
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
											<button type="button" class="rip-button rip-button--ghost rip-button--sm rip-2fa-revoke-device" data-device-id="<?php echo esc_attr( $device->id ); ?>">
												<?php esc_html_e( 'Revoke', 'reportedip-hive' ); ?>
											</button>
										</li>
									<?php endforeach; ?>
								</ul>
								<button type="button" class="rip-button rip-button--secondary rip-button--sm" id="rip-2fa-revoke-all">
									<?php esc_html_e( 'Revoke all devices', 'reportedip-hive' ); ?>
								</button>
							</div>
						<?php endif; ?>

						<div class="rip-2fa-setup__section rip-2fa-profile__card rip-2fa-profile__card--danger">
							<h3 class="rip-2fa-setup__section-title"><?php esc_html_e( 'Turn off two-factor authentication', 'reportedip-hive' ); ?></h3>
							<p class="description rip-2fa-profile__hint">
								<?php esc_html_e( 'This removes all your sign-in methods, recovery codes and trusted devices. Your account is then protected by your password alone. If your role requires 2FA, you will be asked to set it up again on your next sign-in.', 'reportedip-hive' ); ?>
							</p>
							<button type="button" class="rip-button rip-button--danger rip-button--sm" id="rip-2fa-disable">
								<?php esc_html_e( 'Disable 2FA', 'reportedip-hive' ); ?>
							</button>
						</div>
					<?php endif; ?>
					<?php if ( class_exists( 'ReportedIP_Hive_Admin_Settings' ) ) : ?>
						<?php ReportedIP_Hive_Admin_Settings::render_secured_by(); ?>
					<?php endif; ?>
					</div>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Render one sign-in method row on the profile page.
	 *
	 * @param WP_User $user The user being edited.
	 * @param string  $slug Method identifier (totp, email, webauthn, sms).
	 * @param array   $args Row context: label, description, setup (bool),
	 *                      active (bool), default (bool), can_edit (bool),
	 *                      lock (feature status array|null), meta (string),
	 *                      manager (bool).
	 * @since 2.1.36
	 */
	private function render_profile_method_row( $user, $slug, $args ) {
		$icons = array(
			ReportedIP_Hive_Two_Factor::METHOD_TOTP     => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20" aria-hidden="true"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12" y2="18"/></svg>',
			ReportedIP_Hive_Two_Factor::METHOD_EMAIL    => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20" aria-hidden="true"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>',
			ReportedIP_Hive_Two_Factor::METHOD_SMS      => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20" aria-hidden="true"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
			ReportedIP_Hive_Two_Factor::METHOD_WEBAUTHN => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20" aria-hidden="true"><path d="M12 11c1.7 0 3-1.3 3-3s-1.3-3-3-3-3 1.3-3 3 1.3 3 3 3z"/><path d="M6 21v-2c0-2.2 1.8-4 4-4h4c2.2 0 4 1.8 4 4v2"/></svg>',
		);

		$active     = ! empty( $args['active'] );
		$is_default = ! empty( $args['default'] );
		$can_edit   = ! empty( $args['can_edit'] );
		$has_setup  = ! empty( $args['setup'] );
		$is_manager = ! empty( $args['manager'] );
		?>
		<li class="rip-2fa-method" data-method="<?php echo esc_attr( $slug ); ?>" data-active="<?php echo $active ? '1' : '0'; ?>">
			<div class="rip-2fa-method__main">
				<div class="rip-2fa-method__icon"><?php echo $icons[ $slug ]; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Static inline SVG from the map above. ?></div>
				<div class="rip-2fa-method__body">
					<div class="rip-2fa-method__head">
						<span class="rip-2fa-method__name"><?php echo esc_html( $args['label'] ); ?></span>
						<?php if ( $active ) : ?>
							<span class="rip-badge rip-badge--success"><?php esc_html_e( 'Active', 'reportedip-hive' ); ?></span>
							<?php if ( $is_default ) : ?>
								<span class="rip-badge rip-badge--info" title="<?php esc_attr_e( 'This method is asked for first when you sign in.', 'reportedip-hive' ); ?>"><?php esc_html_e( 'Default', 'reportedip-hive' ); ?></span>
							<?php endif; ?>
						<?php else : ?>
							<span class="rip-2fa-method__state"><?php esc_html_e( 'Not set up', 'reportedip-hive' ); ?></span>
						<?php endif; ?>
					</div>
					<p class="rip-2fa-method__desc"><?php echo esc_html( $args['description'] ); ?></p>
					<?php if ( ! empty( $args['meta'] ) ) : ?>
						<p class="rip-2fa-method__meta">
							<?php
							printf(
								/* translators: %s: masked phone number */
								esc_html__( 'Current number: %s', 'reportedip-hive' ),
								esc_html( $args['meta'] )
							);
							?>
						</p>
					<?php endif; ?>
				</div>
				<?php if ( $can_edit ) : ?>
					<div class="rip-2fa-method__actions">
						<?php if ( $active ) : ?>
							<?php if ( ! $is_default ) : ?>
								<button type="button" class="rip-button rip-button--ghost rip-button--sm" data-action="make-default"><?php esc_html_e( 'Make default', 'reportedip-hive' ); ?></button>
							<?php endif; ?>
							<?php if ( ReportedIP_Hive_Two_Factor::METHOD_TOTP === $slug ) : ?>
								<button type="button" class="rip-button rip-button--ghost rip-button--sm" data-action="setup" data-replace="1"><?php esc_html_e( 'Set up again', 'reportedip-hive' ); ?></button>
							<?php elseif ( ReportedIP_Hive_Two_Factor::METHOD_SMS === $slug && $has_setup ) : ?>
								<button type="button" class="rip-button rip-button--ghost rip-button--sm" data-action="setup"><?php esc_html_e( 'Change number', 'reportedip-hive' ); ?></button>
							<?php endif; ?>
							<?php if ( ! $is_manager ) : ?>
								<button type="button" class="rip-button rip-button--danger rip-button--sm" data-action="remove"><?php esc_html_e( 'Remove', 'reportedip-hive' ); ?></button>
							<?php endif; ?>
						<?php elseif ( $has_setup ) : ?>
							<button type="button" class="rip-button rip-button--secondary rip-button--sm" data-action="setup"><?php esc_html_e( 'Set up', 'reportedip-hive' ); ?></button>
						<?php elseif ( ! empty( $args['lock'] ) && class_exists( 'ReportedIP_Hive_Admin_Settings' ) ) : ?>
							<?php ReportedIP_Hive_Admin_Settings::render_tier_lock( $args['lock'], array( 'label' => __( 'Included in Professional', 'reportedip-hive' ) ) ); ?>
						<?php endif; ?>
					</div>
				<?php endif; ?>
			</div>
			<?php if ( $can_edit && ! $is_manager ) : ?>
				<?php $this->render_profile_method_flow( $slug ); ?>
			<?php endif; ?>
			<?php if ( $can_edit && $is_manager ) : ?>
				<div class="rip-2fa-method__manager">
					<?php
					$rip_webauthn_manager = array( 'user_id' => $user->ID );
					include REPORTEDIP_HIVE_PLUGIN_DIR . 'templates/partials/webauthn-key-manager.php';
					?>
				</div>
			<?php endif; ?>
		</li>
		<?php
	}

	/**
	 * Render the hidden inline setup flow for a profile method row.
	 *
	 * All user-facing text is server-rendered here so it flows through the
	 * normal i18n pipeline; assets/js/two-factor-admin.js only toggles the
	 * markup and drives the AJAX steps.
	 *
	 * @param string $slug Method identifier (totp, email, sms).
	 * @since 2.1.36
	 */
	private function render_profile_method_flow( $slug ) {
		if ( ReportedIP_Hive_Two_Factor::METHOD_TOTP === $slug ) :
			?>
			<div class="rip-2fa-method__flow" data-flow="totp" hidden>
				<p class="rip-2fa-method__flow-intro"><?php esc_html_e( 'Scan this QR code with your authenticator app, then enter the 6-digit code the app shows to finish the setup. If you cannot scan, type the key below the code into the app instead.', 'reportedip-hive' ); ?></p>
				<div class="rip-2fa-setup__qr">
					<div class="rip-2fa-qr-target" data-qr></div>
					<p class="rip-2fa-setup__secret" data-secret title="<?php esc_attr_e( 'Manual entry key', 'reportedip-hive' ); ?>"></p>
				</div>
				<div class="rip-2fa-method__flow-controls">
					<input type="text" class="rip-input rip-2fa-method__code" data-code inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="000000" aria-label="<?php esc_attr_e( 'Verification code', 'reportedip-hive' ); ?>" />
					<button type="button" class="rip-button rip-button--primary" data-step="confirm"><?php esc_html_e( 'Confirm', 'reportedip-hive' ); ?></button>
					<button type="button" class="rip-button rip-button--ghost" data-step="cancel"><?php esc_html_e( 'Cancel', 'reportedip-hive' ); ?></button>
				</div>
				<p class="description rip-2fa-method__flow-status" data-status role="status" aria-live="polite"></p>
			</div>
			<?php
		elseif ( ReportedIP_Hive_Two_Factor::METHOD_EMAIL === $slug ) :
			?>
			<div class="rip-2fa-method__flow" data-flow="email" hidden>
				<div data-email-step="send">
					<p class="rip-2fa-method__flow-intro"><?php esc_html_e( 'We will send a 6-digit code to your email address. Click the button, then check your inbox.', 'reportedip-hive' ); ?></p>
					<div class="rip-2fa-method__flow-controls">
						<button type="button" class="rip-button rip-button--primary" data-step="send-email"><?php esc_html_e( 'Send code', 'reportedip-hive' ); ?></button>
						<button type="button" class="rip-button rip-button--ghost" data-step="cancel"><?php esc_html_e( 'Cancel', 'reportedip-hive' ); ?></button>
					</div>
				</div>
				<div data-email-step="code" hidden>
					<p class="rip-2fa-method__flow-intro" data-email-sent-note></p>
					<div class="rip-2fa-method__flow-controls">
						<input type="text" class="rip-input rip-2fa-method__code" data-code inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="000000" aria-label="<?php esc_attr_e( 'Verification code', 'reportedip-hive' ); ?>" />
						<button type="button" class="rip-button rip-button--primary" data-step="confirm"><?php esc_html_e( 'Confirm', 'reportedip-hive' ); ?></button>
						<button type="button" class="rip-button rip-button--ghost" data-step="cancel"><?php esc_html_e( 'Cancel', 'reportedip-hive' ); ?></button>
					</div>
				</div>
				<p class="description rip-2fa-method__flow-status" data-status role="status" aria-live="polite"></p>
			</div>
			<?php
		elseif ( ReportedIP_Hive_Two_Factor::METHOD_SMS === $slug ) :
			?>
			<div class="rip-2fa-method__flow" data-flow="sms" hidden>
				<div data-sms-step="phone">
					<label class="rip-form-label" for="rip-2fa-sms-phone"><?php esc_html_e( 'Mobile number', 'reportedip-hive' ); ?></label>
					<input type="tel" id="rip-2fa-sms-phone" class="rip-input" data-phone placeholder="+49 151 23456789" autocomplete="tel" />
					<label class="rip-2fa-method__consent">
						<input type="checkbox" data-consent />
						<span><?php esc_html_e( 'I agree that my phone number is stored encrypted and processed by the managed ReportedIP SMS service to deliver sign-in codes.', 'reportedip-hive' ); ?></span>
					</label>
					<div class="rip-2fa-method__flow-controls">
						<button type="button" class="rip-button rip-button--primary" data-step="send-sms"><?php esc_html_e( 'Send code', 'reportedip-hive' ); ?></button>
						<button type="button" class="rip-button rip-button--ghost" data-step="cancel"><?php esc_html_e( 'Cancel', 'reportedip-hive' ); ?></button>
					</div>
				</div>
				<div data-sms-step="code" hidden>
					<p class="rip-2fa-method__flow-intro" data-sms-sent-note></p>
					<div class="rip-2fa-method__flow-controls">
						<input type="text" class="rip-input rip-2fa-method__code" data-code inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="000000" aria-label="<?php esc_attr_e( 'Verification code', 'reportedip-hive' ); ?>" />
						<button type="button" class="rip-button rip-button--primary" data-step="confirm"><?php esc_html_e( 'Confirm', 'reportedip-hive' ); ?></button>
						<button type="button" class="rip-button rip-button--ghost" data-step="cancel"><?php esc_html_e( 'Cancel', 'reportedip-hive' ); ?></button>
					</div>
				</div>
				<p class="description rip-2fa-method__flow-status" data-status role="status" aria-live="polite"></p>
			</div>
			<?php
		endif;
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
	 * Refuse enrolment into a method the site policy does not permit.
	 *
	 * The profile UI hides the card for a disallowed method, but the endpoint
	 * behind it stays reachable. Checked before any work happens so a
	 * disallowed SMS or email enrolment cannot burn managed relay quota on the
	 * way to being rejected.
	 *
	 * @param string $method Method identifier.
	 * @return void
	 * @since  2.1.44
	 */
	private function require_allowed_method( $method ) {
		if ( ReportedIP_Hive_Two_Factor::is_method_allowed( $method ) ) {
			return;
		}

		wp_send_json_error(
			array(
				'message' => __( 'This verification method is not available on this site.', 'reportedip-hive' ),
				'code'    => 'method_not_allowed',
			)
		);
	}

	/**
	 * AJAX: Begin TOTP setup, generate secret and return otpauth URI.
	 */
	public function ajax_setup_totp() {
		$user_id = $this->validate_ajax_user();
		$this->require_allowed_method( ReportedIP_Hive_Two_Factor::METHOD_TOTP );

		$user = get_userdata( $user_id );
		if ( ! $user ) {
			wp_send_json_error( array( 'message' => __( 'Invalid user.', 'reportedip-hive' ) ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_user() above.
		$replace        = ! empty( $_POST['replace'] );
		$totp_confirmed = get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_CONFIRMED, true );
		$totp_active    = in_array(
			ReportedIP_Hive_Two_Factor::METHOD_TOTP,
			ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id ),
			true
		);
		if ( '1' === $totp_confirmed && $totp_active && ! $replace ) {
			wp_send_json_error(
				array(
					'message' => __( 'An authenticator app is already connected. Starting a new setup replaces that connection, and codes from the previous app will stop working.', 'reportedip-hive' ),
					'code'    => 'totp_already_configured',
				)
			);
		}

		$secret = ReportedIP_Hive_Two_Factor_TOTP::generate_secret();
		$uri    = ReportedIP_Hive_Two_Factor_TOTP::generate_qr_uri( $secret, $user->user_login );

		$encrypted = ReportedIP_Hive_Two_Factor_Crypto::encrypt( $secret );
		if ( false === $encrypted ) {
			wp_send_json_error( array( 'message' => __( 'Encryption failed.', 'reportedip-hive' ) ) );
		}

		/*
		 * Park the new secret until a code proves the authenticator holds it.
		 * Overwriting the live secret here meant a replacement the user
		 * abandoned, closing the tab before scanning the QR code, left the
		 * old app producing rejected codes and no way back in, and made the
		 * unconfirmed secret a working second factor in the meantime.
		 */
		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET_PENDING, $encrypted );

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

		/*
		 * A pending secret is the setup currently being confirmed. Falling
		 * back to the live one keeps a setup that was started before this
		 * release completable.
		 */
		$encrypted_secret = get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET_PENDING, true );
		if ( empty( $encrypted_secret ) ) {
			$encrypted_secret = get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET, true );
		}
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

		/* Promoting is an identity write when the secret came from the live key
			and the delete is a no-op when nothing was pending, so neither needs
			a branch. */
		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET, $encrypted_secret );
		delete_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET_PENDING );
		update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_CONFIRMED, '1' );

		$recovery_codes = ReportedIP_Hive_Two_Factor::activate_method( $user_id, ReportedIP_Hive_Two_Factor::METHOD_TOTP );

		wp_send_json_success(
			array(
				'message'        => __( '2FA with authenticator app enabled!', 'reportedip-hive' ),
				'recovery_codes' => is_array( $recovery_codes ) ? $recovery_codes : null,
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
		$this->require_allowed_method( ReportedIP_Hive_Two_Factor::METHOD_EMAIL );

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

			$recovery_codes = ReportedIP_Hive_Two_Factor::activate_method( $user_id, ReportedIP_Hive_Two_Factor::METHOD_EMAIL );

			wp_send_json_success(
				array(
					'message'        => __( 'Email code enabled!', 'reportedip-hive' ),
					'recovery_codes' => is_array( $recovery_codes ) ? $recovery_codes : null,
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
	 *   register , stores encrypted phone number + user consent, dispatches first code
	 *   verify   , checks the submitted code and activates SMS-2FA
	 */
	public function ajax_setup_sms() {
		$user_id = $this->validate_ajax_user();
		$this->require_allowed_method( ReportedIP_Hive_Two_Factor::METHOD_SMS );

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
				wp_send_json_error( array( 'message' => __( 'Please confirm processing of your phone number by the managed SMS relay.', 'reportedip-hive' ) ) );
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce verified in validate_ajax_user() above; raw value is normalized/validated by ReportedIP_Hive_Two_Factor_SMS::normalise_phone() (E.164 strict regex) on the next line.
			$phone_raw = isset( $_POST['phone'] ) ? wp_unslash( $_POST['phone'] ) : '';
			$phone     = ReportedIP_Hive_Two_Factor_SMS::normalise_phone( $phone_raw );
			if ( is_wp_error( $phone ) ) {
				wp_send_json_error( array( 'message' => $phone->get_error_message() ) );
			}

			$sms_active = in_array(
				ReportedIP_Hive_Two_Factor::METHOD_SMS,
				ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id ),
				true
			);

			if ( $sms_active ) {
				$encrypted_pending = ReportedIP_Hive_Two_Factor_Crypto::encrypt( $phone );
				if ( false === $encrypted_pending ) {
					wp_send_json_error( array( 'message' => __( 'Could not store phone number securely.', 'reportedip-hive' ) ) );
				}
				update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_SMS_NUMBER_PENDING, $encrypted_pending );

				$result = ReportedIP_Hive_Two_Factor_SMS::send_code( $user_id, $phone );
			} else {
				if ( ! ReportedIP_Hive_Two_Factor_SMS::set_user_phone( $user_id, $phone ) ) {
					wp_send_json_error( array( 'message' => __( 'Could not store phone number securely.', 'reportedip-hive' ) ) );
				}

				$result = ReportedIP_Hive_Two_Factor_SMS::send_code( $user_id );
			}

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

			$pending = get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_SMS_NUMBER_PENDING, true );
			if ( ! empty( $pending ) ) {
				update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_SMS_NUMBER, $pending );
				delete_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_SMS_NUMBER_PENDING );
			}

			$recovery_codes = ReportedIP_Hive_Two_Factor::activate_method( $user_id, ReportedIP_Hive_Two_Factor::METHOD_SMS );

			wp_send_json_success(
				array(
					'message'        => __( 'SMS 2FA enabled!', 'reportedip-hive' ),
					'recovery_codes' => is_array( $recovery_codes ) ? $recovery_codes : null,
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
	 * AJAX: Set the user's default sign-in method.
	 *
	 * The default method decides which verification tab the login challenge
	 * opens with. Only methods the user has actively configured are accepted;
	 * the guard lives in ReportedIP_Hive_Two_Factor::set_user_method().
	 *
	 * @since 2.1.36
	 */
	public function ajax_set_primary_method() {
		$user_id = $this->validate_ajax_user();

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_user() above.
		$method = isset( $_POST['method'] ) ? sanitize_key( wp_unslash( $_POST['method'] ) ) : '';

		if ( ! ReportedIP_Hive_Two_Factor::set_user_method( $user_id, $method ) ) {
			wp_send_json_error( array( 'message' => __( 'Only a method you have set up can be your default.', 'reportedip-hive' ) ) );
		}

		wp_send_json_success(
			array(
				'message' => __( 'Default sign-in method updated.', 'reportedip-hive' ),
				'method'  => $method,
			)
		);
	}

	/**
	 * AJAX: Admin-only test dispatch of an SMS through the managed relay to an
	 * arbitrary number to confirm SMS-2FA works before rolling it out to users.
	 *
	 * The test spends network-wide relay quota and is rendered on the Network
	 * Admin settings tab only, so on Multisite it demands
	 * `manage_network_options`, the same rule the AJAX handler applies to
	 * every option-writing action.
	 */
	public function ajax_admin_test_sms() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );
		if ( ! ReportedIP_Hive_Option_Routing::current_user_can_manage() ) {
			wp_send_json_error( array( 'message' => __( 'You do not have permission.', 'reportedip-hive' ) ) );
		}
		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor_SMS' ) || ! ReportedIP_Hive_Two_Factor_SMS::is_ready() ) {
			wp_send_json_error( array( 'message' => __( 'SMS sending is not available on your current plan.', 'reportedip-hive' ) ) );
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce verified by check_ajax_referer() above; raw value is normalized/validated by ReportedIP_Hive_Two_Factor_SMS::normalise_phone() (E.164 strict regex) on the next line.
		$phone_raw = isset( $_POST['phone'] ) ? wp_unslash( $_POST['phone'] ) : '';
		$phone     = ReportedIP_Hive_Two_Factor_SMS::normalise_phone( $phone_raw );
		if ( is_wp_error( $phone ) ) {
			wp_send_json_error( array( 'message' => $phone->get_error_message() ) );
		}

		$result = ReportedIP_Hive_SMS_Provider_Relay::send( $phone, __( 'ReportedIP Hive: Test SMS. Setup was successful.', 'reportedip-hive' ) );

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
