<?php
/**
 * Setup Wizard Class for ReportedIP Hive.
 *
 * Handles the initial plugin setup wizard for new users — light CI with
 * 9 steps: Welcome → Connect → Protection → 2FA → Privacy → Notifications →
 * Login → Promote → Done.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Setup_Wizard
 */
class ReportedIP_Hive_Setup_Wizard {

	/**
	 * Mode Manager instance
	 *
	 * @var ReportedIP_Hive_Mode_Manager
	 */
	private $mode_manager;

	/**
	 * Current wizard step
	 *
	 * @var int
	 */
	private $current_step = 1;

	/**
	 * Step index → label. Single source of truth: add new steps here and
	 * both get_step_labels() and total_steps stay consistent.
	 */
	private function get_step_labels() {
		return array(
			1 => __( 'Welcome', 'reportedip-hive' ),
			2 => __( 'Connect', 'reportedip-hive' ),
			3 => __( 'Protection', 'reportedip-hive' ),
			4 => __( '2FA', 'reportedip-hive' ),
			5 => __( 'Privacy', 'reportedip-hive' ),
			6 => __( 'Notifications', 'reportedip-hive' ),
			7 => __( 'Login', 'reportedip-hive' ),
			8 => __( 'Promote', 'reportedip-hive' ),
			9 => __( 'Done', 'reportedip-hive' ),
		);
	}

	/**
	 * Wizard page slug
	 *
	 * @var string
	 */
	const PAGE_SLUG = 'reportedip-hive-wizard';

	/**
	 * Constructor
	 *
	 * @param ReportedIP_Hive_Mode_Manager $mode_manager Mode Manager instance
	 */
	public function __construct( $mode_manager ) {
		$this->mode_manager = $mode_manager;

		add_action( 'admin_menu', array( $this, 'add_wizard_page' ) );

		add_action( 'admin_init', array( $this, 'maybe_redirect_to_wizard' ) );
		add_action( 'admin_init', array( $this, 'maybe_render_standalone_wizard' ) );

		add_action( 'wp_ajax_reportedip_wizard_save_mode', array( $this, 'ajax_save_mode' ) );
		add_action( 'wp_ajax_reportedip_wizard_validate_api_key', array( $this, 'ajax_validate_api_key' ) );
		add_action( 'wp_ajax_reportedip_wizard_complete', array( $this, 'ajax_complete_wizard' ) );
		add_action( 'wp_ajax_reportedip_wizard_skip', array( $this, 'ajax_skip_wizard' ) );
		add_action( 'wp_ajax_reportedip_wizard_import_settings', array( $this, 'ajax_import_settings' ) );
		add_action( 'wp_ajax_reportedip_wizard_validate_login_slug', array( $this, 'ajax_validate_login_slug' ) );
		add_action( 'wp_ajax_reportedip_wizard_save_notifications', array( $this, 'ajax_save_notifications' ) );
		add_action( 'wp_ajax_reportedip_wizard_save_promote', array( $this, 'ajax_save_promote' ) );
	}

	/**
	 * AJAX: persist the notifications-step choices (recipients + From sender).
	 *
	 * Validates every recipient via `is_email()`, drops invalids and persists
	 * the cleaned, comma-separated list. The From-Name and From-Email pair is
	 * sanitised the same way the mailer reads it back. When the optional API
	 * sync flag is on we forward the same payload to reportedip.de so the
	 * service plugin can mirror the contact configuration.
	 *
	 * @since 1.5.3
	 */
	public function ajax_save_notifications() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ), 403 );
		}
		check_ajax_referer( 'reportedip_wizard_nonce', 'nonce' );

		$raw_recipients = isset( $_POST['recipients'] ) ? sanitize_textarea_field( wp_unslash( (string) $_POST['recipients'] ) ) : '';
		$candidates     = array_filter( array_map( 'trim', preg_split( '/[\s,;]+/', $raw_recipients ) ) );
		$valid          = array();
		$rejected       = array();
		foreach ( $candidates as $candidate ) {
			$clean = sanitize_email( $candidate );
			if ( '' !== $clean && is_email( $clean ) ) {
				$valid[] = $clean;
			} else {
				$rejected[] = $candidate;
			}
		}
		$valid = array_values( array_unique( $valid ) );

		$from_name  = isset( $_POST['from_name'] ) ? sanitize_text_field( wp_unslash( (string) $_POST['from_name'] ) ) : '';
		$from_email = isset( $_POST['from_email'] ) ? sanitize_email( wp_unslash( (string) $_POST['from_email'] ) ) : '';
		if ( '' !== $from_email && ! is_email( $from_email ) ) {
			$from_email = '';
		}

		$notify_admin = isset( $_POST['notify_admin'] ) && '1' === sanitize_key( wp_unslash( (string) $_POST['notify_admin'] ) );
		$sync_to_api  = isset( $_POST['sync_to_api'] ) && '1' === sanitize_key( wp_unslash( (string) $_POST['sync_to_api'] ) );

		update_option( 'reportedip_hive_notify_recipients', implode( ', ', $valid ) );
		update_option( 'reportedip_hive_notify_from_name', $from_name );
		update_option( 'reportedip_hive_notify_from_email', $from_email );
		update_option( 'reportedip_hive_notify_admin', $notify_admin );
		update_option( 'reportedip_hive_notify_sync_to_api', $sync_to_api );

		if ( $sync_to_api && class_exists( 'ReportedIP_Hive_API' ) ) {
			$api = ReportedIP_Hive_API::get_instance();
			if ( method_exists( $api, 'sync_notification_config' ) ) {
				$api->sync_notification_config(
					array(
						'recipients' => $valid,
						'from_name'  => $from_name,
						'from_email' => $from_email,
					)
				);
			}
		}

		wp_send_json_success(
			array(
				'redirect_url' => admin_url( 'admin.php?page=' . self::PAGE_SLUG . '&step=7' ),
				'recipients'   => $valid,
				'rejected'     => $rejected,
			)
		);
	}

	/**
	 * AJAX: persist the promote-step choices (auto-footer toggle + variant +
	 * alignment).
	 *
	 * Reuses the existing wizard nonce. Skipping the step is signalled by
	 * `promote_action=skip`, which sends `enabled=false` so the auto-footer
	 * stays off — the user can still flip it on later from the Community tab.
	 *
	 * @since 1.5.3
	 */
	public function ajax_save_promote() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ), 403 );
		}
		check_ajax_referer( 'reportedip_wizard_nonce', 'nonce' );

		$action      = isset( $_POST['promote_action'] ) ? sanitize_key( wp_unslash( (string) $_POST['promote_action'] ) ) : 'save';
		$enabled     = isset( $_POST['enabled'] ) && '1' === sanitize_key( wp_unslash( (string) $_POST['enabled'] ) );
		$variant_raw = isset( $_POST['variant'] ) ? sanitize_key( wp_unslash( (string) $_POST['variant'] ) ) : 'badge';
		$variant     = class_exists( 'ReportedIP_Hive_Frontend_Shortcodes' )
			? ReportedIP_Hive_Frontend_Shortcodes::sanitize_footer_variant( $variant_raw )
			: ( 'shield' === $variant_raw ? 'shield' : 'badge' );
		$align_raw   = isset( $_POST['align'] ) ? sanitize_key( wp_unslash( (string) $_POST['align'] ) ) : 'center';
		$align       = in_array( $align_raw, array( 'left', 'center', 'right', 'below' ), true ) ? $align_raw : 'center';

		$done_url = admin_url( 'admin.php?page=' . self::PAGE_SLUG . '&step=9' );

		if ( 'skip' === $action ) {
			update_option( 'reportedip_hive_auto_footer_enabled', false );
			wp_send_json_success( array( 'redirect_url' => $done_url ) );
		}

		update_option( 'reportedip_hive_auto_footer_enabled', $enabled );
		update_option( 'reportedip_hive_auto_footer_variant', $variant );
		update_option( 'reportedip_hive_auto_footer_align', $align );

		wp_send_json_success( array( 'redirect_url' => $done_url ) );
	}

	/**
	 * AJAX: import settings from a JSON file uploaded inside the wizard.
	 *
	 * Reuses the same allowlist + sanitiser pipeline as the regular
	 * settings-import panel. After a successful import the wizard is marked
	 * as completed and the client is told to jump to the final step.
	 *
	 * @since 1.2.0
	 */
	public function ajax_import_settings() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ), 403 );
		}
		check_ajax_referer( 'reportedip_hive_settings_import', '_rip_ie_nonce' );

		if ( ! class_exists( 'ReportedIP_Hive_Settings_Import_Export' ) ) {
			wp_send_json_error( array( 'message' => __( 'Settings import is unavailable.', 'reportedip-hive' ) ), 500 );
		}

		$service = ReportedIP_Hive_Settings_Import_Export::get_instance();
		$decoded = $service->read_uploaded_payload();
		if ( is_wp_error( $decoded ) ) {
			wp_send_json_error( array( 'message' => $decoded->get_error_message() ), 400 );
		}

		$apply_summary = $service->apply_payload( $decoded, array_keys( ReportedIP_Hive_Settings_Import_Export::sections() ) );

		$this->mode_manager->mark_wizard_completed();

		wp_send_json_success(
			array(
				'redirect_url' => $this->get_wizard_url( 9 ),
				'summary'      => $apply_summary,
			)
		);
	}

	/**
	 * Add hidden wizard page to admin menu (needed for URL routing)
	 */
	public function add_wizard_page() {
		add_submenu_page(
			'',
			__( 'Setup Wizard', 'reportedip-hive' ),
			__( 'Setup Wizard', 'reportedip-hive' ),
			'manage_options',
			self::PAGE_SLUG,
			'__return_null'
		);
	}

	/**
	 * Render wizard as standalone page in admin_init
	 */
	public function maybe_render_standalone_wizard() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET['page'] ) || $_GET['page'] !== self::PAGE_SLUG ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$this->current_step = $this->get_current_step();
		$this->render_wizard();
	}

	/**
	 * Maybe redirect to wizard on plugin activation
	 *
	 * The activation transient is an explicit "show the wizard" marker that
	 * `activate_plugin()` only sets for fresh / incomplete setups. An earlier
	 * skip must therefore not block the redirect, otherwise the first
	 * redirect after the very first skip would never fire again — the skip
	 * flag stays persistent, the transient is consumed once.
	 */
	public function maybe_redirect_to_wizard() {
		if ( ! get_transient( 'reportedip_hive_activation_redirect' ) ) {
			return;
		}

		delete_transient( 'reportedip_hive_activation_redirect' );

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( is_network_admin() || isset( $_GET['activate-multi'] ) ) {
			return;
		}

		if ( $this->mode_manager->is_wizard_completed() ) {
			return;
		}

		if ( $this->mode_manager->is_wizard_skipped() ) {
			delete_option( ReportedIP_Hive_Mode_Manager::OPTION_WIZARD_SKIPPED );
		}

		wp_safe_redirect( admin_url( 'admin.php?page=' . self::PAGE_SLUG ) );
		exit;
	}

	/**
	 * Get current wizard step
	 */
	public function get_current_step() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$step = isset( $_GET['step'] ) ? absint( $_GET['step'] ) : 1;
		return max( 1, min( count( $this->get_step_labels() ), $step ) );
	}

	/**
	 * Render the setup wizard as standalone page
	 */
	private function render_wizard() {
		show_admin_bar( false );

		remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
		remove_action( 'wp_print_styles', 'print_emoji_styles' );
		remove_action( 'wp_head', 'wp_admin_bar_header' );
		remove_action( 'wp_footer', 'wp_admin_bar_render', 1000 );

		$this->enqueue_wizard_assets_direct();

		?>
		<!DOCTYPE html>
		<html <?php language_attributes(); ?>>
		<head>
			<meta charset="<?php bloginfo( 'charset' ); ?>">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title><?php esc_html_e( 'ReportedIP Hive Setup', 'reportedip-hive' ); ?></title>
			<?php wp_head(); ?>
		</head>
		<body class="rip-wizard-page rip-setup-wizard">
			<div class="rip-wizard">
				<?php $this->render_wizard_header(); ?>

				<div class="rip-wizard__content">
					<?php $this->render_step_indicator(); ?>
					<?php $this->render_current_step(); ?>
				</div>

				<?php $this->render_wizard_footer(); ?>
			</div>
			<?php wp_footer(); ?>
		</body>
		</html>
		<?php
		exit;
	}

	/**
	 * Enqueue wizard assets directly
	 */
	private function enqueue_wizard_assets_direct() {
		if ( file_exists( REPORTEDIP_HIVE_PLUGIN_DIR . 'assets/css/design-system.css' ) ) {
			wp_enqueue_style(
				'reportedip-hive-design-system',
				REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/design-system.css',
				array(),
				REPORTEDIP_HIVE_VERSION
			);
		}

		wp_enqueue_style(
			'reportedip-hive-wizard',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/wizard.css',
			array(),
			REPORTEDIP_HIVE_VERSION
		);

		wp_enqueue_script( 'jquery-core' );

		wp_enqueue_script(
			'reportedip-hive-wizard',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/wizard.js',
			array( 'jquery' ),
			REPORTEDIP_HIVE_VERSION,
			true
		);

		if ( 8 === $this->current_step && class_exists( 'ReportedIP_Hive_Frontend_Shortcodes' ) ) {
			ReportedIP_Hive_Frontend_Shortcodes::get_instance()->enqueue_frontend_script();
		}

		$saved_key  = (string) get_option( 'reportedip_hive_api_key', '' );
		$saved_tier = class_exists( 'ReportedIP_Hive_Mode_Manager' )
			? ReportedIP_Hive_Mode_Manager::get_instance()->get_current_tier()
			: 'free';

		wp_localize_script(
			'reportedip-hive-wizard',
			'reportedipWizard',
			array(
				'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
				'nonce'         => wp_create_nonce( 'reportedip_wizard_nonce' ),
				'dashboardUrl'  => admin_url( 'admin.php?page=reportedip-hive' ),
				'registerUrl'   => 'https://reportedip.de/register/',
				'wizardBaseUrl' => admin_url( 'admin.php?page=' . self::PAGE_SLUG ),
				'defaults'      => ReportedIP_Hive_Defaults::wizard(),
				'savedApiKey'   => $saved_key,
				'tier'          => $saved_tier,
				'strings'       => array(
					'validating'   => __( 'Checking…', 'reportedip-hive' ),
					'valid'        => __( 'API key is valid!', 'reportedip-hive' ),
					'invalid'      => __( 'Invalid API key.', 'reportedip-hive' ),
					'error'        => __( 'Validation failed.', 'reportedip-hive' ),
					'errorGeneric' => __( 'Error', 'reportedip-hive' ),
					'errorRetry'   => __( 'Error. Please try again.', 'reportedip-hive' ),
					'missingKey'   => __( 'Please enter an API key.', 'reportedip-hive' ),
					'saving'       => __( 'Saving…', 'reportedip-hive' ),
					'saved'        => __( 'Saved!', 'reportedip-hive' ),
					'completing'   => __( 'Finishing setup…', 'reportedip-hive' ),
					'redirecting'  => __( 'Redirecting to dashboard…', 'reportedip-hive' ),
					'noMonitoring' => __( 'No monitoring active — the plugin is effectively disabled.', 'reportedip-hive' ),
					'no2faMethod'  => __( 'Please choose at least one method when 2FA is active.', 'reportedip-hive' ),
					'no2faRole'    => __( 'Please pick at least one role to enforce 2FA for. Administrator was re-selected as a safe default.', 'reportedip-hive' ),
					'confirmSkip'  => __( 'Really skip setup? You can configure the plugin anytime in Settings.', 'reportedip-hive' ),
				),
			)
		);

		wp_set_script_translations(
			'reportedip-hive-wizard',
			'reportedip-hive',
			REPORTEDIP_HIVE_LANGUAGES_DIR
		);
	}

	/**
	 * Render wizard header
	 */
	private function render_wizard_header() {
		?>
		<header class="rip-wizard__header">
			<div class="rip-wizard__logo">
				<svg class="rip-wizard__logo-icon" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
					<path d="M20 4L6 10v10c0 9.2 6.4 17.8 14 20 7.6-2.2 14-10.8 14-20V10L20 4z" fill="currentColor" opacity="0.2"/>
					<path d="M20 4L6 10v10c0 9.2 6.4 17.8 14 20 7.6-2.2 14-10.8 14-20V10L20 4zm0 3.5L31 12v8c0 7.5-5.2 14.5-11 16.5-5.8-2-11-9-11-16.5v-8L20 7.5z" fill="currentColor"/>
					<path d="M18 24l-4-4 1.4-1.4L18 21.2l6.6-6.6L26 16l-8 8z" fill="currentColor"/>
				</svg>
				<span class="rip-wizard__logo-text">ReportedIP Hive</span>
			</div>
			<div class="rip-wizard__header-actions">
				<?php ReportedIP_Hive_Admin_Settings::render_tier_badge(); ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive' ) ); ?>" class="rip-wizard__skip-link" id="rip-skip-wizard">
					<?php esc_html_e( 'Skip setup', 'reportedip-hive' ); ?> →
				</a>
			</div>
		</header>
		<?php
	}

	/**
	 * Render step indicator
	 */
	private function render_step_indicator() {
		$steps = $this->get_step_labels();
		?>
		<div class="rip-wizard__steps">
			<?php foreach ( $steps as $num => $label ) : ?>
				<div class="rip-wizard__step <?php echo $num < $this->current_step ? 'rip-wizard__step--completed' : ''; ?> <?php echo $num === $this->current_step ? 'rip-wizard__step--active' : ''; ?>">
					<div class="rip-wizard__step-number">
						<?php if ( $num < $this->current_step ) : ?>
							<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
						<?php else : ?>
							<?php echo esc_html( $num ); ?>
						<?php endif; ?>
					</div>
					<span class="rip-wizard__step-label"><?php echo esc_html( $label ); ?></span>
				</div>
				<?php if ( $num < count( $steps ) ) : ?>
					<div class="rip-wizard__step-connector <?php echo $num < $this->current_step ? 'rip-wizard__step-connector--completed' : ''; ?>"></div>
				<?php endif; ?>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Render current step content
	 */
	private function render_current_step() {
		?>
		<div class="rip-wizard__step-content" data-step="<?php echo esc_attr( (string) $this->current_step ); ?>">
			<?php
			switch ( $this->current_step ) {
				case 1:
					$this->render_step_welcome();
					break;
				case 2:
					$this->render_step_mode_and_key();
					break;
				case 3:
					$this->render_step_protection();
					break;
				case 4:
					$this->render_step_two_factor();
					break;
				case 5:
					$this->render_step_privacy();
					break;
				case 6:
					$this->render_step_notifications();
					break;
				case 7:
					$this->render_step_hide_login();
					break;
				case 8:
					$this->render_step_promote();
					break;
				case 9:
					$this->render_step_complete();
					break;
			}
			?>
		</div>
		<?php
	}

	/**
	 * Step 1: Welcome
	 */
	private function render_step_welcome() {
		$has_woocommerce = class_exists( 'WooCommerce' );
		$upgrade_url     = REPORTEDIP_HIVE_UPGRADE_URL;
		?>
		<div class="rip-wizard__welcome">
			<div class="rip-wizard__welcome-icon">
				<svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
					<circle cx="40" cy="40" r="38" stroke="currentColor" stroke-width="4" opacity="0.12"/>
					<path d="M40 12L16 22v16c0 14.7 10.2 28.5 24 32 13.8-3.5 24-17.3 24-32V22L40 12z" fill="currentColor" opacity="0.15"/>
					<path d="M40 12L16 22v16c0 14.7 10.2 28.5 24 32 13.8-3.5 24-17.3 24-32V22L40 12zm0 5.6l19 8v12c0 12-8.3 23.2-19 26.4-10.7-3.2-19-14.4-19-26.4v-12l19-8z" fill="currentColor"/>
					<path d="M36 44l-6-6 2.1-2.1 3.9 3.9 9.9-9.9L48 32l-12 12z" fill="currentColor"/>
				</svg>
			</div>

			<h1 class="rip-wizard__title"><?php esc_html_e( 'Welcome to ReportedIP Hive', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle"><?php esc_html_e( 'Set up brute-force protection, community reputation, and 2FA — free forever. With PRO, SMS- and Mail-2FA codes deliver reliably via our managed EU relay (no Twilio account, no SPF/DKIM headaches).', 'reportedip-hive' ); ?></p>

			<div class="rip-wizard__features">
				<div class="rip-wizard__feature">
					<div class="rip-wizard__feature-icon">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					</div>
					<div class="rip-wizard__feature-text">
						<strong><?php esc_html_e( 'Brute-force protection', 'reportedip-hive' ); ?></strong>
						<span><?php esc_html_e( 'Detect and block login, comment and XMLRPC attacks automatically.', 'reportedip-hive' ); ?></span>
					</div>
				</div>
				<div class="rip-wizard__feature">
					<div class="rip-wizard__feature-icon">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
					</div>
					<div class="rip-wizard__feature-text">
						<strong><?php esc_html_e( 'Community reputation', 'reportedip-hive' ); ?></strong>
						<span><?php esc_html_e( 'Optional: share and use threat data from thousands of sites in real time.', 'reportedip-hive' ); ?></span>
					</div>
				</div>
				<div class="rip-wizard__feature">
					<div class="rip-wizard__feature-icon">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					</div>
					<div class="rip-wizard__feature-text">
						<strong><?php esc_html_e( '2FA for admins', 'reportedip-hive' ); ?></strong>
						<span><?php esc_html_e( 'TOTP, email, passkeys and SMS — phishing-resistant and user-friendly.', 'reportedip-hive' ); ?></span>
					</div>
				</div>
				<div class="rip-wizard__feature">
					<div class="rip-wizard__feature-icon">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12l2-2 4 4 8-8 4 4"/><path d="M3 19l4 0M9 19l4 0M15 19l4 0"/></svg>
					</div>
					<div class="rip-wizard__feature-text">
						<strong><?php esc_html_e( 'GDPR-compliant', 'reportedip-hive' ); ?></strong>
						<span><?php esc_html_e( 'Made in Germany, privacy-first defaults, adjustable data retention.', 'reportedip-hive' ); ?></span>
					</div>
				</div>
				<?php if ( $has_woocommerce ) : ?>
				<div class="rip-wizard__feature rip-wizard__feature--woocommerce rip-wizard__feature--full">
					<div class="rip-wizard__feature-icon">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/><path d="M1 1h4l2.7 13.4a2 2 0 0 0 2 1.6h9.7a2 2 0 0 0 2-1.6L23 6H6"/></svg>
					</div>
					<div class="rip-wizard__feature-text">
						<strong><?php esc_html_e( 'WooCommerce login, checkout & frontend 2FA', 'reportedip-hive' ); ?></strong>
						<span><?php esc_html_e( 'Hardens shop login, My Account and checkout against credential stuffing — plus optional second-factor inside the storefront theme so customers never get bounced to wp-login.php.', 'reportedip-hive' ); ?></span>
						<span class="rip-method-card__badges">
							<span class="rip-tier-badge rip-tier-badge--free"><?php esc_html_e( 'Login monitoring: included', 'reportedip-hive' ); ?></span>
							<span class="rip-tier-badge rip-tier-badge--professional"><?php esc_html_e( 'Frontend 2FA: PRO', 'reportedip-hive' ); ?></span>
						</span>
					</div>
				</div>
				<?php endif; ?>
			</div>

			<div class="rip-wizard__tier-teaser">
				<article class="rip-tier-card">
					<header class="rip-tier-card__header">
						<span class="rip-tier-badge rip-tier-badge--professional"><?php esc_html_e( 'PRO', 'reportedip-hive' ); ?></span>
						<h3 class="rip-tier-card__title"><?php esc_html_e( 'Reliable 2FA delivery', 'reportedip-hive' ); ?></h3>
					</header>
					<ul class="rip-tier-card__list">
						<li><?php esc_html_e( 'SMS-2FA: 25/month included (EU-only, anti-fraud capped)', 'reportedip-hive' ); ?></li>
						<li><?php esc_html_e( 'Mail-2FA: 500/month via SPF/DKIM/DMARC-verified relay', 'reportedip-hive' ); ?></li>
						<li><?php esc_html_e( '3 domains per license · 90 days log retention', 'reportedip-hive' ); ?></li>
					</ul>
					<a href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener noreferrer" class="rip-button rip-button--secondary rip-button--sm">
						<?php esc_html_e( 'See plans →', 'reportedip-hive' ); ?>
					</a>
				</article>
				<article class="rip-tier-card">
					<header class="rip-tier-card__header">
						<span class="rip-tier-badge rip-tier-badge--business"><?php esc_html_e( 'Business', 'reportedip-hive' ); ?></span>
						<h3 class="rip-tier-card__title"><?php esc_html_e( 'Agencies & WooCommerce', 'reportedip-hive' ); ?></h3>
					</header>
					<ul class="rip-tier-card__list">
						<li><?php esc_html_e( '15 domains · whitelabel · WooCommerce integration', 'reportedip-hive' ); ?></li>
						<li><?php esc_html_e( 'SMS-2FA: 75/month + prepaid bundles', 'reportedip-hive' ); ?></li>
						<li><?php esc_html_e( 'Mail-2FA: 2,500/month + prepaid bundles · GDPR export tool', 'reportedip-hive' ); ?></li>
					</ul>
					<a href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener noreferrer" class="rip-button rip-button--secondary rip-button--sm">
						<?php esc_html_e( 'See plans →', 'reportedip-hive' ); ?>
					</a>
				</article>
			</div>

			<div class="rip-wizard__actions">
				<a href="<?php echo esc_url( add_query_arg( 'step', 2, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--primary rip-button--large">
					<?php esc_html_e( 'Start setup', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
				</a>
			</div>

			<div class="rip-wizard__import-shortcut">
				<button type="button" class="rip-wizard__import-toggle" id="rip-wizard-import-toggle">
					<?php esc_html_e( 'Already have an export file? Import settings from JSON →', 'reportedip-hive' ); ?>
				</button>

				<form id="rip-wizard-import-form" class="rip-wizard__import-form rip-hidden" method="post" enctype="multipart/form-data">
					<?php wp_nonce_field( 'reportedip_hive_settings_import', '_rip_ie_nonce' ); ?>
					<p class="rip-help-text"><?php esc_html_e( 'Upload a JSON exported from another ReportedIP Hive installation. We apply every section, mark setup as complete and skip ahead.', 'reportedip-hive' ); ?></p>
					<input type="file" name="settings_file" accept="application/json,.json" required />
					<button type="submit" class="rip-button rip-button--secondary"><?php esc_html_e( 'Import & finish', 'reportedip-hive' ); ?></button>
					<div id="rip-wizard-import-status" class="rip-mt-3"></div>
				</form>
			</div>

			<script>
			(function(){
				var toggle = document.getElementById('rip-wizard-import-toggle');
				var form   = document.getElementById('rip-wizard-import-form');
				var status = document.getElementById('rip-wizard-import-status');
				if (!toggle || !form) return;

				toggle.addEventListener('click', function(){ form.classList.toggle('rip-hidden'); });

				form.addEventListener('submit', function(e){
					e.preventDefault();
					if (!window.reportedipWizard || !window.reportedipWizard.ajaxUrl) {
						status.textContent = <?php echo wp_json_encode( __( 'Wizard configuration missing.', 'reportedip-hive' ) ); ?>;
						return;
					}
					var fd = new FormData(form);
					fd.append('action', 'reportedip_wizard_import_settings');
					status.textContent = <?php echo wp_json_encode( __( 'Importing…', 'reportedip-hive' ) ); ?>;
					fetch(window.reportedipWizard.ajaxUrl, {
						method: 'POST',
						credentials: 'same-origin',
						body: fd
					}).then(function(r){ return r.json().catch(function(){ return null; }); }).then(function(resp){
						if (resp && resp.success && resp.data && resp.data.redirect_url) {
							window.location.href = resp.data.redirect_url;
						} else {
							status.textContent = (resp && resp.data && resp.data.message) || <?php echo wp_json_encode( __( 'Import failed.', 'reportedip-hive' ) ); ?>;
						}
					}).catch(function(){
						status.textContent = <?php echo wp_json_encode( __( 'Network error.', 'reportedip-hive' ) ); ?>;
					});
				});
			})();
			</script>
		</div>
		<?php
	}

	/**
	 * Step 2: Mode + API-Key (kombiniert)
	 */
	private function render_step_mode_and_key() {
		$current_mode = $this->mode_manager->get_mode();
		$api_key      = get_option( 'reportedip_hive_api_key', '' );
		?>
		<div class="rip-wizard__mode-select">
			<h1 class="rip-wizard__title"><?php esc_html_e( 'Choose your protection mode', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle"><?php esc_html_e( 'Community mode gives you real-time threat intelligence. Local Shield runs without any external connection.', 'reportedip-hive' ); ?></p>

			<div class="rip-wizard__mode-cards">
				<!-- Local Shield -->
				<div class="rip-mode-card <?php echo 'local' === $current_mode ? 'rip-mode-card--selected' : ''; ?>" data-mode="local">
					<span class="rip-mode-card__check"></span>
					<div class="rip-mode-card__icon rip-mode-card__icon--local">
						<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
							<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4z" fill="currentColor" opacity="0.15"/>
							<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4zm0 4.2l12 6v10c0 8.4-6 16.3-12 18.5-6-2.2-12-10.1-12-18.5v-10l12-6z" fill="currentColor"/>
						</svg>
					</div>
					<h3 class="rip-mode-card__title"><?php esc_html_e( 'Local Shield', 'reportedip-hive' ); ?></h3>
					<p class="rip-mode-card__description"><?php esc_html_e( 'Standalone protection without an external connection. Minimal data use.', 'reportedip-hive' ); ?></p>
					<ul class="rip-mode-card__features">
						<li><svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> <?php esc_html_e( 'Works offline', 'reportedip-hive' ); ?></li>
						<li><svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> <?php esc_html_e( 'No account needed', 'reportedip-hive' ); ?></li>
						<li><svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> <?php esc_html_e( 'Full privacy', 'reportedip-hive' ); ?></li>
						<li><svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> <?php esc_html_e( 'Baseline protection', 'reportedip-hive' ); ?></li>
					</ul>
					<div class="rip-mode-card__badge"><?php esc_html_e( 'Privacy First', 'reportedip-hive' ); ?></div>
				</div>

				<!-- Community Network -->
				<div class="rip-mode-card rip-mode-card--recommended <?php echo 'community' === $current_mode ? 'rip-mode-card--selected' : ''; ?>" data-mode="community">
					<span class="rip-mode-card__check"></span>
					<div class="rip-mode-card__ribbon"><?php esc_html_e( 'Recommended', 'reportedip-hive' ); ?></div>
					<div class="rip-mode-card__icon rip-mode-card__icon--community">
						<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
							<circle cx="24" cy="24" r="18" stroke="currentColor" stroke-width="3" opacity="0.15"/>
							<circle cx="24" cy="24" r="18" stroke="currentColor" stroke-width="3" stroke-dasharray="4 4"/>
							<path d="M4 24h40M24 4c5.5 5.5 8.6 13 8.6 20s-3.1 14.5-8.6 20c-5.5-5.5-8.6-13-8.6-20s3.1-14.5 8.6-20z" stroke="currentColor" stroke-width="3"/>
							<circle cx="24" cy="24" r="6" fill="currentColor"/>
						</svg>
					</div>
					<h3 class="rip-mode-card__title"><?php esc_html_e( 'Community Network', 'reportedip-hive' ); ?></h3>
					<p class="rip-mode-card__description"><?php esc_html_e( 'Thousands of sites share threat intelligence in real time. Maximum strength.', 'reportedip-hive' ); ?></p>
					<ul class="rip-mode-card__features">
						<li><svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> <?php esc_html_e( 'Everything in Local +', 'reportedip-hive' ); ?></li>
						<li><svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> <?php esc_html_e( 'Reputation-based blocking', 'reportedip-hive' ); ?></li>
						<li><svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> <?php esc_html_e( 'Global threat blacklist', 'reportedip-hive' ); ?></li>
						<li><svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg> <?php esc_html_e( 'GDPR-compliant (Made in Germany)', 'reportedip-hive' ); ?></li>
					</ul>
					<div class="rip-mode-card__badge rip-mode-card__badge--community"><?php esc_html_e( 'Free API-Key', 'reportedip-hive' ); ?></div>
				</div>
			</div>

			<input type="hidden" id="rip-selected-mode" name="mode" value="<?php echo esc_attr( $current_mode ); ?>">

			<!-- API-Key card (only shown when Community mode is selected) -->
			<div class="rip-config-card <?php echo 'community' === $current_mode ? '' : 'rip-is-hidden'; ?>" id="rip-api-key-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<h3><?php esc_html_e( 'Community Access Key', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<div class="rip-input-group">
						<input type="text" id="rip-api-key" name="api_key" class="rip-input" placeholder="<?php esc_attr_e( 'Paste API key…', 'reportedip-hive' ); ?>" value="<?php echo esc_attr( $api_key ); ?>">
						<button type="button" id="rip-validate-key" class="rip-button rip-button--secondary">
							<?php esc_html_e( 'Validate', 'reportedip-hive' ); ?>
						</button>
					</div>
					<div id="rip-api-key-status" class="rip-input-status"></div>
					<p class="rip-input-help" id="rip-api-key-gate-hint">
						<?php esc_html_e( 'Validate your API key to continue. Without a valid key, Community mode cannot reach the threat-intelligence service.', 'reportedip-hive' ); ?>
					</p>
					<p class="rip-input-help">
						<?php esc_html_e( 'Don\'t have a key yet?', 'reportedip-hive' ); ?>
						<a href="https://reportedip.de/register/" target="_blank" rel="noopener noreferrer">
							<?php esc_html_e( 'Create a free account', 'reportedip-hive' ); ?> →
						</a>
					</p>

					<div id="rip-api-info" class="rip-help-block rip-help-block--api-info rip-is-hidden">
						<div class="rip-api-info-grid">
							<div class="rip-api-info-item">
								<span class="rip-api-info-label"><?php esc_html_e( 'Key name', 'reportedip-hive' ); ?></span>
								<span class="rip-api-info-value" id="rip-key-name">-</span>
							</div>
							<div class="rip-api-info-item">
								<span class="rip-api-info-label"><?php esc_html_e( 'Account tier', 'reportedip-hive' ); ?></span>
								<span class="rip-api-info-value" id="rip-user-role">-</span>
							</div>
							<div class="rip-api-info-item">
								<span class="rip-api-info-label"><?php esc_html_e( 'Daily limit', 'reportedip-hive' ); ?></span>
								<span class="rip-api-info-value" id="rip-daily-limit">-</span>
							</div>
							<div class="rip-api-info-item">
								<span class="rip-api-info-label"><?php esc_html_e( 'Remaining today', 'reportedip-hive' ); ?></span>
								<span class="rip-api-info-value" id="rip-remaining-calls">-</span>
							</div>
						</div>
					</div>
				</div>
			</div>

			<div class="rip-wizard__actions">
				<a href="<?php echo esc_url( add_query_arg( 'step', 1, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--secondary">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Back', 'reportedip-hive' ); ?>
				</a>
				<button type="button" id="rip-continue-mode" class="rip-button rip-button--primary rip-button--large" disabled>
					<?php esc_html_e( 'Next', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
				</button>
			</div>
		</div>
		<?php
	}

	/**
	 * Step 3: Protection Features
	 */
	private function render_step_protection() {
		?>
		<div class="rip-wizard__configuration">
			<h1 class="rip-wizard__title"><?php esc_html_e( 'Enable protection features', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle"><?php esc_html_e( 'Pick a protection level and decide which attack vectors to monitor. The defaults are a good fit for most sites.', 'reportedip-hive' ); ?></p>

			<!-- Protection Level Preset -->
			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					<h3><?php esc_html_e( 'Protection level', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<div class="rip-protection-levels">
						<label class="rip-protection-level">
							<input type="radio" name="protection_level" value="low">
							<span class="rip-protection-level__content">
								<span class="rip-protection-level__name"><?php esc_html_e( 'Low', 'reportedip-hive' ); ?></span>
								<span class="rip-protection-level__desc"><?php esc_html_e( '10 login failures, 1 hour block', 'reportedip-hive' ); ?></span>
							</span>
						</label>
						<label class="rip-protection-level rip-protection-level--recommended">
							<input type="radio" name="protection_level" value="medium" checked>
							<span class="rip-protection-level__content">
								<span class="rip-protection-level__name"><?php esc_html_e( 'Medium', 'reportedip-hive' ); ?> <small>(<?php esc_html_e( 'Recommended', 'reportedip-hive' ); ?>)</small></span>
								<span class="rip-protection-level__desc"><?php esc_html_e( '5 login failures, 24 hour block', 'reportedip-hive' ); ?></span>
							</span>
						</label>
						<label class="rip-protection-level">
							<input type="radio" name="protection_level" value="high">
							<span class="rip-protection-level__content">
								<span class="rip-protection-level__name"><?php esc_html_e( 'High', 'reportedip-hive' ); ?></span>
								<span class="rip-protection-level__desc"><?php esc_html_e( '3 login failures, 48 hour block', 'reportedip-hive' ); ?></span>
							</span>
						</label>
						<label class="rip-protection-level">
							<input type="radio" name="protection_level" value="paranoid">
							<span class="rip-protection-level__content">
								<span class="rip-protection-level__name"><?php esc_html_e( 'Paranoid', 'reportedip-hive' ); ?></span>
								<span class="rip-protection-level__desc"><?php esc_html_e( '2 login failures, 7 day block', 'reportedip-hive' ); ?></span>
							</span>
						</label>
					</div>
				</div>
			</div>

			<p class="rip-help-block rip-mb-3"><?php esc_html_e( 'The protection level above sets the basic thresholds. The toggles below decide which attack vectors are watched at all — leave them on unless you know you don\'t need a sensor.', 'reportedip-hive' ); ?></p>

			<!-- Authentication monitoring -->
			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<h3><?php esc_html_e( 'Authentication', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<p class="rip-help-block"><?php esc_html_e( 'Stop attackers from guessing passwords or probing usernames.', 'reportedip-hive' ); ?></p>
					<label class="rip-toggle">
						<input type="checkbox" name="monitor_failed_logins" id="rip-monitor-logins" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Failed logins', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-toggle">
						<input type="checkbox" name="monitor_app_passwords" id="rip-monitor-app-passwords" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Application-password abuse (REST/XMLRPC Basic-Auth bypass for 2FA)', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-toggle">
						<input type="checkbox" name="block_user_enumeration" id="rip-block-user-enumeration" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'User-enumeration defence (?author=, /wp-json/wp/v2/users, login-error masking)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
			</div>

			<!-- Content & API abuse -->
			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
					<h3><?php esc_html_e( 'Content & API abuse', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<p class="rip-help-block"><?php esc_html_e( 'Throttle bots that hammer comment forms or APIs.', 'reportedip-hive' ); ?></p>
					<label class="rip-toggle">
						<input type="checkbox" name="monitor_comments" id="rip-monitor-comments" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Spam comments', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-toggle">
						<input type="checkbox" name="monitor_xmlrpc" id="rip-monitor-xmlrpc" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'XMLRPC access (most common attack vector)', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-toggle">
						<input type="checkbox" name="monitor_rest_api" id="rip-monitor-rest-api" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'REST API rate-limit (scrapers, scanners)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
			</div>

			<!-- Behaviour & scanning -->
			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
					<h3><?php esc_html_e( 'Behaviour & scanning', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<p class="rip-help-block"><?php esc_html_e( 'Detect scanners and impossible-travel sign-ins.', 'reportedip-hive' ); ?></p>
					<label class="rip-toggle">
						<input type="checkbox" name="monitor_404_scans" id="rip-monitor-404-scans" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( '404 / scanner detection (.env, wp-config.php.bak, /.git/, …)', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-toggle">
						<input type="checkbox" name="monitor_geo_anomaly" id="rip-monitor-geo-anomaly" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Geographic-anomaly detection on successful logins (forces 2FA from new countries)', 'reportedip-hive' ); ?></span>
					</label>

					<div class="rip-inline-warning" id="rip-monitoring-warning">
						<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
						<span><?php esc_html_e( 'No monitoring active — the plugin is effectively disabled.', 'reportedip-hive' ); ?></span>
					</div>
				</div>
			</div>

			<!-- Auto-Block + Progressive ladder + Report-Only -->
			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
					<h3><?php esc_html_e( 'Automation & special rules', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<p class="rip-help-block"><?php esc_html_e( 'Two-step decision: Auto-blocking decides IF an offender gets blocked at all; the duration strategy decides HOW long. Report-only at the bottom overrides everything — when on, the plugin only watches.', 'reportedip-hive' ); ?></p>

					<label class="rip-toggle">
						<input type="checkbox" name="auto_block" id="rip-auto-block" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Auto-blocking — block suspicious IPs automatically', 'reportedip-hive' ); ?></span>
					</label>

					<div id="rip-block-duration-strategy">
						<h4 class="rip-config-card__subhead">
							<?php esc_html_e( 'Block duration strategy', 'reportedip-hive' ); ?>
							<span class="rip-required" aria-hidden="true">*</span>
						</h4>
						<label class="rip-toggle">
							<input type="checkbox" name="block_escalation_enabled" id="rip-block-escalation" <?php checked( (bool) get_option( 'reportedip_hive_block_escalation_enabled', true ) ); ?>>
							<span class="rip-toggle__slider"></span>
							<span class="rip-toggle__label"><?php esc_html_e( 'Progressive ladder (5 min → 15 min → 30 min → 24 h → 48 h → 7 d) — recommended', 'reportedip-hive' ); ?></span>
						</label>
						<p class="rip-help-block"><?php esc_html_e( 'Each repeat offence inside the reset window (default 30 days) bumps the offender to the next ladder step. First-time tripping legitimate IPs recover in minutes; the ladder can be edited later under Settings → Blocking. Off = a fixed 24 h block for every trigger.', 'reportedip-hive' ); ?></p>
					</div>

					<hr class="rip-helper-divider">

					<label class="rip-toggle">
						<input type="checkbox" name="report_only_mode" id="rip-report-only">
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Report-only mode (observe, do not block)', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-block"><?php esc_html_e( 'Great for testing: the plugin collects events but does not block. Turn off in production.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-wizard__actions">
				<a href="<?php echo esc_url( add_query_arg( 'step', 2, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--secondary">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Back', 'reportedip-hive' ); ?>
				</a>
				<a href="<?php echo esc_url( add_query_arg( 'step', 4, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--primary" id="rip-step3-next">
					<?php esc_html_e( 'Next: 2FA', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
				</a>
			</div>
		</div>
		<?php
	}

	/**
	 * Step 4: 2FA Setup
	 *
	 * PRO+ tiers get SMS + Email + TOTP pre-selected by default since the
	 * managed mail/SMS relay handles delivery without any extra setup. Free
	 * tiers fall back to TOTP + Passkey + Email so users with no relay aren't
	 * pushed towards SMS they cannot fulfil.
	 */
	private function render_step_two_factor() {
		$tier_pro_or_higher = false;
		if ( class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			$mgr = ReportedIP_Hive_Mode_Manager::get_instance();
			if ( $mgr && method_exists( $mgr, 'tier_at_least' ) ) {
				$tier_pro_or_higher = (bool) $mgr->tier_at_least( 'professional' );
			}
		}

		$default_methods = $tier_pro_or_higher
			? array( 'totp', 'email', 'sms' )
			: array( 'totp', 'email', 'webauthn' );

		$saved_methods_raw = get_option( 'reportedip_hive_2fa_allowed_methods', '' );
		$saved_methods     = is_string( $saved_methods_raw ) ? json_decode( $saved_methods_raw, true ) : array();
		if ( ! is_array( $saved_methods ) || empty( $saved_methods ) ) {
			$saved_methods = $default_methods;
		}

		$saved_roles_raw = get_option( 'reportedip_hive_2fa_enforce_roles', '' );
		$saved_roles     = is_string( $saved_roles_raw ) ? json_decode( $saved_roles_raw, true ) : array();
		if ( ! is_array( $saved_roles ) || empty( $saved_roles ) ) {
			$saved_roles = array( 'administrator' );
		}

		$saved_2fa_enabled              = (bool) get_option( 'reportedip_hive_2fa_enabled_global', $tier_pro_or_higher );
		$saved_grace_days               = (int) get_option( 'reportedip_hive_2fa_enforce_grace_days', 7 );
		$saved_max_skips                = (int) get_option( 'reportedip_hive_2fa_max_skips', 3 );
		$saved_trusted_devices          = (bool) get_option( 'reportedip_hive_2fa_trusted_devices', true );
		$saved_frontend_onboarding      = (bool) get_option( 'reportedip_hive_2fa_frontend_onboarding', true );
		$saved_notify_new_device        = (bool) get_option( 'reportedip_hive_2fa_notify_new_device', true );
		$saved_xmlrpc_app_password_only = (bool) get_option( 'reportedip_hive_2fa_xmlrpc_app_password_only', false );

		$method_classes = function ( string $method ) use ( $saved_methods ) {
			return in_array( $method, $saved_methods, true ) ? ' rip-method-card--selected' : '';
		};
		?>
		<div class="rip-wizard__configuration">
			<h1 class="rip-wizard__title"><?php esc_html_e( 'Two-Factor Authentication', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle"><?php esc_html_e( '2FA prevents account takeover — even if a password is stolen. We recommend enforcing 2FA for administrator roles.', 'reportedip-hive' ); ?></p>

			<!-- Global Enable -->
			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/><circle cx="12" cy="16" r="1"/></svg>
					<h3><?php esc_html_e( '2FA system', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<label class="rip-toggle">
						<input type="checkbox" name="2fa_enabled_global" id="rip-2fa-enabled" <?php checked( $saved_2fa_enabled ); ?>>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Enable 2FA (recommended)', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-block"><?php esc_html_e( 'When active, users can configure 2FA in their profile. Admins are guided through onboarding.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<!-- Methods -->
			<div class="rip-config-card" id="rip-2fa-methods-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M9 12l2 2 4-4"/></svg>
					<h3><?php esc_html_e( 'Allowed methods', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<p class="rip-help-block"><?php esc_html_e( 'Pick which factors users may set up. TOTP plus a passkey is a strong default; email is a useful fallback.', 'reportedip-hive' ); ?></p>
					<div class="rip-method-grid" id="rip-2fa-methods">
						<div class="rip-method-card<?php echo esc_attr( $method_classes( 'sms' ) ); ?>" data-method="sms">
							<span class="rip-method-card__check"></span>
							<div class="rip-method-card__badges">
								<span class="rip-tier-badge rip-tier-badge--professional"><?php esc_html_e( 'PRO', 'reportedip-hive' ); ?></span>
								<span class="rip-badge rip-badge--success"><?php esc_html_e( 'Particularly secure', 'reportedip-hive' ); ?></span>
							</div>
							<div class="rip-method-card__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
							</div>
							<h4 class="rip-method-card__title"><?php esc_html_e( 'SMS', 'reportedip-hive' ); ?></h4>
							<p class="rip-method-card__desc"><?php esc_html_e( 'Codes delivered via EU-only relay with anti-fraud caps. PRO includes 25 SMS/month, Business 75. Both tiers can top up with prepaid SMS bundles (50 / 200 / 500). Available with PRO plan.', 'reportedip-hive' ); ?></p>
						</div>

						<div class="rip-method-card<?php echo esc_attr( $method_classes( 'totp' ) ); ?>" data-method="totp">
							<span class="rip-method-card__check"></span>
							<div class="rip-method-card__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="5" y="2" width="14" height="20" rx="2"/><path d="M12 18h.01"/></svg>
							</div>
							<h4 class="rip-method-card__title"><?php esc_html_e( 'TOTP app', 'reportedip-hive' ); ?></h4>
							<p class="rip-method-card__desc"><?php esc_html_e( 'Google Authenticator, Authy, 1Password — standard, offline.', 'reportedip-hive' ); ?></p>
						</div>

						<div class="rip-method-card<?php echo esc_attr( $method_classes( 'webauthn' ) ); ?>" data-method="webauthn">
							<span class="rip-method-card__check"></span>
							<div class="rip-method-card__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2h11"/><circle cx="17" cy="17" r="4"/><path d="M19 19l2 2"/></svg>
							</div>
							<h4 class="rip-method-card__title"><?php esc_html_e( 'Passkey / WebAuthn', 'reportedip-hive' ); ?></h4>
							<p class="rip-method-card__desc"><?php esc_html_e( 'Face ID, Touch ID, Windows Hello, YubiKey — phishing-resistant.', 'reportedip-hive' ); ?></p>
						</div>

						<div class="rip-method-card<?php echo esc_attr( $method_classes( 'email' ) ); ?>" data-method="email">
							<span class="rip-method-card__check"></span>
							<div class="rip-method-card__badges">
								<span class="rip-tier-badge rip-tier-badge--professional"><?php esc_html_e( 'PRO mail relay', 'reportedip-hive' ); ?></span>
							</div>
							<div class="rip-method-card__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
							</div>
							<h4 class="rip-method-card__title"><?php esc_html_e( 'Email', 'reportedip-hive' ); ?></h4>
							<p class="rip-method-card__desc"><?php esc_html_e( 'Code via email — useful as a backup. With PRO mail relay, codes deliver reliably via SPF/DKIM/DMARC.', 'reportedip-hive' ); ?></p>
						</div>
					</div>

					<input type="hidden" id="rip-2fa-methods-input" name="2fa_methods" value="<?php echo esc_attr( implode( ',', array_filter( $saved_methods, 'is_string' ) ) ); ?>">
				</div>
			</div>

			<!-- Enforce Roles -->
			<div class="rip-config-card" id="rip-2fa-roles-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
					<h3>
						<?php esc_html_e( 'Enforce 2FA for which roles?', 'reportedip-hive' ); ?>
						<span class="rip-required" aria-hidden="true">*</span>
					</h3>
				</div>
				<div class="rip-config-card__body">
					<p class="rip-help-block"><?php esc_html_e( 'Pick at least one role. Selected roles must set up 2FA on next sign-in. The grace period and skip counter below cushion the rollout — nobody is locked out on day one.', 'reportedip-hive' ); ?></p>
					<div class="rip-checkbox-row">
						<label class="rip-checkbox-pill">
							<input type="checkbox" name="2fa_enforce_role[]" value="administrator" <?php checked( in_array( 'administrator', $saved_roles, true ) ); ?>>
							<?php esc_html_e( 'Administrators', 'reportedip-hive' ); ?>
						</label>
						<label class="rip-checkbox-pill">
							<input type="checkbox" name="2fa_enforce_role[]" value="editor" <?php checked( in_array( 'editor', $saved_roles, true ) ); ?>>
							<?php esc_html_e( 'Editors', 'reportedip-hive' ); ?>
						</label>
						<label class="rip-checkbox-pill">
							<input type="checkbox" name="2fa_enforce_role[]" value="author" <?php checked( in_array( 'author', $saved_roles, true ) ); ?>>
							<?php esc_html_e( 'Authors', 'reportedip-hive' ); ?>
						</label>
						<label class="rip-checkbox-pill">
							<input type="checkbox" name="2fa_enforce_role[]" value="shop_manager" <?php checked( in_array( 'shop_manager', $saved_roles, true ) ); ?>>
							<?php esc_html_e( 'Shop managers', 'reportedip-hive' ); ?>
						</label>
					</div>

					<hr class="rip-helper-divider">

					<div class="rip-gdpr-select-group">
						<label class="rip-gdpr-select-label" for="rip-2fa-grace-days">
							<?php esc_html_e( 'Grace period (days)', 'reportedip-hive' ); ?>
						</label>
						<div class="rip-number-row">
							<input type="number" id="rip-2fa-grace-days" name="2fa_enforce_grace_days" class="rip-input rip-input--small" value="<?php echo esc_attr( (string) $saved_grace_days ); ?>" min="0" max="60" step="1">
							<span class="rip-number-row__suffix"><?php esc_html_e( 'Days before enforcement kicks in', 'reportedip-hive' ); ?></span>
						</div>
					</div>

					<div class="rip-gdpr-select-group">
						<label class="rip-gdpr-select-label" for="rip-2fa-max-skips">
							<?php esc_html_e( 'Max. skips after the grace period', 'reportedip-hive' ); ?>
						</label>
						<div class="rip-number-row">
							<input type="number" id="rip-2fa-max-skips" name="2fa_max_skips" class="rip-input rip-input--small" value="<?php echo esc_attr( (string) $saved_max_skips ); ?>" min="0" max="20" step="1">
							<span class="rip-number-row__suffix"><?php esc_html_e( 'How many times users may skip 2FA (0 = never)', 'reportedip-hive' ); ?></span>
						</div>
					</div>
				</div>
			</div>

			<!-- Convenience -->
			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12,6 12,12 16,14"/></svg>
					<h3><?php esc_html_e( 'Convenience', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<label class="rip-toggle">
						<input type="checkbox" name="2fa_trusted_devices" id="rip-2fa-trusted-devices" <?php checked( $saved_trusted_devices ); ?>>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Trusted devices (remember for 30 days)', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-toggle">
						<input type="checkbox" name="2fa_frontend_onboarding" id="rip-2fa-frontend-onboarding" <?php checked( $saved_frontend_onboarding ); ?>>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Onboarding on the frontend too (e.g. WooCommerce account)', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-toggle">
						<input type="checkbox" name="2fa_notify_new_device" id="rip-2fa-notify-new-device" <?php checked( $saved_notify_new_device ); ?>>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Email on sign-in from an unknown device', 'reportedip-hive' ); ?></span>
					</label>

					<hr class="rip-helper-divider">

					<label class="rip-toggle">
						<input type="checkbox" name="2fa_xmlrpc_app_password_only" id="rip-2fa-xmlrpc-app-password-only" <?php checked( $saved_xmlrpc_app_password_only ); ?>>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Allow XMLRPC only with application passwords', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-block"><?php esc_html_e( 'Classic XMLRPC body auth is blocked — prevents XMLRPC brute-force attacks against 2FA users.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<?php
			$has_woocommerce        = class_exists( 'WooCommerce' );
			$frontend_status        = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'frontend_2fa' );
			$frontend_locked        = ! $frontend_status['available'];
			$saved_frontend_enabled = (bool) get_option( 'reportedip_hive_2fa_frontend_enabled', false );
			?>
			<?php if ( $has_woocommerce ) : ?>
				<div class="rip-config-card<?php echo $frontend_locked ? ' rip-config-card--disabled' : ''; ?>" id="rip-step4-frontend">
					<div class="rip-config-card__header">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
						<h3><?php esc_html_e( 'Frontend login for WooCommerce', 'reportedip-hive' ); ?></h3>
						<?php if ( $frontend_locked && 'tier' === $frontend_status['reason'] ) : ?>
							&nbsp;<?php ReportedIP_Hive_Admin_Settings::render_tier_lock( $frontend_status, array( 'label' => __( 'PRO', 'reportedip-hive' ) ) ); ?>
						<?php endif; ?>
					</div>
					<div class="rip-config-card__body">
						<p class="rip-help-block">
							<?php esc_html_e( 'Renders the second factor inside the active storefront theme when a customer signs in via My Account, classic checkout or the WooCommerce blocks — instead of bouncing them to wp-login.php.', 'reportedip-hive' ); ?>
						</p>
						<?php if ( $frontend_locked && 'tier' === $frontend_status['reason'] ) : ?>
							<ul class="rip-tier-card__list">
								<li><?php esc_html_e( 'Themed challenge page on the My Account / Checkout slug', 'reportedip-hive' ); ?></li>
								<li><?php esc_html_e( 'Themed onboarding wizard for Customer / Subscriber roles', 'reportedip-hive' ); ?></li>
								<li><?php esc_html_e( 'Cart and checkout state survive the redirect roundtrip', 'reportedip-hive' ); ?></li>
								<li><?php esc_html_e( 'WC Blocks Cart / Checkout error redirect listener', 'reportedip-hive' ); ?></li>
							</ul>
						<?php endif; ?>
						<label class="rip-toggle">
							<input type="checkbox"
								name="2fa_frontend_enabled"
								id="rip-2fa-frontend-enabled"
								<?php checked( $saved_frontend_enabled ); ?>
								<?php echo $frontend_locked ? 'disabled' : ''; ?>>
							<span class="rip-toggle__slider"></span>
							<span class="rip-toggle__label">
								<?php esc_html_e( 'Render the 2FA challenge in the storefront theme frame', 'reportedip-hive' ); ?>
							</span>
						</label>
						<?php if ( $frontend_locked && 'tier' === $frontend_status['reason'] ) : ?>
							<p class="rip-help-block">
								<?php esc_html_e( 'Available with the Professional plan or higher. Finish the wizard now and unlock this later from 2FA settings → Frontend login.', 'reportedip-hive' ); ?>
							</p>
						<?php endif; ?>
					</div>
				</div>
			<?php endif; ?>

			<div class="rip-config-card rip-config-card--note">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
					<h3><?php esc_html_e( 'Login reminder for users without 2FA', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<p class="rip-help-block">
						<?php esc_html_e( 'After this wizard, every user who signs in without an active 2FA method sees a reminder banner. Privileged roles (administrator, editor, shop manager) are forced into 2FA setup after 5 reminders; other roles only see the soft banner so a missing phone never locks anyone out of their account. You can fine-tune the threshold and the role list any time under 2FA settings → Login reminder.', 'reportedip-hive' ); ?>
					</p>
				</div>
			</div>

			<div class="rip-wizard__actions">
				<a href="<?php echo esc_url( add_query_arg( 'step', 3, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--secondary">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Back', 'reportedip-hive' ); ?>
				</a>
				<a href="<?php echo esc_url( add_query_arg( 'step', 5, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--primary" id="rip-step4-next">
					<?php esc_html_e( 'Next: Privacy', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
				</a>
			</div>
		</div>
		<?php
	}

	/**
	 * Step 5: Privacy & GDPR
	 */
	private function render_step_privacy() {
		?>
		<div class="rip-wizard__configuration">
			<h1 class="rip-wizard__title"><?php esc_html_e( 'Privacy & GDPR', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle"><?php esc_html_e( 'The defaults are GDPR-compliant. You can adjust retention and logging depth any time.', 'reportedip-hive' ); ?></p>

			<!-- GDPR-Aufbewahrung -->
			<div class="rip-config-card rip-config-card--gdpr">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/><circle cx="12" cy="16" r="1"/></svg>
					<h3><?php esc_html_e( 'Data retention', 'reportedip-hive' ); ?></h3>
					<span class="rip-config-card__badge-gdpr"><?php esc_html_e( 'EU GDPR', 'reportedip-hive' ); ?></span>
				</div>
				<div class="rip-config-card__body">
					<label class="rip-toggle">
						<input type="checkbox" name="minimal_logging" id="rip-minimal-logging" checked>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Minimal logging — only security-relevant data', 'reportedip-hive' ); ?></span>
					</label>

					<div class="rip-gdpr-selects">
						<div class="rip-gdpr-select-group">
							<label class="rip-gdpr-select-label" for="rip-data-retention">
								<?php esc_html_e( 'Delete logs after', 'reportedip-hive' ); ?>
							</label>
							<select id="rip-data-retention" name="data_retention_days" class="rip-select">
								<option value="7"><?php esc_html_e( '7 days', 'reportedip-hive' ); ?></option>
								<option value="14"><?php esc_html_e( '14 days', 'reportedip-hive' ); ?></option>
								<option value="30" selected><?php esc_html_e( '30 days', 'reportedip-hive' ); ?></option>
								<option value="90"><?php esc_html_e( '90 days', 'reportedip-hive' ); ?></option>
							</select>
						</div>
						<div class="rip-gdpr-select-group">
							<label class="rip-gdpr-select-label" for="rip-auto-anonymize">
								<?php esc_html_e( 'Anonymise personal data after', 'reportedip-hive' ); ?>
							</label>
							<select id="rip-auto-anonymize" name="auto_anonymize_days" class="rip-select">
								<option value="1"><?php esc_html_e( '1 day', 'reportedip-hive' ); ?></option>
								<option value="3"><?php esc_html_e( '3 days', 'reportedip-hive' ); ?></option>
								<option value="7" selected><?php esc_html_e( '7 days', 'reportedip-hive' ); ?></option>
								<option value="14"><?php esc_html_e( '14 days', 'reportedip-hive' ); ?></option>
							</select>
						</div>
					</div>

					<div class="rip-gdpr-notice">
						<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
						<span><?php esc_html_e( 'Defaults are GDPR-compliant. IP addresses are processed under Art. 6(1)(f) GDPR (legitimate interest).', 'reportedip-hive' ); ?></span>
					</div>
				</div>
			</div>

			<!-- Erweitertes Logging (Privacy-impacting) -->
			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg>
					<h3><?php esc_html_e( 'Extended logging', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<label class="rip-toggle">
						<input type="checkbox" name="log_user_agents" id="rip-log-user-agents">
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Log user agents (for forensic analysis)', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-toggle">
						<input type="checkbox" name="log_referer_domains" id="rip-log-referer">
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Log referrer domains', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-block"><?php esc_html_e( 'Both options are off by default for privacy. Enable them only when deeper threat analysis is required.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<!-- Deinstallation -->
			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-2 14a2 2 0 01-2 2H9a2 2 0 01-2-2L5 6"/></svg>
					<h3><?php esc_html_e( 'Uninstall', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<label class="rip-toggle">
						<input type="checkbox" name="delete_data_on_uninstall" id="rip-delete-on-uninstall">
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Delete all data on uninstall', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-block rip-help-block--warning"><?php esc_html_e( 'Only enable this if there is no retention obligation for security logs. Default: off (conservative).', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-wizard__actions">
				<a href="<?php echo esc_url( add_query_arg( 'step', 4, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--secondary">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Back', 'reportedip-hive' ); ?>
				</a>
				<a href="<?php echo esc_url( add_query_arg( 'step', 6, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--primary" id="rip-step5-next">
					<?php esc_html_e( 'Next: Notifications', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
				</a>
			</div>
		</div>
		<?php
	}

	/**
	 * Step 6: Notifications.
	 *
	 * Configurable recipient list (comma- or whitespace-separated), From-name
	 * and From-email for both security alerts and 2FA mails. The same
	 * configuration optionally syncs to the reportedip.de service so the
	 * managed mail relay can mirror the contact set.
	 *
	 * @since 1.5.3
	 */
	private function render_step_notifications() {
		$default_from_name = ReportedIP_Hive_Defaults::NOTIFY_FROM_NAME_DEFAULT;
		$default_from_mail = (string) get_option( 'admin_email', '' );

		$tier_pro_or_higher = false;
		if ( class_exists( 'ReportedIP_Hive_Mode_Manager' ) ) {
			$mgr = ReportedIP_Hive_Mode_Manager::get_instance();
			if ( $mgr && method_exists( $mgr, 'tier_at_least' ) ) {
				$tier_pro_or_higher = (bool) $mgr->tier_at_least( 'professional' );
			}
		}

		$recipients_raw = (string) get_option( 'reportedip_hive_notify_recipients', '' );
		if ( '' === trim( $recipients_raw ) ) {
			$recipients_raw = $default_from_mail;
		}

		$from_name = (string) get_option( 'reportedip_hive_notify_from_name', '' );
		if ( '' === $from_name ) {
			$from_name = $default_from_name;
		}

		$from_email = (string) get_option( 'reportedip_hive_notify_from_email', '' );
		if ( '' === $from_email ) {
			$from_email = $default_from_mail;
		}

		$notify_admin = (bool) get_option( 'reportedip_hive_notify_admin', true );

		$sync_option = get_option( 'reportedip_hive_notify_sync_to_api', null );
		$sync_to_api = null === $sync_option ? $tier_pro_or_higher : (bool) $sync_option;

		$mode = $this->mode_manager->get_mode();
		?>
		<div class="rip-wizard__configuration">
			<h1 class="rip-wizard__title"><?php esc_html_e( 'Notifications', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle"><?php esc_html_e( 'Choose who receives security alerts, and the sender that all plugin mails (alerts and 2FA codes) use.', 'reportedip-hive' ); ?></p>

			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
					<h3><?php esc_html_e( 'Alert recipients', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<label class="rip-toggle">
						<input type="checkbox" name="notify_admin" id="rip-notify-admin" <?php checked( $notify_admin ); ?>>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Send email on new blocks and threshold breaches', 'reportedip-hive' ); ?></span>
					</label>

					<div class="rip-form-group rip-mt-3">
						<label class="rip-label" for="rip-notify-recipients"><?php esc_html_e( 'Recipients', 'reportedip-hive' ); ?></label>
						<textarea
							id="rip-notify-recipients"
							name="recipients"
							class="rip-input rip-input--textarea"
							rows="3"
							placeholder="security@example.com, ops@example.com"
						><?php echo esc_textarea( $recipients_raw ); ?></textarea>
						<p class="rip-help-text"><?php esc_html_e( 'One or more email addresses, separated by commas, spaces or new lines. Invalid entries are dropped on save.', 'reportedip-hive' ); ?></p>
						<p class="rip-help-text rip-validation-line" id="rip-notify-validation" aria-live="polite"></p>
					</div>
				</div>
			</div>

			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16v16H4z"/><path d="M22 6 12 13 2 6"/></svg>
					<h3><?php esc_html_e( 'Sender (used for all plugin mails)', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<p class="rip-help-block"><?php esc_html_e( 'Applies to every plugin mail — security alerts AND 2FA login codes — so both arrive from the same address. Defaults: brand name "ReportedIP" + the WordPress admin email.', 'reportedip-hive' ); ?></p>

					<div class="rip-form-group">
						<label class="rip-label" for="rip-notify-from-name"><?php esc_html_e( 'From name', 'reportedip-hive' ); ?></label>
						<input
							type="text"
							id="rip-notify-from-name"
							name="from_name"
							class="rip-input"
							value="<?php echo esc_attr( $from_name ); ?>"
							placeholder="<?php echo esc_attr( $default_from_name ); ?>"
							maxlength="120"
						>
					</div>

					<div class="rip-form-group rip-mt-3">
						<label class="rip-label" for="rip-notify-from-email"><?php esc_html_e( 'From email', 'reportedip-hive' ); ?></label>
						<input
							type="email"
							id="rip-notify-from-email"
							name="from_email"
							class="rip-input"
							value="<?php echo esc_attr( $from_email ); ?>"
							placeholder="<?php echo esc_attr( $default_from_mail ); ?>"
						>
						<p class="rip-help-text"><?php esc_html_e( 'Should match a domain you own to avoid SPF/DKIM rejections. The mail relay (PRO+) verifies SPF/DKIM/DMARC on your behalf.', 'reportedip-hive' ); ?></p>
					</div>
				</div>
			</div>

			<?php if ( 'community' === $mode ) : ?>
			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
					<h3><?php esc_html_e( 'Sync with reportedip.de', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<label class="rip-toggle">
						<input type="checkbox" name="sync_to_api" id="rip-notify-sync-api" <?php checked( $sync_to_api ); ?>>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Mirror this contact set to my reportedip.de account', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Optional. When on, recipients and From settings are pushed to the service so the relay and account dashboard show the same configuration. Off by default.', 'reportedip-hive' ); ?></p>
				</div>
			</div>
			<?php endif; ?>

			<div class="rip-wizard__actions">
				<a href="<?php echo esc_url( add_query_arg( 'step', 5, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--secondary">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Back', 'reportedip-hive' ); ?>
				</a>
				<button type="button" id="rip-notify-continue" class="rip-button rip-button--primary rip-button--large">
					<?php esc_html_e( 'Save & continue', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
				</button>
			</div>
		</div>

		<script>
		(function(){
			var btn        = document.getElementById('rip-notify-continue');
			var recipients = document.getElementById('rip-notify-recipients');
			var fromName   = document.getElementById('rip-notify-from-name');
			var fromEmail  = document.getElementById('rip-notify-from-email');
			var notifyChk  = document.getElementById('rip-notify-admin');
			var syncChk    = document.getElementById('rip-notify-sync-api');
			var validation = document.getElementById('rip-notify-validation');
			if (!btn) return;

			btn.addEventListener('click', function(e){
				e.preventDefault();
				if (!window.reportedipWizard || !window.reportedipWizard.ajaxUrl) return;
				btn.disabled = true;
				validation.textContent = <?php echo wp_json_encode( __( 'Saving…', 'reportedip-hive' ) ); ?>;
				var data = new FormData();
				data.append('action', 'reportedip_wizard_save_notifications');
				data.append('nonce', window.reportedipWizard.nonce || '');
				data.append('recipients', recipients ? recipients.value : '');
				data.append('from_name', fromName ? fromName.value : '');
				data.append('from_email', fromEmail ? fromEmail.value : '');
				data.append('notify_admin', (notifyChk && notifyChk.checked) ? '1' : '0');
				data.append('sync_to_api', (syncChk && syncChk.checked) ? '1' : '0');
				fetch(window.reportedipWizard.ajaxUrl, { method: 'POST', credentials: 'same-origin', body: data })
					.then(function(r){ return r.json(); })
					.then(function(json){
						if (json && json.success && json.data && json.data.redirect_url) {
							if (json.data.rejected && json.data.rejected.length) {
								validation.textContent = <?php echo wp_json_encode( __( 'Some addresses were dropped: ', 'reportedip-hive' ) ); ?> + json.data.rejected.join(', ');
								btn.disabled = false;
								return;
							}
							window.location.href = json.data.redirect_url;
						} else {
							validation.textContent = (json && json.data && json.data.message) || <?php echo wp_json_encode( __( 'Save failed.', 'reportedip-hive' ) ); ?>;
							btn.disabled = false;
						}
					})
					.catch(function(){
						validation.textContent = <?php echo wp_json_encode( __( 'Network error.', 'reportedip-hive' ) ); ?>;
						btn.disabled = false;
					});
			});
		})();
		</script>
		<?php
	}

	/**
	 * Step 7: Hide Login (optional).
	 *
	 * Lets the user pick a custom slug that replaces wp-login.php. The user
	 * can skip this step entirely — the toggle stays off and the feature is
	 * never enabled.
	 *
	 * @since 1.2.0
	 */
	private function render_step_hide_login() {
		$existing_slug = (string) get_option( 'reportedip_hive_hide_login_slug', '' );
		$existing_mode = (string) get_option( 'reportedip_hive_hide_login_response_mode', ReportedIP_Hive_Hide_Login::RESPONSE_MODE_BLOCK_PAGE );
		$home_url      = trailingslashit( home_url() );
		$suggested     = '' !== $existing_slug
			? $existing_slug
			: ( class_exists( 'ReportedIP_Hive_Hide_Login' )
				? ReportedIP_Hive_Hide_Login::suggest_default_slug()
				: 'wp-secure' );
		?>
		<div class="rip-wizard__configuration">
			<h1 class="rip-wizard__title"><?php esc_html_e( 'Hide your WordPress login', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle"><?php esc_html_e( 'Optional: move wp-login.php behind a custom slug so automated scanners cannot find a login form. You can skip this step and configure it later from Settings.', 'reportedip-hive' ); ?></p>

			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<h3><?php esc_html_e( 'Activate Hide Login', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<div class="rip-gdpr-notice">
						<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
						<span><?php esc_html_e( 'Hiding the URL stops automated scanners — it does not replace strong passwords or 2FA. Use it as one extra layer.', 'reportedip-hive' ); ?></span>
					</div>

					<label class="rip-toggle">
						<input type="checkbox" name="hide_login_enabled" id="rip-hide-login-enabled" <?php checked( '' !== $existing_slug ); ?>>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Enable Hide Login', 'reportedip-hive' ); ?></span>
					</label>

					<div class="rip-form-group rip-mt-3" id="rip-hide-login-fields">
						<label class="rip-label" for="rip-hide-login-slug"><?php esc_html_e( 'Custom slug', 'reportedip-hive' ); ?></label>
						<div class="rip-input-group">
							<span class="rip-input-group__prefix"><?php echo esc_html( $home_url ); ?></span>
							<input type="text" id="rip-hide-login-slug" name="hide_login_slug" value="<?php echo esc_attr( '' !== $existing_slug ? $existing_slug : $suggested ); ?>" class="rip-input rip-input-group__field" placeholder="welcome" autocomplete="off" spellcheck="false">
						</div>
						<p class="rip-help-text"><?php esc_html_e( '3–50 characters: lowercase letters, digits, dashes or underscores. We will reject reserved WordPress paths and existing post/page slugs when you save.', 'reportedip-hive' ); ?></p>
						<p class="rip-help-text rip-validation-line" id="rip-hide-login-validation" aria-live="polite"></p>
					</div>

					<hr class="rip-helper-divider">

					<label class="rip-label"><?php esc_html_e( 'When someone hits the old wp-login.php directly:', 'reportedip-hive' ); ?></label>
					<label class="rip-radio">
						<input type="radio" name="hide_login_response_mode" value="block_page" <?php checked( $existing_mode, 'block_page' ); ?>>
						<span><?php esc_html_e( 'Show the Hive block page (recommended).', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-radio">
						<input type="radio" name="hide_login_response_mode" value="404" <?php checked( $existing_mode, '404' ); ?>>
						<span><?php esc_html_e( 'Show the theme’s 404 page (no plugin fingerprint).', 'reportedip-hive' ); ?></span>
					</label>
				</div>
			</div>

			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
					<h3><?php esc_html_e( 'Recovery if you ever lose the slug', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<p class="rip-help-block"><?php esc_html_e( 'Add this constant to wp-config.php to temporarily disable Hide Login and reach the original wp-login.php again:', 'reportedip-hive' ); ?></p>
					<pre class="rip-codeblock"><code>define( 'REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN', true );</code></pre>
				</div>
			</div>

			<div class="rip-wizard__actions">
				<a href="<?php echo esc_url( add_query_arg( 'step', 6, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--secondary">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Back', 'reportedip-hive' ); ?>
				</a>
				<button type="button" id="rip-save-config" class="rip-button rip-button--primary rip-button--large">
					<?php esc_html_e( 'Save & continue', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/></svg>
				</button>
			</div>
		</div>
		<?php
	}

	/**
	 * Step 8: Promote (optional auto-footer badge).
	 *
	 * Lets the user opt into a small footer badge that links back to
	 * reportedip.de. Variant + alignment + enabled state save in one AJAX
	 * round-trip; the same options are also editable from the Community →
	 * Promote tab in Settings.
	 *
	 * @since 1.5.3
	 */
	private function render_step_promote() {
		$current_enabled = (bool) get_option( 'reportedip_hive_auto_footer_enabled', false );
		$current_variant = class_exists( 'ReportedIP_Hive_Frontend_Shortcodes' )
			? ReportedIP_Hive_Frontend_Shortcodes::sanitize_footer_variant( get_option( 'reportedip_hive_auto_footer_variant', 'badge' ) )
			: 'badge';
		$current_align   = sanitize_key( (string) get_option( 'reportedip_hive_auto_footer_align', 'center' ) );
		if ( ! in_array( $current_align, array( 'left', 'center', 'right', 'below' ), true ) ) {
			$current_align = 'center';
		}
		$skip_url      = admin_url( 'admin.php?page=' . self::PAGE_SLUG . '&step=9' );
		$preview_align = 'below' === $current_align ? 'center' : $current_align;
		?>
		<div class="rip-wizard__configuration">
			<h1 class="rip-wizard__title"><?php esc_html_e( 'You\'re protected. Help others stay protected too.', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle"><?php esc_html_e( 'Your site can show a small badge that links back to ReportedIP. Every link strengthens the community network and helps more sites find this protection. Optional, GDPR-friendly, and you can change it any time.', 'reportedip-hive' ); ?></p>

			<div class="rip-config-card">
				<div class="rip-config-card__header">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
					<h3><?php esc_html_e( 'Live preview', 'reportedip-hive' ); ?></h3>
				</div>
				<div class="rip-config-card__body">
					<div id="rip-promote-preview" class="rip-promote-preview rip-promote-preview--<?php echo esc_attr( $current_align ); ?>">
						<rip-hive-banner
							data-variant="<?php echo esc_attr( $current_variant ); ?>"
							data-stat="attacks_30d"
							data-value=""
							data-label="<?php esc_attr_e( 'Active threat protection', 'reportedip-hive' ); ?>"
							data-mode="local"
							data-theme="dark"
							data-align="<?php echo esc_attr( $preview_align ); ?>"
							data-href="https://reportedip.de/?utm_source=hive&utm_medium=wizard-preview&utm_campaign=protected&utm_content=<?php echo esc_attr( $current_variant ); ?>"
						></rip-hive-banner>
					</div>

					<fieldset class="rip-promote-fieldset">
						<legend class="rip-promote-legend"><?php esc_html_e( 'Variant', 'reportedip-hive' ); ?></legend>
						<label class="rip-radio">
							<input type="radio" name="promote_variant" value="badge" <?php checked( $current_variant, 'badge' ); ?>>
							<span><?php esc_html_e( 'Footer badge — compact pill with logo and label.', 'reportedip-hive' ); ?></span>
						</label>
						<label class="rip-radio">
							<input type="radio" name="promote_variant" value="shield" <?php checked( $current_variant, 'shield' ); ?>>
							<span><?php esc_html_e( 'Shield icon — discreet circle with the shield logo only.', 'reportedip-hive' ); ?></span>
						</label>
					</fieldset>

					<fieldset class="rip-promote-fieldset">
						<legend class="rip-promote-legend"><?php esc_html_e( 'Position', 'reportedip-hive' ); ?></legend>
						<label class="rip-radio">
							<input type="radio" name="promote_align" value="left" <?php checked( $current_align, 'left' ); ?>>
							<span><?php esc_html_e( 'Left edge of the footer', 'reportedip-hive' ); ?></span>
						</label>
						<label class="rip-radio">
							<input type="radio" name="promote_align" value="center" <?php checked( $current_align, 'center' ); ?>>
							<span><?php esc_html_e( 'Centered in the footer', 'reportedip-hive' ); ?></span>
						</label>
						<label class="rip-radio">
							<input type="radio" name="promote_align" value="right" <?php checked( $current_align, 'right' ); ?>>
							<span><?php esc_html_e( 'Right edge of the footer', 'reportedip-hive' ); ?></span>
						</label>
						<label class="rip-radio">
							<input type="radio" name="promote_align" value="below" <?php checked( $current_align, 'below' ); ?>>
							<span><?php esc_html_e( 'Below the theme footer (own row, full width)', 'reportedip-hive' ); ?></span>
						</label>
					</fieldset>

					<label class="rip-toggle rip-promote-toggle">
						<input type="checkbox" id="rip-promote-enabled" name="promote_enabled" <?php checked( $current_enabled ); ?>>
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Show this badge automatically on my site', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-text rip-promote-hint"><?php esc_html_e( 'Renders inside Shadow DOM — your theme cannot break the layout. The link itself is regular HTML, so search engines pick it up.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-wizard__actions">
				<a href="<?php echo esc_url( add_query_arg( 'step', 7, admin_url( 'admin.php?page=' . self::PAGE_SLUG ) ) ); ?>" class="rip-button rip-button--secondary">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Back', 'reportedip-hive' ); ?>
				</a>
				<a href="<?php echo esc_url( $skip_url ); ?>" id="rip-promote-skip" class="rip-button rip-button--secondary">
					<?php esc_html_e( 'Skip this step', 'reportedip-hive' ); ?>
				</a>
				<button type="button" id="rip-promote-continue" class="rip-button rip-button--primary rip-button--large">
					<?php esc_html_e( 'Save & finish', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
				</button>
			</div>
		</div>

		<script>
		(function(){
			var preview = document.getElementById('rip-promote-preview');
			var continueBtn = document.getElementById('rip-promote-continue');
			var skipBtn = document.getElementById('rip-promote-skip');
			var enabledChk = document.getElementById('rip-promote-enabled');
			var variantRadios = document.querySelectorAll('input[name="promote_variant"]');
			var alignRadios = document.querySelectorAll('input[name="promote_align"]');

			var currentAlign = function(){
				var align = 'center';
				alignRadios.forEach(function(r){ if (r.checked) { align = r.value; } });
				return align;
			};

			var renderPreview = function(){
				if (!preview) return;
				var variant = 'badge';
				variantRadios.forEach(function(r){ if (r.checked) { variant = r.value; } });
				var align = currentAlign();
				var elementAlign = align === 'below' ? 'center' : align;
				preview.classList.remove('rip-promote-preview--left', 'rip-promote-preview--center', 'rip-promote-preview--right', 'rip-promote-preview--below');
				preview.classList.add('rip-promote-preview--' + align);
				preview.innerHTML = '';
				var el = document.createElement('rip-hive-banner');
				el.setAttribute('data-variant', variant);
				el.setAttribute('data-stat', 'attacks_30d');
				el.setAttribute('data-value', '');
				el.setAttribute('data-label', <?php echo wp_json_encode( __( 'Active threat protection', 'reportedip-hive' ) ); ?>);
				el.setAttribute('data-mode', 'local');
				el.setAttribute('data-theme', 'dark');
				el.setAttribute('data-align', elementAlign);
				el.setAttribute('data-href', 'https://reportedip.de/?utm_source=hive&utm_medium=wizard-preview&utm_campaign=protected&utm_content=' + variant);
				preview.appendChild(el);
			};

			variantRadios.forEach(function(r){ r.addEventListener('change', renderPreview); });
			alignRadios.forEach(function(r){ r.addEventListener('change', renderPreview); });

			var post = function(action){
				if (continueBtn) continueBtn.disabled = true;
				if (skipBtn) skipBtn.classList.add('disabled');
				var variant = 'badge';
				variantRadios.forEach(function(r){ if (r.checked) { variant = r.value; } });
				var data = new FormData();
				data.append('action', 'reportedip_wizard_save_promote');
				data.append('nonce', (window.reportedipWizard && window.reportedipWizard.nonce) || '');
				data.append('promote_action', action);
				data.append('enabled', (enabledChk && enabledChk.checked) ? '1' : '0');
				data.append('variant', variant);
				data.append('align', currentAlign());
				fetch((window.reportedipWizard && window.reportedipWizard.ajaxUrl) || <?php echo wp_json_encode( admin_url( 'admin-ajax.php' ) ); ?>, {
					method: 'POST',
					credentials: 'same-origin',
					body: data
				}).then(function(r){ return r.json(); }).then(function(json){
					if (json && json.success && json.data && json.data.redirect_url) {
						window.location.href = json.data.redirect_url;
					} else {
						window.location.href = <?php echo wp_json_encode( $skip_url ); ?>;
					}
				}).catch(function(){
					window.location.href = <?php echo wp_json_encode( $skip_url ); ?>;
				});
			};

			if (continueBtn) continueBtn.addEventListener('click', function(e){ e.preventDefault(); post('save'); });
			if (skipBtn) skipBtn.addEventListener('click', function(e){ e.preventDefault(); post('skip'); });
		})();
		</script>
		<?php
	}

	/**
	 * Step 9: Complete / Summary
	 */
	private function render_step_complete() {
		$mode      = $this->mode_manager->get_mode();
		$mode_info = $this->mode_manager->get_mode_info( $mode );

		$retention       = (int) get_option( 'reportedip_hive_data_retention_days', 30 );
		$twofa_enabled   = (bool) get_option( 'reportedip_hive_2fa_enabled_global', false );
		$auto_block      = (bool) get_option( 'reportedip_hive_auto_block', true );
		$minimal_logging = (bool) get_option( 'reportedip_hive_minimal_logging', true );
		$notify_admin    = (bool) get_option( 'reportedip_hive_notify_admin', true );
		$recipients      = ReportedIP_Hive_Defaults::notify_recipients();
		$promote_enabled = (bool) get_option( 'reportedip_hive_auto_footer_enabled', false );
		$promote_variant = (string) get_option( 'reportedip_hive_auto_footer_variant', 'badge' );
		$enforced_roles  = json_decode( get_option( 'reportedip_hive_2fa_enforce_roles', '[]' ), true );
		$enforced_roles  = is_array( $enforced_roles ) ? $enforced_roles : array();

		$twofa_setup_pending = $twofa_enabled && class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' )
			&& ReportedIP_Hive_Two_Factor_Onboarding::user_needs_onboarding( get_current_user_id() );
		?>
		<div class="rip-wizard__complete">
			<div class="rip-wizard__success-icon">
				<svg viewBox="0 0 80 80" fill="none" xmlns="http://www.w3.org/2000/svg">
					<circle cx="40" cy="40" r="36" stroke="currentColor" stroke-width="4" opacity="0.2"/>
					<circle cx="40" cy="40" r="36" stroke="currentColor" stroke-width="4" stroke-dasharray="226" stroke-dashoffset="0" class="rip-success-circle"/>
					<path d="M26 40l10 10 18-18" stroke="currentColor" stroke-width="4" stroke-linecap="round" stroke-linejoin="round" class="rip-success-check"/>
				</svg>
			</div>

			<h1 class="rip-wizard__title"><?php esc_html_e( 'Setup complete!', 'reportedip-hive' ); ?></h1>
			<p class="rip-wizard__subtitle"><?php esc_html_e( 'Your WordPress site is now protected. You can fine-tune all settings any time from the admin menu.', 'reportedip-hive' ); ?></p>

			<div class="rip-wizard__summary">
				<div class="rip-wizard__summary-item" style="--n:1;">
					<span class="rip-wizard__summary-label"><?php esc_html_e( 'Mode', 'reportedip-hive' ); ?></span>
					<span class="rip-mode-badge <?php echo esc_attr( $mode_info['badge_class'] ); ?>">
						<?php echo esc_html( $mode_info['label'] ); ?>
					</span>
				</div>
				<div class="rip-wizard__summary-item" style="--n:2;">
					<span class="rip-wizard__summary-label"><?php esc_html_e( 'Auto-blocking', 'reportedip-hive' ); ?></span>
					<span class="rip-wizard__summary-value">
						<?php echo $auto_block ? esc_html__( 'Active', 'reportedip-hive' ) : esc_html__( 'Inactive', 'reportedip-hive' ); ?>
					</span>
				</div>
				<div class="rip-wizard__summary-item" style="--n:3;">
					<span class="rip-wizard__summary-label"><?php esc_html_e( '2FA', 'reportedip-hive' ); ?></span>
					<span class="rip-wizard__summary-value">
						<?php
						if ( $twofa_enabled ) {
							/* translators: %d: number of enforced roles */
							printf( esc_html__( 'Active (%d roles enforced)', 'reportedip-hive' ), count( $enforced_roles ) );
						} else {
							esc_html_e( 'Off', 'reportedip-hive' );
						}
						?>
					</span>
				</div>
				<div class="rip-wizard__summary-item" style="--n:4;">
					<span class="rip-wizard__summary-label"><?php esc_html_e( 'Retention', 'reportedip-hive' ); ?></span>
					<span class="rip-wizard__summary-value">
						<?php
						/* translators: %d: number of days */
						printf( esc_html( _n( '%d day', '%d days', $retention, 'reportedip-hive' ) ), (int) $retention );
						?>
					</span>
				</div>
				<div class="rip-wizard__summary-item" style="--n:5;">
					<span class="rip-wizard__summary-label"><?php esc_html_e( 'Privacy', 'reportedip-hive' ); ?></span>
					<span class="rip-mode-badge rip-mode-badge--gdpr">
						<?php
						if ( $minimal_logging ) {
							esc_html_e( 'GDPR Minimal', 'reportedip-hive' );
						} else {
							esc_html_e( 'GDPR compliant', 'reportedip-hive' );
						}
						?>
					</span>
				</div>
				<div class="rip-wizard__summary-item" style="--n:6;">
					<span class="rip-wizard__summary-label"><?php esc_html_e( 'Email alerts', 'reportedip-hive' ); ?></span>
					<span class="rip-wizard__summary-value">
						<?php
						if ( $notify_admin && ! empty( $recipients ) ) {
							/* translators: %d: number of notification recipients */
							printf( esc_html( _n( 'On (%d recipient)', 'On (%d recipients)', count( $recipients ), 'reportedip-hive' ) ), count( $recipients ) );
						} elseif ( $notify_admin ) {
							esc_html_e( 'On', 'reportedip-hive' );
						} else {
							esc_html_e( 'Off', 'reportedip-hive' );
						}
						?>
					</span>
				</div>
				<div class="rip-wizard__summary-item" style="--n:7;">
					<span class="rip-wizard__summary-label"><?php esc_html_e( 'Promote', 'reportedip-hive' ); ?></span>
					<span class="rip-wizard__summary-value">
						<?php
						if ( $promote_enabled ) {
							printf(
								/* translators: %s: badge variant name */
								esc_html__( 'Active (%s)', 'reportedip-hive' ),
								'shield' === $promote_variant ? esc_html__( 'shield', 'reportedip-hive' ) : esc_html__( 'badge', 'reportedip-hive' )
							);
						} else {
							esc_html_e( 'Off', 'reportedip-hive' );
						}
						?>
					</span>
				</div>
			</div>

			<div class="rip-wizard__actions">
				<?php if ( $twofa_setup_pending ) : ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive-2fa-onboarding' ) ); ?>" class="rip-button rip-button--secondary">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<?php esc_html_e( 'Set up 2FA for my account now', 'reportedip-hive' ); ?>
				</a>
				<?php endif; ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive' ) ); ?>" class="rip-button rip-button--primary rip-button--large">
					<?php esc_html_e( 'Go to dashboard', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10.293 3.293a1 1 0 011.414 0l6 6a1 1 0 010 1.414l-6 6a1 1 0 01-1.414-1.414L14.586 11H3a1 1 0 110-2h11.586l-4.293-4.293a1 1 0 010-1.414z" clip-rule="evenodd"/></svg>
				</a>
			</div>
		</div>
		<?php
	}

	/**
	 * Render wizard footer (Trust-Badges)
	 */
	private function render_wizard_footer() {
		?>
		<footer class="rip-wizard__footer">
			<div class="rip-wizard__footer-badges rip-trust-badges">
				<span class="rip-wizard__badge rip-trust-badge">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Security Focused', 'reportedip-hive' ); ?>
				</span>
				<span class="rip-wizard__badge rip-trust-badge">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'GDPR Compliant', 'reportedip-hive' ); ?>
				</span>
				<span class="rip-wizard__badge rip-trust-badge">
					<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M3.172 5.172a4 4 0 015.656 0L10 6.343l1.172-1.171a4 4 0 115.656 5.656L10 17.657l-6.828-6.829a4 4 0 010-5.656z" clip-rule="evenodd"/></svg>
					<?php esc_html_e( 'Made in Germany', 'reportedip-hive' ); ?>
				</span>
			</div>
			<p class="rip-wizard__version">
				ReportedIP Hive v<?php echo esc_html( REPORTEDIP_HIVE_VERSION ); ?>
			</p>
		</footer>
		<?php
	}

	/**
	 * AJAX: Save mode selection
	 */
	public function ajax_save_mode() {
		check_ajax_referer( 'reportedip_wizard_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$mode = isset( $_POST['mode'] ) ? sanitize_text_field( wp_unslash( $_POST['mode'] ) ) : '';

		if ( ! in_array( $mode, array( 'local', 'community' ), true ) ) {
			wp_send_json_error( __( 'Invalid mode selected.', 'reportedip-hive' ) );
		}

		$result = $this->mode_manager->set_mode( $mode );

		if ( $result ) {
			wp_send_json_success(
				array(
					'mode'         => $mode,
					'redirect_url' => add_query_arg(
						array(
							'step' => 3,
							'mode' => $mode,
						),
						admin_url( 'admin.php?page=' . self::PAGE_SLUG )
					),
				)
			);
		}

		wp_send_json_error( __( 'Failed to save mode.', 'reportedip-hive' ) );
	}

	/**
	 * AJAX: Validate API key
	 */
	public function ajax_validate_api_key() {
		check_ajax_referer( 'reportedip_wizard_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$api_key = isset( $_POST['api_key'] ) ? sanitize_text_field( wp_unslash( $_POST['api_key'] ) ) : '';

		if ( empty( $api_key ) ) {
			wp_send_json_error( __( 'Please enter an API key.', 'reportedip-hive' ) );
		}

		$api_client = ReportedIP_Hive_API::get_instance();
		$api_client->set_api_key( $api_key );
		$result = $api_client->verify_api_key( $api_key );

		if ( $result && ! empty( $result['valid'] ) ) {
			update_option( 'reportedip_hive_api_key', $api_key );

			wp_send_json_success(
				array(
					'valid'           => true,
					'key_name'        => $result['keyName'] ?? '',
					'user_role'       => $result['userRole'] ?? '',
					'daily_limit'     => $result['dailyApiLimit'] ?? 0,
					'remaining_calls' => $result['remainingApiCalls'] ?? 0,
				)
			);
		}

		wp_send_json_error(
			array(
				'valid'   => false,
				'message' => $result['message'] ?? __( 'Invalid API key.', 'reportedip-hive' ),
			)
		);
	}

	/**
	 * AJAX: complete wizard — saves ALL settings and marks the wizard as completed.
	 */
	public function ajax_complete_wizard() {
		check_ajax_referer( 'reportedip_wizard_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		if ( isset( $_POST['mode'] ) ) {
			$mode = sanitize_text_field( wp_unslash( $_POST['mode'] ) );
			if ( in_array( $mode, array( 'local', 'community' ), true ) ) {
				$this->mode_manager->set_mode( $mode );
			}
		}

		if ( isset( $_POST['api_key'] ) ) {
			$api_key = sanitize_text_field( wp_unslash( $_POST['api_key'] ) );
			if ( ! empty( $api_key ) ) {
				update_option( 'reportedip_hive_api_key', $api_key );
			}
		}

		$protection_level = isset( $_POST['protection_level'] ) ? sanitize_text_field( wp_unslash( $_POST['protection_level'] ) ) : 'medium';
		$presets          = $this->get_protection_presets();
		$preset           = isset( $presets[ $protection_level ] ) ? $presets[ $protection_level ] : $presets['medium'];

		update_option( 'reportedip_hive_failed_login_threshold', $preset['failed_login_threshold'] );
		update_option( 'reportedip_hive_failed_login_timeframe', $preset['failed_login_timeframe'] );
		update_option( 'reportedip_hive_block_duration', $preset['block_duration'] );
		update_option( 'reportedip_hive_block_threshold', $preset['block_threshold'] );

		$protection_defaults = ReportedIP_Hive_Defaults::wizard_protection_defaults();
		foreach ( $protection_defaults as $field => $default_on ) {
			$value = array_key_exists( $field, $_POST )
				? (bool) $_POST[ $field ]
				: (bool) $default_on;
			update_option( 'reportedip_hive_' . $field, $value );
		}

		$twofa_enabled = isset( $_POST['2fa_enabled_global'] ) && (bool) $_POST['2fa_enabled_global'];
		update_option( 'reportedip_hive_2fa_enabled_global', $twofa_enabled );

		$valid_methods = array( 'totp', 'email', 'webauthn', 'sms' );
		$raw_methods   = isset( $_POST['2fa_methods'] ) ? sanitize_text_field( wp_unslash( $_POST['2fa_methods'] ) ) : 'totp,email';
		$methods       = array_values( array_intersect( array_map( 'trim', explode( ',', $raw_methods ) ), $valid_methods ) );
		if ( empty( $methods ) ) {
			$methods = array( 'totp', 'email' );
		}
		update_option( 'reportedip_hive_2fa_allowed_methods', wp_json_encode( $methods ) );

		$valid_roles   = array( 'administrator', 'editor', 'author', 'shop_manager' );
		$posted_roles  = isset( $_POST['2fa_enforce_role'] ) && is_array( $_POST['2fa_enforce_role'] )
			? array_map( 'sanitize_key', wp_unslash( $_POST['2fa_enforce_role'] ) )
			: array();
		$enforce_roles = array_values( array_intersect( $posted_roles, $valid_roles ) );
		if ( $twofa_enabled && empty( $enforce_roles ) ) {
			$enforce_roles = array( 'administrator' );
		}
		update_option( 'reportedip_hive_2fa_enforce_roles', wp_json_encode( $enforce_roles ) );

		update_option( 'reportedip_hive_2fa_trusted_devices', isset( $_POST['2fa_trusted_devices'] ) && (bool) $_POST['2fa_trusted_devices'] );
		update_option( 'reportedip_hive_2fa_frontend_onboarding', isset( $_POST['2fa_frontend_onboarding'] ) && (bool) $_POST['2fa_frontend_onboarding'] );

		$frontend_enabled_desired = isset( $_POST['2fa_frontend_enabled'] ) && (bool) $_POST['2fa_frontend_enabled'];
		if ( $frontend_enabled_desired ) {
			$frontend_status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'frontend_2fa' );
			if ( empty( $frontend_status['available'] ) ) {
				$frontend_enabled_desired = false;
			}
		}
		$frontend_was_on = (bool) get_option( ReportedIP_Hive_Two_Factor_Frontend::OPT_ENABLED, false );
		update_option( ReportedIP_Hive_Two_Factor_Frontend::OPT_ENABLED, $frontend_enabled_desired ? '1' : '' );
		if ( $frontend_was_on !== $frontend_enabled_desired ) {
			ReportedIP_Hive_Two_Factor_Frontend::flush_memo();
			if ( function_exists( 'flush_rewrite_rules' ) ) {
				flush_rewrite_rules( false );
			}
		}
		update_option( 'reportedip_hive_2fa_notify_new_device', isset( $_POST['2fa_notify_new_device'] ) && (bool) $_POST['2fa_notify_new_device'] );
		update_option( 'reportedip_hive_2fa_xmlrpc_app_password_only', isset( $_POST['2fa_xmlrpc_app_password_only'] ) && (bool) $_POST['2fa_xmlrpc_app_password_only'] );

		$grace_days = isset( $_POST['2fa_enforce_grace_days'] ) ? absint( $_POST['2fa_enforce_grace_days'] ) : 7;
		$grace_days = max( 0, min( 60, $grace_days ) );
		update_option( 'reportedip_hive_2fa_enforce_grace_days', $grace_days );

		$max_skips = isset( $_POST['2fa_max_skips'] ) ? absint( $_POST['2fa_max_skips'] ) : 3;
		$max_skips = max( 0, min( 20, $max_skips ) );
		update_option( 'reportedip_hive_2fa_max_skips', $max_skips );

		update_option( 'reportedip_hive_minimal_logging', isset( $_POST['minimal_logging'] ) && (bool) $_POST['minimal_logging'] );

		$retention_days = isset( $_POST['data_retention_days'] ) ? absint( $_POST['data_retention_days'] ) : 30;
		$retention_days = max( 7, min( 365, $retention_days ) );
		update_option( 'reportedip_hive_data_retention_days', $retention_days );

		$anonymize_days = isset( $_POST['auto_anonymize_days'] ) ? absint( $_POST['auto_anonymize_days'] ) : 7;
		$anonymize_days = max( 1, min( 90, $anonymize_days ) );
		update_option( 'reportedip_hive_auto_anonymize_days', $anonymize_days );

		update_option( 'reportedip_hive_log_user_agents', isset( $_POST['log_user_agents'] ) && (bool) $_POST['log_user_agents'] );
		update_option( 'reportedip_hive_log_referer_domains', isset( $_POST['log_referer_domains'] ) && (bool) $_POST['log_referer_domains'] );
		update_option( 'reportedip_hive_delete_data_on_uninstall', isset( $_POST['delete_data_on_uninstall'] ) && (bool) $_POST['delete_data_on_uninstall'] );

		$this->save_hide_login_step();

		$this->apply_safe_defaults();

		$this->mode_manager->mark_wizard_completed();

		if ( $twofa_enabled
			&& class_exists( 'ReportedIP_Hive_Two_Factor_Onboarding' )
			&& class_exists( 'ReportedIP_Hive_Two_Factor' )
		) {
			$current_user = wp_get_current_user();
			if ( $current_user instanceof WP_User
				&& ReportedIP_Hive_Two_Factor::is_enforced_for_user( $current_user )
			) {
				$enabled_methods = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $current_user->ID );
				if ( empty( $enabled_methods ) ) {
					set_transient(
						ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_PREFIX . $current_user->ID,
						1,
						ReportedIP_Hive_Two_Factor_Onboarding::TRANSIENT_TTL
					);
				}
			}
		}

		wp_send_json_success(
			array(
				'message'      => __( 'Setup completed successfully!', 'reportedip-hive' ),
				'redirect_url' => admin_url( 'admin.php?page=' . self::PAGE_SLUG . '&step=8' ),
			)
		);
	}

	/**
	 * Persist the wizard's Hide-Login step into the regular options.
	 *
	 * Validates and stores slug, response mode and the enable toggle. If the
	 * submitted slug fails validation we do not enable the feature — silently
	 * skipping protects the user from a broken state on completion. The
	 * wizard's live AJAX validator is the place to surface error messages.
	 *
	 * @since 1.2.0
	 */
	private function save_hide_login_step(): void {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce is verified by ajax_complete_wizard() before this private helper is reached.
		$wants_enabled = isset( $_POST['hide_login_enabled'] ) && (bool) $_POST['hide_login_enabled'];

		if ( isset( $_POST['hide_login_response_mode'] ) ) {
			$mode        = sanitize_key( wp_unslash( (string) $_POST['hide_login_response_mode'] ) );
			$valid_modes = array(
				ReportedIP_Hive_Hide_Login::RESPONSE_MODE_BLOCK_PAGE,
				ReportedIP_Hive_Hide_Login::RESPONSE_MODE_404,
			);
			if ( in_array( $mode, $valid_modes, true ) ) {
				update_option( 'reportedip_hive_hide_login_response_mode', $mode );
			}
		}

		if ( ! $wants_enabled ) {
			update_option( 'reportedip_hive_hide_login_enabled', false );
			return;
		}

		$raw_slug = isset( $_POST['hide_login_slug'] )
			? sanitize_title( wp_unslash( (string) $_POST['hide_login_slug'] ) )
			: '';
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( '' === $raw_slug || ! class_exists( 'ReportedIP_Hive_Hide_Login' ) ) {
			update_option( 'reportedip_hive_hide_login_enabled', false );
			return;
		}

		$validated = ReportedIP_Hive_Hide_Login::get_instance()->sanitize_slug( $raw_slug );
		if ( '' === $validated || $validated !== $raw_slug ) {
			update_option( 'reportedip_hive_hide_login_enabled', false );
			return;
		}

		update_option( 'reportedip_hive_hide_login_slug', $validated );
		update_option( 'reportedip_hive_hide_login_enabled', true );
		flush_rewrite_rules( false );
	}

	/**
	 * AJAX: validate a candidate login slug live in the wizard.
	 *
	 * Reuses Hide_Login::sanitize_slug which surfaces all error reasons via
	 * add_settings_error. We pull the queue, return the first error to the
	 * client, and otherwise echo the canonicalised slug + final URL.
	 *
	 * @since 1.2.0
	 */
	public function ajax_validate_login_slug() {
		check_ajax_referer( 'reportedip_wizard_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ), 403 );
		}

		if ( ! class_exists( 'ReportedIP_Hive_Hide_Login' ) ) {
			wp_send_json_error( array( 'message' => __( 'Hide Login is unavailable.', 'reportedip-hive' ) ), 500 );
		}

		$raw  = isset( $_POST['slug'] ) ? sanitize_title( wp_unslash( (string) $_POST['slug'] ) ) : '';
		$hide = ReportedIP_Hive_Hide_Login::get_instance();

		$errors_before = count( get_settings_errors( 'reportedip_hive_hide_login_slug' ) );
		$validated     = $hide->sanitize_slug( $raw );
		$all_errors    = get_settings_errors( 'reportedip_hive_hide_login_slug' );
		$new_errors    = array_slice( $all_errors, $errors_before );

		if ( ! empty( $new_errors ) ) {
			wp_send_json_error( array( 'message' => $new_errors[0]['message'] ), 400 );
		}

		if ( '' === $validated || $validated !== $raw ) {
			wp_send_json_error( array( 'message' => __( 'That slug cannot be used.', 'reportedip-hive' ) ), 400 );
		}

		wp_send_json_success(
			array(
				'slug'     => $validated,
				'full_url' => trailingslashit( home_url() ) . $validated,
			)
		);
	}

	/**
	 * AJAX: Skip wizard
	 */
	public function ajax_skip_wizard() {
		check_ajax_referer( 'reportedip_wizard_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$this->mode_manager->skip_wizard();

		if ( ! get_option( 'reportedip_hive_operation_mode' ) ) {
			$this->mode_manager->set_mode( 'local' );
		}

		$this->apply_safe_defaults();

		wp_send_json_success(
			array(
				'message'      => __( 'Setup skipped.', 'reportedip-hive' ),
				'redirect_url' => admin_url( 'admin.php?page=reportedip-hive' ),
			)
		);
	}

	/**
	 * Set all options not asked for in the wizard to conservative defaults —
	 * but only if they do not exist yet. This keeps the DB state predictable
	 * without overwriting existing user values.
	 */
	private function apply_safe_defaults() {
		foreach ( ReportedIP_Hive_Defaults::safe_options() as $option_key => $default_value ) {
			add_option( $option_key, $default_value );
		}
	}

	/**
	 * Protection level presets (shared between UI and AJAX handler)
	 *
	 * @return array
	 */
	private function get_protection_presets() {
		return array(
			'low'      => array(
				'failed_login_threshold' => 10,
				'failed_login_timeframe' => 30,
				'block_duration'         => 1,
				'block_threshold'        => 90,
			),
			'medium'   => array(
				'failed_login_threshold' => 5,
				'failed_login_timeframe' => 15,
				'block_duration'         => 24,
				'block_threshold'        => 75,
			),
			'high'     => array(
				'failed_login_threshold' => 3,
				'failed_login_timeframe' => 15,
				'block_duration'         => 48,
				'block_threshold'        => 50,
			),
			'paranoid' => array(
				'failed_login_threshold' => 2,
				'failed_login_timeframe' => 10,
				'block_duration'         => 168,
				'block_threshold'        => 25,
			),
		);
	}

	/**
	 * Get wizard URL
	 *
	 * @param int $step Step number
	 * @return string Wizard URL
	 */
	public static function get_wizard_url( $step = 1 ) {
		return add_query_arg(
			array(
				'page' => self::PAGE_SLUG,
				'step' => $step,
			),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * Check if we're currently on the wizard page
	 */
	public static function is_wizard_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return isset( $_GET['page'] ) && $_GET['page'] === self::PAGE_SLUG;
	}
}
