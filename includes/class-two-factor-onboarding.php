<?php
/**
 * Two-Factor Onboarding Orchestrator
 *
 * Shows a guided 2FA setup wizard to users who are required to set up 2FA
 * (role-based enforcement) but haven't yet. Supports a configurable skip
 * counter that resets during the admin-defined grace period.
 *
 * Flow:
 *   1. User logs in successfully.
 *   2. wp_login hook detects: 2FA enforced for role + no method configured.
 *   3. Sets a short-lived transient marking the user as "onboarding pending".
 *   4. On admin_init (priority 5): if transient is set and the user is not
 *      already on the onboarding page or an AJAX endpoint, redirect to the
 *      onboarding wizard.
 *   5. User either completes setup (transient cleared, skip counter reset) or
 *      skips (increments counter unless in grace period).
 *   6. Once skip counter >= max_skips AND grace period is over, the
 *      authenticate filter blocks login entirely (see class-two-factor.php).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.4.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Two_Factor_Onboarding
 */
class ReportedIP_Hive_Two_Factor_Onboarding {

	/**
	 * Transient key prefix — marks a user as needing onboarding.
	 */
	const TRANSIENT_PREFIX = 'reportedip_2fa_onboarding_pending_';

	/**
	 * Transient TTL in seconds (1 hour — long enough for a multi-step wizard).
	 */
	const TRANSIENT_TTL = HOUR_IN_SECONDS;

	/**
	 * URL query arg used to route to the onboarding page.
	 */
	const PAGE_SLUG = 'reportedip-hive-2fa-onboarding';

	/**
	 * Constructor — register hooks.
	 */
	public function __construct() {
		if ( ! ReportedIP_Hive_Two_Factor::is_globally_enabled() ) {
			return;
		}

		add_action( 'wp_login', array( $this, 'maybe_flag_for_onboarding' ), 10, 2 );

		add_action( 'admin_init', array( $this, 'maybe_redirect_to_onboarding' ), 5 );
		add_action( 'admin_init', array( $this, 'maybe_render_standalone_page' ), 10 );

		add_action( 'admin_menu', array( $this, 'register_hidden_page' ) );

		add_action( 'wp_ajax_reportedip_hive_2fa_onboarding_skip', array( $this, 'ajax_skip' ) );

		add_action( 'template_redirect', array( $this, 'maybe_frontend_redirect' ) );
	}

	/**
	 * Determine whether the user needs to see the onboarding screen.
	 *
	 * @param int|WP_User $user User ID or object.
	 * @return bool
	 */
	public static function user_needs_onboarding( $user ) {
		$user_id = is_object( $user ) ? $user->ID : (int) $user;
		if ( $user_id <= 0 ) {
			return false;
		}

		$user_obj = is_object( $user ) ? $user : get_userdata( $user_id );
		if ( ! $user_obj ) {
			return false;
		}

		$methods = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user_id );
		if ( ! empty( $methods ) ) {
			return false;
		}

		if ( ReportedIP_Hive_Two_Factor::is_enforced_for_user( $user_obj ) ) {
			return true;
		}

		if ( class_exists( 'ReportedIP_Hive_Two_Factor_Recommend' )
			&& ReportedIP_Hive_Two_Factor_Recommend::should_hard_block( $user_obj ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Return the remaining skip count for a user.
	 *
	 * Returns INF if the user is within the admin-configured grace period
	 * (unlimited skips during the introduction phase).
	 *
	 * @param int $user_id WordPress user ID.
	 * @return float Remaining skips (INF during grace period, otherwise int).
	 */
	public static function get_skips_left( $user_id ) {
		if ( ReportedIP_Hive_Two_Factor::is_in_grace_period( $user_id ) ) {
			return INF;
		}

		$max_skips  = (int) get_option( 'reportedip_hive_2fa_max_skips', 3 );
		$skip_count = (int) get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_SKIP_COUNT, true );
		return max( 0, $max_skips - $skip_count );
	}

	/**
	 * Return the grace period end timestamp (or 0 if none / expired).
	 *
	 * @param int $user_id WordPress user ID.
	 * @return int Unix timestamp.
	 */
	public static function get_grace_deadline( $user_id ) {
		$grace_days = (int) get_option( 'reportedip_hive_2fa_enforce_grace_days', 7 );
		if ( $grace_days <= 0 ) {
			return 0;
		}
		$start = (int) get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_ENFORCEMENT_START, true );
		if ( $start <= 0 ) {
			return 0;
		}
		return $start + ( $grace_days * DAY_IN_SECONDS );
	}

	/**
	 * wp_login callback — flag the user for onboarding if required.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User object.
	 */
	public function maybe_flag_for_onboarding( $user_login, $user ) {
		unset( $user_login );
		if ( ! ( $user instanceof \WP_User ) ) {
			return;
		}
		if ( ! self::user_needs_onboarding( $user ) ) {
			return;
		}

		if ( ! get_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_ENFORCEMENT_START, true ) ) {
			update_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_ENFORCEMENT_START, time() );
		}

		set_transient( self::TRANSIENT_PREFIX . $user->ID, 1, self::TRANSIENT_TTL );
	}

	/**
	 * admin_init callback — redirect to onboarding if pending.
	 */
	public function maybe_redirect_to_onboarding() {
		static $already_ran = false;
		if ( $already_ran ) {
			return;
		}
		$already_ran = true;

		if ( wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}
		if ( ! get_transient( self::TRANSIENT_PREFIX . $user_id ) ) {
			return;
		}
		if ( ! self::user_needs_onboarding( $user_id ) ) {
			delete_transient( self::TRANSIENT_PREFIX . $user_id );
			return;
		}

		$current_page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( self::PAGE_SLUG === $current_page ) {
			return;
		}

		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) ) : '';
		if ( in_array( $script, array( 'wp-login.php', 'admin-ajax.php', 'admin-post.php' ), true ) ) {
			return;
		}

		/**
		 * Opt-out filter — third-party plugins or conditional logic can skip the redirect.
		 *
		 * @param bool $skip    Whether to skip the redirect.
		 * @param int  $user_id WordPress user ID.
		 */
		if ( apply_filters( 'reportedip_2fa_skip_onboarding_redirect', false, $user_id ) ) {
			return;
		}

		wp_safe_redirect( self::get_onboarding_url() );
		exit;
	}

	/**
	 * template_redirect callback — catch users who land on the frontend after login.
	 *
	 * Controlled by the "Enforce onboarding on the frontend" setting (default on).
	 */
	public function maybe_frontend_redirect() {
		if ( is_admin() ) {
			return;
		}
		if ( ! get_option( 'reportedip_hive_2fa_frontend_onboarding', true ) ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}
		if ( ! get_transient( self::TRANSIENT_PREFIX . $user_id ) ) {
			return;
		}
		if ( ! self::user_needs_onboarding( $user_id ) ) {
			delete_transient( self::TRANSIENT_PREFIX . $user_id );
			return;
		}
		if ( apply_filters( 'reportedip_2fa_skip_onboarding_redirect', false, $user_id ) ) {
			return;
		}

		wp_safe_redirect( self::get_onboarding_url() );
		exit;
	}

	/**
	 * Register the hidden admin page — only used for URL routing.
	 * Actual rendering happens in admin_init (see maybe_render_standalone_page).
	 */
	public function register_hidden_page() {
		add_submenu_page(
			'',
			__( 'Set up two-factor', 'reportedip-hive' ),
			__( 'Set up two-factor', 'reportedip-hive' ),
			'read',
			self::PAGE_SLUG,
			'__return_null'
		);
	}

	/**
	 * admin_init callback — render the onboarding page standalone before WP emits
	 * the admin HTML chrome. Mirrors the setup-wizard pattern.
	 */
	public function maybe_render_standalone_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		if ( self::PAGE_SLUG !== $page ) {
			return;
		}
		if ( ! is_user_logged_in() ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		$this->render_page();
	}

	/**
	 * Render the onboarding page (standalone style, no admin chrome).
	 */
	public function render_page() {
		$user_id = get_current_user_id();
		$user    = wp_get_current_user();

		if ( ! self::user_needs_onboarding( $user_id ) ) {
			delete_transient( self::TRANSIENT_PREFIX . $user_id );
			wp_safe_redirect( admin_url() );
			exit;
		}

		show_admin_bar( false );
		remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
		remove_action( 'wp_print_styles', 'print_emoji_styles' );
		remove_action( 'wp_head', 'wp_admin_bar_header' );
		remove_action( 'wp_footer', 'wp_admin_bar_render', 1000 );

		$this->enqueue_assets();

		$skips_left     = self::get_skips_left( $user_id );
		$grace_deadline = self::get_grace_deadline( $user_id );
		$in_grace       = ReportedIP_Hive_Two_Factor::is_in_grace_period( $user_id );

		$allowed_methods = ReportedIP_Hive_Two_Factor::get_allowed_methods();

		$template = REPORTEDIP_HIVE_PLUGIN_DIR . 'templates/two-factor-onboarding.php';
		if ( ! file_exists( $template ) ) {
			wp_die(
				esc_html__( 'Onboarding template is missing.', 'reportedip-hive' ),
				esc_html__( 'Error', 'reportedip-hive' ),
				array( 'response' => 500 )
			);
		}

		$data = array(
			'user'            => $user,
			'allowed_methods' => $allowed_methods,
			'skips_left'      => $skips_left,
			'grace_deadline'  => $grace_deadline,
			'in_grace'        => $in_grace,
			'dashboard_url'   => admin_url(),
		);

		// phpcs:ignore WordPress.PHP.DontExtract.extract_extract
		extract( $data, EXTR_SKIP );
		include $template;
		exit;
	}

	/**
	 * Enqueue CSS/JS for the standalone onboarding page.
	 */
	private function enqueue_assets() {
		$base = REPORTEDIP_HIVE_PLUGIN_URL;
		$ver  = REPORTEDIP_HIVE_VERSION;

		wp_enqueue_style( 'reportedip-hive-design-system', $base . 'assets/css/design-system.css', array(), $ver );
		wp_enqueue_style( 'reportedip-hive-wizard', $base . 'assets/css/wizard.css', array( 'reportedip-hive-design-system' ), $ver );
		wp_enqueue_style( 'reportedip-hive-two-factor', $base . 'assets/css/two-factor.css', array( 'reportedip-hive-design-system' ), $ver );

		wp_enqueue_script(
			'reportedip-hive-qrcode',
			$base . 'assets/vendor/qrcode.min.js',
			array(),
			'1.0.0',
			true
		);

		wp_enqueue_script(
			'reportedip-hive-two-factor-onboarding',
			$base . 'assets/js/two-factor-onboarding.js',
			array( 'jquery', 'reportedip-hive-qrcode' ),
			$ver,
			true
		);

		$user           = wp_get_current_user();
		$skips_left     = self::get_skips_left( $user->ID );
		$grace_deadline = self::get_grace_deadline( $user->ID );

		wp_localize_script(
			'reportedip-hive-two-factor-onboarding',
			'reportedip2faOnboarding',
			array(
				'ajaxUrl'       => admin_url( 'admin-ajax.php' ),
				'nonce'         => wp_create_nonce( 'reportedip_hive_nonce' ),
				'dashboardUrl'  => admin_url(),
				'userId'        => $user->ID,
				'userEmail'     => $user->user_email,
				'maskedEmail'   => ReportedIP_Hive_Two_Factor::mask_email( $user->user_email ),
				'skipsLeft'     => is_infinite( $skips_left ) ? -1 : (int) $skips_left,
				'graceDeadline' => (int) $grace_deadline,
				'strings'       => array(
					'sending'          => __( 'Sending…', 'reportedip-hive' ),
					'sent'             => __( 'Code sent!', 'reportedip-hive' ),
					'verifying'        => __( 'Verifying…', 'reportedip-hive' ),
					'invalid'          => __( 'Invalid code', 'reportedip-hive' ),
					'confirmSkip'      => __( 'Really set up later?', 'reportedip-hive' ),
					'copied'           => __( 'Copied!', 'reportedip-hive' ),
					'passkeyUnsupport' => __( 'Your browser does not support passkeys. Please choose another method.', 'reportedip-hive' ),
					'networkError'     => __( 'Network error. Please try again.', 'reportedip-hive' ),
					'methodTotp'       => __( 'Authenticator app', 'reportedip-hive' ),
					'methodEmail'      => __( 'Email code', 'reportedip-hive' ),
					'methodWebauthn'   => __( 'Passkey', 'reportedip-hive' ),
					'methodSms'        => __( 'SMS', 'reportedip-hive' ),
					'qrLibMissing'     => __( 'QR code library is missing. Please reload the page.', 'reportedip-hive' ),
					'passkeyCreating'  => __( 'Creating passkey…', 'reportedip-hive' ),
					'passkeyDuplicate' => __( 'This passkey is already registered on your account. You can continue with the next method.', 'reportedip-hive' ),
					'passkeyCancelled' => __( 'Passkey creation was cancelled. You can try again or choose another method.', 'reportedip-hive' ),
					'downloaded'       => __( 'Downloaded', 'reportedip-hive' ),
				),
			)
		);

		wp_set_script_translations(
			'reportedip-hive-two-factor-onboarding',
			'reportedip-hive',
			REPORTEDIP_HIVE_LANGUAGES_DIR
		);
	}

	/**
	 * AJAX: skip the onboarding.
	 *
	 * During the grace period, skipping is unlimited and does not increment
	 * the counter. Otherwise, the counter is incremented; if the new value
	 * exceeds max_skips, further skips are refused.
	 */
	public function ajax_skip() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );
		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			wp_send_json_error( array( 'message' => __( 'Not signed in.', 'reportedip-hive' ) ), 401 );
		}

		if ( ! self::user_needs_onboarding( $user_id ) ) {
			delete_transient( self::TRANSIENT_PREFIX . $user_id );
			wp_send_json_success(
				array(
					'message'  => __( 'Onboarding is no longer required.', 'reportedip-hive' ),
					'redirect' => admin_url(),
				)
			);
		}

		$in_grace = ReportedIP_Hive_Two_Factor::is_in_grace_period( $user_id );

		if ( ! $in_grace ) {
			$max_skips  = (int) get_option( 'reportedip_hive_2fa_max_skips', 3 );
			$skip_count = (int) get_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_SKIP_COUNT, true );

			if ( $skip_count >= $max_skips && $max_skips > 0 ) {
				wp_send_json_error(
					array(
						'message' => __( 'Skip quota exhausted. Please set up 2FA now or contact an administrator.', 'reportedip-hive' ),
					),
					403
				);
			}

			update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_SKIP_COUNT, $skip_count + 1 );
		}

		delete_transient( self::TRANSIENT_PREFIX . $user_id );

		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->info(
			'2FA onboarding skipped',
			ReportedIP_Hive::get_client_ip(),
			array(
				'user_id'      => $user_id,
				'in_grace'     => $in_grace,
				'skip_counted' => ! $in_grace,
			)
		);

		$redirect = admin_url();
		$req      = isset( $_POST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_POST['redirect_to'] ) ) : '';
		if ( $req ) {
			$redirect = wp_validate_redirect( $req, $redirect );
		}

		wp_send_json_success(
			array(
				'message'  => __( 'Onboarding postponed.', 'reportedip-hive' ),
				'redirect' => $redirect,
			)
		);
	}

	/**
	 * Get the canonical onboarding URL.
	 *
	 * @return string
	 */
	public static function get_onboarding_url() {
		return admin_url( 'admin.php?page=' . self::PAGE_SLUG );
	}
}
