<?php
/**
 * Plugin Name: ReportedIP Hive
 * Plugin URI: https://reportedip.de
 * Description: Community-powered WordPress security — real-time threat intelligence with 5-layer defense and 4-method 2FA. Be part of the hive.
 * Version: 1.7.1
 * Author: Patrick Schlesinger, ReportedIP
 * Author URI: https://reportedip.de
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: reportedip-hive
 * Domain Path: /languages
 * Requires at least: 5.0
 * Tested up to: 6.9
 * Requires PHP: 8.1
 * Update URI: https://github.com/reportedip/reportedip-hive
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.0.0
 *
 * Copyright (c) 2025-2026 Patrick Schlesinger, ReportedIP. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Composer autoloader (loads plugin-update-checker and any other dependencies).
 */
$reportedip_autoload = __DIR__ . '/vendor/autoload.php';
if ( file_exists( $reportedip_autoload ) ) {
	require_once $reportedip_autoload;
}

use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

define( 'REPORTEDIP_HIVE_VERSION', '1.7.1' );
define( 'REPORTEDIP_HIVE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'REPORTEDIP_HIVE_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'REPORTEDIP_HIVE_PLUGIN_FILE', __FILE__ );
define( 'REPORTEDIP_HIVE_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'REPORTEDIP_HIVE_LANGUAGES_DIR', REPORTEDIP_HIVE_PLUGIN_DIR . 'languages' );
define( 'REPORTEDIP_USER_AGENT_MAX_LENGTH', 50 );
define( 'REPORTEDIP_QUEUE_BATCH_SIZE', 20 );
define( 'REPORTEDIP_MAX_CSV_UPLOAD_SIZE', 1048576 );
define( 'REPORTEDIP_MAX_SETTINGS_UPLOAD_SIZE', 524288 );

/*
 * External URLs (can be overridden via the 'reportedip_hive_external_url' filter).
 */
define( 'REPORTEDIP_HIVE_SITE_URL', 'https://reportedip.de' );
define( 'REPORTEDIP_HIVE_UPGRADE_URL', 'https://reportedip.de/dashboard/' );
define( 'REPORTEDIP_HIVE_CONTACT_MAIL', 'ps@cms-admins.de' );
define( 'REPORTEDIP_HIVE_HONEYPOT_URL', 'https://reportedip.de/docs/honeypot-server/' );
define( 'REPORTEDIP_HIVE_FAQ_URL', 'https://reportedip.de/faq/' );
define( 'REPORTEDIP_HIVE_REGISTER_URL', 'https://reportedip.de/register/' );

/**
 * Update checker: reads releases from the public GitHub repository.
 * Trigger: tag `vX.Y.Z` → GitHub Action builds ZIP release asset → PUC pulls it.
 */
if ( class_exists( PucFactory::class ) ) {
	$reportedip_update_checker = PucFactory::buildUpdateChecker(
		'https://github.com/reportedip/reportedip-hive/',
		__FILE__,
		'reportedip-hive'
	);
	$reportedip_update_checker->setBranch( 'main' );

	$reportedip_vcs_api = $reportedip_update_checker->getVcsApi();
	if ( $reportedip_vcs_api instanceof \YahnisElsts\PluginUpdateChecker\v5p6\Vcs\GitHubApi ) {
		$reportedip_vcs_api->enableReleaseAssets( '/reportedip-hive\.zip$/i' );
	}
}

/**
 * Main ReportedIP Hive Class
 */
class ReportedIP_Hive {

	/**
	 * Single instance of the class
	 */
	private static $instance = null;

	/**
	 * API client
	 */
	private $api_client;

	/**
	 * Security monitor
	 */
	private $security_monitor;

	/**
	 * IP manager
	 */
	private $ip_manager;

	/**
	 * Logger
	 */
	private $logger;

	/**
	 * Cron handler
	 */
	private $cron_handler;

	/**
	 * Mode Manager
	 */
	private $mode_manager;

	/**
	 * Request-level cache: IPs known to be blocked during this request.
	 * Prevents repeated DB queries when the same IP triggers hundreds
	 * of hooks in a single request (e.g. XMLRPC system.multicall).
	 *
	 * @var array<string, bool>
	 */
	private $blocked_ip_cache = array();

	/**
	 * Get single instance
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor
	 */
	private function __construct() {
		$this->load_dependencies();
		$this->init_hooks();
	}

	/**
	 * Initialize WordPress hooks
	 * Note: Activation/deactivation hooks are registered outside the class
	 * to ensure they work properly before plugins_loaded
	 */
	private function init_hooks() {
		add_action( 'init', array( $this, 'init' ), 1 );
		add_action( 'admin_enqueue_scripts', array( $this, 'admin_enqueue_scripts' ) );

		if ( get_option( 'reportedip_hive_disable_xmlrpc_multicall', true ) ) {
			add_filter( 'xmlrpc_methods', array( $this, 'disable_xmlrpc_multicall' ) );
		}

		add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ) );
		add_action( 'wp_authenticate_user', array( $this, 'pre_auth_check' ), 10, 2 );
		add_action( 'comment_post', array( $this, 'handle_comment_post' ), 10, 3 );
		add_action( 'xmlrpc_call', array( $this, 'handle_xmlrpc_call' ) );
		add_action( 'wp_login', array( $this, 'handle_successful_login' ), 10, 2 );

		add_action( 'admin_init', array( $this, 'block_admin_access' ) );
		add_action( 'admin_notices', array( $this, 'display_api_status_notices' ) );

		add_action( 'admin_head', array( $this, 'suppress_foreign_notices_on_plugin_pages' ) );

		add_action( 'wp_ajax_reportedip_get_chart_data', array( $this, 'ajax_get_chart_data' ) );

		if ( is_admin() ) {
			new ReportedIP_Hive_Ajax_Handler( $this );
		}
	}

	/**
	 * Load plugin dependencies
	 */
	private function load_dependencies() {
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-defaults.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-block-escalation.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-database.php';

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-logger.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-cache.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-mode-manager.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-api-client.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-security-monitor.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-ip-manager.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-cron-handler.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-hide-login.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-app-password-monitor.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-rest-monitor.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-user-enumeration.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-scan-detector.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-woocommerce-monitor.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-geo-anomaly.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-password-strength.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-phone-validator.php';

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/interface-mail-provider.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/mail-providers/class-mail-provider-wordpress.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/mail-providers/class-mail-provider-relay.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-mailer.php';

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-crypto.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-totp.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-email.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-recovery.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-reset-gate.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-onboarding.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-notifications.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-sms.php';
		ReportedIP_Hive_Two_Factor_SMS::load_providers();
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-webauthn.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-rest.php';

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-tier-upgrade.php';
		ReportedIP_Hive_Tier_Upgrade::init();

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-recommend.php';
		ReportedIP_Hive_Two_Factor_Recommend::init();

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-frontend.php';
		ReportedIP_Hive_Two_Factor_Frontend::init();

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-wc-notice.php';
		ReportedIP_Hive_Two_Factor_WC_Notice::init();

		if ( is_admin() ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-dashboard.php';
		}

		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-cli.php';
		}

		if ( is_admin() ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-ajax-handler.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-admin-settings.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-two-factor-admin.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-logs-table.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-blocked-ips-table.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-whitelist-table.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-api-queue-table.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-settings-import-export.php';
		}

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-frontend-shortcodes.php';
		ReportedIP_Hive_Frontend_Shortcodes::get_instance();

		$db = ReportedIP_Hive_Database::get_instance();
		$db->maybe_update_schema();

		$this->mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();

		if ( is_admin() ) {
			new ReportedIP_Hive_Admin_Settings();
			ReportedIP_Hive_Settings_Import_Export::get_instance();

			if ( file_exists( REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-setup-wizard.php' ) ) {
				require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-setup-wizard.php';
				new ReportedIP_Hive_Setup_Wizard( $this->mode_manager );
			}
		}

		ReportedIP_Hive_Database::get_instance();
		$this->api_client = ReportedIP_Hive_API::get_instance();
		ReportedIP_Hive_Hide_Login::get_instance();
		$this->security_monitor = new ReportedIP_Hive_Security_Monitor();
		$this->ip_manager       = ReportedIP_Hive_IP_Manager::get_instance();
		$this->logger           = ReportedIP_Hive_Logger::get_instance();
		$this->cron_handler     = new ReportedIP_Hive_Cron_Handler( $this->security_monitor );

		ReportedIP_Hive_App_Password_Monitor::get_instance();
		ReportedIP_Hive_REST_Monitor::get_instance();
		ReportedIP_Hive_User_Enumeration::get_instance();
		ReportedIP_Hive_Scan_Detector::get_instance();
		ReportedIP_Hive_WooCommerce_Monitor::get_instance();
		ReportedIP_Hive_Geo_Anomaly::get_instance();
		ReportedIP_Hive_Password_Strength::get_instance();
		new ReportedIP_Hive_Two_Factor();
		new ReportedIP_Hive_Two_Factor_Reset_Gate();

		new ReportedIP_Hive_Two_Factor_Onboarding();

		new ReportedIP_Hive_Two_Factor_Notifications();

		new ReportedIP_Hive_Two_Factor_WebAuthn();

		new ReportedIP_Hive_Two_Factor_REST();

		if ( is_admin() ) {
			new ReportedIP_Hive_Two_Factor_Admin();
			new ReportedIP_Hive_Two_Factor_Dashboard();
		}
	}

	/**
	 * Static plugin activation (called from register_activation_hook)
	 */
	public static function activate_plugin() {
		if ( ! class_exists( 'ReportedIP_Hive_Database' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-database.php';
		}

		$database = new ReportedIP_Hive_Database();
		$database->create_tables();
		update_option( ReportedIP_Hive_Database::DB_VERSION_OPTION, ReportedIP_Hive_Database::DB_VERSION );

		if ( ! get_option( 'reportedip_hive_activated_at' ) ) {
			update_option( 'reportedip_hive_activated_at', time(), false );
		}

		self::set_default_options_static();

		if ( ! class_exists( 'ReportedIP_Hive_Cron_Handler' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-cron-handler.php';
		}
		ReportedIP_Hive_Cron_Handler::schedule_cron_jobs_static();

		/*
		 * Fresh install only (no completed wizard, no API key): mark for the
		 * post-activation redirect. 5-minute window so the admin still gets
		 * the wizard if they click around the dashboard before opening the
		 * plugin. The transient is consumed on the first admin_init that
		 * hits the redirect handler.
		 */
		$wizard_completed = get_option( 'reportedip_hive_wizard_completed', false );
		$api_key          = get_option( 'reportedip_hive_api_key', '' );

		if ( ! $wizard_completed && empty( $api_key ) ) {
			set_transient( 'reportedip_hive_activation_redirect', true, 5 * MINUTE_IN_SECONDS );
		}

		flush_rewrite_rules();
	}

	/**
	 * Get Mode Manager instance
	 *
	 * @return ReportedIP_Hive_Mode_Manager
	 */
	public function get_mode_manager() {
		if ( null === $this->mode_manager ) {
			$this->mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		}
		return $this->mode_manager;
	}

	/**
	 * Get Security Monitor instance
	 *
	 * @return ReportedIP_Hive_Security_Monitor
	 */
	public function get_security_monitor() {
		return $this->security_monitor;
	}

	/**
	 * Static plugin deactivation (called from register_deactivation_hook)
	 */
	public static function deactivate_plugin() {
		if ( ! class_exists( 'ReportedIP_Hive_Cron_Handler' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-cron-handler.php';
		}
		ReportedIP_Hive_Cron_Handler::clear_cron_jobs_static();
		flush_rewrite_rules();
	}

	/**
	 * Plugin uninstall
	 */
	public static function uninstall() {
		if ( get_option( 'reportedip_hive_delete_data_on_uninstall', false ) ) {
			$database = new ReportedIP_Hive_Database();
			$database->drop_tables();

			self::delete_plugin_options();

			/*
			 * Clean up 2FA user meta for all users — single source of truth is
			 * ReportedIP_Hive_Two_Factor::get_all_meta_keys(). Load the class
			 * if it isn't already, because uninstall runs in a stripped context.
			 */
			if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
				require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-recovery.php';
				require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor.php';
			}
			foreach ( ReportedIP_Hive_Two_Factor::get_all_meta_keys() as $key ) {
				delete_metadata( 'user', 0, $key, '', true );
			}
		}
	}

	/**
	 * Initialize plugin
	 *
	 * Translations are loaded automatically by WordPress 4.6+ via the
	 * `Text Domain` plugin header, so no explicit `load_plugin_textdomain()` call is needed.
	 */
	public function init() {
		$this->check_ip_access();
	}

	/**
	 * Disable XMLRPC system.multicall to prevent bundled brute-force attacks.
	 * A single multicall request can contain hundreds of login attempts that
	 * bypass per-request IP blocking.
	 *
	 * @param array $methods Available XMLRPC methods.
	 * @return array Filtered methods without system.multicall.
	 */
	public function disable_xmlrpc_multicall( $methods ) {
		unset( $methods['system.multicall'] );
		return $methods;
	}

	/**
	 * Check if IP is blocked with request-level caching.
	 * Prevents repeated DB queries when the same IP triggers many hooks
	 * in a single request (e.g. remaining XMLRPC calls after blocking).
	 *
	 * @param string $ip_address IP to check.
	 * @return bool True if IP is blocked.
	 */
	private function is_ip_blocked_cached( $ip_address ) {
		if ( isset( $this->blocked_ip_cache[ $ip_address ] ) ) {
			return $this->blocked_ip_cache[ $ip_address ];
		}

		$blocked                               = $this->ip_manager->is_blocked( $ip_address );
		$this->blocked_ip_cache[ $ip_address ] = $blocked;

		return $blocked;
	}

	/**
	 * Mark IP as blocked in request-level cache.
	 * Called after auto_block_ip succeeds so subsequent hooks in the
	 * same request short-circuit without DB queries.
	 *
	 * @param string $ip_address IP to mark as blocked.
	 */
	public function mark_ip_blocked( $ip_address ) {
		$this->blocked_ip_cache[ $ip_address ] = true;
	}

	/**
	 * Enqueue admin scripts
	 */
	public function admin_enqueue_scripts( $hook ) {
		if ( empty( $hook ) || strpos( (string) $hook, 'reportedip-hive' ) === false ) {
			return;
		}

		wp_enqueue_style(
			'reportedip-hive-design-system',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/design-system.css',
			array(),
			REPORTEDIP_HIVE_VERSION
		);

		wp_enqueue_style(
			'reportedip-hive-dashboard',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/dashboard.css',
			array( 'reportedip-hive-design-system' ),
			REPORTEDIP_HIVE_VERSION
		);

		wp_enqueue_style(
			'reportedip-hive-admin',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/admin.css',
			array( 'reportedip-hive-design-system' ),
			REPORTEDIP_HIVE_VERSION
		);

		wp_enqueue_script(
			'reportedip-hive-admin',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/admin.js',
			array( 'jquery' ),
			REPORTEDIP_HIVE_VERSION,
			true
		);

		if ( str_contains( (string) $hook, 'reportedip-hive-settings' ) ) {
			wp_enqueue_script(
				'reportedip-hive-settings-import-export',
				REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/settings-import-export.js',
				array( 'jquery', 'reportedip-hive-admin' ),
				REPORTEDIP_HIVE_VERSION,
				true
			);
		}

		wp_localize_script(
			'reportedip-hive-admin',
			'reportedip_hive_ajax',
			array(
				'ajax_url' => admin_url( 'admin-ajax.php' ),
				'nonce'    => wp_create_nonce( 'reportedip_hive_nonce' ),
				'strings'  => array(
					'testing_connection'      => __( 'Testing connection...', 'reportedip-hive' ),
					'connection_successful'   => __( 'Connection successful!', 'reportedip-hive' ),
					'connection_failed'       => __( 'Connection failed!', 'reportedip-hive' ),
					'confirm_unblock'         => __( 'Are you sure you want to unblock this IP?', 'reportedip-hive' ),
					'confirm_whitelist'       => __( 'Are you sure you want to whitelist this IP?', 'reportedip-hive' ),
					'confirm_reset_settings'  => __( 'Are you sure you want to reset all settings to defaults?', 'reportedip-hive' ),
					'confirm_uninstall_warn'  => __( 'WARNING: This will delete ALL plugin data including logs, blocked IPs, and whitelist entries. This cannot be undone!', 'reportedip-hive' ),
					'confirm_uninstall_final' => __( 'Are you absolutely sure?', 'reportedip-hive' ),
					'prompt_whitelist_reason' => __( 'Enter reason for whitelisting (optional):', 'reportedip-hive' ),
					'prompt_block_reason'     => __( 'Enter reason for blocking this IP:', 'reportedip-hive' ),
					'prompt_block_default'    => __( 'Blocked from security logs', 'reportedip-hive' ),
					'prompt_export_days'      => __( 'Export logs from how many days? (default: 30)', 'reportedip-hive' ),
					'db_connection_ok'        => __( 'Database connection successful!', 'reportedip-hive' ),
					'request_failed'          => __( 'Request failed. Check server logs.', 'reportedip-hive' ),
					'generic_error'           => __( 'Error', 'reportedip-hive' ),
				),
			)
		);

		wp_set_script_translations(
			'reportedip-hive-admin',
			'reportedip-hive',
			REPORTEDIP_HIVE_LANGUAGES_DIR
		);

		if ( $hook === 'toplevel_page_reportedip-hive' ) {
			wp_enqueue_script(
				'chartjs',
				REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/chart.min.js',
				array(),
				'4.4.1',
				true
			);

			wp_enqueue_script(
				'reportedip-hive-charts',
				REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/charts.js',
				array( 'jquery', 'chartjs' ),
				REPORTEDIP_HIVE_VERSION,
				true
			);

			wp_localize_script( 'reportedip-hive-charts', 'reportedipCharts', $this->get_chart_data() );

			wp_set_script_translations(
				'reportedip-hive-charts',
				'reportedip-hive',
				REPORTEDIP_HIVE_LANGUAGES_DIR
			);
		}
	}

	/**
	 * AJAX handler for fetching chart data with dynamic period
	 */
	public function ajax_get_chart_data() {
		check_ajax_referer( 'reportedip_charts_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Unauthorized' );
		}

		$days = isset( $_POST['days'] ) ? absint( $_POST['days'] ) : 7;
		$data = $this->get_chart_data( $days );

		wp_send_json_success( $data['data'] );
	}

	/**
	 * Get chart data for dashboard
	 *
	 * @return array Chart data and configuration
	 */
	public function get_chart_data( $days = 7 ) {
		$mode_manager = $this->get_mode_manager();

		$days = in_array( (int) $days, array( 7, 30 ), true ) ? (int) $days : 7;

		$labels         = array();
		$failed_logins  = array();
		$blocked_ips    = array();
		$comment_spam   = array();
		$xmlrpc_events  = array();
		$admin_scanning = array();

		global $wpdb;
		$logs_table = $wpdb->prefix . 'reportedip_hive_logs';
		$cutoff_utc = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from $wpdb->prefix and a hardcoded constant; safe.
		$log_stats = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE(created_at) as stat_date,
					SUM(CASE WHEN event_type LIKE %s THEN 1 ELSE 0 END) as failed_logins,
					SUM(CASE WHEN event_type LIKE %s OR event_type LIKE %s OR event_type LIKE %s THEN 1 ELSE 0 END) as blocked_ips,
					SUM(CASE WHEN event_type LIKE %s OR event_type LIKE %s THEN 1 ELSE 0 END) as comment_spam,
					SUM(CASE WHEN event_type LIKE %s THEN 1 ELSE 0 END) as xmlrpc_events,
					SUM(CASE WHEN event_type LIKE %s OR event_type LIKE %s THEN 1 ELSE 0 END) as admin_scanning,
					COUNT(*) as total_events
				FROM $logs_table
				WHERE created_at >= %s OR created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
				GROUP BY DATE(created_at)
				ORDER BY stat_date ASC",
				'%' . $wpdb->esc_like( 'failed_login' ) . '%',
				'%' . $wpdb->esc_like( 'block' ) . '%',
				'%' . $wpdb->esc_like( 'auto_block' ) . '%',
				'%' . $wpdb->esc_like( 'reputation' ) . '%',
				'%' . $wpdb->esc_like( 'spam' ) . '%',
				'%' . $wpdb->esc_like( 'comment' ) . '%',
				'%' . $wpdb->esc_like( 'xmlrpc' ) . '%',
				'%' . $wpdb->esc_like( 'admin_scan' ) . '%',
				'%' . $wpdb->esc_like( 'wp_admin' ) . '%',
				$cutoff_utc,
				$days
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		foreach ( $log_stats as $stat ) {
			$labels[]         = date_i18n( 'M j', strtotime( $stat->stat_date ) );
			$failed_logins[]  = (int) $stat->failed_logins;
			$blocked_ips[]    = (int) $stat->blocked_ips;
			$comment_spam[]   = (int) $stat->comment_spam;
			$xmlrpc_events[]  = (int) $stat->xmlrpc_events;
			$admin_scanning[] = (int) $stat->admin_scanning;
		}

		$total_failed_logins  = array_sum( $failed_logins );
		$total_comment_spam   = array_sum( $comment_spam );
		$total_xmlrpc         = array_sum( $xmlrpc_events );
		$total_admin_scanning = array_sum( $admin_scanning );

		return array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'reportedip_charts_nonce' ),
			'mode'    => $mode_manager->get_mode(),
			'data'    => array(
				'securityEvents'     => array(
					'labels'       => $labels,
					'failedLogins' => $failed_logins,
					'blockedIPs'   => $blocked_ips,
					'commentSpam'  => $comment_spam,
				),
				'threatDistribution' => array(
					'labels' => array(
						__( 'Failed Logins', 'reportedip-hive' ),
						__( 'Comment Spam', 'reportedip-hive' ),
						__( 'XMLRPC Abuse', 'reportedip-hive' ),
						__( 'Admin Scanning', 'reportedip-hive' ),
					),
					'values' => array( $total_failed_logins, $total_comment_spam, $total_xmlrpc, $total_admin_scanning ),
				),
				'apiUsage'           => array(
					'labels'    => $labels,
					'apiCalls'  => array_fill( 0, count( $labels ), 0 ),
					'cacheHits' => array_fill( 0, count( $labels ), 0 ),
				),
			),
			'strings' => array(
				'failedLogins'  => __( 'Failed Logins', 'reportedip-hive' ),
				'blockedIPs'    => __( 'Blocked IPs', 'reportedip-hive' ),
				'commentSpam'   => __( 'Comment Spam', 'reportedip-hive' ),
				'xmlrpcAbuse'   => __( 'XMLRPC Abuse', 'reportedip-hive' ),
				'adminScanning' => __( 'Admin Scanning', 'reportedip-hive' ),
				'apiCalls'      => __( 'API Calls', 'reportedip-hive' ),
				'cacheHits'     => __( 'Cache Hits', 'reportedip-hive' ),
			),
		);
	}

	/**
	 * Handle failed login attempts
	 */
	public function handle_failed_login( $username ) {
		if ( ! get_option( 'reportedip_hive_monitor_failed_logins', true ) ) {
			return;
		}

		$ip_address = $this->get_client_ip();

		if ( $this->ip_manager->is_whitelisted( $ip_address ) ) {
			return;
		}

		if ( $this->is_ip_blocked_cached( $ip_address ) ) {
			return;
		}

		$log_data = array(
			'timestamp' => current_time( 'mysql' ),
		);

		if ( get_option( 'reportedip_hive_detailed_logging', false ) ) {
			$log_data['username_hash'] = hash( 'sha256', $username . wp_salt() );
		}

		if ( get_option( 'reportedip_hive_log_user_agents', false ) ) {
			$user_agent             = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$log_data['user_agent'] = substr( $user_agent, 0, REPORTEDIP_USER_AGENT_MAX_LENGTH );
		}

		$this->logger->log_security_event( 'failed_login', $ip_address, $log_data );

		$this->security_monitor->check_failed_login_threshold( $ip_address, $username );
	}

	/**
	 * Pre-authentication check
	 *
	 * @param mixed  $user     User object or error.
	 * @param string $password Password (unused, kept for hook signature).
	 */
	public function pre_auth_check( $user, $password ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$ip_address        = $this->get_client_ip();
		$report_only       = $this->is_report_only_mode();
		$threshold         = (int) get_option( 'reportedip_hive_block_threshold', 75 );
		$is_blocked        = $this->ip_manager->is_blocked( $ip_address );
		$reputation        = null;
		$exceeds_threshold = false;

		if ( $this->api_client->is_configured() ) {
			$reputation = $this->api_client->check_ip_reputation( $ip_address );
			if ( $reputation && isset( $reputation['abuseConfidencePercentage'] ) && $reputation['abuseConfidencePercentage'] >= $threshold ) {
				$exceeds_threshold = true;
			}
		}

		if ( $report_only ) {
			if ( $is_blocked ) {
				$this->logger->log_security_event(
					'would_block_access',
					$ip_address,
					array(
						'reason'           => 'IP is blocked but report-only mode is active',
						'report_only_mode' => true,
					),
					'medium'
				);
			}

			if ( $exceeds_threshold ) {
				$confidence = isset( $reputation['abuseConfidencePercentage'] ) ? $reputation['abuseConfidencePercentage'] : 0;
				$reports    = isset( $reputation['totalReports'] ) ? $reputation['totalReports'] : 0;

				$this->logger->log_security_event(
					'would_block_by_reputation',
					$ip_address,
					array(
						'confidence'       => $confidence,
						'reports'          => $reports,
						'threshold'        => $threshold,
						'report_only_mode' => true,
					),
					'high'
				);

				$this->security_monitor->report_security_event(
					$ip_address,
					'reputation_threat',
					array(
						'confidence' => $confidence,
						'reports'    => $reports,
						'threshold'  => $threshold,
					)
				);
			}

			return $user;
		}

		if ( $is_blocked ) {
			return new WP_Error( 'ip_blocked', __( 'Your IP address has been blocked due to suspicious activity.', 'reportedip-hive' ) );
		}

		if ( $exceeds_threshold ) {
			$confidence = isset( $reputation['abuseConfidencePercentage'] ) ? $reputation['abuseConfidencePercentage'] : 0;
			$reports    = isset( $reputation['totalReports'] ) ? $reputation['totalReports'] : 0;

			$this->logger->log_security_event(
				'blocked_by_reputation',
				$ip_address,
				array(
					'confidence' => $confidence,
					'reports'    => $reports,
					'threshold'  => $threshold,
				),
				'high'
			);

			$this->security_monitor->report_security_event(
				$ip_address,
				'reputation_threat',
				array(
					'confidence' => $confidence,
					'reports'    => $reports,
					'threshold'  => $threshold,
				)
			);

			return new WP_Error( 'ip_reputation_block', __( 'Access denied due to IP reputation.', 'reportedip-hive' ) );
		}

		return $user;
	}

	/**
	 * Handle comment posts
	 */
	public function handle_comment_post( $comment_id, $approved, $commentdata ) {
		if ( ! get_option( 'reportedip_hive_monitor_comments', true ) ) {
			return;
		}

		$ip_address = $commentdata['comment_author_IP'];

		if ( $this->ip_manager->is_whitelisted( $ip_address ) ) {
			return;
		}

		if ( $this->is_ip_blocked_cached( $ip_address ) ) {
			return;
		}

		if ( $approved === 'spam' || $approved === 0 ) {
			$log_data = array(
				'comment_id' => $comment_id,
				'timestamp'  => current_time( 'mysql' ),
			);

			if ( get_option( 'reportedip_hive_detailed_logging', false ) ) {
				$log_data['author_hash'] = hash( 'sha256', $commentdata['comment_author'] . wp_salt() );
			}

			$log_data['content_length'] = strlen( $commentdata['comment_content'] );

			$this->logger->log_security_event( 'comment_spam', $ip_address, $log_data );

			$this->security_monitor->check_comment_spam_threshold( $ip_address );
		}
	}

	/**
	 * Handle XMLRPC calls
	 */
	public function handle_xmlrpc_call( $method ) {
		if ( ! get_option( 'reportedip_hive_monitor_xmlrpc', true ) ) {
			return;
		}

		$ip_address = $this->get_client_ip();

		if ( $this->ip_manager->is_whitelisted( $ip_address ) ) {
			return;
		}

		if ( $this->is_ip_blocked_cached( $ip_address ) ) {
			return;
		}

		$log_data = array(
			'method'    => $method,
			'timestamp' => current_time( 'mysql' ),
		);

		if ( get_option( 'reportedip_hive_log_user_agents', false ) ) {
			$user_agent             = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$log_data['user_agent'] = substr( $user_agent, 0, REPORTEDIP_USER_AGENT_MAX_LENGTH );
		}

		$this->logger->log_security_event( 'xmlrpc_call', $ip_address, $log_data );

		$this->security_monitor->check_xmlrpc_threshold( $ip_address );
	}

	/**
	 * Handle successful login
	 */
	public function handle_successful_login( $user_login, $user ) {
		$ip_address = $this->get_client_ip();

		$this->security_monitor->reset_failed_login_counter( $ip_address );

		$log_data = array(
			'timestamp' => current_time( 'mysql' ),
		);

		if ( get_option( 'reportedip_hive_detailed_logging', false ) ) {
			$log_data['username_hash'] = hash( 'sha256', $user_login . wp_salt() );
			$log_data['user_id']       = $user->ID;
		}

		if ( get_option( 'reportedip_hive_log_user_agents', false ) ) {
			$user_agent             = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$log_data['user_agent'] = substr( $user_agent, 0, REPORTEDIP_USER_AGENT_MAX_LENGTH );
		}

		$this->logger->log_security_event( 'successful_login', $ip_address, $log_data );
	}

	/**
	 * Block admin access for blocked IPs
	 */
	public function block_admin_access() {
		if ( ! is_admin() || wp_doing_ajax() ) {
			return;
		}

		if ( $this->is_report_only_mode() ) {
			return;
		}

		$ip_address = $this->get_client_ip();

		if ( $this->ip_manager->is_blocked( $ip_address ) && ! $this->ip_manager->is_whitelisted( $ip_address ) ) {
			wp_die( esc_html__( 'Access denied. Your IP address has been blocked due to suspicious activity.', 'reportedip-hive' ) );
		}
	}

	/**
	 * Suppress third-party admin notices on plugin pages for a clean UI.
	 * Our own notices are rendered inline within the page content.
	 */
	public function suppress_foreign_notices_on_plugin_pages() {
		$screen = get_current_screen();
		if ( ! $screen ) {
			return;
		}

		$screen_id = (string) $screen->id;
		if ( strpos( $screen_id, 'reportedip-hive' ) === false ) {
			return;
		}

		remove_all_actions( 'admin_notices' );
		remove_all_actions( 'all_admin_notices' );
	}

	/**
	 * Display admin notices for API status issues
	 */
	public function display_api_status_notices() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$screen = get_current_screen();
		if ( ! $screen ) {
			return;
		}

		$show_on_screens = array( 'dashboard', 'toplevel_page_reportedip-hive', 'reportedip-hive_page_reportedip-hive-logs' );
		$screen_id       = (string) $screen->id;
		$is_plugin_page  = strpos( $screen_id, 'reportedip-hive' ) !== false;

		if ( ! in_array( $screen_id, $show_on_screens ) && ! $is_plugin_page ) {
			return;
		}

		global $wpdb;

		$user_id = get_current_user_id();

		$table = $wpdb->prefix . 'reportedip_hive_api_queue';
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe table name composed from $wpdb->prefix and a hardcoded suffix.
		$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '$table'" ) === $table;
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		if ( $table_exists ) {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from $wpdb->prefix and a hardcoded constant; safe.
			$counts = $wpdb->get_row(
				"SELECT
					SUM( CASE WHEN status = 'failed' THEN 1 ELSE 0 END ) AS failed_count,
					SUM( CASE WHEN status = 'pending' THEN 1 ELSE 0 END ) AS pending_count
				FROM $table"
			);
			// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$failed_count  = (int) ( $counts->failed_count ?? 0 );
			$pending_count = (int) ( $counts->pending_count ?? 0 );

			if ( $failed_count > 0 ) {
				$queue_url = admin_url( 'admin.php?page=reportedip-hive-security&tab=api_queue' );
				echo '<div class="notice notice-error is-dismissible"><p>';
				echo '<strong>' . esc_html__( 'ReportedIP Hive:', 'reportedip-hive' ) . '</strong> ';
				printf(
					/* translators: %1$d: number of failed reports, %2$s: link to queue page */
					esc_html__( '%1$d API reports failed. %2$s', 'reportedip-hive' ),
					intval( $failed_count ),
					'<a href="' . esc_url( $queue_url ) . '">' . esc_html__( 'View queue', 'reportedip-hive' ) . '</a>'
				);
				echo ' <button type="button" class="button button-small" id="retry-failed-reports-notice" style="margin-left: 10px;">';
				echo esc_html__( 'Retry all', 'reportedip-hive' );
				echo '</button>';
				echo '</p></div>';
				echo '<script>
                jQuery(document).ready(function($) {
                    $("#retry-failed-reports-notice").on("click", function(e) {
                        e.preventDefault();
                        var $btn = $(this);
                        $btn.prop("disabled", true).text("' . esc_js( __( 'Retrying…', 'reportedip-hive' ) ) . '");
                        $.post(ajaxurl, {
                            action: "reportedip_hive_retry_all_failed",
                            nonce: "' . esc_js( wp_create_nonce( 'reportedip_hive_nonce' ) ) . '"
                        }, function(response) {
                            if (response.success) {
                                location.reload();
                            } else {
                                alert(response.data || "' . esc_js( __( 'Retry failed.', 'reportedip-hive' ) ) . '");
                                $btn.prop("disabled", false).text("' . esc_js( __( 'Retry all', 'reportedip-hive' ) ) . '");
                            }
                        });
                    });
                });
                </script>';
			}

			$warning_threshold  = get_option( 'reportedip_hive_queue_warning_threshold', 50 );
			$critical_threshold = get_option( 'reportedip_hive_queue_critical_threshold', 200 );
			$queue_url          = admin_url( 'admin.php?page=reportedip-hive-security&tab=api_queue' );
			$community_url      = admin_url( 'admin.php?page=reportedip-hive-community' );
			$queue_dismissed    = get_user_meta( $user_id, 'reportedip_dismissed_queue_warning_' . gmdate( 'Y-m-d' ), true );

			if ( $pending_count >= $critical_threshold ) {
				echo '<div class="notice notice-error is-dismissible reportedip-dismissible" data-notice-id="queue_critical_' . esc_attr( gmdate( 'Y-m-d' ) ) . '"><p>';
				echo '<strong>' . esc_html__( 'ReportedIP Hive - Queue Critical:', 'reportedip-hive' ) . '</strong> ';
				printf(
					/* translators: %1$d: number of pending reports, %2$s: link to community page, %3$s: link to queue page */
					esc_html__( '%1$d reports pending processing. Your API quota may not be sufficient. %2$s or %3$s.', 'reportedip-hive' ),
					intval( $pending_count ),
					'<a href="' . esc_url( $community_url ) . '">' . esc_html__( 'Upgrade API tier', 'reportedip-hive' ) . '</a>',
					'<a href="' . esc_url( $queue_url ) . '">' . esc_html__( 'Manage queue', 'reportedip-hive' ) . '</a>'
				);
				echo '</p></div>';
			} elseif ( $pending_count >= $warning_threshold && ! $queue_dismissed ) {
				echo '<div class="notice notice-warning is-dismissible reportedip-dismissible" data-notice-id="queue_warning_' . esc_attr( gmdate( 'Y-m-d' ) ) . '"><p>';
				echo '<strong>' . esc_html__( 'ReportedIP Hive:', 'reportedip-hive' ) . '</strong> ';
				printf(
					/* translators: %1$d: number of pending reports, %2$s: link to community page */
					esc_html__( '%1$d reports pending processing. %2$s for higher limits.', 'reportedip-hive' ),
					intval( $pending_count ),
					'<a href="' . esc_url( $community_url ) . '">' . esc_html__( 'Upgrade API tier', 'reportedip-hive' ) . '</a>'
				);
				echo '</p></div>';
			}
		}

		$api_key = get_option( 'reportedip_hive_api_key', '' );
		if ( empty( $api_key ) && $is_plugin_page ) {
			$settings_url = admin_url( 'admin.php?page=reportedip-hive' );
			echo '<div class="notice notice-warning is-dismissible"><p>';
			echo '<strong>' . esc_html__( 'ReportedIP Hive:', 'reportedip-hive' ) . '</strong> ';
			printf(
				/* translators: %s: link to settings page */
				esc_html__( 'No API key configured. %s', 'reportedip-hive' ),
				'<a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Configure now', 'reportedip-hive' ) . '</a>'
			);
			echo '</p></div>';
		}
	}

	/**
	 * Check IP access on init
	 */
	private function check_ip_access() {
		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		$ip_address = $this->get_client_ip();

		$cache_key = 'rip_access_' . md5( $ip_address );
		$cached    = wp_cache_get( $cache_key, 'reportedip' );
		if ( $cached === 'allowed' ) {
			return;
		}
		if ( $cached === 'blocked' ) {
			$this->show_blocked_page();
			return;
		}

		if ( $this->ip_manager->is_whitelisted( $ip_address ) ) {
			wp_cache_set( $cache_key, 'allowed', 'reportedip', 300 );
			return;
		}

		if ( $this->is_report_only_mode() ) {
			if ( $this->ip_manager->is_blocked( $ip_address ) ) {
				$this->logger->log_security_event(
					'would_block_access',
					$ip_address,
					array(
						'report_only_mode' => true,
						'reason'           => 'IP is blocked but report-only mode is active',
					)
				);
			}
			wp_cache_set( $cache_key, 'allowed', 'reportedip', 300 );
			return;
		}

		if ( $this->ip_manager->is_blocked( $ip_address ) ) {
			wp_cache_set( $cache_key, 'blocked', 'reportedip', 300 );
			$this->show_blocked_page();
			return;
		}

		wp_cache_set( $cache_key, 'allowed', 'reportedip', 300 );
	}

	/**
	 * Render the 403 "Access Denied" page and terminate.
	 *
	 * The response MUST never be cached: WP Rocket / W3 Total Cache /
	 * WP Super Cache / LiteSpeed Cache / Cloudflare all default to caching
	 * 403 responses unless told otherwise. A cached 403 would lock every
	 * subsequent visitor on the same URL out of the site, even ones with
	 * a perfectly clean IP.
	 *
	 * Mitigation matches the pattern used by `class-hide-login.php`:
	 *  - `nocache_headers()` for the standard WordPress cache-prevention set
	 *  - explicit `Cache-Control: no-store` because some CDNs only honour it
	 *    in that exact form
	 *  - the `DONOTCACHEPAGE` family of constants so plugin-level caches
	 *    refuse to store the response object
	 *
	 * @since 1.0.0
	 */
	private function show_blocked_page() {
		self::emit_block_response_headers();
		status_header( 403 );
		include REPORTEDIP_HIVE_PLUGIN_DIR . 'templates/blocked.php';
		exit;
	}

	/**
	 * Emit the cache-prevention header set used by every blocked-page response.
	 *
	 * Defines the four "DONOTCACHE*" constants the major plugin caches respect
	 * (WP Rocket, W3 Total Cache, WP Super Cache, LiteSpeed) and emits explicit
	 * `Cache-Control: no-store` + `Pragma: no-cache` for CDNs that only honour
	 * those exact forms. Extracted as a public static helper so the unit tests
	 * can assert the contract without invoking the page-rendering path that
	 * ends in `exit`.
	 *
	 * @since 1.5.2
	 * @return void
	 */
	public static function emit_block_response_headers() {
		// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- DONOTCACHE* constants are documented WP-Rocket / W3 Total Cache / WP Super Cache / LiteSpeed integration points; their names cannot be prefixed.
		if ( ! defined( 'DONOTCACHEPAGE' ) ) {
			define( 'DONOTCACHEPAGE', true );
		}
		if ( ! defined( 'DONOTCACHEDB' ) ) {
			define( 'DONOTCACHEDB', true );
		}
		if ( ! defined( 'DONOTCACHEOBJECT' ) ) {
			define( 'DONOTCACHEOBJECT', true );
		}
		// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound

		if ( function_exists( 'nocache_headers' ) ) {
			nocache_headers();
		}
		if ( ! headers_sent() ) {
			header( 'Cache-Control: no-store, no-cache, must-revalidate, max-age=0' );
			header( 'Pragma: no-cache' );
		}
	}

	/**
	 * Check if plugin is in report-only mode
	 */
	private function is_report_only_mode() {
		return get_option( 'reportedip_hive_report_only_mode', false );
	}

	/**
	 * Sanitize data for API reports (remove personal information)
	 *
	 * This is the central utility method for sanitizing report data.
	 * Other classes should call ReportedIP_Hive::sanitize_for_api_report()
	 * instead of implementing their own.
	 *
	 * @param string $reason The original reason (may contain personal data, unused for privacy).
	 * @return string A generic, GDPR-compliant reason
	 */
	public static function sanitize_for_api_report( $reason ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.Found
		return 'Security event detected via WP ReportedIP Hive';
	}

	/**
	 * Get client IP address
	 *
	 * This is the central utility method for IP detection. Other classes should
	 * call ReportedIP_Hive::get_client_ip() instead of implementing their own.
	 *
	 * Only trusts the explicitly configured header (reportedip_hive_trusted_ip_header).
	 * If no trusted header is configured or the header is absent, falls back to REMOTE_ADDR.
	 * This prevents IP spoofing via arbitrary proxy headers.
	 *
	 * @return string The client IP address or 'unknown' if not determinable
	 */
	public static function get_client_ip() {
		static $trusted_header = null;
		if ( null === $trusted_header ) {
			$trusted_header = get_option( 'reportedip_hive_trusted_ip_header', '' );
		}

		if ( ! empty( $trusted_header ) && isset( $_SERVER[ $trusted_header ] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized via filter_var below
			$server_value = wp_unslash( $_SERVER[ $trusted_header ] );
			$ips          = explode( ',', (string) $server_value );
			$ip           = trim( $ips[0] );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) !== false ) {
				return $ip;
			}
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized via filter_var
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : 'unknown';
		return filter_var( $remote_addr, FILTER_VALIDATE_IP ) ? $remote_addr : 'unknown';
	}

	/**
	 * Delete all plugin options
	 */
	private static function delete_plugin_options() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Uninstall cleanup
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'reportedip_hive_%'" );
	}

	/**
	 * Get default option values (single source of truth)
	 *
	 * @return array
	 */
	public static function get_default_options() {
		return array(
			'reportedip_hive_api_key'                      => '',
			'reportedip_hive_api_endpoint'                 => 'https://reportedip.de/wp-json/reportedip/v2/',
			'reportedip_hive_trusted_ip_header'            => '',
			'reportedip_hive_failed_login_threshold'       => 5,
			'reportedip_hive_failed_login_timeframe'       => 15,
			'reportedip_hive_comment_spam_threshold'       => 5,
			'reportedip_hive_comment_spam_timeframe'       => 60,
			'reportedip_hive_xmlrpc_threshold'             => 10,
			'reportedip_hive_xmlrpc_timeframe'             => 60,
			'reportedip_hive_auto_block'                   => true,
			'reportedip_hive_block_duration'               => 24,
			'reportedip_hive_block_threshold'              => 75,
			'reportedip_hive_monitor_comments'             => true,
			'reportedip_hive_monitor_xmlrpc'               => true,
			'reportedip_hive_monitor_failed_logins'        => true,
			'reportedip_hive_notify_admin'                 => true,
			'reportedip_hive_notify_recipients'            => '',
			'reportedip_hive_notify_from_name'             => '',
			'reportedip_hive_notify_from_email'            => '',
			'reportedip_hive_notify_sync_to_api'           => false,
			'reportedip_hive_log_level'                    => 'info',
			'reportedip_hive_delete_data_on_uninstall'     => false,
			'reportedip_hive_report_only_mode'             => false,
			'reportedip_hive_report_cooldown_hours'        => 24,
			'reportedip_hive_detailed_logging'             => false,
			'reportedip_hive_log_user_agents'              => false,
			'reportedip_hive_data_retention_days'          => 30,
			'reportedip_hive_auto_anonymize_days'          => 7,
			'reportedip_hive_minimal_logging'              => false,
			'reportedip_hive_log_referer_domains'          => false,
			'reportedip_hive_enable_caching'               => true,
			'reportedip_hive_cache_duration'               => 24,
			'reportedip_hive_negative_cache_duration'      => 2,
			'reportedip_hive_max_api_calls_per_hour'       => 100,
			'reportedip_hive_queue_warning_threshold'      => 50,
			'reportedip_hive_queue_critical_threshold'     => 200,
			'reportedip_hive_processing_timeout_minutes'   => 10,
			'reportedip_hive_blocked_page_contact_url'     => '',
			'reportedip_hive_disable_xmlrpc_multicall'     => true,
			'reportedip_hive_hide_login_enabled'           => false,
			'reportedip_hive_hide_login_slug'              => '',
			'reportedip_hive_hide_login_response_mode'     => 'block_page',
			'reportedip_hive_hide_login_token_in_urls'     => false,
			'reportedip_hive_notification_cooldown_minutes' => 60,
			'reportedip_hive_2fa_enabled_global'           => false,
			'reportedip_hive_2fa_enforce_roles'            => '[]',
			'reportedip_hive_2fa_enforce_grace_days'       => 7,
			'reportedip_hive_2fa_max_skips'                => 3,
			'reportedip_hive_2fa_allowed_methods'          => '["totp","email"]',
			'reportedip_hive_2fa_trusted_devices'          => true,
			'reportedip_hive_2fa_trusted_device_days'      => 30,
			'reportedip_hive_2fa_email_subject'            => '',
			'reportedip_hive_2fa_ip_allowlist'             => '',
			'reportedip_hive_2fa_frontend_onboarding'      => true,
			'reportedip_hive_2fa_notify_new_device'        => true,
			'reportedip_hive_2fa_xmlrpc_app_password_only' => false,
			'reportedip_hive_2fa_extended_remember'        => false,
			'reportedip_hive_2fa_branded_login'            => false,
			'reportedip_hive_2fa_email_subject_code'       => '',
			'reportedip_hive_2fa_email_body_code'          => '',
			'reportedip_hive_2fa_require_on_password_reset' => true,
			'reportedip_hive_2fa_password_reset_excluded_methods' => '["email"]',
			'reportedip_hive_2fa_password_reset_block_email_only' => true,

			'reportedip_hive_password_spray_threshold'     => 5,
			'reportedip_hive_password_spray_timeframe'     => 10,

			'reportedip_hive_monitor_app_passwords'        => true,
			'reportedip_hive_app_password_threshold'       => 5,
			'reportedip_hive_app_password_timeframe'       => 15,
			'reportedip_hive_app_password_require_2fa'     => true,

			'reportedip_hive_monitor_rest_api'             => true,
			'reportedip_hive_rest_threshold'               => 240,
			'reportedip_hive_rest_timeframe'               => 5,
			'reportedip_hive_rest_sensitive_threshold'     => 20,
			'reportedip_hive_rest_sensitive_timeframe'     => 5,

			'reportedip_hive_block_user_enumeration'       => true,
			'reportedip_hive_user_enum_threshold'          => 5,
			'reportedip_hive_user_enum_timeframe'          => 5,

			'reportedip_hive_monitor_404_scans'            => true,
			'reportedip_hive_scan_404_threshold'           => 12,
			'reportedip_hive_scan_404_timeframe'           => 2,

			'reportedip_hive_monitor_woocommerce'          => true,

			'reportedip_hive_monitor_geo_anomaly'          => true,
			'reportedip_hive_geo_window_days'              => 90,
			'reportedip_hive_geo_revoke_trusted_devices'   => true,
			'reportedip_hive_geo_report_to_api'            => false,

			'reportedip_hive_password_policy_enabled'      => true,
			'reportedip_hive_password_min_length'          => 12,
			'reportedip_hive_password_min_classes'         => 3,
			'reportedip_hive_password_check_hibp'          => true,
			'reportedip_hive_password_policy_all_users'    => false,

			'reportedip_hive_auto_footer_enabled'          => false,
			'reportedip_hive_auto_footer_variant'          => 'badge',
			'reportedip_hive_auto_footer_align'            => 'center',
		);
	}

	/**
	 * Apply default options (public wrapper for external access)
	 */
	public static function apply_default_options() {
		self::set_default_options_static();
	}

	/**
	 * Set default options (static version for activation hook)
	 */
	private static function set_default_options_static() {
		$defaults = self::get_default_options();

		$no_autoload = array(
			'reportedip_hive_queue_warning_threshold',
			'reportedip_hive_queue_critical_threshold',
		);

		foreach ( $defaults as $option => $value ) {
			if ( get_option( $option ) === false ) {
				$autoload = in_array( $option, $no_autoload, true ) ? false : true;
				add_option( $option, $value, '', $autoload );
			}
		}
	}



	/**
	 * Get cron handler instance
	 *
	 * @return ReportedIP_Hive_Cron_Handler
	 */
	public function get_cron_handler() {
		return $this->cron_handler;
	}
}

register_activation_hook( __FILE__, array( 'ReportedIP_Hive', 'activate_plugin' ) );
register_deactivation_hook( __FILE__, array( 'ReportedIP_Hive', 'deactivate_plugin' ) );
register_uninstall_hook( __FILE__, array( 'ReportedIP_Hive', 'uninstall' ) );

add_action(
	'plugins_loaded',
	function () {
		ReportedIP_Hive::get_instance();
	},
	10
);
