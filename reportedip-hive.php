<?php
/**
 * Plugin Name: ReportedIP Hive
 * Plugin URI: https://reportedip.com
 * Description: Community-powered WordPress security — real-time threat intelligence
 * with 5-layer defense and 4-method 2FA. Be part of the hive.
 * Version: 2.1.45
 * Author: Patrick Schlesinger, ReportedIP
 * Author URI: https://reportedip.com
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: reportedip-hive
 * Domain Path: /languages
 * Requires at least: 5.9
 * Tested up to: 7.0
 * Requires PHP: 8.1
 * Network: true
 * Update URI: https://github.com/reportedip/reportedip-hive
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
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

define( 'REPORTEDIP_HIVE_VERSION', '2.1.45' );
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
define( 'REPORTEDIP_HIVE_SITE_URL', 'https://reportedip.com' );
define( 'REPORTEDIP_HIVE_UPGRADE_URL', 'https://reportedip.com/dashboard/' );
define( 'REPORTEDIP_HIVE_CONTACT_MAIL', '1@reportedip.com' );
define( 'REPORTEDIP_HIVE_HONEYPOT_URL', 'https://reportedip.com/docs/integrations/honeypot-server/' );
define( 'REPORTEDIP_HIVE_FAQ_URL', 'https://reportedip.com/docs/support/faq/' );
define( 'REPORTEDIP_HIVE_REGISTER_URL', 'https://reportedip.com/register/' );

/**
 * Update checker: reads releases from the public GitHub repository.
 * Trigger: tag `vX.Y.Z` → GitHub Action builds ZIP release asset → PUC pulls it.
 *
 * Built only where update information is ever consumed — wp-admin, the
 * `wp_update_plugins` cron and WP-CLI. Anonymous front-end requests used to
 * construct the whole checker (plus its hooks) for nothing.
 */
if ( class_exists( PucFactory::class ) && ( is_admin() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) ) {
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
	 * Option holding the access-verdict cache epoch.
	 *
	 * Advancing it retires every cached verdict at once; see
	 * {@see self::flush_ip_verdict_cache()}.
	 *
	 * @var string
	 */
	const OPTION_ACCESS_CACHE_EPOCH = 'reportedip_hive_access_cache_epoch';

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

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_disable_xmlrpc_multicall', true ) ) {
			add_filter( 'xmlrpc_methods', array( $this, 'disable_xmlrpc_multicall' ) );
		}

		add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ) );
		add_action( 'wp_authenticate_user', array( $this, 'pre_auth_check' ), 10, 2 );
		add_action( 'comment_post', array( $this, 'handle_comment_post' ), 10, 3 );
		add_action( 'xmlrpc_call', array( $this, 'handle_xmlrpc_call' ) );
		add_action( 'wp_login', array( $this, 'handle_successful_login' ), 10, 2 );

		add_action( 'admin_init', array( $this, 'block_admin_access' ) );
		add_action( 'admin_notices', array( $this, 'display_api_status_notices' ) );

		add_action( 'reportedip_hive_ip_blocked', array( __CLASS__, 'flush_ip_verdict_cache' ) );
		add_action( 'reportedip_hive_ip_unblocked', array( __CLASS__, 'flush_ip_verdict_cache' ) );
		add_action( 'reportedip_hive_whitelist_changed', array( __CLASS__, 'flush_ip_verdict_cache' ) );

		add_action( 'admin_head', array( $this, 'suppress_foreign_notices_on_plugin_pages' ) );

		add_action( 'wp_ajax_reportedip_get_chart_data', array( $this, 'ajax_get_chart_data' ) );

		add_action( 'wp_initialize_site', array( __CLASS__, 'on_site_initialized' ), 10, 2 );
		add_action( 'wp_delete_site', array( __CLASS__, 'on_site_deleted' ), 10, 1 );
		add_action( 'wpmu_delete_user', array( __CLASS__, 'on_user_deleted' ) );
		add_action( 'delete_user', array( __CLASS__, 'on_user_deleted' ) );
		if ( ! is_multisite() || is_main_site() ) {
			add_action( 'admin_init', array( 'ReportedIP_Hive_Cron_Handler', 'ensure_scheduled' ) );
			add_action( 'admin_init', array( __CLASS__, 'maybe_seed_on_upgrade' ) );
		}

		$flush_routing_cache = array( 'ReportedIP_Hive_Option_Routing', 'flush_resolve_cache' );
		$flush_frontend_memo = array( 'ReportedIP_Hive_Two_Factor_Frontend', 'flush_slug_memo' );
		foreach (
			array(
				'reportedip_hive_2fa_frontend_slug',
				'reportedip_hive_2fa_frontend_slug_site_override',
				'reportedip_hive_2fa_frontend_setup_slug',
				'reportedip_hive_2fa_frontend_setup_slug_site_override',
			) as $slug_opt
		) {
			add_action( 'update_option_' . $slug_opt, $flush_routing_cache );
			add_action( 'update_option_' . $slug_opt, $flush_frontend_memo );
			add_action( 'update_site_option_' . $slug_opt, $flush_routing_cache );
			add_action( 'update_site_option_' . $slug_opt, $flush_frontend_memo );
		}
		add_action( 'update_option_reportedip_hive_2fa_enforce_roles', $flush_routing_cache );
		add_action( 'update_option_reportedip_hive_2fa_enforce_roles_extra', $flush_routing_cache );
		add_action( 'update_site_option_reportedip_hive_2fa_enforce_roles', $flush_routing_cache );

		$flush_score = array( 'ReportedIP_Hive_Score', 'flush_on_option_change' );
		add_action( 'updated_option', $flush_score );
		add_action( 'added_option', $flush_score );
		add_action( 'deleted_option', $flush_score );
		add_action( 'update_site_option', $flush_score );
		add_action( 'add_site_option', $flush_score );
		add_action( 'reportedip_hive_mode_changed', array( 'ReportedIP_Hive_Score', 'flush_cache' ) );

		$on_api_key_change = array( __CLASS__, 'on_api_key_change' );
		add_action( 'add_option_reportedip_hive_api_key', $on_api_key_change );
		add_action( 'update_option_reportedip_hive_api_key', $on_api_key_change );
		add_action( 'add_site_option_reportedip_hive_api_key', $on_api_key_change );
		add_action( 'update_site_option_reportedip_hive_api_key', $on_api_key_change );
		add_action( 'reportedip_hive_refresh_tier_after_key_change', array( __CLASS__, 'refresh_tier_after_key_change' ) );

		if ( is_admin() ) {
			new ReportedIP_Hive_Ajax_Handler( $this );
		}

		ReportedIP_Hive_Admin_Bar::get_instance()->register_hooks();
		ReportedIP_Hive_Admin_Notice::register_hooks();
		ReportedIP_Hive_Decoy_Path_Block::get_instance()->register_hooks();
		ReportedIP_Hive_Decoy_Htaccess_Writer::get_instance()->register_hooks();
		ReportedIP_Hive_Audit_Logger::get_instance()->register_hooks();
	}

	/**
	 * Run schema migrations on freshly-created network sites.
	 *
	 * Because the plugin tables are network-wide there is nothing per-site
	 * to set up — `Migration_Manager::maybe_run()` is a no-op when the
	 * stored version already matches `CURRENT_VERSION`. The hook is wired
	 * defensively so future migrations that DO need per-site work have a
	 * trigger point.
	 *
	 * @param WP_Site $site WordPress site object.
	 * @param array   $args Initialisation arguments.
	 */
	public static function on_site_initialized( $site, $args = array() ) {
		unset( $site, $args );
		ReportedIP_Hive_Migration_Manager::maybe_run();
	}

	/**
	 * Clean up `blog_id`-scoped plugin data when a site is deleted.
	 *
	 * @param WP_Site $site WordPress site object being deleted.
	 */
	public static function on_site_deleted( $site ) {
		$blog_id = (int) $site->blog_id;
		if ( $blog_id <= 0 ) {
			return;
		}
		ReportedIP_Hive_Schema::cleanup_blog_data( $blog_id );
		delete_blog_option( $blog_id, 'reportedip_hive_2fa_frontend_slug_site_override' );
		delete_blog_option( $blog_id, 'reportedip_hive_2fa_enforce_roles_extra' );
	}

	/**
	 * Remove trusted-device rows for a deleted user.
	 *
	 * User meta is cleaned up automatically by WordPress; the plugin's own
	 * trusted_devices table needs an explicit DELETE because it is not
	 * tied to user_meta.
	 *
	 * @param int $user_id User being deleted.
	 */
	public static function on_user_deleted( $user_id ) {
		global $wpdb;
		$user_id = (int) $user_id;
		if ( $user_id <= 0 ) {
			return;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Single-row DELETE on a plugin-owned table during user-deletion lifecycle hook; no caching layer applies.
		$wpdb->delete(
			ReportedIP_Hive_Schema::table( 'reportedip_hive_trusted_devices' ),
			array( 'user_id' => $user_id ),
			array( '%d' )
		);
	}

	/**
	 * React to an API-key change so the tier cache is populated without the
	 * front-end ever polling `/relay-quota` live.
	 *
	 * Fires on both single-site (`update_option_*`) and Multisite
	 * (`update_site_option_*`) save paths, and therefore covers Settings-API,
	 * wizard, WP-CLI, settings import and MainWP provisioning alike. The handler
	 * re-reads the current key rather than trusting the hook arguments, whose
	 * shape differs between those hooks.
	 *
	 * On a cleared key the durable tier baseline and relay caches are dropped so
	 * a removed key is not mis-read as a still-paid tier. On a present key a
	 * one-off background event refreshes the tier shortly after the request, so
	 * the saving request itself is never blocked on an HTTP round-trip.
	 *
	 * @return void
	 * @since 2.1.16
	 */
	public static function on_api_key_change() {
		$key = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );

		if ( '' === $key ) {
			delete_transient( 'reportedip_hive_relay_quota' );
			delete_transient( 'reportedip_hive_relay_quota_cooldown' );
			delete_transient( 'reportedip_hive_api_status' );
			ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_known_tier', '' );
			ReportedIP_Hive_Option_Routing::delete( 'reportedip_hive_domains_snapshot' );
			return;
		}

		delete_transient( 'reportedip_hive_relay_quota_cooldown' );

		if ( ! wp_next_scheduled( 'reportedip_hive_refresh_tier_after_key_change' ) ) {
			wp_schedule_single_event( time() + 5, 'reportedip_hive_refresh_tier_after_key_change' );
		}
	}

	/**
	 * Background handler that refreshes the tier/quota caches after an API-key
	 * change. Runs out of band via {@see wp_schedule_single_event()}.
	 *
	 * @return void
	 * @since 2.1.16
	 */
	public static function refresh_tier_after_key_change() {
		if ( ! class_exists( 'ReportedIP_Hive_API' ) ) {
			return;
		}
		$api = ReportedIP_Hive_API::get_instance();
		$api->refresh_api_quota();
		$api->get_relay_quota( true );
	}

	/**
	 * Load plugin dependencies
	 */
	private function load_dependencies() {
		/*
		 * The 'reportedip' cache group backs base_prefix (network-wide) tables:
		 * whitelist CIDRs, WAF exceptions and the per-IP access verdict are the
		 * same for every site in a network. Without this registration a
		 * persistent object cache would silo those entries per blog — duplicated
		 * memory and stale cross-site verdicts after a network-wide change.
		 */
		wp_cache_add_global_groups( 'reportedip' );

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-option-routing.php';
		ReportedIP_Hive_Option_Routing::prime_cache();
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-schema.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-migration-manager.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-defaults.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-wizard-schema.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-block-escalation.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-block-ref.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-rule-store.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-rule-sync.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-database.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-proxy-trust.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-request-path.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-event-taxonomy.php';

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-logger.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-cache.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-mode-manager.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-promo-manager.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-hardening-mode.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-api-client.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-security-monitor.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-admin-bar.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-admin-notice.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-whats-new.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-decoy-path-block.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-decoy-htaccess-writer.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-ip-manager.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-cron-handler.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-hide-login.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-app-password-monitor.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-bot-allowlist.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-rest-monitor.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-user-enumeration.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-scan-detector.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-waf.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-waf-dropin-manager.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-bot-verifier.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-disposable-email.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-comment-honeypot.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-security-headers.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-audit-logger.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-score.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-woocommerce-monitor.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-geo-anomaly.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-password-strength.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-privacy.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-phone-validator.php';

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-relay-usage-tracker.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/interface-mail-provider.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/mail-providers/class-mail-provider-wordpress.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/mail-providers/class-mail-provider-relay.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-mailer.php';

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-crypto.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-totp.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-email.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-recovery.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-verifier.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-reset-gate.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-onboarding.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-notifications.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-sms.php';
		ReportedIP_Hive_Two_Factor_SMS::load_providers();
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-webauthn-aaguid-registry.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-webauthn.php';
		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-rest.php';

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-tier-upgrade.php';
		ReportedIP_Hive_Tier_Upgrade::init();

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-quota-notifier.php';
		ReportedIP_Hive_Quota_Notifier::init();

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
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-hardening-cli.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-lookup-cli.php';
		}

		if ( is_admin() ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-ajax-handler.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-ip-cell.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-admin-settings.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-admin-firewall.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-two-factor-admin.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-logs-table.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-blocked-ips-table.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-whitelist-table.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-waf-exceptions-table.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-api-queue-table.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-settings-import-export.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'admin/class-dashboard-widget.php';
			ReportedIP_Hive_Dashboard_Widget::init();
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
		ReportedIP_Hive_WAF::get_instance();
		ReportedIP_Hive_WAF_Dropin_Manager::get_instance();
		ReportedIP_Hive_Bot_Verifier::get_instance();
		ReportedIP_Hive_Disposable_Email::get_instance();
		ReportedIP_Hive_Comment_Honeypot::get_instance();
		ReportedIP_Hive_Security_Headers::get_instance();
		ReportedIP_Hive_WooCommerce_Monitor::get_instance();
		ReportedIP_Hive_Geo_Anomaly::get_instance();
		ReportedIP_Hive_Password_Strength::get_instance();
		ReportedIP_Hive_Privacy::get_instance();
		new ReportedIP_Hive_Two_Factor();
		new ReportedIP_Hive_Two_Factor_Reset_Gate();

		new ReportedIP_Hive_Two_Factor_Onboarding();

		new ReportedIP_Hive_Two_Factor_Notifications();

		new ReportedIP_Hive_Two_Factor_WebAuthn();

		new ReportedIP_Hive_Two_Factor_REST();

		require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-mainwp-integration.php';
		ReportedIP_Hive_MainWP_Integration::init();

		if ( is_admin() ) {
			new ReportedIP_Hive_Two_Factor_Admin();
			new ReportedIP_Hive_Two_Factor_Dashboard();
		}
	}

	/**
	 * Static plugin activation (called from register_activation_hook).
	 *
	 * On Multisite the activation hook fires once when the Network Admin
	 * activates the plugin network-wide (the only allowed activation mode
	 * thanks to `Network: true` in the plugin header). All plugin tables
	 * live under `$wpdb->base_prefix`, so a single Schema::ensure_tables()
	 * call sets up storage for every site in the network.
	 *
	 * @param bool $network_wide True when activated from the network admin.
	 *                           Currently informational — Schema/Migration
	 *                           handle both cases identically.
	 */
	public static function activate_plugin( $network_wide = false ) {
		unset( $network_wide );
		foreach ( array(
			'includes/class-option-routing.php',
			'includes/class-defaults.php',
			'includes/class-schema.php',
			'includes/class-migration-manager.php',
			'includes/class-cron-handler.php',
			'includes/class-database.php',
		) as $relative ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . $relative;
		}

		ReportedIP_Hive_Schema::ensure_tables();
		ReportedIP_Hive_Migration_Manager::maybe_run();

		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_activated_at' ) ) {
			ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_activated_at', time() );
		}

		self::set_default_options_static();

		ReportedIP_Hive_Cron_Handler::schedule_cron_jobs_static();

		if ( ! class_exists( 'ReportedIP_Hive_Decoy_Path_Block' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-decoy-path-block.php';
		}
		if ( ! class_exists( 'ReportedIP_Hive_Decoy_Htaccess_Writer' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-decoy-htaccess-writer.php';
		}
		ReportedIP_Hive_Decoy_Htaccess_Writer::get_instance()->sync();

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_waf_dropin_enabled', false ) ) {
			foreach ( array(
				'includes/class-rule-store.php',
				'includes/class-rule-sync.php',
				'includes/class-waf.php',
				'includes/class-waf-dropin-manager.php',
			) as $relative ) {
				$path = REPORTEDIP_HIVE_PLUGIN_DIR . $relative;
				if ( file_exists( $path ) ) {
					require_once $path;
				}
			}
			if ( class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' ) ) {
				ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->sync();
			}
		}

		$wizard_completed = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_wizard_completed', false );
		$api_key          = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );

		if ( ! $wizard_completed && empty( $api_key ) ) {
			set_site_transient( 'reportedip_hive_activation_redirect', true, 5 * MINUTE_IN_SECONDS );
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
	 * Static plugin deactivation (called from register_deactivation_hook).
	 *
	 * Clears scheduled cron jobs but leaves data intact — uninstall.php is
	 * the only path that touches user data, and only when the corresponding
	 * opt-in is set.
	 */
	public static function deactivate_plugin() {
		if ( ! class_exists( 'ReportedIP_Hive_Cron_Handler' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-cron-handler.php';
		}
		ReportedIP_Hive_Cron_Handler::clear_cron_jobs_static();

		if ( ! class_exists( 'ReportedIP_Hive_Decoy_Path_Block' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-decoy-path-block.php';
		}
		if ( ! class_exists( 'ReportedIP_Hive_Decoy_Htaccess_Writer' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-decoy-htaccess-writer.php';
		}
		ReportedIP_Hive_Decoy_Htaccess_Writer::get_instance()->remove();

		if ( ! class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-waf-dropin-manager.php';
		}
		ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->remove();

		flush_rewrite_rules();
	}

	/**
	 * Plugin uninstall.
	 *
	 * Honours the `reportedip_hive_delete_data_on_uninstall` opt-in. On
	 * Multisite the option is checked from network storage so a Network
	 * Admin's choice applies across the whole network; on single-site it
	 * falls back to per-site `wp_options` automatically.
	 */
	public static function uninstall() {
		foreach ( array(
			'includes/class-option-routing.php',
			'includes/class-schema.php',
		) as $relative ) {
			$path = REPORTEDIP_HIVE_PLUGIN_DIR . $relative;
			if ( file_exists( $path ) ) {
				require_once $path;
			}
		}

		foreach ( array(
			'includes/class-waf.php',
			'includes/class-waf-dropin-manager.php',
		) as $relative ) {
			$path = REPORTEDIP_HIVE_PLUGIN_DIR . $relative;
			if ( file_exists( $path ) ) {
				require_once $path;
			}
		}
		if ( class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' ) ) {
			ReportedIP_Hive_WAF_Dropin_Manager::get_instance()->remove();
		}

		$delete_requested = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_delete_data_on_uninstall', false );
		if ( ! $delete_requested ) {
			return;
		}

		ReportedIP_Hive_Schema::drop_all_tables();
		ReportedIP_Hive_Option_Routing::delete_all_plugin_options();

		if ( ! class_exists( 'ReportedIP_Hive_Two_Factor' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor-recovery.php';
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-two-factor.php';
		}
		foreach ( ReportedIP_Hive_Two_Factor::get_all_meta_keys() as $key ) {
			delete_metadata( 'user', 0, $key, '', true );
		}

		delete_metadata( 'user', 0, '_reportedip_hive_known_ips', '', true );
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

		if ( str_contains( (string) $hook, 'reportedip-hive-firewall' ) ) {
			wp_enqueue_script(
				'reportedip-hive-firewall',
				REPORTEDIP_HIVE_PLUGIN_URL . 'assets/js/firewall.js',
				array( 'jquery', 'reportedip-hive-admin' ),
				REPORTEDIP_HIVE_VERSION,
				true
			);
		}

		wp_localize_script(
			'reportedip-hive-admin',
			'reportedip_hive_ajax',
			array(
				'ajax_url'       => admin_url( 'admin-ajax.php' ),
				'nonce'          => wp_create_nonce( 'reportedip_hive_nonce' ),
				'ip_detail_base' => apply_filters( 'reportedip_hive_external_url', REPORTEDIP_HIVE_SITE_URL . '/ip/', 'ip_detail_base' ),
				'current_ip'     => (string) self::get_client_ip(),
				'strings'        => array(
					'testing_connection'                 => __( 'Testing connection...', 'reportedip-hive' ),
					'connection_successful'              => __( 'Connection successful!', 'reportedip-hive' ),
					'connection_failed'                  => __( 'Connection failed!', 'reportedip-hive' ),
					'confirm_unblock'                    => __( 'Are you sure you want to unblock this IP?', 'reportedip-hive' ),
					'confirm_whitelist'                  => __( 'Are you sure you want to whitelist this IP?', 'reportedip-hive' ),
					'confirm_reset_settings'             => __( 'Are you sure you want to reset all settings to defaults?', 'reportedip-hive' ),
					'confirm_reset_api_stats'            => __( 'Reset the API statistics counter? This clears usage history only.', 'reportedip-hive' ),
					'confirm_uninstall_warn'             => __( 'WARNING: This will delete ALL plugin data including logs, blocked IPs, and whitelist entries. This cannot be undone!', 'reportedip-hive' ),
					'confirm_uninstall_final'            => __( 'Are you absolutely sure?', 'reportedip-hive' ),
					'confirm_remove_waf_exception'       => __( 'Remove this WAF exception?', 'reportedip-hive' ),
					/* translators: %1$s = WAF rule id, %2$s = request path. */
					'confirm_waf_allow'                  => __( 'Allow rule "%1$s" on path "%2$s"? The WAF stays active everywhere else.', 'reportedip-hive' ),
					'confirm_remove_whitelist'           => __( 'Are you sure you want to remove this IP from the whitelist?', 'reportedip-hive' ),
					'confirm_cleanup_logs'               => __( 'Are you sure you want to clean up old logs? This action cannot be undone.', 'reportedip-hive' ),
					'confirm_anonymize'                  => __( 'Are you sure you want to anonymize old data? This will remove personal information from logs.', 'reportedip-hive' ),
					'prompt_whitelist_reason'            => __( 'Enter reason for whitelisting (optional):', 'reportedip-hive' ),
					'prompt_whitelist_default'           => __( 'Manually whitelisted from blocked list', 'reportedip-hive' ),
					'prompt_block_reason'                => __( 'Enter reason for blocking this IP:', 'reportedip-hive' ),
					'prompt_block_default'               => __( 'Blocked from security logs', 'reportedip-hive' ),
					'prompt_export_days'                 => __( 'Export logs from how many days? (default: 30)', 'reportedip-hive' ),
					'db_connection_ok'                   => __( 'Database connection successful!', 'reportedip-hive' ),
					'request_failed'                     => __( 'Request failed. Check server logs.', 'reportedip-hive' ),
					'generic_error'                      => __( 'Error', 'reportedip-hive' ),
					'notify_request_failed'              => __( 'Request failed.', 'reportedip-hive' ),
					'notify_network_error'               => __( 'Network error occurred', 'reportedip-hive' ),
					'notify_network_retry'               => __( 'Network error. Please try again.', 'reportedip-hive' ),
					'notify_api_stats_reset'             => __( 'API statistics reset.', 'reportedip-hive' ),
					'notify_api_stats_reset_failed'      => __( 'Failed to reset API statistics.', 'reportedip-hive' ),
					'notify_cache_cleared'               => __( 'Cache cleared.', 'reportedip-hive' ),
					'notify_cache_clear_failed'          => __( 'Failed to clear cache.', 'reportedip-hive' ),
					'notify_cache_expired_cleaned'       => __( 'Expired entries cleaned.', 'reportedip-hive' ),
					'notify_cache_expired_failed'        => __( 'Failed to clean expired entries.', 'reportedip-hive' ),
					'notify_mode_changed'                => __( 'Mode changed successfully', 'reportedip-hive' ),
					'notify_mode_change_failed'          => __( 'Failed to change mode', 'reportedip-hive' ),
					'notify_whitelist_added'             => __( 'IP address added to whitelist successfully', 'reportedip-hive' ),
					'notify_whitelist_add_failed'        => __( 'Failed to add IP to whitelist', 'reportedip-hive' ),
					'notify_whitelist_removed'           => __( 'IP address removed from whitelist', 'reportedip-hive' ),
					'notify_whitelist_remove_failed'     => __( 'Failed to remove IP from whitelist', 'reportedip-hive' ),
					'notify_waf_exception_saved'         => __( 'WAF exception saved', 'reportedip-hive' ),
					'notify_waf_exception_save_failed'   => __( 'Failed to save the exception', 'reportedip-hive' ),
					'notify_waf_exception_removed'       => __( 'WAF exception removed', 'reportedip-hive' ),
					'notify_waf_exception_remove_failed' => __( 'Failed to remove the exception', 'reportedip-hive' ),
					'notify_waf_exception_added'         => __( 'WAF exception added for this rule', 'reportedip-hive' ),
					'notify_waf_exception_add_failed'    => __( 'Failed to add the exception', 'reportedip-hive' ),
					'notify_ip_blocked'                  => __( 'IP address blocked successfully', 'reportedip-hive' ),
					'notify_ip_block_failed'             => __( 'Failed to block IP address', 'reportedip-hive' ),
					'notify_ip_unblocked'                => __( 'IP address unblocked successfully', 'reportedip-hive' ),
					'notify_ip_unblock_failed'           => __( 'Failed to unblock IP address', 'reportedip-hive' ),
					'notify_ip_whitelisted'              => __( 'IP address whitelisted successfully', 'reportedip-hive' ),
					'notify_ip_whitelist_failed'         => __( 'Failed to whitelist IP address', 'reportedip-hive' ),
					'notify_no_ip'                       => __( 'No IP address found', 'reportedip-hive' ),
					'notify_copy_failed'                 => __( 'Failed to copy IP address', 'reportedip-hive' ),
					'notify_cleanup_failed'              => __( 'Failed to cleanup logs', 'reportedip-hive' ),
					'notify_anonymize_failed'            => __( 'Failed to anonymize data', 'reportedip-hive' ),
					'notify_logs_exported'               => __( 'Logs exported successfully', 'reportedip-hive' ),
					'notify_logs_export_failed'          => __( 'Failed to export logs', 'reportedip-hive' ),
					'notify_import_completed'            => __( 'Import completed.', 'reportedip-hive' ),
					'notify_import_failed'               => __( 'Import failed.', 'reportedip-hive' ),
					'lookup_enter_ip'                    => __( 'Please enter an IP address', 'reportedip-hive' ),
					'lookup_failed'                      => __( 'Failed to lookup IP address', 'reportedip-hive' ),
					'label_whitelisted'                  => __( 'Whitelisted', 'reportedip-hive' ),
					'label_blocked'                      => __( 'Blocked', 'reportedip-hive' ),
					'label_clean'                        => __( 'Clean', 'reportedip-hive' ),
					'label_ip_information'               => __( 'IP Information:', 'reportedip-hive' ),
					'label_valid'                        => __( 'Valid:', 'reportedip-hive' ),
					'label_private'                      => __( 'Private:', 'reportedip-hive' ),
					'label_version'                      => __( 'Version:', 'reportedip-hive' ),
					'label_yes'                          => __( 'Yes', 'reportedip-hive' ),
					'label_no'                           => __( 'No', 'reportedip-hive' ),
					'label_country'                      => __( 'Country:', 'reportedip-hive' ),
					'label_abuse_confidence'             => __( 'Abuse Confidence:', 'reportedip-hive' ),
					'label_total_reports'                => __( 'Total Reports:', 'reportedip-hive' ),
					'label_recent_activity'              => __( 'Recent Activity', 'reportedip-hive' ),
					'label_time'                         => __( 'Time', 'reportedip-hive' ),
					'label_event'                        => __( 'Event', 'reportedip-hive' ),
					'label_severity'                     => __( 'Severity', 'reportedip-hive' ),
					'label_isp'                          => __( 'ISP:', 'reportedip-hive' ),
					'label_asn'                          => __( 'ASN:', 'reportedip-hive' ),
					'label_usage_type'                   => __( 'Usage Type:', 'reportedip-hive' ),
					'label_domain'                       => __( 'Domain:', 'reportedip-hive' ),
					'label_distinct_reporters'           => __( 'Distinct Reporters:', 'reportedip-hive' ),
					'label_last_reported'                => __( 'Last Reported:', 'reportedip-hive' ),
					'label_tor'                          => __( 'Tor exit node', 'reportedip-hive' ),
					'label_infrastructure'               => __( 'Community-verified infrastructure', 'reportedip-hive' ),
					'action_block_ip'                    => __( 'Block IP', 'reportedip-hive' ),
					'action_whitelist_ip'                => __( 'Whitelist IP', 'reportedip-hive' ),
					'action_view_report'                 => __( 'View community report', 'reportedip-hive' ),
					'confirm_self_block'                 => __( 'This is your own current IP address. Blocking it can lock you out of wp-admin. Continue?', 'reportedip-hive' ),
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

		$days = in_array( (int) $days, array( 7, 30, 90 ), true ) ? (int) $days : 7;

		$analytics = ReportedIP_Hive_Database::get_instance()->get_threat_analytics( $days );

		$dist_labels = array();
		$dist_keys   = array();
		$dist_values = array();
		foreach ( $analytics['families'] as $family ) {
			$total = (int) ( $analytics['by_family'][ $family['key'] ] ?? 0 );
			if ( $total <= 0 ) {
				continue;
			}
			$dist_keys[]   = $family['key'];
			$dist_labels[] = $family['label'];
			$dist_values[] = $total;
		}

		$waf_label_map = class_exists( 'ReportedIP_Hive_WAF' ) ? ReportedIP_Hive_WAF::group_labels() : array();
		$waf_labels    = array();
		$waf_values    = array();
		foreach ( array_slice( $analytics['waf_groups'], 0, 8, true ) as $group => $count ) {
			$waf_labels[] = $waf_label_map[ $group ] ?? ucwords( str_replace( '_', ' ', (string) $group ) );
			$waf_values[] = (int) $count;
		}

		$severity = $analytics['by_severity'];

		return array(
			'ajaxUrl' => admin_url( 'admin-ajax.php' ),
			'nonce'   => wp_create_nonce( 'reportedip_charts_nonce' ),
			'mode'    => $mode_manager->get_mode(),
			'data'    => array(
				'securityEvents'     => array(
					'labels'   => $analytics['labels'],
					'families' => $analytics['families'],
				),
				'threatDistribution' => array(
					'labels' => $dist_labels,
					'keys'   => $dist_keys,
					'values' => $dist_values,
				),
				'wafGroups'          => array(
					'labels' => $waf_labels,
					'values' => $waf_values,
				),
				'severity'           => array(
					'critical' => (int) $severity['critical'],
					'high'     => (int) $severity['high'],
					'medium'   => (int) $severity['medium'],
					'low'      => (int) $severity['low'],
				),
			),
			'strings' => array(
				'events'   => __( 'Events', 'reportedip-hive' ),
				'attacks'  => __( 'Attacks', 'reportedip-hive' ),
				'critical' => __( 'Critical', 'reportedip-hive' ),
				'high'     => __( 'High', 'reportedip-hive' ),
				'medium'   => __( 'Medium', 'reportedip-hive' ),
				'low'      => __( 'Low', 'reportedip-hive' ),
			),
		);
	}

	/**
	 * Handle failed login attempts.
	 *
	 * On XML-RPC a failed application-password login fires both the
	 * `application_password_failed_authentication` hook and, afterwards in the
	 * same request, `wp_login_failed`. The application-password sensor has
	 * already logged and counted that wire attempt, so this listener consumes
	 * its claim and stands down for the duplicate row and attempt count while
	 * still feeding spray and coordinated-attack detection. The audit trail in
	 * `ReportedIP_Hive_Audit_Logger::on_login_failed()` is a separate
	 * compliance record and deliberately unaffected.
	 *
	 * @param string $username Username the failed attempt used.
	 */
	public function handle_failed_login( $username ) {
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_failed_logins', true ) ) {
			return;
		}

		$ip_address = $this->get_client_ip();

		if ( $this->ip_manager->is_whitelisted( $ip_address ) ) {
			return;
		}

		if ( $this->is_ip_blocked_cached( $ip_address ) ) {
			return;
		}

		$log_data = array();

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_detailed_logging', false ) ) {
			$log_data['username_hash'] = hash( 'sha256', $username . wp_salt() );
		}

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_user_agents', false ) ) {
			$user_agent             = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$log_data['user_agent'] = substr( $user_agent, 0, REPORTEDIP_USER_AGENT_MAX_LENGTH );
		}

		$deduped = class_exists( 'ReportedIP_Hive_App_Password_Monitor' )
			&& ReportedIP_Hive_App_Password_Monitor::consume_pending_failure();

		if ( ! $deduped ) {
			$this->logger->log_security_event( 'failed_login', $ip_address, $log_data );
		}

		$this->security_monitor->check_failed_login_threshold( $ip_address, $username, ! $deduped );
	}

	/**
	 * Pre-authentication check.
	 *
	 * Rejects the sign-in when the IP is locally blocked or the community
	 * reputation exceeds the block threshold. A reputation hit also writes a
	 * temporary `reputation` row into the blocked table (default 24 h,
	 * filterable via `reportedip_hive_reputation_block_hours`), so the IP is
	 * blocked on every surface — front-end, XML-RPC, REST — and appears in
	 * the Blocked IPs list instead of only failing the login form.
	 * Whitelisted IPs and the server's own addresses are never
	 * reputation-blocked.
	 *
	 * @param mixed  $user     User object or error.
	 * @param string $password Password (unused, kept for hook signature).
	 */
	public function pre_auth_check( $user, $password ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$ip_address        = $this->get_client_ip();
		$report_only       = $this->is_report_only_mode();
		$threshold         = ReportedIP_Hive_Hardening_Mode::effective_block_threshold(
			(int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_threshold', 75 )
		);
		$is_blocked        = $this->ip_manager->is_blocked( $ip_address );
		$reputation        = null;
		$exceeds_threshold = false;

		if ( $this->api_client->is_configured() ) {
			$reputation = $this->api_client->check_ip_reputation( $ip_address );
			if ( $reputation && isset( $reputation['abuseConfidencePercentage'] ) && $reputation['abuseConfidencePercentage'] >= $threshold ) {
				$exceeds_threshold = true;
			}
		}

		$is_infrastructure = is_array( $reputation ) && ! empty( $reputation['isWhitelisted'] );
		$tor_candidate     = ! $is_infrastructure && $this->should_block_tor_exit( $ip_address, $reputation );

		if ( $report_only ) {
			if ( $tor_candidate ) {
				$this->logger->log_security_event(
					'would_block_by_tor_exit',
					$ip_address,
					array(
						'reason'           => 'Known Tor exit node (blocking enabled, report-only mode active)',
						'report_only_mode' => true,
					),
					'high'
				);
			}
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

			if ( $exceeds_threshold && $is_infrastructure ) {
				$this->log_infrastructure_spared( $ip_address, $reputation, $threshold, true );
			} elseif ( $exceeds_threshold ) {
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

		if ( $exceeds_threshold && $is_infrastructure ) {
			$this->log_infrastructure_spared( $ip_address, $reputation, $threshold, false );
		}

		if ( $exceeds_threshold && ! $is_infrastructure && ! $this->ip_manager->is_whitelisted( $ip_address ) && ! self::is_own_server_ip( $ip_address ) ) {
			$confidence = isset( $reputation['abuseConfidencePercentage'] ) ? (int) $reputation['abuseConfidencePercentage'] : 0;
			$reports    = isset( $reputation['totalReports'] ) ? (int) $reputation['totalReports'] : 0;

			/**
			 * Filters how long a community-reputation hit stays blocked locally.
			 *
			 * A reputation verdict is a point-in-time snapshot, so the local
			 * block is temporary: after the window expires the next login
			 * attempt re-evaluates the (re-fetched) reputation.
			 *
			 * @param int $hours Block duration in hours (default 24).
			 * @since 2.1.28
			 */
			$block_hours = max( 1, (int) apply_filters( 'reportedip_hive_reputation_block_hours', 24 ) );

			$database = ReportedIP_Hive_Database::get_instance();
			$database->block_ip(
				$ip_address,
				sprintf( 'Community reputation: %d%% confidence (threshold %d%%)', $confidence, $threshold ),
				'reputation',
				$block_hours
			);
			$database->update_daily_stats( 'reputation_blocks' );
			$this->mark_ip_blocked( $ip_address );

			$this->logger->log_security_event(
				'blocked_by_reputation',
				$ip_address,
				array(
					'confidence'  => $confidence,
					'reports'     => $reports,
					'threshold'   => $threshold,
					'block_hours' => $block_hours,
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

		if ( $tor_candidate && ! $this->ip_manager->is_whitelisted( $ip_address ) && ! self::is_own_server_ip( $ip_address ) ) {
			/**
			 * Filters how long a Tor exit node stays blocked locally.
			 *
			 * Exit nodes rotate quickly, so the block is temporary: after the
			 * window expires the next login attempt re-evaluates the address
			 * against the refreshed exit-node list.
			 *
			 * @param int $hours Block duration in hours (default 24).
			 * @since 2.1.41
			 */
			$tor_block_hours = max( 1, (int) apply_filters( 'reportedip_hive_tor_block_hours', 24 ) );

			$database = ReportedIP_Hive_Database::get_instance();
			$database->block_ip(
				$ip_address,
				'Tor exit node',
				'reputation',
				$tor_block_hours
			);
			$database->update_daily_stats( 'reputation_blocks' );
			$this->mark_ip_blocked( $ip_address );

			$this->logger->log_security_event(
				'blocked_by_tor_exit',
				$ip_address,
				array(
					'reason'      => 'Known Tor exit node (Tor blocking enabled)',
					'block_hours' => $tor_block_hours,
				),
				'high'
			);

			return new WP_Error( 'ip_tor_block', __( 'Access denied: connections from Tor exit nodes are not allowed on this site.', 'reportedip-hive' ) );
		}

		return $user;
	}

	/**
	 * Whether the current request should be treated as a blockable Tor exit
	 * node: the feature must be tier-available (Professional+), the operator
	 * must have enabled the toggle, and the address must match the synced
	 * exit-node ruleset or carry the community isTor flag.
	 *
	 * Running an exit node is not abuse evidence, so Tor blocks never produce
	 * a community report — the block row is the only consequence, and it
	 * reaches the pre-WordPress guard through the regular blocklist bridge.
	 *
	 * @param string     $ip_address Client IP.
	 * @param array|bool $reputation Reputation payload from the check response, or false.
	 * @return bool
	 * @since  2.1.41
	 */
	private function should_block_tor_exit( $ip_address, $reputation ) {
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_tor', false ) ) {
			return false;
		}

		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( 'tor_blocking' );
		if ( empty( $status['available'] ) ) {
			return false;
		}

		return self::is_tor_exit( $ip_address, $reputation );
	}

	/**
	 * Check an address against the synced `tor_exits` ruleset, falling back
	 * to the community isTor flag for addresses the (possibly stale) list
	 * does not carry yet.
	 *
	 * The feed delivers flat CIDR strings (`x.x.x.x/32`, IPv6 `/128`), so
	 * host entries are reduced to a per-request hash set for O(1) lookups;
	 * genuine ranges (rare) fall back to the CIDR matcher.
	 *
	 * @param string     $ip_address Client IP.
	 * @param array|bool $reputation Reputation payload from the check response, or false.
	 * @return bool
	 * @since  2.1.41
	 */
	public static function is_tor_exit( $ip_address, $reputation = false ) {
		static $exact  = null;
		static $ranges = null;

		if ( null === $exact ) {
			$exact  = array();
			$ranges = array();

			$ruleset = ReportedIP_Hive_Rule_Sync::get_instance()->get_ruleset( 'tor_exits' );
			foreach ( (array) $ruleset['rules'] as $entry ) {
				if ( ! is_string( $entry ) || '' === $entry ) {
					continue;
				}
				if ( substr( $entry, -3 ) === '/32' || substr( $entry, -4 ) === '/128' ) {
					$exact[ substr( $entry, 0, (int) strrpos( $entry, '/' ) ) ] = true;
				} elseif ( false === strpos( $entry, '/' ) ) {
					$exact[ $entry ] = true;
				} else {
					$ranges[] = $entry;
				}
			}
		}

		if ( isset( $exact[ $ip_address ] ) ) {
			return true;
		}

		foreach ( $ranges as $range ) {
			if ( ReportedIP_Hive_Database::ip_in_cidr( $ip_address, $range ) ) {
				return true;
			}
		}

		return is_array( $reputation ) && ! empty( $reputation['isTor'] );
	}

	/**
	 * Log that an over-threshold IP was spared because the community marks it
	 * as curated infrastructure (search engines, major CDNs, monitoring).
	 *
	 * The reputation service itself whitelists these addresses, so an
	 * over-threshold score for one of them is treated as noise: no local
	 * block is written and no reputation_threat report is sent. Throttled to
	 * one log line per IP per hour.
	 *
	 * @param string $ip_address  Client IP.
	 * @param array  $reputation  Reputation payload from the check response.
	 * @param int    $threshold   Effective block threshold.
	 * @param bool   $report_only Whether report-only mode is active.
	 * @return void
	 * @since  2.1.41
	 */
	private function log_infrastructure_spared( $ip_address, $reputation, $threshold, $report_only ) {
		$log_gate = 'reportedip_hive_infra_spared_' . md5( $ip_address . '|reputation' );
		if ( false !== get_transient( $log_gate ) ) {
			return;
		}
		set_transient( $log_gate, 1, HOUR_IN_SECONDS );

		$this->logger->log_security_event(
			'infrastructure_spared',
			$ip_address,
			array(
				'confidence'       => isset( $reputation['abuseConfidencePercentage'] ) ? (int) $reputation['abuseConfidencePercentage'] : 0,
				'threshold'        => $threshold,
				'reason'           => 'Community reputation marks this IP as curated infrastructure (never-block)',
				'report_only_mode' => (bool) $report_only,
			),
			'medium'
		);
	}

	/**
	 * Handle comment posts.
	 *
	 * The IP comes from `get_client_ip()`, not from `comment_author_IP`:
	 * WordPress fills that field from REMOTE_ADDR and ignores the configured
	 * client-IP header, so behind a reverse proxy every visitor's spam
	 * aggregated onto the edge address. That both reported infrastructure to
	 * the community feed and left the actual spammer untouched, because
	 * enforcement resolves the client IP the canonical way.
	 *
	 * @param int    $comment_id  Comment ID.
	 * @param mixed  $approved    Approval state, or 'spam'.
	 * @param array  $commentdata Comment data.
	 * @return void
	 * @since  1.0.0
	 */
	public function handle_comment_post( $comment_id, $approved, $commentdata ) {
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_comments', true ) ) {
			return;
		}

		$ip_address = $this->get_client_ip();

		if ( $this->ip_manager->is_whitelisted( $ip_address ) ) {
			return;
		}

		if ( $this->is_ip_blocked_cached( $ip_address ) ) {
			return;
		}

		if ( $approved === 'spam' || $approved === 0 ) {
			$log_data = array(
				'comment_id' => $comment_id,
			);

			if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_detailed_logging', false ) ) {
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
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_monitor_xmlrpc', true ) ) {
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
			'method' => $method,
		);

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_user_agents', false ) ) {
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

		$log_data = array();

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_detailed_logging', false ) ) {
			$log_data['username_hash'] = hash( 'sha256', $user_login . wp_salt() );
			$log_data['user_id']       = $user->ID;
		}

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_log_user_agents', false ) ) {
			$user_agent             = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$log_data['user_agent'] = substr( $user_agent, 0, REPORTEDIP_USER_AGENT_MAX_LENGTH );
		}

		$this->logger->log_security_event( 'successful_login', $ip_address, $log_data );
	}

	/**
	 * Whether the current request belongs to a logged-in operator who must
	 * never be locked out by an automatic IP block.
	 *
	 * A site admin, editor or shop manager (the `edit_others_posts` capability)
	 * who happens to share an IP that a sensor auto-blocked — e.g. one tripped
	 * by anonymous front-end plugin traffic from the same network — would
	 * otherwise be wp_die()'d out of their own site and backend. The exemption
	 * is keyed on capability, not merely login: it cannot be abused without
	 * valid privileged credentials, at which point an IP block is moot anyway.
	 * It only spares the authenticated operator session; anonymous visitors on
	 * the same blocked IP are still served the block.
	 *
	 * @return bool True when the current user must not be IP-blocked.
	 * @since  2.0.23
	 */
	private function is_block_exempt_operator() {
		return is_user_logged_in() && current_user_can( 'edit_others_posts' );
	}

	/**
	 * Block back-office access for blocked IPs.
	 *
	 * `admin-ajax.php` does fire `admin_init`, but it never reaches this
	 * handler: {@see self::check_ip_access()} runs on `init` and has already
	 * ended the request there, with a JSON body an AJAX caller can read rather
	 * than the `wp_die()` page below. This is the backstop for wp-admin screens.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	public function block_admin_access() {
		if ( ! is_admin() ) {
			return;
		}

		if ( $this->is_report_only_mode() ) {
			return;
		}

		if ( $this->is_block_exempt_operator() ) {
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

		$table = ReportedIP_Hive_Schema::table( 'reportedip_hive_api_queue' );
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe table name composed from Schema::table() with a hardcoded suffix.
		$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '$table'" ) === $table;
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

		if ( $table_exists ) {
			// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name built from Schema::table() with a hardcoded suffix; safe.
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
				$queue_url = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=api_queue' );
				$body      = sprintf(
					'<strong>%1$s</strong> %2$s',
					esc_html__( 'ReportedIP Hive:', 'reportedip-hive' ),
					sprintf(
						/* translators: %1$d: number of failed reports, %2$s: link to queue page */
						esc_html__( '%1$d API reports failed. %2$s', 'reportedip-hive' ),
						intval( $failed_count ),
						'<a href="' . esc_url( $queue_url ) . '">' . esc_html__( 'View queue', 'reportedip-hive' ) . '</a>'
					)
				);
				ReportedIP_Hive_Admin_Notice::render(
					array(
						'variant'           => 'error',
						'dismissible'       => true,
						'body'              => $body,
						'secondary_actions' => array(
							array(
								'type'    => 'button',
								'label'   => __( 'Retry all', 'reportedip-hive' ),
								'id'      => 'retry-failed-reports-notice',
								'variant' => 'secondary',
							),
						),
					)
				);
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

			$warning_threshold  = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_queue_warning_threshold', 50 );
			$critical_threshold = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_queue_critical_threshold', 200 );
			$queue_url          = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-security&tab=api_queue' );
			$community_url      = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive-community' );
			$queue_dismissed    = get_user_meta( $user_id, 'reportedip_dismissed_queue_warning_' . gmdate( 'Y-m-d' ), true );

			if ( $pending_count >= $critical_threshold ) {
				$body = sprintf(
					'<strong>%1$s</strong> %2$s',
					esc_html__( 'ReportedIP Hive - Queue Critical:', 'reportedip-hive' ),
					sprintf(
						/* translators: %1$d: number of pending reports, %2$s: link to community page, %3$s: link to queue page */
						esc_html__( '%1$d reports pending processing. Your API quota may not be sufficient. %2$s or %3$s.', 'reportedip-hive' ),
						intval( $pending_count ),
						'<a href="' . esc_url( $community_url ) . '">' . esc_html__( 'Upgrade API tier', 'reportedip-hive' ) . '</a>',
						'<a href="' . esc_url( $queue_url ) . '">' . esc_html__( 'Manage queue', 'reportedip-hive' ) . '</a>'
					)
				);
				ReportedIP_Hive_Admin_Notice::render(
					array(
						'variant'        => 'error',
						'dismissible'    => true,
						'data_notice_id' => 'queue_critical_' . gmdate( 'Y-m-d' ),
						'body'           => $body,
					)
				);
			} elseif ( $pending_count >= $warning_threshold && ! $queue_dismissed ) {
				$body = sprintf(
					'<strong>%1$s</strong> %2$s',
					esc_html__( 'ReportedIP Hive:', 'reportedip-hive' ),
					sprintf(
						/* translators: %1$d: number of pending reports, %2$s: link to community page */
						esc_html__( '%1$d reports pending processing. %2$s for higher limits.', 'reportedip-hive' ),
						intval( $pending_count ),
						'<a href="' . esc_url( $community_url ) . '">' . esc_html__( 'Upgrade API tier', 'reportedip-hive' ) . '</a>'
					)
				);
				ReportedIP_Hive_Admin_Notice::render(
					array(
						'variant'        => 'warning',
						'dismissible'    => true,
						'data_notice_id' => 'queue_warning_' . gmdate( 'Y-m-d' ),
						'body'           => $body,
					)
				);
			}
		}

		$api_key = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );
		if ( empty( $api_key ) && $is_plugin_page ) {
			$settings_url = ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=reportedip-hive' );
			$body         = sprintf(
				'<strong>%1$s</strong> %2$s',
				esc_html__( 'ReportedIP Hive:', 'reportedip-hive' ),
				sprintf(
					/* translators: %s: link to settings page */
					esc_html__( 'No API key configured. %s', 'reportedip-hive' ),
					'<a href="' . esc_url( $settings_url ) . '">' . esc_html__( 'Configure now', 'reportedip-hive' ) . '</a>'
				)
			);
			ReportedIP_Hive_Admin_Notice::render(
				array(
					'variant'     => 'warning',
					'dismissible' => true,
					'body'        => $body,
				)
			);
		}

		if ( class_exists( 'ReportedIP_Hive_Admin_Settings' ) ) {
			ReportedIP_Hive_Admin_Settings::maybe_render_domain_limit_notice();
		}
	}

	/**
	 * Object-cache key holding the cached access verdict for one IP.
	 *
	 * The key carries an epoch so verdicts that cannot be addressed
	 * individually — everything decided by a CIDR range or the whitelist —
	 * can still be dropped in one step by advancing the epoch.
	 *
	 * @param string $ip_address Client IP.
	 * @return string Cache key inside the `reportedip` group.
	 * @since  2.1.44
	 */
	private static function ip_verdict_cache_key( $ip_address ) {
		$epoch = (int) ReportedIP_Hive_Option_Routing::get( self::OPTION_ACCESS_CACHE_EPOCH, 0 );

		return 'rip_access_' . $epoch . '_' . md5( (string) $ip_address );
	}

	/**
	 * Drop cached access verdicts after the block or whitelist state changed.
	 *
	 * Without this the 300-second verdict cache outlives the decision that
	 * produced it: a freshly blocked IP would keep browsing on a warm
	 * `allowed` entry, and an unblocked visitor would keep receiving the 403
	 * long after the block was lifted. Only relevant with a persistent object
	 * cache — otherwise `wp_cache_*` is request-local and expires anyway.
	 *
	 * An exact IP invalidates just its own key. A CIDR range (or an empty
	 * argument) cannot enumerate the addresses it covers, so it advances the
	 * epoch and retires every cached verdict at once.
	 *
	 * @param string $ip_address IP, CIDR range, or '' for a full flush.
	 * @return void
	 * @since  2.1.44
	 */
	public static function flush_ip_verdict_cache( $ip_address = '' ) {
		$ip_address = (string) $ip_address;

		if ( '' !== $ip_address && false === strpos( $ip_address, '/' ) ) {
			wp_cache_delete( self::ip_verdict_cache_key( $ip_address ), 'reportedip' );
			return;
		}

		/*
		 * The generation is the time of the flush, not a counter: incrementing
		 * means read-then-write, and two flushes racing (an admin clearing the
		 * cache while the cleanup cron expires a whitelist row) would both read
		 * the same value and one invalidation would be lost. A timestamp is
		 * safe to write blind — concurrent flushes want the same outcome.
		 */
		ReportedIP_Hive_Option_Routing::set( self::OPTION_ACCESS_CACHE_EPOCH, time() );
	}

	/**
	 * Enforce the IP block list on every front-controller request.
	 *
	 * `admin-ajax.php` is deliberately included: it is reachable without
	 * authentication through every `wp_ajax_nopriv_*` action a site has
	 * registered, so exempting it left blocked IPs a fully unguarded entry
	 * point. Only WP-Cron stays exempt — its loopback originates from the
	 * server itself and must never be able to self-block the site.
	 * Authenticated operators are spared separately by
	 * {@see self::is_block_exempt_operator()}.
	 *
	 * @return void
	 * @since  1.0.0
	 */
	private function check_ip_access() {
		if ( wp_doing_cron() ) {
			return;
		}

		if ( $this->is_block_exempt_operator() ) {
			return;
		}

		$ip_address = $this->get_client_ip();

		$cache_key = self::ip_verdict_cache_key( $ip_address );
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
	private function show_blocked_page( $reason = 'ip_block' ) {
		self::serve_blocked_page( $reason );
	}

	/**
	 * Render the 403 block page and terminate. Public entry point so sensors
	 * that live in their own classes (e.g. the WAF engine) reject the current
	 * request through the identical cache-safe, ref-coded response path.
	 *
	 * @param string $reason Reason key (see {@see ReportedIP_Hive_Block_Ref::CATEGORY_MAP}).
	 * @return void
	 * @since  2.1.2
	 */
	public static function serve_blocked_page( $reason = 'ip_block' ) {
		$reportedip_hive_block_context = is_string( $reason ) && '' !== $reason ? $reason : 'ip_block';

		self::emit_block_response_headers();

		/**
		 * Fires once per denied request, just before the 403 block page is
		 * served. Guard-layer (pre-WordPress) refusals never reach this hook —
		 * they terminate before WordPress loads.
		 *
		 * @param string $ip      Client IP the request was attributed to.
		 * @param string $context Normalized block context (see {@see ReportedIP_Hive_Block_Ref::CATEGORY_MAP}).
		 * @since 2.1.41
		 */
		do_action( 'reportedip_hive_access_denied', self::get_client_ip(), $reportedip_hive_block_context );

		status_header( 403 );

		/*
		 * AJAX and REST callers cannot render the themed block page — they
		 * expect a machine-readable body. Serving the full HTML document there
		 * would leave the caller parsing markup for a status it already has.
		 */
		if ( wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			wp_send_json_error(
				array(
					'code'    => 'ip_blocked',
					'message' => __( 'Access denied. Your IP address has been blocked due to suspicious activity.', 'reportedip-hive' ),
				),
				403
			);
		}

		include REPORTEDIP_HIVE_PLUGIN_DIR . 'templates/blocked.php';
		exit;
	}

	/**
	 * Accessor for the shared structured logger.
	 *
	 * @return ReportedIP_Hive_Logger|null
	 * @since  2.1.2
	 */
	public function get_logger() {
		return $this->logger;
	}

	/**
	 * Resolve the public reference code for a blocked-page response.
	 *
	 * Thin facade over {@see ReportedIP_Hive_Block_Ref::code()} that supplies
	 * the central client IP. The IP is only hashed into the incident token and
	 * never appears in the returned string, so the code is safe to print on the
	 * block page and emit as the `X-RIP-Ref` header.
	 *
	 * @param string               $reason  Reason key (see ReportedIP_Hive_Block_Ref::CATEGORY_MAP).
	 * @param array<string, mixed> $context Optional context (`minutes`, `window`).
	 * @return string Reference code, e.g. `IP_BLOCK-3F9A2B71`.
	 * @since  2.1.0
	 */
	public static function block_ref_code( $reason, $context = array() ) {
		if ( ! class_exists( 'ReportedIP_Hive_Block_Ref' ) ) {
			require_once REPORTEDIP_HIVE_PLUGIN_DIR . 'includes/class-block-ref.php';
		}
		return ReportedIP_Hive_Block_Ref::code( $reason, self::get_client_ip(), is_array( $context ) ? $context : array() );
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
	 * Neutralise the front-end head/footer side-effects that misfire when a
	 * standalone plugin page (setup wizard, 2FA onboarding) renders inside
	 * wp-admin.
	 *
	 * Because `is_admin()` is true while `wp_head()`/`wp_footer()` run, the
	 * front-end `wp_enqueue_scripts` phase would invoke third-party theme /
	 * optimisation callbacks that deregister core scripts like jQuery — which
	 * WordPress rejects in the admin area with a `_doing_it_wrong` notice. These
	 * pages enqueue their own assets directly, so the whole front-end enqueue
	 * phase plus the emoji detector and the admin-bar bump styles are pure
	 * third-party noise here. Callers still hide the bar via
	 * `show_admin_bar( false )`.
	 *
	 * @since 2.1.21
	 * @return void
	 */
	public static function isolate_standalone_frontend_page() {
		remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
		remove_action( 'wp_print_styles', 'print_emoji_styles' );
		remove_action( 'wp_head', 'wp_admin_bar_header' );
		remove_action( 'wp_footer', 'wp_admin_bar_render', 1000 );
		remove_action( 'wp_head', 'wp_enqueue_scripts', 1 );
		remove_action( 'wp_head', 'wp_enqueue_admin_bar_bump_styles' );
		remove_action( 'wp_head', 'wp_enqueue_admin_bar_header_styles' );
		remove_action( 'wp_head', '_admin_bar_bump_cb' );
	}

	/**
	 * Check if plugin is in report-only mode
	 */
	private function is_report_only_mode() {
		return ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false );
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
	 * Only trusts the explicitly configured header (reportedip_hive_trusted_ip_header),
	 * and only when the connecting peer passes the trusted-proxy source check
	 * (reportedip_hive_trusted_proxy_ranges — empty list trusts every peer).
	 * If no trusted header is configured, the header is absent, or the peer is
	 * not a declared proxy, falls back to REMOTE_ADDR. This prevents IP
	 * spoofing via arbitrary proxy headers, including direct-to-origin
	 * requests that carry a forged header past a CDN.
	 *
	 * @return string The client IP address or 'unknown' if not determinable
	 */
	public static function get_client_ip() {
		static $trusted_header = null;
		static $trusted_ranges = null;
		if ( null === $trusted_header ) {
			$trusted_header = ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_ip_header', '' );
			$trusted_ranges = ReportedIP_Hive_Proxy_Trust::parse_ranges(
				(string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_trusted_proxy_ranges', '' )
			);
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized via filter_var
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';

		if ( ! empty( $trusted_header )
			&& isset( $_SERVER[ $trusted_header ] )
			&& ReportedIP_Hive_Proxy_Trust::source_is_trusted( $remote_addr, $trusted_ranges )
		) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized via filter_var below
			$server_value = wp_unslash( $_SERVER[ $trusted_header ] );
			$ips          = explode( ',', (string) $server_value );
			$ip           = trim( $ips[0] );
			/*
			 * Only accept a publicly-routable address from the proxy header. A
			 * private or reserved value (a loopback/RFC1918 hop the proxy
			 * prepended, an internal health-check, or a spoofed 10.0.0.1) must
			 * not become the "client" IP, or internal infrastructure ends up
			 * flagged as an attacker and queued for an API report it can never
			 * pass. Falls through to REMOTE_ADDR when the header is not public.
			 */
			if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) !== false ) {
				return $ip;
			}
		}

		return filter_var( $remote_addr, FILTER_VALIDATE_IP ) ? $remote_addr : 'unknown';
	}

	/**
	 * Whether an address is a publicly-routable IP that may be blocked, reported
	 * or escalated. Rejects the empty/`unknown` sentinel and every private or
	 * reserved range (loopback `127.0.0.1`/`::1`, RFC1918 `10/172.16/192.168`,
	 * link-local, etc.). Loopback and internal requests (wp-cron, REST loopback,
	 * proxy health checks) legitimately carry such addresses; they are never an
	 * external attacker, so the sensors and the report queue must skip them.
	 *
	 * @param string $ip Candidate IP address.
	 * @return bool      True when the address is a public, reportable IP.
	 * @since  2.1.5
	 */
	public static function is_public_ip( $ip ) {
		if ( ! is_string( $ip ) || '' === $ip || 'unknown' === $ip ) {
			return false;
		}
		return false !== filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Whether an address is one of the server's own — a loopback address, the
	 * interface address the current request arrived on, or an address the
	 * site's own hostname resolves to.
	 *
	 * Self-traffic legitimately hammers the site: cache-preload crawlers,
	 * WP-Cron loopbacks and REST self-requests all connect back through the
	 * site's public URL, so their REMOTE_ADDR is the server's own public
	 * address — which passes {@see is_public_ip()}. Auto-blocking that address
	 * takes every loopback down with it (the pre-WordPress guard enforces the
	 * block before any path exception), and reporting it poisons the site's
	 * own community reputation. The automatic pipeline therefore stands down
	 * for these addresses; manual blocks remain possible.
	 *
	 * @param string $ip Candidate IP address.
	 * @return bool      True when the address belongs to the server itself.
	 * @since  2.1.31
	 */
	public static function is_own_server_ip( $ip ) {
		if ( ! is_string( $ip ) || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		if ( 0 === strpos( $ip, '127.' ) || ReportedIP_Hive_Bot_Verifier::ip_equals( $ip, '::1' ) ) {
			return true;
		}

		foreach ( self::get_own_server_ips() as $candidate ) {
			if ( ReportedIP_Hive_Bot_Verifier::ip_equals( $ip, (string) $candidate ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The server's own addresses: the interface address the current request
	 * arrived on plus every address the site hostname resolves to.
	 *
	 * Memoised per request; the list is only consulted when a sensor
	 * threshold actually trips, never on the hot path.
	 *
	 * @return string[] IP addresses considered "the server itself".
	 * @since  2.1.31
	 */
	private static function get_own_server_ips() {
		static $cache = null;
		if ( is_array( $cache ) ) {
			return $cache;
		}

		$ips = array();

		if ( isset( $_SERVER['SERVER_ADDR'] ) ) {
			$server_addr = (string) wp_unslash( $_SERVER['SERVER_ADDR'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized via filter_var below.
			if ( false !== filter_var( $server_addr, FILTER_VALIDATE_IP ) ) {
				$ips[] = $server_addr;
			}
		}

		$ips = array_merge( $ips, self::resolve_site_host_ips() );

		/**
		 * Filters the list of addresses treated as the server's own.
		 *
		 * Multi-node setups (a separate cron runner, an internal proxy, a
		 * second interface the loopbacks leave through) can append addresses
		 * the automatic block pipeline must never target.
		 *
		 * @param string[] $ips Own-server IP addresses.
		 * @since 2.1.31
		 */
		$cache = (array) apply_filters( 'reportedip_hive_own_server_ips', array_values( array_unique( $ips ) ) );

		return $cache;
	}

	/**
	 * Resolve the site's own hostname to its addresses.
	 *
	 * Loopback requests that enter through a local proxy or a second
	 * interface do not match SERVER_ADDR, so the addresses the site's DNS
	 * name points at complete the picture. The lookup itself is the same
	 * forward resolver the bot verifier uses
	 * ({@see ReportedIP_Hive_Bot_Verifier::resolve_host_ips()}); results —
	 * a failed lookup included — are cached network-wide for six hours.
	 *
	 * @return string[] Addresses the site hostname resolves to.
	 * @since  2.1.31
	 */
	private static function resolve_site_host_ips() {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( ! is_string( $host ) || '' === $host ) {
			return array();
		}

		$host = strtolower( trim( $host, '[]' ) );
		if ( false !== filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return array( $host );
		}

		$cache_key = 'reportedip_hive_own_host_ips_' . md5( $host );
		$cached    = get_site_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}

		$resolved = ReportedIP_Hive_Bot_Verifier::resolve_host_ips( $host );

		set_site_transient( $cache_key, $resolved, 6 * HOUR_IN_SECONDS );

		return $resolved;
	}

	/**
	 * Format a stored UTC datetime string for display in the site timezone.
	 *
	 * Every plugin datetime column (except the admin-entered whitelist expiry)
	 * is stored in UTC. Admin tables render those values through this helper so
	 * the same install reads correctly for an operator in any timezone instead
	 * of showing raw UTC.
	 *
	 * @param string $utc_mysql A 'Y-m-d H:i:s' UTC datetime string.
	 * @return string           Localised datetime, or '' when empty/invalid.
	 * @since  2.1.14
	 */
	public static function format_local_datetime( $utc_mysql ) {
		$utc_mysql = (string) $utc_mysql;
		if ( '' === $utc_mysql || 0 === strpos( $utc_mysql, '0000-00-00' ) ) {
			return '';
		}
		if ( false === date_create( $utc_mysql, new DateTimeZone( 'UTC' ) ) ) {
			return '';
		}
		$format = get_option( 'date_format', 'Y-m-d' ) . ' ' . get_option( 'time_format', 'H:i:s' );
		return get_date_from_gmt( $utc_mysql, $format );
	}

	/**
	 * Get the canonical option-key => default map.
	 *
	 * Delegates to {@see ReportedIP_Hive_Defaults::all_option_defaults()} —
	 * the single source of truth for every plugin default.
	 *
	 * @return array<string, scalar>
	 */
	public static function get_default_options() {
		return ReportedIP_Hive_Defaults::all_option_defaults();
	}

	/**
	 * Apply default options (public wrapper for external access).
	 */
	public static function apply_default_options() {
		self::set_default_options_static();
	}

	/**
	 * Seed missing defaults at activation through the option router so that
	 * network-wide keys land in sitemeta on Multisite. Existing values are
	 * never overwritten.
	 */
	private static function set_default_options_static() {
		ReportedIP_Hive_Defaults::seed_missing();
	}

	/**
	 * Seed newly-added default options after an in-place plugin update.
	 *
	 * The activation hook only fires on a manual (re)activation, so options
	 * introduced in a release are missing on a site that auto-updated. A boolean
	 * default-on option without a stored row cannot be switched off — WordPress
	 * treats `update_option( $key, false )` on an absent option as a no-op — so
	 * its admin toggle would silently do nothing. Re-seeding once per version
	 * change (gated by a stored version marker, main-site-only on Multisite so
	 * the network keys are written once) closes that gap.
	 *
	 * @return void
	 * @since 2.1.2
	 */
	public static function maybe_seed_on_upgrade() {
		$stored = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_seeded_version', '' );
		if ( REPORTEDIP_HIVE_VERSION === $stored ) {
			return;
		}
		ReportedIP_Hive_Defaults::seed_missing();
		ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_seeded_version', REPORTEDIP_HIVE_VERSION );
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
