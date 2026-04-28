<?php
/**
 * Admin Settings Class for ReportedIP Hive.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_Admin_Settings {

	private $database;
	private $api_client;
	private $logger;

	public function __construct() {
		$this->database   = ReportedIP_Hive_Database::get_instance();
		$this->api_client = ReportedIP_Hive_API::get_instance();
		$this->logger     = ReportedIP_Hive_Logger::get_instance();

		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_init', array( 'ReportedIP_Hive_Two_Factor_Admin', 'register_settings' ) );
	}

	/**
	 * Render unified page header for all plugin pages
	 *
	 * @param string $title   Page title
	 * @param string $subtitle Page subtitle/description
	 */
	private function render_page_header( $title, $subtitle ) {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$mode_info    = $mode_manager->get_mode_info();
		?>
		<div class="wrap rip-wrap">
			<div class="rip-header">
				<div class="rip-header__brand">
					<div class="rip-header__logo">
						<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
							<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4z" fill="currentColor" opacity="0.15"/>
							<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4zm0 4.2l12 6v10c0 8.4-6 16.3-12 18.5-6-2.2-12-10.1-12-18.5v-10l12-6z" fill="currentColor"/>
							<path d="M21 28l-5-5 1.8-1.8 3.2 3.2 7.2-7.2L30 19l-9 9z" fill="currentColor"/>
						</svg>
					</div>
					<div>
						<h1 class="rip-header__title"><?php echo esc_html( $title ); ?></h1>
						<p class="rip-header__subtitle"><?php echo esc_html( $subtitle ); ?></p>
					</div>
				</div>
				<div class="rip-header__actions">
					<span class="rip-mode-badge <?php echo esc_attr( $mode_info['badge_class'] ); ?>">
						<?php if ( $mode_info['key'] === 'local' ) : ?>
							<svg viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
						<?php else : ?>
							<svg viewBox="0 0 20 20" fill="currentColor"><circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="2" fill="none"/><path d="M2 10h16M10 2c2.8 2.8 4.4 6.5 4.4 8s-1.6 5.2-4.4 8c-2.8-2.8-4.4-6.5-4.4-8s1.6-5.2 4.4-8z" stroke="currentColor" stroke-width="1.5" fill="none"/></svg>
						<?php endif; ?>
						<?php echo esc_html( $mode_info['label'] ); ?>
					</span>
				</div>
			</div>

			<?php $this->render_inline_notices(); ?>
		<?php
	}

	/**
	 * Render unified page footer with trust badges
	 */
	private function render_page_footer() {
		?>
			<div class="rip-trust-badges">
				<div class="rip-trust-badge">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					<?php esc_html_e( 'Security Focused', 'reportedip-hive' ); ?>
				</div>
				<div class="rip-trust-badge">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
					<?php esc_html_e( 'GDPR Compliant', 'reportedip-hive' ); ?>
				</div>
				<div class="rip-trust-badge">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>
					<?php esc_html_e( 'Made in Germany', 'reportedip-hive' ); ?>
				</div>
			</div>
		</div><!-- /.wrap.rip-wrap -->
		<?php
	}

	/**
	 * Render inline notices within plugin pages (replaces admin_notices)
	 */
	public function render_inline_notices() {
		global $wpdb;

		$table = $wpdb->prefix . 'reportedip_hive_api_queue';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe table name composed from $wpdb->prefix and a hardcoded suffix.
		$table_exists = $wpdb->get_var( "SHOW TABLES LIKE '$table'" ) === $table;

		if ( ! $table_exists ) {
			return;
		}

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
			?>
			<div class="rip-alert rip-alert--error" style="margin-bottom: var(--rip-space-4);">
				<strong><?php esc_html_e( 'ReportedIP Hive:', 'reportedip-hive' ); ?></strong>
				<?php
				printf(
					/* translators: %1$d: number of failed reports, %2$s: link to queue page */
					esc_html__( '%1$d API reports failed. %2$s', 'reportedip-hive' ),
					intval( $failed_count ),
					'<a href="' . esc_url( $queue_url ) . '">' . esc_html__( 'View queue', 'reportedip-hive' ) . '</a>'
				);
				?>
				<button type="button" class="button button-small" id="retry-failed-reports-notice" style="margin-left: 10px;">
					<?php esc_html_e( 'Retry all', 'reportedip-hive' ); ?>
				</button>
			</div>
			<script>
			jQuery(document).ready(function($) {
				$('#retry-failed-reports-notice').on('click', function(e) {
					e.preventDefault();
					var $btn = $(this);
					$btn.prop('disabled', true).text('<?php echo esc_js( __( 'Retrying…', 'reportedip-hive' ) ); ?>');
					$.post(ajaxurl, {
						action: 'reportedip_hive_retry_all_failed',
						nonce: '<?php echo esc_js( wp_create_nonce( 'reportedip_hive_nonce' ) ); ?>'
					}, function(response) {
						if (response.success) {
							location.reload();
						} else {
							$btn.prop('disabled', false).text('<?php echo esc_js( __( 'Retry all', 'reportedip-hive' ) ); ?>');
						}
					});
				});
			});
			</script>
			<?php
		}

		$warning_threshold  = get_option( 'reportedip_hive_queue_warning_threshold', 50 );
		$critical_threshold = get_option( 'reportedip_hive_queue_critical_threshold', 200 );

		if ( $pending_count >= $critical_threshold ) {
			$queue_url     = admin_url( 'admin.php?page=reportedip-hive-security&tab=api_queue' );
			$community_url = admin_url( 'admin.php?page=reportedip-hive-community' );
			?>
			<div class="rip-alert rip-alert--error" style="margin-bottom: var(--rip-space-4);">
				<strong><?php esc_html_e( 'Queue Critical:', 'reportedip-hive' ); ?></strong>
				<?php
				printf(
					/* translators: 1: pending count, 2: upgrade link, 3: queue link */
					esc_html__( '%1$d reports pending processing. %2$s or %3$s.', 'reportedip-hive' ),
					intval( $pending_count ),
					'<a href="' . esc_url( $community_url ) . '">' . esc_html__( 'Upgrade API tier', 'reportedip-hive' ) . '</a>',
					'<a href="' . esc_url( $queue_url ) . '">' . esc_html__( 'Manage queue', 'reportedip-hive' ) . '</a>'
				);
				?>
			</div>
			<?php
		} elseif ( $pending_count >= $warning_threshold ) {
			$community_url = admin_url( 'admin.php?page=reportedip-hive-community' );
			?>
			<div class="rip-alert rip-alert--warning" style="margin-bottom: var(--rip-space-4);">
				<strong><?php esc_html_e( 'ReportedIP Hive:', 'reportedip-hive' ); ?></strong>
				<?php
				printf(
					/* translators: 1: pending count, 2: upgrade link */
					esc_html__( '%1$d reports pending processing. %2$s for higher limits.', 'reportedip-hive' ),
					intval( $pending_count ),
					'<a href="' . esc_url( $community_url ) . '">' . esc_html__( 'Upgrade API tier', 'reportedip-hive' ) . '</a>'
				);
				?>
			</div>
			<?php
		}
	}

	/**
	 * Add admin menu
	 */
	public function add_admin_menu() {
		add_menu_page(
			__( 'ReportedIP Hive', 'reportedip-hive' ),
			__( 'ReportedIP Hive', 'reportedip-hive' ),
			'manage_options',
			'reportedip-hive',
			array( $this, 'dashboard_page' ),
			'dashicons-shield-alt',
			30
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'Dashboard', 'reportedip-hive' ),
			__( 'Dashboard', 'reportedip-hive' ),
			'manage_options',
			'reportedip-hive',
			array( $this, 'dashboard_page' )
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'Security', 'reportedip-hive' ),
			__( 'Security', 'reportedip-hive' ),
			'manage_options',
			'reportedip-hive-security',
			array( $this, 'security_page' )
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'Settings', 'reportedip-hive' ),
			__( 'Settings', 'reportedip-hive' ),
			'manage_options',
			'reportedip-hive-settings',
			array( $this, 'settings_page' )
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'System Status', 'reportedip-hive' ),
			__( 'System Status', 'reportedip-hive' ),
			'manage_options',
			'reportedip-hive-debug',
			array( $this, 'debug_page' )
		);

		add_submenu_page(
			'reportedip-hive',
			__( 'Community & Quota', 'reportedip-hive' ),
			__( 'Community', 'reportedip-hive' ),
			'manage_options',
			'reportedip-hive-community',
			array( $this, 'community_page' )
		);
	}

	/**
	 * Register settings
	 */
	public function register_settings() {
		register_setting(
			'reportedip_hive_api',
			'reportedip_hive_api_key',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_api_key' ),
			)
		);
		register_setting(
			'reportedip_hive_api',
			'reportedip_hive_api_endpoint',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_api_endpoint' ),
			)
		);

		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_failed_login_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_failed_login_threshold' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_failed_login_timeframe',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_timeframe' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_comment_spam_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_spam_threshold' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_xmlrpc_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_xmlrpc_threshold' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_comment_spam_timeframe',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_timeframe' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_xmlrpc_timeframe',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_timeframe' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_monitor_failed_logins',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_monitor_comments',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_detection',
			'reportedip_hive_monitor_xmlrpc',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);

		foreach ( array(
			'reportedip_hive_password_spray_threshold',
			'reportedip_hive_app_password_threshold',
			'reportedip_hive_rest_threshold',
			'reportedip_hive_rest_sensitive_threshold',
			'reportedip_hive_user_enum_threshold',
			'reportedip_hive_scan_404_threshold',
		) as $threshold_option ) {
			register_setting(
				'reportedip_hive_protection_detection',
				$threshold_option,
				array(
					'type'              => 'integer',
					'sanitize_callback' => array( $this, 'sanitize_failed_login_threshold' ),
				)
			);
		}
		foreach ( array(
			'reportedip_hive_password_spray_timeframe',
			'reportedip_hive_app_password_timeframe',
			'reportedip_hive_rest_timeframe',
			'reportedip_hive_rest_sensitive_timeframe',
			'reportedip_hive_user_enum_timeframe',
			'reportedip_hive_scan_404_timeframe',
			'reportedip_hive_geo_window_days',
			'reportedip_hive_password_min_length',
			'reportedip_hive_password_min_classes',
		) as $integer_option ) {
			register_setting(
				'reportedip_hive_protection_detection',
				$integer_option,
				array(
					'type'              => 'integer',
					'sanitize_callback' => array( $this, 'sanitize_timeframe' ),
				)
			);
		}
		foreach ( array(
			'reportedip_hive_monitor_app_passwords',
			'reportedip_hive_app_password_require_2fa',
			'reportedip_hive_monitor_rest_api',
			'reportedip_hive_block_user_enumeration',
			'reportedip_hive_monitor_404_scans',
			'reportedip_hive_monitor_woocommerce',
			'reportedip_hive_monitor_geo_anomaly',
			'reportedip_hive_geo_revoke_trusted_devices',
			'reportedip_hive_geo_report_to_api',
			'reportedip_hive_password_policy_enabled',
			'reportedip_hive_password_check_hibp',
			'reportedip_hive_password_policy_all_users',
		) as $boolean_option ) {
			register_setting(
				'reportedip_hive_protection_detection',
				$boolean_option,
				array(
					'type'              => 'boolean',
					'sanitize_callback' => array( $this, 'sanitize_boolean' ),
				)
			);
		}

		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_auto_block',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_block_duration',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_block_duration' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_block_threshold',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_block_threshold' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_notifications',
			'reportedip_hive_notify_admin',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_report_only_mode',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);

		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_hide_login_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_hide_login_enabled' ),
			)
		);
		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_hide_login_slug',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_hide_login_slug' ),
			)
		);
		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_hide_login_response_mode',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_hide_login_response_mode' ),
			)
		);
		register_setting(
			'reportedip_hive_hide_login',
			'reportedip_hive_hide_login_token_in_urls',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);

		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_log_level',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_log_level' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_delete_data_on_uninstall',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_detailed_logging',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_log_user_agents',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_minimal_logging',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_log_referer_domains',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_data_retention_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_retention_days' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_privacy',
			'reportedip_hive_auto_anonymize_days',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_anonymize_days' ),
			)
		);

		register_setting(
			'reportedip_hive_advanced_performance',
			'reportedip_hive_enable_caching',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_boolean' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_performance',
			'reportedip_hive_cache_duration',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_cache_duration' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_performance',
			'reportedip_hive_negative_cache_duration',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_negative_cache_duration' ),
			)
		);
		register_setting(
			'reportedip_hive_advanced_performance',
			'reportedip_hive_max_api_calls_per_hour',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_max_api_calls' ),
			)
		);
		register_setting(
			'reportedip_hive_api',
			'reportedip_hive_trusted_ip_header',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_trusted_ip_header' ),
			)
		);

		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_blocked_page_contact_url',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_url_nullsafe' ),
			)
		);

		register_setting(
			'reportedip_hive_protection_blocking',
			'reportedip_hive_report_cooldown_hours',
			array(
				'type'              => 'integer',
				'sanitize_callback' => 'absint',
			)
		);

		register_setting(
			'reportedip_hive_promote',
			'reportedip_hive_auto_footer_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => 'rest_sanitize_boolean',
				'default'           => false,
			)
		);

		register_setting(
			'reportedip_hive_promote',
			'reportedip_hive_auto_footer_variant',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_auto_footer_variant' ),
				'default'           => 'badge',
			)
		);

		register_setting(
			'reportedip_hive_promote',
			'reportedip_hive_auto_footer_align',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_auto_footer_align' ),
				'default'           => 'center',
			)
		);
	}

	/**
	 * Sanitiser: auto-footer variant must be one of the supported values.
	 *
	 * Delegates to the canonical allowlist on `ReportedIP_Hive_Frontend_Shortcodes`
	 * so the wizard, the Promote tab, and Settings API all share one source of truth.
	 *
	 * @param mixed $value Raw value from $_POST.
	 * @return string Sanitised variant key (`badge` or `shield`).
	 * @since  1.3.0
	 */
	public function sanitize_auto_footer_variant( $value ) {
		return ReportedIP_Hive_Frontend_Shortcodes::sanitize_footer_variant( $value );
	}

	/**
	 * Sanitiser: auto-footer alignment must be left, center, or right.
	 *
	 * @param mixed $value Raw value from $_POST.
	 * @return string Sanitised alignment key.
	 * @since  1.3.1
	 */
	public function sanitize_auto_footer_align( $value ) {
		$value = sanitize_key( (string) $value );
		return in_array( $value, array( 'left', 'center', 'right', 'below' ), true ) ? $value : 'center';
	}

	/**
	 * Null-safe URL sanitiser for settings that point to an external URL.
	 *
	 * Coerces null to an empty string before handing off to esc_url_raw(),
	 * which in turn calls esc_url() — that function's first op is ltrim(),
	 * and PHP 8.1+ deprecates passing null there. The deprecation output
	 * breaks the Settings API redirect because headers have already been
	 * emitted by the time wp_redirect fires.
	 *
	 * @param mixed $value Raw option value from $_POST (may be null).
	 * @return string Sanitised URL or empty string.
	 */
	public function sanitize_url_nullsafe( $value ) {
		return esc_url_raw( (string) ( $value ?? '' ) );
	}

	/**
	 * Sanitize API key - validates format
	 */
	public function sanitize_api_key( $value ) {
		$value = sanitize_text_field( $value ?? '' );

		if ( empty( $value ) ) {
			return '';
		}

		if ( strlen( $value ) < 32 || strlen( $value ) > 64 ) {
			add_settings_error(
				'reportedip_hive_api_key',
				'invalid_api_key_length',
				__( 'API key must be between 32 and 64 characters.', 'reportedip-hive' ),
				'error'
			);
			return get_option( 'reportedip_hive_api_key', '' );
		}

		if ( ! preg_match( '/^[a-zA-Z0-9]+$/', $value ) ) {
			add_settings_error(
				'reportedip_hive_api_key',
				'invalid_api_key_format',
				__( 'API key must contain only alphanumeric characters.', 'reportedip-hive' ),
				'error'
			);
			return get_option( 'reportedip_hive_api_key', '' );
		}

		return $value;
	}

	/**
	 * Sanitize API endpoint - validates URL and enforces HTTPS
	 */
	public function sanitize_api_endpoint( $value ) {
		$value = esc_url_raw( $value ?? '' );

		if ( empty( $value ) ) {
			return 'https://reportedip.de/wp-json/reportedip/v2/';
		}

		if ( ! filter_var( $value, FILTER_VALIDATE_URL ) ) {
			add_settings_error(
				'reportedip_hive_api_endpoint',
				'invalid_api_endpoint',
				__( 'API endpoint must be a valid URL.', 'reportedip-hive' ),
				'error'
			);
			return get_option( 'reportedip_hive_api_endpoint', 'https://reportedip.de/wp-json/reportedip/v2/' );
		}

		if ( ! is_string( $value ) || strpos( $value, 'https://' ) !== 0 ) {
			add_settings_error(
				'reportedip_hive_api_endpoint',
				'insecure_api_endpoint',
				__( 'API endpoint must use HTTPS for security.', 'reportedip-hive' ),
				'error'
			);
			return get_option( 'reportedip_hive_api_endpoint', 'https://reportedip.de/wp-json/reportedip/v2/' );
		}

		return trailingslashit( $value );
	}

	/**
	 * Sanitize boolean values
	 */
	public function sanitize_boolean( $value ) {
		return (bool) $value;
	}

	/**
	 * Sanitize failed login threshold (1-100)
	 */
	public function sanitize_failed_login_threshold( $value ) {
		$value  = absint( $value );
		$min    = 1;
		$max    = 100;
		$result = max( $min, min( $max, $value ) );

		if ( $value !== $result ) {
			add_settings_error(
				'reportedip_hive_failed_login_threshold',
				'value_adjusted',
				sprintf(
					/* translators: 1: adjusted threshold value, 2: minimum allowed value, 3: maximum allowed value */
					__( 'Failed login threshold was adjusted to %1$d (must be between %2$d and %3$d).', 'reportedip-hive' ),
					$result,
					$min,
					$max
				),
				'warning'
			);
		}
		return $result;
	}

	/**
	 * Sanitize timeframe (1-1440 minutes = 24 hours)
	 */
	public function sanitize_timeframe( $value ) {
		$value  = absint( $value );
		$min    = 1;
		$max    = 1440;
		$result = max( $min, min( $max, $value ) );

		if ( $value !== $result ) {
			add_settings_error(
				'reportedip_hive_timeframe',
				'value_adjusted',
				sprintf(
					/* translators: 1: adjusted value in minutes, 2: minimum allowed value, 3: maximum allowed value */
					__( 'Time window was adjusted to %1$d minutes (must be between %2$d and %3$d).', 'reportedip-hive' ),
					$result,
					$min,
					$max
				),
				'warning'
			);
		}
		return $result;
	}

	/**
	 * Sanitize spam threshold (1-50)
	 */
	public function sanitize_spam_threshold( $value ) {
		$value  = absint( $value );
		$min    = 1;
		$max    = 50;
		$result = max( $min, min( $max, $value ) );

		if ( $value !== $result ) {
			add_settings_error(
				'reportedip_hive_spam_threshold',
				'value_adjusted',
				sprintf(
					/* translators: 1: adjusted threshold value, 2: minimum allowed value, 3: maximum allowed value */
					__( 'Comment spam threshold was adjusted to %1$d (must be between %2$d and %3$d).', 'reportedip-hive' ),
					$result,
					$min,
					$max
				),
				'warning'
			);
		}
		return $result;
	}

	/**
	 * Sanitize XMLRPC threshold (1-100)
	 */
	public function sanitize_xmlrpc_threshold( $value ) {
		$value  = absint( $value );
		$min    = 1;
		$max    = 100;
		$result = max( $min, min( $max, $value ) );

		if ( $value !== $result ) {
			add_settings_error(
				'reportedip_hive_xmlrpc_threshold',
				'value_adjusted',
				sprintf(
					/* translators: 1: adjusted threshold value, 2: minimum allowed value, 3: maximum allowed value */
					__( 'XMLRPC threshold was adjusted to %1$d (must be between %2$d and %3$d).', 'reportedip-hive' ),
					$result,
					$min,
					$max
				),
				'warning'
			);
		}
		return $result;
	}

	/**
	 * Sanitize block duration (0-8760 hours = 1 year, 0 = permanent)
	 */
	public function sanitize_block_duration( $value ) {
		$value = absint( $value );
		return min( 8760, $value );
	}

	/**
	 * Sanitize block threshold (0-100 percent)
	 */
	public function sanitize_block_threshold( $value ) {
		$value  = absint( $value );
		$min    = 0;
		$max    = 100;
		$result = max( $min, min( $max, $value ) );

		if ( $value !== $result ) {
			add_settings_error(
				'reportedip_hive_block_threshold',
				'value_adjusted',
				sprintf(
					/* translators: 1: adjusted threshold percentage, 2: minimum allowed value, 3: maximum allowed value */
					__( 'Block threshold was adjusted to %1$d%% (must be between %2$d and %3$d).', 'reportedip-hive' ),
					$result,
					$min,
					$max
				),
				'warning'
			);
		}
		return $result;
	}

	/**
	 * Sanitize log level
	 */
	public function sanitize_log_level( $value ) {
		$valid_levels = array( 'debug', 'info', 'warning', 'error', 'critical' );
		$value        = sanitize_text_field( $value ?? '' );
		return in_array( $value, $valid_levels ) ? $value : 'info';
	}

	/**
	 * Sanitize Hide-Login enable toggle.
	 *
	 * Refuses to enable when no slug has been configured yet — protects users
	 * from locking themselves out by toggling the feature on without setting
	 * a slug first.
	 *
	 * @param mixed $value Raw posted value.
	 * @return bool Effective enabled state.
	 * @since  1.2.0
	 */
	public function sanitize_hide_login_enabled( $value ) {
		$wants_enabled = $this->sanitize_boolean( $value );
		if ( ! $wants_enabled ) {
			return false;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified by Settings API options.php handler before sanitize callbacks fire.
		$slug_option = isset( $_POST['reportedip_hive_hide_login_slug'] )
			? sanitize_text_field( wp_unslash( (string) $_POST['reportedip_hive_hide_login_slug'] ) )
			: (string) get_option( 'reportedip_hive_hide_login_slug', '' );

		if ( '' === trim( $slug_option ) ) {
			add_settings_error(
				'reportedip_hive_hide_login_enabled',
				'reportedip_hive_hide_login_no_slug',
				__( 'Set a custom login slug before enabling Hide Login — otherwise the feature has nowhere to send admins.', 'reportedip-hive' )
			);
			return false;
		}

		flush_rewrite_rules( false );
		return true;
	}

	/**
	 * Sanitize the hidden-login slug. Delegates to the Hide_Login class which
	 * owns the validation rules (reserved slugs, permalink collisions, format).
	 *
	 * @param mixed $value Raw posted value.
	 * @return string Validated slug or the previously-stored value.
	 * @since  1.2.0
	 */
	public function sanitize_hide_login_slug( $value ) {
		if ( ! class_exists( 'ReportedIP_Hive_Hide_Login' ) ) {
			return is_string( $value ) ? sanitize_title( $value ) : '';
		}
		return ReportedIP_Hive_Hide_Login::get_instance()->sanitize_slug( $value );
	}

	/**
	 * Sanitize the hidden-login response mode (block_page | 404).
	 *
	 * @param mixed $value Raw posted value.
	 * @return string A valid response mode.
	 * @since  1.2.0
	 */
	public function sanitize_hide_login_response_mode( $value ) {
		if ( ! class_exists( 'ReportedIP_Hive_Hide_Login' ) ) {
			return 'block_page';
		}
		return ReportedIP_Hive_Hide_Login::get_instance()->sanitize_response_mode( $value );
	}

	/**
	 * Sanitize data retention days (1-365)
	 */
	public function sanitize_retention_days( $value ) {
		$value = absint( $value );
		return max( 1, min( 365, $value ) );
	}

	/**
	 * Sanitize auto anonymize days (1-365, must be <= retention days)
	 */
	public function sanitize_anonymize_days( $value ) {
		$value          = absint( $value );
		$retention_days = get_option( 'reportedip_hive_data_retention_days', 30 );
		return max( 1, min( $retention_days, min( 365, $value ) ) );
	}

	/**
	 * Sanitize cache duration (1-168 hours = 1 week)
	 */
	public function sanitize_cache_duration( $value ) {
		$value = absint( $value );
		return max( 1, min( 168, $value ) );
	}

	/**
	 * Sanitize negative cache duration (1-24 hours)
	 */
	public function sanitize_negative_cache_duration( $value ) {
		$value = absint( $value );
		return max( 1, min( 24, $value ) );
	}

	/**
	 * Sanitize max API calls per hour (1-10000)
	 */
	public function sanitize_max_api_calls( $value ) {
		$value = absint( $value );
		return max( 1, min( 10000, $value ) );
	}

	/**
	 * Sanitize trusted IP header - only allow known safe values
	 */
	public function sanitize_trusted_ip_header( $value ) {
		$allowed = array( '', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_CLIENT_IP' );
		$value   = sanitize_text_field( $value ?? '' );
		return in_array( $value, $allowed, true ) ? $value : '';
	}

	/**
	 * Dashboard page
	 */
	public function dashboard_page() {
		$stats         = $this->get_dashboard_stats();
		$recent_events = $this->database->get_recent_events( 24, 10 );
		$api_status    = $this->api_client->is_configured() ? $this->api_client->test_connection() : array( 'success' => false );

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();

		$this->render_page_header( __( 'ReportedIP Hive', 'reportedip-hive' ), __( 'Security Dashboard', 'reportedip-hive' ) );
		?>

			<div class="rip-dashboard">
				<?php
				$queue_stats = $this->database->get_queue_statistics();
				?>

				<!-- Stat Cards (New Design) -->
				<div class="rip-stat-cards">
					<!-- Events Card -->
					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--danger">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo esc_html( $stats['events_24h'] ); ?></div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'Events (24h)', 'reportedip-hive' ); ?></div>
						</div>
					</div>

					<!-- Blocked IPs Card -->
					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--warning">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo esc_html( $stats['blocked_ips'] ); ?></div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'Blocked IPs', 'reportedip-hive' ); ?></div>
						</div>
					</div>

					<!-- Whitelisted IPs Card -->
					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--success">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo esc_html( $stats['whitelisted_ips'] ); ?></div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'Whitelisted IPs', 'reportedip-hive' ); ?></div>
						</div>
					</div>

					<!-- API/Queue Card (Community Mode) or Cache Card (Local Mode) -->
					<?php if ( $mode_manager->is_community_mode() ) : ?>
					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--<?php echo $api_status['success'] ? 'primary' : 'danger'; ?>">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php echo (int) $queue_stats['pending']; ?></div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'API Queue', 'reportedip-hive' ); ?></div>
						</div>
					</div>
					<?php else : ?>
					<div class="rip-stat-card">
						<div class="rip-stat-card__icon rip-stat-card__icon--info">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
						</div>
						<div class="rip-stat-card__content">
							<div class="rip-stat-card__value"><?php esc_html_e( 'Local', 'reportedip-hive' ); ?></div>
							<div class="rip-stat-card__label"><?php esc_html_e( 'Protection Active', 'reportedip-hive' ); ?></div>
						</div>
					</div>
					<?php endif; ?>
				</div>

				<!-- Charts Section -->
				<div class="rip-charts-grid">
					<!-- Security Events Chart -->
					<div class="rip-chart-card">
						<div class="rip-chart-card__header">
							<h3 class="rip-chart-card__title"><?php esc_html_e( 'Security Events', 'reportedip-hive' ); ?></h3>
							<div class="rip-time-selector">
								<button type="button" class="rip-time-selector__btn rip-time-selector__btn--active" data-period="7"><?php esc_html_e( '7 Days', 'reportedip-hive' ); ?></button>
								<button type="button" class="rip-time-selector__btn" data-period="30"><?php esc_html_e( '30 Days', 'reportedip-hive' ); ?></button>
							</div>
						</div>
						<div class="rip-chart-card__body">
							<canvas id="rip-security-events-chart" class="rip-chart-card__canvas"></canvas>
						</div>
					</div>

					<!-- Threat Distribution Chart -->
					<div class="rip-chart-card">
						<div class="rip-chart-card__header">
							<h3 class="rip-chart-card__title"><?php esc_html_e( 'Threat Distribution', 'reportedip-hive' ); ?></h3>
						</div>
						<div class="rip-chart-card__body">
							<canvas id="rip-threat-distribution-chart" class="rip-chart-card__canvas"></canvas>
						</div>
					</div>
				</div>

				<!-- Recent Activity Section -->
				<div class="rip-dashboard__section">
					<div class="rip-dashboard__section-title">
						<h2>
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
							<?php esc_html_e( 'Recent Activity', 'reportedip-hive' ); ?>
						</h2>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive-security&tab=logs' ) ); ?>" class="rip-button rip-button--ghost rip-button--sm">
							<?php esc_html_e( 'View All', 'reportedip-hive' ); ?>
						</a>
					</div>

					<div class="rip-card">
						<?php if ( empty( $recent_events ) ) : ?>
							<div class="rip-empty-state rip-empty-state--compact">
								<svg class="rip-empty-state__icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
									<path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
								</svg>
								<p class="rip-empty-state__text"><?php esc_html_e( 'No critical events in the last 24 hours. Your site is secure!', 'reportedip-hive' ); ?></p>
							</div>
						<?php else : ?>
							<ul class="rip-activity-list">
								<?php
								foreach ( $recent_events as $event ) :
									$icon_class = 'info';
									switch ( $event->severity ) {
										case 'critical':
											$icon_class = 'danger';
											break;
										case 'high':
											$icon_class = 'danger';
											break;
										case 'medium':
											$icon_class = 'warning';
											break;
										case 'low':
											$icon_class = 'success';
											break;
									}

									$time_ago = human_time_diff( strtotime( $event->created_at ), time() );
									?>
								<li class="rip-activity-item">
									<div class="rip-activity-item__icon rip-activity-item__icon--<?php echo esc_attr( $icon_class ); ?>">
										<?php if ( $icon_class === 'danger' ) : ?>
											<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
										<?php elseif ( $icon_class === 'warning' ) : ?>
											<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
										<?php else : ?>
											<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>
										<?php endif; ?>
									</div>
									<div class="rip-activity-item__content">
										<div class="rip-activity-item__title">
											<?php echo esc_html( ucwords( str_replace( '_', ' ', $event->event_type ) ) ); ?>
											<span class="rip-activity-item__ip"><?php echo esc_html( $event->ip_address ); ?></span>
										</div>
										<div class="rip-activity-item__desc">
											<?php echo wp_kses_post( $this->logger->format_details( $event->details ) ); ?>
										</div>
									</div>
									<span class="rip-activity-item__time"><?php echo esc_html( $time_ago ); ?> <?php esc_html_e( 'ago', 'reportedip-hive' ); ?></span>
								</li>
								<?php endforeach; ?>
							</ul>
						<?php endif; ?>
					</div>
				</div>

				<!-- Quick Actions Section -->
				<div class="rip-dashboard__section">
					<div class="rip-dashboard__section-title">
						<h2>
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
							<?php esc_html_e( 'Quick Actions', 'reportedip-hive' ); ?>
						</h2>
					</div>

					<div class="rip-quick-actions">
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive-settings' ) ); ?>" class="rip-quick-action">
							<div class="rip-quick-action__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
							</div>
							<span class="rip-quick-action__label"><?php esc_html_e( 'Settings', 'reportedip-hive' ); ?></span>
						</a>

						<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive-security&tab=blocked' ) ); ?>" class="rip-quick-action">
							<div class="rip-quick-action__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
							</div>
							<span class="rip-quick-action__label"><?php esc_html_e( 'Blocked IPs', 'reportedip-hive' ); ?></span>
						</a>

						<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive-security&tab=whitelist' ) ); ?>" class="rip-quick-action">
							<div class="rip-quick-action__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
							</div>
							<span class="rip-quick-action__label"><?php esc_html_e( 'Whitelist', 'reportedip-hive' ); ?></span>
						</a>

						<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive-security&tab=logs' ) ); ?>" class="rip-quick-action">
							<div class="rip-quick-action__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
							</div>
							<span class="rip-quick-action__label"><?php esc_html_e( 'View Logs', 'reportedip-hive' ); ?></span>
						</a>

						<?php if ( $mode_manager->is_community_mode() ) : ?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive-security&tab=lookup' ) ); ?>" class="rip-quick-action">
							<div class="rip-quick-action__icon">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
							</div>
							<span class="rip-quick-action__label"><?php esc_html_e( 'IP Lookup', 'reportedip-hive' ); ?></span>
						</a>
						<?php endif; ?>
					</div>
				</div>

			</div><!-- /.rip-dashboard -->

		<?php $this->render_page_footer(); ?>
		<?php
	}

	/**
	 * Security page - Combined IP Management and Security Logs
	 * Consolidated navigation: IP Lists | Activity | Advanced (Community only)
	 */
	public function security_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Tab navigation only, no data modification
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'ip_lists';
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Tab navigation only, no data modification
		$sub_tab = isset( $_GET['sub'] ) ? sanitize_text_field( wp_unslash( $_GET['sub'] ) ) : '';

		if ( $active_tab === 'blocked' || $active_tab === 'whitelist' ) {
			$sub_tab    = $active_tab;
			$active_tab = 'ip_lists';
		}
		if ( $active_tab === 'logs' || $active_tab === 'lookup' ) {
			$sub_tab    = $active_tab;
			$active_tab = 'activity';
		}
		if ( $active_tab === 'api_queue' ) {
			$active_tab = 'advanced';
		}

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();

		$database    = ReportedIP_Hive_Database::get_instance();
		$queue_stats = $database->get_queue_statistics();

		$this->render_page_header( __( 'Security', 'reportedip-hive' ), __( 'Manage blocked IPs, whitelist, and security logs', 'reportedip-hive' ) );
		?>

			<!-- Main Navigation Tabs -->
			<nav class="rip-nav-tabs">
				<a href="?page=reportedip-hive-security&tab=ip_lists" class="rip-nav-tabs__tab <?php echo $active_tab === 'ip_lists' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					<?php esc_html_e( 'IP Lists', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-security&tab=activity" class="rip-nav-tabs__tab <?php echo $active_tab === 'activity' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
					<?php esc_html_e( 'Activity', 'reportedip-hive' ); ?>
				</a>
				<?php if ( $mode_manager->is_community_mode() || $queue_stats['failed'] > 0 || $queue_stats['pending'] > 0 ) : ?>
				<a href="?page=reportedip-hive-security&tab=advanced" class="rip-nav-tabs__tab <?php echo $active_tab === 'advanced' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
					<?php esc_html_e( 'Advanced', 'reportedip-hive' ); ?>
					<?php if ( $queue_stats['failed'] > 0 ) : ?>
						<span class="rip-nav-tabs__badge rip-nav-tabs__badge--danger"><?php echo (int) $queue_stats['failed']; ?></span>
					<?php endif; ?>
				</a>
				<?php endif; ?>
			</nav>

			<div class="rip-content">
				<?php
				switch ( $active_tab ) {
					case 'ip_lists':
						$this->render_ip_lists_tab( $sub_tab );
						break;
					case 'activity':
						$this->render_activity_tab( $sub_tab );
						break;
					case 'advanced':
						if ( $mode_manager->is_community_mode() || $queue_stats['failed'] > 0 || $queue_stats['pending'] > 0 ) {
							$this->render_advanced_tab();
						} else {
							$this->render_ip_lists_tab( $sub_tab );
						}
						break;
					default:
						$this->render_ip_lists_tab( $sub_tab );
				}
				?>
			</div>

		<?php $this->render_page_footer(); ?>
		<?php
	}

	/**
	 * Render consolidated IP Lists tab (Blocked + Whitelist)
	 */
	private function render_ip_lists_tab( $sub_tab = '' ) {
		if ( empty( $sub_tab ) ) {
			$sub_tab = 'blocked';
		}
		?>
		<div class="rip-sub-tabs">
			<a href="?page=reportedip-hive-security&tab=ip_lists&sub=blocked" class="rip-sub-tabs__tab <?php echo $sub_tab === 'blocked' ? 'rip-sub-tabs__tab--active' : ''; ?>">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
				<?php esc_html_e( 'Blocked', 'reportedip-hive' ); ?>
				<span class="rip-sub-tabs__count"><?php echo (int) $this->database->count_blocked_ips(); ?></span>
			</a>
			<a href="?page=reportedip-hive-security&tab=ip_lists&sub=whitelist" class="rip-sub-tabs__tab <?php echo $sub_tab === 'whitelist' ? 'rip-sub-tabs__tab--active' : ''; ?>">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
				<?php esc_html_e( 'Whitelist', 'reportedip-hive' ); ?>
				<span class="rip-sub-tabs__count"><?php echo (int) $this->database->count_whitelisted_ips(); ?></span>
			</a>
		</div>

		<?php
		if ( $sub_tab === 'whitelist' ) {
			$this->render_whitelist_tab();
		} else {
			$this->render_blocked_tab();
		}
	}

	/**
	 * Render consolidated Activity tab (Logs + Lookup)
	 */
	private function render_activity_tab( $sub_tab = '' ) {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();

		if ( empty( $sub_tab ) ) {
			$sub_tab = 'logs';
		}
		?>
		<div class="rip-sub-tabs">
			<a href="?page=reportedip-hive-security&tab=activity&sub=logs" class="rip-sub-tabs__tab <?php echo $sub_tab === 'logs' ? 'rip-sub-tabs__tab--active' : ''; ?>">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
				<?php esc_html_e( 'Event Log', 'reportedip-hive' ); ?>
			</a>
			<?php if ( $mode_manager->is_community_mode() ) : ?>
			<a href="?page=reportedip-hive-security&tab=activity&sub=lookup" class="rip-sub-tabs__tab <?php echo $sub_tab === 'lookup' ? 'rip-sub-tabs__tab--active' : ''; ?>">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
				<?php esc_html_e( 'IP Lookup', 'reportedip-hive' ); ?>
			</a>
			<?php endif; ?>
		</div>

		<?php
		if ( $sub_tab === 'lookup' && $mode_manager->is_community_mode() ) {
			$this->render_lookup_tab();
		} else {
			$this->render_logs_tab();
		}
	}

	/**
	 * Render Advanced tab (API Queue - Community mode only)
	 */
	private function render_advanced_tab() {
		$this->render_api_queue_tab();
	}

	/**
	 * Render logs tab using WP_List_Table
	 */
	private function render_logs_tab() {
		$logs_table = new ReportedIP_Hive_Logs_Table();
		$logs_table->process_bulk_action();
		$logs_table->prepare_items();

		?>
		<form method="post">
			<input type="hidden" name="page" value="reportedip-hive-security" />
			<input type="hidden" name="tab" value="logs" />
			<?php
			$logs_table->search_box( __( 'Search', 'reportedip-hive' ), 'log-search' );
			$logs_table->display();
			?>
		</form>

		<div class="tablenav bottom">
			<a href="<?php echo esc_url( admin_url( 'admin-ajax.php?action=reportedip_hive_export_logs&format=csv&nonce=' . wp_create_nonce( 'reportedip_hive_nonce' ) ) ); ?>" class="button">
				<?php esc_html_e( 'Export CSV', 'reportedip-hive' ); ?>
			</a>
			<a href="<?php echo esc_url( admin_url( 'admin-ajax.php?action=reportedip_hive_export_logs&format=json&nonce=' . wp_create_nonce( 'reportedip_hive_nonce' ) ) ); ?>" class="button">
				<?php esc_html_e( 'Export JSON', 'reportedip-hive' ); ?>
			</a>
		</div>
		<?php
	}

	/**
	 * Render API Queue tab using WP_List_Table
	 */
	private function render_api_queue_tab() {
		$queue_table = new ReportedIP_Hive_API_Queue_Table();
		$queue_table->process_bulk_action();
		$queue_table->prepare_items();

		?>

		<div class="rip-alert rip-alert--info rip-mb-4">
			<p><?php esc_html_e( 'This page shows all pending API reports that will be sent to the ReportedIP service. Reports are processed automatically via cron (hourly). Failed reports will be retried up to 3 times.', 'reportedip-hive' ); ?></p>
		</div>

		<?php $queue_table->display_statistics(); ?>

		<form method="get">
			<input type="hidden" name="page" value="reportedip-hive-security" />
			<input type="hidden" name="tab" value="api_queue" />
			<?php
			$queue_table->search_box( __( 'Search IP', 'reportedip-hive' ), 'queue-search' );
			$queue_table->display();
			?>
		</form>

		<script type="text/javascript">
		jQuery(document).ready(function($) {
			$(document).on('click', '.retry-report', function(e) {
				e.preventDefault();
				var $button = $(this);
				var reportId = $button.data('id');

				$button.prop('disabled', true).text('<?php esc_html_e( 'Retrying...', 'reportedip-hive' ); ?>');

				$.post(ajaxurl, {
					action: 'reportedip_hive_retry_report',
					nonce: reportedip_hive_ajax.nonce,
					report_id: reportId
				}, function(response) {
					if (response.success) {
						location.reload();
					} else {
						alert(response.data || '<?php esc_html_e( 'Error retrying report', 'reportedip-hive' ); ?>');
						$button.prop('disabled', false).text('<?php esc_html_e( 'Retry', 'reportedip-hive' ); ?>');
					}
				});
			});

			$(document).on('click', '.delete-report', function(e) {
				e.preventDefault();
				var $button = $(this);
				var reportId = $button.data('id');

				if (!confirm('<?php esc_html_e( 'Are you sure you want to delete this queue item?', 'reportedip-hive' ); ?>')) {
					return;
				}

				$button.prop('disabled', true).text('<?php esc_html_e( 'Deleting...', 'reportedip-hive' ); ?>');

				$.post(ajaxurl, {
					action: 'reportedip_hive_delete_report',
					nonce: reportedip_hive_ajax.nonce,
					report_id: reportId
				}, function(response) {
					if (response.success) {
						location.reload();
					} else {
						alert(response.data || '<?php esc_html_e( 'Error deleting report', 'reportedip-hive' ); ?>');
						$button.prop('disabled', false).text('<?php esc_html_e( 'Delete', 'reportedip-hive' ); ?>');
					}
				});
			});

			$('#retry-all-failed').on('click', function(e) {
				e.preventDefault();
				var $button = $(this);

				if (!confirm('<?php esc_html_e( 'Are you sure you want to retry all failed reports?', 'reportedip-hive' ); ?>')) {
					return;
				}

				$button.prop('disabled', true).text('<?php esc_html_e( 'Retrying...', 'reportedip-hive' ); ?>');

				$.post(ajaxurl, {
					action: 'reportedip_hive_retry_all_failed',
					nonce: reportedip_hive_ajax.nonce
				}, function(response) {
					if (response.success) {
						location.reload();
					} else {
						alert(response.data || '<?php esc_html_e( 'Error retrying reports', 'reportedip-hive' ); ?>');
						$button.prop('disabled', false).text('<?php esc_html_e( 'Retry All Failed', 'reportedip-hive' ); ?>');
					}
				});
			});
		});
		</script>

		<?php
	}

	/**
	 * Render blocked IPs tab using WP_List_Table
	 */
	private function render_blocked_tab() {
		$blocked_table = new ReportedIP_Hive_Blocked_IPs_Table();
		$blocked_table->process_bulk_action();
		$blocked_table->prepare_items();

		?>
		<div class="rip-card rip-mb-4">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
					<?php esc_html_e( 'Block an IP Address', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<form id="block-ip-form" method="post" class="rip-form-inline">
					<div class="rip-form-group">
						<input type="text" id="block-ip-address" name="ip_address" class="rip-input" placeholder="<?php esc_html_e( 'IP Address', 'reportedip-hive' ); ?>" required />
					</div>
					<div class="rip-form-group">
						<input type="text" id="block-ip-reason" name="reason" class="rip-input" placeholder="<?php esc_html_e( 'Reason', 'reportedip-hive' ); ?>" required />
					</div>
					<div class="rip-form-group">
						<select id="block-ip-duration" name="duration" class="rip-select">
							<option value="24"><?php esc_html_e( '24 Hours', 'reportedip-hive' ); ?></option>
							<option value="72"><?php esc_html_e( '3 Days', 'reportedip-hive' ); ?></option>
							<option value="168"><?php esc_html_e( '1 Week', 'reportedip-hive' ); ?></option>
							<option value="720"><?php esc_html_e( '30 Days', 'reportedip-hive' ); ?></option>
							<option value="0"><?php esc_html_e( 'Permanent', 'reportedip-hive' ); ?></option>
						</select>
					</div>
					<button type="submit" class="rip-button rip-button--danger"><?php esc_html_e( 'Block IP', 'reportedip-hive' ); ?></button>
				</form>
			</div>
		</div>

		<div class="rip-card rip-mb-4">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
					<?php esc_html_e( 'Import Blocked IPs from CSV', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<form id="import-blocked-csv-form" method="post" enctype="multipart/form-data" class="rip-form-inline">
					<div class="rip-form-group">
						<input type="file" id="blocked-csv-file" name="csv_file" class="rip-input" accept=".csv,.txt" required />
					</div>
					<div class="rip-form-group">
						<select id="blocked-import-duration" name="duration" class="rip-select">
							<option value="24"><?php esc_html_e( '24 Hours', 'reportedip-hive' ); ?></option>
							<option value="72"><?php esc_html_e( '3 Days', 'reportedip-hive' ); ?></option>
							<option value="168"><?php esc_html_e( '1 Week', 'reportedip-hive' ); ?></option>
							<option value="720" selected><?php esc_html_e( '30 Days', 'reportedip-hive' ); ?></option>
							<option value="0"><?php esc_html_e( 'Permanent', 'reportedip-hive' ); ?></option>
						</select>
					</div>
					<button type="submit" class="rip-button rip-button--secondary"><?php esc_html_e( 'Import CSV', 'reportedip-hive' ); ?></button>
				</form>
				<p class="rip-help-text rip-mt-2"><?php esc_html_e( 'CSV format: One IP address per line, or columns: ip_address, reason (optional)', 'reportedip-hive' ); ?></p>
			</div>
		</div>

		<form method="post">
			<input type="hidden" name="page" value="reportedip-hive-security" />
			<input type="hidden" name="tab" value="blocked" />
			<?php
			$blocked_table->search_box( __( 'Search', 'reportedip-hive' ), 'blocked-search' );
			$blocked_table->display();
			?>
		</form>
		<?php
	}

	/**
	 * Render whitelist tab using WP_List_Table
	 */
	private function render_whitelist_tab() {
		$whitelist_table = new ReportedIP_Hive_Whitelist_Table();
		$whitelist_table->process_bulk_action();
		$whitelist_table->prepare_items();

		?>
		<div class="rip-card rip-mb-4">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
					<?php esc_html_e( 'Add to Whitelist', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<form id="add-whitelist-form" method="post" class="rip-form-inline">
					<div class="rip-form-group">
						<input type="text" id="whitelist-ip-address" name="ip_address" class="rip-input" placeholder="<?php esc_html_e( 'IP Address or CIDR', 'reportedip-hive' ); ?>" required />
					</div>
					<div class="rip-form-group">
						<input type="text" id="whitelist-reason" name="reason" class="rip-input" placeholder="<?php esc_html_e( 'Reason', 'reportedip-hive' ); ?>" />
					</div>
					<div class="rip-form-group">
						<input type="date" id="whitelist-expires" name="expires_at" class="rip-input" placeholder="<?php esc_html_e( 'Expires (optional)', 'reportedip-hive' ); ?>" />
					</div>
					<button type="submit" class="rip-button rip-button--success"><?php esc_html_e( 'Add to Whitelist', 'reportedip-hive' ); ?></button>
				</form>
			</div>
		</div>

		<div class="rip-card rip-mb-4">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
					<?php esc_html_e( 'Import Whitelist from CSV', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<form id="import-whitelist-csv-form" method="post" enctype="multipart/form-data" class="rip-form-inline">
					<div class="rip-form-group">
						<input type="file" id="whitelist-csv-file" name="csv_file" class="rip-input" accept=".csv,.txt" required />
					</div>
					<button type="submit" class="rip-button rip-button--secondary"><?php esc_html_e( 'Import CSV', 'reportedip-hive' ); ?></button>
				</form>
				<p class="rip-help-text rip-mt-2"><?php esc_html_e( 'CSV format: One IP address per line, or columns: ip_address, reason (optional)', 'reportedip-hive' ); ?></p>
			</div>
		</div>

		<form method="post">
			<input type="hidden" name="page" value="reportedip-hive-security" />
			<input type="hidden" name="tab" value="whitelist" />
			<?php
			$whitelist_table->search_box( __( 'Search', 'reportedip-hive' ), 'whitelist-search' );
			$whitelist_table->display();
			?>
		</form>
		<?php
	}

	/**
	 * Render IP lookup tab
	 */
	private function render_lookup_tab() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Pre-fill lookup field from URL, no data modification
		$lookup_ip = isset( $_GET['lookup_ip'] ) ? sanitize_text_field( wp_unslash( $_GET['lookup_ip'] ) ) : '';
		?>
		<div class="rip-card">
			<div class="rip-card__header">
				<h3 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
					<?php esc_html_e( 'IP Address Lookup', 'reportedip-hive' ); ?>
				</h3>
			</div>
			<div class="rip-card__body">
				<p class="rip-help-text rip-mb-4"><?php esc_html_e( 'Check the reputation of any IP address using the ReportedIP.de service.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-inline rip-mb-4">
					<div class="rip-form-group">
						<input type="text" id="lookup-ip-address" class="rip-input" placeholder="<?php esc_html_e( 'Enter IP address...', 'reportedip-hive' ); ?>" value="<?php echo esc_attr( $lookup_ip ); ?>" />
					</div>
					<button type="button" class="rip-button rip-button--primary" id="lookup-ip-button">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
						<?php esc_html_e( 'Lookup', 'reportedip-hive' ); ?>
					</button>
				</div>

				<div id="lookup-results" class="rip-lookup-results rip-hidden">
					<h4 class="rip-mb-2"><?php esc_html_e( 'Lookup Results', 'reportedip-hive' ); ?></h4>
					<div id="lookup-results-content"></div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Settings page entrypoint with seven-tab navigation.
	 *
	 * Old slugs (api, security, actions, protection, logging, caching, advanced)
	 * are aliased to their new home so external links keep working.
	 */
	public function settings_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Tab navigation only, no data modification
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'general';

		$tab_aliases = array(
			'api'        => 'general',
			'security'   => 'detection',
			'protection' => 'detection',
			'actions'    => 'blocking',
			'logging'    => 'privacy_logs',
			'advanced'   => 'performance',
			'caching'    => 'performance',
			'login'      => 'hide_login',
			'hide-login' => 'hide_login',
		);
		if ( isset( $tab_aliases[ $active_tab ] ) ) {
			$active_tab = $tab_aliases[ $active_tab ];
		}

		$this->render_page_header(
			__( 'Settings', 'reportedip-hive' ),
			__( 'Configure how ReportedIP Hive protects your site — grouped by topic so you can find what you need quickly.', 'reportedip-hive' )
		);
		?>

			<nav class="rip-nav-tabs">
				<a href="?page=reportedip-hive-settings&tab=general" class="rip-nav-tabs__tab <?php echo $active_tab === 'general' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
					<?php esc_html_e( 'General', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=detection" class="rip-nav-tabs__tab <?php echo $active_tab === 'detection' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
					<?php esc_html_e( 'Detection', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=blocking" class="rip-nav-tabs__tab <?php echo $active_tab === 'blocking' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
					<?php esc_html_e( 'Blocking', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=hide_login" class="rip-nav-tabs__tab <?php echo $active_tab === 'hide_login' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/><line x1="4" y1="20" x2="20" y2="4"/></svg>
					<?php esc_html_e( 'Hide Login', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=notifications" class="rip-nav-tabs__tab <?php echo $active_tab === 'notifications' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
					<?php esc_html_e( 'Notifications', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=privacy_logs" class="rip-nav-tabs__tab <?php echo $active_tab === 'privacy_logs' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="15" y2="17"/></svg>
					<?php esc_html_e( 'Privacy & Logs', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=performance" class="rip-nav-tabs__tab <?php echo $active_tab === 'performance' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
					<?php esc_html_e( 'Performance & Tools', 'reportedip-hive' ); ?>
				</a>
				<a href="?page=reportedip-hive-settings&tab=two_factor" class="rip-nav-tabs__tab <?php echo $active_tab === 'two_factor' ? 'rip-nav-tabs__tab--active' : ''; ?>">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<?php esc_html_e( 'Two-Factor Auth', 'reportedip-hive' ); ?>
				</a>
			</nav>

			<div class="rip-content">
				<?php
				switch ( $active_tab ) {
					case 'general':
						$this->render_general_settings_tab();
						break;
					case 'detection':
						$this->render_detection_tab();
						break;
					case 'blocking':
						$this->render_blocking_tab();
						break;
					case 'hide_login':
						$this->render_hide_login_tab();
						break;
					case 'notifications':
						$this->render_notifications_tab();
						break;
					case 'privacy_logs':
						$this->render_privacy_logs_tab();
						break;
					case 'performance':
						$this->render_performance_advanced_tab();
						break;
					case 'two_factor':
						ReportedIP_Hive_Two_Factor_Admin::render_global_settings();
						break;
					default:
						$this->render_general_settings_tab();
				}
				?>
			</div>

		<?php $this->render_page_footer(); ?>
		<?php
	}

	/**
	 * Render General settings tab (Mode + API Configuration)
	 */
	private function render_general_settings_tab() {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$current_mode = $mode_manager->get_mode();
		?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="8" stroke="currentColor" stroke-width="2" fill="none"/><path d="M2 10h16M10 2c2.8 2.8 4.4 6.5 4.4 8s-1.6 5.2-4.4 8" stroke="currentColor" stroke-width="1.5" fill="none"/></svg>
				<?php esc_html_e( 'Operation Mode', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc"><?php esc_html_e( 'Choose how ReportedIP Hive should operate. You can switch modes at any time.', 'reportedip-hive' ); ?></p>

			<div class="rip-mode-cards">
				<label class="rip-mode-card <?php echo $current_mode === 'local' ? 'rip-mode-card--selected' : ''; ?>">
					<input type="radio" name="reportedip_hive_operation_mode" value="local" <?php checked( $current_mode, 'local' ); ?> class="rip-mode-card__input" />
					<div class="rip-mode-card__icon">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
					</div>
					<div class="rip-mode-card__content">
						<h3 class="rip-mode-card__title"><?php esc_html_e( 'Local Protection', 'reportedip-hive' ); ?></h3>
						<p class="rip-mode-card__desc"><?php esc_html_e( 'Standalone protection without API connection. Perfect for privacy-focused sites.', 'reportedip-hive' ); ?></p>
						<ul class="rip-mode-card__features">
							<li><?php esc_html_e( 'Works offline', 'reportedip-hive' ); ?></li>
							<li><?php esc_html_e( 'No account required', 'reportedip-hive' ); ?></li>
							<li><?php esc_html_e( 'Local blocking only', 'reportedip-hive' ); ?></li>
						</ul>
					</div>
					<span class="rip-mode-card__check">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
					</span>
				</label>

				<label class="rip-mode-card <?php echo $current_mode === 'community' ? 'rip-mode-card--selected' : ''; ?>">
					<input type="radio" name="reportedip_hive_operation_mode" value="community" <?php checked( $current_mode, 'community' ); ?> class="rip-mode-card__input" />
					<div class="rip-mode-card__icon rip-mode-card__icon--community">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2c3 3.6 4.7 7.4 4.7 10s-1.7 6.4-4.7 10c-3-3.6-4.7-7.4-4.7-10s1.7-6.4 4.7-10z"/></svg>
					</div>
					<div class="rip-mode-card__content">
						<h3 class="rip-mode-card__title"><?php esc_html_e( 'Community Network', 'reportedip-hive' ); ?></h3>
						<p class="rip-mode-card__desc"><?php esc_html_e( 'Join thousands of sites sharing threat intelligence. Collective protection powered by community.', 'reportedip-hive' ); ?></p>
						<ul class="rip-mode-card__features">
							<li><?php esc_html_e( 'Real-time threat data', 'reportedip-hive' ); ?></li>
							<li><?php esc_html_e( 'Community blocklists', 'reportedip-hive' ); ?></li>
							<li><?php esc_html_e( 'GDPR compliant', 'reportedip-hive' ); ?></li>
						</ul>
					</div>
					<span class="rip-mode-card__check">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
					</span>
				</label>
			</div>
			<p class="rip-help-text"><?php esc_html_e( 'Mode changes take effect immediately.', 'reportedip-hive' ); ?></p>
		</div>

		<?php if ( $mode_manager->is_community_mode() ) : ?>
		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
				<?php esc_html_e( 'API Configuration', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc"><?php esc_html_e( 'Connect to the ReportedIP community network for enhanced protection.', 'reportedip-hive' ); ?></p>

			<form method="post" action="options.php" class="rip-form">
				<?php settings_fields( 'reportedip_hive_api' ); ?>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_api_key"><?php esc_html_e( 'API Key', 'reportedip-hive' ); ?></label>
					<input type="password" id="reportedip_hive_api_key" name="reportedip_hive_api_key" value="<?php echo esc_attr( get_option( 'reportedip_hive_api_key', '' ) ); ?>" class="rip-input" />
					<p class="rip-help-text">
						<?php esc_html_e( 'Your ReportedIP.de API key.', 'reportedip-hive' ); ?>
						<a href="https://reportedip.de/dashboard/api-keys" target="_blank"><?php esc_html_e( 'Get API Key', 'reportedip-hive' ); ?></a>
					</p>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_api_endpoint"><?php esc_html_e( 'API Endpoint', 'reportedip-hive' ); ?></label>
					<input type="url" id="reportedip_hive_api_endpoint" name="reportedip_hive_api_endpoint" value="<?php echo esc_attr( get_option( 'reportedip_hive_api_endpoint', 'https://reportedip.de/wp-json/reportedip/v2/' ) ); ?>" class="rip-input" />
					<p class="rip-help-text"><?php esc_html_e( 'The ReportedIP.de API endpoint URL.', 'reportedip-hive' ); ?></p>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_trusted_ip_header">
						<?php esc_html_e( 'Trusted IP Header', 'reportedip-hive' ); ?>
					</label>
					<select name="reportedip_hive_trusted_ip_header" id="reportedip_hive_trusted_ip_header" class="rip-input">
						<option value="" <?php selected( get_option( 'reportedip_hive_trusted_ip_header', '' ), '' ); ?>>
							<?php esc_html_e( 'None (REMOTE_ADDR only)', 'reportedip-hive' ); ?>
						</option>
						<option value="HTTP_CF_CONNECTING_IP" <?php selected( get_option( 'reportedip_hive_trusted_ip_header', '' ), 'HTTP_CF_CONNECTING_IP' ); ?>>
							<?php esc_html_e( 'Cloudflare (CF-Connecting-IP)', 'reportedip-hive' ); ?>
						</option>
						<option value="HTTP_X_REAL_IP" <?php selected( get_option( 'reportedip_hive_trusted_ip_header', '' ), 'HTTP_X_REAL_IP' ); ?>>
							<?php esc_html_e( 'Nginx (X-Real-IP)', 'reportedip-hive' ); ?>
						</option>
						<option value="HTTP_X_FORWARDED_FOR" <?php selected( get_option( 'reportedip_hive_trusted_ip_header', '' ), 'HTTP_X_FORWARDED_FOR' ); ?>>
							<?php esc_html_e( 'Generic Proxy (X-Forwarded-For)', 'reportedip-hive' ); ?>
						</option>
						<option value="HTTP_CLIENT_IP" <?php selected( get_option( 'reportedip_hive_trusted_ip_header', '' ), 'HTTP_CLIENT_IP' ); ?>>
							<?php esc_html_e( 'Client-IP Header', 'reportedip-hive' ); ?>
						</option>
					</select>
					<p class="rip-help-text">
						<?php esc_html_e( 'Select which HTTP header to trust for determining the client IP. Use "None" unless your site is behind a reverse proxy.', 'reportedip-hive' ); ?>
					</p>
				</div>

				<div class="rip-form-actions">
					<button type="button" class="rip-button rip-button--secondary" id="test-api-connection-general">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
						<?php esc_html_e( 'Test Connection', 'reportedip-hive' ); ?>
					</button>
					<?php submit_button( __( 'Save Changes', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
				</div>
				<div id="api-test-result" class="rip-api-result"></div>
			</form>
		</div>
		<?php endif; ?>
		<?php
	}

	/**
	 * Tab: Detection — what is monitored and at which thresholds.
	 *
	 * Plain-language framing: every section answers "what triggers an
	 * incident, and how many tries within how much time".
	 *
	 * @since 1.2.0
	 */
	private function render_detection_tab() {
		?>
		<form method="post" action="options.php" class="rip-form">
			<?php settings_fields( 'reportedip_hive_protection_detection' ); ?>

			<?php /* Checkbox-off fallbacks — see render_global_settings() in class-two-factor-admin.php for context. */ ?>
			<input type="hidden" name="reportedip_hive_monitor_failed_logins" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_comments" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_xmlrpc" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_app_passwords" value="0" />
			<input type="hidden" name="reportedip_hive_app_password_require_2fa" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_rest_api" value="0" />
			<input type="hidden" name="reportedip_hive_block_user_enumeration" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_404_scans" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_woocommerce" value="0" />
			<input type="hidden" name="reportedip_hive_monitor_geo_anomaly" value="0" />
			<input type="hidden" name="reportedip_hive_geo_revoke_trusted_devices" value="0" />
			<input type="hidden" name="reportedip_hive_geo_report_to_api" value="0" />
			<input type="hidden" name="reportedip_hive_password_policy_enabled" value="0" />
			<input type="hidden" name="reportedip_hive_password_check_hibp" value="0" />
			<input type="hidden" name="reportedip_hive_password_policy_all_users" value="0" />

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
					<?php esc_html_e( 'Failed login attempts', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Catches password-guessing attacks. We count wrong passwords per IP. Once an IP exceeds the limit within the window, it is treated as a threat. A second layer also fires if one IP probes many different usernames in a short window (password-spray / credential-stuffing).', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_failed_logins" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_monitor_failed_logins', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch failed logins', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_failed_login_threshold"><?php esc_html_e( 'How many wrong passwords?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_failed_login_threshold" name="reportedip_hive_failed_login_threshold" value="<?php echo esc_attr( get_option( 'reportedip_hive_failed_login_threshold', 5 ) ); ?>" min="1" max="100" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Trigger after this many failed attempts from one IP. 5 is a good starting point.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_failed_login_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_failed_login_timeframe" name="reportedip_hive_failed_login_timeframe" value="<?php echo esc_attr( get_option( 'reportedip_hive_failed_login_timeframe', 15 ) ); ?>" min="1" max="1440" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Counters reset after this window. Shorter = stricter, but more sensitive to legitimate users mistyping their password.', 'reportedip-hive' ); ?></p>
					</div>
				</div>

				<h3 class="rip-settings-subsection__title"><?php esc_html_e( 'Password-spray detection', 'reportedip-hive' ); ?></h3>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Triggers when one IP tries many different usernames quickly — a stronger signal than the per-IP attempt count above.', 'reportedip-hive' ); ?></p>
				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_password_spray_threshold"><?php esc_html_e( 'How many distinct usernames?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_password_spray_threshold" name="reportedip_hive_password_spray_threshold" value="<?php echo esc_attr( get_option( 'reportedip_hive_password_spray_threshold', 5 ) ); ?>" min="2" max="100" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_password_spray_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_password_spray_timeframe" name="reportedip_hive_password_spray_timeframe" value="<?php echo esc_attr( get_option( 'reportedip_hive_password_spray_timeframe', 10 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
					<?php esc_html_e( 'Comment spam', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'When the same IP submits comments that WordPress flags as spam in rapid succession, treat that IP as a threat.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_comments" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_monitor_comments', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch comment spam', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_comment_spam_threshold"><?php esc_html_e( 'How many spam comments?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_comment_spam_threshold" name="reportedip_hive_comment_spam_threshold" value="<?php echo esc_attr( get_option( 'reportedip_hive_comment_spam_threshold', 3 ) ); ?>" min="1" max="50" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Counts comments WordPress already marked as spam. 3 catches most bots.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_comment_spam_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_comment_spam_timeframe" name="reportedip_hive_comment_spam_timeframe" value="<?php echo esc_attr( get_option( 'reportedip_hive_comment_spam_timeframe', 60 ) ); ?>" min="1" max="1440" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Counter window. Real spammers post quickly — 60 minutes is generous.', 'reportedip-hive' ); ?></p>
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
					<?php esc_html_e( 'XML-RPC abuse', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'XML-RPC is an older WordPress remote-control interface that bots often hammer to brute-force passwords. Most modern sites do not actively use it.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_xmlrpc" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_monitor_xmlrpc', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch XML-RPC requests', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_xmlrpc_threshold"><?php esc_html_e( 'How many requests?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_xmlrpc_threshold" name="reportedip_hive_xmlrpc_threshold" value="<?php echo esc_attr( get_option( 'reportedip_hive_xmlrpc_threshold', 10 ) ); ?>" min="1" max="100" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Trigger after this many XML-RPC calls from one IP.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_xmlrpc_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_xmlrpc_timeframe" name="reportedip_hive_xmlrpc_timeframe" value="<?php echo esc_attr( get_option( 'reportedip_hive_xmlrpc_timeframe', 60 ) ); ?>" min="1" max="1440" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Counter window for XML-RPC requests.', 'reportedip-hive' ); ?></p>
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 1v6m0 6v6"/><path d="m4.22 4.22 4.24 4.24m6.36 6.36 4.24 4.24"/><path d="M1 12h6m6 0h6"/><path d="m4.22 19.78 4.24-4.24m6.36-6.36 4.24-4.24"/></svg>
					<?php esc_html_e( 'Application password abuse', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Application passwords authenticate over Basic Auth on REST and XML-RPC and bypass the wp-login 2FA prompt. We rate-limit failed app-password authentications and (optionally) block app-password creation for users in 2FA-enforced roles until they have completed enrolment.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_app_passwords" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_monitor_app_passwords', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch application-password authentications', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_app_password_require_2fa" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_app_password_require_2fa', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Block app-password creation until 2FA enrolment is finished (for enforced roles)', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_app_password_threshold"><?php esc_html_e( 'How many failed auths?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_app_password_threshold" name="reportedip_hive_app_password_threshold" value="<?php echo esc_attr( get_option( 'reportedip_hive_app_password_threshold', 5 ) ); ?>" min="1" max="100" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_app_password_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_app_password_timeframe" name="reportedip_hive_app_password_timeframe" value="<?php echo esc_attr( get_option( 'reportedip_hive_app_password_timeframe', 15 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
					<?php esc_html_e( 'REST API abuse', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Per-IP rate limit on /wp-json/* requests. Catches scrapers and vulnerability scanners that hammer the REST surface. Sensitive routes (/wp/v2/users, /wp/v2/comments) use a tighter threshold by default.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_rest_api" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_monitor_rest_api', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch REST API requests', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_rest_threshold"><?php esc_html_e( 'Global requests threshold', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_rest_threshold" name="reportedip_hive_rest_threshold" value="<?php echo esc_attr( get_option( 'reportedip_hive_rest_threshold', 240 ) ); ?>" min="1" max="1000" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_rest_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_rest_timeframe" name="reportedip_hive_rest_timeframe" value="<?php echo esc_attr( get_option( 'reportedip_hive_rest_timeframe', 5 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_rest_sensitive_threshold"><?php esc_html_e( 'Sensitive-route threshold', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_rest_sensitive_threshold" name="reportedip_hive_rest_sensitive_threshold" value="<?php echo esc_attr( get_option( 'reportedip_hive_rest_sensitive_threshold', 20 ) ); ?>" min="1" max="500" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Tighter limit for /wp/v2/users and /wp/v2/comments.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_rest_sensitive_timeframe"><?php esc_html_e( 'Sensitive timeframe (min)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_rest_sensitive_timeframe" name="reportedip_hive_rest_sensitive_timeframe" value="<?php echo esc_attr( get_option( 'reportedip_hive_rest_sensitive_timeframe', 5 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
					<?php esc_html_e( 'User enumeration defence', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Closes the four classic username-leak vectors: ?author= probes, /wp-json/wp/v2/users, oEmbed author leaks, and the verbose "user does not exist" login error. Repeated probes from one IP also trip the auto-block.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_block_user_enumeration" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_block_user_enumeration', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Block username discovery and unify login errors', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_user_enum_threshold"><?php esc_html_e( 'How many probes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_user_enum_threshold" name="reportedip_hive_user_enum_threshold" value="<?php echo esc_attr( get_option( 'reportedip_hive_user_enum_threshold', 5 ) ); ?>" min="1" max="100" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_user_enum_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_user_enum_timeframe" name="reportedip_hive_user_enum_timeframe" value="<?php echo esc_attr( get_option( 'reportedip_hive_user_enum_timeframe', 5 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
					<?php esc_html_e( '404 / Scanner detection', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Catches vulnerability scanners. A single hit on a known-bad path (.env, wp-config.php.bak, /.git/config, /phpmyadmin, …) triggers immediately; bursts of regular 404s also count.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_404_scans" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_monitor_404_scans', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch suspicious 404s and known scanner paths', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_scan_404_threshold"><?php esc_html_e( '404 burst threshold', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_scan_404_threshold" name="reportedip_hive_scan_404_threshold" value="<?php echo esc_attr( get_option( 'reportedip_hive_scan_404_threshold', 8 ) ); ?>" min="1" max="100" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_scan_404_timeframe"><?php esc_html_e( 'Within how many minutes?', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_scan_404_timeframe" name="reportedip_hive_scan_404_timeframe" value="<?php echo esc_attr( get_option( 'reportedip_hive_scan_404_timeframe', 1 ) ); ?>" min="1" max="1440" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 2L3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4z"/><line x1="3" y1="6" x2="21" y2="6"/><path d="M16 10a4 4 0 0 1-8 0"/></svg>
					<?php esc_html_e( 'WooCommerce login', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Hooks into WooCommerce-specific login failures (my-account form, checkout AJAX login). Uses the same threshold as Failed login attempts.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_woocommerce" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_monitor_woocommerce', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch WooCommerce login attempts', 'reportedip-hive' ); ?></span>
					</label>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
					<?php esc_html_e( 'Geographic anomaly', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Watches successful logins. When the country / ASN seen for a user differs from anything observed in the rolling window, the event is logged and (optionally) the user\'s trusted-device cookies are revoked so the next login forces a fresh 2FA challenge. Country/ASN data comes from the cached community-mode reputation lookup — no extra external call.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_monitor_geo_anomaly" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_monitor_geo_anomaly', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch logins from new countries / networks', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_geo_revoke_trusted_devices" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_geo_revoke_trusted_devices', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Revoke trusted-device cookies on geo anomaly (forces 2FA on next login)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_geo_report_to_api" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_geo_report_to_api', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Also share anomalies with the community network (off by default — informational)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_geo_window_days"><?php esc_html_e( 'Look-back window (days)', 'reportedip-hive' ); ?></label>
					<input type="number" id="reportedip_hive_geo_window_days" name="reportedip_hive_geo_window_days" value="<?php echo esc_attr( get_option( 'reportedip_hive_geo_window_days', 90 ) ); ?>" min="1" max="365" class="rip-input" style="max-width: 180px;" />
					<p class="rip-help-text"><?php esc_html_e( 'How long a country/ASN stays "known" for a user.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><line x1="12" y1="15" x2="12" y2="18"/></svg>
					<?php esc_html_e( 'Password strength policy', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Enforces a minimum length, character-class diversity and an optional public-breach check (HaveIBeenPwned k-anonymity — only the first 5 SHA-1 hex characters of the password leave the server). Applies to users in the 2FA-enforced roles by default.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_password_policy_enabled" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_password_policy_enabled', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Enforce password policy', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_password_check_hibp" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_password_check_hibp', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Reject passwords that appear in public breaches (HaveIBeenPwned, k-anonymity protocol)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_password_policy_all_users" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_password_policy_all_users', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Apply to all users (default: only 2FA-enforced roles)', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_password_min_length"><?php esc_html_e( 'Minimum length', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_password_min_length" name="reportedip_hive_password_min_length" value="<?php echo esc_attr( get_option( 'reportedip_hive_password_min_length', 12 ) ); ?>" min="8" max="128" class="rip-input" />
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_password_min_classes"><?php esc_html_e( 'Required character classes (lower / upper / digit / symbol)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_password_min_classes" name="reportedip_hive_password_min_classes" value="<?php echo esc_attr( get_option( 'reportedip_hive_password_min_classes', 3 ) ); ?>" min="1" max="4" class="rip-input" />
					</div>
				</div>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save detection settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>
		<?php
	}

	/**
	 * Tab: Blocking — what to do once an incident has been detected.
	 *
	 * Plain-language framing: "do we block, for how long, and at what
	 * community-confidence level."
	 *
	 * @since 1.2.0
	 */
	private function render_blocking_tab() {
		?>
		<form method="post" action="options.php" class="rip-form">
			<?php settings_fields( 'reportedip_hive_protection_blocking' ); ?>

			<?php /* Checkbox-off fallbacks. */ ?>
			<input type="hidden" name="reportedip_hive_auto_block" value="0" />
			<input type="hidden" name="reportedip_hive_report_only_mode" value="0" />

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
					<?php esc_html_e( 'Auto-blocking', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'When detection triggers, automatically block the offender. Disable this if you only want to monitor.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_auto_block" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_auto_block', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Block IPs automatically when a threshold is crossed', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-2">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_block_duration"><?php esc_html_e( 'Block length (hours)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_block_duration" name="reportedip_hive_block_duration" value="<?php echo esc_attr( get_option( 'reportedip_hive_block_duration', 24 ) ); ?>" min="0" max="8760" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'How long an IP stays blocked after a trigger. 0 = permanent. 24 hours is a good default.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_block_threshold"><?php esc_html_e( 'Community confidence to block', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_block_threshold" name="reportedip_hive_block_threshold" value="<?php echo esc_attr( get_option( 'reportedip_hive_block_threshold', 75 ) ); ?>" min="0" max="100" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'When community-mode is on, only block IPs the network is at least this confident about (0–100). Lower = more aggressive but more false positives.', 'reportedip-hive' ); ?></p>
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
					<?php esc_html_e( 'Report-only mode', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Audit mode: detect and log incidents but do not block anyone. Useful before flipping enforcement on.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_report_only_mode" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_report_only_mode', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Watch and report only — never block', 'reportedip-hive' ); ?></span>
					</label>
					<div class="rip-alert rip-alert--warning rip-mt-2">
						<strong><?php esc_html_e( 'Heads up:', 'reportedip-hive' ); ?></strong>
						<?php esc_html_e( 'When this is on, no IP will be blocked, even if Auto-blocking above is enabled. The plugin keeps watching and logging.', 'reportedip-hive' ); ?>
					</div>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_report_cooldown_hours"><?php esc_html_e( 'Report cool-down (hours)', 'reportedip-hive' ); ?></label>
					<input type="number" id="reportedip_hive_report_cooldown_hours" name="reportedip_hive_report_cooldown_hours" value="<?php echo esc_attr( get_option( 'reportedip_hive_report_cooldown_hours', 24 ) ); ?>" min="0" max="168" class="rip-input" style="max-width: 180px;" />
					<p class="rip-help-text"><?php esc_html_e( 'Wait at least this long before re-reporting the same IP to the community network. Prevents duplicate reports.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
					<?php esc_html_e( 'Blocked-page contact link', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Optional URL shown to blocked visitors if they think the block is a mistake (your contact form, support page, etc.). Leave empty to hide the link.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-label rip-sr-only" for="reportedip_hive_blocked_page_contact_url"><?php esc_html_e( 'Contact URL', 'reportedip-hive' ); ?></label>
					<input type="url" id="reportedip_hive_blocked_page_contact_url" name="reportedip_hive_blocked_page_contact_url" value="<?php echo esc_attr( (string) get_option( 'reportedip_hive_blocked_page_contact_url', '' ) ); ?>" class="rip-input" placeholder="https://example.com/contact" />
				</div>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save blocking settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>
		<?php
	}

	/**
	 * Tab: Hide Login — moves wp-login.php behind a custom slug.
	 *
	 * @since 1.2.0
	 */
	private function render_hide_login_tab() {
		$hide_login = class_exists( 'ReportedIP_Hive_Hide_Login' )
			? ReportedIP_Hive_Hide_Login::get_instance()
			: null;

		$enabled       = (bool) get_option( 'reportedip_hive_hide_login_enabled', false );
		$slug          = (string) get_option( 'reportedip_hive_hide_login_slug', '' );
		$response_mode = (string) get_option( 'reportedip_hive_hide_login_response_mode', ReportedIP_Hive_Hide_Login::RESPONSE_MODE_BLOCK_PAGE );
		$token_in_urls = (bool) get_option( 'reportedip_hive_hide_login_token_in_urls', true );
		$preview_url   = $hide_login && $hide_login->is_active() ? $hide_login->get_login_url() : '';
		$kill_switch   = defined( 'REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN' ) && REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN;
		?>
		<form method="post" action="options.php" class="rip-form">
			<?php settings_fields( 'reportedip_hive_hide_login' ); ?>

			<?php /* Checkbox-off fallbacks. */ ?>
			<input type="hidden" name="reportedip_hive_hide_login_enabled" value="0" />
			<input type="hidden" name="reportedip_hive_hide_login_token_in_urls" value="0" />

			<?php if ( $kill_switch ) : ?>
				<div class="rip-alert rip-alert--warning rip-mb-4">
					<strong><?php esc_html_e( 'Kill switch is active.', 'reportedip-hive' ); ?></strong>
					<?php esc_html_e( 'The constant REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN is defined as true in wp-config.php — Hide Login is disabled until you remove it. This is the recovery path: if you ever lose your custom slug, drop the constant in and the original wp-login.php is reachable again.', 'reportedip-hive' ); ?>
				</div>
			<?php endif; ?>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
					<?php esc_html_e( 'Hide WordPress login', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Move wp-login.php behind a custom slug. Bots that scan default WordPress paths will no longer find a login form to brute-force.', 'reportedip-hive' ); ?></p>

				<div class="rip-alert rip-alert--info rip-mb-4">
					<strong><?php esc_html_e( 'Heads up — this is security through obscurity.', 'reportedip-hive' ); ?></strong>
					<?php esc_html_e( 'Hiding the login URL stops automated scanners but does not replace strong passwords, 2FA or rate limiting. Use it as one layer of a defense-in-depth setup.', 'reportedip-hive' ); ?>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_hide_login_enabled" value="1" class="rip-toggle__input" <?php checked( $enabled ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Enable Hide Login', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_hide_login_slug"><?php esc_html_e( 'Custom login slug', 'reportedip-hive' ); ?></label>
					<div class="rip-input-row" style="display:flex; align-items:center; gap:.5rem;">
						<span class="rip-help-text" style="white-space:nowrap;"><?php echo esc_html( trailingslashit( home_url() ) ); ?></span>
						<input type="text" id="reportedip_hive_hide_login_slug" name="reportedip_hive_hide_login_slug" value="<?php echo esc_attr( $slug ); ?>" class="rip-input" placeholder="welcome" autocomplete="off" spellcheck="false" />
					</div>
					<p class="rip-help-text">
						<?php esc_html_e( '3–50 characters: lowercase letters, digits, dashes or underscores. Reserved WordPress paths and existing post/page/author slugs are rejected.', 'reportedip-hive' ); ?>
					</p>
					<?php if ( '' !== $preview_url ) : ?>
						<p class="rip-help-text">
							<strong><?php esc_html_e( 'Active login URL:', 'reportedip-hive' ); ?></strong>
							<code><?php echo esc_html( $preview_url ); ?></code>
						</p>
					<?php endif; ?>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
					<?php esc_html_e( 'What visitors see at the old URL', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Choose the response when someone hits wp-login.php or wp-admin without being logged in.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-radio">
						<input type="radio" name="reportedip_hive_hide_login_response_mode" value="block_page" <?php checked( $response_mode, 'block_page' ); ?> />
						<span><strong><?php esc_html_e( 'Hive block page (recommended)', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'shows the same 403 page as a blocked IP. Branded and friendly to legitimate users who got there by accident.', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-radio">
						<input type="radio" name="reportedip_hive_hide_login_response_mode" value="404" <?php checked( $response_mode, '404' ); ?> />
						<span><strong><?php esc_html_e( 'Soft 404', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'serves the theme’s 404 page. Hides that the plugin exists at all — better against fingerprinting, less helpful to humans.', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_hide_login_token_in_urls" value="1" class="rip-toggle__input" <?php checked( $token_in_urls ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Append the slug as a marker query argument to all generated login URLs', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Off by default — the slug already lives in the URL path, the extra query argument is redundant and can collide with plugins that use the same name. Enable only if you have a specific integration that expects the marker.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4"/><path d="M12 17h.01"/><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>
					<?php esc_html_e( 'Locked out? Recovery via wp-config.php', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'If you forget the slug, add this constant to wp-config.php (above the line that says “That’s all, stop editing!”). The original wp-login.php becomes reachable again — Hide Login stays inactive until you remove the constant.', 'reportedip-hive' ); ?></p>

				<div class="rip-alert rip-alert--warning">
					<pre style="margin:0; white-space:pre-wrap; word-break:break-all;"><code>define( 'REPORTEDIP_HIVE_DISABLE_HIDE_LOGIN', true );</code></pre>
				</div>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save Hide Login settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>
		<?php
	}

	/**
	 * Tab: Notifications — admin emails when incidents happen.
	 *
	 * @since 1.2.0
	 */
	private function render_notifications_tab() {
		?>
		<form method="post" action="options.php" class="rip-form">
			<?php settings_fields( 'reportedip_hive_protection_notifications' ); ?>

			<?php /* Checkbox-off fallbacks. */ ?>
			<input type="hidden" name="reportedip_hive_notify_admin" value="0" />

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
					<?php esc_html_e( 'Email the admin', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Send an email when something significant happens — repeated brute-force attempts, new blocks, etc. Goes to the WordPress admin email by default.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_notify_admin" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_notify_admin', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Send admin notifications when security events occur', 'reportedip-hive' ); ?></span>
					</label>
				</div>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save notification settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>

		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
				<?php esc_html_e( 'Test the email pipeline', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc"><?php esc_html_e( 'Sends a sample mail through the unified branded template and your active mail provider. Useful before flipping notifications on, or after changing SMTP settings.', 'reportedip-hive' ); ?></p>

			<div class="rip-form-group">
				<button type="button" class="rip-button rip-button--secondary" id="reportedip-send-test-mail">
					<?php esc_html_e( 'Send test email', 'reportedip-hive' ); ?>
				</button>
				<span id="reportedip-send-test-mail-status" class="rip-help-text rip-ml-3 rip-hidden"></span>
				<script>
				(function(){
					var btn = document.getElementById('reportedip-send-test-mail');
					if (!btn || !window.jQuery || !window.reportedip_hive_ajax) return;
					var $ = window.jQuery, $btn = $(btn), $status = $('#reportedip-send-test-mail-status');
					var labelIdle = <?php echo wp_json_encode( __( 'Send test email', 'reportedip-hive' ) ); ?>;
					var labelBusy = <?php echo wp_json_encode( __( 'Sending…', 'reportedip-hive' ) ); ?>;
					$btn.on('click', function(e){
						e.preventDefault();
						$btn.prop('disabled', true).text(labelBusy);
						$status.removeClass('rip-hidden').text('').css('color', '');
						$.post(window.reportedip_hive_ajax.ajax_url, {
							action: 'reportedip_hive_send_test_mail',
							nonce:  window.reportedip_hive_ajax.nonce
						}).done(function(resp){
							if (resp && resp.success) {
								$status.text(resp.data && resp.data.message ? resp.data.message : '').css('color', 'var(--rip-success)');
							} else {
								$status.text(resp && resp.data && resp.data.message ? resp.data.message : <?php echo wp_json_encode( __( 'Test email failed.', 'reportedip-hive' ) ); ?>).css('color', 'var(--rip-danger)');
							}
						}).fail(function(){
							$status.text(<?php echo wp_json_encode( __( 'Request failed. Check server logs.', 'reportedip-hive' ) ); ?>).css('color', 'var(--rip-danger)');
						}).always(function(){
							$btn.prop('disabled', false).text(labelIdle);
						});
					});
				})();
				</script>
			</div>
		</div>
		<?php
	}

	/**
	 * Tab: Privacy & Logs — what the plugin records and how long it keeps it.
	 *
	 * Plain-language framing: a logging-profile radio (Minimal / Standard /
	 * Detailed) writes the underlying minimal_logging + detailed_logging
	 * toggles, so users do not have to reason about both.
	 *
	 * @since 1.2.0
	 */
	private function render_privacy_logs_tab() {
		$minimal  = (bool) get_option( 'reportedip_hive_minimal_logging', false );
		$detailed = (bool) get_option( 'reportedip_hive_detailed_logging', false );
		$profile  = $minimal ? 'minimal' : ( $detailed ? 'detailed' : 'standard' );
		?>
		<form method="post" action="options.php" class="rip-form" id="rip-privacy-logs-form">
			<?php settings_fields( 'reportedip_hive_advanced_privacy' ); ?>

			<?php /* Checkbox-off fallbacks. (minimal_/detailed_logging are JS-driven hidden fields, see below.) */ ?>
			<input type="hidden" name="reportedip_hive_log_user_agents" value="0" />
			<input type="hidden" name="reportedip_hive_log_referer_domains" value="0" />
			<input type="hidden" name="reportedip_hive_delete_data_on_uninstall" value="0" />

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
					<?php esc_html_e( 'Logging profile', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Pick how much detail to keep about security events. Minimal is the privacy-first choice; Detailed helps when investigating attacks.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-radio">
						<input type="radio" name="rip_logging_profile" value="minimal" data-min="1" data-det="0" <?php checked( $profile, 'minimal' ); ?> />
						<span class="rip-radio__label"><strong><?php esc_html_e( 'Minimal', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Essential security events only. Recommended for strict GDPR setups.', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-radio rip-mt-2">
						<input type="radio" name="rip_logging_profile" value="standard" data-min="0" data-det="0" <?php checked( $profile, 'standard' ); ?> />
						<span class="rip-radio__label"><strong><?php esc_html_e( 'Standard', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Default. Enough context to spot patterns without storing personal data.', 'reportedip-hive' ); ?></span>
					</label>
					<label class="rip-radio rip-mt-2">
						<input type="radio" name="rip_logging_profile" value="detailed" data-min="0" data-det="1" <?php checked( $profile, 'detailed' ); ?> />
						<span class="rip-radio__label"><strong><?php esc_html_e( 'Detailed', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Adds hashed usernames so repeat-offender analysis is possible. Disable if you do not need it.', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<input type="hidden" name="reportedip_hive_minimal_logging" id="rip-minimal-logging" value="<?php echo $minimal ? '1' : '0'; ?>" />
				<input type="hidden" name="reportedip_hive_detailed_logging" id="rip-detailed-logging" value="<?php echo $detailed ? '1' : '0'; ?>" />

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_log_level"><?php esc_html_e( 'Log severity threshold', 'reportedip-hive' ); ?></label>
					<select id="reportedip_hive_log_level" name="reportedip_hive_log_level" class="rip-select">
						<option value="debug" <?php selected( get_option( 'reportedip_hive_log_level', 'info' ), 'debug' ); ?>><?php esc_html_e( 'Debug — everything (verbose, dev only)', 'reportedip-hive' ); ?></option>
						<option value="info" <?php selected( get_option( 'reportedip_hive_log_level', 'info' ), 'info' ); ?>><?php esc_html_e( 'Info — normal events (recommended)', 'reportedip-hive' ); ?></option>
						<option value="warning" <?php selected( get_option( 'reportedip_hive_log_level', 'info' ), 'warning' ); ?>><?php esc_html_e( 'Warning — only important events', 'reportedip-hive' ); ?></option>
						<option value="error" <?php selected( get_option( 'reportedip_hive_log_level', 'info' ), 'error' ); ?>><?php esc_html_e( 'Error — critical events only', 'reportedip-hive' ); ?></option>
					</select>
				</div>

				<script>
				(function(){
					if (!window.jQuery) return;
					var $ = window.jQuery;
					$(document).on('change', 'input[name="rip_logging_profile"]', function(){
						$('#rip-minimal-logging').val($(this).data('min'));
						$('#rip-detailed-logging').val($(this).data('det'));
					});
				})();
				</script>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="7" r="4"/><path d="M5 21v-2a4 4 0 0 1 4-4h6a4 4 0 0 1 4 4v2"/></svg>
					<?php esc_html_e( 'What we record about visitors', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Both options below are off by default for privacy. Enable only what you need for incident analysis.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_log_user_agents" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_log_user_agents', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Log browser user-agent strings (truncated to 50 chars to limit fingerprinting)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_log_referer_domains" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_log_referer_domains', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Log referrer domain only (e.g. "example.com" — never the full URL)', 'reportedip-hive' ); ?></span>
					</label>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
					<?php esc_html_e( 'How long we keep data', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Old log entries are removed automatically. Anonymisation strips personal data even earlier without losing the security signal.', 'reportedip-hive' ); ?></p>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4 rip-mb-4">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_data_retention_days"><?php esc_html_e( 'Delete logs after (days)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_data_retention_days" name="reportedip_hive_data_retention_days" value="<?php echo esc_attr( get_option( 'reportedip_hive_data_retention_days', 30 ) ); ?>" min="7" max="365" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( '30 days is plenty for security analysis. Longer retention may require a privacy-policy update.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_auto_anonymize_days"><?php esc_html_e( 'Anonymise older entries after (days)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_auto_anonymize_days" name="reportedip_hive_auto_anonymize_days" value="<?php echo esc_attr( get_option( 'reportedip_hive_auto_anonymize_days', 7 ) ); ?>" min="1" max="90" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Removes IP last-octet, user-agent strings, etc. while keeping aggregate counts.', 'reportedip-hive' ); ?></p>
					</div>
				</div>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_delete_data_on_uninstall" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_delete_data_on_uninstall', false ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Delete all plugin data on uninstall (logs, settings, IP lists)', 'reportedip-hive' ); ?></span>
					</label>
					<p class="rip-help-text"><?php esc_html_e( 'Off by default — uninstalling normally keeps your configuration so reinstalling restores it.', 'reportedip-hive' ); ?></p>
				</div>
			</div>

			<div class="rip-alert rip-alert--info">
				<strong><?php esc_html_e( 'GDPR note:', 'reportedip-hive' ); ?></strong>
				<?php esc_html_e( 'IP-based blocking has a legitimate-interest legal basis under GDPR. Mention security monitoring in your privacy policy.', 'reportedip-hive' ); ?>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save privacy & logs settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>

		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
				<?php esc_html_e( 'Maintenance & exports', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc"><?php esc_html_e( 'These actions run immediately and are not part of the form above.', 'reportedip-hive' ); ?></p>

			<div class="rip-card">
				<div class="rip-card__body">
					<div class="rip-grid rip-grid-cols-3 rip-gap-4">
						<div>
							<p class="rip-label rip-mb-2"><?php esc_html_e( 'Database cleanup', 'reportedip-hive' ); ?></p>
							<button type="button" class="rip-button rip-button--secondary" id="cleanup-old-logs">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
								<?php esc_html_e( 'Clean up logs', 'reportedip-hive' ); ?>
							</button>
							<p class="rip-help-text">
								<?php
								/* translators: %d: number of days after which log entries are removed */
								echo esc_html( sprintf( __( 'Removes logs older than %d days right now.', 'reportedip-hive' ), (int) get_option( 'reportedip_hive_data_retention_days', 30 ) ) );
								?>
							</p>
						</div>
						<div>
							<p class="rip-label rip-mb-2"><?php esc_html_e( 'Anonymise old data', 'reportedip-hive' ); ?></p>
							<button type="button" class="rip-button rip-button--secondary" id="anonymize-old-data">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="23" y1="11" x2="17" y2="11"/></svg>
								<?php esc_html_e( 'Anonymise', 'reportedip-hive' ); ?>
							</button>
							<p class="rip-help-text">
								<?php
								/* translators: %d: number of days after which personal data is anonymized */
								echo esc_html( sprintf( __( 'Strips personal data older than %d days right now.', 'reportedip-hive' ), (int) get_option( 'reportedip_hive_auto_anonymize_days', 7 ) ) );
								?>
							</p>
						</div>
						<div>
							<p class="rip-label rip-mb-2"><?php esc_html_e( 'Export logs', 'reportedip-hive' ); ?></p>
							<div class="rip-flex rip-gap-2">
								<button type="button" class="rip-button rip-button--secondary" id="export-logs-csv">CSV</button>
								<button type="button" class="rip-button rip-button--secondary" id="export-logs-json">JSON</button>
							</div>
							<p class="rip-help-text"><?php esc_html_e( 'Download log entries for offline analysis.', 'reportedip-hive' ); ?></p>
						</div>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Tab: Performance & Tools — caching, rate-limiting, settings import/export.
	 *
	 * @since 1.2.0
	 */
	private function render_performance_advanced_tab() {
		$cache         = ReportedIP_Hive_Cache::get_instance();
		$cache_stats   = $cache->get_cache_statistics();
		$cache_info    = $cache->get_cache_info();
		$cache_savings = $cache->estimate_monthly_savings();
		$api_health    = $this->api_client->get_api_health_status();
		$api_usage     = $this->api_client->estimate_monthly_usage();
		?>
		<form method="post" action="options.php" class="rip-form">
			<?php settings_fields( 'reportedip_hive_advanced_performance' ); ?>

			<?php /* Checkbox-off fallbacks. */ ?>
			<input type="hidden" name="reportedip_hive_enable_caching" value="0" />

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
					<?php esc_html_e( 'Caching — saves API credits', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Caching reuses the result of past IP lookups instead of asking the community network again. Typically saves 70–90% of API calls.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-toggle">
						<input type="checkbox" name="reportedip_hive_enable_caching" value="1" class="rip-toggle__input" <?php checked( get_option( 'reportedip_hive_enable_caching', true ) ); ?> />
						<span class="rip-toggle__slider"></span>
						<span class="rip-toggle__label"><?php esc_html_e( 'Cache IP-reputation results (recommended)', 'reportedip-hive' ); ?></span>
					</label>
				</div>

				<div class="rip-grid rip-grid-cols-2 rip-gap-4">
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_cache_duration"><?php esc_html_e( 'Cache results for (hours)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_cache_duration" name="reportedip_hive_cache_duration" value="<?php echo esc_attr( get_option( 'reportedip_hive_cache_duration', 24 ) ); ?>" min="1" max="168" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'How long to keep a "known IP" answer. 24–48 hours fits most sites.', 'reportedip-hive' ); ?></p>
					</div>
					<div class="rip-form-group">
						<label class="rip-label" for="reportedip_hive_negative_cache_duration"><?php esc_html_e( 'Cache "unknown IP" for (hours)', 'reportedip-hive' ); ?></label>
						<input type="number" id="reportedip_hive_negative_cache_duration" name="reportedip_hive_negative_cache_duration" value="<?php echo esc_attr( get_option( 'reportedip_hive_negative_cache_duration', 2 ) ); ?>" min="1" max="24" class="rip-input" />
						<p class="rip-help-text"><?php esc_html_e( 'Shorter than the regular cache so a freshly-reported IP gets re-checked sooner.', 'reportedip-hive' ); ?></p>
					</div>
				</div>
			</div>

			<div class="rip-settings-section">
				<h2 class="rip-settings-section__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
					<?php esc_html_e( 'API rate limit', 'reportedip-hive' ); ?>
				</h2>
				<p class="rip-settings-section__desc"><?php esc_html_e( 'Hard ceiling on API calls per hour. Once reached, cached data is used; new IPs are skipped. Protects you from runaway costs during a flood attack.', 'reportedip-hive' ); ?></p>

				<div class="rip-form-group">
					<label class="rip-label" for="reportedip_hive_max_api_calls_per_hour"><?php esc_html_e( 'Max API calls per hour', 'reportedip-hive' ); ?></label>
					<input type="number" id="reportedip_hive_max_api_calls_per_hour" name="reportedip_hive_max_api_calls_per_hour" value="<?php echo esc_attr( get_option( 'reportedip_hive_max_api_calls_per_hour', 100 ) ); ?>" min="10" max="10000" class="rip-input" style="max-width: 180px;" />
				</div>
			</div>

			<div class="rip-form-actions">
				<?php submit_button( __( 'Save performance settings', 'reportedip-hive' ), 'rip-button rip-button--primary', 'submit', false ); ?>
			</div>
		</form>

		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 20V10"/><path d="M12 20V4"/><path d="M6 20v-6"/></svg>
				<?php esc_html_e( 'Live usage stats', 'reportedip-hive' ); ?>
			</h2>
			<div class="rip-stat-cards">
				<div class="rip-stat-card rip-stat-card--centered">
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__title"><?php esc_html_e( 'Estimated monthly API calls', 'reportedip-hive' ); ?></div>
						<div class="rip-stat-card__value"><?php echo esc_html( $api_usage['estimated_monthly_calls'] ); ?></div>
						<div class="rip-stat-card__detail">
						<?php
							/* translators: %1$s: confidence level, %2$s: daily average */
							echo esc_html( sprintf( __( 'Confidence: %1$s · Daily avg: %2$s', 'reportedip-hive' ), ucfirst( (string) $api_usage['confidence'] ), (string) $api_usage['current_daily_average'] ) );
						?>
						</div>
					</div>
				</div>
				<div class="rip-stat-card rip-stat-card--centered">
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__title"><?php esc_html_e( 'Cache efficiency', 'reportedip-hive' ); ?></div>
						<div class="rip-stat-card__value"><?php echo esc_html( $cache_stats['hit_rate'] ); ?>%</div>
						<div class="rip-stat-card__detail">
						<?php
							/* translators: %1$s: cache hits, %2$s: cache misses */
							echo esc_html( sprintf( __( 'Hits: %1$s · Misses: %2$s', 'reportedip-hive' ), (string) $cache_stats['hits'], (string) $cache_stats['misses'] ) );
						?>
						</div>
					</div>
				</div>
				<div class="rip-stat-card rip-stat-card--centered">
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__title"><?php esc_html_e( 'Credits saved this month', 'reportedip-hive' ); ?></div>
						<div class="rip-stat-card__value"><?php echo esc_html( $cache_savings['estimated_monthly_calls_saved'] ); ?></div>
					</div>
				</div>
				<div class="rip-stat-card rip-stat-card--centered">
					<div class="rip-stat-card__content">
						<div class="rip-stat-card__title"><?php esc_html_e( 'API health', 'reportedip-hive' ); ?></div>
						<div class="rip-stat-card__value"><?php echo esc_html( $api_health['health_score'] ); ?>%</div>
					</div>
				</div>
			</div>
		</div>

		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
				<?php esc_html_e( 'Cache management', 'reportedip-hive' ); ?>
			</h2>
			<div class="rip-card">
				<div class="rip-card__body">
					<div class="rip-cache-info rip-mb-3">
						<div class="rip-cache-info__item">
							<span class="rip-cache-info__label"><?php esc_html_e( 'Entries', 'reportedip-hive' ); ?></span>
							<span class="rip-cache-info__value">
							<?php
								/* translators: %1$s: active entries, %2$s: expired entries */
								echo esc_html( sprintf( __( '%1$s active, %2$s expired', 'reportedip-hive' ), (string) $cache_info['active_count'], (string) $cache_info['expired_count'] ) );
							?>
							</span>
						</div>
						<div class="rip-cache-info__item">
							<span class="rip-cache-info__label"><?php esc_html_e( 'Size', 'reportedip-hive' ); ?></span>
							<span class="rip-cache-info__value"><?php echo esc_html( $cache_info['total_size_mb'] ); ?> MB</span>
						</div>
					</div>
					<div class="rip-flex rip-gap-2">
						<button type="button" class="rip-button rip-button--secondary" id="clear-cache">
							<?php esc_html_e( 'Clear all cache', 'reportedip-hive' ); ?>
						</button>
						<button type="button" class="rip-button rip-button--ghost" id="cleanup-expired-cache">
							<?php esc_html_e( 'Clean expired entries', 'reportedip-hive' ); ?>
						</button>
					</div>
				</div>
			</div>
		</div>

		<div class="rip-settings-section">
			<h2 class="rip-settings-section__title">
				<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
				<?php esc_html_e( 'Setup wizard', 'reportedip-hive' ); ?>
			</h2>
			<p class="rip-settings-section__desc"><?php esc_html_e( 'Re-run the guided setup to reconfigure mode, API access, detection thresholds and notifications. Existing settings are pre-filled — you can review and confirm each step.', 'reportedip-hive' ); ?></p>

			<div class="rip-flex rip-gap-2">
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive-wizard&step=1' ) ); ?>" class="rip-button rip-button--secondary">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg>
					<?php esc_html_e( 'Restart setup wizard', 'reportedip-hive' ); ?>
				</a>
			</div>
		</div>

		<?php
		/**
		 * Render the Settings Import/Export panel inside this tab.
		 * Lives in admin/class-settings-import-export.php for separation of concerns.
		 */
		if ( class_exists( 'ReportedIP_Hive_Settings_Import_Export' ) ) {
			ReportedIP_Hive_Settings_Import_Export::get_instance()->render_panel();
		}
		?>
		<?php
	}

	/**
	 * Debug & Health page
	 */
	public function debug_page() {
		$current_user_ip = $this->get_current_user_ip();
		$plugin_health   = $this->get_plugin_health_status();

		$plugin_data    = get_plugin_data( REPORTEDIP_HIVE_PLUGIN_FILE );
		$plugin_version = $plugin_data['Version'] ?? '1.0.0';

		$this->render_page_header( __( 'System Status', 'reportedip-hive' ), __( 'Health check and diagnostics', 'reportedip-hive' ) );
		?>

			<!-- Health Status Cards -->
			<div class="rip-health-grid">
				<?php
				$health_items = array(
					'logging'  => array(
						'icon'  => '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
						'title' => __( 'Logging', 'reportedip-hive' ),
					),
					'database' => array(
						'icon'  => '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
						'title' => __( 'Database', 'reportedip-hive' ),
					),
					'api'      => array(
						'icon'  => '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>',
						'title' => __( 'API', 'reportedip-hive' ),
					),
				);
				foreach ( $health_items as $key => $item ) :
					$status       = $plugin_health[ $key ]['status'];
					$status_class = $status === 'healthy' ? 'success' : ( $status === 'warning' ? 'warning' : 'danger' );
					?>
				<div class="rip-health-card rip-health-card--<?php echo esc_attr( $status_class ); ?>">
					<div class="rip-health-card-icon">
						<?php echo wp_kses_post( $item['icon'] ); ?>
					</div>
					<div class="rip-health-card-content">
						<h3><?php echo esc_html( $item['title'] ); ?></h3>
						<span class="rip-health-status"><?php echo esc_html( $plugin_health[ $key ]['message'] ); ?></span>
					</div>
					<div class="rip-health-indicator rip-health-indicator--<?php echo esc_attr( $status_class ); ?>">
						<?php if ( $status === 'healthy' ) : ?>
							<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>
						<?php elseif ( $status === 'warning' ) : ?>
							<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
						<?php else : ?>
							<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
						<?php endif; ?>
					</div>
				</div>
				<?php endforeach; ?>
			</div>

			<!-- System Info Section -->
			<div class="rip-card">
				<div class="rip-card__header">
					<h2><?php esc_html_e( 'System Information', 'reportedip-hive' ); ?></h2>
				</div>
				<div class="rip-card__body">
					<div class="rip-info-grid">
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'Plugin Version', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value"><code><?php echo esc_html( $plugin_version ); ?></code></span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'PHP Version', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value"><code><?php echo esc_html( PHP_VERSION ); ?></code></span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'WordPress Version', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value"><code><?php echo esc_html( get_bloginfo( 'version' ) ); ?></code></span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'Your IP Address', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value">
								<code><?php echo esc_html( $current_user_ip ); ?></code>
								<?php
								if ( $this->database->is_whitelisted( $current_user_ip ) ) {
									echo '<span class="rip-badge rip-badge--success">' . esc_html__( 'Whitelisted', 'reportedip-hive' ) . '</span>';
								} elseif ( $this->database->is_blocked( $current_user_ip ) ) {
									echo '<span class="rip-badge rip-badge--danger">' . esc_html__( 'Blocked', 'reportedip-hive' ) . '</span>';
								}
								?>
							</span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'Protection Mode', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value">
								<?php if ( get_option( 'reportedip_hive_report_only_mode', false ) ) : ?>
									<span class="rip-badge rip-badge--warning"><?php esc_html_e( 'Report Only', 'reportedip-hive' ); ?></span>
								<?php else : ?>
									<span class="rip-badge rip-badge--success"><?php esc_html_e( 'Full Protection', 'reportedip-hive' ); ?></span>
								<?php endif; ?>
							</span>
						</div>
						<div class="rip-info-item">
							<span class="rip-info-label"><?php esc_html_e( 'Log Level', 'reportedip-hive' ); ?></span>
							<span class="rip-info-value"><code><?php echo esc_html( get_option( 'reportedip_hive_log_level', 'info' ) ); ?></code></span>
						</div>
					</div>
				</div>
			</div>

			<!-- Quick Actions -->
			<div class="rip-card">
				<div class="rip-card__header">
					<h2><?php esc_html_e( 'Quick Actions', 'reportedip-hive' ); ?></h2>
				</div>
				<div class="rip-card__body">
					<div class="rip-actions-grid">
						<div class="rip-action-group">
							<h3><?php esc_html_e( 'Connection Tests', 'reportedip-hive' ); ?></h3>
							<div class="rip-action-buttons">
								<?php if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) : ?>
								<button type="button" class="rip-button rip-button--secondary" id="test-database-connection">
									<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>
									<?php esc_html_e( 'Test Database', 'reportedip-hive' ); ?>
								</button>
								<?php endif; ?>
								<button type="button" class="rip-button rip-button--secondary" id="test-api-connection-debug">
									<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
									<?php esc_html_e( 'Test API', 'reportedip-hive' ); ?>
								</button>
							</div>
							<?php if ( ! ( defined( 'WP_DEBUG' ) && WP_DEBUG ) ) : ?>
							<p class="rip-help-text"><?php esc_html_e( 'Enable WP_DEBUG for additional diagnostic tests.', 'reportedip-hive' ); ?></p>
							<?php endif; ?>
							<div id="system-test-results" class="rip-test-results"></div>
						</div>

						<div class="rip-action-group rip-action-group--danger">
							<h3><?php esc_html_e( 'Reset Plugin', 'reportedip-hive' ); ?></h3>
							<p class="rip-action-description"><?php esc_html_e( 'Reset all plugin settings to defaults. This will not delete your blocked IPs or logs.', 'reportedip-hive' ); ?></p>
							<div class="rip-action-buttons">
								<button type="button" class="rip-button rip-button--warning" id="reset-settings">
									<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2.5 2v6h6M21.5 22v-6h-6"/><path d="M22 11.5A10 10 0 0 0 3.2 7.2M2 12.5a10 10 0 0 0 18.8 4.2"/></svg>
									<?php esc_html_e( 'Reset Settings', 'reportedip-hive' ); ?>
								</button>
								<button type="button" class="rip-button rip-button--danger" id="reset-all-data">
									<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
									<?php esc_html_e( 'Reset All Data', 'reportedip-hive' ); ?>
								</button>
							</div>
							<div id="reset-results" class="rip-test-results"></div>
						</div>
					</div>
				</div>
			</div>

		<?php $this->render_page_footer(); ?>
		<?php
	}

	/**
	 * Get current user IP - delegates to main plugin class
	 */
	private function get_current_user_ip() {
		return ReportedIP_Hive::get_client_ip();
	}

	/**
	 * Get plugin health status
	 */
	private function get_plugin_health_status() {
		$health = array(
			'logging'  => array(
				'status'  => 'healthy',
				'message' => '',
				'details' => array(),
			),
			'database' => array(
				'status'  => 'healthy',
				'message' => '',
				'details' => array(),
			),
			'api'      => array(
				'status'  => 'healthy',
				'message' => '',
				'details' => array(),
			),
		);

		try {
			$recent_logs = $this->logger->get_logs( 1, 1 );
			if ( empty( $recent_logs ) ) {
				$health['logging']['status']    = 'warning';
				$health['logging']['message']   = __( 'No recent logs found', 'reportedip-hive' );
				$health['logging']['details'][] = __( 'No logs in the last 24 hours. This might indicate a logging problem.', 'reportedip-hive' );
			} else {
				$health['logging']['message'] = __( 'Logging system operational', 'reportedip-hive' );
				/* translators: %s: timestamp of the most recent log entry */
				$health['logging']['details'][] = sprintf( __( 'Last log entry: %s', 'reportedip-hive' ), $recent_logs[0]->created_at );
			}

			$log_level = get_option( 'reportedip_hive_log_level', 'info' );
			if ( $log_level === 'error' ) {
				$health['logging']['status']    = 'warning';
				$health['logging']['details'][] = __( 'Log level is set to "error" - many events may not be logged.', 'reportedip-hive' );
			}
		} catch ( Exception $e ) {
			$health['logging']['status']    = 'error';
			$health['logging']['message']   = __( 'Logging system error', 'reportedip-hive' );
			$health['logging']['details'][] = $e->getMessage();
		}

		try {
			global $wpdb;
			$table_name = $wpdb->prefix . 'reportedip_hive_logs';
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- One-time health check
			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) === $table_name;

			if ( ! $table_exists ) {
				$health['database']['status']    = 'error';
				$health['database']['message']   = __( 'Database tables missing', 'reportedip-hive' );
				$health['database']['details'][] = __( 'Plugin tables not found. Try deactivating and reactivating the plugin.', 'reportedip-hive' );
			} else {
				$health['database']['message'] = __( 'Database operational', 'reportedip-hive' );

				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe table name composed from $wpdb->prefix and a hardcoded suffix.
				$log_count = $wpdb->get_var( "SELECT COUNT(*) FROM $table_name" );
				/* translators: %d: total number of log entries in the database */
				$health['database']['details'][] = sprintf( __( 'Total log entries: %d', 'reportedip-hive' ), $log_count );
			}
		} catch ( Exception $e ) {
			$health['database']['status']    = 'error';
			$health['database']['message']   = __( 'Database error', 'reportedip-hive' );
			$health['database']['details'][] = $e->getMessage();
		}

		try {
			if ( ! $this->api_client->is_configured() ) {
				$health['api']['status']    = 'warning';
				$health['api']['message']   = __( 'API not configured', 'reportedip-hive' );
				$health['api']['details'][] = __( 'API key not set. Some features will not work.', 'reportedip-hive' );
			} else {
				$test_result = get_transient( 'reportedip_hive_api_health' );
				if ( false === $test_result ) {
					$test_result = $this->api_client->test_connection();
					set_transient( 'reportedip_hive_api_health', $test_result, 300 );
				}
				if ( $test_result['success'] ) {
					$health['api']['message']   = __( 'API connection operational', 'reportedip-hive' );
					$health['api']['details'][] = __( 'API connection test successful.', 'reportedip-hive' );
				} else {
					$health['api']['status']    = 'error';
					$health['api']['message']   = __( 'API connection failed', 'reportedip-hive' );
					$health['api']['details'][] = $test_result['message'] ?? __( 'Unknown API error', 'reportedip-hive' );
				}
			}
		} catch ( Exception $e ) {
			$health['api']['status']    = 'error';
			$health['api']['message']   = __( 'API system error', 'reportedip-hive' );
			$health['api']['details'][] = $e->getMessage();
		}

		return $health;
	}

	/**
	 * Get dashboard statistics
	 */
	public function get_dashboard_stats() {
		global $wpdb;

		$ip_stats   = $this->database->get_ip_management_stats();
		$logs_table = $wpdb->prefix . 'reportedip_hive_logs';

		$cutoff_utc = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name built from $wpdb->prefix and a hardcoded constant; safe.
		$events_24h = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM $logs_table
				 WHERE created_at >= %s OR created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)",
				$cutoff_utc
			)
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		$queue_table = $wpdb->prefix . 'reportedip_hive_api_queue';
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name built from $wpdb->prefix and a hardcoded constant; safe.
		$queue_count = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM $queue_table WHERE status IN ('pending', 'failed')"
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared

		return array(
			'events_24h'      => $events_24h,
			'blocked_ips'     => $ip_stats['active_blocked'] ?? 0,
			'whitelisted_ips' => $ip_stats['active_whitelist'] ?? 0,
			'queue_count'     => $queue_count,
		);
	}

	/**
	 * Tier definitions — single source of truth for the Community page.
	 *
	 * Mirrors the constants in reportedip-service/includes/class-constants.php.
	 * Update only this table when the service side changes.
	 *
	 * @return array<string, array{label:string,reports_day:int,checks_day:int,features:array<int,string>,cta_type:string,in_pricing:bool}>
	 */
	private function get_tier_definitions() {
		return array(
			'free'         => array(
				'label'       => 'Free',
				'reports_day' => 50,
				'checks_day'  => 1000,
				'features'    => array(
					__( 'Local protection included', 'reportedip-hive' ),
					__( 'Community threat checks', 'reportedip-hive' ),
					__( 'Limited reports', 'reportedip-hive' ),
				),
				'cta_type'    => 'upgrade',
				'in_pricing'  => true,
			),
			'contributor'  => array(
				'label'       => 'Contributor',
				'reports_day' => 200,
				'checks_day'  => 5000,
				'features'    => array(
					__( 'Full report permission', 'reportedip-hive' ),
					__( 'Community recognition', 'reportedip-hive' ),
					__( 'Email support', 'reportedip-hive' ),
				),
				'cta_type'    => 'upgrade',
				'in_pricing'  => true,
			),
			'professional' => array(
				'label'       => 'Professional',
				'reports_day' => 1000,
				'checks_day'  => 25000,
				'features'    => array(
					__( 'Bulk operations', 'reportedip-hive' ),
					__( 'Analytics & trends', 'reportedip-hive' ),
					__( 'Priority support', 'reportedip-hive' ),
				),
				'cta_type'    => 'upgrade',
				'in_pricing'  => true,
			),
			'enterprise'   => array(
				'label'       => 'Enterprise',
				'reports_day' => -1,
				'checks_day'  => -1,
				'features'    => array(
					__( 'Unlimited API calls', 'reportedip-hive' ),
					__( 'Bulk import/export', 'reportedip-hive' ),
					__( 'White-label & SLA', 'reportedip-hive' ),
					__( 'Priority support', 'reportedip-hive' ),
				),
				'cta_type'    => 'contact',
				'in_pricing'  => true,
			),
			'honeypot'     => array(
				'label'       => 'Honeypot',
				'reports_day' => -1,
				'checks_day'  => -1,
				'features'    => array(),
				'cta_type'    => 'none',
				'in_pricing'  => false,
			),
		);
	}

	/**
	 * Normalize a service role to a tier slug plus metadata.
	 *
	 * @param string $user_role   Role from the verify-key response (e.g. "reportedip_free").
	 * @param bool   $is_honeypot Whether the key is flagged as honeypot.
	 * @return array Definition including an additional `slug` field.
	 */
	private function get_tier_info( $user_role, $is_honeypot = false ) {
		static $role_map = array(
			'reportedip_free'         => 'free',
			'reportedip_contributor'  => 'contributor',
			'reportedip_professional' => 'professional',
			'reportedip_enterprise'   => 'enterprise',
			'reportedip_honeypot'     => 'honeypot',
			'subscriber'              => 'free',
			'contributor'             => 'free',
			'author'                  => 'contributor',
			'editor'                  => 'professional',
			'administrator'           => 'enterprise',
		);

		if ( $is_honeypot ) {
			$slug = 'honeypot';
		} else {
			$key  = strtolower( (string) $user_role );
			$slug = $role_map[ $key ] ?? 'free';
		}

		$tiers        = $this->get_tier_definitions();
		$tier         = $tiers[ $slug ];
		$tier['slug'] = $slug;

		return $tier;
	}

	/**
	 * Return an external URL, optionally with a filter override.
	 *
	 * @param string $key          Identifier (upgrade|honeypot|faq|register|contact_mail).
	 * @param string $fallback_url Default URL used when no filter overrides it.
	 * @return string
	 */
	private function get_external_url( $key, $fallback_url ) {
		$url = apply_filters( 'reportedip_hive_external_url', $fallback_url, $key );

		return is_string( $url ) && $url !== '' ? $url : $fallback_url;
	}

	/**
	 * Community & Quota page
	 */
	public function community_page() {
		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();

		if ( isset( $_GET['rip_refresh'] ) && check_admin_referer( 'reportedip_hive_refresh_quota' ) ) {
			delete_transient( 'reportedip_hive_api_quota' );
			delete_transient( 'reportedip_hive_api_status' );
			if ( $this->api_client->is_configured() && $mode_manager->is_community_mode() ) {
				$this->api_client->refresh_api_quota();
			}
			wp_safe_redirect( admin_url( 'admin.php?page=reportedip-hive-community&refreshed=1' ) );
			exit;
		}

		$is_community_mode = $mode_manager->is_community_mode();
		$is_configured     = $this->api_client->is_configured();

		$cached_quota = $this->api_client->get_cached_quota();
		if ( false === $cached_quota && $is_community_mode && $is_configured ) {
			$fresh = $this->api_client->refresh_api_quota();
			if ( is_array( $fresh ) ) {
				$cached_quota = $fresh;
			}
		}

		$has_quota        = is_array( $cached_quota );
		$quota            = $has_quota ? $cached_quota : array();
		$quota_status     = $this->api_client->get_quota_status();
		$queue_summary    = $this->database->get_queue_summary();
		$security_summary = $this->database->get_security_summary( 30 );

		$user_role         = (string) ( $quota['user_role'] ?? '' );
		$is_honeypot       = ! empty( $quota['is_honeypot'] );
		$daily_limit       = (int) ( $quota['daily_report_limit'] ?? 0 );
		$remaining_reports = (int) ( $quota['remaining_reports'] ?? 0 );
		$reset_time        = $quota['reset_time'] ?? null;

		$tier = $this->get_tier_info( $user_role, $is_honeypot );

		$daily_limit_display = $daily_limit < 0 ? __( 'Unbegrenzt', 'reportedip-hive' ) : number_format_i18n( $daily_limit );
		$remaining_display   = $daily_limit < 0 ? __( 'Unbegrenzt', 'reportedip-hive' ) : number_format_i18n( $remaining_reports );

		$queue_size    = (int) ( $queue_summary['total_pending'] ?? 0 );
		$days_to_clear = $daily_limit > 0 ? (int) ceil( $queue_size / $daily_limit ) : null;

		$reset_formatted = '';
		if ( ! empty( $reset_time ) ) {
			$ts = strtotime( $reset_time );
			if ( $ts ) {
				$reset_formatted = wp_date( 'd.m.Y H:i', $ts );
			}
		}

		$refresh_url = wp_nonce_url(
			admin_url( 'admin.php?page=reportedip-hive-community&rip_refresh=1' ),
			'reportedip_hive_refresh_quota'
		);

		$upgrade_url = add_query_arg(
			array(
				'utm_source'   => 'plugin',
				'utm_medium'   => 'community-page',
				'utm_campaign' => 'upgrade',
			),
			$this->get_external_url( 'upgrade', REPORTEDIP_HIVE_UPGRADE_URL )
		);

		$contact_mail = $this->get_external_url( 'contact_mail', REPORTEDIP_HIVE_CONTACT_MAIL );
		$contact_url  = 'mailto:' . rawurlencode( $contact_mail ) . '?subject=' . rawurlencode( 'ReportedIP Enterprise-Anfrage' );

		$honeypot_url = add_query_arg(
			array(
				'utm_source'   => 'plugin',
				'utm_medium'   => 'community-page',
				'utm_campaign' => 'honeypot',
			),
			$this->get_external_url( 'honeypot', REPORTEDIP_HIVE_HONEYPOT_URL )
		);

		$subtab = isset( $_GET['subtab'] ) ? sanitize_key( wp_unslash( $_GET['subtab'] ) ) : 'main';
		$subtab = in_array( $subtab, array( 'main', 'promote' ), true ) ? $subtab : 'main';

		$main_tab_url    = admin_url( 'admin.php?page=reportedip-hive-community' );
		$promote_tab_url = admin_url( 'admin.php?page=reportedip-hive-community&subtab=promote' );

		$this->render_page_header( __( 'Community & Quota', 'reportedip-hive' ), __( 'Manage your API quota and community participation', 'reportedip-hive' ) );
		?>

			<div class="rip-content">

				<nav class="nav-tab-wrapper rip-mb-6" aria-label="<?php esc_attr_e( 'Community sections', 'reportedip-hive' ); ?>">
					<a href="<?php echo esc_url( $main_tab_url ); ?>" class="nav-tab <?php echo 'main' === $subtab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Community & Quota', 'reportedip-hive' ); ?></a>
					<a href="<?php echo esc_url( $promote_tab_url ); ?>" class="nav-tab <?php echo 'promote' === $subtab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Promote', 'reportedip-hive' ); ?></a>
				</nav>

				<?php if ( 'main' === $subtab ) : ?>

					<?php if ( isset( $_GET['refreshed'] ) ) : ?>
					<div class="rip-alert rip-alert--success rip-mb-6">
						<?php esc_html_e( 'Status has been refreshed.', 'reportedip-hive' ); ?>
					</div>
				<?php endif; ?>

					<?php if ( ! $is_community_mode ) : ?>
					<div class="rip-alert rip-alert--info rip-mb-6">
						<strong><?php esc_html_e( 'Local Shield mode active', 'reportedip-hive' ); ?></strong><br>
						<?php esc_html_e( 'The plugin is currently running in local mode. Community features like shared reports, quota management and tier upgrades are disabled. Switch to community mode to benefit from the community threat intelligence.', 'reportedip-hive' ); ?>
						<br><br>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive-settings&tab=general' ) ); ?>" class="rip-button rip-button--primary">
							<?php esc_html_e( 'Switch to Community', 'reportedip-hive' ); ?>
						</a>
					</div>
				<?php elseif ( ! $is_configured ) : ?>
					<div class="rip-alert rip-alert--warning rip-mb-6">
						<strong><?php esc_html_e( 'API key is missing', 'reportedip-hive' ); ?></strong><br>
						<?php esc_html_e( 'Community mode is active, but no API key is configured. Without a key, neither reports can be sent nor quota/tier can be queried.', 'reportedip-hive' ); ?>
						<br><br>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=reportedip-hive-settings&tab=general' ) ); ?>" class="rip-button rip-button--primary">
							<?php esc_html_e( 'Add API key', 'reportedip-hive' ); ?>
						</a>
						<a href="<?php echo esc_url( REPORTEDIP_HIVE_REGISTER_URL ); ?>" target="_blank" rel="noopener" class="rip-button rip-button--secondary">
							<?php esc_html_e( 'Create account', 'reportedip-hive' ); ?>
						</a>
					</div>
				<?php endif; ?>

				<!-- Current Status -->
				<div class="rip-card rip-mb-6">
					<div class="rip-card__header">
						<h2 class="rip-card__title">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
								<path d="M12 2L2 7l10 5 10-5-10-5z"/>
								<path d="M2 17l10 5 10-5"/>
								<path d="M2 12l10 5 10-5"/>
							</svg>
							<?php esc_html_e( 'Your current status', 'reportedip-hive' ); ?>
						</h2>
						<?php if ( $is_community_mode && $is_configured ) : ?>
							<a href="<?php echo esc_url( $refresh_url ); ?>" class="rip-button rip-button--ghost rip-button--sm" title="<?php esc_attr_e( 'Refresh status now', 'reportedip-hive' ); ?>">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
									<polyline points="23 4 23 10 17 10"/>
									<polyline points="1 20 1 14 7 14"/>
									<path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
								</svg>
								<?php esc_html_e( 'Refresh', 'reportedip-hive' ); ?>
							</a>
						<?php endif; ?>
					</div>
					<div class="rip-card__body">
						<?php if ( $is_community_mode && $is_configured && ! $has_quota ) : ?>
							<div class="rip-alert rip-alert--warning">
								<?php esc_html_e( 'The status could not be fetched from the service right now. Please check your API key and internet connection, then try again.', 'reportedip-hive' ); ?>
							</div>
						<?php else : ?>
							<div class="rip-stat-cards">
								<!-- Tier Card -->
								<div class="rip-stat-card">
									<div class="rip-stat-card__icon rip-stat-card__icon--info">
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<path d="M12 15l-2-2m0 0l-2-2m2 2l2-2m-2 2v6"/>
											<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
											<circle cx="12" cy="7" r="4"/>
										</svg>
									</div>
									<div class="rip-stat-card__content">
										<div class="rip-stat-card__value"><?php echo esc_html( $tier['label'] ); ?></div>
										<div class="rip-stat-card__label">
											<?php
											if ( $is_honeypot ) {
												esc_html_e( 'Honeypot-Tier (unbegrenzt)', 'reportedip-hive' );
											} else {
												esc_html_e( 'API Tier', 'reportedip-hive' );
											}
											?>
										</div>
									</div>
								</div>

								<!-- Daily Reports Card -->
								<div class="rip-stat-card">
									<div class="rip-stat-card__icon <?php echo ( $daily_limit < 0 || $remaining_reports > 0 ) ? 'rip-stat-card__icon--success' : 'rip-stat-card__icon--warning'; ?>">
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
											<polyline points="14 2 14 8 20 8"/>
										</svg>
									</div>
									<div class="rip-stat-card__content">
										<div class="rip-stat-card__value">
											<?php
											if ( $daily_limit < 0 ) {
												echo esc_html__( '∞', 'reportedip-hive' );
											} else {
												echo esc_html( $remaining_display . ' / ' . $daily_limit_display );
											}
											?>
										</div>
										<div class="rip-stat-card__label"><?php esc_html_e( 'Reports available today', 'reportedip-hive' ); ?></div>
									</div>
								</div>

								<!-- Queue Card -->
								<div class="rip-stat-card">
									<div class="rip-stat-card__icon <?php echo $queue_size > 50 ? 'rip-stat-card__icon--warning' : 'rip-stat-card__icon--success'; ?>">
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<line x1="8" y1="6" x2="21" y2="6"/>
											<line x1="8" y1="12" x2="21" y2="12"/>
											<line x1="8" y1="18" x2="21" y2="18"/>
											<line x1="3" y1="6" x2="3.01" y2="6"/>
											<line x1="3" y1="12" x2="3.01" y2="12"/>
											<line x1="3" y1="18" x2="3.01" y2="18"/>
										</svg>
									</div>
									<div class="rip-stat-card__content">
										<div class="rip-stat-card__value"><?php echo esc_html( number_format_i18n( $queue_size ) ); ?></div>
										<div class="rip-stat-card__label"><?php esc_html_e( 'Reports in queue', 'reportedip-hive' ); ?></div>
									</div>
								</div>

								<!-- Queue Age Card -->
								<div class="rip-stat-card">
									<div class="rip-stat-card__icon <?php echo ( isset( $queue_summary['age_days'] ) && $queue_summary['age_days'] > 3 ) ? 'rip-stat-card__icon--warning' : 'rip-stat-card__icon--info'; ?>">
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<circle cx="12" cy="12" r="10"/>
											<polyline points="12 6 12 12 16 14"/>
										</svg>
									</div>
									<div class="rip-stat-card__content">
										<div class="rip-stat-card__value">
											<?php
											if ( isset( $queue_summary['age_days'] ) && $queue_summary['age_days'] !== null ) {
												echo esc_html( sprintf( /* translators: %d: number of days */ _n( '%d day', '%d days', (int) $queue_summary['age_days'], 'reportedip-hive' ), (int) $queue_summary['age_days'] ) );
											} else {
												echo '—';
											}
											?>
										</div>
										<div class="rip-stat-card__label"><?php esc_html_e( 'Oldest report', 'reportedip-hive' ); ?></div>
									</div>
								</div>
							</div>

							<?php if ( ! empty( $quota_status['exhausted'] ) ) : ?>
								<div class="rip-alert rip-alert--warning rip-mt-4">
									<strong><?php esc_html_e( 'Notice:', 'reportedip-hive' ); ?></strong>
									<?php echo esc_html( $quota_status['message'] ); ?>
									<?php if ( $reset_formatted ) : ?>
										<br>
										<small>
											<?php
											echo esc_html(
												sprintf(
													/* translators: %s: reset date/time */
													__( 'Reset: %s', 'reportedip-hive' ),
													$reset_formatted
												)
											);
											?>
										</small>
									<?php endif; ?>
								</div>
							<?php endif; ?>

							<?php if ( $queue_size > 0 && $daily_limit > 0 && $days_to_clear > 1 ) : ?>
								<div class="rip-alert rip-alert--info rip-mt-4">
									<?php
									echo esc_html(
										sprintf(
											/* translators: %d: days to clear queue */
											__( 'At current quota, the queue will clear in about %d days.', 'reportedip-hive' ),
											$days_to_clear
										)
									);
									?>
								</div>
							<?php endif; ?>
						<?php endif; ?>
					</div>
				</div>

				<!-- Upgrade Options -->
				<div class="rip-card rip-mb-6">
					<div class="rip-card__header">
						<h2 class="rip-card__title">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
								<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
							</svg>
							<?php esc_html_e( 'Tier overview', 'reportedip-hive' ); ?>
						</h2>
					</div>
					<div class="rip-card__body">
						<?php
						$active_slug = $tier['slug'];
						$plans       = array_filter(
							$this->get_tier_definitions(),
							static function ( $plan ) {
								return ! empty( $plan['in_pricing'] );
							}
						);
						$unlimited   = __( 'Unlimited', 'reportedip-hive' );
						?>
						<div class="rip-pricing-grid">
							<?php foreach ( $plans as $slug => $plan ) : ?>
								<?php
								$is_active   = ( $active_slug === $slug );
								$reports_txt = $plan['reports_day'] < 0 ? $unlimited : number_format_i18n( $plan['reports_day'] );
								$checks_txt  = $plan['checks_day'] < 0 ? $unlimited : number_format_i18n( $plan['checks_day'] );
								?>
								<div class="rip-pricing-card <?php echo $is_active ? 'rip-pricing-card--active' : ''; ?>">
									<?php if ( $is_active ) : ?>
										<span class="rip-pricing-card__badge"><?php esc_html_e( 'Current tier', 'reportedip-hive' ); ?></span>
									<?php endif; ?>
									<h3 class="rip-pricing-card__title"><?php echo esc_html( $plan['label'] ); ?></h3>
									<p class="rip-pricing-card__price">
										<?php echo esc_html( $reports_txt ); ?>
										<small><?php esc_html_e( 'Reports/day', 'reportedip-hive' ); ?></small>
									</p>
									<p class="rip-pricing-card__subprice">
										<?php
										echo esc_html(
											sprintf(
												/* translators: %s: number of API checks */
												__( '%s API checks/day', 'reportedip-hive' ),
												$checks_txt
											)
										);
										?>
									</p>
									<ul class="rip-pricing-card__features">
										<?php foreach ( $plan['features'] as $feature ) : ?>
											<li><?php echo esc_html( $feature ); ?></li>
										<?php endforeach; ?>
									</ul>
									<?php if ( $is_active ) : ?>
										<span class="rip-button rip-button--secondary rip-button--full-width rip-button--disabled">
											<?php esc_html_e( 'Current plan', 'reportedip-hive' ); ?>
										</span>
									<?php elseif ( 'contact' === $plan['cta_type'] ) : ?>
										<a href="<?php echo esc_url( $contact_url ); ?>" class="rip-button rip-button--primary rip-button--full-width">
											<?php esc_html_e( 'Kontakt aufnehmen', 'reportedip-hive' ); ?>
										</a>
									<?php else : ?>
										<a href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener" class="rip-button rip-button--primary rip-button--full-width">
											<?php esc_html_e( 'Upgrade', 'reportedip-hive' ); ?>
										</a>
									<?php endif; ?>
								</div>
							<?php endforeach; ?>
						</div>

						<?php if ( $is_honeypot ) : ?>
							<div class="rip-alert rip-alert--success rip-mt-4">
								<strong><?php esc_html_e( 'Honeypot status detected', 'reportedip-hive' ); ?></strong> —
								<?php esc_html_e( 'Your key has honeypot privileges: unlimited reports, unlimited API checks, higher weighting.', 'reportedip-hive' ); ?>
							</div>
						<?php endif; ?>
					</div>
				</div>

				<!-- Honeypot Program -->
				<div class="rip-highlight-card rip-mb-6">
					<h2 class="rip-highlight-card__title">
						<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
							<path d="M12 2a10 10 0 0 1 10 10c0 5.52-4.48 10-10 10S2 17.52 2 12 6.48 2 12 2z"/>
							<path d="M12 6v6l4 2"/>
						</svg>
						<?php esc_html_e( 'Honeypot program (free!)', 'reportedip-hive' ); ?>
					</h2>

					<p>
						<?php esc_html_e( 'Running a honeypot server? Join our honeypot network and enjoy special benefits:', 'reportedip-hive' ); ?>
					</p>

					<ul>
						<li><strong><?php esc_html_e( 'Unlimited reports', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'No daily limits', 'reportedip-hive' ); ?></li>
						<li><strong><?php esc_html_e( 'Higher weighting', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Your reports count more', 'reportedip-hive' ); ?></li>
						<li><strong><?php esc_html_e( 'Special API keys', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Optimised for automated systems', 'reportedip-hive' ); ?></li>
						<li><strong><?php esc_html_e( 'Community recognition', 'reportedip-hive' ); ?></strong> — <?php esc_html_e( 'Visible as an active contributor', 'reportedip-hive' ); ?></li>
					</ul>

					<a href="<?php echo esc_url( $honeypot_url ); ?>" target="_blank" rel="noopener" class="rip-button rip-button--primary rip-mt-3">
						<?php esc_html_e( 'Learn more about the honeypot program', 'reportedip-hive' ); ?>
					</a>
				</div>

				<!-- Activity Summary -->
				<div class="rip-card">
					<div class="rip-card__header">
						<h2 class="rip-card__title">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
								<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
							</svg>
							<?php esc_html_e( 'Your activity (last 30 days)', 'reportedip-hive' ); ?>
						</h2>
					</div>
					<div class="rip-card__body">
						<?php
						$total_events      = (int) ( $security_summary['summary']->total_failed_logins ?? 0 );
						$total_events     += (int) ( $security_summary['summary']->total_comment_spam ?? 0 );
						$total_events     += (int) ( $security_summary['summary']->total_xmlrpc_calls ?? 0 );
						$total_blocked     = (int) ( $security_summary['summary']->total_blocked_ips ?? 0 );
						$total_api_reports = (int) ( $security_summary['summary']->total_api_reports ?? 0 );
						?>

						<div class="rip-activity-stats">
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--danger"><?php echo esc_html( number_format_i18n( $total_events ) ); ?></div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'Security events', 'reportedip-hive' ); ?></div>
							</div>
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--warning"><?php echo esc_html( number_format_i18n( $total_blocked ) ); ?></div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'IPs blocked', 'reportedip-hive' ); ?></div>
							</div>
							<div class="rip-activity-stat">
								<div class="rip-activity-stat__value rip-activity-stat__value--success"><?php echo esc_html( number_format_i18n( $total_api_reports ) ); ?></div>
								<div class="rip-activity-stat__label"><?php esc_html_e( 'Reported to community', 'reportedip-hive' ); ?></div>
							</div>
						</div>

						<?php if ( $total_events > 0 && $total_api_reports === 0 && 'free' === $tier['slug'] ) : ?>
							<div class="rip-alert rip-alert--info rip-mt-4">
								<strong><?php esc_html_e( 'Recommendation:', 'reportedip-hive' ); ?></strong>
								<?php
								echo esc_html(
									sprintf(
										/* translators: %d: number of events */
										__( 'You have detected %d security events but have not reported anything to the community yet. A Contributor upgrade lets you share up to 200 reports per day and strengthens threat intelligence for everyone.', 'reportedip-hive' ),
										$total_events
									)
								);
								?>
								<br><br>
								<a href="<?php echo esc_url( $upgrade_url ); ?>" target="_blank" rel="noopener" class="rip-button rip-button--primary rip-button--sm">
									<?php esc_html_e( 'Upgrade now', 'reportedip-hive' ); ?>
								</a>
							</div>
						<?php endif; ?>
					</div>
				</div>

				<?php endif; ?>

				<?php if ( 'promote' === $subtab ) : ?>
					<?php $this->render_promote_tab(); ?>
				<?php endif; ?>

			</div>

		<?php $this->render_page_footer(); ?>
		<?php
	}

	/**
	 * Render the "Promote" sub-tab inside the Community page.
	 *
	 * Surfaces the auto-footer toggle plus copy-to-clipboard previews for the
	 * four public shortcodes that drive backlinks to reportedip.de.
	 *
	 * @since 1.3.0
	 */
	private function render_promote_tab() {
		$auto_enabled = (bool) get_option( 'reportedip_hive_auto_footer_enabled', false );
		$auto_variant = ReportedIP_Hive_Frontend_Shortcodes::sanitize_footer_variant( get_option( 'reportedip_hive_auto_footer_variant', 'badge' ) );
		$auto_align   = $this->sanitize_auto_footer_align( get_option( 'reportedip_hive_auto_footer_align', 'center' ) );

		$shortcodes = ReportedIP_Hive_Frontend_Shortcodes::get_instance();

		$showcase = array(
			array(
				'variant'   => 'badge',
				'title'     => __( 'Footer Badge', 'reportedip-hive' ),
				'desc'      => __( 'Compact "Protected by ReportedIP Hive" badge — fits any footer or sidebar.', 'reportedip-hive' ),
				'shortcode' => '[reportedip_badge]',
				'args'      => array(),
			),
			array(
				'variant'   => 'stat',
				'title'     => __( 'Stat Card — All-Time', 'reportedip-hive' ),
				'desc'      => __( 'Cumulative threat count since installation — animates up on first scroll into view, with a live indicator dot.', 'reportedip-hive' ),
				'shortcode' => '[reportedip_stat type="attacks_total" tone="trust"]',
				'args'      => array(
					'type' => 'attacks_total',
					'tone' => 'trust',
				),
			),
			array(
				'variant'   => 'banner',
				'title'     => __( 'Community Banner', 'reportedip-hive' ),
				'desc'      => __( 'Wider banner that pitches community participation — perfect for landing pages or "About" sections.', 'reportedip-hive' ),
				'shortcode' => '[reportedip_banner type="reports_total" tone="community"]',
				'args'      => array(
					'type' => 'reports_total',
					'tone' => 'community',
				),
			),
			array(
				'variant'   => 'shield',
				'title'     => __( 'Shield Icon', 'reportedip-hive' ),
				'desc'      => __( 'Discreet icon-only shield — pair with a footer line or a fixed corner widget.', 'reportedip-hive' ),
				'shortcode' => '[reportedip_shield]',
				'args'      => array(),
			),
		);

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- WordPress sets `settings-updated` on its own redirect after the Settings API form save; not user-mutable.
		if ( isset( $_GET['settings-updated'] ) ) :
			?>
			<div class="rip-alert rip-alert--success rip-mb-6">
				<?php esc_html_e( 'Settings saved.', 'reportedip-hive' ); ?>
			</div>
			<?php
		endif;
		?>

		<div class="rip-card rip-mb-6">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>
					<?php esc_html_e( 'Help grow the ReportedIP community', 'reportedip-hive' ); ?>
				</h2>
			</div>
			<div class="rip-card__body">
				<p>
					<?php esc_html_e( 'Add a small badge to your site that links back to ReportedIP. Every link strengthens the community network and helps more sites stay protected.', 'reportedip-hive' ); ?>
				</p>
				<p style="color:var(--rip-gray-600);">
					<?php esc_html_e( 'Banners render inside Shadow DOM, so your theme cannot override the design. The link itself stays in regular HTML — search engines will find it and credit your site.', 'reportedip-hive' ); ?>
				</p>
			</div>
		</div>

		<div class="rip-card rip-mb-6">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
					<?php esc_html_e( 'Auto-footer badge', 'reportedip-hive' ); ?>
				</h2>
			</div>
			<div class="rip-card__body">
				<form method="post" action="options.php">
					<?php settings_fields( 'reportedip_hive_promote' ); ?>
					<input type="hidden" name="_wp_http_referer" value="<?php echo esc_attr( admin_url( 'admin.php?page=reportedip-hive-community&subtab=promote' ) ); ?>">

					<p style="margin-top:0;">
						<label style="display:flex;align-items:center;gap:.5em;cursor:pointer;">
							<input type="checkbox" name="reportedip_hive_auto_footer_enabled" value="1" <?php checked( $auto_enabled ); ?>>
							<strong><?php esc_html_e( 'Show a "Protected by ReportedIP Hive" badge in the site footer', 'reportedip-hive' ); ?></strong>
						</label>
						<span style="display:block;margin-left:1.65em;color:var(--rip-gray-600);font-size:.9em;">
							<?php esc_html_e( 'Renders automatically at the bottom of every front-end page. No shortcode placement needed.', 'reportedip-hive' ); ?>
						</span>
					</p>

					<fieldset style="margin-top:1.25em;">
						<legend style="font-weight:600;margin-bottom:.5em;"><?php esc_html_e( 'Variant', 'reportedip-hive' ); ?></legend>
						<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1.5em;">
							<input type="radio" name="reportedip_hive_auto_footer_variant" value="badge" <?php checked( $auto_variant, 'badge' ); ?>>
							<?php esc_html_e( 'Footer badge', 'reportedip-hive' ); ?>
						</label>
						<label style="display:inline-flex;align-items:center;gap:.4em;">
							<input type="radio" name="reportedip_hive_auto_footer_variant" value="shield" <?php checked( $auto_variant, 'shield' ); ?>>
							<?php esc_html_e( 'Shield icon', 'reportedip-hive' ); ?>
						</label>
					</fieldset>

					<fieldset style="margin-top:1.25em;">
						<legend style="font-weight:600;margin-bottom:.5em;"><?php esc_html_e( 'Position', 'reportedip-hive' ); ?></legend>
						<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1.5em;">
							<input type="radio" name="reportedip_hive_auto_footer_align" value="left" <?php checked( $auto_align, 'left' ); ?>>
							<?php esc_html_e( 'Left', 'reportedip-hive' ); ?>
						</label>
						<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1.5em;">
							<input type="radio" name="reportedip_hive_auto_footer_align" value="center" <?php checked( $auto_align, 'center' ); ?>>
							<?php esc_html_e( 'Center', 'reportedip-hive' ); ?>
						</label>
						<label style="display:inline-flex;align-items:center;gap:.4em;">
							<input type="radio" name="reportedip_hive_auto_footer_align" value="right" <?php checked( $auto_align, 'right' ); ?>>
							<?php esc_html_e( 'Right', 'reportedip-hive' ); ?>
						</label>
					</fieldset>

					<p style="margin-top:1.5em;">
						<button type="submit" class="rip-button rip-button--primary"><?php esc_html_e( 'Save', 'reportedip-hive' ); ?></button>
					</p>
				</form>
			</div>
		</div>

		<div class="rip-card">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
					<?php esc_html_e( 'Manual shortcodes', 'reportedip-hive' ); ?>
				</h2>
			</div>
			<div class="rip-card__body">
				<p style="margin-top:0;">
					<?php esc_html_e( 'Drop any of these shortcodes into a post, page, widget, or theme template. Each one renders a self-contained banner that links back to reportedip.de with UTM tracking.', 'reportedip-hive' ); ?>
				</p>

				<div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(280px, 1fr));gap:1.25em;margin-top:1.25em;">
					<?php foreach ( $showcase as $info ) : ?>
						<div style="border:1px solid var(--rip-gray-200);border-radius:var(--rip-radius-lg);padding:1.25em;background:var(--rip-gray-50);">
							<h3 style="margin-top:0;margin-bottom:.5em;font-size:1em;"><?php echo esc_html( $info['title'] ); ?></h3>
							<p style="color:var(--rip-gray-600);font-size:.9em;margin-top:0;margin-bottom:1em;"><?php echo esc_html( $info['desc'] ); ?></p>
							<div style="background:#fff;border:1px dashed var(--rip-gray-300);border-radius:var(--rip-radius-md);padding:1em;margin-bottom:1em;min-height:80px;display:flex;align-items:center;justify-content:center;">
								<?php
								echo $shortcodes->build_element( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- build_element() escapes its own attributes; the custom-element wrapper would be stripped by wp_kses.
									$info['variant'],
									array_merge(
										array(
											'utm_medium' => 'admin-preview',
											'theme'      => 'dark',
											'align'      => 'center',
										),
										$info['args']
									)
								);
								?>
							</div>
							<div style="display:flex;gap:.5em;align-items:center;">
								<code style="flex:1;background:#fff;padding:.5em .75em;border-radius:var(--rip-radius-sm);font-size:.85em;border:1px solid var(--rip-gray-200);overflow-x:auto;white-space:nowrap;"><?php echo esc_html( $info['shortcode'] ); ?></code>
								<button type="button" class="rip-button rip-button--secondary rip-button--sm rip-copy-shortcode" data-shortcode="<?php echo esc_attr( $info['shortcode'] ); ?>"><?php esc_html_e( 'Copy', 'reportedip-hive' ); ?></button>
							</div>
						</div>
					<?php endforeach; ?>
				</div>

				<details style="margin-top:1.5em;">
					<summary style="cursor:pointer;font-weight:600;color:var(--rip-gray-700);"><?php esc_html_e( 'All available attributes', 'reportedip-hive' ); ?></summary>
					<div style="margin-top:1em;color:var(--rip-gray-600);font-size:.9em;line-height:1.6;">
						<p><strong><?php esc_html_e( 'type', 'reportedip-hive' ); ?></strong> — <code>attacks_total</code> (lifetime), <code>attacks_30d</code>, <code>reports_total</code>, <code>api_reports_30d</code>, <code>blocked_active</code>, <code>whitelist_active</code>, <code>logins_30d</code>, <code>spam_30d</code></p>
						<p><strong><?php esc_html_e( 'tone', 'reportedip-hive' ); ?></strong> — <code>protect</code> (default), <code>trust</code> (<em>"Secured by…"</em>), <code>community</code> (<em>"Part of the ReportedIP Hive"</em>), <code>contributor</code> (<em>"ReportedIP Contributor"</em>)</p>
						<p><strong><?php esc_html_e( 'bg', 'reportedip-hive' ); ?></strong> — Hex colour <code>#RRGGBB</code> or two stops for a gradient: <code>#FF6B00,#FFB800</code></p>
						<p><strong><?php esc_html_e( 'color', 'reportedip-hive' ); ?></strong> — Foreground hex colour</p>
						<p><strong><?php esc_html_e( 'border', 'reportedip-hive' ); ?></strong> — Hex colour or <code>none</code> (default)</p>
						<p><strong><?php esc_html_e( 'intro', 'reportedip-hive' ); ?></strong> — Override the headline text (max 80 chars)</p>
						<p><strong><?php esc_html_e( 'label', 'reportedip-hive' ); ?></strong> — Override the metric label / noun (max 80 chars)</p>
						<p><strong><?php esc_html_e( 'live', 'reportedip-hive' ); ?></strong> — <code>true</code> (default) shows a pulsing live dot, <code>false</code> hides it</p>
						<p><strong><?php esc_html_e( 'theme', 'reportedip-hive' ); ?></strong> — <code>dark</code> (default Indigo) or <code>light</code> (white card)</p>
						<p><strong><?php esc_html_e( 'align', 'reportedip-hive' ); ?></strong> — <code>left</code>, <code>center</code>, <code>right</code></p>
					</div>
				</details>
			</div>
		</div>

		<?php
		$customizer_payload = array(
			'tones'        => ReportedIP_Hive_Frontend_Shortcodes::tone_definitions(),
			'sampleValues' => $shortcodes->get_cached_stats(),
			'statLabels'   => array(
				'attacks_total'    => array(
					'label'    => __( 'attacks blocked', 'reportedip-hive' ),
					'fallback' => __( 'Active threat protection', 'reportedip-hive' ),
				),
				'attacks_30d'      => array(
					'label'    => __( 'attacks blocked (30 days)', 'reportedip-hive' ),
					'fallback' => __( 'Active threat protection', 'reportedip-hive' ),
				),
				'blocked_active'   => array(
					'label'    => __( 'IPs currently blocked', 'reportedip-hive' ),
					'fallback' => __( 'Active IP protection', 'reportedip-hive' ),
				),
				'whitelist_active' => array(
					'label'    => __( 'Trusted IPs', 'reportedip-hive' ),
					'fallback' => __( 'Trust-aware filtering', 'reportedip-hive' ),
				),
				'logins_30d'       => array(
					'label'    => __( 'Failed logins blocked (30 days)', 'reportedip-hive' ),
					'fallback' => __( 'Brute-force protection', 'reportedip-hive' ),
				),
				'spam_30d'         => array(
					'label'    => __( 'Spam comments stopped (30 days)', 'reportedip-hive' ),
					'fallback' => __( 'Comment spam protection', 'reportedip-hive' ),
				),
				'api_reports_30d'  => array(
					'label'    => __( 'reports shared this month', 'reportedip-hive' ),
					'fallback' => __( 'Community contributor', 'reportedip-hive' ),
				),
				'reports_total'    => array(
					'label'    => __( 'IPs reported to the community', 'reportedip-hive' ),
					'fallback' => __( 'Active community member', 'reportedip-hive' ),
				),
			),
			'variantTones' => array(
				'badge'  => 'protect',
				'stat'   => 'trust',
				'banner' => 'community',
				'shield' => 'protect',
			),
			'siteUrl'      => defined( 'REPORTEDIP_HIVE_SITE_URL' ) ? REPORTEDIP_HIVE_SITE_URL : 'https://reportedip.de',
		);
		?>

		<div class="rip-card rip-mt-6">
			<div class="rip-card__header">
				<h2 class="rip-card__title">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 1 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
					<?php esc_html_e( 'Build your own banner', 'reportedip-hive' ); ?>
				</h2>
			</div>
			<div class="rip-card__body">
				<p style="margin-top:0;color:var(--rip-gray-600);">
					<?php esc_html_e( 'Configure every attribute. The preview updates as you change values, and the matching shortcode is generated on the right — just copy it into your post or template.', 'reportedip-hive' ); ?>
				</p>

				<div id="rip-customizer" style="display:grid;grid-template-columns:minmax(0, 1fr) minmax(0, 1fr);gap:1.5em;margin-top:1em;">
					<div>
						<div class="rip-form-group">
							<label class="rip-label" for="rip-cust-variant"><?php esc_html_e( 'Variant', 'reportedip-hive' ); ?></label>
							<select id="rip-cust-variant" class="rip-input">
								<option value="badge"><?php esc_html_e( 'Badge — compact pill', 'reportedip-hive' ); ?></option>
								<option value="stat"><?php esc_html_e( 'Stat — single big number', 'reportedip-hive' ); ?></option>
								<option value="banner" selected><?php esc_html_e( 'Banner — full marketing block', 'reportedip-hive' ); ?></option>
								<option value="shield"><?php esc_html_e( 'Shield — icon only', 'reportedip-hive' ); ?></option>
							</select>
						</div>

						<div class="rip-form-group rip-mt-3">
							<label class="rip-label" for="rip-cust-type"><?php esc_html_e( 'Stat type', 'reportedip-hive' ); ?></label>
							<select id="rip-cust-type" class="rip-input">
								<option value="attacks_total" selected><?php esc_html_e( 'attacks_total — Lifetime attacks', 'reportedip-hive' ); ?></option>
								<option value="attacks_30d"><?php esc_html_e( 'attacks_30d — Last 30 days', 'reportedip-hive' ); ?></option>
								<option value="reports_total"><?php esc_html_e( 'reports_total — Lifetime reports', 'reportedip-hive' ); ?></option>
								<option value="api_reports_30d"><?php esc_html_e( 'api_reports_30d — Reports this month', 'reportedip-hive' ); ?></option>
								<option value="blocked_active"><?php esc_html_e( 'blocked_active — Currently blocked', 'reportedip-hive' ); ?></option>
								<option value="whitelist_active"><?php esc_html_e( 'whitelist_active — Trusted IPs', 'reportedip-hive' ); ?></option>
								<option value="logins_30d"><?php esc_html_e( 'logins_30d — Failed logins (30 days)', 'reportedip-hive' ); ?></option>
								<option value="spam_30d"><?php esc_html_e( 'spam_30d — Spam (30 days)', 'reportedip-hive' ); ?></option>
							</select>
						</div>

						<div class="rip-form-group rip-mt-3">
							<label class="rip-label" for="rip-cust-tone"><?php esc_html_e( 'Tone', 'reportedip-hive' ); ?></label>
							<select id="rip-cust-tone" class="rip-input">
								<option value="protect"><?php esc_html_e( 'protect — "Protected by ReportedIP Hive"', 'reportedip-hive' ); ?></option>
								<option value="trust"><?php esc_html_e( 'trust — "Secured by ReportedIP Hive"', 'reportedip-hive' ); ?></option>
								<option value="community" selected><?php esc_html_e( 'community — "Part of the ReportedIP Hive"', 'reportedip-hive' ); ?></option>
								<option value="contributor"><?php esc_html_e( 'contributor — "ReportedIP Contributor"', 'reportedip-hive' ); ?></option>
							</select>
						</div>

						<fieldset style="margin-top:1em;">
							<legend style="font-weight:600;font-size:.9em;margin-bottom:.4em;color:var(--rip-gray-700);"><?php esc_html_e( 'Theme', 'reportedip-hive' ); ?></legend>
							<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1.25em;">
								<input type="radio" name="rip-cust-theme" value="dark" checked> <?php esc_html_e( 'Dark', 'reportedip-hive' ); ?>
							</label>
							<label style="display:inline-flex;align-items:center;gap:.4em;">
								<input type="radio" name="rip-cust-theme" value="light"> <?php esc_html_e( 'Light', 'reportedip-hive' ); ?>
							</label>
						</fieldset>

						<fieldset style="margin-top:1em;">
							<legend style="font-weight:600;font-size:.9em;margin-bottom:.4em;color:var(--rip-gray-700);"><?php esc_html_e( 'Alignment', 'reportedip-hive' ); ?></legend>
							<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1em;">
								<input type="radio" name="rip-cust-align" value="left"> <?php esc_html_e( 'Left', 'reportedip-hive' ); ?>
							</label>
							<label style="display:inline-flex;align-items:center;gap:.4em;margin-right:1em;">
								<input type="radio" name="rip-cust-align" value="center" checked> <?php esc_html_e( 'Center', 'reportedip-hive' ); ?>
							</label>
							<label style="display:inline-flex;align-items:center;gap:.4em;">
								<input type="radio" name="rip-cust-align" value="right"> <?php esc_html_e( 'Right', 'reportedip-hive' ); ?>
							</label>
						</fieldset>

						<div class="rip-form-group rip-mt-3" style="display:grid;grid-template-columns:1fr 1fr;gap:.75em;">
							<div>
								<label class="rip-label" for="rip-cust-bg1" style="display:flex;align-items:center;justify-content:space-between;gap:.4em;">
									<span><?php esc_html_e( 'Background', 'reportedip-hive' ); ?></span>
									<button type="button" class="rip-cust-clear" data-target="rip-cust-bg1" style="background:none;border:none;color:var(--rip-gray-500);cursor:pointer;font-size:.8em;text-decoration:underline;"><?php esc_html_e( 'reset', 'reportedip-hive' ); ?></button>
								</label>
								<input type="color" id="rip-cust-bg1" class="rip-input" value="#4F46E5" data-empty="1" style="height:38px;padding:2px;">
							</div>
							<div>
								<label class="rip-label" for="rip-cust-bg2" style="display:flex;align-items:center;justify-content:space-between;gap:.4em;">
									<span><?php esc_html_e( 'Gradient stop', 'reportedip-hive' ); ?></span>
									<button type="button" class="rip-cust-clear" data-target="rip-cust-bg2" style="background:none;border:none;color:var(--rip-gray-500);cursor:pointer;font-size:.8em;text-decoration:underline;"><?php esc_html_e( 'reset', 'reportedip-hive' ); ?></button>
								</label>
								<input type="color" id="rip-cust-bg2" class="rip-input" value="#7C3AED" data-empty="1" style="height:38px;padding:2px;">
							</div>
						</div>

						<div class="rip-form-group rip-mt-3" style="display:grid;grid-template-columns:1fr 1fr;gap:.75em;">
							<div>
								<label class="rip-label" for="rip-cust-color" style="display:flex;align-items:center;justify-content:space-between;gap:.4em;">
									<span><?php esc_html_e( 'Foreground', 'reportedip-hive' ); ?></span>
									<button type="button" class="rip-cust-clear" data-target="rip-cust-color" style="background:none;border:none;color:var(--rip-gray-500);cursor:pointer;font-size:.8em;text-decoration:underline;"><?php esc_html_e( 'reset', 'reportedip-hive' ); ?></button>
								</label>
								<input type="color" id="rip-cust-color" class="rip-input" value="#ffffff" data-empty="1" style="height:38px;padding:2px;">
							</div>
							<div>
								<label class="rip-label" for="rip-cust-border" style="display:flex;align-items:center;justify-content:space-between;gap:.4em;">
									<span><?php esc_html_e( 'Border', 'reportedip-hive' ); ?></span>
									<button type="button" class="rip-cust-clear" data-target="rip-cust-border" style="background:none;border:none;color:var(--rip-gray-500);cursor:pointer;font-size:.8em;text-decoration:underline;"><?php esc_html_e( 'reset', 'reportedip-hive' ); ?></button>
								</label>
								<input type="color" id="rip-cust-border" class="rip-input" value="#ffffff" data-empty="1" style="height:38px;padding:2px;">
							</div>
						</div>

						<div class="rip-form-group rip-mt-3">
							<label class="rip-label" for="rip-cust-intro"><?php esc_html_e( 'Intro override', 'reportedip-hive' ); ?></label>
							<input type="text" id="rip-cust-intro" class="rip-input" maxlength="80" placeholder="<?php esc_attr_e( 'Leave empty to use tone default', 'reportedip-hive' ); ?>">
						</div>

						<div class="rip-form-group rip-mt-3">
							<label class="rip-label" for="rip-cust-label"><?php esc_html_e( 'Label override', 'reportedip-hive' ); ?></label>
							<input type="text" id="rip-cust-label" class="rip-input" maxlength="80" placeholder="<?php esc_attr_e( 'Leave empty to use tone default', 'reportedip-hive' ); ?>">
						</div>

						<label class="rip-mt-3" style="display:inline-flex;align-items:center;gap:.5em;cursor:pointer;">
							<input type="checkbox" id="rip-cust-live" checked>
							<?php esc_html_e( 'Show pulsing live indicator', 'reportedip-hive' ); ?>
						</label>
					</div>

					<div>
						<div id="rip-cust-preview" style="background:var(--rip-gray-50);border:1px dashed var(--rip-gray-300);border-radius:var(--rip-radius-lg);padding:2em 1em;min-height:140px;display:flex;align-items:center;justify-content:center;"></div>

						<div style="margin-top:1em;">
							<label class="rip-label" style="font-weight:600;"><?php esc_html_e( 'Generated shortcode', 'reportedip-hive' ); ?></label>
							<div style="display:flex;gap:.5em;align-items:stretch;margin-top:.4em;">
								<code id="rip-cust-shortcode" style="flex:1;background:#fff;padding:.6em .8em;border-radius:var(--rip-radius-sm);font-size:.85em;border:1px solid var(--rip-gray-200);overflow-x:auto;white-space:nowrap;line-height:1.4;">[reportedip_banner]</code>
								<button type="button" id="rip-cust-copy" class="rip-button rip-button--primary rip-button--sm"><?php esc_html_e( 'Copy', 'reportedip-hive' ); ?></button>
							</div>
						</div>

						<p style="margin-top:1em;font-size:.85em;color:var(--rip-gray-600);">
							<?php esc_html_e( 'Drop the shortcode into any post, page, widget, or template. The banner will render with these exact settings.', 'reportedip-hive' ); ?>
						</p>
					</div>
				</div>
			</div>
		</div>

		<script>
		window.ripCustomizerData = <?php echo wp_json_encode( $customizer_payload ); ?>;
		(function(){
			document.querySelectorAll('.rip-copy-shortcode').forEach(function(btn){
				btn.addEventListener('click', function(){
					var sc = btn.getAttribute('data-shortcode') || '';
					copyToClipboard(sc, btn);
				});
			});

			function copyToClipboard(text, btn){
				var orig = btn.textContent;
				var done = function(){
					btn.textContent = '<?php echo esc_js( __( 'Copied!', 'reportedip-hive' ) ); ?>';
					setTimeout(function(){ btn.textContent = orig; }, 1400);
				};
				if (navigator.clipboard && navigator.clipboard.writeText) {
					navigator.clipboard.writeText(text).then(done, function(){
						window.prompt('<?php echo esc_js( __( 'Copy this shortcode:', 'reportedip-hive' ) ); ?>', text);
					});
				} else {
					window.prompt('<?php echo esc_js( __( 'Copy this shortcode:', 'reportedip-hive' ) ); ?>', text);
				}
			}

			var data = window.ripCustomizerData || {tones:{},sampleValues:{},statLabels:{},variantTones:{}};
			var $ = function(id){ return document.getElementById(id); };

			var preview = $('rip-cust-preview');
			var shortcodeEl = $('rip-cust-shortcode');
			var copyBtn = $('rip-cust-copy');
			if (!preview || !shortcodeEl) return;

			var formatNumber = function(n){
				try { return new Intl.NumberFormat().format(n); } catch(e) { return String(n); }
			};

			var attrEscape = function(s){
				return String(s).replace(/"/g, '\\"');
			};

			var readState = function(){
				var bg1El = $('rip-cust-bg1');
				var bg2El = $('rip-cust-bg2');
				var colorEl = $('rip-cust-color');
				var borderEl = $('rip-cust-border');
				return {
					variant: $('rip-cust-variant').value,
					type: $('rip-cust-type').value,
					tone: $('rip-cust-tone').value,
					theme: document.querySelector('input[name="rip-cust-theme"]:checked').value,
					align: document.querySelector('input[name="rip-cust-align"]:checked').value,
					bg1: bg1El.dataset.empty === '1' ? '' : bg1El.value,
					bg2: bg2El.dataset.empty === '1' ? '' : bg2El.value,
					color: colorEl.dataset.empty === '1' ? '' : colorEl.value,
					border: borderEl.dataset.empty === '1' ? '' : borderEl.value,
					intro: $('rip-cust-intro').value.trim(),
					label: $('rip-cust-label').value.trim(),
					live: $('rip-cust-live').checked
				};
			};

			var resolveBg = function(state){
				if (!state.bg1) return '';
				return state.bg2 ? state.bg1 + ',' + state.bg2 : state.bg1;
			};

			var resolveHeadlineNoun = function(state){
				var tone = data.tones[state.tone] || {headline:'Protected by ReportedIP Hive', noun:null};
				var stat = data.statLabels[state.type] || {label:'', fallback:'Active threat protection'};
				return {
					headline: state.intro || tone.headline,
					noun: state.label || (tone.noun !== null ? tone.noun : stat.label),
					fallback: stat.fallback
				};
			};

			var renderBanner = function(state){
				var hn = resolveHeadlineNoun(state);
				var sample = (data.sampleValues && data.sampleValues[state.type]) || 0;
				var hasValue = sample > 0;
				var metricText = hasValue ? formatNumber(sample) + ' ' + hn.noun : hn.fallback;
				var bg = resolveBg(state);

				var wrap = document.createElement('span');
				wrap.style.cssText = 'display:block;text-align:' + state.align + ';margin:0;';

				var banner = document.createElement('rip-hive-banner');
				banner.setAttribute('data-variant', state.variant);
				banner.setAttribute('data-tone', state.tone);
				banner.setAttribute('data-stat', state.type);
				banner.setAttribute('data-value', hasValue ? String(sample) : '');
				banner.setAttribute('data-headline', hn.headline);
				banner.setAttribute('data-noun', hn.noun);
				banner.setAttribute('data-metric-text', metricText);
				banner.setAttribute('data-mode', 'community');
				banner.setAttribute('data-theme', state.theme);
				banner.setAttribute('data-bg', bg);
				banner.setAttribute('data-color', state.color);
				banner.setAttribute('data-border', state.border);
				banner.setAttribute('data-live', state.live ? 'true' : 'false');
				banner.setAttribute('data-href', (data.siteUrl || 'https://reportedip.de') + '/?utm_source=hive&utm_medium=admin-customizer&utm_campaign=protected&utm_content=' + state.variant);

				var fallback = document.createElement('a');
				fallback.href = banner.getAttribute('data-href');
				fallback.rel = 'noopener';
				fallback.className = 'rip-hive-fallback-link';
				fallback.textContent = hn.headline + ' — ' + metricText;
				banner.appendChild(fallback);

				wrap.appendChild(banner);
				preview.replaceChildren(wrap);
			};

			var buildShortcode = function(state){
				var tag = 'reportedip_' + state.variant;
				var defaultTone = (data.variantTones && data.variantTones[state.variant]) || 'protect';
				var bg = resolveBg(state);
				var attrs = [];
				if (state.type !== 'attacks_total') attrs.push('type="' + state.type + '"');
				if (state.tone !== defaultTone) attrs.push('tone="' + state.tone + '"');
				if (state.theme !== 'dark') attrs.push('theme="' + state.theme + '"');
				if (state.align !== 'left') attrs.push('align="' + state.align + '"');
				if (bg) attrs.push('bg="' + bg + '"');
				if (state.color) attrs.push('color="' + state.color + '"');
				if (state.border) attrs.push('border="' + state.border + '"');
				if (state.intro) attrs.push('intro="' + attrEscape(state.intro) + '"');
				if (state.label) attrs.push('label="' + attrEscape(state.label) + '"');
				if (!state.live) attrs.push('live="false"');
				return attrs.length ? '[' + tag + ' ' + attrs.join(' ') + ']' : '[' + tag + ']';
			};

			var update = function(){
				var state = readState();
				renderBanner(state);
				shortcodeEl.textContent = buildShortcode(state);
			};

			var inputs = document.querySelectorAll('#rip-customizer input, #rip-customizer select');
			inputs.forEach(function(el){
				el.addEventListener('input', function(e){
					if (e.target && e.target.type === 'color') {
						e.target.dataset.empty = '0';
					}
					update();
				});
				el.addEventListener('change', update);
			});

			document.querySelectorAll('.rip-cust-clear').forEach(function(btn){
				btn.addEventListener('click', function(){
					var input = $(btn.getAttribute('data-target'));
					if (input) {
						input.dataset.empty = '1';
						update();
					}
				});
			});

			if (copyBtn) {
				copyBtn.addEventListener('click', function(){
					copyToClipboard(shortcodeEl.textContent, copyBtn);
				});
			}

			update();
		})();
		</script>
		<?php
	}
}
