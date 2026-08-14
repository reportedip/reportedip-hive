<?php
/**
 * WordPress-dashboard widget with the Hive security snapshot.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.41
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registers and renders the "ReportedIP Hive — Security" widget on the WP
 * dashboard (wp-admin/index.php) and the network dashboard.
 *
 * Visibility mirrors the plugin's Multisite capability model: on single
 * site the widget shows to `manage_options`; on Multisite sub-site
 * dashboards it shows ONLY to `manage_network_options`, because site
 * admins are read-only by design (the plugin admin lives in the Network
 * Admin) and every number the widget shows is network-wide. The network
 * dashboard registers via `wp_network_dashboard_setup` with the same
 * network capability.
 *
 * All values come from existing caches — the 30-day threat-analytics
 * site transient, the public-stats transient, the option-router reads
 * behind the layer counter and the score transient — so rendering the
 * widget issues no new aggregate queries and no HTTP requests.
 *
 * @since 2.1.41
 */
final class ReportedIP_Hive_Dashboard_Widget {

	/**
	 * Dashboard widget id.
	 *
	 * @var string
	 */
	const WIDGET_ID = 'reportedip_hive_overview';

	/**
	 * Wire the dashboard hooks. Idempotent.
	 *
	 * @return void
	 * @since  2.1.41
	 */
	public static function init() {
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'register_site_widget' ) );
		add_action( 'wp_network_dashboard_setup', array( __CLASS__, 'register_network_widget' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_assets' ) );
	}

	/**
	 * Register the widget on the site dashboard for eligible users.
	 *
	 * @return void
	 * @since  2.1.41
	 */
	public static function register_site_widget() {
		if ( ! self::current_user_can_view() ) {
			return;
		}
		self::add_widget();
	}

	/**
	 * Register the widget on the network dashboard for network admins.
	 *
	 * @return void
	 * @since  2.1.41
	 */
	public static function register_network_widget() {
		if ( ! current_user_can( 'manage_network_options' ) ) {
			return;
		}
		self::add_widget();
	}

	/**
	 * Enqueue the self-contained widget stylesheet on the dashboard screen
	 * only (`index.php` covers both the site and the network dashboard).
	 *
	 * @param string $hook_suffix Current admin page hook suffix.
	 * @return void
	 * @since  2.1.41
	 */
	public static function enqueue_assets( $hook_suffix ) {
		if ( 'index.php' !== $hook_suffix || ! self::current_user_can_view() ) {
			return;
		}

		wp_enqueue_style(
			'rip-dashboard-widget',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/dashboard-widget.css',
			array(),
			REPORTEDIP_HIVE_VERSION
		);
	}

	/**
	 * Render the widget body from cached data sources.
	 *
	 * @return void
	 * @since  2.1.41
	 */
	public static function render() {
		$analytics      = ReportedIP_Hive_Database::get_instance()->get_threat_analytics( 30 );
		$blocked_period = isset( $analytics['totals']['period'] ) ? (int) $analytics['totals']['period'] : 0;
		$blocked_today  = isset( $analytics['totals']['today'] ) ? (int) $analytics['totals']['today'] : 0;

		$stats          = ReportedIP_Hive_Frontend_Shortcodes::get_instance()->get_cached_stats();
		$blocked_active = isset( $stats['blocked_active'] ) ? (int) $stats['blocked_active'] : 0;

		$layers = ReportedIP_Hive_Admin_Settings::get_active_protection_layers();
		$score  = ReportedIP_Hive_Score::detection_score();
		$grade  = isset( $score['grade'] ) ? (string) $score['grade'] : '';

		$mode_info = ReportedIP_Hive_Mode_Manager::get_instance()->get_mode_info();
		/* translators: %s: operation-mode label, e.g. "Community Network" or "Local Shield". */
		$mode_line = sprintf( __( '%s mode', 'reportedip-hive' ), $mode_info['label'] );
		if ( is_multisite() ) {
			$mode_line .= ' · ' . __( 'Network-wide numbers', 'reportedip-hive' );
		}

		$dashboard_url = self::plugin_admin_url( 'admin.php?page=reportedip-hive' );
		$logs_url      = self::plugin_admin_url( 'admin.php?page=reportedip-hive-security&tab=logs' );
		?>
		<div class="rip-dw">
			<div class="rip-dw__hero">
				<span class="rip-dw__hero-icon" aria-hidden="true">
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
				</span>
				<div class="rip-dw__hero-body">
					<span class="rip-dw__hero-value"><?php echo esc_html( number_format_i18n( $blocked_period ) ); ?></span>
					<span class="rip-dw__hero-label"><?php esc_html_e( 'Attacks blocked — last 30 days', 'reportedip-hive' ); ?></span>
				</div>
				<?php ReportedIP_Hive_Admin_Settings::render_tier_badge( null, array( 'small' => true ) ); ?>
			</div>

			<ul class="rip-dw__tiles" role="list">
				<li class="rip-dw__tile">
					<span class="rip-dw__tile-value"><?php echo esc_html( number_format_i18n( $blocked_today ) ); ?></span>
					<span class="rip-dw__tile-label"><?php esc_html_e( 'Blocked today', 'reportedip-hive' ); ?></span>
				</li>
				<li class="rip-dw__tile">
					<span class="rip-dw__tile-value"><?php echo esc_html( number_format_i18n( $blocked_active ) ); ?></span>
					<span class="rip-dw__tile-label"><?php esc_html_e( 'Active IP blocks', 'reportedip-hive' ); ?></span>
				</li>
				<li class="rip-dw__tile">
					<span class="rip-dw__tile-value"><?php echo esc_html( number_format_i18n( $layers['active'] ) . ' / ' . number_format_i18n( $layers['total'] ) ); ?></span>
					<span class="rip-dw__tile-label"><?php esc_html_e( 'Protection layers', 'reportedip-hive' ); ?></span>
				</li>
				<li class="rip-dw__tile">
					<span class="rip-dw__tile-value"><?php echo esc_html( $grade ); ?></span>
					<span class="rip-dw__tile-label"><?php esc_html_e( 'Detection score', 'reportedip-hive' ); ?></span>
				</li>
			</ul>

			<p class="rip-dw__meta"><?php echo esc_html( $mode_line ); ?></p>

			<div class="rip-dw__actions">
				<a class="rip-dw__action" href="<?php echo esc_url( $dashboard_url ); ?>">
					<?php esc_html_e( 'Open Security Dashboard', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
				</a>
				<a class="rip-dw__action rip-dw__action--muted" href="<?php echo esc_url( $logs_url ); ?>">
					<?php esc_html_e( 'View logs', 'reportedip-hive' ); ?>
					<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
				</a>
			</div>
		</div>
		<?php
	}

	/**
	 * Register the widget in the top slot of the normal column.
	 *
	 * @return void
	 * @since  2.1.41
	 */
	private static function add_widget() {
		wp_add_dashboard_widget(
			self::WIDGET_ID,
			__( 'ReportedIP Hive — Security', 'reportedip-hive' ),
			array( __CLASS__, 'render' ),
			null,
			null,
			'normal',
			'high'
		);
	}

	/**
	 * Whether the current user may see the widget on a site dashboard.
	 *
	 * @return bool
	 * @since  2.1.41
	 */
	private static function current_user_can_view() {
		if ( is_multisite() ) {
			return current_user_can( 'manage_network_options' );
		}
		return current_user_can( 'manage_options' );
	}

	/**
	 * Resolve a plugin admin URL; on Multisite the plugin UI lives in the
	 * Network Admin, so links always target `network_admin_url()` there.
	 *
	 * @param string $path Relative admin path.
	 * @return string
	 * @since  2.1.41
	 */
	private static function plugin_admin_url( $path ) {
		if ( is_multisite() ) {
			return network_admin_url( $path );
		}
		return admin_url( $path );
	}
}
