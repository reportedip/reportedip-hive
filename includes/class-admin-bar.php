<?php
/**
 * Admin-Bar indicator for the active Hardening Mode.
 *
 * Adds a red node to the WordPress admin bar while
 * {@see ReportedIP_Hive_Hardening_Mode::is_active()} returns true. Visible to
 * users with `manage_options` (super_admin on Multisite). Links to the
 * Hardening-Mode settings tab.
 *
 * The admin bar renders on every wp-admin page, but `class-admin-settings.php`
 * only enqueues `admin.css` on plugin pages. We therefore attach the styling
 * via `wp_add_inline_style( 'admin-bar', ... )` so the indicator is consistent
 * across the whole admin UI.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.8
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders the Hardening-Mode node into the WordPress admin bar.
 *
 * @since 2.0.8
 */
final class ReportedIP_Hive_Admin_Bar {

	private static $instance = null;

	/**
	 * @return self
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Wire up the hooks. Called from the plugin bootstrap.
	 *
	 * @return void
	 */
	public function register_hooks() {
		add_action( 'admin_bar_menu', array( $this, 'register_node' ), 90 );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_admin_bar_style' ), 100 );
		add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_admin_bar_style' ), 100 );
	}

	/**
	 * Whether the current user is allowed to see the indicator.
	 *
	 * @return bool
	 */
	private function user_can_see() {
		if ( is_multisite() ) {
			return current_user_can( 'manage_network_options' ) || is_super_admin();
		}
		return current_user_can( 'manage_options' );
	}

	/**
	 * Register the admin-bar node.
	 *
	 * @param WP_Admin_Bar $wp_admin_bar
	 * @return void
	 */
	public function register_node( $wp_admin_bar ) {
		if ( ! is_object( $wp_admin_bar ) || ! method_exists( $wp_admin_bar, 'add_node' ) ) {
			return;
		}
		if ( ! ReportedIP_Hive_Hardening_Mode::is_active() ) {
			return;
		}
		if ( ! $this->user_can_see() ) {
			return;
		}

		$expires_at = ReportedIP_Hive_Hardening_Mode::expires_at();
		$label      = __( 'Hardening Mode active', 'reportedip-hive' );
		if ( $expires_at ) {
			$label = sprintf(
				/* translators: %s: HH:MM time-of-expiry in site timezone. */
				__( 'Hardening Mode · until %s', 'reportedip-hive' ),
				esc_html( wp_date( 'H:i', (int) $expires_at ) )
			);
		}

		$settings_url = $this->settings_tab_url();

		$wp_admin_bar->add_node(
			array(
				'id'    => 'rip-hardening',
				'title' => '<span class="rip-hardening-pulse" aria-hidden="true"></span>' . esc_html( $label ),
				'href'  => esc_url( $settings_url ),
				'meta'  => array(
					'class' => 'rip-hardening-active',
					'title' => __( 'A coordinated-attack pattern triggered the Hardening Mode. Click to manage.', 'reportedip-hive' ),
				),
			)
		);

		$reason = ReportedIP_Hive_Hardening_Mode::current_reason();
		if ( is_array( $reason ) && ! empty( $reason['unique_ips'] ) ) {
			$wp_admin_bar->add_node(
				array(
					'id'     => 'rip-hardening-reason',
					'parent' => 'rip-hardening',
					'title'  => esc_html(
						sprintf(
						/* translators: 1: number of attacking IPs, 2: total attempts, 3: time window minute. */
							__( '%1$d IPs · %2$d attempts · window %3$s', 'reportedip-hive' ),
							(int) $reason['unique_ips'],
							(int) $reason['total_attempts'],
							(string) ( $reason['time_window'] ?? '' )
						)
					),
					'meta'   => array(
						'tabindex' => '0',
					),
				)
			);
		}

		$wp_admin_bar->add_node(
			array(
				'id'     => 'rip-hardening-manage',
				'parent' => 'rip-hardening',
				'title'  => esc_html__( 'Manage Hardening settings', 'reportedip-hive' ),
				'href'   => esc_url( $settings_url ),
			)
		);
	}

	/**
	 * Inline styles for the admin-bar node — scoped, scharfe Kanten, prefers-reduced-motion aware.
	 *
	 * @return void
	 */
	public function enqueue_admin_bar_style() {
		if ( ! is_admin_bar_showing() ) {
			return;
		}
		if ( ! ReportedIP_Hive_Hardening_Mode::is_active() ) {
			return;
		}
		if ( ! $this->user_can_see() ) {
			return;
		}

		$css = <<<'CSS'
#wpadminbar #wp-admin-bar-rip-hardening > .ab-item {
	background-color: #b91c1c !important;
	color: #ffffff !important;
}
#wpadminbar #wp-admin-bar-rip-hardening:hover > .ab-item {
	background-color: #991b1b !important;
}
#wpadminbar #wp-admin-bar-rip-hardening .rip-hardening-pulse {
	display: inline-block;
	width: 8px;
	height: 8px;
	margin-right: 8px;
	background-color: #ffffff;
	box-shadow: 0 0 0 0 rgba(255, 255, 255, 0.85);
	animation: rip-hardening-pulse 1.6s infinite;
	vertical-align: middle;
}
@keyframes rip-hardening-pulse {
	0%   { box-shadow: 0 0 0 0   rgba(255,255,255,0.85); }
	70%  { box-shadow: 0 0 0 8px rgba(255,255,255,0); }
	100% { box-shadow: 0 0 0 0   rgba(255,255,255,0); }
}
@media (prefers-reduced-motion: reduce) {
	#wpadminbar #wp-admin-bar-rip-hardening .rip-hardening-pulse {
		animation: none;
	}
}
CSS;

		wp_register_style( 'rip-hardening-admin-bar', false, array( 'admin-bar' ), REPORTEDIP_HIVE_VERSION );
		wp_enqueue_style( 'rip-hardening-admin-bar' );
		wp_add_inline_style( 'rip-hardening-admin-bar', $css );
	}

	/**
	 * Settings-Tab URL (network-admin on MS).
	 *
	 * @return string
	 */
	private function settings_tab_url() {
		$args = array(
			'page' => 'reportedip-hive-settings',
			'tab'  => 'hardening_mode',
		);
		if ( is_multisite() ) {
			return add_query_arg( $args, network_admin_url( 'admin.php' ) );
		}
		return add_query_arg( $args, admin_url( 'admin.php' ) );
	}
}
