<?php
/**
 * Tools page: server setup, rules, data and diagnostics in four tabs.
 *
 * Listed in the menu in expert mode only, always reachable by URL because
 * readiness issues link here.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.56
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders the tools page.
 *
 * @since 2.1.56
 */
class ReportedIP_Hive_Tools_Page {

	/**
	 * Page slug.
	 *
	 * @var string
	 */
	const PAGE_SLUG = 'reportedip-hive-tools';

	/**
	 * Render the page.
	 *
	 * @return void
	 */
	public function render_page() {
		$tabs   = array(
			'server'   => __( 'Server', 'reportedip-hive' ),
			'rules'    => __( 'Rules', 'reportedip-hive' ),
			'data'     => __( 'Data', 'reportedip-hive' ),
			'diagnose' => __( 'Diagnostics', 'reportedip-hive' ),
		);
		$active = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'server'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- tab selection only
		if ( ! isset( $tabs[ $active ] ) ) {
			$active = 'server';
		}
		ReportedIP_Hive_Admin_Settings::render_page_header( __( 'Tools', 'reportedip-hive' ), __( 'Server setup, rule delivery, data and diagnostics', 'reportedip-hive' ) );
		echo '<nav class="rip-nav-tabs">';
		foreach ( $tabs as $slug => $label ) {
			printf(
				'<a href="%1$s" class="rip-nav-tabs__tab%2$s">%3$s</a>',
				esc_url( ReportedIP_Hive_Admin_Settings::get_admin_page_url( 'admin.php?page=' . self::PAGE_SLUG . '&tab=' . $slug ) ),
				$active === $slug ? ' rip-nav-tabs__tab--active' : '',
				esc_html( $label )
			);
		}
		echo '</nav><div class="rip-content">';
		$firewall = ReportedIP_Hive_Admin_Firewall::get_instance();
		switch ( $active ) {
			case 'rules':
				$firewall->render_rule_sync_tab();
				$firewall->render_waf_exceptions_box();
				ReportedIP_Hive_Admin_Settings::render_hardening_mode_tab();
				break;
			case 'data':
				ReportedIP_Hive_Settings_Import_Export::get_instance()->render_panel();
				ReportedIP_Hive_Admin_Settings::render_maintenance_panel();
				ReportedIP_Hive_Admin_Settings::render_uninstall_card();
				break;
			case 'diagnose':
				ReportedIP_Hive_Admin_Settings::render_diagnostics_panel();
				break;
			case 'server':
			default:
				$firewall->render_waf_dropin_box();
				$firewall->render_server_tab();
		}
		echo '</div>';
		ReportedIP_Hive_Admin_Settings::render_page_footer();
	}
}
