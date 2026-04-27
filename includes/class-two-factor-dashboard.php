<?php
/**
 * Admin 2FA Status Dashboard.
 *
 * Adds an admin submenu page that gives operators a single-pane view over
 * the 2FA state of every user: stat cards + filterable user list + audit
 * log excerpts. CSV export for compliance reviewers.
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

class ReportedIP_Hive_Two_Factor_Dashboard {

	const PAGE_SLUG = 'reportedip-hive-2fa-status';

	public function __construct() {
		add_action( 'admin_menu', array( $this, 'register_page' ), 20 );
		add_action( 'admin_post_reportedip_hive_2fa_export', array( $this, 'export_csv' ) );
	}

	public function register_page() {
		add_submenu_page(
			'reportedip-hive',
			__( '2FA Status', 'reportedip-hive' ),
			__( '2FA Status', 'reportedip-hive' ),
			'manage_options',
			self::PAGE_SLUG,
			array( $this, 'render' )
		);
	}

	public function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission.', 'reportedip-hive' ) );
		}

		$stats            = self::compute_stats();
		$users            = self::list_users( 200 );
		$export_users_url = wp_nonce_url( admin_url( 'admin-post.php?action=reportedip_hive_2fa_export&type=users' ), 'reportedip_hive_2fa_export' );
		$export_audit_url = wp_nonce_url( admin_url( 'admin-post.php?action=reportedip_hive_2fa_export&type=audit' ), 'reportedip_hive_2fa_export' );

		$mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
		$mode_info    = $mode_manager->get_mode_info();
		?>
		<div class="wrap rip-wrap">
			<div class="rip-header">
				<div class="rip-header__brand">
					<div class="rip-header__logo">
						<svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
							<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4z" fill="currentColor" opacity="0.15"/>
							<path d="M24 4L8 12v12c0 11 7.7 21.3 16 24 8.3-2.7 16-13 16-24V12L24 4zm0 4.2l12 6v10c0 8.4-6 16.3-12 18.5-6-2.2-12-10.1-12-18.5v-10l12-6z" fill="currentColor"/>
							<path d="M21 28l-5-5 1.8-1.8 3.2 3.2 7.2-7.2L30 19l-9 9z" fill="currentColor"/>
						</svg>
					</div>
					<div>
						<h1 class="rip-header__title"><?php esc_html_e( '2FA Status', 'reportedip-hive' ); ?></h1>
						<p class="rip-header__subtitle"><?php esc_html_e( 'Overview of two-factor authentication for all users', 'reportedip-hive' ); ?></p>
					</div>
				</div>
				<div class="rip-header__actions">
					<span class="rip-mode-badge <?php echo esc_attr( $mode_info['badge_class'] ); ?>">
						<?php if ( 'local' === $mode_info['key'] ) : ?>
							<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
						<?php else : ?>
							<svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><circle cx="10" cy="10" r="8" stroke="currentColor" stroke-width="2" fill="none"/><path d="M2 10h16M10 2c2.8 2.8 4.4 6.5 4.4 8s-1.6 5.2-4.4 8c-2.8-2.8-4.4-6.5-4.4-8s1.6-5.2 4.4-8z" stroke="currentColor" stroke-width="1.5" fill="none"/></svg>
						<?php endif; ?>
						<?php echo esc_html( $mode_info['label'] ); ?>
					</span>
				</div>
			</div>

			<div class="rip-content">

				<div class="rip-stat-cards">
					<?php
					self::render_stat_card( __( 'Total users', 'reportedip-hive' ), $stats['total'], 'info', 'users' );
					self::render_stat_card( __( 'With 2FA', 'reportedip-hive' ), $stats['enabled'], 'success', 'shield-check' );
					self::render_stat_card( __( 'Without 2FA', 'reportedip-hive' ), $stats['without'], 'danger', 'shield-off' );
					self::render_stat_card( __( 'In grace period', 'reportedip-hive' ), $stats['in_grace'], 'warning', 'clock' );
					self::render_stat_card( __( 'Skip exhausted', 'reportedip-hive' ), $stats['skip_exhausted'], 'danger', 'lock' );
					self::render_stat_card( __( 'Low recovery codes', 'reportedip-hive' ), $stats['recovery_low'], 'warning', 'key' );
					?>
				</div>

				<div class="rip-card rip-2fa-dashboard__users-card">
					<div class="rip-card__header">
						<h2 class="rip-card__title">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20" aria-hidden="true"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/></svg>
							<?php esc_html_e( 'Users', 'reportedip-hive' ); ?>
						</h2>
						<div class="rip-card__actions">
							<a href="<?php echo esc_url( $export_users_url ); ?>" class="rip-button rip-button--secondary rip-button--sm">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" aria-hidden="true"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3"/></svg>
								<?php esc_html_e( 'User status CSV', 'reportedip-hive' ); ?>
							</a>
							<a href="<?php echo esc_url( $export_audit_url ); ?>" class="rip-button rip-button--secondary rip-button--sm">
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14" aria-hidden="true"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
								<?php esc_html_e( 'Audit log CSV', 'reportedip-hive' ); ?>
							</a>
						</div>
					</div>
					<div class="rip-card__body">
						<table class="rip-table">
							<thead>
								<tr>
									<th><?php esc_html_e( 'Users', 'reportedip-hive' ); ?></th>
									<th><?php esc_html_e( 'Role(s)', 'reportedip-hive' ); ?></th>
									<th><?php esc_html_e( 'Methods', 'reportedip-hive' ); ?></th>
									<th><?php esc_html_e( 'Recovery', 'reportedip-hive' ); ?></th>
									<th><?php esc_html_e( 'Status', 'reportedip-hive' ); ?></th>
									<th><?php esc_html_e( 'Skips', 'reportedip-hive' ); ?></th>
									<th><?php esc_html_e( 'Set up', 'reportedip-hive' ); ?></th>
								</tr>
							</thead>
							<tbody>
							<?php foreach ( $users as $row ) : ?>
								<tr>
									<td><a href="<?php echo esc_url( get_edit_user_link( $row['id'] ) ); ?>"><?php echo esc_html( $row['login'] ); ?></a> <span class="rip-muted">#<?php echo (int) $row['id']; ?></span></td>
									<td><?php echo esc_html( implode( ', ', $row['roles'] ) ); ?></td>
									<td><?php echo esc_html( $row['methods'] ?: '—' ); ?></td>
									<td><?php echo (int) $row['recovery']; ?></td>
									<td>
										<?php if ( $row['enabled'] ) : ?>
											<span class="rip-badge rip-badge--success"><?php esc_html_e( 'active', 'reportedip-hive' ); ?></span>
										<?php elseif ( $row['enforced'] ) : ?>
											<span class="rip-badge rip-badge--danger"><?php esc_html_e( 'Required, not set up', 'reportedip-hive' ); ?></span>
										<?php else : ?>
											<span class="rip-badge"><?php esc_html_e( 'optional', 'reportedip-hive' ); ?></span>
										<?php endif; ?>
									</td>
									<td><?php echo (int) $row['skips']; ?></td>
									<td><?php echo esc_html( $row['setup'] ); ?></td>
								</tr>
							<?php endforeach; ?>
							</tbody>
						</table>
					</div>
				</div>

			</div><!-- /.rip-content -->

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

	public function export_csv() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission.', 'reportedip-hive' ) );
		}
		check_admin_referer( 'reportedip_hive_2fa_export' );

		$type = isset( $_GET['type'] ) ? sanitize_key( wp_unslash( $_GET['type'] ) ) : 'users';
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=reportedip-2fa-' . $type . '-' . gmdate( 'Ymd-His' ) . '.csv' );

		$out = fopen( 'php://output', 'w' );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Streaming CSV directly to PHP output buffer; WP_Filesystem is for file paths.
		fwrite( $out, "\xEF\xBB\xBF" );

		if ( 'audit' === $type ) {
			fputcsv( $out, array( 'id', 'when', 'event', 'ip', 'severity', 'details' ) );
			global $wpdb;
			$table = $wpdb->prefix . 'reportedip_hive_logs';
			$rows  = $wpdb->get_results( "SELECT id, created_at, event_type, ip_address, severity, details FROM $table WHERE event_type LIKE '%2fa%' OR details LIKE '%2fa%' ORDER BY id DESC LIMIT 500" ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe: table name from $wpdb->prefix; literal hardcoded LIKE patterns.
			foreach ( (array) $rows as $row ) {
				fputcsv( $out, array( $row->id, $row->created_at, $row->event_type, $row->ip_address, $row->severity, $row->details ) );
			}
		} else {
			fputcsv( $out, array( 'id', 'login', 'email', 'roles', 'methods', 'recovery', 'enabled', 'enforced', 'skips', 'setup_date' ) );
			foreach ( self::list_users( 10000 ) as $row ) {
				fputcsv(
					$out,
					array(
						$row['id'],
						$row['login'],
						$row['email'],
						implode( '|', $row['roles'] ),
						$row['methods'],
						$row['recovery'],
						$row['enabled'] ? '1' : '0',
						$row['enforced'] ? '1' : '0',
						$row['skips'],
						$row['setup'],
					)
				);
			}
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closing the php://output stream; WP_Filesystem is for file paths.
		fclose( $out );
		exit;
	}

	/* ------------------------------------------------------------------ */

	private static function render_stat_card( $label, $value, $tone = 'info', $icon = 'users' ) {
		$tone_class = 'rip-stat-card__icon--' . $tone;
		?>
		<div class="rip-stat-card">
			<div class="rip-stat-card__icon <?php echo esc_attr( $tone_class ); ?>">
				<?php echo self::stat_icon( $icon ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- trusted inline SVG ?>
			</div>
			<div class="rip-stat-card__content">
				<div class="rip-stat-card__value"><?php echo esc_html( (string) $value ); ?></div>
				<div class="rip-stat-card__label"><?php echo esc_html( $label ); ?></div>
			</div>
		</div>
		<?php
	}

	/**
	 * Return an inline SVG for a given icon name (keeps markup-building tidy).
	 */
	private static function stat_icon( $name ) {
		$base  = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';
		$icons = array(
			'users'        => '<path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>',
			'shield-check' => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>',
			'shield-off'   => '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 01-.67 0C7.5 20.5 4 18 4 13V5l8-3 8 3"/><path d="M4 4l16 16"/>',
			'clock'        => '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
			'lock'         => '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>',
			'key'          => '<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/>',
		);
		$svg   = $icons[ $name ] ?? $icons['users'];
		return $base . $svg . '</svg>';
	}

	public static function compute_stats() {
		global $wpdb;
		$total          = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->users}" ); // phpcs:ignore WordPress.DB
		$enabled        = 0;
		$without        = 0;
		$in_grace       = 0;
		$skip_exhausted = 0;
		$recovery_low   = 0;
		$max_skips      = (int) get_option( 'reportedip_hive_2fa_max_skips', 3 );

		$ids = $wpdb->get_col( "SELECT ID FROM {$wpdb->users} LIMIT 2000" ); // phpcs:ignore WordPress.DB
		foreach ( $ids as $id ) {
			$user = get_userdata( (int) $id );
			if ( ! $user ) {
				continue; }

			if ( ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID ) ) {
				++$enabled;
				if ( ReportedIP_Hive_Two_Factor_Recovery::is_low( $user->ID ) ) {
					++$recovery_low;
				}
			} else {
				++$without;
				if ( ReportedIP_Hive_Two_Factor::is_enforced_for_user( $user ) ) {
					if ( ReportedIP_Hive_Two_Factor::is_in_grace_period( $user->ID ) ) {
						++$in_grace;
					}
					$skip_count = (int) get_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_SKIP_COUNT, true );
					if ( $max_skips > 0 && $skip_count >= $max_skips ) {
						++$skip_exhausted;
					}
				}
			}
		}

		return compact( 'total', 'enabled', 'without', 'in_grace', 'skip_exhausted', 'recovery_low' );
	}

	public static function list_users( $limit = 200 ) {
		global $wpdb;
		$ids  = $wpdb->get_col( $wpdb->prepare( "SELECT ID FROM {$wpdb->users} ORDER BY ID ASC LIMIT %d", $limit ) ); // phpcs:ignore WordPress.DB
		$rows = array();
		foreach ( $ids as $id ) {
			$user = get_userdata( (int) $id );
			if ( ! $user ) {
				continue; }
			$methods = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user->ID );
			$ts      = get_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_SETUP_DATE, true );
			$rows[]  = array(
				'id'       => $user->ID,
				'login'    => $user->user_login,
				'email'    => $user->user_email,
				'roles'    => array_map( 'translate_user_role', (array) $user->roles ),
				'methods'  => implode( ',', $methods ),
				'recovery' => ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user->ID ),
				'enabled'  => ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID ),
				'enforced' => ReportedIP_Hive_Two_Factor::is_enforced_for_user( $user ),
				'skips'    => (int) get_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_SKIP_COUNT, true ),
				'setup'    => $ts ? wp_date( 'd.m.Y', (int) $ts ) : '—',
			);
		}
		return $rows;
	}
}
