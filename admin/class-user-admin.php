<?php
/**
 * Admin surfaces for account blocking and the session manager.
 *
 * Three surfaces, one state machine: the "Account access" card on the user
 * edit screen, the Account column with its Blocked view and bulk actions on
 * the users list, and the Users -> Sessions page.
 *
 * Everything posts through forms WordPress already nonces — the user edit form
 * and the list table's own bulk form — so there is no extra admin-post
 * endpoint and no JavaScript.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.51
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Wires account blocking and session management into wp-admin.
 *
 * @since 2.1.51
 */
class ReportedIP_Hive_User_Admin {

	/**
	 * Page slug of the session manager.
	 */
	const PAGE_SLUG = 'reportedip-hive-sessions';

	/**
	 * Bulk-action keys handled on the users list.
	 *
	 * @var string[]
	 */
	const BULK_ACTIONS = array( 'reportedip_block', 'reportedip_unblock' );

	/**
	 * Register every admin hook.
	 *
	 * @since 2.1.51
	 */
	public function __construct() {
		add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', array( $this, 'add_menu' ) );
		add_action( 'load-users_page_' . self::PAGE_SLUG, array( $this, 'handle_sessions_actions' ) );

		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile_update', array( $this, 'save_profile_section' ) );

		add_filter( 'manage_users_columns', array( $this, 'add_column' ) );
		add_filter( 'wpmu_users_columns', array( $this, 'add_column' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'render_column' ), 10, 3 );
		add_filter( 'views_users', array( $this, 'add_blocked_view' ) );
		add_filter( 'views_users-network', array( $this, 'add_blocked_view' ) );
		add_action( 'pre_get_users', array( $this, 'filter_blocked_view' ) );
		add_filter( 'bulk_actions-users', array( $this, 'add_bulk_actions' ) );
		add_filter( 'bulk_actions-users-network', array( $this, 'add_bulk_actions' ) );
		add_filter( 'handle_bulk_actions-users', array( $this, 'handle_bulk_single_site' ), 10, 3 );
		add_filter( 'handle_network_bulk_actions-users-network', array( $this, 'handle_bulk_network' ), 10, 3 );
		add_action( 'admin_notices', array( $this, 'show_users_notice' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_styles' ) );
	}

	/**
	 * Capability required to manage sessions and blocks.
	 *
	 * @return string
	 * @since  2.1.51
	 */
	public static function page_capability() {
		return is_multisite() ? 'manage_network_users' : 'edit_users';
	}

	/**
	 * Register the Users -> Sessions submenu.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function add_menu() {
		add_submenu_page(
			'users.php',
			__( 'Sessions', 'reportedip-hive' ),
			__( 'Sessions', 'reportedip-hive' ),
			self::page_capability(),
			self::PAGE_SLUG,
			array( $this, 'render_sessions_page' )
		);
	}

	/**
	 * Load the design-system stylesheet on the core user screens.
	 *
	 * The plugin's own pages get it from the main bootstrap; `users.php`,
	 * `user-edit.php` and `profile.php` are core screens where the badges and
	 * the account card would otherwise render unstyled.
	 *
	 * @param string $hook Current admin screen hook.
	 * @return void
	 * @since  2.1.51
	 */
	public function enqueue_styles( $hook ) {
		if ( ! in_array( (string) $hook, array( 'users.php', 'user-edit.php', 'profile.php' ), true ) ) {
			return;
		}
		wp_enqueue_style(
			'reportedip-hive-design-system',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/design-system.css',
			array(),
			REPORTEDIP_HIVE_VERSION
		);
	}

	/* --------------------------------------------------------------------- *
	 * Sessions page
	 * --------------------------------------------------------------------- */

	/**
	 * Render the session manager.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function render_sessions_page() {
		if ( ! current_user_can( self::page_capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to manage sessions.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}

		ReportedIP_Hive_Admin_Settings::render_page_header(
			__( 'Sessions', 'reportedip-hive' ),
			__( 'Who is signed in, from where — and the switch to end it.', 'reportedip-hive' )
		);

		$this->render_sessions_notice();

		$status = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( ReportedIP_Hive_User_Block::FEATURE );
		if ( empty( $status['available'] ) ) {
			echo '<div class="rip-content">';
			ReportedIP_Hive_Admin_Settings::render_tier_marker( $status );
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'See every active WordPress session — user, sign-in time, IP address and device — and end any of them. Unlocks with Business.', 'reportedip-hive' ) . '</div>';
			echo '</div>';
			ReportedIP_Hive_Admin_Settings::render_page_footer();
			return;
		}

		$table = new ReportedIP_Hive_Sessions_Table();
		$table->prepare_items();

		echo '<div class="rip-content">';
		if ( ! $table->supports_single_termination() ) {
			echo '<div class="rip-alert rip-alert--info">' . esc_html__( 'Another plugin manages WordPress sessions on this site, so individual sessions cannot be listed or ended here. Blocking an account still signs it out everywhere.', 'reportedip-hive' ) . '</div>';
		}
		echo '<form method="post" id="rip-sessions-form">';
		printf( '<input type="hidden" name="page" value="%s" />', esc_attr( self::PAGE_SLUG ) );
		$table->display();
		echo '</form>';
		echo '</div>';

		ReportedIP_Hive_Admin_Settings::render_page_footer();
	}

	/**
	 * Result notice for the session actions (plugin screens strip
	 * `admin_notices`, so it is rendered inline).
	 *
	 * @return void
	 * @since  2.1.51
	 */
	private function render_sessions_notice() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only result counters echoed back after a nonced redirect.
		$ended   = isset( $_GET['rip_terminated'] ) ? absint( $_GET['rip_terminated'] ) : 0;
		$skipped = isset( $_GET['rip_skipped'] ) ? absint( $_GET['rip_skipped'] ) : 0;
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		if ( $ended < 1 && $skipped < 1 ) {
			return;
		}

		ReportedIP_Hive_Admin_Notice::render(
			array(
				'variant'     => $skipped > 0 ? 'warning' : 'success',
				'dismissible' => true,
				'body'        => sprintf(
					/* translators: 1: number of sessions ended, 2: number of sessions skipped */
					esc_html__( '%1$d session(s) ended, %2$d skipped.', 'reportedip-hive' ),
					$ended,
					$skipped
				),
			)
		);
	}

	/**
	 * Process the session form before any output is sent.
	 *
	 * The filter bar posts through the same form, so a request without a
	 * termination target falls through to the normal render with `$_REQUEST`
	 * still carrying the filter values.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function handle_sessions_actions() {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) ) {
			return;
		}
		if ( ! current_user_can( self::page_capability() ) ) {
			wp_die( esc_html__( 'You are not allowed to manage sessions.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'bulk-sessions' );

		$single = isset( $_POST['rip_terminate'] ) ? sanitize_text_field( wp_unslash( $_POST['rip_terminate'] ) ) : '';
		$all_of = isset( $_POST['rip_terminate_user'] ) ? absint( $_POST['rip_terminate_user'] ) : 0;
		$action = isset( $_POST['action'] ) ? sanitize_key( wp_unslash( $_POST['action'] ) ) : '';
		if ( 'terminate' !== $action ) {
			$action = isset( $_POST['action2'] ) ? sanitize_key( wp_unslash( $_POST['action2'] ) ) : '';
		}
		$bulk = ( 'terminate' === $action && isset( $_POST['sessions'] ) && is_array( $_POST['sessions'] ) )
			? array_map( 'sanitize_text_field', wp_unslash( $_POST['sessions'] ) )
			: array();

		if ( '' === $single && $all_of < 1 && empty( $bulk ) ) {
			return;
		}

		if ( ! ReportedIP_Hive_User_Block::is_available() ) {
			wp_die( esc_html__( 'Session management requires the Business plan.', 'reportedip-hive' ), '', array( 'response' => 403 ) );
		}

		$ended   = 0;
		$skipped = 0;

		if ( '' !== $single ) {
			$this->terminate_target( $single, $ended, $skipped );
		} elseif ( $all_of > 0 ) {
			$this->terminate_all_for( $all_of, $ended, $skipped );
		} else {
			foreach ( $bulk as $target ) {
				$this->terminate_target( $target, $ended, $skipped );
			}
		}

		wp_safe_redirect(
			add_query_arg(
				array(
					'rip_terminated' => $ended,
					'rip_skipped'    => $skipped,
				),
				self_admin_url( 'users.php?page=' . self::PAGE_SLUG )
			)
		);
		exit;
	}

	/**
	 * End one `user_id:verifier` target.
	 *
	 * @param string $target  Combined target token.
	 * @param int    $ended   Running success counter (by reference).
	 * @param int    $skipped Running skip counter (by reference).
	 * @return void
	 * @since  2.1.51
	 */
	private function terminate_target( $target, &$ended, &$skipped ) {
		$parts = explode( ':', $target, 2 );
		if ( count( $parts ) !== 2 ) {
			++$skipped;
			return;
		}
		$user_id  = (int) $parts[0];
		$verifier = preg_replace( '/[^a-f0-9]/i', '', (string) $parts[1] );

		if ( $user_id <= 0 || ! current_user_can( 'edit_user', $user_id ) ) {
			++$skipped;
			return;
		}
		if ( ! ReportedIP_Hive_User_Sessions::terminate( $user_id, (string) $verifier ) ) {
			++$skipped;
			return;
		}

		++$ended;
		$user = get_userdata( $user_id );
		ReportedIP_Hive_Audit_Logger::get_instance()->record(
			'session',
			'terminated',
			array(
				'by'             => get_current_user_id(),
				'target_user_id' => $user_id,
				'verifier'       => substr( (string) $verifier, 0, 8 ),
			),
			$user_id,
			$user ? (string) $user->user_login : ''
		);
	}

	/**
	 * End every session of one user.
	 *
	 * @param int $user_id Session owner.
	 * @param int $ended   Running success counter (by reference).
	 * @param int $skipped Running skip counter (by reference).
	 * @return void
	 * @since  2.1.51
	 */
	private function terminate_all_for( $user_id, &$ended, &$skipped ) {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			++$skipped;
			return;
		}

		$count  = ReportedIP_Hive_User_Sessions::terminate_all( $user_id );
		$ended += $count;

		$user = get_userdata( $user_id );
		ReportedIP_Hive_Audit_Logger::get_instance()->record(
			'session',
			'terminated_all',
			array(
				'by'             => get_current_user_id(),
				'target_user_id' => (int) $user_id,
				'count'          => $count,
			),
			(int) $user_id,
			$user ? (string) $user->user_login : ''
		);
	}

	/* --------------------------------------------------------------------- *
	 * User edit screen
	 * --------------------------------------------------------------------- */

	/**
	 * Render the "Account access" card on the user edit screen.
	 *
	 * @param WP_User $user User being edited.
	 * @return void
	 * @since  2.1.51
	 */
	public function render_profile_section( $user ) {
		if ( ! ( $user instanceof WP_User ) || ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}

		wp_enqueue_style(
			'reportedip-hive-design-system',
			REPORTEDIP_HIVE_PLUGIN_URL . 'assets/css/design-system.css',
			array(),
			REPORTEDIP_HIVE_VERSION
		);

		$record   = ReportedIP_Hive_User_Block::get( $user->ID );
		$blocked  = null !== $record;
		$status   = ReportedIP_Hive_Mode_Manager::get_instance()->feature_status( ReportedIP_Hive_User_Block::FEATURE );
		$refusal  = ReportedIP_Hive_User_Block::refusal( $user->ID );
		$editable = $blocked || ( '' === $refusal && ! empty( $status['available'] ) );

		$hint = '';
		if ( ! $editable ) {
			$hint = '' !== $refusal
				? ReportedIP_Hive_User_Block::refusal_message( $refusal )
				: __( 'Blocking user accounts requires the Business plan.', 'reportedip-hive' );
		}
		?>
		<h2 id="reportedip-hive-account-access">
			<?php esc_html_e( 'Account access', 'reportedip-hive' ); ?>
			<?php ReportedIP_Hive_Admin_Settings::render_tier_marker( $status ); ?>
		</h2>
		<table class="form-table" role="presentation">
			<tr>
				<td colspan="2">
					<div class="rip-card">
						<div class="rip-card__body">
							<?php $this->render_profile_error( $user->ID ); ?>
							<p>
								<?php if ( $blocked ) : ?>
									<span class="rip-badge rip-badge--danger"><?php esc_html_e( 'Blocked', 'reportedip-hive' ); ?></span>
									<span class="rip-text-muted">
										<?php
										printf(
											/* translators: 1: local date and time, 2: administrator name */
											esc_html__( 'since %1$s by %2$s', 'reportedip-hive' ),
											esc_html( ReportedIP_Hive::format_local_datetime( $record['blocked_at'] ) ),
											esc_html( ReportedIP_Hive_User_Block::blocked_by_label( $record['blocked_by'] ) )
										);
										?>
									</span>
								<?php else : ?>
									<span class="rip-badge rip-badge--success"><?php esc_html_e( 'Active', 'reportedip-hive' ); ?></span>
								<?php endif; ?>
							</p>

							<?php if ( $editable ) : ?>
								<input type="hidden" name="rip_block_editable" value="1" />
							<?php endif; ?>
							<div class="rip-form-row">
								<label class="rip-toggle">
									<input type="checkbox" class="rip-toggle__input" name="rip_block_user" value="1" <?php checked( $blocked ); ?> <?php disabled( ! $editable ); ?> />
									<span class="rip-toggle__slider"></span>
									<span class="rip-toggle__label"><?php esc_html_e( 'Block this account', 'reportedip-hive' ); ?></span>
								</label>
								<p class="rip-field-hint">
									<?php
									echo '' !== $hint
										? esc_html( $hint )
										: esc_html__( 'A blocked account keeps its content but cannot sign in, use an application password or reset its password. All its sessions and trusted devices end immediately.', 'reportedip-hive' );
									?>
								</p>
							</div>

							<div class="rip-form-row">
								<label class="rip-form-label" for="rip_block_message"><?php esc_html_e( 'Message shown to the user', 'reportedip-hive' ); ?></label>
								<textarea class="rip-textarea" id="rip_block_message" name="rip_block_message" rows="2" maxlength="<?php echo esc_attr( (string) ReportedIP_Hive_User_Block::MESSAGE_MAX ); ?>" <?php disabled( ! $editable ); ?>><?php echo esc_textarea( $blocked ? $record['message'] : '' ); ?></textarea>
								<p class="rip-field-hint"><?php esc_html_e( 'Appended to the standard notice on the sign-in page.', 'reportedip-hive' ); ?></p>
							</div>

							<div class="rip-form-row">
								<label class="rip-form-label" for="rip_block_note"><?php esc_html_e( 'Administrator note (not shown at login)', 'reportedip-hive' ); ?></label>
								<textarea class="rip-textarea" id="rip_block_note" name="rip_block_note" rows="2" maxlength="<?php echo esc_attr( (string) ReportedIP_Hive_User_Block::NOTE_MAX ); ?>" <?php disabled( ! $editable ); ?>><?php echo esc_textarea( $blocked ? $record['note'] : '' ); ?></textarea>
								<p class="rip-field-hint"><?php esc_html_e( 'Internal reason for the block. It is part of this user\'s personal-data export, so keep it factual.', 'reportedip-hive' ); ?></p>
							</div>

							<?php $this->render_diagnosis( $user ); ?>
						</div>
					</div>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * "Why can this user not sign in?" — the three answers that are not the
	 * password, gathered from the block record, the IP block list and 2FA.
	 *
	 * @param WP_User $user User being edited.
	 * @return void
	 * @since  2.1.51
	 */
	private function render_diagnosis( $user ) {
		$lines = array();

		$lines[] = ReportedIP_Hive_User_Block::is_blocked( $user->ID )
			? __( 'The account is blocked.', 'reportedip-hive' )
			: __( 'The account is not blocked.', 'reportedip-hive' );

		$known = get_user_meta( $user->ID, ReportedIP_Hive_Audit_Logger::KNOWN_IPS_META, true );
		$known = is_array( $known ) ? $known : array();
		$last  = empty( $known ) ? '' : (string) end( $known );
		if ( '' !== $last ) {
			$lines[] = sprintf(
				/* translators: 1: IP address markup, 2: block state of that address */
				__( 'Last known address: %1$s (%2$s).', 'reportedip-hive' ),
				ReportedIP_Hive_IP_Cell::render( $last ),
				ReportedIP_Hive_IP_Manager::get_instance()->is_blocked( $last )
					? __( 'currently blocked', 'reportedip-hive' )
					: __( 'not blocked', 'reportedip-hive' )
			);
		}

		if ( ReportedIP_Hive_Two_Factor::is_globally_enabled()
			&& ReportedIP_Hive_Two_Factor::is_enforced_for_user( $user )
			&& ! ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID ) ) {
			$lines[] = __( 'Two-factor authentication is required for this role but not set up yet.', 'reportedip-hive' );
		}
		?>
		<p class="rip-form-label"><?php esc_html_e( 'Why can this user not sign in?', 'reportedip-hive' ); ?></p>
		<ul>
			<?php foreach ( $lines as $line ) : ?>
				<li><?php echo wp_kses_post( $line ); ?></li>
			<?php endforeach; ?>
		</ul>
		<?php
	}

	/**
	 * Apply the profile card on save.
	 *
	 * Runs before `edit_user()`, so a refusal must never `wp_die()` — that
	 * would discard every other field the administrator changed. Refusals are
	 * stashed and rendered on the next view of the same profile instead.
	 *
	 * @param int $user_id User being saved.
	 * @return void
	 * @since  2.1.51
	 */
	public function save_profile_section( $user_id ) {
		$user_id = (int) $user_id;
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}
		check_admin_referer( 'update-user_' . $user_id );

		if ( empty( $_POST['rip_block_editable'] ) ) {
			return;
		}

		$want    = ! empty( $_POST['rip_block_user'] );
		$message = isset( $_POST['rip_block_message'] ) ? sanitize_textarea_field( wp_unslash( $_POST['rip_block_message'] ) ) : '';
		$note    = isset( $_POST['rip_block_note'] ) ? sanitize_textarea_field( wp_unslash( $_POST['rip_block_note'] ) ) : '';
		$blocked = ReportedIP_Hive_User_Block::is_blocked( $user_id );

		if ( $want && ! $blocked ) {
			$result = ReportedIP_Hive_User_Block::block( $user_id, $message, $note );
		} elseif ( $want ) {
			ReportedIP_Hive_User_Block::update_texts( $user_id, $message, $note );
			return;
		} elseif ( $blocked ) {
			$result = ReportedIP_Hive_User_Block::unblock( $user_id );
		} else {
			return;
		}

		if ( is_wp_error( $result ) ) {
			set_transient( $this->profile_error_key( $user_id ), $result->get_error_message(), MINUTE_IN_SECONDS );
		}
	}

	/**
	 * Transient key carrying a refusal from the last save of this profile.
	 *
	 * @param int $user_id Edited user.
	 * @return string
	 * @since  2.1.51
	 */
	private function profile_error_key( $user_id ) {
		return 'reportedip_hive_block_error_' . get_current_user_id() . '_' . (int) $user_id;
	}

	/**
	 * Show and consume a stashed refusal.
	 *
	 * @param int $user_id Edited user.
	 * @return void
	 * @since  2.1.51
	 */
	private function render_profile_error( $user_id ) {
		$key     = $this->profile_error_key( $user_id );
		$message = get_transient( $key );
		if ( ! is_string( $message ) || '' === $message ) {
			return;
		}
		delete_transient( $key );
		echo '<div class="rip-alert rip-alert--warning">' . esc_html( $message ) . '</div>';
	}

	/* --------------------------------------------------------------------- *
	 * Users list
	 * --------------------------------------------------------------------- */

	/**
	 * Whether the block surfaces should appear on the users list at all.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	private function surfaces_visible() {
		return ReportedIP_Hive_User_Block::is_available()
			|| ReportedIP_Hive_User_Block::count_blocked( $this->scope_blog_id() ) > 0;
	}

	/**
	 * User-query scope for the current screen.
	 *
	 * @return int Blog id, 0 for the whole network.
	 * @since  2.1.51
	 */
	private function scope_blog_id() {
		return is_network_admin() ? 0 : get_current_blog_id();
	}

	/**
	 * Add the Account column.
	 *
	 * @param array<string,string> $columns Existing columns.
	 * @return array<string,string>
	 * @since  2.1.51
	 */
	public function add_column( $columns ) {
		if ( $this->surfaces_visible() ) {
			$columns['rip_account'] = __( 'Account', 'reportedip-hive' );
		}
		return $columns;
	}

	/**
	 * Render the Account column.
	 *
	 * @param string $output      Current cell output.
	 * @param string $column_name Column key.
	 * @param int    $user_id     Row user id.
	 * @return string
	 * @since  2.1.51
	 */
	public function render_column( $output, $column_name, $user_id ) {
		if ( 'rip_account' !== $column_name ) {
			return $output;
		}

		$record = ReportedIP_Hive_User_Block::get( (int) $user_id );
		if ( null === $record ) {
			return '<span class="rip-text-muted">' . esc_html__( 'Active', 'reportedip-hive' ) . '</span>';
		}

		return sprintf(
			'<span class="rip-badge rip-badge--danger" title="%s">%s</span>',
			esc_attr(
				sprintf(
					/* translators: 1: local date and time, 2: administrator name */
					__( 'Blocked since %1$s by %2$s', 'reportedip-hive' ),
					ReportedIP_Hive::format_local_datetime( $record['blocked_at'] ),
					ReportedIP_Hive_User_Block::blocked_by_label( $record['blocked_by'] )
				)
			),
			esc_html__( 'Blocked', 'reportedip-hive' )
		);
	}

	/**
	 * Add the "Blocked (n)" view link.
	 *
	 * @param array<string,string> $views Existing views.
	 * @return array<string,string>
	 * @since  2.1.51
	 */
	public function add_blocked_view( $views ) {
		if ( ! $this->surfaces_visible() ) {
			return $views;
		}

		$count = ReportedIP_Hive_User_Block::count_blocked( $this->scope_blog_id() );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only view flag.
		$active = isset( $_GET['rip_blocked'] );

		$views['rip_blocked'] = sprintf(
			'<a href="%s"%s>%s <span class="count">(%d)</span></a>',
			esc_url( add_query_arg( 'rip_blocked', 1, self_admin_url( 'users.php' ) ) ),
			$active ? ' class="current" aria-current="page"' : '',
			esc_html__( 'Blocked', 'reportedip-hive' ),
			(int) $count
		);

		return $views;
	}

	/**
	 * Restrict the users list to blocked accounts when the view is active.
	 *
	 * @param WP_User_Query $query User query.
	 * @return void
	 * @since  2.1.51
	 */
	public function filter_blocked_view( $query ) {
		global $pagenow;

		if ( ! is_admin() || 'users.php' !== $pagenow ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only view flag.
		if ( isset( $_GET['page'] ) || ! isset( $_GET['rip_blocked'] ) ) {
			return;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		$query->set( 'meta_key', ReportedIP_Hive_User_Block::META ); // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Existence probe over a rare meta key.
		$query->set( 'meta_compare', 'EXISTS' );
	}

	/**
	 * Offer the Block / Unblock bulk actions.
	 *
	 * @param array<string,string> $actions Existing bulk actions.
	 * @return array<string,string>
	 * @since  2.1.51
	 */
	public function add_bulk_actions( $actions ) {
		if ( ReportedIP_Hive_User_Block::is_available() ) {
			$actions['reportedip_block'] = __( 'Block account', 'reportedip-hive' );
		}
		if ( $this->surfaces_visible() ) {
			$actions['reportedip_unblock'] = __( 'Unblock account', 'reportedip-hive' );
		}
		return $actions;
	}

	/**
	 * Single-site bulk handler.
	 *
	 * `wp-admin/users.php` dispatches custom bulk actions from its `default:`
	 * branch without verifying the nonce, so the handler does it.
	 *
	 * @param string $sendback Redirect target.
	 * @param string $action   Bulk action key.
	 * @param int[]  $user_ids Selected user ids.
	 * @return string
	 * @since  2.1.51
	 */
	public function handle_bulk_single_site( $sendback, $action, $user_ids ) {
		if ( ! in_array( (string) $action, self::BULK_ACTIONS, true ) ) {
			return $sendback;
		}
		check_admin_referer( 'bulk-users' );
		return $this->apply_bulk( $sendback, (string) $action, (array) $user_ids );
	}

	/**
	 * Network bulk handler.
	 *
	 * `wp-admin/network/users.php` runs `check_admin_referer( 'bulk-users-network' )`
	 * and the `manage_network_users` check before it dispatches this filter.
	 *
	 * @param string $sendback Redirect target.
	 * @param string $action   Bulk action key.
	 * @param int[]  $user_ids Selected user ids.
	 * @return string
	 * @since  2.1.51
	 */
	public function handle_bulk_network( $sendback, $action, $user_ids ) {
		if ( ! in_array( (string) $action, self::BULK_ACTIONS, true ) ) {
			return $sendback;
		}
		return $this->apply_bulk( $sendback, (string) $action, (array) $user_ids );
	}

	/**
	 * Run one bulk action and append the result counters to the redirect.
	 *
	 * @param string $sendback Redirect target.
	 * @param string $action   Bulk action key.
	 * @param array  $user_ids Selected user ids.
	 * @return string
	 * @since  2.1.51
	 */
	private function apply_bulk( $sendback, $action, array $user_ids ) {
		$done    = 0;
		$skipped = 0;

		foreach ( $user_ids as $user_id ) {
			$user_id = (int) $user_id;
			if ( $user_id <= 0 || ! current_user_can( 'edit_user', $user_id ) ) {
				++$skipped;
				continue;
			}

			$result = ( 'reportedip_block' === $action )
				? ReportedIP_Hive_User_Block::block( $user_id )
				: ReportedIP_Hive_User_Block::unblock( $user_id );

			if ( is_wp_error( $result ) ) {
				++$skipped;
				continue;
			}
			++$done;
		}

		return add_query_arg(
			array(
				'rip_blocked_done' => $done,
				'rip_skipped'      => $skipped,
			),
			$sendback ? $sendback : self_admin_url( 'users.php' )
		);
	}

	/**
	 * Result notice after a bulk block / unblock.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function show_users_notice() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only result counters echoed back after a nonced redirect.
		if ( ! isset( $_GET['rip_blocked_done'] ) ) {
			return;
		}
		$done    = absint( $_GET['rip_blocked_done'] );
		$skipped = isset( $_GET['rip_skipped'] ) ? absint( $_GET['rip_skipped'] ) : 0;
		// phpcs:enable WordPress.Security.NonceVerification.Recommended

		ReportedIP_Hive_Admin_Notice::render(
			array(
				'variant'     => $skipped > 0 ? 'warning' : 'success',
				'dismissible' => true,
				'body'        => sprintf(
					/* translators: 1: number of accounts changed, 2: number of accounts skipped */
					esc_html__( '%1$d account(s) updated, %2$d skipped.', 'reportedip-hive' ),
					$done,
					$skipped
				),
			)
		);
	}
}
