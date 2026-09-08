<?php
/**
 * Session list table — who is signed in, from where, and the switch to end it.
 *
 * Pagination runs over users that own at least one session; every live session
 * of a listed user becomes one row. Rows come from
 * {@see ReportedIP_Hive_User_Sessions}, the single session reader.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.51
 *
 * @phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filter/sort query args; no state change.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Renders every active WordPress session with per-row termination controls.
 *
 * @since 2.1.51
 */
class ReportedIP_Hive_Sessions_Table extends WP_List_Table {

	/**
	 * Verifier of the request's own session.
	 *
	 * @var string
	 */
	private $own_verifier = '';

	/**
	 * Whether per-session controls can act at all.
	 *
	 * @var bool
	 */
	private $can_terminate_single = true;

	/**
	 * Constructor.
	 *
	 * @since 2.1.51
	 */
	public function __construct() {
		parent::__construct(
			array(
				'singular' => 'session',
				'plural'   => 'sessions',
				'ajax'     => false,
			)
		);

		$this->own_verifier         = ReportedIP_Hive_User_Sessions::current_verifier();
		$this->can_terminate_single = ReportedIP_Hive_User_Sessions::uses_usermeta_store();
	}

	/**
	 * Whether per-session termination is possible on this install.
	 *
	 * @return bool
	 * @since  2.1.51
	 */
	public function supports_single_termination() {
		return $this->can_terminate_single;
	}

	/**
	 * Column definitions.
	 *
	 * @return array<string,string>
	 * @since  2.1.51
	 */
	public function get_columns() {
		$columns = array();
		if ( $this->can_terminate_single ) {
			$columns['cb'] = '<input type="checkbox" />';
		}
		$columns['user']       = __( 'User', 'reportedip-hive' );
		$columns['login']      = __( 'Signed in', 'reportedip-hive' );
		$columns['expiration'] = __( 'Expires', 'reportedip-hive' );
		$columns['ip']         = __( 'IP address', 'reportedip-hive' );
		$columns['device']     = __( 'Device', 'reportedip-hive' );
		$columns['actions']    = __( 'Actions', 'reportedip-hive' );

		return $columns;
	}

	/**
	 * Sortable columns — sorting happens on the user query, not per session.
	 *
	 * @return array<string,array{0:string,1:bool}>
	 * @since  2.1.51
	 */
	protected function get_sortable_columns() {
		return array(
			'user' => array( 'user_login', true ),
		);
	}

	/**
	 * Bulk actions.
	 *
	 * @return array<string,string>
	 * @since  2.1.51
	 */
	protected function get_bulk_actions() {
		if ( ! $this->can_terminate_single ) {
			return array();
		}
		return array( 'terminate' => __( 'End session', 'reportedip-hive' ) );
	}

	/**
	 * Add the design-system table class.
	 *
	 * @return string[]
	 * @since  2.1.51
	 */
	protected function get_table_classes() {
		return array( 'widefat', 'fixed', 'striped', 'rip-table', $this->_args['plural'] );
	}

	/**
	 * Checkbox column.
	 *
	 * @param array $item Row.
	 * @return string
	 * @since  2.1.51
	 */
	protected function column_cb( $item ) {
		if ( $this->is_own_current( $item ) ) {
			return '';
		}
		return sprintf(
			'<input type="checkbox" name="sessions[]" value="%s" />',
			esc_attr( $item['user']->ID . ':' . $item['verifier'] )
		);
	}

	/**
	 * Render one cell.
	 *
	 * @param array  $item        Row.
	 * @param string $column_name Column key.
	 * @return string
	 * @since  2.1.51
	 */
	protected function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'user':
				return $this->render_user( $item );

			case 'login':
				return esc_html( $this->format_timestamp( $item['session']['login'] ?? 0 ) );

			case 'expiration':
				return esc_html( $this->format_timestamp( $item['session']['expiration'] ?? 0 ) );

			case 'ip':
				$ip = ReportedIP_Hive_User_Sessions::display_ip( $item['session'] );
				return '' !== $ip ? ReportedIP_Hive_IP_Cell::render( $ip ) : '&mdash;';

			case 'device':
				$ua = isset( $item['session']['ua'] ) ? (string) $item['session']['ua'] : '';
				if ( '' === $ua ) {
					return '&mdash;';
				}
				return sprintf(
					'<span title="%s">%s</span>',
					esc_attr( $ua ),
					esc_html( ReportedIP_Hive_Two_Factor_Notifications::short_ua( $ua ) )
				);

			case 'actions':
				return $this->render_actions( $item );

			default:
				return '';
		}
	}

	/**
	 * User cell: avatar, names, roles and status badges.
	 *
	 * @param array $item Row.
	 * @return string
	 * @since  2.1.51
	 */
	private function render_user( array $item ) {
		$user = $item['user'];
		$out  = get_avatar( $user->ID, 24 );
		$out .= ' <strong>' . esc_html( $user->display_name ) . '</strong>';
		$out .= ' <span class="rip-text-muted">' . esc_html( $user->user_login ) . '</span>';

		if ( ! empty( $item['first'] ) ) {
			$role_names = wp_roles()->get_names();
			$roles      = array();
			foreach ( (array) $user->roles as $role ) {
				$roles[] = isset( $role_names[ $role ] ) ? translate_user_role( $role_names[ $role ] ) : $role;
			}
			if ( ! empty( $roles ) ) {
				$out .= '<br /><span class="rip-text-muted">' . esc_html( implode( ', ', $roles ) ) . '</span>';
			}
		}

		$badges = array();
		if ( get_current_user_id() === (int) $user->ID ) {
			$badges[] = '<span class="rip-badge rip-badge--info">' . esc_html__( 'You', 'reportedip-hive' ) . '</span>';
		}
		if ( ReportedIP_Hive_Two_Factor::is_globally_enabled() && ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID ) ) {
			$badges[] = '<span class="rip-badge rip-badge--success">' . esc_html__( '2FA', 'reportedip-hive' ) . '</span>';
		}
		if ( ReportedIP_Hive_User_Block::is_blocked( $user->ID ) ) {
			$badges[] = '<span class="rip-badge rip-badge--danger">' . esc_html__( 'Blocked', 'reportedip-hive' ) . '</span>';
		}
		if ( ! empty( $badges ) ) {
			$out .= '<br />' . implode( ' ', $badges );
		}

		return $out;
	}

	/**
	 * Action cell: end this session, end all sessions of the user.
	 *
	 * @param array $item Row.
	 * @return string
	 * @since  2.1.51
	 */
	private function render_actions( array $item ) {
		if ( ! current_user_can( 'edit_user', $item['user']->ID ) ) {
			return '&mdash;';
		}

		$buttons = array();

		if ( $this->is_own_current( $item ) ) {
			$buttons[] = '<span class="rip-badge rip-badge--info">' . esc_html__( 'Current session', 'reportedip-hive' ) . '</span>';
		} elseif ( $this->can_terminate_single ) {
			$buttons[] = sprintf(
				'<button type="submit" class="rip-button rip-button--danger rip-button--sm" name="rip_terminate" value="%s">%s</button>',
				esc_attr( $item['user']->ID . ':' . $item['verifier'] ),
				esc_html__( 'End session', 'reportedip-hive' )
			);
		}

		if ( ! empty( $item['first'] ) ) {
			$label     = get_current_user_id() === (int) $item['user']->ID
				? __( 'End all other sessions', 'reportedip-hive' )
				: __( 'End all sessions', 'reportedip-hive' );
			$buttons[] = sprintf(
				'<button type="submit" class="rip-button rip-button--secondary rip-button--sm" name="rip_terminate_user" value="%d">%s</button>',
				(int) $item['user']->ID,
				esc_html( $label )
			);
		}

		return implode( ' ', $buttons );
	}

	/**
	 * Whether the row is the requesting browser's own session.
	 *
	 * @param array $item Row.
	 * @return bool
	 * @since  2.1.51
	 */
	private function is_own_current( array $item ) {
		return get_current_user_id() === (int) $item['user']->ID
			&& '' !== $this->own_verifier
			&& $this->own_verifier === $item['verifier'];
	}

	/**
	 * Render a UNIX timestamp in the site timezone.
	 *
	 * @param int $timestamp UNIX timestamp.
	 * @return string
	 * @since  2.1.51
	 */
	private function format_timestamp( $timestamp ) {
		$timestamp = (int) $timestamp;
		if ( $timestamp <= 0 ) {
			return '—';
		}
		return ReportedIP_Hive::format_local_datetime( gmdate( 'Y-m-d H:i:s', $timestamp ) );
	}

	/**
	 * Search and IP filter controls.
	 *
	 * @param string $which Table position.
	 * @return void
	 * @since  2.1.51
	 */
	protected function extra_tablenav( $which ) {
		if ( 'top' !== $which ) {
			return;
		}
		$search = isset( $_REQUEST['s'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) : '';
		$ip     = isset( $_REQUEST['session_ip'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['session_ip'] ) ) : '';
		?>
		<div class="alignleft actions">
			<input type="search" name="s" value="<?php echo esc_attr( $search ); ?>" placeholder="<?php esc_attr_e( 'User', 'reportedip-hive' ); ?>" />
			<input type="search" name="session_ip" value="<?php echo esc_attr( $ip ); ?>" placeholder="<?php esc_attr_e( 'IP address', 'reportedip-hive' ); ?>" />
			<?php submit_button( __( 'Filter', 'reportedip-hive' ), 'button', 'filter_sessions', false ); ?>
		</div>
		<?php
	}

	/**
	 * Load one page of session owners and flatten their live sessions.
	 *
	 * Users whose stored sessions have all expired are skipped: core purges
	 * the meta lazily, so the row can still exist long after the last sign-out.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function prepare_items() {
		$per_page = $this->get_items_per_page( 'sessions_users_per_page', 20 );
		$filters  = array(
			'search'  => isset( $_REQUEST['s'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) : '',
			'ip'      => isset( $_REQUEST['session_ip'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['session_ip'] ) ) : '',
			'orderby' => isset( $_REQUEST['orderby'] ) ? sanitize_key( wp_unslash( $_REQUEST['orderby'] ) ) : '',
			'order'   => isset( $_REQUEST['order'] ) ? sanitize_key( wp_unslash( $_REQUEST['order'] ) ) : '',
		);

		$query = new WP_User_Query(
			ReportedIP_Hive_User_Sessions::users_query_args(
				$filters,
				$per_page,
				$this->get_pagenum(),
				is_multisite() ? 0 : get_current_blog_id()
			)
		);

		$items = array();
		foreach ( (array) $query->get_results() as $user ) {
			$first = true;
			foreach ( ReportedIP_Hive_User_Sessions::for_user( $user->ID ) as $verifier => $session ) {
				$items[] = array(
					'user'     => $user,
					'verifier' => (string) $verifier,
					'session'  => $session,
					'first'    => $first,
				);
				$first   = false;
			}
		}
		$this->items = $items;

		$total = (int) $query->get_total();
		$this->set_pagination_args(
			array(
				'total_items' => $total,
				'per_page'    => $per_page,
				'total_pages' => $per_page > 0 ? (int) ceil( $total / $per_page ) : 1,
			)
		);

		$this->_column_headers = array( $this->get_columns(), array(), $this->get_sortable_columns() );
	}

	/**
	 * Empty-state message.
	 *
	 * @return void
	 * @since  2.1.51
	 */
	public function no_items() {
		esc_html_e( 'Nobody is signed in right now.', 'reportedip-hive' );
	}
}
