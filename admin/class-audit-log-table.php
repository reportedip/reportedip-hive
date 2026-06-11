<?php
/**
 * Audit-log list table for ReportedIP Hive.
 *
 * Read-only WP_List_Table over the `audit_log` table: pagination, sorting and
 * filtering by event type, user, IP and date range. The trail is append-only,
 * so there are no bulk mutation actions. On Multisite a site administrator is
 * automatically scoped to the current blog; a network administrator sees the
 * whole network.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.2
 *
 * @phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filter/sort query args; no state change.
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
 * @phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name from base_prefix; ORDER BY column/dir whitelisted.
 * @phpcs:disable WordPress.DB.PreparedSQL.NotPrepared -- Filtered count/select use $wpdb->prepare with bound params; the no-filter count path is a constant query.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Renders the audit event trail as a sortable, filterable table.
 *
 * @since 2.1.2
 */
class ReportedIP_Hive_Audit_Log_Table extends WP_List_Table {

	/**
	 * Constructor.
	 *
	 * @since 2.1.2
	 */
	public function __construct() {
		parent::__construct(
			array(
				'singular' => __( 'Audit Entry', 'reportedip-hive' ),
				'plural'   => __( 'Audit Entries', 'reportedip-hive' ),
				'ajax'     => false,
			)
		);
	}

	/**
	 * Column definitions.
	 *
	 * @return array<string,string>
	 * @since  2.1.2
	 */
	public function get_columns() {
		return array(
			'created_at'   => __( 'Time', 'reportedip-hive' ),
			'username'     => __( 'User', 'reportedip-hive' ),
			'event_type'   => __( 'Event', 'reportedip-hive' ),
			'event_action' => __( 'Action', 'reportedip-hive' ),
			'ip'           => __( 'IP Address', 'reportedip-hive' ),
			'event_data'   => __( 'Details', 'reportedip-hive' ),
		);
	}

	/**
	 * Sortable columns.
	 *
	 * @return array<string,array{0:string,1:bool}>
	 * @since  2.1.2
	 */
	protected function get_sortable_columns() {
		return array(
			'created_at' => array( 'created_at', true ),
			'event_type' => array( 'event_type', false ),
			'username'   => array( 'username', false ),
		);
	}

	/**
	 * Render a cell.
	 *
	 * @param object $item        Audit row.
	 * @param string $column_name Column key.
	 * @return string
	 * @since  2.1.2
	 */
	protected function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'created_at':
				return esc_html( (string) $item->created_at );

			case 'username':
				$name = (string) ( $item->username ?? '' );
				if ( '' === $name && ! empty( $item->user_id ) ) {
					$name = '#' . (int) $item->user_id;
				}
				return esc_html( '' === $name ? '—' : $name );

			case 'event_type':
				return '<span class="rip-badge rip-badge--neutral">' . esc_html( ucwords( str_replace( '_', ' ', (string) $item->event_type ) ) ) . '</span>';

			case 'event_action':
				$action = (string) $item->event_action;
				$class  = 'rip-badge--info';
				if ( in_array( $action, array( 'failed' ), true ) ) {
					$class = 'rip-badge--danger';
				} elseif ( in_array( $action, array( 'new_ip', 'role_changed', 'email_changed' ), true ) ) {
					$class = 'rip-badge--warning';
				} elseif ( in_array( $action, array( 'success', 'completed' ), true ) ) {
					$class = 'rip-badge--success';
				}
				return '<span class="rip-badge ' . esc_attr( $class ) . '">' . esc_html( ucwords( str_replace( '_', ' ', $action ) ) ) . '</span>';

			case 'ip':
				return esc_html( '' !== (string) $item->ip ? (string) $item->ip : '—' );

			case 'event_data':
				return self::render_data( (string) ( $item->event_data ?? '' ) );

			default:
				return '';
		}
	}

	/**
	 * Render the JSON data blob as compact, escaped key/value lines.
	 *
	 * @param string $json Raw JSON from the row.
	 * @return string
	 * @since  2.1.2
	 */
	private static function render_data( $json ) {
		if ( '' === $json ) {
			return '—';
		}
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) || empty( $data ) ) {
			return '—';
		}
		$lines = array();
		foreach ( $data as $key => $value ) {
			if ( is_array( $value ) ) {
				$value = implode( ', ', array_map( 'strval', $value ) );
			}
			$lines[] = '<strong>' . esc_html( (string) $key ) . ':</strong> ' . esc_html( (string) $value );
		}
		return implode( '<br />', $lines );
	}

	/**
	 * Filter controls above the table.
	 *
	 * @param string $which Table position.
	 * @return void
	 * @since  2.1.2
	 */
	protected function extra_tablenav( $which ) {
		if ( 'top' !== $which ) {
			return;
		}
		$event_type = isset( $_REQUEST['event_type'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['event_type'] ) ) : '';
		$audit_user = isset( $_REQUEST['audit_user'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['audit_user'] ) ) : '';
		$audit_ip   = isset( $_REQUEST['audit_ip'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['audit_ip'] ) ) : '';
		$types      = array(
			''               => __( 'All events', 'reportedip-hive' ),
			'login'          => __( 'Login', 'reportedip-hive' ),
			'logout'         => __( 'Logout', 'reportedip-hive' ),
			'password_reset' => __( 'Password reset', 'reportedip-hive' ),
			'profile_change' => __( 'Profile change', 'reportedip-hive' ),
			'registration'   => __( 'Registration', 'reportedip-hive' ),
		);
		?>
		<div class="alignleft actions">
			<select name="event_type">
				<?php foreach ( $types as $value => $label ) : ?>
					<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $event_type, $value ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>
			<input type="search" name="audit_user" value="<?php echo esc_attr( $audit_user ); ?>" placeholder="<?php esc_attr_e( 'User', 'reportedip-hive' ); ?>" />
			<input type="search" name="audit_ip" value="<?php echo esc_attr( $audit_ip ); ?>" placeholder="<?php esc_attr_e( 'IP address', 'reportedip-hive' ); ?>" />
			<?php submit_button( __( 'Filter', 'reportedip-hive' ), 'button', 'filter_audit', false ); ?>
		</div>
		<?php
	}

	/**
	 * Load rows for the current page with the active filters applied.
	 *
	 * @return void
	 * @since  2.1.2
	 */
	public function prepare_items() {
		global $wpdb;

		$table    = $wpdb->base_prefix . ReportedIP_Hive_Audit_Logger::TABLE;
		$per_page = $this->get_items_per_page( 'audit_per_page', 25 );
		$page     = $this->get_pagenum();
		$offset   = ( $page - 1 ) * $per_page;

		$where  = array( '1=1' );
		$params = array();

		if ( is_multisite() && ! is_network_admin() ) {
			$where[]  = 'blog_id = %d';
			$params[] = get_current_blog_id();
		}

		$event_type = isset( $_REQUEST['event_type'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['event_type'] ) ) : '';
		if ( '' !== $event_type ) {
			$where[]  = 'event_type = %s';
			$params[] = $event_type;
		}
		$audit_user = isset( $_REQUEST['audit_user'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['audit_user'] ) ) : '';
		if ( '' !== $audit_user ) {
			$where[]  = 'username LIKE %s';
			$params[] = '%' . $wpdb->esc_like( $audit_user ) . '%';
		}
		$audit_ip = isset( $_REQUEST['audit_ip'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['audit_ip'] ) ) : '';
		if ( '' !== $audit_ip ) {
			$where[]  = 'ip = %s';
			$params[] = $audit_ip;
		}

		$where_sql = implode( ' AND ', $where );

		$orderby      = isset( $_REQUEST['orderby'] ) ? sanitize_key( wp_unslash( $_REQUEST['orderby'] ) ) : 'created_at';
		$allowed_cols = array( 'created_at', 'event_type', 'username' );
		if ( ! in_array( $orderby, $allowed_cols, true ) ) {
			$orderby = 'created_at';
		}
		$order = ( isset( $_REQUEST['order'] ) && 'asc' === strtolower( sanitize_key( wp_unslash( $_REQUEST['order'] ) ) ) ) ? 'ASC' : 'DESC';

		$count_sql = "SELECT COUNT(*) FROM $table WHERE $where_sql";
		$total     = empty( $params ) ? (int) $wpdb->get_var( $count_sql ) : (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) );

		$data_sql    = "SELECT * FROM $table WHERE $where_sql ORDER BY $orderby $order LIMIT %d OFFSET %d";
		$data_params = array_merge( $params, array( $per_page, $offset ) );
		$this->items = (array) $wpdb->get_results( $wpdb->prepare( $data_sql, $data_params ) );

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
	 * @since  2.1.2
	 */
	public function no_items() {
		esc_html_e( 'No audit events recorded yet.', 'reportedip-hive' );
	}
}
