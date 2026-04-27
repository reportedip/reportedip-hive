<?php
/**
 * Security Logs List Table for ReportedIP Hive.
 *
 * Implements WP_List_Table for security logs with pagination,
 * sorting, searching, and bulk actions.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.0.0
 *
 * @phpcs:disable WordPress.Security.NonceVerification.Recommended -- WP_List_Table handles nonces via _wpnonce
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
 * @phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table names are safe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class ReportedIP_Hive_Logs_Table extends WP_List_Table {

	private $logger;

	public function __construct() {
		parent::__construct(
			array(
				'singular' => __( 'Log Entry', 'reportedip-hive' ),
				'plural'   => __( 'Log Entries', 'reportedip-hive' ),
				'ajax'     => false,
			)
		);

		$this->logger = ReportedIP_Hive_Logger::get_instance();
	}

	/**
	 * Get table columns
	 */
	public function get_columns() {
		return array(
			'cb'         => '<input type="checkbox" />',
			'created_at' => __( 'Time', 'reportedip-hive' ),
			'event_type' => __( 'Event Type', 'reportedip-hive' ),
			'ip_address' => __( 'IP Address', 'reportedip-hive' ),
			'severity'   => __( 'Severity', 'reportedip-hive' ),
			'details'    => __( 'Details', 'reportedip-hive' ),
			'actions'    => __( 'Actions', 'reportedip-hive' ),
		);
	}

	/**
	 * Sortable columns
	 */
	protected function get_sortable_columns() {
		return array(
			'created_at' => array( 'created_at', true ),
			'event_type' => array( 'event_type', false ),
			'ip_address' => array( 'ip_address', false ),
			'severity'   => array( 'severity', false ),
		);
	}

	/**
	 * Bulk actions
	 */
	protected function get_bulk_actions() {
		return array(
			'delete'    => __( 'Delete', 'reportedip-hive' ),
			'block'     => __( 'Block IP', 'reportedip-hive' ),
			'whitelist' => __( 'Whitelist IP', 'reportedip-hive' ),
		);
	}

	/**
	 * Checkbox column
	 *
	 * @param \stdClass $item Log row from database.
	 * @return string
	 */
	protected function column_cb( $item ) {
		return sprintf(
			'<input type="checkbox" name="log_ids[]" value="%s" />',
			$item->id
		);
	}

	/**
	 * Default column rendering
	 *
	 * @param \stdClass $item        Log row from database.
	 * @param string    $column_name Column name.
	 * @return string
	 */
	protected function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'created_at':
				return esc_html( $item->created_at );

			case 'event_type':
				$event_type  = $item->event_type ?? '';
				$event_class = str_replace( '_', '-', $event_type );
				$event_label = ucwords( str_replace( '_', ' ', $event_type ) );
				return sprintf(
					'<span class="event-type-badge %s">%s</span>',
					esc_attr( $event_class ),
					esc_html( $event_label )
				);

			case 'ip_address':
				return sprintf(
					'<code class="ip-address" title="%s">%s</code>
                     <button type="button" class="button-link copy-ip" data-ip="%s" title="%s">
                         <span class="dashicons dashicons-clipboard"></span>
                     </button>',
					esc_attr__( 'Click to copy', 'reportedip-hive' ),
					esc_html( $item->ip_address ),
					esc_attr( $item->ip_address ),
					esc_attr__( 'Copy IP', 'reportedip-hive' )
				);

			case 'severity':
				$severity = $item->severity ?? 'medium';
				return sprintf(
					'<span class="severity-%s">%s</span>',
					esc_attr( $severity ),
					esc_html( ucfirst( $severity ) )
				);

			case 'details':
				return wp_kses_post( $this->logger->format_details( $item->details ) );

			case 'actions':
				$actions  = '<div class="action-buttons-inline">';
				$actions .= sprintf(
					'<button class="button button-small lookup-ip" data-ip="%s" title="%s"><span class="dashicons dashicons-search"></span></button>',
					esc_attr( $item->ip_address ),
					esc_attr__( 'Lookup IP', 'reportedip-hive' )
				);
				$actions .= sprintf(
					'<button class="button button-small block-ip button-danger" data-ip="%s" title="%s"><span class="dashicons dashicons-dismiss"></span></button>',
					esc_attr( $item->ip_address ),
					esc_attr__( 'Block IP', 'reportedip-hive' )
				);
				$actions .= sprintf(
					'<button class="button button-small whitelist-ip button-success" data-ip="%s" title="%s"><span class="dashicons dashicons-yes-alt"></span></button>',
					esc_attr( $item->ip_address ),
					esc_attr__( 'Whitelist IP', 'reportedip-hive' )
				);
				$actions .= '</div>';
				return $actions;

			default:
				return '';
		}
	}

	/**
	 * Get logs data
	 */
	private function get_logs_data( $per_page, $current_page ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_logs';
		$orderby    = isset( $_REQUEST['orderby'] ) ? sanitize_sql_orderby( wp_unslash( $_REQUEST['orderby'] ) ) : 'created_at';
		$order_raw  = isset( $_REQUEST['order'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['order'] ) ) : 'DESC';
		$order      = in_array( strtoupper( $order_raw ), array( 'ASC', 'DESC' ), true ) ? strtoupper( $order_raw ) : 'DESC';

		$allowed_columns = array( 'created_at', 'event_type', 'ip_address', 'severity' );
		if ( ! in_array( $orderby, $allowed_columns, true ) ) {
			$orderby = 'created_at';
		}

		$where = array( '1=1' );

		if ( ! empty( $_REQUEST['event_type'] ) ) {
			$event_type = sanitize_text_field( wp_unslash( $_REQUEST['event_type'] ) );
			$where[]    = $wpdb->prepare( 'event_type = %s', $event_type );
		}

		if ( ! empty( $_REQUEST['severity'] ) ) {
			$severity = sanitize_text_field( wp_unslash( $_REQUEST['severity'] ) );
			$where[]  = $wpdb->prepare( 'severity = %s', $severity );
		}

		if ( ! empty( $_REQUEST['s'] ) ) {
			$search  = '%' . $wpdb->esc_like( sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) ) . '%';
			$where[] = $wpdb->prepare( '(ip_address LIKE %s OR details LIKE %s)', $search, $search );
		}

		$where_clause = implode( ' AND ', $where );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name composed from $wpdb->prefix and a hardcoded suffix; WHERE clause built from $wpdb->prepare() fragments.
		$total = $wpdb->get_var( "SELECT COUNT(*) FROM {$table_name} WHERE {$where_clause}" );

		$offset = ( $current_page - 1 ) * $per_page;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name composed from $wpdb->prefix and a hardcoded suffix; ORDER BY column from allowlist, integer values cast.
		$results = $wpdb->get_results(
			"SELECT * FROM {$table_name} WHERE {$where_clause} ORDER BY {$orderby} {$order} LIMIT {$per_page} OFFSET {$offset}"
		);

		return array(
			'items' => $results,
			'total' => (int) $total,
		);
	}

	/**
	 * Prepare items for display
	 */
	public function prepare_items() {
		$per_page     = $this->get_items_per_page( 'logs_per_page', 25 );
		$current_page = $this->get_pagenum();

		$data = $this->get_logs_data( $per_page, $current_page );

		$this->items = $data['items'];

		$this->set_pagination_args(
			array(
				'total_items' => (int) $data['total'],
				'per_page'    => (int) $per_page,
				'total_pages' => $per_page > 0 ? (int) ceil( $data['total'] / $per_page ) : 1,
			)
		);

		$columns  = $this->get_columns();
		$hidden   = array();
		$sortable = $this->get_sortable_columns();

		$this->_column_headers = array( $columns, $hidden, $sortable );
	}

	/**
	 * Process bulk actions
	 */
	public function process_bulk_action() {
		if ( ! isset( $_POST['log_ids'] ) || ! is_array( $_POST['log_ids'] ) ) {
			return;
		}

		$nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'bulk-' . $this->_args['plural'] ) ) {
			return;
		}

		$log_ids = array_map( 'intval', $_POST['log_ids'] );
		$action  = $this->current_action();

		if ( $action === 'delete' ) {
			global $wpdb;
			$table_name      = $wpdb->prefix . 'reportedip_hive_logs';
			$ids_placeholder = implode( ',', array_fill( 0, count( $log_ids ), '%d' ) );
			// phpcs:disable WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dynamic placeholder count; table name composed from $wpdb->prefix and a hardcoded suffix.
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$table_name} WHERE id IN ({$ids_placeholder})",
					...$log_ids
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
		}

		if ( $action === 'block' || $action === 'whitelist' ) {
			global $wpdb;
			$table_name      = $wpdb->prefix . 'reportedip_hive_logs';
			$ids_placeholder = implode( ',', array_fill( 0, count( $log_ids ), '%d' ) );
			// phpcs:disable WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Dynamic placeholder count; table name composed from $wpdb->prefix and a hardcoded suffix.
			$ips = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT DISTINCT ip_address FROM {$table_name} WHERE id IN ({$ids_placeholder})",
					...$log_ids
				)
			);
			// phpcs:enable WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter

			$ip_manager = ReportedIP_Hive_IP_Manager::get_instance();
			foreach ( $ips as $ip ) {
				if ( $action === 'block' ) {
					$ip_manager->block_ip( $ip, __( 'Blocked from bulk action', 'reportedip-hive' ) );
				} else {
					$ip_manager->add_to_whitelist( $ip, __( 'Added from bulk action', 'reportedip-hive' ) );
				}
			}
		}
	}

	/**
	 * Display extra filter controls
	 */
	protected function extra_tablenav( $which ) {
		if ( $which !== 'top' ) {
			return;
		}

		$event_type = isset( $_REQUEST['event_type'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['event_type'] ) ) : '';
		$severity   = isset( $_REQUEST['severity'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['severity'] ) ) : '';
		?>
		<div class="alignleft actions">
			<select name="event_type">
				<option value=""><?php esc_html_e( 'All Event Types', 'reportedip-hive' ); ?></option>
				<option value="failed_login" <?php selected( $event_type, 'failed_login' ); ?>><?php esc_html_e( 'Failed Login', 'reportedip-hive' ); ?></option>
				<option value="comment_spam" <?php selected( $event_type, 'comment_spam' ); ?>><?php esc_html_e( 'Comment Spam', 'reportedip-hive' ); ?></option>
				<option value="xmlrpc_abuse" <?php selected( $event_type, 'xmlrpc_abuse' ); ?>><?php esc_html_e( 'XMLRPC Abuse', 'reportedip-hive' ); ?></option>
				<option value="ip_blocked" <?php selected( $event_type, 'ip_blocked' ); ?>><?php esc_html_e( 'IP Blocked', 'reportedip-hive' ); ?></option>
			</select>

			<select name="severity">
				<option value=""><?php esc_html_e( 'All Severities', 'reportedip-hive' ); ?></option>
				<option value="low" <?php selected( $severity, 'low' ); ?>><?php esc_html_e( 'Low', 'reportedip-hive' ); ?></option>
				<option value="medium" <?php selected( $severity, 'medium' ); ?>><?php esc_html_e( 'Medium', 'reportedip-hive' ); ?></option>
				<option value="high" <?php selected( $severity, 'high' ); ?>><?php esc_html_e( 'High', 'reportedip-hive' ); ?></option>
				<option value="critical" <?php selected( $severity, 'critical' ); ?>><?php esc_html_e( 'Critical', 'reportedip-hive' ); ?></option>
			</select>

			<?php submit_button( __( 'Filter', 'reportedip-hive' ), '', 'filter_action', false ); ?>
		</div>
		<?php
	}

	/**
	 * Message when no items found
	 */
	public function no_items() {
		esc_html_e( 'No log entries found.', 'reportedip-hive' );
	}
}
