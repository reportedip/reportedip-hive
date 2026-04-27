<?php
/**
 * Whitelist List Table for ReportedIP Hive.
 *
 * Implements WP_List_Table for whitelisted IPs with pagination,
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

class ReportedIP_Hive_Whitelist_Table extends WP_List_Table {

	private $ip_manager;

	public function __construct() {
		parent::__construct(
			array(
				'singular' => __( 'Whitelisted IP', 'reportedip-hive' ),
				'plural'   => __( 'Whitelisted IPs', 'reportedip-hive' ),
				'ajax'     => false,
			)
		);

		$this->ip_manager = ReportedIP_Hive_IP_Manager::get_instance();
	}

	/**
	 * Get table columns
	 */
	public function get_columns() {
		return array(
			'cb'         => '<input type="checkbox" />',
			'ip_address' => __( 'IP Address', 'reportedip-hive' ),
			'ip_type'    => __( 'Type', 'reportedip-hive' ),
			'reason'     => __( 'Reason', 'reportedip-hive' ),
			'created_at' => __( 'Added', 'reportedip-hive' ),
			'expires_at' => __( 'Expires', 'reportedip-hive' ),
			'actions'    => __( 'Actions', 'reportedip-hive' ),
		);
	}

	/**
	 * Sortable columns
	 */
	protected function get_sortable_columns() {
		return array(
			'ip_address' => array( 'ip_address', false ),
			'ip_type'    => array( 'ip_type', false ),
			'created_at' => array( 'created_at', true ),
			'expires_at' => array( 'expires_at', false ),
		);
	}

	/**
	 * Bulk actions
	 */
	protected function get_bulk_actions() {
		return array(
			'remove' => __( 'Remove', 'reportedip-hive' ),
		);
	}

	/**
	 * Checkbox column
	 *
	 * @param \stdClass $item Whitelist row from database.
	 * @return string
	 */
	protected function column_cb( $item ) {
		return sprintf(
			'<input type="checkbox" name="ip_addresses[]" value="%s" />',
			esc_attr( $item->ip_address )
		);
	}

	/**
	 * Default column rendering
	 *
	 * @param \stdClass $item        Whitelist row from database.
	 * @param string    $column_name Column name.
	 * @return string
	 */
	protected function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'ip_address':
				return sprintf(
					'<strong><code class="ip-address">%s</code></strong>
                     <button type="button" class="button-link copy-ip" data-ip="%s" title="%s">
                         <span class="dashicons dashicons-clipboard"></span>
                     </button>',
					esc_html( $item->ip_address ),
					esc_attr( $item->ip_address ),
					esc_attr__( 'Copy IP', 'reportedip-hive' )
				);

			case 'ip_type':
				$ip_type = $item->ip_type ?? 'ipv4';
				return sprintf(
					'<span class="ip-type-badge %s">%s</span>',
					esc_attr( $ip_type ),
					esc_html( strtoupper( $ip_type ) )
				);

			case 'reason':
				return esc_html( $item->reason ?? '' );

			case 'created_at':
				return esc_html( $item->created_at );

			case 'expires_at':
				if ( empty( $item->expires_at ) ) {
					return '<span class="status-good">' . __( 'Never', 'reportedip-hive' ) . '</span>';
				}
				return esc_html( $item->expires_at );

			case 'actions':
				return sprintf(
					'<button class="button button-small remove-whitelist button-danger" data-ip="%s" title="%s"><span class="dashicons dashicons-trash"></span> %s</button>',
					esc_attr( $item->ip_address ),
					esc_attr__( 'Remove from whitelist', 'reportedip-hive' ),
					__( 'Remove', 'reportedip-hive' )
				);

			default:
				return '';
		}
	}

	/**
	 * Get whitelist data
	 */
	private function get_whitelist_data( $per_page, $current_page ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_whitelist';
		$orderby    = isset( $_REQUEST['orderby'] ) ? sanitize_sql_orderby( wp_unslash( $_REQUEST['orderby'] ) ) : 'created_at';
		$order_raw  = isset( $_REQUEST['order'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['order'] ) ) : 'DESC';
		$order      = in_array( strtoupper( $order_raw ), array( 'ASC', 'DESC' ), true ) ? strtoupper( $order_raw ) : 'DESC';

		$allowed_columns = array( 'ip_address', 'ip_type', 'created_at', 'expires_at' );
		if ( ! in_array( $orderby, $allowed_columns, true ) ) {
			$orderby = 'created_at';
		}

		$where = array( 'is_active = 1 AND (expires_at IS NULL OR expires_at > NOW())' );

		if ( ! empty( $_REQUEST['ip_type'] ) ) {
			$ip_type = sanitize_text_field( wp_unslash( $_REQUEST['ip_type'] ) );
			$where[] = $wpdb->prepare( 'ip_type = %s', $ip_type );
		}

		if ( ! empty( $_REQUEST['s'] ) ) {
			$search  = '%' . $wpdb->esc_like( sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) ) . '%';
			$where[] = $wpdb->prepare( '(ip_address LIKE %s OR reason LIKE %s)', $search, $search );
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
		$per_page     = $this->get_items_per_page( 'whitelist_per_page', 25 );
		$current_page = $this->get_pagenum();

		$data = $this->get_whitelist_data( $per_page, $current_page );

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
		if ( ! isset( $_POST['ip_addresses'] ) || ! is_array( $_POST['ip_addresses'] ) ) {
			return;
		}

		$nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'bulk-' . $this->_args['plural'] ) ) {
			return;
		}

		$ip_addresses = array_map( 'sanitize_text_field', wp_unslash( $_POST['ip_addresses'] ) );
		$action       = $this->current_action();

		if ( $action === 'remove' ) {
			foreach ( $ip_addresses as $ip ) {
				$this->ip_manager->remove_from_whitelist( $ip );
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

		$ip_type = isset( $_REQUEST['ip_type'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['ip_type'] ) ) : '';
		?>
		<div class="alignleft actions">
			<select name="ip_type">
				<option value=""><?php esc_html_e( 'All Types', 'reportedip-hive' ); ?></option>
				<option value="single" <?php selected( $ip_type, 'single' ); ?>><?php esc_html_e( 'Single IP', 'reportedip-hive' ); ?></option>
				<option value="cidr" <?php selected( $ip_type, 'cidr' ); ?>><?php esc_html_e( 'CIDR Range', 'reportedip-hive' ); ?></option>
			</select>

			<?php submit_button( __( 'Filter', 'reportedip-hive' ), '', 'filter_action', false ); ?>
		</div>
		<?php
	}

	/**
	 * Message when no items found
	 */
	public function no_items() {
		esc_html_e( 'No whitelisted IPs found.', 'reportedip-hive' );
	}
}
