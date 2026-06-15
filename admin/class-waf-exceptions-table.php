<?php
/**
 * WAF Exceptions List Table for ReportedIP Hive.
 *
 * Implements WP_List_Table for the backend-managed WAF allowlist
 * (rule/group/whole-path exceptions) with pagination and bulk removal.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.9
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

/**
 * Renders the WAF exceptions admin table.
 *
 * @since 2.1.9
 */
class ReportedIP_Hive_WAF_Exceptions_Table extends WP_List_Table {

	/**
	 * Database service.
	 *
	 * @var ReportedIP_Hive_Database
	 */
	private $database;

	/**
	 * Constructor.
	 *
	 * @since 2.1.9
	 */
	public function __construct() {
		parent::__construct(
			array(
				'singular' => __( 'WAF Exception', 'reportedip-hive' ),
				'plural'   => __( 'WAF Exceptions', 'reportedip-hive' ),
				'ajax'     => false,
			)
		);

		$this->database = ReportedIP_Hive_Database::get_instance();
	}

	/**
	 * Table columns.
	 *
	 * @return array<string,string>
	 * @since  2.1.9
	 */
	public function get_columns() {
		return array(
			'cb'          => '<input type="checkbox" />',
			'scope'       => __( 'Scope', 'reportedip-hive' ),
			'rule_id'     => __( 'Rule / Group', 'reportedip-hive' ),
			'path_prefix' => __( 'Path', 'reportedip-hive' ),
			'ip_address'  => __( 'IP', 'reportedip-hive' ),
			'reason'      => __( 'Reason', 'reportedip-hive' ),
			'source'      => __( 'Source', 'reportedip-hive' ),
			'created_at'  => __( 'Added', 'reportedip-hive' ),
			'actions'     => __( 'Actions', 'reportedip-hive' ),
		);
	}

	/**
	 * Bulk actions.
	 *
	 * @return array<string,string>
	 * @since  2.1.9
	 */
	protected function get_bulk_actions() {
		return array(
			'remove' => __( 'Remove', 'reportedip-hive' ),
		);
	}

	/**
	 * Checkbox column.
	 *
	 * @param \stdClass $item Exception row.
	 * @return string
	 * @since  2.1.9
	 */
	protected function column_cb( $item ) {
		return sprintf(
			'<input type="checkbox" name="exception_ids[]" value="%d" />',
			(int) $item->id
		);
	}

	/**
	 * Default column rendering.
	 *
	 * @param \stdClass $item        Exception row.
	 * @param string    $column_name Column key.
	 * @return string
	 * @since  2.1.9
	 */
	protected function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'scope':
				$labels = array(
					'rule'  => __( 'Rule', 'reportedip-hive' ),
					'group' => __( 'Group', 'reportedip-hive' ),
					'all'   => __( 'Whole engine', 'reportedip-hive' ),
				);
				$scope  = isset( $item->scope ) ? (string) $item->scope : 'rule';
				return esc_html( $labels[ $scope ] ?? $scope );

			case 'rule_id':
				return '' !== (string) ( $item->rule_id ?? '' )
					? '<code>' . esc_html( (string) $item->rule_id ) . '</code>'
					: '<span aria-hidden="true">—</span>';

			case 'path_prefix':
				return '' !== (string) ( $item->path_prefix ?? '' )
					? '<code>' . esc_html( (string) $item->path_prefix ) . '</code>'
					: '<span aria-hidden="true">—</span>';

			case 'ip_address':
				return '' !== (string) ( $item->ip_address ?? '' )
					? '<code>' . esc_html( (string) $item->ip_address ) . '</code>'
					: '<span aria-hidden="true">—</span>';

			case 'reason':
				return esc_html( (string) ( $item->reason ?? '' ) );

			case 'source':
				return esc_html( (string) ( $item->source ?? 'manual' ) );

			case 'created_at':
				return esc_html( (string) ( $item->created_at ?? '' ) );

			case 'actions':
				return sprintf(
					'<button class="button button-small remove-waf-exception button-danger" data-id="%d" title="%s"><span class="dashicons dashicons-trash"></span> %s</button>',
					(int) $item->id,
					esc_attr__( 'Remove exception', 'reportedip-hive' ),
					esc_html__( 'Remove', 'reportedip-hive' )
				);

			default:
				return '';
		}
	}

	/**
	 * Prepare items for display.
	 *
	 * @return void
	 * @since  2.1.9
	 */
	public function prepare_items() {
		global $wpdb;

		$table_name = $wpdb->base_prefix . 'reportedip_hive_waf_exceptions';

		$where = array( 'is_active = 1' );
		if ( ! empty( $_REQUEST['scope'] ) ) {
			$scope = sanitize_key( wp_unslash( $_REQUEST['scope'] ) );
			if ( in_array( $scope, array( 'rule', 'group', 'all' ), true ) ) {
				$where[] = $wpdb->prepare( 'scope = %s', $scope );
			}
		}
		$where_clause = implode( ' AND ', $where );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name composed from $wpdb->base_prefix and a hardcoded suffix; WHERE built from prepared fragments.
		$items = $wpdb->get_results( "SELECT * FROM {$table_name} WHERE {$where_clause} ORDER BY created_at DESC" );

		$this->items           = is_array( $items ) ? $items : array();
		$columns               = $this->get_columns();
		$this->_column_headers = array( $columns, array(), array() );
	}

	/**
	 * Process bulk removal.
	 *
	 * @return void
	 * @since  2.1.9
	 */
	public function process_bulk_action() {
		if ( 'remove' !== $this->current_action() ) {
			return;
		}
		if ( ! isset( $_POST['exception_ids'] ) || ! is_array( $_POST['exception_ids'] ) ) {
			return;
		}

		$nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $nonce, 'bulk-' . $this->_args['plural'] ) ) {
			return;
		}

		$ids = array_map( 'absint', wp_unslash( $_POST['exception_ids'] ) );
		foreach ( $ids as $id ) {
			if ( $id > 0 ) {
				$this->database->remove_waf_exception( $id );
			}
		}
	}

	/**
	 * Scope filter control.
	 *
	 * @param string $which Tablenav position.
	 * @return void
	 * @since  2.1.9
	 */
	protected function extra_tablenav( $which ) {
		if ( 'top' !== $which ) {
			return;
		}

		$scope = isset( $_REQUEST['scope'] ) ? sanitize_key( wp_unslash( $_REQUEST['scope'] ) ) : '';
		?>
		<div class="alignleft actions">
			<select name="scope">
				<option value=""><?php esc_html_e( 'All scopes', 'reportedip-hive' ); ?></option>
				<option value="rule" <?php selected( $scope, 'rule' ); ?>><?php esc_html_e( 'Rule', 'reportedip-hive' ); ?></option>
				<option value="group" <?php selected( $scope, 'group' ); ?>><?php esc_html_e( 'Group', 'reportedip-hive' ); ?></option>
				<option value="all" <?php selected( $scope, 'all' ); ?>><?php esc_html_e( 'Whole engine', 'reportedip-hive' ); ?></option>
			</select>
			<?php submit_button( __( 'Filter', 'reportedip-hive' ), '', 'filter_action', false ); ?>
		</div>
		<?php
	}

	/**
	 * Empty-state message.
	 *
	 * @return void
	 * @since  2.1.9
	 */
	public function no_items() {
		esc_html_e( 'No WAF exceptions yet. Add one from a blocked request in the Activity log, or with the form above.', 'reportedip-hive' );
	}
}
