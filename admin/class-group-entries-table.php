<?php
/**
 * Group list table for ReportedIP Hive.
 *
 * Shows the group ban list exactly as the service sent it, one row per
 * entry, with the member that reported it, the categories, the window and
 * what this site made of it. The local status is worked out on render, so a
 * block lifted or an address whitelisted in between shows up at once.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.67
 *
 * @phpcs:disable WordPress.Security.NonceVerification.Recommended -- Read-only filters, no data modification.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Class ReportedIP_Hive_Group_Entries_Table
 *
 * @since 2.1.67
 */
class ReportedIP_Hive_Group_Entries_Table extends WP_List_Table {

	/**
	 * Category id to name, from the cached category list.
	 *
	 * @var array<int,string>
	 */
	private $category_names = array();

	/**
	 * Constructor.
	 */
	public function __construct() {
		parent::__construct(
			array(
				'singular' => __( 'Group entry', 'reportedip-hive' ),
				'plural'   => __( 'Group entries', 'reportedip-hive' ),
				'ajax'     => false,
			)
		);

		$cached = get_transient( 'reportedip_hive_categories' );
		if ( ! is_array( $cached ) && ReportedIP_Hive_Mode_Manager::get_instance()->is_community_mode() && false === get_transient( 'reportedip_hive_categories_refresh_lock' ) ) {
			set_transient( 'reportedip_hive_categories_refresh_lock', true, HOUR_IN_SECONDS );
			$cached = ReportedIP_Hive_API::get_instance()->get_categories();
			if ( is_array( $cached ) && ! empty( $cached ) ) {
				set_transient( 'reportedip_hive_categories', $cached, DAY_IN_SECONDS );
			}
		}
		foreach ( is_array( $cached ) ? $cached : array() as $category ) {
			if ( is_array( $category ) && isset( $category['id'], $category['name'] ) ) {
				$this->category_names[ (int) $category['id'] ] = (string) $category['name'];
			}
		}
	}

	/**
	 * Table columns.
	 *
	 * @return array<string,string>
	 */
	public function get_columns() {
		return array(
			'ip_address' => __( 'IP Address', 'reportedip-hive' ),
			'status'     => __( 'On this site', 'reportedip-hive' ),
			'reporter'   => __( 'Reported by', 'reportedip-hive' ),
			'categories' => __( 'Categories', 'reportedip-hive' ),
			'since'      => __( 'Listed since', 'reportedip-hive' ),
			'expires'    => __( 'Listed until', 'reportedip-hive' ),
		);
	}

	/**
	 * Labels and badge variants of the local status, in the order the sync
	 * checks them.
	 *
	 * @return array<string,array{0:string,1:string}>
	 */
	public static function status_labels() {
		return array(
			'group'       => array( __( 'Blocked by the group', 'reportedip-hive' ), 'success' ),
			'other'       => array( __( 'Already blocked by another rule', 'reportedip-hive' ), 'info' ),
			'expired'     => array( __( 'Window over, drops with the next list', 'reportedip-hive' ), 'neutral' ),
			'whitelisted' => array( __( 'Not blocked: on the whitelist', 'reportedip-hive' ), 'neutral' ),
			'own'         => array( __( 'Not blocked: address of this server', 'reportedip-hive' ), 'warning' ),
			'report_only' => array( __( 'Not blocked: report-only mode', 'reportedip-hive' ), 'warning' ),
			'lifted'      => array( __( 'Not blocked: lifted by hand, returns with the next list change', 'reportedip-hive' ), 'warning' ),
		);
	}

	/**
	 * Render one cell.
	 *
	 * @param \stdClass $item        Row of get_group_entries().
	 * @param string    $column_name Column.
	 * @return string
	 */
	protected function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'ip_address':
				$cell = ReportedIP_Hive_IP_Cell::render( (string) $item->ip_address, array( 'strong' => true ) );
				if ( 'manual' === (string) $item->origin ) {
					$cell .= ' <span class="rip-badge rip-badge--neutral">' . esc_html__( 'Added in the account', 'reportedip-hive' ) . '</span>';
				}
				return $cell;

			case 'status':
				return $this->status_cell( $item );

			case 'reporter':
				return esc_html( '' !== (string) $item->reporter ? (string) $item->reporter : __( 'Unknown member', 'reportedip-hive' ) );

			case 'categories':
				$ids = array_filter( array_map( 'intval', explode( ',', (string) $item->categories ) ) );
				if ( empty( $ids ) ) {
					return '<span class="description">' . esc_html__( 'None', 'reportedip-hive' ) . '</span>';
				}
				$names = array();
				foreach ( $ids as $id ) {
					$names[] = $this->category_names[ $id ] ?? '#' . $id;
				}
				return esc_html( implode( ', ', $names ) );

			case 'since':
			case 'expires':
				$value = (string) ( $item->$column_name ?? '' );
				return '' === $value ? '' : esc_html( ReportedIP_Hive::format_local_datetime( $value ) );
		}
		return '';
	}

	/**
	 * Badge plus the local block's expiry where one exists.
	 *
	 * @param \stdClass $item Row.
	 * @return string
	 */
	private function status_cell( $item ) {
		$ip_manager = ReportedIP_Hive_IP_Manager::get_instance();
		$ip         = (string) $item->ip_address;
		$type       = (string) ( $item->block_type ?? '' );
		$expires    = ! empty( $item->expires ) ? (int) strtotime( (string) $item->expires . ' UTC' ) : 0;

		$key = ReportedIP_Hive_Group_Sync::local_status(
			$type,
			$expires,
			'' === $type && $ip_manager->is_whitelisted( $ip ),
			'' === $type && ReportedIP_Hive::is_own_server_ip( $ip ),
			(bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ),
			time()
		);

		$labels = self::status_labels();
		$html   = sprintf( '<span class="rip-badge rip-badge--%1$s">%2$s</span>', esc_attr( $labels[ $key ][1] ), esc_html( $labels[ $key ][0] ) );

		if ( '' !== $type && ! empty( $item->blocked_until ) ) {
			$html .= '<br /><span class="description">' . esc_html(
				sprintf(
					/* translators: %s: local date and time */
					__( 'until %s', 'reportedip-hive' ),
					ReportedIP_Hive::format_local_datetime( (string) $item->blocked_until )
				)
			) . '</span>';
		}
		if ( 'other' === $key ) {
			$html .= '<br /><span class="description">' . esc_html( $type ) . '</span>';
		}
		return $html;
	}

	/**
	 * Load the current page.
	 *
	 * @return void
	 */
	public function prepare_items() {
		$per_page = $this->get_items_per_page( 'group_entries_per_page', 25 );
		$args     = $this->filter_args();
		$database = ReportedIP_Hive_Database::get_instance();

		$total       = (int) $database->get_group_entries( array_merge( $args, array( 'count' => true ) ) );
		$this->items = $database->get_group_entries(
			array_merge(
				$args,
				array(
					'per_page' => $per_page,
					'offset'   => ( $this->get_pagenum() - 1 ) * $per_page,
				)
			)
		);

		$this->_column_headers = array( $this->get_columns(), array(), array() );
		$this->set_pagination_args(
			array(
				'total_items' => $total,
				'per_page'    => (int) $per_page,
				'total_pages' => $per_page > 0 ? (int) ceil( $total / $per_page ) : 1,
			)
		);
	}

	/**
	 * Filter values from the request.
	 *
	 * @return array{search:string,reporter:string,status:string}
	 */
	private function filter_args() {
		$status = isset( $_REQUEST['group_status'] ) ? sanitize_key( wp_unslash( $_REQUEST['group_status'] ) ) : '';
		return array(
			'search'   => isset( $_REQUEST['s'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) : '',
			'reporter' => isset( $_REQUEST['reporter'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['reporter'] ) ) : '',
			'status'   => in_array( $status, array( 'group', 'other', 'none' ), true ) ? $status : '',
		);
	}

	/**
	 * Filter bar above the table.
	 *
	 * @return void
	 */
	public function render_filters() {
		$args      = $this->filter_args();
		$reporters = ReportedIP_Hive_Database::get_instance()->get_group_reporters();

		ReportedIP_Hive_Filter_Bar::open(
			array(
				'page' => 'reportedip-hive-security',
				'tab'  => 'ip_lists',
				'sub'  => 'group',
			)
		);
		ReportedIP_Hive_Filter_Bar::field(
			'rip-group-search',
			__( 'Search', 'reportedip-hive' ),
			sprintf(
				'<input type="search" id="rip-group-search" name="s" class="rip-input" value="%s" placeholder="%s" />',
				esc_attr( $args['search'] ),
				esc_attr__( 'IP address', 'reportedip-hive' )
			)
		);
		?>
		<div class="rip-filter-bar__field">
			<label class="rip-filter-bar__label" for="rip-group-status"><?php esc_html_e( 'On this site', 'reportedip-hive' ); ?></label>
			<select name="group_status" id="rip-group-status" class="rip-select">
				<option value=""><?php esc_html_e( 'All entries', 'reportedip-hive' ); ?></option>
				<option value="group" <?php selected( $args['status'], 'group' ); ?>><?php esc_html_e( 'Blocked by the group', 'reportedip-hive' ); ?></option>
				<option value="other" <?php selected( $args['status'], 'other' ); ?>><?php esc_html_e( 'Already blocked by another rule', 'reportedip-hive' ); ?></option>
				<option value="none" <?php selected( $args['status'], 'none' ); ?>><?php esc_html_e( 'Not blocked', 'reportedip-hive' ); ?></option>
			</select>
		</div>
		<div class="rip-filter-bar__field">
			<label class="rip-filter-bar__label" for="rip-group-reporter"><?php esc_html_e( 'Reported by', 'reportedip-hive' ); ?></label>
			<select name="reporter" id="rip-group-reporter" class="rip-select">
				<option value=""><?php esc_html_e( 'All members', 'reportedip-hive' ); ?></option>
				<?php foreach ( $reporters as $reporter ) : ?>
					<option value="<?php echo esc_attr( $reporter ); ?>" <?php selected( $args['reporter'], $reporter ); ?>><?php echo esc_html( $reporter ); ?></option>
				<?php endforeach; ?>
			</select>
		</div>
		<?php
		ReportedIP_Hive_Filter_Bar::close( array( 's', 'group_status', 'reporter' ) );
	}

	/**
	 * Message for an empty list.
	 *
	 * @return void
	 */
	public function no_items() {
		esc_html_e( 'The group list is empty, or no entry matches the filters.', 'reportedip-hive' );
	}
}
