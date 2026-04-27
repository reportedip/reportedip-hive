<?php
/**
 * API Queue List Table for ReportedIP Hive.
 *
 * Implements WP_List_Table for API report queue management with pagination,
 * sorting, searching, and bulk actions including retry functionality.
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

class ReportedIP_Hive_API_Queue_Table extends WP_List_Table {

	private $database;

	public function __construct() {
		parent::__construct(
			array(
				'singular' => __( 'Queue Item', 'reportedip-hive' ),
				'plural'   => __( 'Queue Items', 'reportedip-hive' ),
				'ajax'     => false,
			)
		);

		$this->database = ReportedIP_Hive_Database::get_instance();
	}

	/**
	 * Get table columns
	 */
	public function get_columns() {
		return array(
			'cb'            => '<input type="checkbox" />',
			'ip_address'    => __( 'IP Address', 'reportedip-hive' ),
			'category_ids'  => __( 'Categories', 'reportedip-hive' ),
			'status'        => __( 'Status', 'reportedip-hive' ),
			'priority'      => __( 'Priority', 'reportedip-hive' ),
			'attempts'      => __( 'Attempts', 'reportedip-hive' ),
			'error_message' => __( 'Error', 'reportedip-hive' ),
			'created_at'    => __( 'Created', 'reportedip-hive' ),
			'last_attempt'  => __( 'Last Attempt', 'reportedip-hive' ),
			'actions'       => __( 'Actions', 'reportedip-hive' ),
		);
	}

	/**
	 * Sortable columns
	 */
	protected function get_sortable_columns() {
		return array(
			'ip_address'   => array( 'ip_address', false ),
			'status'       => array( 'status', false ),
			'priority'     => array( 'priority', true ),
			'attempts'     => array( 'attempts', false ),
			'created_at'   => array( 'created_at', true ),
			'last_attempt' => array( 'last_attempt', false ),
		);
	}

	/**
	 * Bulk actions
	 */
	protected function get_bulk_actions() {
		return array(
			'retry'         => __( 'Retry', 'reportedip-hive' ),
			'delete'        => __( 'Delete', 'reportedip-hive' ),
			'delete_failed' => __( 'Delete All Failed', 'reportedip-hive' ),
		);
	}

	/**
	 * Checkbox column
	 *
	 * @param \stdClass $item Queue row from database.
	 * @return string
	 */
	protected function column_cb( $item ) {
		return sprintf(
			'<input type="checkbox" name="queue_ids[]" value="%s" />',
			$item->id
		);
	}

	/**
	 * Default column rendering
	 *
	 * @param \stdClass $item        Queue row from database.
	 * @param string    $column_name Column name.
	 * @return string
	 */
	protected function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'ip_address':
				return esc_html( $item->ip_address );

			case 'category_ids':
				return $this->format_categories( $item->category_ids );

			case 'status':
				return $this->format_status( $item->status, $item->attempts, $item->max_attempts );

			case 'priority':
				return $this->format_priority( $item->priority );

			case 'attempts':
				return sprintf(
					'%d / %d',
					(int) $item->attempts,
					(int) $item->max_attempts
				);

			case 'error_message':
				if ( empty( $item->error_message ) ) {
					return '<span class="dashicons dashicons-yes-alt" style="color: #46b450;"></span>';
				}
				return sprintf(
					'<span class="error-message" title="%s">%s</span>',
					esc_attr( $item->error_message ),
					esc_html( mb_strimwidth( $item->error_message, 0, 40, '...' ) )
				);

			case 'created_at':
				return esc_html( $this->format_date( $item->created_at ) );

			case 'last_attempt':
				if ( empty( $item->last_attempt ) ) {
					return __( 'Never', 'reportedip-hive' );
				}
				return esc_html( $this->format_date( $item->last_attempt ) );

			case 'actions':
				return $this->get_row_actions_html( $item );

			default:
				return '';
		}
	}

	/**
	 * Format categories for display
	 */
	private function format_categories( $category_ids ) {
		if ( empty( $category_ids ) ) {
			return '-';
		}

		$ids            = explode( ',', $category_ids );
		$category_names = $this->get_category_names();

		$formatted = array();
		foreach ( $ids as $id ) {
			$id = trim( $id );
			if ( isset( $category_names[ $id ] ) ) {
				$formatted[] = sprintf(
					'<span class="category-badge" title="%s">%s</span>',
					esc_attr( $category_names[ $id ] ),
					esc_html( $id )
				);
			} else {
				$formatted[] = esc_html( $id );
			}
		}

		return implode( ' ', $formatted );
	}

	/**
	 * Get category names mapping
	 */
	private function get_category_names() {
		return array(
			'4'  => __( 'Malicious Host', 'reportedip-hive' ),
			'12' => __( 'Blog Spam', 'reportedip-hive' ),
			'15' => __( 'Hacking', 'reportedip-hive' ),
			'18' => __( 'Brute-Force', 'reportedip-hive' ),
			'21' => __( 'Web App Attack', 'reportedip-hive' ),
		);
	}

	/**
	 * Format status with color
	 */
	private function format_status( $status, $attempts, $max_attempts ) {
		$status         = $status ?? 'pending';
		$status_classes = array(
			'pending'    => 'status-pending',
			'processing' => 'status-processing',
			'completed'  => 'status-completed',
			'failed'     => 'status-failed',
		);

		$class = isset( $status_classes[ $status ] ) ? $status_classes[ $status ] : '';

		if ( $status === 'failed' && $attempts >= $max_attempts ) {
			$class      .= ' permanently-failed';
			$status_text = __( 'Permanently Failed', 'reportedip-hive' );
		} else {
			$status_text = ucfirst( $status );
		}

		return sprintf(
			'<span class="status-badge %s">%s</span>',
			esc_attr( $class ),
			esc_html( $status_text )
		);
	}

	/**
	 * Format priority
	 */
	private function format_priority( $priority ) {
		$priority         = $priority ?? 'normal';
		$priority_classes = array(
			'low'    => 'priority-low',
			'normal' => 'priority-normal',
			'high'   => 'priority-high',
		);

		$class = isset( $priority_classes[ $priority ] ) ? $priority_classes[ $priority ] : '';

		return sprintf(
			'<span class="priority-badge %s">%s</span>',
			esc_attr( $class ),
			esc_html( ucfirst( $priority ) )
		);
	}

	/**
	 * Format date
	 */
	private function format_date( $date ) {
		if ( empty( $date ) ) {
			return '-';
		}

		$timestamp = strtotime( $date . ' UTC' );
		$time_diff = time() - $timestamp;

		if ( $time_diff < 0 ) {
			return __( 'just now', 'reportedip-hive' );
		}

		if ( $time_diff < 60 ) {
			return __( 'just now', 'reportedip-hive' );
		} elseif ( $time_diff < 86400 ) {
			return human_time_diff( $timestamp, time() ) . ' ' . __( 'ago', 'reportedip-hive' );
		} else {
			return wp_date( get_option( 'date_format', 'Y-m-d' ) . ' ' . get_option( 'time_format', 'H:i:s' ), $timestamp );
		}
	}

	/**
	 * Get row actions HTML
	 *
	 * @param \stdClass $item Queue row from database.
	 * @return string
	 */
	private function get_row_actions_html( $item ) {
		$actions = '';

		if ( ( $item->status === 'failed' || $item->status === 'pending' ) && $item->attempts < $item->max_attempts ) {
			$actions .= sprintf(
				'<button class="button button-small retry-report" data-id="%d">%s</button> ',
				(int) $item->id,
				__( 'Retry', 'reportedip-hive' )
			);
		}

		$actions .= sprintf(
			'<button class="button button-small delete-report" data-id="%d">%s</button>',
			(int) $item->id,
			__( 'Delete', 'reportedip-hive' )
		);

		return $actions;
	}

	/**
	 * Prepare items for display
	 */
	public function prepare_items() {
		$per_page     = $this->get_items_per_page( 'queue_items_per_page', 25 );
		$current_page = $this->get_pagenum();

		$orderby = isset( $_REQUEST['orderby'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['orderby'] ) ) : 'created_at';
		$order   = isset( $_REQUEST['order'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['order'] ) ) : 'DESC';
		$status  = isset( $_REQUEST['status'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['status'] ) ) : '';
		$search  = isset( $_REQUEST['s'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) : '';

		$args = array(
			'limit'   => $per_page,
			'offset'  => ( $current_page - 1 ) * $per_page,
			'orderby' => $orderby,
			'order'   => $order,
			'status'  => $status,
			'search'  => $search,
		);

		$this->items = $this->database->get_api_queue_items( $args );
		$total_items = (int) $this->database->count_api_queue_items( $status, $search );

		$this->set_pagination_args(
			array(
				'total_items' => $total_items,
				'per_page'    => (int) $per_page,
				'total_pages' => $per_page > 0 ? (int) ceil( $total_items / $per_page ) : 1,
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
		$action = $this->current_action();

		if ( ! $action ) {
			return;
		}

		if ( $action === 'delete_failed' ) {
			$nonce = isset( $_REQUEST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['_wpnonce'] ) ) : '';
			if ( ! wp_verify_nonce( $nonce, 'bulk-' . $this->_args['plural'] ) ) {
				return;
			}

			$deleted = $this->database->delete_permanently_failed_reports();

			add_settings_error(
				'reportedip_hive_queue',
				'queue_deleted',
				/* translators: %d: number of deleted reports */
				sprintf( __( '%d permanently failed reports deleted.', 'reportedip-hive' ), $deleted ),
				'success'
			);
			return;
		}

		if ( ! isset( $_POST['queue_ids'] ) || ! is_array( $_POST['queue_ids'] ) ) {
			return;
		}

		$post_nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
		if ( ! wp_verify_nonce( $post_nonce, 'bulk-' . $this->_args['plural'] ) ) {
			return;
		}

		$queue_ids = array_map( 'intval', $_POST['queue_ids'] );

		switch ( $action ) {
			case 'retry':
				$count = 0;
				foreach ( $queue_ids as $id ) {
					if ( $this->database->reset_report_for_retry( $id ) ) {
						++$count;
					}
				}
				add_settings_error(
					'reportedip_hive_queue',
					'queue_retry',
					/* translators: %d: number of reports queued for retry */
					sprintf( __( '%d reports queued for retry.', 'reportedip-hive' ), $count ),
					'success'
				);
				break;

			case 'delete':
				$count = 0;
				foreach ( $queue_ids as $id ) {
					if ( $this->database->delete_api_queue_item( $id ) ) {
						++$count;
					}
				}
				add_settings_error(
					'reportedip_hive_queue',
					'queue_deleted',
					/* translators: %d: number of queue items deleted */
					sprintf( __( '%d queue items deleted.', 'reportedip-hive' ), $count ),
					'success'
				);
				break;
		}
	}

	/**
	 * Display extra filter controls
	 */
	protected function extra_tablenav( $which ) {
		if ( $which !== 'top' ) {
			return;
		}

		$status = isset( $_REQUEST['status'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['status'] ) ) : '';
		$stats  = $this->database->get_queue_statistics();
		?>
		<div class="alignleft actions">
			<select name="status">
				<option value="">
					<?php
					/* translators: %d: total number of queue items */
					echo esc_html( sprintf( __( 'All Statuses (%d)', 'reportedip-hive' ), $stats['total'] ) );
					?>
				</option>
				<option value="pending" <?php selected( $status, 'pending' ); ?>>
					<?php
					/* translators: %d: number of pending queue items */
					echo esc_html( sprintf( __( 'Pending (%d)', 'reportedip-hive' ), $stats['pending'] ) );
					?>
				</option>
				<option value="processing" <?php selected( $status, 'processing' ); ?>>
					<?php
					/* translators: %d: number of processing queue items */
					echo esc_html( sprintf( __( 'Processing (%d)', 'reportedip-hive' ), $stats['processing'] ) );
					?>
				</option>
				<option value="completed" <?php selected( $status, 'completed' ); ?>>
					<?php
					/* translators: %d: number of completed queue items */
					echo esc_html( sprintf( __( 'Completed (%d)', 'reportedip-hive' ), $stats['completed'] ) );
					?>
				</option>
				<option value="failed" <?php selected( $status, 'failed' ); ?>>
					<?php
					/* translators: %d: number of failed queue items */
					echo esc_html( sprintf( __( 'Failed (%d)', 'reportedip-hive' ), $stats['failed'] ) );
					?>
				</option>
			</select>

			<?php submit_button( __( 'Filter', 'reportedip-hive' ), '', 'filter_action', false ); ?>
		</div>

		<div class="alignleft actions">
			<button type="button" class="button" id="retry-all-failed" <?php echo $stats['retryable'] === 0 ? 'disabled' : ''; ?>>
				<?php
				echo esc_html(
					sprintf(
						/* translators: %d: number of retryable items */
						__( 'Retry All Failed (%d)', 'reportedip-hive' ),
						$stats['retryable']
					)
				);
				?>
			</button>
		</div>
		<?php
	}

	/**
	 * Display queue statistics
	 */
	public function display_statistics() {
		$stats = $this->database->get_queue_statistics();
		?>
		<div class="queue-statistics">
			<div class="stat-item">
				<span class="stat-label"><?php esc_html_e( 'Pending', 'reportedip-hive' ); ?>:</span>
				<span class="stat-value pending"><?php echo (int) $stats['pending']; ?></span>
			</div>
			<div class="stat-item">
				<span class="stat-label"><?php esc_html_e( 'Processing', 'reportedip-hive' ); ?>:</span>
				<span class="stat-value processing"><?php echo (int) $stats['processing']; ?></span>
			</div>
			<div class="stat-item">
				<span class="stat-label"><?php esc_html_e( 'Completed', 'reportedip-hive' ); ?>:</span>
				<span class="stat-value completed"><?php echo (int) $stats['completed']; ?></span>
			</div>
			<div class="stat-item">
				<span class="stat-label"><?php esc_html_e( 'Failed', 'reportedip-hive' ); ?>:</span>
				<span class="stat-value failed"><?php echo (int) $stats['failed']; ?></span>
			</div>
			<?php if ( $stats['last_success'] ) : ?>
			<div class="stat-item">
				<span class="stat-label"><?php esc_html_e( 'Last Success', 'reportedip-hive' ); ?>:</span>
				<span class="stat-value"><?php echo esc_html( $this->format_date( $stats['last_success'] ) ); ?></span>
			</div>
			<?php endif; ?>
		</div>

		<style>
		.queue-statistics {
			display: flex;
			flex-wrap: wrap;
			gap: 20px;
			margin-bottom: 20px;
			padding: 15px;
			background: #fff;
			border: 1px solid #ccd0d4;
			border-radius: 4px;
		}
		.queue-statistics .stat-item {
			display: flex;
			align-items: center;
			gap: 5px;
		}
		.queue-statistics .stat-label {
			font-weight: 600;
		}
		.queue-statistics .stat-value {
			padding: 2px 8px;
			border-radius: 3px;
			font-weight: bold;
		}
		.queue-statistics .stat-value.pending { background: #fff3cd; color: #856404; }
		.queue-statistics .stat-value.processing { background: #cce5ff; color: #004085; }
		.queue-statistics .stat-value.completed { background: #d4edda; color: #155724; }
		.queue-statistics .stat-value.failed { background: #f8d7da; color: #721c24; }

		.status-badge {
			display: inline-block;
			padding: 2px 8px;
			border-radius: 3px;
			font-size: 12px;
			font-weight: 500;
		}
		.status-badge.status-pending { background: #fff3cd; color: #856404; }
		.status-badge.status-processing { background: #cce5ff; color: #004085; }
		.status-badge.status-completed { background: #d4edda; color: #155724; }
		.status-badge.status-failed { background: #f8d7da; color: #721c24; }
		.status-badge.permanently-failed { background: #dc3545; color: #fff; }

		.priority-badge {
			display: inline-block;
			padding: 2px 6px;
			border-radius: 3px;
			font-size: 11px;
		}
		.priority-badge.priority-low { background: #e9ecef; color: #495057; }
		.priority-badge.priority-normal { background: #d1ecf1; color: #0c5460; }
		.priority-badge.priority-high { background: #f5c6cb; color: #721c24; }

		.category-badge {
			display: inline-block;
			background: #e9ecef;
			padding: 1px 5px;
			border-radius: 3px;
			font-size: 11px;
			cursor: help;
		}

		.error-message {
			color: #721c24;
			cursor: help;
		}
		</style>
		<?php
	}

	/**
	 * Message when no items found
	 */
	public function no_items() {
		esc_html_e( 'No queue items found.', 'reportedip-hive' );
	}
}
