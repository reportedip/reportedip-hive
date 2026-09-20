<?php
/**
 * Audit-log list table for ReportedIP Hive.
 *
 * Read-only WP_List_Table over the `audit_log` table: pagination, sorting and
 * filtering by event or trigger group, user, IP, date range and object. The
 * trail is append-only, so there are no bulk mutation actions. On Multisite
 * a site administrator is automatically scoped to the current blog; a
 * network administrator sees the whole network and can narrow it to one
 * site or to the network rows. The WHERE clause is built in one place and
 * shared with the export.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
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
	 * Request keys the filter bar controls.
	 *
	 * @var string[]
	 */
	public const FILTER_KEYS = array( 'audit_event', 'audit_site', 'audit_user', 'audit_ip', 'rip_date_from', 'rip_date_to', 's' );

	/**
	 * Filter value that selects the network rows (`blog_id = 0`).
	 */
	public const SITE_NETWORK = 'network';

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
		$columns = array(
			'created_at'   => __( 'Time', 'reportedip-hive' ),
			'username'     => __( 'User', 'reportedip-hive' ),
			'event'        => __( 'Event', 'reportedip-hive' ),
			'object_label' => __( 'Object', 'reportedip-hive' ),
			'details'      => __( 'Details', 'reportedip-hive' ),
		);
		if ( is_multisite() && is_network_admin() ) {
			$columns['blog_id'] = __( 'Site', 'reportedip-hive' );
		}
		return $columns;
	}

	/**
	 * Sortable columns.
	 *
	 * @return array<string,array{0:string,1:bool}>
	 * @since  2.1.2
	 */
	protected function get_sortable_columns() {
		return array(
			'created_at'   => array( 'created_at', true ),
			'username'     => array( 'username', false ),
			'object_label' => array( 'object_label', false ),
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
				return esc_html( ReportedIP_Hive::format_local_datetime( $item->created_at ) );

			case 'username':
				$name = (string) ( $item->username ?? '' );
				if ( '' === $name && ! empty( $item->user_id ) ) {
					$name = '#' . (int) $item->user_id;
				}
				$agent = self::agent_of( $item );
				if ( '' === $name ) {
					$name = 'web' === $agent ? __( 'Visitor', 'reportedip-hive' ) : __( 'System', 'reportedip-hive' );
				}
				$out = '<strong>' . esc_html( $name ) . '</strong>';
				if ( 'web' !== $agent ) {
					$out .= ' <span class="rip-badge rip-badge--neutral">' . esc_html( strtoupper( $agent ) ) . '</span>';
				}
				$ip = (string) ( $item->ip ?? '' );
				if ( '' !== $ip ) {
					$out .= '<div class="rip-audit-ip">' . ReportedIP_Hive_IP_Cell::render(
						$ip,
						array(
							'lookup'   => false,
							'external' => false,
						)
					) . '</div>';
				}
				return $out;

			case 'event':
				$type   = (string) $item->event_type;
				$action = (string) $item->event_action;
				$row    = ReportedIP_Hive_Audit_Registry::event( $type, $action );
				$groups = ReportedIP_Hive_Audit_Registry::groups();
				$group  = $row && isset( $groups[ $row['group'] ] ) ? $groups[ $row['group'] ]['label'] : ucwords( str_replace( '_', ' ', $type ) );
				return sprintf(
					'<span class="rip-badge rip-badge--%1$s">%2$s</span><div class="rip-audit-group">%3$s</div>',
					esc_attr( ReportedIP_Hive_Audit_Registry::badge( $type, $action ) ),
					esc_html( ReportedIP_Hive_Audit_Registry::label( $type, $action ) ),
					esc_html( $group )
				);

			case 'object_label':
				$label = ReportedIP_Hive_Audit_Registry::object_label( $item );
				if ( '' === $label ) {
					return '<span class="rip-text-muted">-</span>';
				}
				$url = self::object_url( $item );
				if ( '' !== $url ) {
					return '<a href="' . esc_url( $url ) . '">' . esc_html( $label ) . '</a>';
				}
				return esc_html( $label );

			case 'details':
				return self::render_details( $item );

			case 'blog_id':
				$blog_id = (int) ( $item->blog_id ?? 0 );
				if ( 0 === $blog_id ) {
					return '<span class="rip-badge rip-badge--neutral">' . esc_html__( 'Network', 'reportedip-hive' ) . '</span>';
				}
				$site = function_exists( 'get_site' ) ? get_site( $blog_id ) : null;
				return esc_html( $site ? (string) $site->blogname : '#' . $blog_id );

			default:
				return '';
		}
	}

	/**
	 * Agent stored with the row, `web` when absent.
	 *
	 * @param object $item Audit row.
	 * @return string
	 * @since  2.1.62
	 */
	private static function agent_of( $item ) {
		$data = json_decode( (string) ( $item->event_data ?? '' ), true );
		return is_array( $data ) && ! empty( $data['agent'] ) ? (string) $data['agent'] : 'web';
	}

	/**
	 * Admin URL of the affected object while it still exists.
	 *
	 * @param object $item Audit row.
	 * @return string Empty when there is nothing to link to.
	 * @since  2.1.62
	 */
	public static function object_url( $item ) {
		$type = (string) ( $item->object_type ?? '' );
		$id   = (int) ( $item->object_id ?? 0 );
		switch ( $type ) {
			case 'post':
				if ( $id > 0 && get_post( $id ) ) {
					return (string) get_edit_post_link( $id, 'raw' );
				}
				return '';
			case 'user':
				if ( $id > 0 && get_userdata( $id ) ) {
					return (string) get_edit_user_link( $id );
				}
				return '';
			case 'menu':
				if ( $id > 0 && wp_get_nav_menu_object( $id ) ) {
					return admin_url( 'nav-menus.php?action=edit&menu=' . $id );
				}
				return '';
			case 'plugin':
				return is_multisite() && is_network_admin() ? network_admin_url( 'plugins.php' ) : admin_url( 'plugins.php' );
			case 'theme':
				return admin_url( 'themes.php' );
			default:
				return '';
		}
	}

	/**
	 * The sentence for the row plus the compact old/new lines.
	 *
	 * @param object $item Audit row.
	 * @return string
	 * @since  2.1.62
	 */
	private static function render_details( $item ) {
		$summary = ReportedIP_Hive_Audit_Registry::summary( $item );
		$data    = json_decode( (string) ( $item->event_data ?? '' ), true );
		$data    = is_array( $data ) ? $data : array();
		$lines   = array();
		if ( '' !== $summary && $summary !== ReportedIP_Hive_Audit_Registry::object_label( $item ) ) {
			$lines[] = esc_html( $summary );
		}
		$skip = array( 'agent', 'network', 'network_wide', 'old', 'new', 'old_slug', 'new_slug', 'old_status', 'new_status', 'from_version', 'to_version', 'changes', 'added', 'removed', 'caps_changed', 'sidebar', 'old_roles', 'new_role', 'option' );
		foreach ( $data as $key => $value ) {
			if ( in_array( (string) $key, $skip, true ) ) {
				continue;
			}
			if ( is_array( $value ) ) {
				$value = implode( ', ', array_map( 'strval', $value ) );
			}
			if ( '' === (string) $value || '0' === (string) $value ) {
				continue;
			}
			$lines[] = '<span class="rip-text-muted">' . esc_html( (string) $key ) . ':</span> ' . esc_html( (string) $value );
		}
		if ( empty( $lines ) ) {
			return '<span class="rip-text-muted">-</span>';
		}
		return implode( '<br />', $lines );
	}

	/**
	 * The filter bar above the table, as a GET form of its own.
	 *
	 * @param array<string,string> $location Hidden fields naming the page the form posts back to; the Activity tab by default.
	 * @return void
	 * @since  2.1.2
	 */
	public function render_filters( array $location = array() ) {
		$args = self::filter_args();

		ReportedIP_Hive_Filter_Bar::open(
			empty( $location ) ? array(
				'page' => 'reportedip-hive-security',
				'tab'  => 'activity',
				'sub'  => 'audit',
			) : $location
		);
		?>
		<div class="rip-filter-bar__field">
			<label class="rip-filter-bar__label" for="rip-audit-event"><?php esc_html_e( 'Event', 'reportedip-hive' ); ?></label>
			<select name="audit_event" id="rip-audit-event" class="rip-select">
				<option value=""><?php esc_html_e( 'All events', 'reportedip-hive' ); ?></option>
				<?php
				$groups = ReportedIP_Hive_Audit_Registry::groups();
				foreach ( ReportedIP_Hive_Audit_Registry::filter_options() as $group => $options ) :
					$group_label = isset( $groups[ $group ] ) ? $groups[ $group ]['label'] : $group;
					$group_value = ReportedIP_Hive_Audit_Registry::GROUP_PREFIX . $group;
					?>
					<optgroup label="<?php echo esc_attr( $group_label ); ?>">
						<option value="<?php echo esc_attr( $group_value ); ?>" <?php selected( $args['audit_event'], $group_value ); ?>>
							<?php
							/* translators: %s: trigger group label */
							echo esc_html( sprintf( __( 'All: %s', 'reportedip-hive' ), $group_label ) );
							?>
						</option>
						<?php foreach ( $options as $value => $label ) : ?>
							<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $args['audit_event'], $value ); ?>><?php echo esc_html( $label ); ?></option>
						<?php endforeach; ?>
					</optgroup>
				<?php endforeach; ?>
			</select>
		</div>
		<?php
		if ( is_multisite() && is_network_admin() ) :
			?>
			<div class="rip-filter-bar__field">
				<label class="rip-filter-bar__label" for="rip-audit-site"><?php esc_html_e( 'Site', 'reportedip-hive' ); ?></label>
				<select name="audit_site" id="rip-audit-site" class="rip-select">
					<option value=""><?php esc_html_e( 'All sites', 'reportedip-hive' ); ?></option>
					<option value="<?php echo esc_attr( self::SITE_NETWORK ); ?>" <?php selected( $args['audit_site'], self::SITE_NETWORK ); ?>><?php esc_html_e( 'Network', 'reportedip-hive' ); ?></option>
					<?php foreach ( self::site_choices() as $blog_id => $name ) : ?>
						<option value="<?php echo esc_attr( (string) $blog_id ); ?>" <?php selected( $args['audit_site'], (string) $blog_id ); ?>><?php echo esc_html( $name ); ?></option>
					<?php endforeach; ?>
				</select>
			</div>
			<?php
		endif;
		ReportedIP_Hive_Filter_Bar::field(
			'rip-audit-user',
			__( 'User', 'reportedip-hive' ),
			sprintf(
				'<input type="search" id="rip-audit-user" name="audit_user" class="rip-input" value="%s" placeholder="%s" />',
				esc_attr( $args['audit_user'] ),
				esc_attr__( 'Login name', 'reportedip-hive' )
			)
		);
		ReportedIP_Hive_Filter_Bar::field(
			'rip-audit-ip',
			__( 'IP address', 'reportedip-hive' ),
			sprintf( '<input type="search" id="rip-audit-ip" name="audit_ip" class="rip-input" value="%s" />', esc_attr( $args['audit_ip'] ) )
		);
		ReportedIP_Hive_Filter_Bar::field(
			'rip-audit-search',
			__( 'Object', 'reportedip-hive' ),
			sprintf(
				'<input type="search" id="rip-audit-search" name="s" class="rip-input" value="%s" placeholder="%s" />',
				esc_attr( $args['s'] ),
				esc_attr__( 'Title, plugin, setting', 'reportedip-hive' )
			)
		);
		ReportedIP_Hive_Filter_Bar::field(
			'rip-audit-date-from',
			__( 'From', 'reportedip-hive' ),
			sprintf( '<input type="date" id="rip-audit-date-from" name="rip_date_from" class="rip-input" value="%s" />', esc_attr( $args['rip_date_from'] ) )
		);
		ReportedIP_Hive_Filter_Bar::field(
			'rip-audit-date-to',
			__( 'To', 'reportedip-hive' ),
			sprintf( '<input type="date" id="rip-audit-date-to" name="rip_date_to" class="rip-input" value="%s" />', esc_attr( $args['rip_date_to'] ) )
		);
		ReportedIP_Hive_Filter_Bar::close( self::FILTER_KEYS );
	}

	/**
	 * Sites of the network for the site filter, id to name.
	 *
	 * @return array<int,string>
	 * @since  2.1.62
	 */
	private static function site_choices() {
		$choices = array();
		if ( ! function_exists( 'get_sites' ) ) {
			return $choices;
		}
		foreach ( get_sites( array( 'number' => 200 ) ) as $site ) {
			$choices[ (int) $site->blog_id ] = (string) $site->blogname . ' (' . (string) $site->domain . (string) $site->path . ')';
		}
		return $choices;
	}

	/**
	 * Current filter values from the request, sanitised, every key present.
	 *
	 * @return array<string,string>
	 * @since  2.1.62
	 */
	public static function filter_args() {
		$args = array();
		foreach ( self::FILTER_KEYS as $key ) {
			$args[ $key ] = isset( $_REQUEST[ $key ] ) ? sanitize_text_field( wp_unslash( $_REQUEST[ $key ] ) ) : '';
		}
		return $args;
	}

	/**
	 * WHERE clause and bound parameters for the current filters.
	 *
	 * The one query builder for the table and the export: a row the reader
	 * filtered onto the screen is the row the export contains.
	 *
	 * @param array<string,string> $args Filter values as {@see filter_args()} returns them.
	 * @return array{0:string, 1:array<int,mixed>} SQL fragment without WHERE, parameters.
	 * @since  2.1.62
	 */
	public static function build_where( array $args ) {
		global $wpdb;

		$where  = array( '1=1' );
		$params = array();

		if ( is_multisite() && ! is_network_admin() ) {
			$where[]  = 'blog_id = %d';
			$params[] = get_current_blog_id();
		} elseif ( is_multisite() ) {
			$site = (string) ( $args['audit_site'] ?? '' );
			if ( self::SITE_NETWORK === $site ) {
				$where[] = 'blog_id = 0';
			} elseif ( ctype_digit( $site ) && (int) $site > 0 ) {
				$where[]  = 'blog_id = %d';
				$params[] = (int) $site;
			}
		}

		$event = (string) ( $args['audit_event'] ?? '' );
		if ( '' !== $event ) {
			$pairs = array();
			foreach ( ReportedIP_Hive_Audit_Registry::expand_filter_value( $event ) as $key ) {
				$parts = explode( '/', $key, 2 );
				if ( 2 === count( $parts ) ) {
					$pairs[]  = '(event_type = %s AND event_action = %s)';
					$params[] = $parts[0];
					$params[] = $parts[1];
				} else {
					$pairs[]  = 'event_type = %s';
					$params[] = $key;
				}
			}
			$where[] = '(' . implode( ' OR ', $pairs ) . ')';
		}

		$user = (string) ( $args['audit_user'] ?? '' );
		if ( '' !== $user ) {
			$where[]  = 'username LIKE %s';
			$params[] = '%' . $wpdb->esc_like( $user ) . '%';
		}

		$ip = (string) ( $args['audit_ip'] ?? '' );
		if ( '' !== $ip ) {
			$where[]  = 'ip = %s';
			$params[] = $ip;
		}

		$search = (string) ( $args['s'] ?? '' );
		if ( '' !== $search ) {
			$where[]  = '(object_label LIKE %s OR event_data LIKE %s)';
			$like     = '%' . $wpdb->esc_like( $search ) . '%';
			$params[] = $like;
			$params[] = $like;
		}

		$from = (string) ( $args['rip_date_from'] ?? '' );
		if ( preg_match( '/^\d{4}-\d{2}-\d{2}$/', $from ) ) {
			$where[]  = 'created_at >= %s';
			$params[] = get_gmt_from_date( $from . ' 00:00:00' );
		}

		$to = (string) ( $args['rip_date_to'] ?? '' );
		if ( preg_match( '/^\d{4}-\d{2}-\d{2}$/', $to ) ) {
			$where[]  = 'created_at <= %s';
			$params[] = get_gmt_from_date( $to . ' 23:59:59' );
		}

		return array( implode( ' AND ', $where ), $params );
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

		list( $where_sql, $params ) = self::build_where( self::filter_args() );

		$orderby      = isset( $_REQUEST['orderby'] ) ? sanitize_key( wp_unslash( $_REQUEST['orderby'] ) ) : 'created_at';
		$allowed_cols = array( 'created_at', 'username', 'object_label' );
		if ( ! in_array( $orderby, $allowed_cols, true ) ) {
			$orderby = 'created_at';
		}
		$order = ( isset( $_REQUEST['order'] ) && 'asc' === strtolower( sanitize_key( wp_unslash( $_REQUEST['order'] ) ) ) ) ? 'ASC' : 'DESC';

		$count_sql = "SELECT COUNT(*) FROM $table WHERE $where_sql";
		$total     = empty( $params ) ? (int) $wpdb->get_var( $count_sql ) : (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) );

		$data_sql    = "SELECT * FROM $table WHERE $where_sql ORDER BY $orderby $order, id $order LIMIT %d OFFSET %d";
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
	 * Render the table over a fixed list of rows without touching the
	 * database; used for the sample on plans without the trail.
	 *
	 * @param object[] $items Rows shaped like table rows.
	 * @return void
	 * @since  2.1.62
	 */
	public function display_items( array $items ) {
		$this->items           = $items;
		$this->_column_headers = array( $this->get_columns(), array(), array() );
		$this->display();
	}

	/**
	 * Five example rows that show what the trail records.
	 *
	 * @return object[]
	 * @since  2.1.62
	 */
	public static function sample_items() {
		$now   = time();
		$rows  = array(
			array(
				'customer',
				'setting',
				'updated',
				'option',
				(string) ReportedIP_Hive_Audit_Registry::option_label( 'permalink_structure' ),
				array(
					'option' => 'permalink_structure',
					'old'    => '/%postname%/',
					'new'    => '/%year%/%postname%/',
				),
				3 * HOUR_IN_SECONDS,
			),
			array(
				'customer',
				'plugin',
				'deactivated',
				'plugin',
				'WooCommerce',
				array(
					'slug'       => 'woocommerce/woocommerce.php',
					'to_version' => '9.9.5',
				),
				5 * HOUR_IN_SECONDS,
			),
			array( 'editor', 'content', 'trashed', 'post', __( 'Imprint', 'reportedip-hive' ), array( 'post_type' => 'page' ), DAY_IN_SECONDS ),
			array( 'admin', 'file', 'edited', 'theme_file', 'twentytwentyfive/functions.php', array( 'kind' => 'theme' ), 2 * DAY_IN_SECONDS ),
			array(
				'admin',
				'profile_change',
				'role_changed',
				'user',
				'editor',
				array(
					'old_roles'  => array( 'author' ),
					'new_role'   => 'administrator',
					'changed_by' => 1,
				),
				3 * DAY_IN_SECONDS,
			),
		);
		$items = array();
		foreach ( $rows as $index => $row ) {
			$items[] = (object) array(
				'id'           => $index + 1,
				'blog_id'      => 1,
				'created_at'   => gmdate( 'Y-m-d H:i:s', $now - $row[6] ),
				'ip'           => '203.0.113.' . ( 10 + $index ),
				'user_id'      => $index + 2,
				'username'     => $row[0],
				'event_type'   => $row[1],
				'event_action' => $row[2],
				'event_data'   => wp_json_encode( $row[5] ),
				'object_type'  => $row[3],
				'object_id'    => 0,
				'object_label' => $row[4],
			);
		}
		return $items;
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
