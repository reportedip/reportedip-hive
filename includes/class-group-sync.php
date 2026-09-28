<?php
/**
 * Group ban sync for ReportedIP Hive.
 *
 * A Community Access Key can be a member of one group on reportedip.com.
 * Every address a member reports is banned by every other member. The
 * service derives that list from the members' reports and serves it as the
 * `group` list of the blacklist endpoint. This class mirrors the list into
 * the blocked table as `group` blocks every fifteen minutes: new entries are
 * blocked until the expiry the service names, entries that left the list are
 * lifted, and a key without a group ends up with no group block at all.
 *
 * The whitelist wins as it always does: a whitelisted address is refused by
 * {@see ReportedIP_Hive_IP_Manager::block_ip()} and simply skipped here. A
 * block the operator placed by hand is never overwritten and never lifted by
 * the sync. A shorter automatic or reputation block on a listed address
 * becomes a group block, and only rows carrying the `group` block type are
 * lifted by it.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.67
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Group_Sync
 */
class ReportedIP_Hive_Group_Sync {

	/**
	 * Block type written for every entry of the group list.
	 */
	const BLOCK_TYPE = 'group';

	/**
	 * Option holding the group the key belongs to (`id`, `name`, `members`,
	 * `ban_hours`). Absent while the key is in no group.
	 */
	const OPT_GROUP = 'reportedip_hive_group';

	/**
	 * Option holding the ETag of the last applied list.
	 */
	const OPT_ETAG = 'reportedip_hive_group_etag';

	/**
	 * Option set when the service refused the list for the plan (`group_tier`).
	 * Cleared by the next accepted answer.
	 */
	const OPT_ERROR = 'reportedip_hive_group_error';

	/**
	 * Header the service sets on every answer of the group list. An answer
	 * without it comes from a server that does not know the list and would
	 * carry the community list instead, so it is thrown away.
	 */
	const LIST_HEADER = 'x-rip-list';

	/**
	 * Schema version that carries the `group` block type (v19) and
	 * `whitelist.source` (v20). The migration runs under a lock, so a cron
	 * request can arrive before it finished; a write with the new column
	 * would fail and the stored ETag would freeze the gap.
	 */
	const MIN_DB_VERSION = 21;

	/**
	 * Option holding what the last run did (`last_run`, `last_result`,
	 * `http_code`, `entries`, `last_change`, `changes`). Runtime state, never
	 * a setting.
	 */
	const OPT_STATUS = 'reportedip_hive_group_status';

	/**
	 * What the current run changed, by kind. Reset at the start of sync().
	 *
	 * @var array<string,int>
	 */
	private $counts = array();

	/**
	 * HTTP code of the current run, 0 when no request was made.
	 *
	 * @var int
	 */
	private $http_code = 0;

	/**
	 * Entries in the last accepted list, null while the run did not read one.
	 *
	 * @var int|null
	 */
	private $entries = null;

	/**
	 * Singleton.
	 *
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * Get the singleton.
	 *
	 * @return self
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Fetch the group list, mirror it into the blocked table and record what
	 * happened for the Group tab.
	 *
	 * @return string What happened: applied|report_only|unchanged|cleared|tier|discarded|released|skipped|error.
	 */
	public function sync() {
		$this->counts    = array_fill_keys( array( 'added', 'extended', 'lifted', 'whitelist_added', 'whitelist_removed', 'skipped_whitelist', 'skipped_own', 'skipped_manual' ), 0 );
		$this->http_code = 0;
		$this->entries   = null;

		$result = $this->run();
		if ( 'skipped' !== $result ) {
			$this->write_status( $result );
		}
		return $result;
	}

	/**
	 * The last recorded run, with defaults for a site that never ran one.
	 *
	 * @return array{last_run:int,last_result:string,http_code:int,entries:int,last_change:int,changes:array<string,int>}
	 */
	public static function status() {
		$stored = ReportedIP_Hive_Option_Routing::get( self::OPT_STATUS, array() );
		return array_merge(
			array(
				'last_run'    => 0,
				'last_result' => '',
				'http_code'   => 0,
				'entries'     => 0,
				'last_change' => 0,
				'changes'     => array(),
			),
			is_array( $stored ) ? $stored : array()
		);
	}

	/**
	 * Why this site did or did not block one entry of the group list.
	 *
	 * Mirrors the order of the checks in apply() and IP_Manager::block_ip(),
	 * and is worked out when the tab renders, so it stays true after an
	 * operator lifted a block or whitelisted an address in between.
	 *
	 * @param string      $block_type    Type of the active block on the address, '' for none.
	 * @param int         $expires       Expiry the service named (Unix time), 0 when unknown.
	 * @param bool        $whitelisted   Address is on the whitelist.
	 * @param bool        $own           Address belongs to this server.
	 * @param bool        $report_only   Report-only mode is on.
	 * @param int         $now           Unix time.
	 * @return string group|other|expired|whitelisted|own|report_only|lifted
	 */
	public static function local_status( $block_type, $expires, $whitelisted, $own, $report_only, $now ) {
		if ( self::BLOCK_TYPE === $block_type ) {
			return 'group';
		}
		if ( '' !== (string) $block_type ) {
			return 'other';
		}
		if ( $expires > 0 && $expires <= $now ) {
			return 'expired';
		}
		if ( $whitelisted ) {
			return 'whitelisted';
		}
		if ( $own ) {
			return 'own';
		}
		if ( $report_only ) {
			return 'report_only';
		}
		return 'lifted';
	}

	/**
	 * One run of the sync.
	 *
	 * @return string See sync().
	 */
	private function run() {
		if ( ! $this->is_connected() ) {
			if ( '' !== (string) ReportedIP_Hive_Option_Routing::get( self::OPT_ETAG, '' ) ) {
				$this->release();
				ReportedIP_Hive_Option_Routing::delete( self::OPT_GROUP );
				return 'released';
			}
			return 'skipped';
		}
		if ( ! $this->is_eligible() ) {
			return 'skipped';
		}

		$response = $this->fetch_remote( (string) ReportedIP_Hive_Option_Routing::get( self::OPT_ETAG, '' ) );
		if ( ! is_array( $response ) ) {
			return 'error';
		}

		$code            = (int) $response['code'];
		$this->http_code = $code;

		if ( 304 === $code ) {
			return 'unchanged';
		}

		if ( 403 === $code ) {
			$data = json_decode( (string) $response['body'], true );
			if ( 'group_tier' === (string) ( $data['code'] ?? '' ) ) {
				$this->release();
				ReportedIP_Hive_Option_Routing::set( self::OPT_ERROR, 'group_tier' );
				return 'tier';
			}
			return 'error';
		}

		if ( 200 !== $code && 204 !== $code ) {
			$this->log( 'warning', 'Group list sync failed', array( 'http_code' => $code ) );
			return 'error';
		}

		if ( self::BLOCK_TYPE !== strtolower( (string) $response['list'] ) ) {
			$this->log( 'warning', 'Group list answer discarded: missing X-Rip-List header', array( 'http_code' => $code ) );
			return 'discarded';
		}

		ReportedIP_Hive_Option_Routing::delete( self::OPT_ERROR );

		if ( 204 === $code ) {
			$this->release();
			ReportedIP_Hive_Option_Routing::delete( self::OPT_GROUP );
			return 'cleared';
		}

		$data = json_decode( (string) $response['body'], true );
		if ( ! is_array( $data ) || ! isset( $data['entries'] ) || ! is_array( $data['entries'] ) ) {
			$this->log( 'warning', 'Group list answer discarded: unreadable body', array() );
			return 'error';
		}

		$grown         = $this->apply_whitelist( isset( $data['whitelist'] ) && is_array( $data['whitelist'] ) ? $data['whitelist'] : array() );
		$this->entries = count( $data['entries'] );
		$this->store()->replace_group_entries( $data['entries'] );

		if ( isset( $data['group'] ) && is_array( $data['group'] ) ) {
			$known = ReportedIP_Hive_Option_Routing::get( self::OPT_GROUP, array() );
			ReportedIP_Hive_Option_Routing::set( self::OPT_GROUP, array_merge( is_array( $known ) ? $known : array(), $data['group'] ) );
		}

		/*
		 * Report-only enforces nothing, and block_ip() would log a
		 * would_block row for every entry on every changed list. The ETag is
		 * not kept either, so the list is applied in full the first time the
		 * mode is switched off instead of waiting for the next change.
		 */
		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ) ) {
			ReportedIP_Hive_Option_Routing::delete( self::OPT_ETAG );
			return 'report_only';
		}

		$this->apply( $data['entries'], $grown );

		if ( '' !== (string) $response['etag'] ) {
			ReportedIP_Hive_Option_Routing::set( self::OPT_ETAG, (string) $response['etag'] );
		}

		return 'applied';
	}

	/**
	 * Drop everything the sync placed: group whitelist rows, group blocks and
	 * the ETag. Used when the key leaves the group (204), when the plan no
	 * longer includes groups (403 group_tier) and when the site stops talking
	 * to the service (no key, Local Shield). A list nobody refreshes any more
	 * must not keep trusting or banning addresses.
	 *
	 * @return void
	 */
	private function release() {
		$this->apply_whitelist( array() );
		$this->apply( array(), false );
		$this->store()->clear_group_entries();
		$this->entries = 0;
		ReportedIP_Hive_Option_Routing::delete( self::OPT_ETAG );
	}

	/**
	 * Record the run in the status option and, when it changed anything,
	 * one summary line in the event log next to the per-address rows.
	 *
	 * @param string $result Result of the run.
	 * @return void
	 */
	private function write_status( $result ) {
		$previous = self::status();
		$changed  = array_sum(
			array_intersect_key(
				$this->counts,
				array_flip( array( 'added', 'extended', 'lifted', 'whitelist_added', 'whitelist_removed' ) )
			)
		) > 0;

		$status = array(
			'last_run'    => time(),
			'last_result' => (string) $result,
			'http_code'   => $this->http_code,
			'entries'     => null === $this->entries ? (int) $previous['entries'] : $this->entries,
			'last_change' => $changed ? time() : (int) $previous['last_change'],
			'changes'     => $changed ? $this->counts : $previous['changes'],
		);
		ReportedIP_Hive_Option_Routing::set( self::OPT_STATUS, $status );

		if ( $changed ) {
			$this->event(
				array_merge(
					array(
						'result'  => (string) $result,
						'entries' => $status['entries'],
					),
					$this->counts
				)
			);
		}
	}

	/**
	 * Bring the whitelist rows of source `group` in line with the list.
	 *
	 * Rows an operator entered keep their source `manual` and are never
	 * touched; a group entry that already matches a manual row is left to
	 * that row.
	 *
	 * @param array $entries Entries as the service sends them (`entry`, `note`, `since`).
	 * @return bool True when at least one row was added.
	 */
	private function apply_whitelist( array $entries ) {
		$ip_manager = $this->ip_manager();
		$grown      = false;

		$owned = array();
		foreach ( (array) $ip_manager->get_whitelist( true ) as $row ) {
			if ( self::BLOCK_TYPE === (string) ( $row->source ?? 'manual' ) ) {
				$owned[ (string) $row->ip_address ] = true;
			}
		}

		$wanted = array();
		foreach ( $entries as $entry ) {
			$address = isset( $entry['entry'] ) ? trim( (string) $entry['entry'] ) : '';
			if ( '' === $address ) {
				continue;
			}
			$wanted[ $address ] = true;
			if ( isset( $owned[ $address ] ) ) {
				continue;
			}
			$note   = isset( $entry['note'] ) ? sanitize_text_field( (string) $entry['note'] ) : '';
			$result = $ip_manager->whitelist_ip( $address, 'group: ' . $note, null, self::BLOCK_TYPE );
			if ( ! empty( $result['success'] ) ) {
				$grown = true;
				$this->count( 'whitelist_added' );
			}
		}

		foreach ( array_keys( $owned ) as $address ) {
			if ( ! isset( $wanted[ $address ] ) ) {
				$result = $ip_manager->remove_from_whitelist( $address, self::BLOCK_TYPE );
				if ( ! empty( $result['success'] ) ) {
					$this->count( 'whitelist_removed' );
				}
			}
		}

		return $grown;
	}

	/**
	 * Bring the group blocks in line with the list.
	 *
	 * When the whitelist just grew, a block that is not manual and sits on a
	 * whitelisted address (a range from the group whitelist included) is
	 * lifted here, so the whitelist wins over blocks placed before it
	 * arrived. The pass costs one lookup per active block, so it only runs
	 * when there is something new to win with.
	 *
	 * An automatic or reputation block that ends before the group ban is
	 * replaced by the group ban. Left alone, the address would walk free when
	 * the shorter block runs out, and a 304 would keep it free until the list
	 * changes. A manual block is never touched.
	 *
	 * @param array $entries    Entries as the service sends them (`ip`, `reporter`, `expires`).
	 * @param bool  $lift_white Lift non-manual blocks on whitelisted addresses first.
	 * @return void
	 */
	private function apply( array $entries, $lift_white ) {
		$ip_manager = $this->ip_manager();
		$now        = time();

		$active = array();
		foreach ( (array) $ip_manager->get_blocked_ips( true ) as $row ) {
			$ip = (string) $row->ip_address;
			if ( $lift_white && 'manual' !== (string) $row->block_type && $ip_manager->is_whitelisted( $ip ) ) {
				$ip_manager->unblock_ip( $ip );
				$this->count( 'lifted' );
				continue;
			}
			$active[ $ip ] = $row;
		}

		$wanted = array();
		foreach ( $entries as $entry ) {
			$ip = isset( $entry['ip'] ) ? trim( (string) $entry['ip'] ) : '';
			if ( '' === $ip ) {
				continue;
			}
			$expires = isset( $entry['expires'] ) ? strtotime( (string) $entry['expires'] ) : false;
			if ( false === $expires || $expires <= $now ) {
				continue;
			}
			$wanted[ $ip ] = true;

			$hours = (int) ceil( ( $expires - $now ) / HOUR_IN_SECONDS );

			$kind = 'added';
			if ( isset( $active[ $ip ] ) ) {
				$row = $active[ $ip ];
				if ( 'manual' === (string) $row->block_type || empty( $row->blocked_until ) ) {
					$this->count( 'skipped_manual' );
					continue;
				}
				$until = strtotime( (string) $row->blocked_until . ' UTC' );
				if ( false !== $until && $until >= $expires ) {
					continue;
				}
				$kind = 'extended';
			} elseif ( $ip_manager->is_whitelisted( $ip ) ) {
				$this->count( 'skipped_whitelist' );
				continue;
			} elseif ( $this->is_own( $ip ) ) {
				$this->count( 'skipped_own' );
				continue;
			}

			$reporter = isset( $entry['reporter'] ) ? sanitize_text_field( (string) $entry['reporter'] ) : '';
			$result   = $ip_manager->block_ip( $ip, 'group: ' . $reporter, max( 1, $hours ), self::BLOCK_TYPE );
			if ( ! empty( $result['success'] ) ) {
				$this->count( $kind );
			}
		}

		foreach ( $active as $ip => $row ) {
			if ( self::BLOCK_TYPE === (string) $row->block_type && ! isset( $wanted[ $ip ] ) ) {
				$ip_manager->unblock_ip( $ip );
				$this->count( 'lifted' );
			}
		}
	}

	/**
	 * Add one to a counter of the current run.
	 *
	 * @param string $key Counter.
	 * @return void
	 */
	private function count( $key ) {
		$this->counts[ $key ] = ( $this->counts[ $key ] ?? 0 ) + 1;
	}

	/**
	 * Whether an address or range covers this server. Isolated so tests can
	 * run without the main plugin class.
	 *
	 * @param string $ip Address or CIDR.
	 * @return bool
	 */
	protected function is_own( $ip ) {
		return class_exists( 'ReportedIP_Hive' ) && ReportedIP_Hive::is_own_server_ip( $ip );
	}

	/**
	 * Storage of the group list. Isolated so tests can hand in a double; it
	 * only ever writes the mirror table, blocks go through the IP manager.
	 *
	 * @return ReportedIP_Hive_Database
	 */
	protected function store() {
		return ReportedIP_Hive_Database::get_instance();
	}

	/**
	 * Write the summary row of a run that changed something.
	 *
	 * @param array $details Counters and result.
	 * @return void
	 */
	protected function event( array $details ) {
		if ( class_exists( 'ReportedIP_Hive_Logger' ) ) {
			ReportedIP_Hive_Logger::get_instance()->log_security_event( 'group_list_synced', 'system', $details, 'low' );
		}
	}

	/**
	 * True while the site talks to the service at all: community mode and a
	 * key. False means whatever the sync placed has to go.
	 *
	 * @return bool
	 */
	protected function is_connected() {
		if ( '' === (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' ) ) {
			return false;
		}
		return class_exists( 'ReportedIP_Hive_Mode_Manager' ) && ReportedIP_Hive_Mode_Manager::get_instance()->is_community_mode();
	}

	/**
	 * True when the sync may run now: the schema carries the group columns
	 * and the API client has no open back-off. A false here is temporary and
	 * changes nothing locally.
	 *
	 * @return bool
	 */
	protected function is_eligible() {
		if ( (int) get_site_option( ReportedIP_Hive_Migration_Manager::VERSION_OPTION, 0 ) < self::MIN_DB_VERSION ) {
			return false;
		}
		if ( class_exists( 'ReportedIP_Hive_API' ) && ReportedIP_Hive_API::get_instance()->is_rate_limited( 'meta' ) ) {
			return false;
		}
		return true;
	}

	/**
	 * The IP manager. Isolated so tests can hand in a double.
	 *
	 * @return ReportedIP_Hive_IP_Manager
	 */
	protected function ip_manager() {
		return ReportedIP_Hive_IP_Manager::get_instance();
	}

	/**
	 * Perform the HTTP GET. Isolated so tests can stub it.
	 *
	 * @param string $etag Previously stored ETag (sent as If-None-Match).
	 * @return array{code:int,body:string,etag:string,list:string}|null
	 */
	protected function fetch_remote( $etag ) {
		$base = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_endpoint', '' );
		if ( '' === $base ) {
			return null;
		}
		$url = rtrim( $base, '/' ) . '/blacklist?' . http_build_query(
			array(
				'source' => 'group',
				'format' => 'json',
			)
		);

		$args = array(
			'timeout'   => 15,
			'sslverify' => true,
			'headers'   => array_merge(
				array(
					'X-Key'      => (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' ),
					'User-Agent' => ReportedIP_Hive_API::api_user_agent(),
					'Accept'     => 'application/json',
				),
				ReportedIP_Hive_API::identity_headers()
			),
		);
		if ( '' !== $etag ) {
			$args['headers']['If-None-Match'] = $etag;
		}

		$response = wp_remote_get( $url, $args );
		if ( is_wp_error( $response ) ) {
			$this->log( 'warning', 'Group list sync failed', array( 'error' => $response->get_error_message() ) );
			return null;
		}

		return array(
			'code' => (int) wp_remote_retrieve_response_code( $response ),
			'body' => (string) wp_remote_retrieve_body( $response ),
			'etag' => (string) wp_remote_retrieve_header( $response, 'etag' ),
			'list' => (string) wp_remote_retrieve_header( $response, self::LIST_HEADER ),
		);
	}

	/**
	 * Write a system log line when the logger is loaded.
	 *
	 * @param string $level   info|warning.
	 * @param string $message Message.
	 * @param array  $details Details.
	 * @return void
	 */
	protected function log( $level, $message, array $details ) {
		if ( class_exists( 'ReportedIP_Hive_Logger' ) ) {
			ReportedIP_Hive_Logger::get_instance()->$level( $message, 'system', $details );
		}
	}
}
