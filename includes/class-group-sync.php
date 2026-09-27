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
 * the sync, only rows carrying the `group` block type belong to it.
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
	 * Fetch the group list and mirror it into the blocked table.
	 *
	 * @return string What happened: applied|unchanged|cleared|tier|discarded|skipped|error.
	 */
	public function sync() {
		if ( ! $this->is_eligible() ) {
			return 'skipped';
		}

		$response = $this->fetch_remote( (string) ReportedIP_Hive_Option_Routing::get( self::OPT_ETAG, '' ) );
		if ( ! is_array( $response ) ) {
			return 'error';
		}

		$code = (int) $response['code'];

		if ( 304 === $code ) {
			return 'unchanged';
		}

		if ( 403 === $code ) {
			$data = json_decode( (string) $response['body'], true );
			if ( 'group_tier' === (string) ( $data['code'] ?? '' ) ) {
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
			$this->apply( array() );
			ReportedIP_Hive_Option_Routing::delete( self::OPT_GROUP );
			ReportedIP_Hive_Option_Routing::delete( self::OPT_ETAG );
			return 'cleared';
		}

		$data = json_decode( (string) $response['body'], true );
		if ( ! is_array( $data ) || ! isset( $data['entries'] ) || ! is_array( $data['entries'] ) ) {
			$this->log( 'warning', 'Group list answer discarded: unreadable body', array() );
			return 'error';
		}

		$this->apply( $data['entries'] );

		if ( isset( $data['group'] ) && is_array( $data['group'] ) ) {
			$known = ReportedIP_Hive_Option_Routing::get( self::OPT_GROUP, array() );
			ReportedIP_Hive_Option_Routing::set( self::OPT_GROUP, array_merge( is_array( $known ) ? $known : array(), $data['group'] ) );
		}
		if ( '' !== (string) $response['etag'] ) {
			ReportedIP_Hive_Option_Routing::set( self::OPT_ETAG, (string) $response['etag'] );
		}

		return 'applied';
	}

	/**
	 * Bring the group blocks in line with the list.
	 *
	 * @param array $entries Entries as the service sends them (`ip`, `reporter`, `expires`).
	 * @return void
	 */
	private function apply( array $entries ) {
		$ip_manager = $this->ip_manager();
		$now        = time();

		$active = array();
		foreach ( (array) $ip_manager->get_blocked_ips( true ) as $row ) {
			$active[ (string) $row->ip_address ] = $row;
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

			if ( isset( $active[ $ip ] ) ) {
				$row = $active[ $ip ];
				if ( self::BLOCK_TYPE !== (string) $row->block_type ) {
					continue;
				}
				$until = ! empty( $row->blocked_until ) ? strtotime( (string) $row->blocked_until . ' UTC' ) : false;
				if ( false !== $until && $until >= $expires ) {
					continue;
				}
			}

			$reporter = isset( $entry['reporter'] ) ? sanitize_text_field( (string) $entry['reporter'] ) : '';
			$ip_manager->block_ip( $ip, 'group: ' . $reporter, max( 1, $hours ), self::BLOCK_TYPE );
		}

		foreach ( $active as $ip => $row ) {
			if ( self::BLOCK_TYPE === (string) $row->block_type && ! isset( $wanted[ $ip ] ) ) {
				$ip_manager->unblock_ip( $ip );
			}
		}
	}

	/**
	 * True when the sync may run: community mode, a key, and no open
	 * back-off of the API client.
	 *
	 * @return bool
	 */
	protected function is_eligible() {
		if ( '' === (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' ) ) {
			return false;
		}
		if ( ! class_exists( 'ReportedIP_Hive_Mode_Manager' ) || ! ReportedIP_Hive_Mode_Manager::get_instance()->is_community_mode() ) {
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
