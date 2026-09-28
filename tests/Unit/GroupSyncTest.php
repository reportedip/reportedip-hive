<?php
/**
 * Unit tests for the group ban sync.
 *
 * Locks down the contract with the service: a `group` list is mirrored as
 * `group` blocks until the expiry the service names, a 304 changes nothing, a
 * 204 lifts every group block and nothing else, an answer without the
 * `X-Rip-List: group` header is thrown away (an older server would hand out
 * the community list under that URL), a whitelisted address is never
 * blocked and a plan refusal leaves a marker for the admin notice. The group
 * whitelist that rides along is mirrored as rows of source `group`, ranges
 * match as ranges, and rows an operator entered are never touched.
 *
 * @package    ReportedIP_Hive
 * @subpackage Tests\Unit
 * @author     Patrick Schlesinger <1@reportedip.com>
 * @copyright  2025-2026 Patrick Schlesinger
 * @license    GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link       https://github.com/reportedip/reportedip-hive
 * @since      2.1.67
 */

namespace {
	if ( ! defined( 'ABSPATH' ) ) {
		exit;
	}

	require_once dirname( __DIR__, 2 ) . '/includes/class-database.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-ip-manager.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-group-sync.php';
	require_once dirname( __DIR__, 2 ) . '/includes/class-cron-handler.php';

	/**
	 * IP manager double: an in-memory blocked table that refuses whitelisted
	 * addresses the way the real block_ip() does.
	 */
	class Rip_Group_Sync_Ip_Manager_Double extends \ReportedIP_Hive_IP_Manager {

		/** @var array<int,array<string,mixed>> Active rows as get_blocked_ips() returns them. */
		public $rows = array();

		/** @var string[] Addresses the whitelist covers. */
		public $whitelist = array();

		/** @var array<int,array<string,mixed>> Recorded block_ip() calls. */
		public $blocked = array();

		/** @var string[] Recorded unblock_ip() calls. */
		public $unblocked = array();

		/** @var array<int,array<string,string>> Whitelist rows: ip_address, source. */
		public $whitelist_rows = array();

		/** @var array<int,array<string,mixed>> Recorded whitelist_ip() calls. */
		public $whitelisted = array();

		/** @var array<int,array<string,string>> Recorded remove_from_whitelist() calls. */
		public $unwhitelisted = array();

		public function __construct() {
		}

		public function get_whitelist( $active_only = true ) {
			return array_map(
				static function ( $row ) {
					return (object) $row;
				},
				$this->whitelist_rows
			);
		}

		public function whitelist_ip( $ip_address, $reason = '', $expires_at = null, $source = 'manual' ) {
			if ( $this->is_whitelisted( $ip_address ) ) {
				return array(
					'success' => false,
					'message' => 'already',
				);
			}
			$this->whitelist_rows[] = array(
				'ip_address' => $ip_address,
				'source'     => $source,
			);
			$this->whitelisted[]    = array(
				'ip'     => $ip_address,
				'why'    => $reason,
				'source' => $source,
			);
			return array(
				'success' => true,
				'message' => '',
			);
		}

		public function remove_from_whitelist( $ip_address, $source = 'manual' ) {
			foreach ( $this->whitelist_rows as $i => $row ) {
				if ( $row['ip_address'] === $ip_address && $row['source'] === $source ) {
					unset( $this->whitelist_rows[ $i ] );
					$this->unwhitelisted[] = array(
						'ip'     => $ip_address,
						'source' => $source,
					);
					return array(
						'success' => true,
						'message' => '',
					);
				}
			}
			return array(
				'success' => false,
				'message' => 'refused',
			);
		}

		public function get_blocked_ips( $active_only = true ) {
			return array_map(
				static function ( $row ) {
					return (object) $row;
				},
				$this->rows
			);
		}

		public function is_whitelisted( $ip_address ) {
			if ( in_array( $ip_address, $this->whitelist, true ) ) {
				return true;
			}
			foreach ( $this->whitelist_rows as $row ) {
				if ( \ReportedIP_Hive_Database::ip_in_cidr( $ip_address, $row['ip_address'] ) ) {
					return true;
				}
			}
			return false;
		}

		public function block_ip( $ip_address, $reason = '', $duration_hours = null, $block_type = 'manual' ) {
			if ( $this->is_whitelisted( $ip_address ) ) {
				return array(
					'success' => false,
					'message' => 'Cannot block whitelisted IP address.',
				);
			}
			$this->blocked[] = array(
				'ip'    => $ip_address,
				'why'   => $reason,
				'hours' => $duration_hours,
				'type'  => $block_type,
			);
			return array(
				'success' => true,
				'message' => '',
			);
		}

		public function unblock_ip( $ip_address ) {
			$this->unblocked[] = $ip_address;
			return array(
				'success' => true,
				'message' => '',
			);
		}
	}

	/**
	 * Store double: the mirror table as an array.
	 */
	class Rip_Group_Sync_Store_Double {

		/** @var array<int,array>|null Stored entries, null before the first write. */
		public $entries = null;

		public function replace_group_entries( array $entries ) {
			$this->entries = $entries;
			return count( $entries );
		}

		public function clear_group_entries() {
			$this->entries = array();
		}
	}

	/**
	 * Sync double: canned HTTP answer, always eligible, injected IP manager.
	 */
	class Rip_Group_Sync_Double extends \ReportedIP_Hive_Group_Sync {

		/** @var array|null Canned answer of fetch_remote(). */
		public $response = null;

		/** @var string[] ETags handed to fetch_remote(). */
		public $sent_etags = array();

		/** @var Rip_Group_Sync_Ip_Manager_Double */
		public $manager;

		/** @var Rip_Group_Sync_Store_Double */
		public $store_double;

		/** @var array<int,array> Recorded summary events. */
		public $events = array();

		/** @var string[] Addresses that count as this server. */
		public $own = array();

		public function __construct() {
			$this->manager      = new Rip_Group_Sync_Ip_Manager_Double();
			$this->store_double = new Rip_Group_Sync_Store_Double();
		}

		protected function store() {
			return $this->store_double;
		}

		protected function event( array $details ) {
			$this->events[] = $details;
		}

		protected function is_own( $ip ) {
			return in_array( $ip, $this->own, true );
		}

		/** @var bool Answer of is_connected(). */
		public $connected = true;

		protected function is_connected() {
			return $this->connected;
		}

		protected function is_eligible() {
			return true;
		}

		protected function ip_manager() {
			return $this->manager;
		}

		protected function fetch_remote( $etag ) {
			$this->sent_etags[] = $etag;
			return $this->response;
		}

		protected function log( $level, $message, array $details ) {
		}
	}
}

namespace ReportedIP\Hive\Tests\Unit {

	use ReportedIP\Hive\Tests\TestCase;

	/**
	 * @covers \ReportedIP_Hive_Group_Sync
	 */
	class GroupSyncTest extends TestCase {

		/** @var \Rip_Group_Sync_Double */
		private $sync;

		protected function set_up() {
			parent::set_up();
			$GLOBALS['wp_options'] = array();
			$this->sync            = new \Rip_Group_Sync_Double();
		}

		private function answer( int $code, $body = '', string $list = 'group', string $etag = '"g1-1-1"' ): array {
			return array(
				'code' => $code,
				'body' => is_string( $body ) ? $body : wp_json_encode( $body ),
				'etag' => $etag,
				'list' => $list,
			);
		}

		private function list_body( array $entries, array $whitelist = array() ): array {
			return array(
				'group'     => array(
					'id'        => 1,
					'name'      => 'Production',
					'ban_hours' => 24,
					'members'   => 5,
				),
				'entries'   => $entries,
				'whitelist' => $whitelist,
			);
		}

		private function wl( string $entry, string $note = 'office' ): array {
			return array(
				'entry' => $entry,
				'note'  => $note,
				'since' => gmdate( 'c', time() - 86400 ),
			);
		}

		private function entry( string $ip, int $seconds_from_now, string $reporter = 'web03' ): array {
			return array(
				'ip'         => $ip,
				'reporter'   => $reporter,
				'kind'       => 'agent',
				'categories' => array( 22, 18 ),
				'since'      => gmdate( 'c', time() - 600 ),
				'expires'    => gmdate( 'c', time() + $seconds_from_now ),
				'origin'     => 'report',
			);
		}

		private function row( string $ip, string $type, int $seconds_from_now ): array {
			return array(
				'ip_address'    => $ip,
				'block_type'    => $type,
				'blocked_until' => gmdate( 'Y-m-d H:i:s', time() + $seconds_from_now ),
			);
		}

		public function test_a_list_is_mirrored_as_group_blocks_until_the_named_expiry() {
			$this->sync->response = $this->answer( 200, $this->list_body( array( $this->entry( '45.33.32.10', 5 * HOUR_IN_SECONDS + 1800 ) ) ) );

			$this->assertSame( 'applied', $this->sync->sync() );

			$this->assertCount( 1, $this->sync->manager->blocked );
			$block = $this->sync->manager->blocked[0];
			$this->assertSame( '45.33.32.10', $block['ip'] );
			$this->assertSame( 'group: web03', $block['why'] );
			$this->assertSame( 6, $block['hours'], 'Five and a half hours until expiry round up to six.' );
			$this->assertSame( 'group', $block['type'] );

			$this->assertSame( '"g1-1-1"', \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '' ) );
			$group = \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_GROUP, null );
			$this->assertSame( 'Production', $group['name'] );
			$this->assertSame( 5, $group['members'] );
		}

		public function test_the_group_whitelist_is_mirrored_with_the_group_source() {
			$this->sync->response = $this->answer( 200, $this->list_body( array(), array( $this->wl( '45.33.32.0/24' ), $this->wl( '2001:db8:1::/64', 'lab' ) ) ) );

			$this->assertSame( 'applied', $this->sync->sync() );

			$this->assertSame(
				array(
					array( 'ip' => '45.33.32.0/24', 'why' => 'group: office', 'source' => 'group' ),
					array( 'ip' => '2001:db8:1::/64', 'why' => 'group: lab', 'source' => 'group' ),
				),
				$this->sync->manager->whitelisted
			);
			$this->assertSame( array(), $this->sync->manager->unwhitelisted );
		}

		public function test_a_second_sync_does_not_write_the_same_whitelist_row_again() {
			$this->sync->response = $this->answer( 200, $this->list_body( array(), array( $this->wl( '45.33.32.0/24' ) ) ) );
			$this->sync->sync();
			$this->sync->sync();

			$this->assertCount( 1, $this->sync->manager->whitelisted );
		}

		public function test_a_whitelist_entry_that_left_the_answer_is_removed_and_manual_rows_stay() {
			$this->sync->manager->whitelist_rows = array(
				array( 'ip_address' => '45.33.32.0/24', 'source' => 'group' ),
				array( 'ip_address' => '45.33.32.99', 'source' => 'group' ),
				array( 'ip_address' => '10.0.0.0/8', 'source' => 'manual' ),
			);
			$this->sync->response = $this->answer( 200, $this->list_body( array(), array( $this->wl( '45.33.32.0/24' ) ) ) );

			$this->sync->sync();

			$this->assertSame( array( array( 'ip' => '45.33.32.99', 'source' => 'group' ) ), $this->sync->manager->unwhitelisted );
			$this->assertSame( array( '45.33.32.0/24', '10.0.0.0/8' ), array_column( array_values( $this->sync->manager->whitelist_rows ), 'ip_address' ) );
		}

		public function test_a_204_removes_every_group_whitelist_row_and_no_manual_one() {
			$this->sync->manager->whitelist_rows = array(
				array( 'ip_address' => '45.33.32.0/24', 'source' => 'group' ),
				array( 'ip_address' => '10.0.0.0/8', 'source' => 'manual' ),
			);
			$this->sync->response = $this->answer( 204 );

			$this->sync->sync();

			$this->assertSame( array( '45.33.32.0/24' ), array_column( $this->sync->manager->unwhitelisted, 'ip' ) );
			$this->assertSame( array( '10.0.0.0/8' ), array_column( array_values( $this->sync->manager->whitelist_rows ), 'ip_address' ) );
		}

		public function test_a_304_leaves_the_whitelist_alone() {
			$this->sync->manager->whitelist_rows = array( array( 'ip_address' => '45.33.32.0/24', 'source' => 'group' ) );
			$this->sync->response                = $this->answer( 304 );

			$this->sync->sync();

			$this->assertSame( array(), $this->sync->manager->whitelisted );
			$this->assertSame( array(), $this->sync->manager->unwhitelisted );
		}

		public function test_an_answer_without_a_whitelist_field_removes_group_rows() {
			$this->sync->manager->whitelist_rows = array( array( 'ip_address' => '45.33.32.0/24', 'source' => 'group' ) );
			$body                                = $this->list_body( array() );
			unset( $body['whitelist'] );
			$this->sync->response = $this->answer( 200, $body );

			$this->sync->sync();

			$this->assertSame( array( '45.33.32.0/24' ), array_column( $this->sync->manager->unwhitelisted, 'ip' ) );
		}

		public function test_a_group_range_matches_as_a_range_for_v4_and_v6() {
			$this->assertTrue( \ReportedIP_Hive_Database::ip_in_cidr( '45.33.32.200', '45.33.32.0/24' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '45.33.33.1', '45.33.32.0/24' ) );
			$this->assertTrue( \ReportedIP_Hive_Database::ip_in_cidr( '2001:db8:1:0:dead:beef::1', '2001:db8:1::/64' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '2001:db8:2::1', '2001:db8:1::/64' ) );
			$this->assertFalse( \ReportedIP_Hive_Database::ip_in_cidr( '45.33.32.200', '2001:db8:1::/64' ) );
		}

		public function test_an_address_inside_a_group_range_is_neither_blocked_nor_kept_blocked() {
			$this->sync->manager->rows = array(
				$this->row( '45.33.32.7', 'automatic', HOUR_IN_SECONDS ),
				$this->row( '45.33.32.8', 'reputation', HOUR_IN_SECONDS ),
				$this->row( '45.33.32.9', 'manual', HOUR_IN_SECONDS ),
				$this->row( '45.33.40.1', 'automatic', HOUR_IN_SECONDS ),
			);
			$this->sync->response = $this->answer(
				200,
				$this->list_body(
					array( $this->entry( '45.33.32.10', HOUR_IN_SECONDS ), $this->entry( '45.33.40.2', HOUR_IN_SECONDS ) ),
					array( $this->wl( '45.33.32.0/24' ) )
				)
			);

			$this->sync->sync();

			$this->assertSame( array( '45.33.32.7', '45.33.32.8' ), $this->sync->manager->unblocked, 'Automatic and reputation blocks inside the range are lifted, the manual one and the block outside stay.' );
			$this->assertSame( array( '45.33.40.2' ), array_column( $this->sync->manager->blocked, 'ip' ), 'The listed address inside the range is refused by the whitelist.' );
		}

		public function test_a_whitelisted_address_is_dropped_from_the_report_queue_and_cannot_be_removed_by_hand() {
			$client = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-api-client.php' );
			$queue  = substr( $client, strpos( $client, 'function process_report_queue' ) );
			$guard  = strpos( $queue, '$database->is_whitelisted( $report->ip_address )' );
			$send   = strpos( $queue, '$this->report_ip( $report->ip_address' );
			$this->assertNotFalse( $guard, 'The queue worker must check the whitelist before sending.' );
			$this->assertLessThan( $send, $guard );

			$manager = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-ip-manager.php' );
			$this->assertStringContainsString( "public function remove_from_whitelist( \$ip_address, \$source = 'manual' )", $manager );
			$this->assertStringContainsString( 'get_whitelist_entry( $ip_address )', $manager );

			$schema = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-schema.php' );
			$this->assertStringContainsString( "source varchar(16) NOT NULL DEFAULT 'manual'", $schema );
			$this->assertGreaterThanOrEqual( 20, \ReportedIP_Hive_Migration_Manager::CURRENT_VERSION );
		}

		public function test_the_stored_etag_is_sent_and_a_304_changes_nothing() {
			\ReportedIP_Hive_Option_Routing::set( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '"g1-9-3"' );
			$this->sync->manager->rows = array( $this->row( '45.33.32.10', 'group', HOUR_IN_SECONDS ) );
			$this->sync->response      = $this->answer( 304 );

			$this->assertSame( 'unchanged', $this->sync->sync() );

			$this->assertSame( array( '"g1-9-3"' ), $this->sync->sent_etags );
			$this->assertSame( array(), $this->sync->manager->blocked );
			$this->assertSame( array(), $this->sync->manager->unblocked );
		}

		public function test_a_204_lifts_group_blocks_and_leaves_manual_ones_alone() {
			\ReportedIP_Hive_Option_Routing::set( \ReportedIP_Hive_Group_Sync::OPT_GROUP, array( 'name' => 'Production' ) );
			\ReportedIP_Hive_Option_Routing::set( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '"g1-9-3"' );
			$this->sync->manager->rows = array(
				$this->row( '45.33.32.10', 'group', HOUR_IN_SECONDS ),
				$this->row( '45.33.32.11', 'manual', HOUR_IN_SECONDS ),
				$this->row( '45.33.32.12', 'automatic', HOUR_IN_SECONDS ),
			);
			$this->sync->response = $this->answer( 204 );

			$this->assertSame( 'cleared', $this->sync->sync() );

			$this->assertSame( array( '45.33.32.10' ), $this->sync->manager->unblocked );
			$this->assertSame( array(), $this->sync->manager->blocked );
			$this->assertNull( \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_GROUP, null ) );
			$this->assertSame( '', \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '' ) );
		}

		public function test_a_whitelisted_address_is_never_blocked() {
			$this->sync->manager->whitelist = array( '45.33.32.10' );
			$this->sync->response           = $this->answer(
				200,
				$this->list_body(
					array(
						$this->entry( '45.33.32.10', HOUR_IN_SECONDS ),
						$this->entry( '45.33.32.11', HOUR_IN_SECONDS ),
					)
				)
			);

			$this->assertSame( 'applied', $this->sync->sync() );

			$this->assertSame( array( '45.33.32.11' ), array_column( $this->sync->manager->blocked, 'ip' ) );
			$this->assertSame( array(), $this->sync->manager->unblocked );
		}

		public function test_the_sync_only_ever_blocks_through_the_ip_manager() {
			$source = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-group-sync.php' );

			$this->assertStringContainsString( '$ip_manager->block_ip(', $source );
			$this->assertStringNotContainsString( 'block_ip_for_minutes', $source, 'The whitelist gate lives in IP_Manager::block_ip(); the sync must not bypass it.' );
			$this->assertStringNotContainsString( '->block_ip_for_minutes(', $source );
			$this->assertSame( 1, substr_count( $source, '->block_ip(' ), 'Exactly one block call, on the IP manager.' );
			$this->assertStringContainsString( '$ip_manager->block_ip(', $source );
		}

		public function test_an_answer_without_the_list_header_is_discarded() {
			\ReportedIP_Hive_Option_Routing::set( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '"old"' );
			$this->sync->manager->rows = array( $this->row( '45.33.32.10', 'group', HOUR_IN_SECONDS ) );
			$this->sync->response      = $this->answer( 200, "45.33.32.20\n45.33.32.21\n", '', '"community"' );

			$this->assertSame( 'discarded', $this->sync->sync() );

			$this->assertSame( array(), $this->sync->manager->blocked );
			$this->assertSame( array(), $this->sync->manager->unblocked, 'A discarded answer must not lift anything either.' );
			$this->assertSame( '"old"', \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '' ) );
		}

		public function test_a_204_without_the_list_header_is_discarded_too() {
			$this->sync->manager->rows = array( $this->row( '45.33.32.10', 'group', HOUR_IN_SECONDS ) );
			$this->sync->response      = $this->answer( 204, '', '' );

			$this->assertSame( 'discarded', $this->sync->sync() );
			$this->assertSame( array(), $this->sync->manager->unblocked );
		}

		public function test_a_plan_refusal_sets_the_marker_and_the_next_accepted_answer_clears_it() {
			$this->sync->response = $this->answer( 403, array( 'code' => 'group_tier' ), '' );

			$this->assertSame( 'tier', $this->sync->sync() );
			$this->assertSame( 'group_tier', \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_ERROR, '' ) );
			$this->assertSame( array(), $this->sync->manager->blocked );

			$this->sync->response = $this->answer( 200, $this->list_body( array() ) );

			$this->assertSame( 'applied', $this->sync->sync() );
			$this->assertSame( '', \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_ERROR, '' ) );
		}

		public function test_a_403_for_another_reason_is_a_plain_error() {
			$this->sync->response = $this->answer( 403, array( 'code' => 'server_unlicensed' ), '' );

			$this->assertSame( 'error', $this->sync->sync() );
			$this->assertSame( '', \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_ERROR, '' ) );
		}

		public function test_an_address_that_left_the_list_is_lifted() {
			$this->sync->manager->rows = array(
				$this->row( '45.33.32.10', 'group', HOUR_IN_SECONDS ),
				$this->row( '45.33.32.11', 'group', HOUR_IN_SECONDS ),
			);
			$this->sync->response = $this->answer( 200, $this->list_body( array( $this->entry( '45.33.32.10', 2 * HOUR_IN_SECONDS ) ) ) );

			$this->sync->sync();

			$this->assertSame( array( '45.33.32.11' ), $this->sync->manager->unblocked );
		}

		public function test_a_block_that_already_covers_the_expiry_is_not_written_again() {
			$this->sync->manager->rows = array( $this->row( '45.33.32.10', 'group', 3 * HOUR_IN_SECONDS ) );
			$this->sync->response      = $this->answer( 200, $this->list_body( array( $this->entry( '45.33.32.10', 2 * HOUR_IN_SECONDS ) ) ) );

			$this->sync->sync();

			$this->assertSame( array(), $this->sync->manager->blocked, 'Rewriting an unchanged block every fifteen minutes would flood the event log.' );
			$this->assertSame( array(), $this->sync->manager->unblocked );
		}

		public function test_a_block_is_extended_when_the_list_names_a_later_expiry() {
			$this->sync->manager->rows = array( $this->row( '45.33.32.10', 'group', HOUR_IN_SECONDS ) );
			$this->sync->response      = $this->answer( 200, $this->list_body( array( $this->entry( '45.33.32.10', 4 * HOUR_IN_SECONDS ) ) ) );

			$this->sync->sync();

			$this->assertSame( array( '45.33.32.10' ), array_column( $this->sync->manager->blocked, 'ip' ) );
			$this->assertSame( 4, $this->sync->manager->blocked[0]['hours'] );
		}

		public function test_a_manual_block_on_a_listed_address_is_left_alone() {
			$this->sync->manager->rows = array( $this->row( '45.33.32.10', 'manual', 10 * MINUTE_IN_SECONDS ) );
			$this->sync->response      = $this->answer( 200, $this->list_body( array( $this->entry( '45.33.32.10', 4 * HOUR_IN_SECONDS ) ) ) );

			$this->sync->sync();

			$this->assertSame( array(), $this->sync->manager->blocked );
			$this->assertSame( array(), $this->sync->manager->unblocked );
		}

		public function test_an_expired_or_broken_entry_is_skipped() {
			$this->sync->response = $this->answer(
				200,
				$this->list_body(
					array(
						$this->entry( '45.33.32.10', -60 ),
						array( 'ip' => '45.33.32.11' ),
						array( 'reporter' => 'web03', 'expires' => gmdate( 'c', time() + 3600 ) ),
					)
				)
			);

			$this->assertSame( 'applied', $this->sync->sync() );
			$this->assertSame( array(), $this->sync->manager->blocked );
		}

		public function test_an_unreadable_body_changes_nothing() {
			\ReportedIP_Hive_Option_Routing::set( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '"old"' );
			$this->sync->manager->rows = array( $this->row( '45.33.32.10', 'group', HOUR_IN_SECONDS ) );
			$this->sync->response      = $this->answer( 200, 'not json' );

			$this->assertSame( 'error', $this->sync->sync() );
			$this->assertSame( array(), $this->sync->manager->unblocked );
			$this->assertSame( '"old"', \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '' ) );
		}

		public function test_a_network_failure_changes_nothing() {
			$this->sync->manager->rows = array( $this->row( '45.33.32.10', 'group', HOUR_IN_SECONDS ) );
			$this->sync->response      = null;

			$this->assertSame( 'error', $this->sync->sync() );
			$this->assertSame( array(), $this->sync->manager->unblocked );
		}

		public function test_the_cron_job_runs_every_fifteen_minutes() {
			$this->assertContains( 'reportedip_hive_sync_group', \ReportedIP_Hive_Cron_Handler::get_hook_names() );

			$jobs = ( new \ReflectionClassConstant( \ReportedIP_Hive_Cron_Handler::class, 'JOBS' ) )->getValue();
			$this->assertSame( 'fifteen_minutes', $jobs['reportedip_hive_sync_group'] );
		}

		public function test_the_schema_and_the_migration_carry_the_group_block_type() {
			$schema = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-schema.php' );
			$this->assertStringContainsString( "block_type enum('manual','automatic','reputation','group')", $schema );
			$this->assertGreaterThanOrEqual( 19, \ReportedIP_Hive_Migration_Manager::CURRENT_VERSION );
			$this->assertTrue( method_exists( \ReportedIP_Hive_Migration_Manager::class, 'migrate_to_v19' ) );
		}

		public function test_a_plan_refusal_lifts_what_the_group_placed() {
			\ReportedIP_Hive_Option_Routing::set( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '"g1-9-3"' );
			$this->sync->manager->rows           = array(
				$this->row( '45.33.32.10', 'group', HOUR_IN_SECONDS ),
				$this->row( '45.33.32.11', 'automatic', HOUR_IN_SECONDS ),
			);
			$this->sync->manager->whitelist_rows = array(
				array( 'ip_address' => '10.0.0.0/24', 'source' => 'group' ),
				array( 'ip_address' => '10.0.1.1', 'source' => 'manual' ),
			);
			$this->sync->response                = $this->answer( 403, array( 'code' => 'group_tier' ), '' );

			$this->assertSame( 'tier', $this->sync->sync() );

			$this->assertSame( array( '45.33.32.10' ), $this->sync->manager->unblocked );
			$this->assertSame( array( '10.0.0.0/24' ), array_column( $this->sync->manager->unwhitelisted, 'ip' ) );
			$this->assertSame( '', \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '' ) );
		}

		public function test_a_shorter_automatic_block_becomes_the_group_ban() {
			$this->sync->manager->rows = array(
				$this->row( '45.33.32.10', 'automatic', 5 * MINUTE_IN_SECONDS ),
				$this->row( '45.33.32.11', 'reputation', 30 * HOUR_IN_SECONDS ),
			);
			$this->sync->response      = $this->answer(
				200,
				$this->list_body( array( $this->entry( '45.33.32.10', 4 * HOUR_IN_SECONDS ), $this->entry( '45.33.32.11', 4 * HOUR_IN_SECONDS ) ) )
			);

			$this->sync->sync();

			$this->assertSame( array( '45.33.32.10' ), array_column( $this->sync->manager->blocked, 'ip' ), 'A 304 would otherwise keep the address free once the five minutes run out.' );
			$this->assertSame( 'group', $this->sync->manager->blocked[0]['type'] );
			$this->assertSame( array(), $this->sync->manager->unblocked, 'The longer reputation block stays and is never lifted by the sync.' );
		}

		public function test_report_only_blocks_nothing_and_keeps_no_etag() {
			\ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_report_only_mode', true );
			$this->sync->response = $this->answer( 200, $this->list_body( array( $this->entry( '45.33.32.10', HOUR_IN_SECONDS ) ), array( $this->wl( '10.0.0.0/24' ) ) ) );

			$this->assertSame( 'report_only', $this->sync->sync() );

			$this->assertSame( array(), $this->sync->manager->blocked );
			$this->assertSame( array( '10.0.0.0/24' ), array_column( $this->sync->manager->whitelisted, 'ip' ), 'The whitelist still arrives, it enforces nothing.' );
			$this->assertSame( '', \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '' ) );
		}

		public function test_a_disconnected_site_drops_the_group_state_once() {
			\ReportedIP_Hive_Option_Routing::set( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '"g1-9-3"' );
			\ReportedIP_Hive_Option_Routing::set( \ReportedIP_Hive_Group_Sync::OPT_GROUP, array( 'name' => 'Production' ) );
			$this->sync->connected               = false;
			$this->sync->manager->rows           = array( $this->row( '45.33.32.10', 'group', HOUR_IN_SECONDS ) );
			$this->sync->manager->whitelist_rows = array( array( 'ip_address' => '10.0.0.0/24', 'source' => 'group' ) );

			$this->assertSame( 'released', $this->sync->sync() );
			$this->assertSame( array( '45.33.32.10' ), $this->sync->manager->unblocked );
			$this->assertSame( array(), $this->sync->manager->whitelist_rows );
			$this->assertNull( \ReportedIP_Hive_Option_Routing::get( \ReportedIP_Hive_Group_Sync::OPT_GROUP, null ) );
			$this->assertSame( array(), $this->sync->sent_etags, 'Nothing is fetched while disconnected.' );

			$this->assertSame( 'skipped', $this->sync->sync() );
		}

		public function test_the_whitelist_lift_pass_only_runs_when_the_whitelist_grew() {
			$this->sync->manager->whitelist_rows = array( array( 'ip_address' => '45.33.32.0/24', 'source' => 'group' ) );
			$this->sync->manager->rows           = array( $this->row( '45.33.32.7', 'automatic', HOUR_IN_SECONDS ) );
			$this->sync->response                = $this->answer( 200, $this->list_body( array(), array( $this->wl( '45.33.32.0/24' ) ) ) );

			$this->sync->sync();

			$this->assertSame( array(), $this->sync->manager->unblocked, 'An unchanged whitelist costs no lookup per active block.' );
		}

		public function test_a_range_around_the_own_server_counts_as_own() {
			$main = (string) file_get_contents( dirname( __DIR__, 2 ) . '/reportedip-hive.php' );
			$body = substr( $main, strpos( $main, 'public static function is_own_server_ip(' ), 900 );

			$range  = strpos( $body, 'ip_in_cidr( (string) $candidate, $ip )' );
			$single = strpos( $body, 'FILTER_VALIDATE_IP' );

			$this->assertNotFalse( $range, 'A group list may carry a /24 around this host; block_ip() must see the range as the host address.' );
			$this->assertLessThan( $single, $range, 'The range check must run before the single-address check refuses a CIDR string.' );
		}

		public function test_an_accepted_list_is_stored_whole_and_a_304_keeps_it() {
			$entries              = array( $this->entry( '45.33.32.10', HOUR_IN_SECONDS ), $this->entry( '45.33.32.11', -60 ) );
			$this->sync->response = $this->answer( 200, $this->list_body( $entries ) );

			$this->sync->sync();
			$this->assertCount( 2, $this->sync->store_double->entries, 'An expired entry is still shown, the tab explains it.' );

			$this->sync->response = $this->answer( 304 );
			$this->sync->sync();
			$this->assertCount( 2, $this->sync->store_double->entries );
			$this->assertSame( 2, \ReportedIP_Hive_Group_Sync::status()['entries'] );
			$this->assertSame( 'unchanged', \ReportedIP_Hive_Group_Sync::status()['last_result'] );
		}

		public function test_a_release_empties_the_stored_list() {
			\ReportedIP_Hive_Option_Routing::set( \ReportedIP_Hive_Group_Sync::OPT_ETAG, '"g1-9-3"' );
			$this->sync->store_double->entries = array( $this->entry( '45.33.32.10', HOUR_IN_SECONDS ) );
			$this->sync->response              = $this->answer( 204 );

			$this->sync->sync();

			$this->assertSame( array(), $this->sync->store_double->entries );
			$this->assertSame( 0, \ReportedIP_Hive_Group_Sync::status()['entries'] );
		}

		public function test_the_run_is_counted_by_reason_and_summarised_once() {
			$this->sync->manager->whitelist = array( '45.33.32.12' );
			$this->sync->own                = array( '45.33.32.13' );
			$this->sync->manager->rows      = array(
				$this->row( '45.33.32.11', 'automatic', MINUTE_IN_SECONDS ),
				$this->row( '45.33.32.14', 'manual', HOUR_IN_SECONDS ),
				$this->row( '45.33.32.20', 'group', HOUR_IN_SECONDS ),
			);
			$this->sync->response           = $this->answer(
				200,
				$this->list_body(
					array(
						$this->entry( '45.33.32.10', HOUR_IN_SECONDS ),
						$this->entry( '45.33.32.11', HOUR_IN_SECONDS ),
						$this->entry( '45.33.32.12', HOUR_IN_SECONDS ),
						$this->entry( '45.33.32.13', HOUR_IN_SECONDS ),
						$this->entry( '45.33.32.14', HOUR_IN_SECONDS ),
					),
					array( $this->wl( '10.0.0.0/24' ) )
				)
			);

			$this->assertSame( 'applied', $this->sync->sync() );

			$status = \ReportedIP_Hive_Group_Sync::status();
			$this->assertSame(
				array(
					'added'             => 1,
					'extended'          => 1,
					'lifted'            => 1,
					'whitelist_added'   => 1,
					'whitelist_removed' => 0,
					'skipped_whitelist' => 1,
					'skipped_own'       => 1,
					'skipped_manual'    => 1,
				),
				$status['changes']
			);
			$this->assertSame( 200, $status['http_code'] );
			$this->assertSame( 5, $status['entries'] );
			$this->assertCount( 1, $this->sync->events );
			$this->assertSame( array( '45.33.32.10', '45.33.32.11' ), array_column( $this->sync->manager->blocked, 'ip' ), 'The own address is never handed to block_ip().' );
		}

		public function test_a_run_that_changes_nothing_writes_no_event_and_keeps_the_last_change() {
			$this->sync->manager->rows = array( $this->row( '45.33.32.10', 'group', 3 * HOUR_IN_SECONDS ) );
			$this->sync->response      = $this->answer( 200, $this->list_body( array( $this->entry( '45.33.32.10', 2 * HOUR_IN_SECONDS ) ) ) );

			$this->sync->sync();

			$this->assertSame( array(), $this->sync->events );
			$this->assertSame( 0, \ReportedIP_Hive_Group_Sync::status()['last_change'] );
			$this->assertGreaterThan( 0, \ReportedIP_Hive_Group_Sync::status()['last_run'] );
		}

		public function test_a_skipped_run_leaves_the_status_alone() {
			$this->sync->connected = false;

			$this->assertSame( 'skipped', $this->sync->sync() );
			$this->assertSame( 0, \ReportedIP_Hive_Group_Sync::status()['last_run'] );
		}

		/**
		 * @dataProvider local_status_cases
		 */
		public function test_the_local_status_names_the_reason( string $expected, string $type, int $expires, bool $white, bool $own, bool $report_only ) {
			$this->assertSame( $expected, \ReportedIP_Hive_Group_Sync::local_status( $type, $expires, $white, $own, $report_only, 1000 ) );
		}

		public function local_status_cases(): array {
			return array(
				'group block'      => array( 'group', 'group', 2000, true, true, true ),
				'other block'      => array( 'other', 'automatic', 2000, true, false, false ),
				'expired'          => array( 'expired', '', 900, true, false, false ),
				'whitelisted'      => array( 'whitelisted', '', 2000, true, true, true ),
				'own server'       => array( 'own', '', 2000, false, true, true ),
				'report only'      => array( 'report_only', '', 2000, false, false, true ),
				'lifted by hand'   => array( 'lifted', '', 2000, false, false, false ),
			);
		}

		public function test_verify_key_hands_group_and_reputation_to_the_options() {
			$client = (string) file_get_contents( dirname( __DIR__, 2 ) . '/includes/class-api-client.php' );
			$this->assertStringContainsString( "\$data['data']['agent']['group']", $client );
			$this->assertStringContainsString( "\$data['data']['agent']['reputation']", $client );
			$this->assertStringContainsString( "foreach ( array( 'group', 'reputation' ) as \$field )", $client );
		}
	}
}
