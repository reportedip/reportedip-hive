<?php
/**
 * WP-CLI commands for IP block management.
 *
 * Registers four command paths once WP-CLI sees the plugin:
 *
 *     block <ip>          → place a manual block on an IP or CIDR range
 *     unblock <ip>        → lift an active block (optionally reset counters)
 *     blocked list        → list active blocks (table/json/csv/yaml)
 *     attempts reset <ip> → clear the per-IP attempt counters
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.50
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

class ReportedIP_Hive_Block_CLI {

	/**
	 * Register the block-management command paths.
	 *
	 * @return void
	 */
	public static function register() {
		$instance = new self();

		WP_CLI::add_command( 'reportedip block', array( $instance, 'block' ) );
		WP_CLI::add_command( 'reportedip unblock', array( $instance, 'unblock' ) );
		WP_CLI::add_command( 'reportedip blocked list', array( $instance, 'blocked_list' ) );
		WP_CLI::add_command( 'reportedip attempts reset', array( $instance, 'attempts_reset' ) );
	}

	/**
	 * Place a manual block on an IP address or CIDR range.
	 *
	 * The block is enforced at `init` priority 1 and, when the extended
	 * protection guard is enabled, before WordPress loads. Whitelisted
	 * addresses cannot be blocked. With global report-only mode on, the
	 * block is logged but not enforced.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address (IPv4 or IPv6) or CIDR range to block.
	 *
	 * [--reason=<reason>]
	 * : Optional note stored with the block.
	 *
	 * [--hours=<hours>]
	 * : Block duration in hours. Defaults to the configured block
	 * duration setting.
	 *
	 * ## EXAMPLES
	 *
	 *     # Block an address with the configured default duration
	 *     wp reportedip block 203.0.113.9 --reason="abuse"
	 *
	 *     # Block a range for a week
	 *     wp reportedip block 203.0.113.0/24 --hours=168
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function block( $args, $assoc_args ) {
		$ip = isset( $args[0] ) ? (string) $args[0] : '';

		$manager = ReportedIP_Hive_IP_Manager::get_instance();

		if ( ! $manager->validate_ip_address( $ip ) ) {
			WP_CLI::error( 'Invalid IP address or CIDR range: ' . $ip );
		}

		if ( $manager->is_whitelisted( $ip ) ) {
			WP_CLI::error( 'Cannot block a whitelisted address: ' . $ip );
		}

		$reason = isset( $assoc_args['reason'] ) ? (string) $assoc_args['reason'] : '';
		$hours  = isset( $assoc_args['hours'] ) ? absint( $assoc_args['hours'] ) : null;

		if ( isset( $assoc_args['hours'] ) && $hours < 1 ) {
			WP_CLI::error( 'Invalid --hours value: must be a positive integer.' );
		}

		$report_only = (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false );

		$result = $manager->block_ip( $ip, $reason, $hours, 'manual' );

		if ( empty( $result['success'] ) ) {
			WP_CLI::error( 'Failed to block ' . $ip . '.' );
		}

		if ( $report_only ) {
			WP_CLI::warning( 'Report-only mode is active: the block on ' . $ip . ' was logged but is NOT enforced.' );
			return;
		}

		WP_CLI::success( 'Blocked ' . $ip . ( null !== $hours ? ' for ' . $hours . ' hours' : '' ) . '.' );
	}

	/**
	 * Lift an active block from an IP address or CIDR range.
	 *
	 * The attempt counters survive an unblock; while a threshold is
	 * still exceeded inside its timeframe, the next request re-blocks
	 * the address immediately, pass --reset-attempts to clear them in
	 * the same call. The escalation ladder keeps counting past
	 * `ip_blocked` log events, so a future block of the same address
	 * resumes on the previously reached rung.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The blocked IP address or CIDR range to release.
	 *
	 * [--reset-attempts]
	 * : Also clear the per-IP attempt counters so the address is not
	 * re-blocked by a still-exceeded threshold.
	 *
	 * ## EXAMPLES
	 *
	 *     # Release a locked-out customer for good
	 *     wp reportedip unblock 203.0.113.9 --reset-attempts
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function unblock( $args, $assoc_args ) {
		$ip = isset( $args[0] ) ? (string) $args[0] : '';

		$manager = ReportedIP_Hive_IP_Manager::get_instance();

		if ( ! $manager->validate_ip_address( $ip ) ) {
			WP_CLI::error( 'Invalid IP address or CIDR range: ' . $ip );
		}

		$was_blocked = $manager->is_blocked( $ip );
		$result      = $manager->unblock_ip( $ip );

		if ( empty( $result['success'] ) ) {
			WP_CLI::error( 'Failed to unblock ' . $ip . '.' );
		}

		if ( isset( $assoc_args['reset-attempts'] ) ) {
			$deleted = ReportedIP_Hive_Database::get_instance()->reset_attempt_counter( $ip );
			WP_CLI::log( 'Cleared ' . (int) $deleted . ' attempt counter(s) for ' . $ip . '.' );
		} elseif ( $was_blocked ) {
			WP_CLI::log( 'Attempt counters were kept; use --reset-attempts if the address gets re-blocked immediately.' );
		}

		if ( ! $was_blocked ) {
			WP_CLI::log( 'No active block existed for ' . $ip . '.' );
			return;
		}

		WP_CLI::success( 'Unblocked ' . $ip . '.' );
	}

	/**
	 * List active IP blocks.
	 *
	 * A `blocked_until` of `permanent` means the block has no expiry;
	 * datetimes are UTC.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp reportedip blocked list
	 *     wp reportedip blocked list --format=csv
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function blocked_list( $args, $assoc_args ) {
		unset( $args );

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		$entries = ReportedIP_Hive_IP_Manager::get_instance()->get_blocked_ips( true );

		if ( empty( $entries ) ) {
			WP_CLI::log( 'No active blocks.' );
			return;
		}

		$rows = array();
		foreach ( $entries as $entry ) {
			$rows[] = array(
				'ip_address'    => (string) $entry->ip_address,
				'reason'        => '' !== (string) $entry->reason ? (string) $entry->reason : '-',
				'block_type'    => (string) $entry->block_type,
				'blocked_until' => null !== $entry->blocked_until ? (string) $entry->blocked_until : 'permanent',
				'created_at'    => (string) $entry->created_at,
			);
		}

		\WP_CLI\Utils\format_items( $format, $rows, array( 'ip_address', 'reason', 'block_type', 'blocked_until', 'created_at' ) );
	}

	/**
	 * Clear the per-IP attempt counters.
	 *
	 * Counters feed the auto-block thresholds; clearing them gives the
	 * address a clean slate inside the current timeframe. This does not
	 * lift an active block, use `wp reportedip unblock` for that.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address whose counters should be cleared.
	 *
	 * [--type=<type>]
	 * : Clear only this counter bucket (e.g. login, comment_spam,
	 * xmlrpc, scan_404). Omit to clear all buckets for the address.
	 *
	 * ## EXAMPLES
	 *
	 *     # Clear every counter for an address
	 *     wp reportedip attempts reset 203.0.113.9
	 *
	 *     # Clear only the failed-login counter
	 *     wp reportedip attempts reset 203.0.113.9 --type=login
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function attempts_reset( $args, $assoc_args ) {
		$ip = isset( $args[0] ) ? (string) $args[0] : '';

		if ( ! ReportedIP_Hive_IP_Manager::get_instance()->validate_ip_address( $ip ) ) {
			WP_CLI::error( 'Invalid IP address or CIDR range: ' . $ip );
		}

		$type = isset( $assoc_args['type'] ) ? (string) $assoc_args['type'] : null;

		$deleted = ReportedIP_Hive_Database::get_instance()->reset_attempt_counter( $ip, $type );

		if ( false === $deleted ) {
			WP_CLI::error( 'Failed to reset attempt counters for ' . $ip . '.' );
		}

		if ( 0 === (int) $deleted ) {
			WP_CLI::log( 'No attempt counters existed for ' . $ip . ( $type ? ' (type ' . $type . ')' : '' ) . '.' );
			return;
		}

		WP_CLI::success( 'Cleared ' . (int) $deleted . ' attempt counter(s) for ' . $ip . '.' );
	}
}

ReportedIP_Hive_Block_CLI::register();
