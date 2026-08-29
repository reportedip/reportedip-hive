<?php
/**
 * WP-CLI commands for whitelist management.
 *
 * Available as `wp reportedip whitelist <subcommand>` once WP-CLI sees
 * the plugin:
 *
 *     add <ip>    → whitelist an IP or CIDR range (lifts an active block)
 *     remove <ip> → remove an IP or CIDR range from the whitelist
 *     list        → list active whitelist entries (table/json/csv/yaml)
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

class ReportedIP_Hive_Whitelist_CLI {

	/**
	 * Register the class as a WP-CLI command.
	 *
	 * @return void
	 */
	public static function register() {
		WP_CLI::add_command( 'reportedip whitelist', __CLASS__ );
	}

	/**
	 * Add an IP address or CIDR range to the whitelist.
	 *
	 * A whitelisted address is exempt from every protection layer,
	 * including the pre-WordPress guard. An active block on the same
	 * address is lifted automatically.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The IP address (IPv4 or IPv6) or CIDR range to whitelist.
	 *
	 * [--reason=<reason>]
	 * : Optional note stored with the entry.
	 *
	 * [--expires=<datetime>]
	 * : Optional expiry as `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS` in the
	 * site's local timezone. Omit for a permanent entry.
	 *
	 * ## EXAMPLES
	 *
	 *     # Whitelist an office IP permanently
	 *     wp reportedip whitelist add 203.0.113.9 --reason="office"
	 *
	 *     # Whitelist a rotating IPv6 prefix until year's end
	 *     wp reportedip whitelist add 2001:db8::/56 --expires="2026-12-31"
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function add( $args, $assoc_args ) {
		$ip = isset( $args[0] ) ? (string) $args[0] : '';

		$manager = ReportedIP_Hive_IP_Manager::get_instance();

		if ( ! $manager->validate_ip_address( $ip ) ) {
			WP_CLI::error( 'Invalid IP address or CIDR range: ' . $ip );
		}

		$reason  = isset( $assoc_args['reason'] ) ? (string) $assoc_args['reason'] : '';
		$expires = isset( $assoc_args['expires'] ) ? (string) $assoc_args['expires'] : null;

		if ( null !== $expires && false === strtotime( $expires ) ) {
			WP_CLI::error( 'Invalid --expires value: ' . $expires );
		}

		$was_blocked = $manager->is_blocked( $ip );
		$result      = $manager->whitelist_ip( $ip, $reason, $expires );

		if ( empty( $result['success'] ) ) {
			if ( $manager->is_whitelisted( $ip ) ) {
				WP_CLI::error( 'Already whitelisted: ' . $ip );
			}
			WP_CLI::error( 'Failed to whitelist ' . $ip . '.' );
		}

		if ( $was_blocked ) {
			WP_CLI::log( 'Active block on ' . $ip . ' was lifted.' );
		}

		WP_CLI::success( 'Whitelisted ' . $ip . ( $expires ? ' until ' . $expires : '' ) . '.' );
	}

	/**
	 * Remove an IP address or CIDR range from the whitelist.
	 *
	 * ## OPTIONS
	 *
	 * <ip>
	 * : The whitelisted IP address or CIDR range to remove.
	 *
	 * ## EXAMPLES
	 *
	 *     wp reportedip whitelist remove 203.0.113.9
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function remove( $args, $assoc_args ) {
		unset( $assoc_args );

		$ip = isset( $args[0] ) ? (string) $args[0] : '';

		$manager = ReportedIP_Hive_IP_Manager::get_instance();

		if ( ! $manager->validate_ip_address( $ip ) ) {
			WP_CLI::error( 'Invalid IP address or CIDR range: ' . $ip );
		}

		if ( ! $manager->is_whitelisted( $ip ) ) {
			WP_CLI::error( 'Not on the whitelist: ' . $ip );
		}

		$result = $manager->remove_from_whitelist( $ip );

		if ( empty( $result['success'] ) ) {
			WP_CLI::error( 'Failed to remove ' . $ip . ' from the whitelist.' );
		}

		WP_CLI::success( 'Removed ' . $ip . ' from the whitelist.' );
	}

	/**
	 * List active whitelist entries.
	 *
	 * The `expires_at` column is the site's local time (the one plugin
	 * datetime column that is not UTC); `created_at` is UTC.
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
	 *     wp reportedip whitelist list
	 *     wp reportedip whitelist list --format=json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function list( $args, $assoc_args ) {
		unset( $args );

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';

		$entries = ReportedIP_Hive_IP_Manager::get_instance()->get_whitelist( true );

		if ( empty( $entries ) ) {
			WP_CLI::log( 'The whitelist is empty.' );
			return;
		}

		$rows = array();
		foreach ( $entries as $entry ) {
			$rows[] = array(
				'ip_address' => (string) $entry->ip_address,
				'reason'     => '' !== (string) $entry->reason ? (string) $entry->reason : '-',
				'added_by'   => (int) $entry->added_by,
				'expires_at' => null !== $entry->expires_at ? (string) $entry->expires_at : 'never',
				'created_at' => (string) $entry->created_at,
			);
		}

		\WP_CLI\Utils\format_items( $format, $rows, array( 'ip_address', 'reason', 'added_by', 'expires_at', 'created_at' ) );
	}
}

ReportedIP_Hive_Whitelist_CLI::register();
