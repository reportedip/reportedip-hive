<?php
/**
 * WP-CLI commands for user account blocking.
 *
 * Available as `wp reportedip user <subcommand>` once WP-CLI sees the plugin:
 *
 *     block <user>   → block an account and end its sessions
 *     unblock <user> → lift a block
 *     list           → list blocked accounts (table/json/csv/yaml)
 *
 * Sessions themselves are not covered here — core already ships
 * `wp user session list|destroy`.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.51
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

class ReportedIP_Hive_User_CLI {

	/**
	 * Register the class as a WP-CLI command.
	 *
	 * @return void
	 */
	public static function register() {
		WP_CLI::add_command( 'reportedip user', __CLASS__ );
	}

	/**
	 * Block a user account.
	 *
	 * The account keeps its content but cannot sign in, authenticate an
	 * application password or complete a password reset. Every WordPress
	 * session and every trusted 2FA device is revoked immediately.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or e-mail address.
	 *
	 * [--message=<text>]
	 * : Text appended to the standard notice on the sign-in page.
	 *
	 * [--note=<text>]
	 * : Internal note. Not shown at login, but part of the user's
	 * personal-data export.
	 *
	 * ## EXAMPLES
	 *
	 *     wp reportedip user block jdoe --note="offboarded 2026-09-01"
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function block( $args, $assoc_args ) {
		$user = self::fetch_user( $args );

		$result = ReportedIP_Hive_User_Block::block(
			$user->ID,
			isset( $assoc_args['message'] ) ? (string) $assoc_args['message'] : '',
			isset( $assoc_args['note'] ) ? (string) $assoc_args['note'] : ''
		);

		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}

		WP_CLI::success( 'Blocked ' . $user->user_login . ' (#' . $user->ID . '). Sessions and trusted devices revoked.' );
	}

	/**
	 * Lift the block on a user account.
	 *
	 * Never gated by the plan: an existing block can always be removed.
	 *
	 * ## OPTIONS
	 *
	 * <user>
	 * : User ID, login or e-mail address.
	 *
	 * ## EXAMPLES
	 *
	 *     wp reportedip user unblock jdoe
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function unblock( $args, $assoc_args ) {
		unset( $assoc_args );

		$user    = self::fetch_user( $args );
		$existed = ReportedIP_Hive_User_Block::is_blocked( $user->ID );
		$result  = ReportedIP_Hive_User_Block::unblock( $user->ID );

		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}
		if ( ! $existed ) {
			WP_CLI::log( 'No block existed for ' . $user->user_login . '.' );
		}

		WP_CLI::success( 'Unblocked ' . $user->user_login . ' (#' . $user->ID . ').' );
	}

	/**
	 * List blocked user accounts.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Output format.
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
	 *     wp reportedip user list --format=json
	 *
	 * @subcommand list
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function list_( $args, $assoc_args ) {
		unset( $args );

		$query = new WP_User_Query(
			array(
				'blog_id'      => 0,
				'meta_key'     => ReportedIP_Hive_User_Block::META, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Existence probe over a rare meta key.
				'meta_compare' => 'EXISTS',
				'number'       => -1,
			)
		);

		$rows = array();
		foreach ( (array) $query->get_results() as $user ) {
			$record = ReportedIP_Hive_User_Block::get( $user->ID );
			if ( null === $record ) {
				continue;
			}
			$rows[] = array(
				'id'         => (int) $user->ID,
				'login'      => (string) $user->user_login,
				'blocked_at' => $record['blocked_at'],
				'blocked_by' => ReportedIP_Hive_User_Block::blocked_by_label( $record['blocked_by'] ),
				'message'    => $record['message'],
				'note'       => $record['note'],
			);
		}

		if ( empty( $rows ) ) {
			WP_CLI::log( 'No blocked accounts.' );
			return;
		}

		$format = isset( $assoc_args['format'] ) ? (string) $assoc_args['format'] : 'table';
		WP_CLI\Utils\format_items( $format, $rows, array( 'id', 'login', 'blocked_at', 'blocked_by', 'message', 'note' ) );
	}

	/**
	 * Resolve the positional user argument or abort.
	 *
	 * @param array $args Positional arguments.
	 * @return WP_User
	 */
	private static function fetch_user( $args ) {
		$identifier = isset( $args[0] ) ? (string) $args[0] : '';
		if ( '' === $identifier ) {
			WP_CLI::error( 'Please name a user (ID, login or e-mail address).' );
		}

		$fetcher = new WP_CLI\Fetchers\User();
		return $fetcher->get_check( $identifier );
	}
}

ReportedIP_Hive_User_CLI::register();
