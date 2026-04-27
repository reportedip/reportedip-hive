<?php
/**
 * WP-CLI commands for 2FA administration.
 *
 * Available as `wp reportedip 2fa …` once WP-CLI sees the plugin:
 *   status [--user=<id>]                  → overview
 *   enable --user=<id> --method=<m>       → flag one method (TOTP setup still needs a secret, see --secret)
 *   disable --user=<id> [--method=<m>]    → drop one or all methods
 *   reset --user=<id>                     → full 2FA reset (logs audit entry + email)
 *   enforce --role=<role> [--remove]      → toggle role-based enforcement
 *   audit [--user=<id>] [--since=<date>]  → query 2FA audit log entries
 *   cleanup                               → prune expired trusted devices
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.4.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

class ReportedIP_Hive_Two_Factor_CLI {

	/**
	 * Register the class as a WP-CLI command tree (each public method is a subcommand).
	 */
	public static function register() {
		WP_CLI::add_command( 'reportedip 2fa', __CLASS__ );
	}

	/**
	 * ## OPTIONS
	 *
	 * [<user_id>]
	 * : Restrict output to a single user.
	 */
	public function status( $args, $assoc ) {
		unset( $assoc );
		$user_id = isset( $args[0] ) ? absint( $args[0] ) : 0;

		if ( $user_id ) {
			$user = get_userdata( $user_id );
			if ( ! $user ) {
				WP_CLI::error( 'User not found.' );
			}
			self::render_user_row( $user );
			return;
		}

		global $wpdb;
		$ids  = $wpdb->get_col( "SELECT ID FROM {$wpdb->users} ORDER BY ID ASC LIMIT 500" ); // phpcs:ignore WordPress.DB
		$rows = array();
		foreach ( $ids as $id ) {
			$user = get_userdata( (int) $id );
			if ( ! $user ) {
				continue; }
			$methods = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user->ID );
			$rows[]  = array(
				'id'       => $user->ID,
				'login'    => $user->user_login,
				'methods'  => implode( ',', $methods ),
				'enabled'  => ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID ) ? 'yes' : 'no',
				'enforced' => ReportedIP_Hive_Two_Factor::is_enforced_for_user( $user ) ? 'yes' : 'no',
			);
		}
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'id', 'login', 'methods', 'enabled', 'enforced' ) );
	}

	/**
	 * ## OPTIONS
	 *
	 * <user_id>
	 * : Target user ID (positional).
	 *
	 * --method=<method>
	 * : One of: totp, email, webauthn, sms.
	 *
	 * [--secret=<secret>]
	 * : Optional TOTP secret to import (Base32). Skip for email/webauthn/sms setups
	 *   — those require interactive enrolment; CLI only flags the method.
	 */
	public function enable( $args, $assoc ) {
		$user_id = isset( $args[0] ) ? absint( $args[0] ) : 0;
		$method  = isset( $assoc['method'] ) ? sanitize_key( $assoc['method'] ) : '';
		if ( ! $user_id || ! $method ) {
			WP_CLI::error( 'Missing <user_id> or --method.' );
		}
		if ( ! ReportedIP_Hive_Two_Factor::get_method_meta_key( $method ) ) {
			WP_CLI::error( 'Unknown method: ' . $method );
		}

		if ( ReportedIP_Hive_Two_Factor::METHOD_TOTP === $method && ! empty( $assoc['secret'] ) ) {
			$encrypted = ReportedIP_Hive_Two_Factor_Crypto::encrypt( strtoupper( (string) $assoc['secret'] ) );
			if ( false === $encrypted ) {
				WP_CLI::error( 'Could not encrypt the TOTP secret — check REPORTEDIP_AUTH_KEY / AUTH_KEY.' );
			}
			update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_SECRET, $encrypted );
			update_user_meta( $user_id, ReportedIP_Hive_Two_Factor::META_TOTP_CONFIRMED, '1' );
		}

		ReportedIP_Hive_Two_Factor::enable_for_user( $user_id, $method );
		WP_CLI::success( sprintf( '2FA method "%s" flagged for user #%d.', $method, $user_id ) );
	}

	/**
	 * ## OPTIONS
	 *
	 * <user_id>
	 * : Target user ID (positional).
	 *
	 * [--method=<method>]
	 * : Single method to remove. If omitted, disables all 2FA for the user.
	 */
	public function disable( $args, $assoc ) {
		$user_id = isset( $args[0] ) ? absint( $args[0] ) : 0;
		if ( ! $user_id ) {
			WP_CLI::error( 'Missing --user.' );
		}
		if ( ! empty( $assoc['method'] ) ) {
			$method = sanitize_key( $assoc['method'] );
			if ( ! ReportedIP_Hive_Two_Factor::disable_method( $user_id, $method ) ) {
				WP_CLI::error( 'Unknown method.' );
			}
			WP_CLI::success( sprintf( 'Method "%s" removed from user #%d.', $method, $user_id ) );
			return;
		}
		ReportedIP_Hive_Two_Factor::disable_for_user( $user_id );
		WP_CLI::success( sprintf( 'All 2FA data removed for user #%d.', $user_id ) );
	}

	/**
	 * ## OPTIONS
	 *
	 * <user_id>
	 * : Target user ID (positional).
	 */
	public function reset( $args, $assoc ) {
		unset( $assoc );
		$user_id = isset( $args[0] ) ? absint( $args[0] ) : 0;
		if ( ! $user_id ) {
			WP_CLI::error( 'Missing --user.' );
		}
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			WP_CLI::error( 'User not found.' );
		}
		ReportedIP_Hive_Two_Factor::disable_for_user( $user_id );

		$logger = ReportedIP_Hive_Logger::get_instance();
		$logger->warning(
			'2FA reset via WP-CLI',
			'cli',
			array( 'target_user_id' => $user_id )
		);

		WP_CLI::success( sprintf( '2FA reset for user #%d (%s).', $user_id, $user->user_login ) );
	}

	/**
	 * ## OPTIONS
	 *
	 * --role=<role>
	 * : Role slug to enforce 2FA on.
	 *
	 * [--remove]
	 * : Remove the role from the enforcement list instead.
	 */
	public function enforce( $args, $assoc ) {
		unset( $args );
		$role   = isset( $assoc['role'] ) ? sanitize_key( $assoc['role'] ) : '';
		$remove = ! empty( $assoc['remove'] );
		if ( ! $role ) {
			WP_CLI::error( 'Missing --role.' );
		}
		$roles = wp_roles()->get_names();
		if ( ! isset( $roles[ $role ] ) ) {
			WP_CLI::error( 'Unknown role: ' . $role );
		}

		$current = json_decode( (string) get_option( 'reportedip_hive_2fa_enforce_roles', '[]' ), true );
		$current = is_array( $current ) ? $current : array();
		if ( $remove ) {
			$current = array_values( array_diff( $current, array( $role ) ) );
		} else {
			$current[] = $role;
			$current   = array_values( array_unique( $current ) );
		}
		update_option( 'reportedip_hive_2fa_enforce_roles', wp_json_encode( $current ) );

		WP_CLI::success( sprintf( 'Enforced roles: %s', implode( ', ', $current ) ?: '(none)' ) );
	}

	/**
	 * ## OPTIONS
	 *
	 * [<user_id>]
	 * : Filter by user ID (positional).
	 *
	 * [--since=<date>]
	 * : Only show events since this date (any strtotime-compatible string).
	 */
	public function audit( $args, $assoc ) {
		global $wpdb;
		$table = $wpdb->prefix . 'reportedip_hive_logs';

		$where  = array( "event_type LIKE '%2fa%' OR details LIKE '%2fa%'" );
		$params = array();
		if ( ! empty( $assoc['since'] ) ) {
			$ts = strtotime( (string) $assoc['since'] );
			if ( $ts ) {
				$where[]  = 'created_at >= %s';
				$params[] = gmdate( 'Y-m-d H:i:s', $ts );
			}
		}

		$sql  = "SELECT id, created_at, event_type, ip_address, severity, details FROM $table WHERE " . implode( ' AND ', $where ) . ' ORDER BY id DESC LIMIT 100';
		$rows = $params
			? $wpdb->get_results( $wpdb->prepare( $sql, $params ) ) // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe: table name from $wpdb->prefix; placeholders used for params.
			: $wpdb->get_results( $sql );                            // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Safe: table name from $wpdb->prefix; no user input in SQL.

		$user_filter = isset( $args[0] ) ? absint( $args[0] ) : 0;
		$formatted   = array();
		foreach ( $rows as $row ) {
			$detail = json_decode( (string) $row->details, true );
			if ( $user_filter ) {
				$uid = (int) ( $detail['user_id'] ?? $detail['target_user_id'] ?? 0 );
				if ( $uid !== $user_filter ) {
					continue; }
			}
			$formatted[] = array(
				'id'      => $row->id,
				'when'    => $row->created_at,
				'event'   => $row->event_type,
				'ip'      => $row->ip_address,
				'level'   => $row->severity,
				'details' => is_array( $detail ) ? wp_json_encode( $detail ) : $row->details,
			);
		}
		\WP_CLI\Utils\format_items( 'table', $formatted, array( 'id', 'when', 'event', 'ip', 'level', 'details' ) );
	}

	/**
	 * Prune expired trusted-device rows.
	 */
	public function cleanup() {
		$removed = ReportedIP_Hive_Two_Factor::cleanup_expired_devices();
		WP_CLI::success( sprintf( '%d expired trusted devices removed.', $removed ) );
	}

	private function render_user_row( $user ) {
		$methods = ReportedIP_Hive_Two_Factor::get_user_enabled_methods( $user->ID );
		WP_CLI::line( sprintf( 'User:      #%d %s (%s)', $user->ID, $user->user_login, $user->user_email ) );
		WP_CLI::line( sprintf( 'Enabled:   %s', ReportedIP_Hive_Two_Factor::is_user_enabled( $user->ID ) ? 'yes' : 'no' ) );
		WP_CLI::line( sprintf( 'Methods:   %s', implode( ', ', $methods ) ?: '(none)' ) );
		WP_CLI::line( sprintf( 'Primary:   %s', (string) get_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_METHOD, true ) ) );
		WP_CLI::line( sprintf( 'Skip cnt:  %d', (int) get_user_meta( $user->ID, ReportedIP_Hive_Two_Factor::META_SKIP_COUNT, true ) ) );
		WP_CLI::line( sprintf( 'Recovery:  %d codes', ReportedIP_Hive_Two_Factor_Recovery::get_remaining_count( $user->ID ) ) );
		WP_CLI::line( sprintf( 'Enforced:  %s', ReportedIP_Hive_Two_Factor::is_enforced_for_user( $user ) ? 'yes' : 'no' ) );
		WP_CLI::line( sprintf( 'In grace:  %s', ReportedIP_Hive_Two_Factor::is_in_grace_period( $user->ID ) ? 'yes' : 'no' ) );
	}
}

ReportedIP_Hive_Two_Factor_CLI::register();
