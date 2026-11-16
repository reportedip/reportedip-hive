<?php
/**
 * WP-CLI commands for the plugin settings.
 *
 * Available as `wp reportedip settings <subcommand>` once WP-CLI sees
 * the plugin:
 *
 *     list              → every setting with its kind and current value
 *     get <key>         → one setting
 *     set <key> <value> → write one setting
 *
 * The command reads the settings registry and writes through the same
 * pipeline as every other channel, so validation, plan limits and the
 * multisite routing are the ones the admin pages use.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     3.0.9
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Reads and writes registry settings from the shell.
 *
 * @since 3.0.9
 */
class ReportedIP_Hive_Settings_CLI {

	/**
	 * Register the class as a WP-CLI command.
	 *
	 * @return void
	 */
	public static function register() {
		WP_CLI::add_command( 'reportedip settings', __CLASS__ );
	}

	/**
	 * Settings as rows of key, kind and current value.
	 *
	 * @param string $key One key, '' for every setting.
	 * @return array<int, array{key:string, kind:string, value:string}> Empty when the key is unknown.
	 */
	public static function rows( $key = '' ) {
		$spec = ReportedIP_Hive_Settings_Registry::remote_spec();
		if ( '' !== $key ) {
			$spec = array_intersect_key( $spec, array( $key => true ) );
		}

		$rows = array();
		foreach ( ReportedIP_Hive_Settings_Registry::current_values( array_keys( $spec ) ) as $name => $value ) {
			$value  = ReportedIP_Hive_Settings_Registry::normalize_value( $name, $value );
			$rows[] = array(
				'key'   => $name,
				'kind'  => (string) $spec[ $name ]['kind'],
				'value' => is_bool( $value ) ? ( $value ? '1' : '0' ) : (string) $value,
			);
		}
		return $rows;
	}

	/**
	 * Write one setting through the shared pipeline.
	 *
	 * @param string $key   Option key.
	 * @param string $value Raw value.
	 * @return array{status:string, message:string} Status as reported by the pipeline.
	 */
	public static function write( $key, $value ) {
		$out    = ReportedIP_Hive_Settings_Apply::apply( array( $key => $value ), 'cli' );
		$result = $out['results'][ $key ] ?? array( 'status' => ReportedIP_Hive_Settings_Apply::STATUS_UNKNOWN );

		return array(
			'status'  => (string) $result['status'],
			'message' => (string) ( $result['message'] ?? '' ),
		);
	}

	/**
	 * List every setting with its kind and current value.
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
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp reportedip settings list
	 *     wp reportedip settings list --format=json
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function list( $args, $assoc_args ) {
		unset( $args );

		\WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), self::rows(), array( 'key', 'kind', 'value' ) );
	}

	/**
	 * Show one setting.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The option key, as printed by `wp reportedip settings list`.
	 *
	 * [--format=<format>]
	 * : Render output in a particular format.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp reportedip settings get reportedip_hive_failed_login_threshold
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function get( $args, $assoc_args ) {
		$key  = (string) ( $args[0] ?? '' );
		$rows = self::rows( $key );

		if ( empty( $rows ) ) {
			WP_CLI::error( 'unknown_key: ' . $key );
		}

		\WP_CLI\Utils\format_items( (string) ( $assoc_args['format'] ?? 'table' ), $rows, array( 'key', 'kind', 'value' ) );
	}

	/**
	 * Write one setting.
	 *
	 * The value passes the same validation and plan limits as a change
	 * on the admin pages. Switches take 1 or 0, lists take the stored
	 * form shown by `get`.
	 *
	 * ## OPTIONS
	 *
	 * <key>
	 * : The option key, as printed by `wp reportedip settings list`.
	 *
	 * <value>
	 * : The new value.
	 *
	 * ## EXAMPLES
	 *
	 *     wp reportedip settings set reportedip_hive_failed_login_threshold 8
	 *     wp reportedip settings set reportedip_hive_monitor_comments 0
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Associative arguments.
	 * @return void
	 */
	public function set( $args, $assoc_args ) {
		unset( $assoc_args );

		$key    = (string) ( $args[0] ?? '' );
		$result = self::write( $key, (string) ( $args[1] ?? '' ) );

		if ( ReportedIP_Hive_Settings_Apply::STATUS_APPLIED === $result['status'] ) {
			WP_CLI::success( 'Updated ' . $key . '.' );
			return;
		}
		if ( ReportedIP_Hive_Settings_Apply::STATUS_UNCHANGED === $result['status'] ) {
			WP_CLI::success( $key . ' already has this value.' );
			return;
		}

		WP_CLI::error( $result['status'] . ': ' . $key . ( '' !== $result['message'] ? ' (' . $result['message'] . ')' : '' ) );
	}
}

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	ReportedIP_Hive_Settings_CLI::register();
}
