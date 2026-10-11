<?php
/**
 * WP-CLI command for the support bundle.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.73
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * `wp reportedip support-bundle`: the support bundle as JSON.
 *
 * @since 2.1.73
 */
class ReportedIP_Hive_Support_Bundle_CLI {

	/**
	 * Register the class as a WP-CLI command.
	 *
	 * @return void
	 */
	public static function register() {
		WP_CLI::add_command( 'reportedip support-bundle', __CLASS__ );
	}

	/**
	 * Print or save the support bundle.
	 *
	 * ## OPTIONS
	 *
	 * [--days=<days>]
	 * : Period in days, 1 to 30.
	 * ---
	 * default: 7
	 * ---
	 *
	 * [--events=<events>]
	 * : Raw events to include, 0 to 2000.
	 * ---
	 * default: 300
	 * ---
	 *
	 * [--full-ips]
	 * : Keep full IP addresses instead of their network.
	 *
	 * [--output=<file>]
	 * : Write to this file instead of standard output.
	 *
	 * @param array<int,string>    $args       Positional arguments.
	 * @param array<string,string> $assoc_args Named arguments.
	 * @return void
	 */
	public function __invoke( $args, $assoc_args ) {
		$bundle = ReportedIP_Hive_Support_Bundle::build(
			array(
				'days'     => isset( $assoc_args['days'] ) ? (int) $assoc_args['days'] : 7,
				'events'   => isset( $assoc_args['events'] ) ? (int) $assoc_args['events'] : 300,
				'full_ips' => isset( $assoc_args['full-ips'] ),
			)
		);
		ReportedIP_Hive_Support_Bundle::log_generated( 'cli' );

		$json = (string) wp_json_encode( $bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );

		if ( ! empty( $assoc_args['output'] ) ) {
			if ( false === file_put_contents( (string) $assoc_args['output'], $json ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- CLI writes to the path the operator names.
				WP_CLI::error( 'Could not write ' . $assoc_args['output'] );
			}
			WP_CLI::success( 'Support bundle written to ' . $assoc_args['output'] );
			return;
		}

		WP_CLI::line( $json );
	}
}

ReportedIP_Hive_Support_Bundle_CLI::register();
