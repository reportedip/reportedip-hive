<?php
/**
 * WP-CLI commands for the Hardening Mode.
 *
 * Available as `wp reportedip hardening …` once WP-CLI sees the plugin:
 *   status                       → show active flag, expires_at, reason
 *   activate [--minutes=<int>]   → force-activate the window (manual trigger)
 *   deactivate                   → clear an active window immediately
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.8
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

class ReportedIP_Hive_Hardening_CLI {

	/**
	 * Register the class as a WP-CLI command tree.
	 *
	 * @return void
	 */
	public static function register() {
		WP_CLI::add_command( 'reportedip hardening', __CLASS__ );
	}

	/**
	 * Show the current Hardening Mode state.
	 *
	 * @return void
	 */
	public function status() {
		$active     = ReportedIP_Hive_Hardening_Mode::is_active();
		$expires_at = ReportedIP_Hive_Hardening_Mode::expires_at();
		$reason     = ReportedIP_Hive_Hardening_Mode::current_reason();
		$available  = ReportedIP_Hive_Hardening_Mode::is_available();

		WP_CLI::log( 'Hardening Mode status' );
		WP_CLI::log( '----------------------' );
		WP_CLI::log( 'available:  ' . ( $available ? 'yes' : 'no (PRO tier or master toggle off)' ) );
		WP_CLI::log( 'active:     ' . ( $active ? 'yes' : 'no' ) );
		if ( $active && $expires_at ) {
			WP_CLI::log( 'expires_at: ' . gmdate( 'Y-m-d H:i:s', (int) $expires_at ) . ' UTC' );
		}
		if ( is_array( $reason ) ) {
			WP_CLI::log( 'reason:' );
			foreach ( $reason as $key => $value ) {
				WP_CLI::log( '  ' . $key . ': ' . ( is_scalar( $value ) ? $value : wp_json_encode( $value ) ) );
			}
		}
	}

	/**
	 * Force-activate the Hardening Mode (manual trigger).
	 *
	 * ## OPTIONS
	 *
	 * [--minutes=<int>]
	 * : Override the configured duration (5–360). Defaults to the option value.
	 *
	 * @param array $args
	 * @param array $assoc
	 * @return void
	 */
	public function activate( $args, $assoc ) {
		unset( $args );

		if ( ! ReportedIP_Hive_Hardening_Mode::is_available() ) {
			WP_CLI::error( 'Hardening Mode is not available. Check the PRO tier and master toggle in Settings → Hardening Mode.' );
		}

		$minutes_override = isset( $assoc['minutes'] ) ? absint( $assoc['minutes'] ) : 0;
		if ( $minutes_override > 0 ) {
			$minutes_override = max( 5, min( 360, $minutes_override ) );
			ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_hardening_duration_minutes', $minutes_override );
		}

		$ok = ReportedIP_Hive_Hardening_Mode::activate(
			array(
				'unique_ips'     => 0,
				'total_attempts' => 0,
				'time_window'    => gmdate( 'Y-m-d H:i' ),
			),
			'manual'
		);

		if ( $ok ) {
			$expires_at = ReportedIP_Hive_Hardening_Mode::expires_at();
			WP_CLI::success( 'Hardening Mode activated until ' . gmdate( 'Y-m-d H:i:s', (int) $expires_at ) . ' UTC.' );
			return;
		}
		WP_CLI::warning( 'Activation skipped (already active with stronger reason; use `deactivate` first).' );
	}

	/**
	 * Clear the active Hardening Mode window.
	 *
	 * @return void
	 */
	public function deactivate() {
		$was_active = ReportedIP_Hive_Hardening_Mode::is_active();
		ReportedIP_Hive_Hardening_Mode::deactivate( 'cli' );
		if ( $was_active ) {
			WP_CLI::success( 'Hardening Mode deactivated.' );
		} else {
			WP_CLI::log( 'Hardening Mode was not active. No state changed.' );
		}
	}
}

ReportedIP_Hive_Hardening_CLI::register();
