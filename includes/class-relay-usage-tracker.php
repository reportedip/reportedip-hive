<?php
/**
 * Relay-Usage-Tracker: per-site informational counters for mail/SMS relay sends.
 *
 * The authoritative quota lives server-side (the relay endpoint returns
 * HTTP 402 once the network's monthly cap is exhausted). This tracker is
 * purely local bookkeeping so the Network Admin can answer the question
 * "which site is consuming the shared pool?" without round-tripping to the
 * service.
 *
 * Storage layout (single network option, key per month):
 *
 *   reportedip_hive_relay_usage_per_site = [
 *     '2026-05' => [
 *       'site_1' => [ 'mail' => 200, 'sms' => 25 ],
 *       'site_2' => [ 'mail' => 50,  'sms' => 5  ],
 *       'totals' => [ 'mail' => 250, 'sms' => 30 ],
 *     ],
 *   ]
 *
 * History is capped at 6 months (older months are pruned on every write).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Tracks relay mail/SMS usage per site for reporting purposes.
 *
 * @since 2.0.0
 */
final class ReportedIP_Hive_Relay_Usage_Tracker {

	/**
	 * Network option name for the rolling per-site usage map.
	 */
	public const OPTION = 'reportedip_hive_relay_usage_per_site';

	/**
	 * Number of months kept in the rolling history before pruning.
	 */
	private const HISTORY_MONTHS = 6;

	/**
	 * Record a successful relay send.
	 *
	 * @param string $type  'mail' or 'sms'.
	 * @param int    $count Items sent (default 1; SMS may segment to 2+).
	 * @return void
	 * @since  2.0.0
	 */
	public static function record( $type, $count = 1 ) {
		$type  = (string) $type;
		$count = max( 0, (int) $count );
		if ( 0 === $count || ! in_array( $type, array( 'mail', 'sms' ), true ) ) {
			return;
		}

		$blog_id = (int) ( function_exists( 'get_current_blog_id' ) ? get_current_blog_id() : 1 );
		$period  = gmdate( 'Y-m' );
		$site    = 'site_' . $blog_id;

		$snapshot = self::load();

		if ( ! isset( $snapshot[ $period ] ) || ! is_array( $snapshot[ $period ] ) ) {
			$snapshot[ $period ] = array();
		}
		if ( ! isset( $snapshot[ $period ][ $site ] ) || ! is_array( $snapshot[ $period ][ $site ] ) ) {
			$snapshot[ $period ][ $site ] = array(
				'mail' => 0,
				'sms'  => 0,
			);
		}
		if ( ! isset( $snapshot[ $period ]['totals'] ) || ! is_array( $snapshot[ $period ]['totals'] ) ) {
			$snapshot[ $period ]['totals'] = array(
				'mail' => 0,
				'sms'  => 0,
			);
		}

		$snapshot[ $period ][ $site ][ $type ]   = (int) $snapshot[ $period ][ $site ][ $type ] + $count;
		$snapshot[ $period ]['totals'][ $type ] = (int) $snapshot[ $period ]['totals'][ $type ] + $count;

		self::prune( $snapshot );
		self::save( $snapshot );
	}

	/**
	 * Returns the full per-site usage map. Network-scoped on Multisite,
	 * per-site on single-site (where it has the same effect).
	 *
	 * @return array<string, array<string, array<string, int>>>
	 * @since  2.0.0
	 */
	public static function load() {
		$raw = ReportedIP_Hive_Option_Routing::get( self::OPTION, array() );
		return is_array( $raw ) ? $raw : array();
	}

	/**
	 * Persist the snapshot back into network storage.
	 *
	 * @param array<string, mixed> $snapshot
	 * @return void
	 * @since  2.0.0
	 */
	private static function save( array $snapshot ) {
		ReportedIP_Hive_Option_Routing::set( self::OPTION, $snapshot );
	}

	/**
	 * Drop history older than `HISTORY_MONTHS`.
	 *
	 * @param array<string, mixed> $snapshot Modified by reference.
	 * @return void
	 * @since  2.0.0
	 */
	private static function prune( array &$snapshot ) {
		$keys = array_keys( $snapshot );
		if ( count( $keys ) <= self::HISTORY_MONTHS ) {
			return;
		}
		sort( $keys );
		$drop = array_slice( $keys, 0, count( $keys ) - self::HISTORY_MONTHS );
		foreach ( $drop as $key ) {
			unset( $snapshot[ $key ] );
		}
	}
}
