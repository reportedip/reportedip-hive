<?php
/**
 * Progressive block-duration escalation.
 *
 * The plugin previously applied a single uniform block duration (default
 * 24 h) to every threshold trip — fine for repeat offenders, but harsh on
 * a CGNAT visitor or a backend admin who fat-fingered a password three
 * times in a row. This class derives a progressive ladder instead:
 *
 *  - first block in the rolling reset window: shortest entry (e.g. 5 min)
 *  - each subsequent block within the window: next ladder rung
 *  - quiet for the full reset window: counter resets to step 1
 *
 * History is read from the existing `wp_reportedip_hive_logs` table by
 * counting `ip_blocked` events for the IP — no schema migration needed.
 * If event logs are pruned more aggressively than the reset window, the
 * effective memory shortens accordingly; documented behaviour rather
 * than a silent regression.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.5.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Picks the next block duration for an IP based on its recent block history.
 *
 * @since 1.5.0
 */
class ReportedIP_Hive_Block_Escalation {

	/**
	 * Default ladder in minutes: 5m → 15m → 30m → 24h → 48h → 7d.
	 *
	 * @var int[]
	 */
	public const DEFAULT_LADDER_MINUTES = array( 5, 15, 30, 1440, 2880, 10080 );

	/**
	 * Default reset window — number of days an IP must stay blockless to
	 * fall back to ladder step 1.
	 *
	 * @var int
	 */
	public const DEFAULT_RESET_DAYS = 30;

	/**
	 * Extra ladder rungs granted by the size of the burst that triggered the
	 * block, keyed by how many times the threshold was exceeded.
	 *
	 * The ladder counts block *events*, not offences, so an attacker who trips
	 * the threshold once and then keeps hammering is punished exactly like one
	 * who stopped at the threshold: every further offence lands on an IP that
	 * is already blocked, and the tracker returns early instead of escalating.
	 * Observed in the field — a bot fired 60 rule violations in ten seconds and
	 * earned the same five-minute rung as three violations would have.
	 *
	 * Sustained volume is therefore weighted directly: 5x the threshold skips
	 * one rung, 10x skips two, 25x skips three.
	 *
	 * @var array<int, int>
	 */
	private const BURST_RUNGS = array(
		25 => 3,
		10 => 2,
		5  => 1,
	);

	/**
	 * Is progressive escalation enabled?
	 *
	 * @return bool
	 */
	public static function is_enabled(): bool {
		return (bool) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_escalation_enabled', true );
	}

	/**
	 * Resolve the configured ladder. Falls back to DEFAULT_LADDER_MINUTES
	 * when the option is missing or unparseable; clamps every step to a
	 * positive integer; preserves the user's order.
	 *
	 * @return int[]
	 */
	public static function get_ladder(): array {
		$raw = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_ladder_minutes', '' );
		if ( '' === trim( $raw ) ) {
			return self::DEFAULT_LADDER_MINUTES;
		}

		$parts  = array_filter(
			array_map( 'trim', explode( ',', $raw ) ),
			static fn( string $part ): bool => '' !== $part
		);
		$ladder = array();
		foreach ( $parts as $part ) {
			$minutes = (int) $part;
			if ( $minutes >= 1 ) {
				$ladder[] = $minutes;
			}
		}
		return empty( $ladder ) ? self::DEFAULT_LADDER_MINUTES : $ladder;
	}

	/**
	 * How many days back we look for prior blocks before the counter
	 * resets to step 1.
	 *
	 * @return int
	 */
	public static function get_reset_days(): int {
		$days = (int) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_block_ladder_reset_days', self::DEFAULT_RESET_DAYS );
		return max( 1, min( 365, $days ) );
	}

	/**
	 * Pick the next block duration for $ip in minutes.
	 *
	 * @param string $ip        Client IP.
	 * @param int    $attempts  Offences counted in the window that triggered this block.
	 * @param int    $threshold Threshold those offences crossed.
	 * @return int Block duration in minutes (always >= 1).
	 */
	public static function next_block_minutes( string $ip, int $attempts = 0, int $threshold = 0 ): int {
		$ladder = self::get_ladder();
		if ( empty( $ladder ) ) {
			return 1440;
		}

		$prior = self::count_recent_blocks( $ip, self::get_reset_days() );
		$index = max( 0, $prior ) + self::burst_rungs( $attempts, $threshold );
		$index = min( $index, count( $ladder ) - 1 );

		return (int) $ladder[ $index ];
	}

	/**
	 * Extra ladder rungs earned by the volume of a single burst.
	 *
	 * @param int $attempts  Offences counted in the window.
	 * @param int $threshold Threshold they crossed.
	 * @return int Number of rungs to skip (0 when the burst is unremarkable).
	 */
	public static function burst_rungs( int $attempts, int $threshold ): int {
		if ( $attempts < 1 || $threshold < 1 ) {
			return 0;
		}

		$ratio = intdiv( $attempts, $threshold );
		foreach ( self::BURST_RUNGS as $factor => $rungs ) {
			if ( $ratio >= $factor ) {
				return $rungs;
			}
		}

		return 0;
	}

	/**
	 * Count `ip_blocked` events for $ip in the last $days days.
	 *
	 * @param string $ip   Client IP.
	 * @param int    $days Reset window.
	 * @return int Block count (lower-bounded at 0).
	 */
	private static function count_recent_blocks( string $ip, int $days ): int {
		global $wpdb;

		if ( '' === $ip ) {
			return 0;
		}

		$table = ReportedIP_Hive_Schema::table( 'reportedip_hive_logs' );
		$since = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- security-event log lookup, intentionally uncached; $table is built from Schema::table() with a hardcoded suffix, every user-supplied value is bound via prepare().
		$count = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $table is a trusted Schema::table() interpolation, all user-supplied values bound via prepare().
				"SELECT COUNT(*) FROM {$table}
                 WHERE ip_address = %s
                 AND event_type = %s
                 AND created_at >= %s",
				$ip,
				'ip_blocked',
				$since
			)
		);

		return max( 0, (int) $count );
	}
}
