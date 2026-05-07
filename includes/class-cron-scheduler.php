<?php
/**
 * Cron-Scheduler: registers plugin cron jobs only on the main site.
 *
 * Because the plugin tables are network-wide (Schema), there is no need to
 * iterate over sites for cron work. Registering on the main site only avoids
 * the N-fold execution problem you'd otherwise see with `wp_schedule_event`
 * on networks with many subsites.
 *
 * The actual job handlers live in `class-cron-handler.php` — this scheduler
 * is the orchestrator for `wp_schedule_event` / `wp_clear_scheduled_hook`.
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
 * Schedules and unschedules the plugin's cron jobs.
 *
 * @since 2.0.0
 */
final class ReportedIP_Hive_Cron_Scheduler {

	/**
	 * Map of cron hook → recurrence slug. Recurrence slugs are added by the
	 * existing Cron_Handler::add_custom_cron_intervals() filter.
	 *
	 * @var array<string,string>
	 */
	private const JOBS = array(
		'reportedip_hive_cleanup'         => 'daily',
		'reportedip_hive_sync_reputation' => 'hourly',
		'reportedip_hive_process_queue'   => 'fifteen_minutes',
		'reportedip_hive_refresh_quota'   => 'six_hours',
	);

	/**
	 * Schedule every plugin cron job that is not yet scheduled.
	 *
	 * Only registers on the main site of a Multisite network. On single-site
	 * `is_main_site()` is always true, so behaviour is unchanged from v1.x.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public static function schedule_all() {
		if ( is_multisite() && ! is_main_site() ) {
			return;
		}
		foreach ( self::JOBS as $hook => $recurrence ) {
			if ( ! wp_next_scheduled( $hook ) ) {
				wp_schedule_event( time(), $recurrence, $hook );
			}
		}
	}

	/**
	 * Clear every plugin cron job from the current site.
	 *
	 * Run on deactivation. Safe to call repeatedly — `wp_clear_scheduled_hook`
	 * is a no-op if no event is scheduled.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public static function unschedule_all() {
		foreach ( self::JOBS as $hook => $_ ) {
			wp_clear_scheduled_hook( $hook );
		}
	}

	/**
	 * Self-healing helper: re-register any missing job.
	 *
	 * Wired to `admin_init` so that switching the main site (a rare but
	 * valid Multisite operation) does not leave the network without crons.
	 *
	 * @return void
	 * @since  2.0.0
	 */
	public static function ensure_scheduled() {
		self::schedule_all();
	}

	/**
	 * Returns the list of registered cron hook names. Used by tests.
	 *
	 * @return string[]
	 * @since  2.0.0
	 */
	public static function get_hook_names() {
		return array_keys( self::JOBS );
	}
}
