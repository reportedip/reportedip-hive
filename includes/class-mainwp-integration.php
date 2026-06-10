<?php
/**
 * MainWP integration — exposes the plugin to a MainWP dashboard.
 *
 * Makes the plugin remote-manageable from a MainWP dashboard without requiring an
 * extra plugin on the child site. It hooks the `mainwp_child_extra_execution`
 * filter provided by the MainWP Child component, which the dashboard invokes on
 * every authenticated dashboard request (notably the regular sync); the MainWP
 * Child component owns the request authentication, so the handler only runs for
 * a trusted, signed dashboard connection. When MainWP Child is absent the filter
 * never fires and the registration is inert.
 *
 * Supported jobs (keys in the passed `$data` array):
 *   - `reportedip_hive_sync`      returns aggregated security metrics in
 *                                 `$information['reportedip_hive']`.
 *   - `reportedip_hive_provision` sets the site's `reportedip_hive_api_key` and
 *                                 confirms it (`provisioned => true`).
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     2.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Bridges the plugin to a MainWP dashboard via the MainWP Child filter.
 *
 * @since 2.1.0
 */
class ReportedIP_Hive_MainWP_Integration {

	/**
	 * Register the MainWP hooks.
	 *
	 * The `mainwp_child_extra_execution` filter is fired exclusively by the
	 * MainWP Child component; without it the registration has no effect.
	 *
	 * @return void
	 * @since  2.1.0
	 */
	public static function init() {
		add_filter( 'mainwp_child_extra_execution', array( __CLASS__, 'handle_child_execution' ), 10, 2 );
	}

	/**
	 * Handle jobs sent by the MainWP dashboard extension.
	 *
	 * @param array $information Response array returned to the dashboard.
	 * @param array $data        Extra data supplied by the dashboard (othersData).
	 * @return array
	 * @since  2.1.0
	 */
	public static function handle_child_execution( $information, $data ) {
		if ( ! is_array( $information ) ) {
			$information = array();
		}
		if ( ! is_array( $data ) ) {
			return $information;
		}

		$payload = array();

		if ( isset( $data['reportedip_hive_sync'] ) ) {
			$days    = isset( $data['reportedip_hive_sync']['days'] ) ? (int) $data['reportedip_hive_sync']['days'] : 30;
			$days    = $days > 0 ? $days : 30;
			$payload = array_merge( $payload, self::collect_metrics( $days ) );
		}

		if ( isset( $data['reportedip_hive_provision']['api_key'] ) ) {
			$api_key = sanitize_text_field( $data['reportedip_hive_provision']['api_key'] );
			if ( '' !== $api_key && class_exists( 'ReportedIP_Hive_Option_Routing' ) ) {
				ReportedIP_Hive_Option_Routing::set( 'reportedip_hive_api_key', $api_key );
				$payload['provisioned'] = true;
			}
		}

		if ( ! empty( $payload ) ) {
			$existing                       = isset( $information['reportedip_hive'] ) && is_array( $information['reportedip_hive'] ) ? $information['reportedip_hive'] : array();
			$information['reportedip_hive'] = array_merge( $existing, $payload );
		}

		return $information;
	}

	/**
	 * Aggregate this site's security metrics.
	 *
	 * Returns counts only — no IP addresses, usernames, secrets or the API key
	 * leave the site through this channel.
	 *
	 * @param int $days Time window for the period metrics.
	 * @return array
	 * @since  2.1.0
	 */
	protected static function collect_metrics( $days ) {
		$metrics = array(
			'version' => defined( 'REPORTEDIP_HIVE_VERSION' ) ? REPORTEDIP_HIVE_VERSION : '',
			'active'  => true,
		);

		if ( ! class_exists( 'ReportedIP_Hive_Database' ) ) {
			return $metrics;
		}

		$db = ReportedIP_Hive_Database::get_instance();

		if ( method_exists( $db, 'count_blocked_ips' ) ) {
			$metrics['blocks_active'] = (int) $db->count_blocked_ips();
		}

		if ( method_exists( $db, 'count_whitelisted_ips' ) ) {
			$metrics['whitelisted'] = (int) $db->count_whitelisted_ips();
		}

		if ( method_exists( $db, 'get_security_summary' ) ) {
			$summary = $db->get_security_summary( $days );
			if ( is_array( $summary ) && isset( $summary['summary'] ) ) {
				$s                            = $summary['summary'];
				$metrics['blocks_30d']        = isset( $s->total_blocked_ips ) ? (int) $s->total_blocked_ips : 0;
				$metrics['failed_logins_30d'] = isset( $s->total_failed_logins ) ? (int) $s->total_failed_logins : 0;
				$metrics['comment_spam_30d']  = isset( $s->total_comment_spam ) ? (int) $s->total_comment_spam : 0;
				$metrics['reputation_blocks'] = isset( $s->total_reputation_blocks ) ? (int) $s->total_reputation_blocks : 0;
			}
		}

		if ( method_exists( $db, 'get_queue_size' ) ) {
			$metrics['queue_size'] = (int) $db->get_queue_size();
		}

		if ( method_exists( $db, 'get_recent_critical_events' ) ) {
			$critical                = $db->get_recent_critical_events( 24, 200 );
			$metrics['critical_24h'] = is_array( $critical ) ? count( $critical ) : 0;
		}

		$metrics['twofa_users'] = self::count_2fa_users();

		return $metrics;
	}

	/**
	 * Count users with two-factor authentication enabled.
	 *
	 * @return int
	 * @since  2.1.0
	 */
	protected static function count_2fa_users() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Aggregate count for a remote dashboard sync; not cacheable per-request.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT user_id) FROM {$wpdb->usermeta} WHERE meta_key = %s AND meta_value IN ('1', 'yes', 'true')",
				'reportedip_hive_2fa_enabled'
			)
		);

		return (int) $count;
	}
}
