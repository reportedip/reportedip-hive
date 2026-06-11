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
	 * Two entry points, both provided by the MainWP Child component and both
	 * authenticated/signed; without MainWP Child the registrations are inert:
	 *
	 *  - `mainwp_child_extra_execution`  — fired by the dedicated `extra_execution`
	 *    call (dashboard "fetch now" buttons). $data = full $_POST.
	 *  - `mainwp_site_sync_others_data`  — fired during every regular sync; lets the
	 *    metrics ride the normal MainWP sync without an extra round-trip.
	 *    $data = decoded `othersData`.
	 *
	 * The same handler serves both: it only acts when the dashboard included the
	 * `reportedip_hive_sync` / `reportedip_hive_provision` keys.
	 *
	 * @return void
	 * @since  2.1.0
	 */
	public static function init() {
		add_filter( 'mainwp_child_extra_execution', array( __CLASS__, 'handle_child_execution' ), 10, 2 );
		add_filter( 'mainwp_site_sync_others_data', array( __CLASS__, 'handle_child_execution' ), 10, 2 );
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
		$days = max( 1, (int) $days );

		$metrics = array(
			'version'     => defined( 'REPORTEDIP_HIVE_VERSION' ) ? REPORTEDIP_HIVE_VERSION : '',
			'active'      => true,
			'period_days' => $days,
		);

		// Aktuell konfigurierten reportedip.de-API-Key mitliefern, damit das Dashboard
		// den tatsächlich auf der Site gesetzten Key auflisten/verifizieren kann.
		// Übertragung erfolgt ausschließlich über die signierte MainWP-Verbindung.
		if ( class_exists( 'ReportedIP_Hive_Option_Routing' ) ) {
			$metrics['api_key'] = (string) ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_api_key', '' );
		}

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
				$s                              = $summary['summary'];
				$metrics['blocks_period']       = isset( $s->total_blocked_ips ) ? (int) $s->total_blocked_ips : 0;
				$metrics['failed_logins_period'] = isset( $s->total_failed_logins ) ? (int) $s->total_failed_logins : 0;
				$metrics['comment_spam_period'] = isset( $s->total_comment_spam ) ? (int) $s->total_comment_spam : 0;
				$metrics['reputation_blocks']   = isset( $s->total_reputation_blocks ) ? (int) $s->total_reputation_blocks : 0;
			}
		}

		if ( method_exists( $db, 'get_queue_size' ) ) {
			$metrics['queue_size'] = (int) $db->get_queue_size();
		}

		$metrics['critical_24h'] = self::count_critical_events( 24 );
		$metrics['twofa_users']  = self::count_2fa_users();

		$metrics = array_merge( $metrics, self::collect_waf_status() );

		return $metrics;
	}

	/**
	 * Report the WAF engine and pre-WordPress drop-in status.
	 *
	 * Mirrors the firewall admin "Extended Protection" box so the MainWP overview
	 * can flag sites whose drop-in is enabled but not yet running — typically an
	 * nginx host that still needs the manual server snippet. `waf_needs_setup` is
	 * the derived "needs care" flag: enabled, not running, and on a server MainWP
	 * cannot auto-configure (nginx/unknown); Apache and PHP-FPM write the directive
	 * themselves and resolve on their own.
	 *
	 * @return array
	 * @since  2.1.6
	 */
	protected static function collect_waf_status() {
		if ( ! class_exists( 'ReportedIP_Hive_WAF' ) ) {
			return array();
		}

		$waf    = ReportedIP_Hive_WAF::get_instance();
		$status = array(
			'waf_enabled'     => (bool) $waf->is_enabled(),
			'waf_report_only' => (bool) $waf->is_report_only(),
		);

		if ( class_exists( 'ReportedIP_Hive_WAF_Dropin_Manager' ) && class_exists( 'ReportedIP_Hive_Option_Routing' ) ) {
			$dropin = ReportedIP_Hive_WAF_Dropin_Manager::get_instance();

			$dropin_enabled = (bool) ReportedIP_Hive_Option_Routing::get( ReportedIP_Hive_WAF::OPT_DROPIN_ENABLED, false );
			$running        = (bool) $dropin->is_running();
			$server         = (string) $dropin->detect_server();

			$status['waf_dropin_enabled'] = $dropin_enabled;
			$status['waf_dropin_running'] = $running;
			$status['waf_server']         = $server;
			$status['waf_needs_setup']    = $dropin_enabled && ! $running && ! in_array( $server, array( 'apache', 'fpm' ), true );
		}

		return $status;
	}

	/**
	 * Count high/critical security log events within the last N hours.
	 *
	 * Uses a direct COUNT so the value is not capped by any LIMIT (unlike
	 * iterating the list returned by get_recent_critical_events()).
	 *
	 * @param int $hours Lookback window in hours.
	 * @return int
	 * @since  2.1.1
	 */
	protected static function count_critical_events( $hours ) {
		global $wpdb;

		$table  = $wpdb->base_prefix . 'reportedip_hive_logs';
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - max( 1, (int) $hours ) * HOUR_IN_SECONDS );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Aggregate count for a remote dashboard sync; table name is internal.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE severity IN ('high', 'critical') AND created_at >= %s",
				$cutoff
			)
		);

		return (int) $count;
	}

	/**
	 * Count users with two-factor authentication enabled.
	 *
	 * Mirrors ReportedIP_Hive_Two_Factor::is_user_enabled(): a user counts if any
	 * per-method flag (TOTP/E-Mail/WebAuthn/SMS) is set, or the legacy enabled flag.
	 *
	 * @return int
	 * @since  2.1.0
	 */
	protected static function count_2fa_users() {
		global $wpdb;

		$keys = array(
			'reportedip_hive_2fa_totp_enabled',
			'reportedip_hive_2fa_email_enabled',
			'reportedip_hive_2fa_webauthn_enabled',
			'reportedip_hive_2fa_sms_enabled',
			'reportedip_hive_2fa_enabled',
		);

		$placeholders = implode( ', ', array_fill( 0, count( $keys ), '%s' ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Aggregate count for a remote dashboard sync.
		$count = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT user_id) FROM {$wpdb->usermeta}
				 WHERE meta_key IN ($placeholders) AND meta_value IN ('1', 'yes', 'true')",
				$keys
			)
		);

		return (int) $count;
	}
}
