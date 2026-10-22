<?php
/**
 * Daily summary of blocked attacks.
 *
 * Replaces the per-threshold warning mail as the default: one mail a day
 * that says how many attacks were blocked, of which kind and from where.
 * Reads the logs table that the sensors write anyway, so the sensors need
 * to know nothing about it.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <1@reportedip.com>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     3.0.3
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Builds and sends the daily summary mail.
 *
 * @since 3.0.3
 */
class ReportedIP_Hive_Digest {

	/**
	 * Option: how blocked attacks are reported.
	 */
	const OPT_MODE = 'reportedip_hive_notify_attacks';

	/**
	 * Mode: one summary mail a day.
	 */
	const MODE_DIGEST = 'digest';

	/**
	 * Mode: one warning mail per threshold, the behaviour before 3.0.3.
	 */
	const MODE_INSTANT = 'instant';

	/**
	 * Mode: no mail about blocked attacks.
	 */
	const MODE_OFF = 'off';

	/**
	 * Cron hook of the daily run.
	 */
	const CRON_HOOK = 'reportedip_hive_send_digest';

	/**
	 * Runtime state: UTC date of the last summary, guards against a second
	 * mail when cron fires twice on one day.
	 */
	const OPT_LAST_SENT = 'reportedip_hive_digest_last_sent';

	/**
	 * Rows in the "most active addresses" table.
	 */
	const TOP_IPS = 5;

	/**
	 * Current reporting mode for blocked attacks.
	 *
	 * @return string One of the MODE_* constants.
	 * @since  3.0.3
	 */
	public static function attack_mode() {
		$mode = (string) ReportedIP_Hive_Option_Routing::get( self::OPT_MODE, self::MODE_DIGEST );
		return in_array( $mode, array( self::MODE_DIGEST, self::MODE_INSTANT, self::MODE_OFF ), true ) ? $mode : self::MODE_DIGEST;
	}

	/**
	 * Cron callback: send the last 24 hours as one mail, once a day.
	 *
	 * @return void
	 * @since  3.0.3
	 */
	public static function run() {
		if ( is_multisite() && ! is_main_site() ) {
			return;
		}
		if ( ! ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_notify_admin', true ) || self::MODE_DIGEST !== self::attack_mode() ) {
			return;
		}

		$today = gmdate( 'Y-m-d' );
		if ( get_site_option( self::OPT_LAST_SENT ) === $today ) {
			return;
		}

		$summary = self::build( self::query_counts(), self::query_top_ips() );
		if ( 0 === $summary['total'] ) {
			update_site_option( self::OPT_LAST_SENT, $today );
			return;
		}

		if ( ReportedIP_Hive_Option_Routing::get( 'reportedip_hive_report_only_mode', false ) ) {
			ReportedIP_Hive_Logger::get_instance()->log_security_event(
				'would_send_notification',
				'',
				array(
					'type'  => 'digest',
					'total' => $summary['total'],
				),
				'low'
			);
			update_site_option( self::OPT_LAST_SENT, $today );
			return;
		}

		update_site_option( self::OPT_LAST_SENT, $today );
		self::send( $summary );
	}

	/**
	 * Turn raw counts into the summary the mail shows.
	 *
	 * A sensor writes either one row per attempt plus a threshold row, or the
	 * threshold row alone. Counting both would double the attack, so each
	 * kind takes the larger of its two counts. Operational rows (no family in
	 * the taxonomy) never count; `ip_blocked` counts as new blocks only.
	 *
	 * @param array<string,int>                       $counts  event_type => rows in the last 24 h.
	 * @param array<int,array{ip:string,hits:int}>    $top_ips Most active addresses.
	 * @return array{total:int,blocks:int,kinds:array<string,int>,top_ips:array<int,array{ip:string,hits:int}>}
	 * @since  3.0.3
	 */
	public static function build( array $counts, array $top_ips ) {
		$kinds  = array();
		$blocks = (int) ( $counts['ip_blocked'] ?? 0 );

		foreach ( $counts as $type => $n ) {
			$type   = (string) $type;
			$family = ReportedIP_Hive_Event_Taxonomy::classify( $type );
			if ( null === $family || 'other' === $family ) {
				continue;
			}
			$label           = ReportedIP_Hive_Event_Taxonomy::label( self::base_type( $type ) );
			$kinds[ $label ] = max( (int) ( $kinds[ $label ] ?? 0 ), (int) $n );
		}

		arsort( $kinds );

		return array(
			'total'   => (int) array_sum( $kinds ),
			'blocks'  => $blocks,
			'kinds'   => $kinds,
			'top_ips' => array_slice( $top_ips, 0, self::TOP_IPS ),
		);
	}

	/**
	 * Strip the generated threshold suffix.
	 *
	 * @param string $type Event type.
	 * @return string
	 */
	private static function base_type( $type ) {
		$suffix = '_threshold_exceeded';
		return substr( $type, -strlen( $suffix ) ) === $suffix ? substr( $type, 0, -strlen( $suffix ) ) : $type;
	}

	/**
	 * Rows per event type in the last 24 hours.
	 *
	 * @return array<string,int>
	 */
	private static function query_counts() {
		global $wpdb;
		$types = array_merge( ReportedIP_Hive_Event_Taxonomy::threat_event_types(), array( 'ip_blocked' ) );
		$in    = implode( ',', array_fill( 0, count( $types ), '%s' ) );
		$table = $wpdb->base_prefix . 'reportedip_hive_logs';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin table name from base_prefix, placeholders built from the count of $types.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT event_type, COUNT(*) AS n FROM {$table} WHERE created_at >= UTC_TIMESTAMP() - INTERVAL 1 DAY AND event_type IN ({$in}) GROUP BY event_type",
				$types
			)
		);
		// phpcs:enable

		$counts = array();
		foreach ( (array) $rows as $row ) {
			$counts[ (string) $row->event_type ] = (int) $row->n;
		}
		return $counts;
	}

	/**
	 * Addresses with the most attack rows in the last 24 hours.
	 *
	 * @return array<int,array{ip:string,hits:int}>
	 */
	private static function query_top_ips() {
		global $wpdb;
		$types = ReportedIP_Hive_Event_Taxonomy::threat_event_types();
		$in    = implode( ',', array_fill( 0, count( $types ), '%s' ) );
		$table = $wpdb->base_prefix . 'reportedip_hive_logs';
		$args  = array_merge( $types, array( self::TOP_IPS ) );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,PluginCheck.Security.DirectDB.UnescapedDBParameter -- plugin table name from base_prefix, placeholders built from the count of $types.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip_address, COUNT(*) AS n FROM {$table} WHERE created_at >= UTC_TIMESTAMP() - INTERVAL 1 DAY AND event_type IN ({$in}) AND ip_address <> '' GROUP BY ip_address ORDER BY n DESC LIMIT %d",
				$args
			)
		);
		// phpcs:enable

		$out = array();
		foreach ( (array) $rows as $row ) {
			$out[] = array(
				'ip'   => (string) $row->ip_address,
				'hits' => (int) $row->n,
			);
		}
		return $out;
	}

	/**
	 * Send the summary mail.
	 *
	 * @param array{total:int,blocks:int,kinds:array<string,int>,top_ips:array<int,array{ip:string,hits:int}>} $summary Summary from build().
	 * @return bool
	 */
	private static function send( array $summary ) {
		$recipients = ReportedIP_Hive_Defaults::notify_recipients();
		if ( empty( $recipients ) ) {
			return false;
		}

		$rows = array();
		foreach ( $summary['kinds'] as $label => $n ) {
			$rows[] = array( (string) $label, number_format_i18n( $n ) );
		}
		$rows[] = array( __( 'New blocks', 'reportedip-hive' ), number_format_i18n( $summary['blocks'] ) );
		$blocks = ReportedIP_Hive_Alerts::rows_block( $rows );

		if ( ! empty( $summary['top_ips'] ) ) {
			$ip_rows = array();
			foreach ( $summary['top_ips'] as $entry ) {
				$ip_rows[] = array( $entry['ip'], number_format_i18n( $entry['hits'] ) );
			}
			$top             = ReportedIP_Hive_Alerts::rows_block( $ip_rows );
			$heading         = __( 'Most active addresses', 'reportedip-hive' );
			$blocks['html'] .= '<p style="margin:0 0 8px;font-size:13px;font-weight:600;color:#111827;">' . esc_html( $heading ) . '</p>' . $top['html'];
			$blocks['text'] .= "\n" . $heading . "\n" . $top['text'];
		}

		$site_name = wp_specialchars_decode( (string) ( get_bloginfo( 'name' ) ?: 'WordPress Site' ), ENT_QUOTES );

		return (bool) ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => implode( ', ', $recipients ),
				/* translators: 1: site name, 2: number of blocked attacks */
				'subject'         => sprintf( __( '[%1$s] Daily summary: %2$s attacks blocked', 'reportedip-hive' ), $site_name, number_format_i18n( $summary['total'] ) ),
				'intro_text'      => __( 'ReportedIP Hive detected and handled these attacks in the last 24 hours. You do not need to do anything.', 'reportedip-hive' ),
				'main_block_html' => $blocks['html'],
				'main_block_text' => $blocks['text'],
				'cta'             => array(
					'label' => __( 'Open dashboard', 'reportedip-hive' ),
					'url'   => is_multisite() ? network_admin_url( 'admin.php?page=reportedip-hive' ) : admin_url( 'admin.php?page=reportedip-hive' ),
				),
				'disclaimer'      => __( 'One summary a day replaces the single warnings. Change this under ReportedIP Hive > Protection Settings > Operations > Notifications.', 'reportedip-hive' ),
				'context'         => array( 'type' => 'admin_security_digest' ),
			)
		);
	}
}
