<?php
/**
 * Security Monitor Class for ReportedIP Hive.
 *
 * Detects security events (failed logins, comment spam, XMLRPC abuse,
 * admin scanning) and feeds them into the local IP-Manager and the
 * community-mode reporting queue.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.0.0
 *
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery
 * @phpcs:disable WordPress.DB.DirectDatabaseQuery.NoCaching
 * @phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table names are safe
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ReportedIP_Hive_Security_Monitor {

	private static $default_category_mapping = array(
		'failed_login'      => array( 18 ),
		'comment_spam'      => array( 12 ),
		'xmlrpc_abuse'      => array( 21 ),
		'admin_scanning'    => array( 21, 15 ),
		'reputation_threat' => array( 15, 4 ),
	);

	private $database;
	private $api_client;
	private $logger;
	private $mode_manager;

	public function __construct() {
		$this->database     = ReportedIP_Hive_Database::get_instance();
		$this->api_client   = ReportedIP_Hive_API::get_instance();
		$this->logger       = ReportedIP_Hive_Logger::get_instance();
		$this->mode_manager = ReportedIP_Hive_Mode_Manager::get_instance();
	}

	/**
	 * Check if community features are available
	 *
	 * @return bool
	 */
	public function is_community_mode() {
		return $this->mode_manager->is_community_mode() && $this->api_client->can_use_api();
	}

	/**
	 * Check failed login threshold
	 */
	public function check_failed_login_threshold( $ip_address, $username = '' ) {
		$threshold = get_option( 'reportedip_hive_failed_login_threshold', 5 );
		$timeframe = get_option( 'reportedip_hive_failed_login_timeframe', 15 );

		$track_username   = null;
		$track_user_agent = null;

		if ( get_option( 'reportedip_hive_detailed_logging', false ) ) {
			$track_username = $username;
		}

		if ( get_option( 'reportedip_hive_log_user_agents', false ) ) {
			$user_agent       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$track_user_agent = ! empty( $user_agent ) ? substr( (string) $user_agent, 0, REPORTEDIP_USER_AGENT_MAX_LENGTH ) : '';
		}

		$this->database->track_attempt( $ip_address, 'login', $track_username, $track_user_agent );

		$attempt_count = $this->database->get_attempt_count( $ip_address, 'login', $timeframe );

		if ( $attempt_count >= $threshold ) {
			if ( $this->database->is_blocked( $ip_address ) ) {
				return true;
			}

			$details = array(
				'attempts'  => $attempt_count,
				'threshold' => $threshold,
				'timeframe' => $timeframe,
			);

			if ( get_option( 'reportedip_hive_detailed_logging', false ) ) {
				$details['username_provided'] = ! empty( $username );
			}

			$this->handle_threshold_exceeded( $ip_address, 'failed_login', $details );

			return true;
		}

		return false;
	}

	/**
	 * Check comment spam threshold
	 */
	public function check_comment_spam_threshold( $ip_address ) {
		$threshold = get_option( 'reportedip_hive_comment_spam_threshold', 3 );
		$timeframe = get_option( 'reportedip_hive_comment_spam_timeframe', 60 );

		$track_user_agent = null;
		if ( get_option( 'reportedip_hive_log_user_agents', false ) ) {
			$user_agent       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$track_user_agent = ! empty( $user_agent ) ? substr( (string) $user_agent, 0, REPORTEDIP_USER_AGENT_MAX_LENGTH ) : '';
		}
		$this->database->track_attempt( $ip_address, 'comment', null, $track_user_agent );

		$attempt_count = $this->database->get_attempt_count( $ip_address, 'comment', $timeframe );

		if ( $attempt_count >= $threshold ) {
			if ( $this->database->is_blocked( $ip_address ) ) {
				return true;
			}

			$this->handle_threshold_exceeded(
				$ip_address,
				'comment_spam',
				array(
					'attempts'  => $attempt_count,
					'threshold' => $threshold,
					'timeframe' => $timeframe,
				)
			);

			return true;
		}

		return false;
	}

	/**
	 * Check XMLRPC threshold
	 */
	public function check_xmlrpc_threshold( $ip_address ) {
		$threshold = get_option( 'reportedip_hive_xmlrpc_threshold', 10 );
		$timeframe = get_option( 'reportedip_hive_xmlrpc_timeframe', 60 );

		$track_user_agent = null;
		if ( get_option( 'reportedip_hive_log_user_agents', false ) ) {
			$user_agent       = isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
			$track_user_agent = ! empty( $user_agent ) ? substr( (string) $user_agent, 0, REPORTEDIP_USER_AGENT_MAX_LENGTH ) : '';
		}
		$this->database->track_attempt( $ip_address, 'xmlrpc', null, $track_user_agent );

		$attempt_count = $this->database->get_attempt_count( $ip_address, 'xmlrpc', $timeframe );

		if ( $attempt_count >= $threshold ) {
			if ( $this->database->is_blocked( $ip_address ) ) {
				return true;
			}

			$this->handle_threshold_exceeded(
				$ip_address,
				'xmlrpc_abuse',
				array(
					'attempts'  => $attempt_count,
					'threshold' => $threshold,
					'timeframe' => $timeframe,
				)
			);

			return true;
		}

		return false;
	}

	/**
	 * Handle threshold exceeded
	 */
	private function handle_threshold_exceeded( $ip_address, $event_type, $details ) {
		$this->logger->log_security_event( $event_type . '_threshold_exceeded', $ip_address, $details, 'high' );

		$this->database->update_daily_stats( $this->get_stat_type_for_event( $event_type ) );

		if ( get_option( 'reportedip_hive_auto_block', true ) ) {
			$this->auto_block_ip( $ip_address, $event_type, $details );
		}

		$this->report_security_event( $ip_address, $event_type, $details );

		if ( get_option( 'reportedip_hive_notify_admin', true ) ) {
			$this->send_admin_notification( $ip_address, $event_type, $details );
		}
	}

	/**
	 * Auto-block IP address
	 */
	public function auto_block_ip( $ip_address, $event_type, $details ) {
		if ( get_option( 'reportedip_hive_report_only_mode', false ) ) {
			$this->logger->log_security_event(
				'would_block_ip',
				$ip_address,
				array(
					'event_type'       => $event_type,
					'details'          => $details,
					'report_only_mode' => true,
					'reason'           => 'Auto-blocking disabled due to report-only mode',
				),
				'medium'
			);
			return false;
		}

		if ( $this->database->is_whitelisted( $ip_address ) ) {
			$this->logger->log_security_event(
				'block_skipped_whitelist',
				$ip_address,
				array(
					'event_type' => $event_type,
					'details'    => $details,
					'reason'     => 'IP is whitelisted',
				),
				'low'
			);
			return false;
		}

		if ( $this->database->is_blocked( $ip_address ) ) {
			$this->logger->log_security_event(
				'block_skipped_already_blocked',
				$ip_address,
				array(
					'event_type' => $event_type,
					'details'    => $details,
					'reason'     => 'IP is already blocked',
				),
				'low'
			);
			return false;
		}

		$block_duration = get_option( 'reportedip_hive_block_duration', 24 );
		$reason         = $this->get_block_reason( $event_type, $details );

		$this->logger->log_security_event(
			'attempting_auto_block',
			$ip_address,
			array(
				'event_type'        => $event_type,
				'reason'            => $reason,
				'duration_hours'    => $block_duration,
				'threshold_details' => $details,
			),
			'high'
		);

		$result = $this->database->block_ip( $ip_address, $reason, 'automatic', $block_duration );

		if ( $result ) {
			$client = ReportedIP_Hive::get_instance();
			$client->mark_ip_blocked( $ip_address );

			$cache_key = 'rip_access_' . md5( $ip_address );
			wp_cache_delete( $cache_key, 'reportedip' );

			$this->logger->log_security_event(
				'ip_blocked',
				$ip_address,
				array(
					'reason'         => $reason,
					'duration_hours' => $block_duration,
					'trigger_event'  => $event_type,
					'block_type'     => 'automatic',
				),
				'high'
			);

			$this->database->update_daily_stats( 'blocked_ips' );

			return true;
		} else {
			$this->logger->log_security_event(
				'auto_block_failed',
				$ip_address,
				array(
					'event_type' => $event_type,
					'reason'     => $reason,
					'error'      => 'Database block operation failed',
				),
				'critical'
			);

			return false;
		}
	}

	/**
	 * Report security event to API (unified function for all modes)
	 *
	 * In Local Mode, this method logs the event locally but does NOT queue API reports.
	 * In Community Mode, this method queues API reports to share threats with the network.
	 *
	 * @param string $ip_address IP address to report
	 * @param string $event_type Type of security event
	 * @param array  $details Event details
	 * @return bool|null Success status (null in local mode)
	 */
	public function report_security_event( $ip_address, $event_type, $details ) {
		if ( $this->mode_manager->is_local_mode() ) {
			$this->logger->log_security_event(
				'local_event_detected',
				$ip_address,
				array(
					'event_type' => $event_type,
					'mode'       => 'local',
					'details'    => $details,
				),
				'low'
			);

			return null;
		}

		$category_ids = $this->get_category_ids_for_event( $event_type );
		$comment      = $this->generate_report_comment( $event_type, $details );

		$report_details = $details;
		if ( get_option( 'reportedip_hive_report_only_mode', false ) ) {
			$report_details['report_only_mode']   = true;
			$report_details['would_have_blocked'] = get_option( 'reportedip_hive_auto_block', true );
		}

		$result = $this->database->queue_api_report( $ip_address, $category_ids, $comment, 'negative', 'high' );

		if ( $result ) {
			$this->logger->log_security_event(
				'api_report_queued',
				$ip_address,
				array(
					'event_type'       => $event_type,
					'category_ids'     => $category_ids,
					'mode'             => 'community',
					'report_only_mode' => get_option( 'reportedip_hive_report_only_mode', false ),
				),
				'low'
			);
		} else {
			$this->logger->log_security_event(
				'api_report_skipped',
				$ip_address,
				array(
					'event_type'       => $event_type,
					'reason'           => 'Cooldown period or duplicate prevention',
					'mode'             => 'community',
					'report_only_mode' => get_option( 'reportedip_hive_report_only_mode', false ),
				),
				'low'
			);
		}

		return $result;
	}

	/**
	 * Get category IDs for event type
	 *
	 * Category mappings based on ReportedIP service threat categories:
	 * - 4: Malicious Host
	 * - 12: Blog Spam
	 * - 15: Hacking
	 * - 18: Brute-Force
	 * - 21: Web App Attack
	 */
	private function get_category_ids_for_event( $event_type ) {
		$category_mapping = self::$default_category_mapping;

		$validated_mapping = $this->get_validated_category_mapping();
		if ( ! empty( $validated_mapping ) ) {
			$category_mapping = array_merge( $category_mapping, $validated_mapping );
		}

		// phpcs:ignore Squiz.PHP.CommentedOutCode.Found -- This is not commented-out code.
		return isset( $category_mapping[ $event_type ] ) ? $category_mapping[ $event_type ] : array( 15 );
	}

	/**
	 * Get validated category mapping from cached API categories
	 *
	 * @return array Validated category mapping or empty array if not available
	 */
	private function get_validated_category_mapping() {
		$cached_categories = get_transient( 'reportedip_hive_categories' );

		if ( empty( $cached_categories ) || ! is_array( $cached_categories ) ) {
			$this->maybe_refresh_categories();
			return array();
		}

		$valid_ids = array();
		foreach ( $cached_categories as $category ) {
			if ( isset( $category['id'] ) ) {
				$valid_ids[] = (int) $category['id'];
			}
		}

		if ( empty( $valid_ids ) ) {
			return array();
		}

		$validated_mapping = array();
		foreach ( self::$default_category_mapping as $event_type => $category_ids ) {
			$validated_ids = array_filter(
				$category_ids,
				function ( $id ) use ( $valid_ids ) {
					return in_array( $id, $valid_ids );
				}
			);

			if ( ! empty( $validated_ids ) ) {
				$validated_mapping[ $event_type ] = array_values( $validated_ids );
			}
		}

		return $validated_mapping;
	}

	/**
	 * Refresh categories from API if needed (runs in background)
	 */
	private function maybe_refresh_categories() {
		if ( get_transient( 'reportedip_hive_categories_refresh_lock' ) ) {
			return;
		}

		set_transient( 'reportedip_hive_categories_refresh_lock', true, HOUR_IN_SECONDS );

		if ( $this->api_client->is_configured() ) {
			$categories = $this->api_client->get_categories();
			if ( ! empty( $categories ) && is_array( $categories ) ) {
				set_transient( 'reportedip_hive_categories', $categories, DAY_IN_SECONDS );

				$this->logger->log_security_event(
					'categories_cached',
					'system',
					array(
						'category_count' => count( $categories ),
					),
					'low'
				);
			}
		}
	}

	/**
	 * Generate report comment (GDPR-compliant - no personal data)
	 */
	private function generate_report_comment( $event_type, $details ) {
		$site_url  = get_site_url();
		$site_name = get_bloginfo( 'name' );

		switch ( $event_type ) {
			case 'failed_login':
				return sprintf(
					'WordPress login brute-force detected on %s (%s): %d failed attempts in %d minutes',
					$site_name,
					$site_url,
					$details['attempts'],
					$details['timeframe']
				);

			case 'comment_spam':
				return sprintf(
					'WordPress comment spam detected on %s (%s): %d spam comments in %d minutes',
					$site_name,
					$site_url,
					$details['attempts'],
					$details['timeframe']
				);

			case 'xmlrpc_abuse':
				return sprintf(
					'WordPress XMLRPC abuse detected on %s (%s): %d requests in %d minutes',
					$site_name,
					$site_url,
					$details['attempts'],
					$details['timeframe']
				);

			case 'admin_scanning':
				return sprintf(
					'WordPress admin area scanning detected on %s (%s): %d requests in %d minutes',
					$site_name,
					$site_url,
					$details['attempts'],
					$details['timeframe']
				);

			default:
				return sprintf(
					'Suspicious activity detected on %s (%s): %s',
					$site_name,
					$site_url,
					$event_type
				);
		}
	}

	/**
	 * Get block reason
	 */
	private function get_block_reason( $event_type, $details ) {
		switch ( $event_type ) {
			case 'failed_login':
				return sprintf( 'Failed login attempts: %d in %d minutes', $details['attempts'], $details['timeframe'] );

			case 'comment_spam':
				return sprintf( 'Comment spam: %d attempts in %d minutes', $details['attempts'], $details['timeframe'] );

			case 'xmlrpc_abuse':
				return sprintf( 'XMLRPC abuse: %d requests in %d minutes', $details['attempts'], $details['timeframe'] );

			case 'admin_scanning':
				return sprintf( 'Admin scanning: %d requests in %d minutes', $details['attempts'], $details['timeframe'] );

			default:
				return 'Suspicious activity detected';
		}
	}

	/**
	 * Get stat type for event
	 */
	private function get_stat_type_for_event( $event_type ) {
		$stat_mapping = array(
			'failed_login'   => 'failed_logins',
			'comment_spam'   => 'comment_spam',
			'xmlrpc_abuse'   => 'xmlrpc_calls',
			'admin_scanning' => 'failed_logins',
		);

		return isset( $stat_mapping[ $event_type ] ) ? $stat_mapping[ $event_type ] : 'failed_logins';
	}

	/**
	 * Send admin notification (rate-limited per IP + event type)
	 */
	private function send_admin_notification( $ip_address, $event_type, $details ) {
		if ( get_option( 'reportedip_hive_report_only_mode', false ) ) {
			$this->logger->log_security_event(
				'would_send_notification',
				$ip_address,
				array(
					'event_type'       => $event_type,
					'details'          => $details,
					'report_only_mode' => true,
					'reason'           => 'Email notification skipped due to report-only mode',
				),
				'low'
			);
			return;
		}

		$cooldown_minutes = (int) get_option( 'reportedip_hive_notification_cooldown_minutes', 60 );
		$transient_key    = 'rip_notif_' . md5( $ip_address . '_' . $event_type );

		if ( get_transient( $transient_key ) ) {
			$this->logger->log_security_event(
				'notification_rate_limited',
				$ip_address,
				array(
					'event_type'       => $event_type,
					'cooldown_minutes' => $cooldown_minutes,
					'reason'           => 'Email notification skipped due to cooldown',
				),
				'low'
			);
			return;
		}

		set_transient( $transient_key, true, $cooldown_minutes * MINUTE_IN_SECONDS );

		$admin_email = (string) get_option( 'admin_email', '' );
		if ( '' === $admin_email ) {
			return;
		}

		$site_name = wp_specialchars_decode( (string) ( get_bloginfo( 'name' ) ?: 'WordPress Site' ), ENT_QUOTES );

		$event_type_safe = $event_type ?? 'unknown';
		$event_label     = ucwords( str_replace( '_', ' ', $event_type_safe ) );
		$subject         = sprintf( '[%s] Security Alert: %s', $site_name, $event_label );
		$timestamp       = current_time( 'Y-m-d H:i:s' );

		$blocks = $this->build_alert_blocks( $event_label, $ip_address, $details, $timestamp );

		ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => $admin_email,
				'subject'         => $subject,
				'intro_text'      => __( 'Heads-up: a security threshold was reached on your site. ReportedIP Hive has already handled it according to your settings — details below for your records.', 'reportedip-hive' ),
				'main_block_html' => $blocks['html'],
				'main_block_text' => $blocks['text'],
				'security_notice' => array(
					'ip'        => $ip_address,
					'timestamp' => $timestamp,
				),
				'disclaimer'      => __( 'No action required if this matches your expectations. You can fine-tune thresholds and alerts under ReportedIP Hive → Settings → Notifications.', 'reportedip-hive' ),
				'context'         => array(
					'type'       => 'admin_security_alert',
					'event_type' => $event_type_safe,
				),
			)
		);
	}

	/**
	 * Build the HTML + plain-text blocks for an admin security alert.
	 *
	 * @param string $event_label Human-readable event label.
	 * @param string $ip_address  Triggering IP.
	 * @param array  $details     Threshold details.
	 * @param string $timestamp   Formatted timestamp.
	 * @return array{html:string,text:string}
	 */
	private function build_alert_blocks( $event_label, $ip_address, $details, $timestamp ) {
		$rows = array(
			array( __( 'Event', 'reportedip-hive' ), $event_label ),
			array( __( 'IP address', 'reportedip-hive' ), $ip_address ),
			array( __( 'Time', 'reportedip-hive' ), $timestamp ),
		);

		if ( isset( $details['attempts'] ) ) {
			$rows[] = array( __( 'Attempts', 'reportedip-hive' ), (string) (int) $details['attempts'] );
		}
		if ( isset( $details['timeframe'] ) ) {
			$rows[] = array(
				__( 'Timeframe', 'reportedip-hive' ),
				sprintf(
					/* translators: %d: minutes */
					__( '%d minutes', 'reportedip-hive' ),
					(int) $details['timeframe']
				),
			);
		}
		if ( ! empty( $details['username'] ) ) {
			$rows[] = array( __( 'Username', 'reportedip-hive' ), (string) $details['username'] );
		}

		$html = '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F9FAFB;border-radius:8px;margin:0 0 24px;">';
		foreach ( $rows as $row ) {
			$html .= '<tr>';
			$html .= '<td style="padding:10px 16px;font-size:12px;color:#6B7280;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;width:40%;">' . esc_html( $row[0] ) . '</td>';
			$html .= '<td style="padding:10px 16px;font-size:13px;color:#111827;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;word-break:break-all;">' . esc_html( $row[1] ) . '</td>';
			$html .= '</tr>';
		}
		$html .= '</table>';

		if ( get_option( 'reportedip_hive_auto_block', true ) ) {
			$duration = (int) get_option( 'reportedip_hive_block_duration', 24 );
			$html    .= '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#FEF3C7;border-radius:8px;margin:0 0 24px;">';
			$html    .= '<tr><td style="padding:16px;">';
			$html    .= '<p style="margin:0 0 4px;font-size:13px;font-weight:600;color:#92400E;">' . esc_html__( 'Action taken', 'reportedip-hive' ) . '</p>';
			$html    .= '<p style="margin:0;font-size:12px;color:#92400E;line-height:1.5;">' . esc_html(
				sprintf(
					/* translators: %d: hours */
					__( 'IP address has been automatically blocked for %d hours.', 'reportedip-hive' ),
					$duration
				)
			) . '</p>';
			$html .= '</td></tr></table>';
		}

		$html .= '<p style="margin:0 0 8px;font-size:13px;font-weight:600;color:#111827;">' . esc_html__( 'Optional next steps', 'reportedip-hive' ) . '</p>';
		$html .= '<ul style="margin:0 0 24px;padding-left:20px;font-size:13px;color:#374151;line-height:1.6;">';
		$html .= '<li>' . esc_html__( 'Open the ReportedIP Hive dashboard if you want a full timeline of recent events.', 'reportedip-hive' ) . '</li>';
		$html .= '<li>' . esc_html__( 'If this IP belongs to a legitimate user (e.g. office router, monitoring service), add it to your whitelist.', 'reportedip-hive' ) . '</li>';
		$html .= '<li>' . esc_html__( 'No further action is needed if the automatic block above matches your expectations.', 'reportedip-hive' ) . '</li>';
		$html .= '</ul>';

		$text_lines = array();
		foreach ( $rows as $row ) {
			$text_lines[] = $row[0] . ': ' . $row[1];
		}
		if ( get_option( 'reportedip_hive_auto_block', true ) ) {
			$duration     = (int) get_option( 'reportedip_hive_block_duration', 24 );
			$text_lines[] = '';
			$text_lines[] = sprintf(
				/* translators: %d: hours */
				__( 'Action: IP has been automatically blocked for %d hours.', 'reportedip-hive' ),
				$duration
			);
		}

		return array(
			'html' => $html,
			'text' => implode( "\n", $text_lines ),
		);
	}

	/**
	 * Reset failed login counter
	 */
	public function reset_failed_login_counter( $ip_address ) {
		$this->database->reset_attempt_counter( $ip_address, 'login' );
	}

	/**
	 * Check for coordinated attacks
	 */
	public function check_coordinated_attacks() {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_attempts';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name composed from $wpdb->prefix and a hardcoded suffix; safe.
		$coordinated_attacks = $wpdb->get_results(
			"SELECT
                DATE_FORMAT(last_attempt, '%Y-%m-%d %H:%i') as time_window,
                COUNT(DISTINCT ip_address) as unique_ips,
                SUM(attempt_count) as total_attempts
             FROM $table_name
             WHERE last_attempt > DATE_SUB(NOW(), INTERVAL 2 HOUR)
             AND attempt_type = 'login'
             GROUP BY time_window
             HAVING unique_ips >= 3 AND total_attempts >= 20
             ORDER BY time_window DESC"
		);

		if ( ! empty( $coordinated_attacks ) ) {
			foreach ( $coordinated_attacks as $attack ) {
				$this->logger->log_security_event(
					'coordinated_attack_detected',
					'multiple',
					array(
						'time_window'    => $attack->time_window,
						'unique_ips'     => $attack->unique_ips,
						'total_attempts' => $attack->total_attempts,
					),
					'critical'
				);
			}
		}

		return $coordinated_attacks;
	}
}
