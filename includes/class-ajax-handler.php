<?php
/**
 * AJAX Handler for ReportedIP Hive.
 *
 * Handles all AJAX requests for the plugin admin interface.
 *
 * @package   ReportedIP_Hive
 * @author    Patrick Schlesinger <ps@cms-admins.de>
 * @copyright 2025-2026 Patrick Schlesinger
 * @license   GPL-2.0-or-later https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/reportedip/reportedip-hive
 * @since     1.1.0
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ReportedIP_Hive_Ajax_Handler
 *
 * Centralizes all AJAX handler methods previously in the main plugin class.
 */
class ReportedIP_Hive_Ajax_Handler {

	/**
	 * Reference to the main plugin instance
	 *
	 * @var ReportedIP_Hive
	 */
	private $plugin;

	/**
	 * Logger instance
	 *
	 * @var ReportedIP_Hive_Logger
	 */
	private $logger;

	/**
	 * API client instance
	 *
	 * @var ReportedIP_Hive_API
	 */
	private $api_client;

	/**
	 * IP manager instance
	 *
	 * @var ReportedIP_Hive_IP_Manager
	 */
	private $ip_manager;

	/**
	 * Database instance
	 *
	 * @var ReportedIP_Hive_Database
	 */
	private $database;

	/**
	 * Security monitor instance
	 *
	 * @var ReportedIP_Hive_Security_Monitor
	 */
	private $security_monitor;

	/**
	 * Constructor - receives plugin reference and registers all AJAX hooks
	 *
	 * @param ReportedIP_Hive $plugin Main plugin instance.
	 */
	public function __construct( $plugin ) {
		$this->plugin           = $plugin;
		$this->logger           = ReportedIP_Hive_Logger::get_instance();
		$this->api_client       = ReportedIP_Hive_API::get_instance();
		$this->ip_manager       = ReportedIP_Hive_IP_Manager::get_instance();
		$this->database         = ReportedIP_Hive_Database::get_instance();
		$this->security_monitor = $plugin->get_security_monitor();

		$this->register_hooks();
	}

	/**
	 * Register all AJAX action hooks
	 */
	private function register_hooks() {
		add_action( 'wp_ajax_reportedip_hive_test_connection', array( $this, 'ajax_test_connection' ) );
		add_action( 'wp_ajax_reportedip_hive_send_test_mail', array( $this, 'ajax_send_test_mail' ) );
		add_action( 'wp_ajax_reportedip_hive_unblock_ip', array( $this, 'ajax_unblock_ip' ) );
		add_action( 'wp_ajax_reportedip_hive_export_logs', array( $this, 'ajax_export_logs' ) );
		add_action( 'wp_ajax_reportedip_hive_lookup_ip', array( $this, 'ajax_lookup_ip' ) );
		add_action( 'wp_ajax_reportedip_hive_block_ip', array( $this, 'ajax_block_ip' ) );
		add_action( 'wp_ajax_reportedip_hive_add_whitelist', array( $this, 'ajax_add_whitelist' ) );
		add_action( 'wp_ajax_reportedip_hive_remove_whitelist', array( $this, 'ajax_remove_whitelist' ) );
		add_action( 'wp_ajax_reportedip_hive_cleanup_logs', array( $this, 'ajax_cleanup_logs' ) );
		add_action( 'wp_ajax_reportedip_hive_anonymize_data', array( $this, 'ajax_anonymize_data' ) );

		add_action( 'wp_ajax_reportedip_hive_set_mode', array( $this, 'ajax_set_mode' ) );

		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			add_action( 'wp_ajax_reportedip_hive_test_logging', array( $this, 'ajax_test_logging' ) );
			add_action( 'wp_ajax_reportedip_hive_test_database', array( $this, 'ajax_test_database' ) );
			add_action( 'wp_ajax_reportedip_hive_trigger_cron', array( $this, 'ajax_trigger_cron' ) );
			add_action( 'wp_ajax_reportedip_hive_test_auto_block', array( $this, 'ajax_test_auto_block' ) );
			add_action( 'wp_ajax_reportedip_hive_simulate_failed_login', array( $this, 'ajax_simulate_failed_login' ) );
		}

		add_action( 'wp_ajax_reportedip_hive_clear_cache', array( $this, 'ajax_clear_cache' ) );
		add_action( 'wp_ajax_reportedip_hive_cleanup_cache', array( $this, 'ajax_cleanup_cache' ) );

		add_action( 'wp_ajax_reportedip_hive_import_blocked_csv', array( $this, 'ajax_import_blocked_csv' ) );
		add_action( 'wp_ajax_reportedip_hive_import_whitelist_csv', array( $this, 'ajax_import_whitelist_csv' ) );

		add_action( 'wp_ajax_reportedip_hive_retry_report', array( $this, 'ajax_retry_report' ) );
		add_action( 'wp_ajax_reportedip_hive_retry_all_failed', array( $this, 'ajax_retry_all_failed' ) );
		add_action( 'wp_ajax_reportedip_hive_delete_report', array( $this, 'ajax_delete_report' ) );

		add_action( 'wp_ajax_reportedip_hive_reset_settings', array( $this, 'ajax_reset_settings' ) );
		add_action( 'wp_ajax_reportedip_hive_reset_all_data', array( $this, 'ajax_reset_all_data' ) );

		add_action( 'wp_ajax_reportedip_hive_dismiss_notice', array( $this, 'ajax_dismiss_notice' ) );

		add_action( 'wp_ajax_reportedip_hive_dashboard_stats', array( $this, 'ajax_dashboard_stats' ) );

		add_action( 'wp_ajax_reportedip_hive_run_queue_now', array( $this, 'ajax_run_queue_now' ) );
		add_action( 'wp_ajax_reportedip_hive_clear_queue_lock', array( $this, 'ajax_clear_queue_lock' ) );
	}

	/**
	 * AJAX: Set operation mode (local/community)
	 */
	public function ajax_set_mode() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'Insufficient permissions.', 'reportedip-hive' ),
				)
			);
		}

		$mode = isset( $_POST['mode'] ) ? sanitize_text_field( wp_unslash( $_POST['mode'] ) ) : '';

		if ( ! in_array( $mode, array( 'local', 'community' ), true ) ) {
			wp_send_json_error(
				array(
					'message' => __( 'Invalid mode specified.', 'reportedip-hive' ),
				)
			);
		}

		$mode_manager = $this->plugin->get_mode_manager();
		$result       = $mode_manager->set_mode( $mode );

		if ( $result ) {
			$mode_info = $mode_manager->get_mode_info();
			wp_send_json_success(
				array(
					'message'   => sprintf(
						/* translators: %s: mode label */
						__( 'Mode changed to %s', 'reportedip-hive' ),
						$mode_info['label']
					),
					'mode'      => $mode,
					'mode_info' => $mode_info,
				)
			);
		} else {
			wp_send_json_error(
				array(
					'message' => __( 'Failed to change mode. Please try again.', 'reportedip-hive' ),
				)
			);
		}
	}

	/**
	 * AJAX: Test API connection
	 */
	public function ajax_test_connection() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'reportedip-hive' ) ) );
		}

		$result = $this->api_client->test_connection();
		wp_send_json( $result );
	}

	/**
	 * AJAX: Send a test mail through the central Mailer.
	 *
	 * Lets admins verify the brand template + provider setup before any real
	 * mail goes out. Recipient defaults to the admin who triggered the action;
	 * a `recipient` POST arg may override (still capability-gated).
	 */
	public function ajax_send_test_mail() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'reportedip-hive' ) ) );
		}

		$current_user = wp_get_current_user();
		$default_to   = $current_user instanceof WP_User && ! empty( $current_user->user_email )
			? $current_user->user_email
			: (string) get_option( 'admin_email', '' );

		$override = isset( $_POST['recipient'] ) ? sanitize_email( wp_unslash( $_POST['recipient'] ) ) : '';
		$to       = '' !== $override ? $override : $default_to;

		if ( '' === $to || ! is_email( $to ) ) {
			wp_send_json_error( array( 'message' => __( 'No valid recipient address available.', 'reportedip-hive' ) ) );
		}

		$site_name = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
		$timestamp = wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ) );

		$main_html  = '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F9FAFB;border-radius:8px;margin:0 0 24px;">';
		$main_html .= '<tr><td style="padding:10px 16px;font-size:12px;color:#6B7280;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;width:40%;">' . esc_html__( 'Test type', 'reportedip-hive' ) . '</td>';
		$main_html .= '<td style="padding:10px 16px;font-size:13px;color:#111827;">' . esc_html__( 'Brand template + provider verification', 'reportedip-hive' ) . '</td></tr>';
		$main_html .= '<tr><td style="padding:10px 16px;font-size:12px;color:#6B7280;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;width:40%;">' . esc_html__( 'Triggered by', 'reportedip-hive' ) . '</td>';
		$main_html .= '<td style="padding:10px 16px;font-size:13px;color:#111827;">' . esc_html( $current_user->display_name ?? '—' ) . '</td></tr>';
		$main_html .= '<tr><td style="padding:10px 16px;font-size:12px;color:#6B7280;text-transform:uppercase;letter-spacing:0.5px;font-weight:600;width:40%;">' . esc_html__( 'Time', 'reportedip-hive' ) . '</td>';
		$main_html .= '<td style="padding:10px 16px;font-size:13px;color:#111827;">' . esc_html( $timestamp ) . '</td></tr>';
		$main_html .= '</table>';

		$result = ReportedIP_Hive_Mailer::get_instance()->send(
			array(
				'to'              => $to,
				'subject'         => sprintf(
					/* translators: %s: site name */
					__( '[%s] ReportedIP Hive test email', 'reportedip-hive' ),
					$site_name
				),
				'greeting'        => sprintf(
					/* translators: %s: user display name */
					__( 'Hello %s,', 'reportedip-hive' ),
					$current_user->display_name ?? ''
				),
				'intro_text'      => __( 'This is a test message from ReportedIP Hive. If you can read this in your usual mail client, the brand template and your active mail provider are working correctly.', 'reportedip-hive' ),
				'main_block_html' => $main_html,
				'main_block_text' => sprintf(
					"%s: %s\n%s: %s\n%s: %s",
					__( 'Test type', 'reportedip-hive' ),
					__( 'Brand template + provider verification', 'reportedip-hive' ),
					__( 'Triggered by', 'reportedip-hive' ),
					$current_user->display_name ?? '—',
					__( 'Time', 'reportedip-hive' ),
					$timestamp
				),
				'disclaimer'      => __( 'No action required. This email was sent on demand from the plugin settings.', 'reportedip-hive' ),
				'context'         => array(
					'type'    => 'test_mail',
					'user_id' => get_current_user_id(),
				),
			)
		);

		if ( $result ) {
			wp_send_json_success(
				array(
					'message'   => sprintf(
						/* translators: %s: masked recipient */
						__( 'Test email sent to %s.', 'reportedip-hive' ),
						$to
					),
					'recipient' => $to,
				)
			);
		}

		wp_send_json_error(
			array(
				'message' => __( 'Test email could not be sent. Check the WordPress mail configuration or your active mail provider.', 'reportedip-hive' ),
			)
		);
	}

	/**
	 * AJAX: Unblock IP
	 * Note: Unblocking is only local - it does NOT send any feedback to the ReportedIP API
	 */
	public function ajax_unblock_ip() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'reportedip-hive' ) ) );
		}

		$ip_address = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';

		$result = $this->ip_manager->unblock_ip( $ip_address );

		if ( $result ) {
			$this->logger->log_security_event(
				'ip_unblocked',
				$ip_address,
				array(
					'user_id' => get_current_user_id(),
				),
				'low'
			);
		}

		wp_send_json_success( $result );
	}

	/**
	 * AJAX: Export logs
	 */
	public function ajax_export_logs() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Unauthorized.', 'reportedip-hive' ) ) );
		}

		$format = isset( $_POST['format'] ) ? sanitize_text_field( wp_unslash( $_POST['format'] ) ) : 'csv';
		$days   = intval( $_POST['days'] ?? 30 );

		$logs = $this->logger->get_logs( $days );

		if ( $format === 'csv' ) {
			$this->export_logs_csv( $logs );
		} else {
			$this->export_logs_json( $logs );
		}
	}

	/**
	 * Export logs as CSV
	 *
	 * @param array $logs Log entries to export.
	 */
	private function export_logs_csv( $logs ) {
		header( 'Content-Type: text/csv' );
		header( 'Content-Disposition: attachment; filename="reportedip-hive-logs-' . gmdate( 'Y-m-d' ) . '.csv"' );

		$output = fopen( 'php://output', 'w' );
		fputcsv( $output, array( 'Date', 'Event Type', 'IP Address', 'Details' ) );

		foreach ( $logs as $log ) {
			fputcsv(
				$output,
				array(
					$log->created_at,
					$log->event_type,
					$log->ip_address,
					$log->details,
				)
			);
		}

		fclose( $output ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- php://output stream
		exit;
	}

	/**
	 * Export logs as JSON
	 *
	 * @param array $logs Log entries to export.
	 */
	private function export_logs_json( $logs ) {
		header( 'Content-Type: application/json' );
		header( 'Content-Disposition: attachment; filename="reportedip-hive-logs-' . gmdate( 'Y-m-d' ) . '.json"' );

		echo wp_json_encode( $logs, JSON_PRETTY_PRINT );
		exit;
	}

	/**
	 * AJAX: Lookup IP
	 */
	public function ajax_lookup_ip() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$ip_address = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';

		if ( empty( $ip_address ) || ! filter_var( $ip_address, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( __( 'Invalid IP address.', 'reportedip-hive' ) );
		}

		try {
			$result = $this->ip_manager->get_ip_info( $ip_address );
			wp_send_json_success( $result );
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Block IP
	 */
	public function ajax_block_ip() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$ip_address = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';
		$reason     = isset( $_POST['reason'] ) ? sanitize_textarea_field( wp_unslash( $_POST['reason'] ) ) : '';
		$duration   = isset( $_POST['duration'] ) ? intval( $_POST['duration'] ) : 24;

		if ( empty( $ip_address ) || ! filter_var( $ip_address, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( __( 'Invalid IP address.', 'reportedip-hive' ) );
		}

		if ( empty( $reason ) ) {
			wp_send_json_error( __( 'Reason is required.', 'reportedip-hive' ) );
		}

		try {
			$result = $this->ip_manager->block_ip( $ip_address, $reason, $duration, 'manual' );

			if ( $result['success'] ) {
				wp_send_json_success( $result );
			} else {
				wp_send_json_error( $result['message'] );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Add to whitelist
	 */
	public function ajax_add_whitelist() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$ip_address = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';
		$reason     = isset( $_POST['reason'] ) ? sanitize_textarea_field( wp_unslash( $_POST['reason'] ) ) : '';
		$expires_at = isset( $_POST['expires_at'] ) ? sanitize_text_field( wp_unslash( $_POST['expires_at'] ) ) : '';

		if ( empty( $ip_address ) ) {
			wp_send_json_error( __( 'IP address is required.', 'reportedip-hive' ) );
		}

		if ( ! $this->ip_manager->validate_ip_address( $ip_address ) ) {
			wp_send_json_error( __( 'Invalid IP address or CIDR format.', 'reportedip-hive' ) );
		}

		if ( ! empty( $expires_at ) && strtotime( $expires_at ) === false ) {
			wp_send_json_error( __( 'Invalid expiration date.', 'reportedip-hive' ) );
		}

		try {
			$result = $this->ip_manager->whitelist_ip( $ip_address, $reason, ! empty( $expires_at ) ? $expires_at : null );

			if ( $result['success'] ) {
				wp_send_json_success( $result );
			} else {
				wp_send_json_error( $result['message'] );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Remove from whitelist
	 */
	public function ajax_remove_whitelist() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$ip_address = isset( $_POST['ip_address'] ) ? sanitize_text_field( wp_unslash( $_POST['ip_address'] ) ) : '';

		if ( empty( $ip_address ) ) {
			wp_send_json_error( __( 'IP address is required.', 'reportedip-hive' ) );
		}

		try {
			$result = $this->ip_manager->remove_from_whitelist( $ip_address );

			if ( $result['success'] ) {
				wp_send_json_success( $result );
			} else {
				wp_send_json_error( $result['message'] );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Cleanup old logs
	 */
	public function ajax_cleanup_logs() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			$retention_days = get_option( 'reportedip_hive_data_retention_days', 30 );
			$cleaned        = $this->database->cleanup_old_data( $retention_days );
			$expired        = $this->ip_manager->cleanup_expired_entries();

			wp_send_json_success(
				array(
					'message'         => sprintf(
						/* translators: 1: number of old log entries removed, 2: number of expired IP entries removed */
						__( 'Cleanup completed. Removed %1$d old log entries and %2$d expired IP entries.', 'reportedip-hive' ),
						$cleaned,
						$expired
					),
					'cleaned_logs'    => $cleaned,
					'expired_entries' => $expired,
				)
			);
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Anonymize old data
	 */
	public function ajax_anonymize_data() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			$anonymize_days = get_option( 'reportedip_hive_auto_anonymize_days', 7 );
			$anonymized     = $this->database->anonymize_old_data( $anonymize_days );

			wp_send_json_success(
				array(
					'message'            => sprintf(
						/* translators: 1: number of anonymized entries, 2: minimum age in days */
						__( 'Anonymization completed. Anonymized %1$d entries older than %2$d days.', 'reportedip-hive' ),
						$anonymized,
						$anonymize_days
					),
					'anonymized_entries' => $anonymized,
					'anonymize_days'     => $anonymize_days,
				)
			);
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Import blocked IPs from CSV
	 * Note: Import is local only - no reports are sent to the API
	 */
	public function ajax_import_blocked_csv() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$content  = $this->validate_csv_upload();
		$duration = isset( $_POST['duration'] ) ? intval( $_POST['duration'] ) : 720;

		$lines    = explode( "\n", trim( $content ) );
		$imported = 0;
		$errors   = array();
		$skipped  = 0;

		foreach ( $lines as $line_num => $line ) {
			$line = trim( $line );

			if ( empty( $line ) || strpos( $line, '#' ) === 0 ) {
				continue;
			}

			$parts      = str_getcsv( $line );
			$ip_address = isset( $parts[0] ) ? trim( $parts[0] ) : '';
			$reason     = isset( $parts[1] ) ? trim( $parts[1] ) : __( 'Imported from CSV', 'reportedip-hive' );

			if ( ! filter_var( $ip_address, FILTER_VALIDATE_IP ) ) {
				/* translators: 1: line number in CSV file, 2: invalid IP value found */
				$errors[] = sprintf( __( 'Line %1$d: Invalid IP "%2$s"', 'reportedip-hive' ), $line_num + 1, esc_html( $ip_address ) );
				continue;
			}

			if ( $this->ip_manager->is_blocked( $ip_address ) ) {
				++$skipped;
				continue;
			}

			$result = $this->ip_manager->block_ip( $ip_address, $reason, $duration, 'manual' );
			if ( $result['success'] ) {
				++$imported;
			} else {
				/* translators: 1: line number in CSV file, 2: IP address, 3: error message returned by the blocker */
				$errors[] = sprintf( __( 'Line %1$d: Failed to block "%2$s" - %3$s', 'reportedip-hive' ), $line_num + 1, esc_html( $ip_address ), $result['message'] );
			}
		}

		$this->logger->log_security_event(
			'csv_import_blocked',
			'0.0.0.0',
			array(
				'imported'       => $imported,
				'skipped'        => $skipped,
				'errors'         => count( $errors ),
				'duration_hours' => $duration,
			),
			'low'
		);

		wp_send_json_success(
			array(
				'imported' => $imported,
				'skipped'  => $skipped,
				'errors'   => $errors,
				'message'  => sprintf(
					/* translators: 1: number of imported IPs, 2: number of skipped IPs, 3: number of errors */
					__( '%1$d IPs imported, %2$d skipped (already blocked), %3$d errors.', 'reportedip-hive' ),
					$imported,
					$skipped,
					count( $errors )
				),
			)
		);
	}

	/**
	 * AJAX: Import whitelist IPs from CSV
	 * Note: Import is local only - no reports are sent to the API
	 */
	public function ajax_import_whitelist_csv() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$content = $this->validate_csv_upload();

		$result = $this->ip_manager->import_whitelist_csv( $content );

		$this->logger->log_security_event(
			'csv_import_whitelist',
			'0.0.0.0',
			array(
				'imported' => $result['imported'],
				'errors'   => count( $result['errors'] ),
			),
			'low'
		);

		wp_send_json_success(
			array(
				'imported' => $result['imported'],
				'errors'   => $result['errors'],
				'message'  => sprintf(
					/* translators: 1: number of IPs imported to whitelist, 2: number of errors */
					__( '%1$d IPs imported to whitelist, %2$d errors.', 'reportedip-hive' ),
					$result['imported'],
					count( $result['errors'] )
				),
			)
		);
	}

	/**
	 * AJAX: Test logging system
	 */
	public function ajax_test_logging() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$severity = isset( $_POST['severity'] ) ? sanitize_text_field( wp_unslash( $_POST['severity'] ) ) : 'medium';

		try {
			$test_ip      = ReportedIP_Hive::get_client_ip();
			$test_details = array(
				'test_type'       => 'logging_test',
				'severity_tested' => $severity,
				'timestamp'       => current_time( 'mysql' ),
				'user_id'         => get_current_user_id(),
				'test_message'    => sprintf( 'This is a %s severity logging test', $severity ),
			);

			$result = $this->logger->log_security_event( 'debug_test_' . $severity, $test_ip, $test_details, $severity );

			if ( $result !== false ) {
				wp_send_json_success(
					array(
						/* translators: %s: severity level used in the test event */
						'message' => sprintf( __( 'Successfully logged %s severity test event.', 'reportedip-hive' ), $severity ),
						'log_id'  => $result,
					)
				);
			} else {
				wp_send_json_error( __( 'Failed to log test event. Check database connection.', 'reportedip-hive' ) );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Test database connection
	 */
	public function ajax_test_database() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			global $wpdb;

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Test query
			$test_query = $wpdb->get_var( 'SELECT 1' );

			if ( $test_query !== '1' ) {
				wp_send_json_error( __( 'Basic database connection failed.', 'reportedip-hive' ) );
			}

			$table_name = $wpdb->prefix . 'reportedip_hive_logs';
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Schema introspection.
			$table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table_name ) ) === $table_name;

			if ( ! $table_exists ) {
				wp_send_json_error( __( 'Plugin database tables are missing. Try deactivating and reactivating the plugin.', 'reportedip-hive' ) );
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Test insert
			$test_result = $wpdb->insert(
				$table_name,
				array(
					'event_type' => 'database_test',
					'ip_address' => ReportedIP_Hive::get_client_ip(),
					'details'    => wp_json_encode(
						array(
							'test_type' => 'database_connection_test',
							'timestamp' => current_time( 'mysql' ),
						)
					),
					'severity'   => 'low',
				),
				array( '%s', '%s', '%s', '%s' )
			);

			if ( $test_result === false ) {
				wp_send_json_error( __( 'Database insert test failed: ', 'reportedip-hive' ) . $wpdb->last_error );
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Test cleanup
			$wpdb->delete( $table_name, array( 'id' => $wpdb->insert_id ), array( '%d' ) );

			wp_send_json_success(
				array(
					'message' => __( 'Database connection and functionality test successful.', 'reportedip-hive' ),
					'details' => array(
						'connection' => 'OK',
						'tables'     => 'OK',
						'insert'     => 'OK',
						'cleanup'    => 'OK',
					),
				)
			);

		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Trigger cron jobs manually
	 */
	public function ajax_trigger_cron() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			$this->logger->info(
				'Manual cron trigger initiated',
				ReportedIP_Hive::get_client_ip(),
				array(
					'user_id'   => get_current_user_id(),
					'timestamp' => current_time( 'mysql' ),
				)
			);

			$this->plugin->get_cron_handler()->trigger_cron_manually( 'all' );

			wp_send_json_success(
				array(
					'message'   => __( 'Cron jobs triggered successfully. Check logs for results.', 'reportedip-hive' ),
					'triggered' => array( 'cleanup', 'sync_reputation' ),
				)
			);

		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Test auto-block function
	 */
	public function ajax_test_auto_block() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			$test_ip      = '192.0.2.1';
			$test_details = array(
				'test_type' => 'auto_block_test',
				'attempts'  => 10,
				'threshold' => 5,
				'timeframe' => 15,
				'timestamp' => current_time( 'mysql' ),
				'user_id'   => get_current_user_id(),
			);

			$this->logger->log_security_event( 'auto_block_test_initiated', $test_ip, $test_details, 'medium' );

			$block_result = $this->security_monitor->auto_block_ip( $test_ip, 'failed_login', $test_details );

			if ( $block_result ) {
				wp_send_json_success(
					array(
						'message' => __( 'Auto-block function test successful! Test IP was blocked.', 'reportedip-hive' ),
						'test_ip' => $test_ip,
						'blocked' => true,
						'details' => $test_details,
					)
				);
			} else {
				$is_report_only     = get_option( 'reportedip_hive_report_only_mode', false );
				$auto_block_enabled = get_option( 'reportedip_hive_auto_block', true );

				$failure_reason = '';
				if ( $is_report_only ) {
					$failure_reason = 'Report-only mode is enabled';
				} elseif ( ! $auto_block_enabled ) {
					$failure_reason = 'Auto-block is disabled';
				} else {
					$failure_reason = 'Unknown reason - check logs for details';
				}

				wp_send_json_success(
					array(
						/* translators: %s: human readable reason why the IP was not blocked */
						'message'            => sprintf( __( 'Auto-block function test completed. IP was not blocked. Reason: %s', 'reportedip-hive' ), $failure_reason ),
						'test_ip'            => $test_ip,
						'blocked'            => false,
						'reason'             => $failure_reason,
						'report_only_mode'   => $is_report_only,
						'auto_block_enabled' => $auto_block_enabled,
					)
				);
			}
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Simulate failed login threshold
	 */
	public function ajax_simulate_failed_login() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			$test_ip   = '192.0.2.2';
			$threshold = get_option( 'reportedip_hive_failed_login_threshold', 5 );
			$timeframe = get_option( 'reportedip_hive_failed_login_timeframe', 15 );

			$this->logger->log_security_event(
				'failed_login_simulation_started',
				$test_ip,
				array(
					'test_type' => 'failed_login_threshold_simulation',
					'threshold' => $threshold,
					'timeframe' => $timeframe,
					'user_id'   => get_current_user_id(),
					'timestamp' => current_time( 'mysql' ),
				),
				'medium'
			);

			for ( $i = 1; $i <= $threshold + 1; $i++ ) {
				$this->database->track_attempt( $test_ip, 'login', 'test_user_' . $i, 'Test User Agent' );

				$this->logger->log_security_event(
					'simulated_failed_login',
					$test_ip,
					array(
						'attempt_number' => $i,
						'username'       => 'test_user_' . $i,
						'simulation'     => true,
					),
					'low'
				);
			}

			$attempt_count = $this->database->get_attempt_count( $test_ip, 'login', $timeframe );

			if ( $attempt_count >= $threshold ) {
				$threshold_exceeded = $this->security_monitor->check_failed_login_threshold( $test_ip, 'test_user_final' );

				wp_send_json_success(
					array(
						'message'            => sprintf(
							/* translators: 1: number of attempts recorded, 2: configured threshold, 3: "Yes" or "No" indicating threshold exceeded */
							__( 'Failed login threshold simulation completed. %1$d attempts recorded, threshold is %2$d. Threshold exceeded: %3$s', 'reportedip-hive' ),
							$attempt_count,
							$threshold,
							$threshold_exceeded ? 'Yes' : 'No'
						),
						'test_ip'            => $test_ip,
						'attempts'           => $attempt_count,
						'threshold'          => $threshold,
						'threshold_exceeded' => $threshold_exceeded,
						'auto_block_enabled' => get_option( 'reportedip_hive_auto_block', true ),
						'report_only_mode'   => get_option( 'reportedip_hive_report_only_mode', false ),
					)
				);
			} else {
				wp_send_json_error(
					sprintf(
						/* translators: 1: number of attempts that were actually recorded, 2: number of attempts that were expected */
						__( 'Simulation failed. Only %1$d attempts recorded, but %2$d were expected.', 'reportedip-hive' ),
						$attempt_count,
						$threshold + 1
					)
				);
			}
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Clear all cache
	 */
	public function ajax_clear_cache() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			$cache   = ReportedIP_Hive_Cache::get_instance();
			$deleted = $cache->clear_all_cache();

			wp_send_json_success(
				array(
					'message'         => sprintf(
						/* translators: %d: number of cache entries that were removed */
						__( 'Cache cleared successfully. Removed %d cache entries.', 'reportedip-hive' ),
						$deleted
					),
					'deleted_entries' => $deleted,
				)
			);

		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Cleanup expired cache
	 */
	public function ajax_cleanup_cache() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			$cache   = ReportedIP_Hive_Cache::get_instance();
			$cleaned = $cache->cleanup_expired_cache();

			wp_send_json_success(
				array(
					'message'         => sprintf(
						/* translators: %d: number of expired cache entries that were removed */
						__( 'Expired cache entries cleaned up. Removed %d expired entries.', 'reportedip-hive' ),
						$cleaned
					),
					'cleaned_entries' => $cleaned,
				)
			);

		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Retry single API report
	 */
	public function ajax_retry_report() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$report_id = intval( $_POST['report_id'] ?? 0 );

		if ( $report_id <= 0 ) {
			wp_send_json_error( __( 'Invalid report ID.', 'reportedip-hive' ) );
		}

		try {
			$this->database->reset_report_for_retry( $report_id );

			global $wpdb;
			$tbl = $wpdb->prefix . 'reportedip_hive_api_queue';
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $tbl WHERE id = %d", $report_id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name composed from $wpdb->prefix and a hardcoded suffix.
			if ( ! $row ) {
				wp_send_json_error( __( 'Queue row not found.', 'reportedip-hive' ) );
			}

			$api = ReportedIP_Hive_API::get_instance();
			if ( $row->report_type === 'positive' ) {
				$send    = $api->report_positive_feedback( $row->ip_address, (string) ( $row->comment ?? '' ) );
				$success = $send !== false;
				$message = $success ? 'sent' : 'failed';
			} else {
				$cats    = explode( ',', (string) $row->category_ids );
				$send    = $api->report_ip( $row->ip_address, $cats, (string) ( $row->comment ?? '' ) );
				$success = ! empty( $send['success'] );
				$message = is_array( $send ) ? (string) ( $send['message'] ?? '' ) : '';
			}

			if ( $success ) {
				$this->database->update_api_report_status( $report_id, 'completed' );
			} else {
				$this->database->update_api_report_status( $report_id, 'failed', $message ?: 'Unknown error' );
			}

			$this->logger->log_security_event(
				'api_report_retry',
				'system',
				array(
					'report_id' => $report_id,
					'user_id'   => get_current_user_id(),
					'success'   => $success,
					'message'   => $message,
				),
				'low'
			);

			if ( $success ) {
				wp_send_json_success(
					array(
						'message'   => __( 'Report sent.', 'reportedip-hive' ),
						'report_id' => $report_id,
					)
				);
			} else {
				wp_send_json_error(
					sprintf(
					/* translators: %s: API error message */
						__( 'Send failed: %s', 'reportedip-hive' ),
						$message ?: __( 'unknown error', 'reportedip-hive' )
					)
				);
			}
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Retry all failed API reports
	 */
	public function ajax_retry_all_failed() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			$reset_count = $this->database->reset_all_failed_reports();

			$api    = ReportedIP_Hive_API::get_instance();
			$result = $api->process_report_queue( 50 );

			$processed = is_array( $result ) ? (int) ( $result['processed'] ?? 0 ) : 0;
			$errors    = is_array( $result ) ? (int) ( $result['errors'] ?? 0 ) : 0;
			$skipped   = is_array( $result ) && ! empty( $result['skipped'] );
			$reason    = is_array( $result ) ? (string) ( $result['reason'] ?? '' ) : '';

			$this->logger->log_security_event(
				'api_reports_bulk_retry',
				'system',
				array(
					'reset'     => $reset_count,
					'processed' => $processed,
					'errors'    => $errors,
					'skipped'   => $skipped,
					'reason'    => $reason,
					'user_id'   => get_current_user_id(),
				),
				'low'
			);

			$msg = sprintf(
				/* translators: 1: reset count, 2: processed count, 3: errors count */
				__( '%1$d failed reset · %2$d sent · %3$d errors', 'reportedip-hive' ),
				$reset_count,
				$processed,
				$errors
			);
			if ( $skipped ) {
				$msg .= ' (' . ( $reason ?: 'skipped' ) . ')';
			}

			wp_send_json_success(
				array(
					'message'   => $msg,
					'reset'     => $reset_count,
					'processed' => $processed,
					'errors'    => $errors,
				)
			);

		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Delete API queue item
	 */
	public function ajax_delete_report() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$report_id = intval( $_POST['report_id'] ?? 0 );

		if ( $report_id <= 0 ) {
			wp_send_json_error( __( 'Invalid report ID.', 'reportedip-hive' ) );
		}

		try {
			$result = $this->database->delete_api_queue_item( $report_id );

			if ( $result ) {
				$this->logger->log_security_event(
					'api_report_deleted',
					'system',
					array(
						'report_id' => $report_id,
						'user_id'   => get_current_user_id(),
					),
					'low'
				);

				wp_send_json_success(
					array(
						'message'   => __( 'Queue item deleted.', 'reportedip-hive' ),
						'report_id' => $report_id,
					)
				);
			} else {
				wp_send_json_error( __( 'Failed to delete queue item.', 'reportedip-hive' ) );
			}
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX handler: Reset all settings to defaults
	 */
	public function ajax_reset_settings() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			$defaults = ReportedIP_Hive::get_default_options();

			foreach ( array_keys( $defaults ) as $option ) {
				delete_option( $option );
			}

			delete_option( 'reportedip_hive_operation_mode' );
			delete_option( 'reportedip_hive_wizard_completed' );
			delete_option( 'reportedip_hive_wizard_completed_at' );
			delete_option( 'reportedip_hive_wizard_skipped' );

			delete_transient( 'reportedip_hive_health_warning_logged' );
			delete_transient( 'reportedip_hive_wizard_redirect' );

			ReportedIP_Hive::apply_default_options();

			$this->logger->info(
				'All settings have been reset to defaults',
				'0.0.0.0',
				array(
					'user_id' => get_current_user_id(),
				)
			);

			wp_send_json_success( __( 'All settings have been reset to defaults. The page will reload.', 'reportedip-hive' ) );
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX handler: Reset all plugin data (settings, blocked IPs, logs, cache)
	 */
	public function ajax_reset_all_data() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		try {
			global $wpdb;

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Bulk deletion for plugin reset.
			$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'reportedip_hive_%'" );

			$tables = array(
				$wpdb->prefix . 'reportedip_hive_logs',
				$wpdb->prefix . 'reportedip_hive_blocked',
				$wpdb->prefix . 'reportedip_hive_whitelist',
				$wpdb->prefix . 'reportedip_hive_api_queue',
				$wpdb->prefix . 'reportedip_hive_attempts',
				$wpdb->prefix . 'reportedip_hive_stats',
			);

			foreach ( $tables as $table ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Bulk table truncation for plugin reset.
				$wpdb->query( "TRUNCATE TABLE {$table}" );
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Bulk deletion for plugin reset.
			$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_reportedip_hive_%' OR option_name LIKE '_transient_timeout_reportedip_hive_%'" );

			delete_option( 'reportedip_hive_wizard_completed' );

			wp_send_json_success( __( 'All plugin data has been deleted. The page will reload.', 'reportedip-hive' ) );
		} catch ( Exception $e ) {
			wp_send_json_error( $e->getMessage() );
		}
	}

	/**
	 * AJAX: Dismiss admin notice persistently
	 */
	public function ajax_dismiss_notice() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$notice_id = isset( $_POST['notice_id'] ) ? sanitize_key( $_POST['notice_id'] ) : '';
		if ( empty( $notice_id ) ) {
			wp_send_json_error( __( 'Invalid notice ID.', 'reportedip-hive' ) );
		}

		$meta_key = 'reportedip_dismissed_' . $notice_id;
		update_user_meta( get_current_user_id(), $meta_key, time() );

		wp_send_json_success();
	}

	/**
	 * AJAX: Get dashboard statistics
	 */
	public function ajax_dashboard_stats() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( __( 'Insufficient permissions.', 'reportedip-hive' ) );
		}

		$stats = array(
			'blocked_ips'     => $this->database->count_blocked_ips(),
			'total_events'    => $this->database->get_log_statistics(),
			'pending_reports' => $this->database->get_queue_size(),
		);

		wp_send_json_success( $stats );
	}

	/**
	 * Validate and read CSV upload file
	 *
	 * Validates file presence, upload errors, size, type, and reads content.
	 * Sends JSON error and dies on any validation failure.
	 *
	 * @return string File content on success (only returns on success, dies on failure)
	 */
	private function validate_csv_upload() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Caller (ajax_import_*_csv) verifies the nonce via check_ajax_referer() before invoking this helper.
		if ( ! isset( $_FILES['csv_file'] ) ) {
			wp_send_json_error( __( 'No file uploaded.', 'reportedip-hive' ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Caller verifies the nonce; the $_FILES array is validated field-by-field below (error/size/type) and read via wp_check_filetype() / file_get_contents() on the validated tmp path.
		$file = $_FILES['csv_file'];

		if ( $file['error'] !== UPLOAD_ERR_OK ) {
			$error_messages = array(
				UPLOAD_ERR_INI_SIZE   => __( 'File exceeds upload_max_filesize.', 'reportedip-hive' ),
				UPLOAD_ERR_FORM_SIZE  => __( 'File exceeds MAX_FILE_SIZE.', 'reportedip-hive' ),
				UPLOAD_ERR_PARTIAL    => __( 'File was only partially uploaded.', 'reportedip-hive' ),
				UPLOAD_ERR_NO_FILE    => __( 'No file was uploaded.', 'reportedip-hive' ),
				UPLOAD_ERR_NO_TMP_DIR => __( 'Missing temporary folder.', 'reportedip-hive' ),
				UPLOAD_ERR_CANT_WRITE => __( 'Failed to write file to disk.', 'reportedip-hive' ),
				UPLOAD_ERR_EXTENSION  => __( 'File upload stopped by extension.', 'reportedip-hive' ),
			);
			$error_msg      = isset( $error_messages[ $file['error'] ] ) ? $error_messages[ $file['error'] ] : __( 'Unknown upload error.', 'reportedip-hive' );
			wp_send_json_error( $error_msg );
		}

		if ( $file['size'] > REPORTEDIP_MAX_CSV_UPLOAD_SIZE ) {
			wp_send_json_error( __( 'File too large. Maximum size is 1 MB.', 'reportedip-hive' ) );
		}

		$file_type = wp_check_filetype( $file['name'] );
		if ( ! in_array( $file_type['ext'], array( 'csv', 'txt' ), true ) ) {
			wp_send_json_error( __( 'Invalid file type. Only CSV and TXT files are allowed.', 'reportedip-hive' ) );
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading local temp file
		$content = file_get_contents( $file['tmp_name'] );
		if ( $content === false ) {
			wp_send_json_error( __( 'Failed to read uploaded file.', 'reportedip-hive' ) );
		}

		return $content;
	}

	/**
	 * AJAX: Manually drain the API report queue and refresh quota.
	 *
	 * Runs the same path as the 15-minute WP-Cron job. Used when WP-Cron is
	 * not firing reliably (loopback blocked by CDN/cache plugin) or for
	 * one-shot draining after a tier upgrade. Capability- and nonce-gated.
	 *
	 * @return void
	 * @since 1.6.7
	 */
	public function ajax_run_queue_now() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ) );
		}

		try {
			$cron_handler = $this->plugin->get_cron_handler();
			$cron_handler->cron_process_queue();
			$cron_handler->cron_refresh_quota();

			$queue_size = $this->database->get_queue_size();

			wp_send_json_success(
				array(
					'message'   => __( 'Queue processed and quota refreshed. Check Activity log for details.', 'reportedip-hive' ),
					'remaining' => (int) $queue_size,
				)
			);
		} catch ( \Throwable $e ) {
			wp_send_json_error( array( 'message' => $e->getMessage() ) );
		}
	}

	/**
	 * AJAX: Clear the queue-processing lock transient.
	 *
	 * Safety net for the rare case that the lock survives a crashed worker
	 * (e.g. PHP timeout combined with a flaky object-cache backend) and
	 * blocks every subsequent cron run for 5 minutes longer than expected.
	 * Capability- and nonce-gated.
	 *
	 * @return void
	 * @since 1.6.7
	 */
	public function ajax_clear_queue_lock() {
		check_ajax_referer( 'reportedip_hive_nonce', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'reportedip-hive' ) ) );
		}

		$held = (bool) get_transient( ReportedIP_Hive_Cron_Handler::QUEUE_LOCK_TRANSIENT );
		delete_transient( ReportedIP_Hive_Cron_Handler::QUEUE_LOCK_TRANSIENT );

		wp_send_json_success(
			array(
				'message'      => $held
					? __( 'Queue lock cleared.', 'reportedip-hive' )
					: __( 'No queue lock was held.', 'reportedip-hive' ),
				'was_locked'   => $held,
			)
		);
	}
}
