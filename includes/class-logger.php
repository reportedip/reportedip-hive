<?php
/**
 * Logger Class for ReportedIP Hive.
 *
 * Implements Singleton pattern to avoid multiple instantiations.
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

class ReportedIP_Hive_Logger {

	/**
	 * Single instance of the class
	 */
	private static $instance = null;

	private $database;
	private $log_level;

	/**
	 * Get single instance
	 *
	 * @return ReportedIP_Hive_Logger
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor - private for singleton
	 */
	private function __construct() {
		$this->log_level = get_option( 'reportedip_hive_log_level', 'info' );
		$this->database  = ReportedIP_Hive_Database::get_instance();
	}

	/**
	 * Prevent cloning
	 */
	private function __clone() {}

	/**
	 * Prevent unserialization
	 */
	public function __wakeup() {
		throw new \Exception( 'Cannot unserialize singleton' );
	}

	/**
	 * Log security event
	 */
	public function log_security_event( $event_type, $ip_address, $details = array(), $severity = 'medium' ) {
		if ( ! $this->should_log( $severity ) ) {
			return false;
		}

		$log_details = array(
			'timestamp' => current_time( 'mysql' ),
		);

		if ( ! get_option( 'reportedip_hive_minimal_logging', true ) ) {
			$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			if ( ! empty( $request_uri ) ) {
				$uri = wp_parse_url( $request_uri, PHP_URL_PATH );
				if ( $uri !== false && $uri !== null ) {
					$log_details['request_path'] = $uri;
				}
			}

			$server_name = isset( $_SERVER['SERVER_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) ) : '';
			if ( ! empty( $server_name ) ) {
				$log_details['server_name'] = $server_name;
			}

			$http_referer = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';
			if ( ! empty( $http_referer ) && get_option( 'reportedip_hive_log_referer_domains', false ) ) {
				$referer_domain = wp_parse_url( $http_referer, PHP_URL_HOST );
				if ( $referer_domain !== false && $referer_domain !== null ) {
					$log_details['referer_domain'] = $referer_domain;
				}
			}
		}

		$log_details = array_merge( $log_details, $details );

		$result = $this->database->log_security_event( $event_type, $ip_address, $log_details, $severity );

		if ( defined( 'REPORTEDIP_DEBUG' ) && REPORTEDIP_DEBUG ) {
			$log_message = sprintf(
				'ReportedIP Hive [%s]: %s from %s',
				strtoupper( $severity ),
				$event_type,
				$ip_address
			);
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Plugin diagnostic logging gated behind REPORTEDIP_DEBUG; debug.log only.
			error_log( $log_message );
		}

		return $result;
	}

	/**
	 * Format log details for display
	 */
	public function format_details( $details ) {
		if ( empty( $details ) ) {
			return '-';
		}

		if ( is_string( $details ) && $details !== '' && ( strpos( $details, '{' ) === 0 || strpos( $details, '[' ) === 0 ) ) {
			$decoded = json_decode( $details, true );
			if ( json_last_error() === JSON_ERROR_NONE ) {
				$formatted = array();
				foreach ( $decoded as $key => $value ) {
					if ( is_array( $value ) || is_object( $value ) ) {
						$value = wp_json_encode( $value );
					}
					$formatted[] = '<strong>' . esc_html( ucfirst( str_replace( '_', ' ', $key ) ) ) . ':</strong> ' . esc_html( $value );
				}
				return implode( '<br>', $formatted );
			}
		}

		if ( is_array( $details ) ) {
			$formatted = array();
			foreach ( $details as $key => $value ) {
				if ( is_array( $value ) || is_object( $value ) ) {
					$value = wp_json_encode( $value );
				}
				$formatted[] = '<strong>' . esc_html( ucfirst( str_replace( '_', ' ', $key ) ) ) . ':</strong> ' . esc_html( $value );
			}
			return implode( '<br>', $formatted );
		}

		return esc_html( $details );
	}

	/**
	 * Log critical message
	 */
	public function critical( $message, $ip_address = null, $details = array() ) {
		return $this->log_security_event( 'critical', $ip_address ?: 'system', array_merge( $details, array( 'message' => $message ) ), 'critical' );
	}

	/**
	 * Log info message
	 */
	public function info( $message, $ip_address = null, $details = array() ) {
		return $this->log_security_event( 'info', $ip_address ?: 'system', array_merge( $details, array( 'message' => $message ) ), 'low' );
	}

	/**
	 * Log error message
	 */
	public function error( $message, $ip_address = null, $details = array() ) {
		return $this->log_security_event( 'error', $ip_address ?: 'system', array_merge( $details, array( 'message' => $message ) ), 'high' );
	}

	/**
	 * Log warning message
	 */
	public function warning( $message, $ip_address = null, $details = array() ) {
		return $this->log_security_event( 'warning', $ip_address ?: 'system', array_merge( $details, array( 'message' => $message ) ), 'medium' );
	}

	/**
	 * Log debug message
	 */
	public function debug( $message, $ip_address = null, $details = array() ) {
		return $this->log_security_event( 'debug', $ip_address ?: 'system', array_merge( $details, array( 'message' => $message ) ), 'low' );
	}

	/**
	 * Generic log method
	 *
	 * @param string $event_type Event type identifier.
	 * @param string $ip_address IP address related to the event.
	 * @param string $severity   Severity level (low, medium, high, critical).
	 * @param array  $details    Additional details.
	 */
	public function log( $event_type, $ip_address, $severity = 'medium', $details = array() ) {
		return $this->log_security_event( $event_type, $ip_address, $details, $severity );
	}

	/**
	 * Get logs from database
	 */
	public function get_logs( $days = 30, $limit = 1000, $event_type = null, $severity = null ) {
		$logs = $this->database->get_logs( $days, $limit, $event_type );

		if ( $severity ) {
			$logs = array_filter(
				$logs,
				function ( $log ) use ( $severity ) {
					return $log->severity === $severity;
				}
			);
		}

		foreach ( $logs as $log ) {
			if ( is_string( $log->details ) ) {
				$log->details = json_decode( $log->details, true );
			}
		}

		return $logs;
	}

	/**
	 * Get logs for specific IP
	 */
	public function get_logs_for_ip( $ip_address, $days = 30, $limit = 100 ) {
		global $wpdb;

		$table_name = $wpdb->prefix . 'reportedip_hive_logs';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name composed from $wpdb->prefix and a hardcoded suffix; safe.
		$logs = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM $table_name
                 WHERE ip_address = %s
                 AND created_at >= DATE_SUB(NOW(), INTERVAL %d DAY)
                 ORDER BY created_at DESC
                 LIMIT %d",
				$ip_address,
				$days,
				$limit
			)
		);

		foreach ( $logs as $log ) {
			if ( is_string( $log->details ) ) {
				$log->details = json_decode( $log->details, true );
			}
		}

		return $logs;
	}

	/**
	 * Check if we should log this severity level
	 */
	private function should_log( $severity ) {
		$severity_levels = array(
			'low'      => 1,
			'medium'   => 2,
			'high'     => 3,
			'critical' => 4,
		);

		$log_levels = array(
			'debug'   => 1,
			'info'    => 1,
			'warning' => 2,
			'error'   => 3,
		);

		$current_level = isset( $log_levels[ $this->log_level ] ) ? $log_levels[ $this->log_level ] : 1;
		$message_level = isset( $severity_levels[ $severity ] ) ? $severity_levels[ $severity ] : 2;

		$should_log = $message_level >= $current_level;

		if ( defined( 'REPORTEDIP_DEBUG' ) && REPORTEDIP_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Plugin diagnostic logging gated behind REPORTEDIP_DEBUG; debug.log only.
			error_log(
				sprintf(
					'ReportedIP Logger Debug: severity=%s (%d), log_level=%s (min=%d), should_log=%s',
					$severity,
					$message_level,
					$this->log_level,
					$current_level,
					$should_log ? 'YES' : 'NO'
				)
			);
		}

		return $should_log;
	}
}
