<?php
/**
 * IP Manager Class for ReportedIP Hive.
 *
 * Manages local block- and whitelist entries for IPs and CIDR ranges.
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

class ReportedIP_Hive_IP_Manager {

	/**
	 * Single instance of the class
	 */
	private static $instance = null;

	private $database;
	private $api_client;
	private $logger;

	/**
	 * Get single instance
	 */
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor
	 */
	private function __construct() {
		$this->database   = ReportedIP_Hive_Database::get_instance();
		$this->api_client = ReportedIP_Hive_API::get_instance();
		$this->logger     = ReportedIP_Hive_Logger::get_instance();
	}

	/**
	 * Check if IP is whitelisted
	 */
	public function is_whitelisted( $ip_address ) {
		return $this->database->is_whitelisted( $ip_address );
	}

	/**
	 * Check if IP is blocked
	 */
	public function is_blocked( $ip_address ) {
		return $this->database->is_blocked( $ip_address );
	}

	/**
	 * Whitelist IP address
	 */
	public function whitelist_ip( $ip_address, $reason = '', $expires_at = null ) {
		if ( ! $this->validate_ip_address( $ip_address ) ) {
			return array(
				'success' => false,
				'message' => __( 'Invalid IP address format.', 'reportedip-hive' ),
			);
		}

		if ( $this->is_whitelisted( $ip_address ) ) {
			return array(
				'success' => false,
				'message' => __( 'IP address is already whitelisted.', 'reportedip-hive' ),
			);
		}

		$result = $this->database->add_to_whitelist( $ip_address, $reason, get_current_user_id(), $expires_at );

		if ( $result ) {
			if ( $this->is_blocked( $ip_address ) ) {
				$this->unblock_ip( $ip_address );
			}

			$this->logger->log_security_event(
				'ip_whitelisted',
				$ip_address,
				array(
					'reason'     => $reason,
					'expires_at' => $expires_at,
					'added_by'   => get_current_user_id(),
				),
				'low'
			);

			return array(
				'success' => true,
				'message' => __( 'IP address has been whitelisted successfully.', 'reportedip-hive' ),
			);
		}

		return array(
			'success' => false,
			'message' => __( 'Failed to whitelist IP address.', 'reportedip-hive' ),
		);
	}

	/**
	 * Remove IP from whitelist
	 */
	public function remove_from_whitelist( $ip_address ) {
		$result = $this->database->remove_from_whitelist( $ip_address );

		if ( $result ) {
			$this->logger->log_security_event(
				'ip_removed_from_whitelist',
				$ip_address,
				array(
					'removed_by' => get_current_user_id(),
				),
				'low'
			);

			return array(
				'success' => true,
				'message' => __( 'IP address has been removed from whitelist.', 'reportedip-hive' ),
			);
		}

		return array(
			'success' => false,
			'message' => __( 'Failed to remove IP address from whitelist.', 'reportedip-hive' ),
		);
	}

	/**
	 * Block IP address
	 */
	public function block_ip( $ip_address, $reason = '', $duration_hours = null, $block_type = 'manual' ) {
		if ( ! $this->validate_ip_address( $ip_address ) ) {
			return array(
				'success' => false,
				'message' => __( 'Invalid IP address format.', 'reportedip-hive' ),
			);
		}

		if ( $this->is_whitelisted( $ip_address ) ) {
			return array(
				'success' => false,
				'message' => __( 'Cannot block whitelisted IP address.', 'reportedip-hive' ),
			);
		}

		if ( $duration_hours === null ) {
			$duration_hours = get_option( 'reportedip_hive_block_duration', 24 );
		}

		if ( get_option( 'reportedip_hive_report_only_mode', false ) ) {
			$this->logger->log_security_event(
				'would_block_ip',
				$ip_address,
				array(
					'reason'           => $reason,
					'duration_hours'   => $duration_hours,
					'block_type'       => $block_type,
					'blocked_by'       => get_current_user_id(),
					'report_only_mode' => true,
				),
				'medium'
			);

			return array(
				'success' => true,
				'message' => sprintf(
					/* translators: %d: number of hours the IP would have been blocked */
					__( 'Report-only mode: Would have blocked IP address for %d hours. Event logged for reporting.', 'reportedip-hive' ),
					$duration_hours
				),
			);
		}

		$result = $this->database->block_ip( $ip_address, $reason, $block_type, $duration_hours );

		if ( $result ) {
			$this->logger->log_security_event(
				'ip_blocked',
				$ip_address,
				array(
					'reason'         => $reason,
					'duration_hours' => $duration_hours,
					'block_type'     => $block_type,
					'blocked_by'     => get_current_user_id(),
				),
				'medium'
			);

			$this->database->update_daily_stats( 'blocked_ips' );

			return array(
				'success' => true,
				'message' => sprintf(
					/* translators: %d: number of hours the IP has been blocked */
					__( 'IP address has been blocked for %d hours.', 'reportedip-hive' ),
					$duration_hours
				),
			);
		}

		return array(
			'success' => false,
			'message' => __( 'Failed to block IP address.', 'reportedip-hive' ),
		);
	}

	/**
	 * Unblock IP address
	 */
	public function unblock_ip( $ip_address ) {
		$result = $this->database->unblock_ip( $ip_address );

		if ( $result ) {
			$this->logger->log_security_event(
				'ip_unblocked',
				$ip_address,
				array(
					'unblocked_by' => get_current_user_id(),
				),
				'low'
			);

			return array(
				'success' => true,
				'message' => __( 'IP address has been unblocked.', 'reportedip-hive' ),
			);
		}

		return array(
			'success' => false,
			'message' => __( 'Failed to unblock IP address.', 'reportedip-hive' ),
		);
	}

	/**
	 * Get whitelist entries
	 */
	public function get_whitelist( $active_only = true ) {
		return $this->database->get_whitelist( $active_only );
	}

	/**
	 * Get blocked IPs
	 */
	public function get_blocked_ips( $active_only = true ) {
		return $this->database->get_blocked_ips( $active_only );
	}

	/**
	 * Import whitelist from CSV
	 */
	public function import_whitelist_csv( $csv_content ) {
		$lines    = explode( "\n", trim( $csv_content ) );
		$imported = 0;
		$errors   = array();

		foreach ( $lines as $line_num => $line ) {
			$line = trim( $line );
			if ( empty( $line ) || strpos( $line, '#' ) === 0 ) {
				continue;
			}

			$parts = str_getcsv( $line );
			if ( count( $parts ) < 1 ) {
				/* translators: %d: line number in CSV file */
				$errors[] = sprintf( __( 'Line %d: Invalid format', 'reportedip-hive' ), $line_num + 1 );
				continue;
			}

			$ip_address = trim( $parts[0] );
			$reason     = isset( $parts[1] ) ? trim( $parts[1] ) : 'Imported from CSV';
			$expires_at = isset( $parts[2] ) && ! empty( trim( $parts[2] ) ) ? trim( $parts[2] ) : null;

			if ( ! $this->validate_ip_address( $ip_address ) ) {
				/* translators: 1: line number in CSV file, 2: invalid IP value found */
				$errors[] = sprintf( __( 'Line %1$d: Invalid IP address "%2$s"', 'reportedip-hive' ), $line_num + 1, $ip_address );
				continue;
			}

			if ( $expires_at && strtotime( $expires_at ) === false ) {
				/* translators: 1: line number in CSV file, 2: invalid expiration date value */
				$errors[] = sprintf( __( 'Line %1$d: Invalid expiration date "%2$s"', 'reportedip-hive' ), $line_num + 1, $expires_at );
				continue;
			}

			$result = $this->database->add_to_whitelist( $ip_address, $reason, get_current_user_id(), $expires_at );
			if ( $result ) {
				++$imported;
			} else {
				/* translators: 1: line number in CSV file, 2: IP address that failed to import */
				$errors[] = sprintf( __( 'Line %1$d: Failed to import IP "%2$s"', 'reportedip-hive' ), $line_num + 1, $ip_address );
			}
		}

		$this->logger->log_security_event(
			'whitelist_imported',
			'system',
			array(
				'imported_count' => $imported,
				'error_count'    => count( $errors ),
				'imported_by'    => get_current_user_id(),
			),
			'low'
		);

		return array(
			'imported' => $imported,
			'errors'   => $errors,
		);
	}

	/**
	 * Get IP information
	 */
	public function get_ip_info( $ip_address ) {
		$info = array(
			'ip_address'     => $ip_address,
			'is_valid'       => $this->validate_ip_address( $ip_address ),
			'is_whitelisted' => $this->is_whitelisted( $ip_address ),
			'is_blocked'     => $this->is_blocked( $ip_address ),
			'is_private'     => $this->is_private_ip( $ip_address ),
			'ip_version'     => $this->get_ip_version( $ip_address ),
			'country'        => null,
			'asn'            => null,
			'isp'            => null,
		);

		if ( $this->api_client->is_configured() && $info['is_valid'] ) {
			$reputation = $this->api_client->check_ip_reputation( $ip_address, true );
			if ( $reputation ) {
				$info['reputation'] = $reputation;
				$info['country']    = $reputation['countryCode'] ?? null;
				$info['asn']        = $reputation['asn'] ?? null;
				$info['isp']        = $reputation['isp'] ?? null;
			}
		}

		$info['recent_logs'] = $this->logger->get_logs_for_ip( $ip_address, 7, 10 );

		return $info;
	}

	/**
	 * Validate IP address (supports IPv4, IPv6, and CIDR)
	 */
	public function validate_ip_address( $ip_address ) {
		if ( ! is_string( $ip_address ) || $ip_address === '' ) {
			return false;
		}

		if ( strpos( $ip_address, '/' ) !== false ) {
			return $this->validate_cidr( $ip_address );
		}

		return filter_var( $ip_address, FILTER_VALIDATE_IP ) !== false;
	}

	/**
	 * Validate CIDR notation
	 */
	private function validate_cidr( $cidr ) {
		if ( ! is_string( $cidr ) || $cidr === '' ) {
			return false;
		}

		if ( strpos( $cidr, '/' ) === false ) {
			return false;
		}

		list($ip, $mask) = explode( '/', $cidr, 2 );

		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		$mask = intval( $mask );

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return $mask >= 0 && $mask <= 32;
		} elseif ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return $mask >= 0 && $mask <= 128;
		}

		return false;
	}

	/**
	 * Check if IP is private
	 */
	public function is_private_ip( $ip_address ) {
		return filter_var( $ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false;
	}

	/**
	 * Get IP version
	 */
	public function get_ip_version( $ip_address ) {
		if ( filter_var( $ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return 4;
		} elseif ( filter_var( $ip_address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return 6;
		}

		return null;
	}

	/**
	 * Clean up expired entries
	 */
	public function cleanup_expired_entries() {
		global $wpdb;

		$cleaned = 0;

		$whitelist_table = $wpdb->prefix . 'reportedip_hive_whitelist';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name composed from $wpdb->prefix and a hardcoded suffix; safe.
		$expired_whitelist = $wpdb->query(
			"UPDATE $whitelist_table
             SET is_active = 0
             WHERE expires_at IS NOT NULL
             AND expires_at < NOW()
             AND is_active = 1"
		);

		if ( $expired_whitelist !== false ) {
			$cleaned += $expired_whitelist;
		}

		$blocked_table = $wpdb->prefix . 'reportedip_hive_blocked';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- Table name composed from $wpdb->prefix and a hardcoded suffix; safe.
		$expired_blocks = $wpdb->query(
			"UPDATE $blocked_table
             SET is_active = 0
             WHERE blocked_until IS NOT NULL
             AND blocked_until < NOW()
             AND is_active = 1"
		);

		if ( $expired_blocks !== false ) {
			$cleaned += $expired_blocks;
		}

		if ( $cleaned > 0 ) {
			$this->logger->info( "Cleaned up $cleaned expired IP entries" );
		}

		return $cleaned;
	}
}
